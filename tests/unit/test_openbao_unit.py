"""OpenBao ohne Server: Entscheidungstabelle present/absent/unknown, Rendering, Validierung."""

import pytest

from ordivus import openbao_http
from ordivus.adapters.base import Secret, TransientError
from ordivus.adapters.openbao import OpenBaoAdapter, canonical, render
from ordivus.credentials import PROVIDERS
from ordivus.credentials.base import ABSENT, CONFLICT, PRESENT, UNKNOWN

REF = {"providerRef": "bao", "path": "app/db"}
META, DATA = "secret/metadata/app/db", "secret/data/app/db"
LIVE = {"data": {"current_version": 1, "versions": {"1": {"deletion_time": "", "destroyed": False}}}}
MOUNT = "sys/internal/ui/mounts/secret"
CAPS = ("POST", "sys/capabilities-self")
KV2 = {("GET", MOUNT): (200, {"data": {"type": "kv", "options": {"version": "2"}}})}


def provider(tmp_path, responses, calls=None):
    token = tmp_path / "token"
    token.write_text("t0k3n\n")
    spec = {"type": "openbao-kv-v2", "endpoint": "https://bao.example", "auth": {"method": "token",
                                                                                   "tokenFile": str(token)}}
    p = PROVIDERS["openbao-kv-v2"](spec)

    def fake(url, method, path, token=None, body=None, namespace=None, ctx=None):
        assert token == "t0k3n"
        if calls is not None:
            calls.append((method, path, body))
        result = responses[(method, path)]
        if isinstance(result, Exception):
            raise result
        return result

    return p, fake


@pytest.mark.parametrize("responses, expected", [
    ({("GET", META): (200, LIVE)}, PRESENT),
    ({**KV2, ("GET", META): (404, {}), ("POST", "sys/capabilities-self"): (200, {"data": {META: ["read", "list"],
                                                                                   DATA: ["create", "read"]}})},
     ABSENT),
    ({**KV2, ("GET", META): (404, {}), CAPS: (200, {"data": {META: ["root"], DATA: ["root"]}})},
     ABSENT),
    ({**KV2, ("GET", META): (404, {}), CAPS: (200, {"data": {META: ["read"], DATA: ["deny"]}})},
     UNKNOWN),
    ({**KV2, ("GET", META): (404, {}), ("POST", "sys/capabilities-self"): (403, {})}, UNKNOWN),
    ({("GET", META): (403, {"errors": ["permission denied"]})}, UNKNOWN),
    # KV v1: metadata/<pfad> ist dort nur ein fehlender Schlüssel, nie Beweis für "fehlt"
    ({("GET", META): (404, {}), ("GET", MOUNT): (200, {"data": {"type": "kv", "options": {"version": "1"}}})},
     UNKNOWN),
    ({("GET", META): (404, {}), ("GET", MOUNT): (403, {})}, UNKNOWN),
    ({("GET", META): (503, {})}, UNKNOWN),
    ({("GET", META): (200, {"data": {"current_version": 2, "versions": {
        "2": {"deletion_time": "2026-01-01T00:00:00Z", "destroyed": False}}}})}, CONFLICT),
    ({("GET", META): (200, {"data": {"current_version": 1, "versions": {"1": {"destroyed": True}}}})}, CONFLICT),
])
def test_state_decision_table(tmp_path, monkeypatch, responses, expected):
    p, fake = provider(tmp_path, responses)
    monkeypatch.setattr(openbao_http, "request", fake)
    state = p.state(REF)
    assert state == expected and (state in (PRESENT, ABSENT) or state.reason)  # unknown/conflict mit Begründung


def test_timeout_raises_transient_which_engine_maps_to_unknown(tmp_path, monkeypatch):
    p, fake = provider(tmp_path, {("GET", META): TransientError("openbao GET x: TimeoutError")})
    monkeypatch.setattr(openbao_http, "request", fake)
    with pytest.raises(TransientError):  # engine._state wandelt jede Exception in unknown
        p.state(REF)


def test_cas_conflict_returns_existing_winner(tmp_path, monkeypatch):
    calls = []
    p, fake = provider(tmp_path, {
        ("POST", DATA): (400, {"errors": ["check-and-set parameter did not match the current version"]}),
        ("GET", DATA): (200, {"data": {"data": {"password": "winner"}}})}, calls)
    monkeypatch.setattr(openbao_http, "request", fake)
    assert p.create_if_absent(REF, Secret("mine")).reveal() == "winner"
    assert calls[0] == ("POST", DATA, {"options": {"cas": 0}, "data": {"password": "mine"}})


def test_path_traversal_rejected(tmp_path, monkeypatch):
    p, fake = provider(tmp_path, {})
    monkeypatch.setattr(openbao_http, "request", fake)
    with pytest.raises(Exception, match="segments"):
        p.state({"path": "app/../../sys/x"})


def test_provider_validation():
    validate = PROVIDERS["openbao-kv-v2"].validate
    assert validate({"endpoint": "https://b", "auth": {"method": "approle", "roleId": "r", "secretIdFile": "/s"}}) == []
    assert validate({"endpoint": "https://b", "auth": {"method": "token", "token": "inline"}}) == [
        "unknown field spec.auth.token", "spec.auth.tokenFile must be a non-empty string"]
    assert validate({"endpoint": "b", "auth": {"method": "x"}, "extra": 1}) == [
        "unknown field spec.extra", "spec.endpoint must be an http(s) URL",
        "spec.auth.method must be one of ['approle', 'jwt', 'kubernetes', 'token']"]
    http = PROVIDERS["openbao-kv-v2"]({"endpoint": "http://b", "auth": {"method": "token", "tokenFile": "/t"}})
    assert http.development_only  # Klartext-HTTP nur im Profil development


def test_render_is_deterministic_and_canonical():
    text = render([{"path": "secret/data/b/*", "capabilities": ["read", "list", "read"]},
                   {"path": "secret/data/a", "capabilities": ["update", "create"]}])
    assert text == ('path "secret/data/b/*" {\n  capabilities = ["list", "read"]\n}\n\n'
                    'path "secret/data/a" {\n  capabilities = ["create", "update"]\n}')
    assert canonical(text) == text
    assert canonical("\r\npath \"x\" {  \r\n}\r\n\n") == 'path "x" {\n}'


def test_policy_validation():
    a = OpenBaoAdapter()

    def check(**spec):
        return a.validate({"kind": "OpenBaoPolicy", "metadata": {"name": "p"}, "spec": spec})

    assert check(policyName="app", rules=[{"path": "secret/*", "capabilities": ["read"]}]) == []
    assert check(policyName="app", policy='path "x" { capabilities = ["read"] }') == []
    for bad in ("App", "default ", " default", "a/b", "ｄefault", "-x", ""):
        assert check(policyName=bad, policy="x") == [
            "spec.policyName must match [a-z0-9][a-z0-9_.-]* (OpenBao trims and lowercases names)"]
    assert check(policyName="app") == ["exactly one of spec.rules or spec.policy is required"]
    assert check(policyName="app", rules=[{"path": "x", "capabilities": ['read"]}']}]) == [
        "spec.rules[0].capabilities must be a non-empty list of capability names"]
    assert a.validate({"kind": "Target", "metadata": {"name": "t"},
                       "spec": {"endpoint": {"url": "https://b"}, "protectedPolicies": ["break-glass"]}}) == []
