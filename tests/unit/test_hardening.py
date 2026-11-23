"""Regressionstests der Core-Sicherheitsbefunde (Review H1–H3, M1–M4, L1–L5)."""

import http.server
import json
import os
import stat
import threading
from contextlib import contextmanager
from importlib.metadata import EntryPoint

import pytest
from conftest import doc

from ordivus import adapters, net, openbao_http
from ordivus.adapters import arcadedb, clickhouse
from ordivus.adapters.base import PermanentError, Secret, TransientError
from ordivus.adapters.fake import FakeAdapter
from ordivus.cli import ExitCode, main
from ordivus.core import config, engine, policy, report
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy
from ordivus.credentials import PROVIDERS, FileProvider
from ordivus.credentials.base import ABSENT, PRESENT, UNKNOWN, CredentialError

CRED = doc("Credential", "pw", providerRef="files", path="u1")
ADMIN_PW = "S3cretAdminPW-canary"


def user(name="u1", policy="verify"):
    return doc("FakeUser", name, targetRef="t1", credentials={"credentialRef": "pw", "passwordPolicy": policy})


def run(path, mode, **pol):
    return engine.run(mode, config.load(path), OperatorPolicy(**pol))


# --- H1: unbekannt ist nie "in_sync" -----------------------------------------------------------

def test_apply_with_forbidden_discovery_is_incomplete_exit_13(cfg, fake):
    fake.discovery_status[("i1", "FakeUser")] = "forbidden"
    (cfg.secrets / "u1").write_text("pw")
    path = cfg(CRED, user())
    rep = run(path, "apply")
    assert rep["targets"][0]["status"] == "incomplete" and fake.calls == []
    assert report.exit_code(rep) == main(["apply", "-f", str(path)]) == ExitCode.TARGET
    assert main(["plan", "-f", str(path)]) == ExitCode.OK  # plan/drift: Status incomplete, Exit nur mit --fail-on
    assert main(["drift", "-f", str(path)]) == ExitCode.OK
    assert main(["drift", "-f", str(path), "--fail-on", "unknown"]) == ExitCode.DRIFT
    assert main(["drift", "-f", str(path), "--fail-on", "any"]) == ExitCode.DRIFT


def test_apply_unverifiable_password_is_incomplete(cfg, fake):
    fake.put("i1", "FakeUser", "u1", password="x")
    fake.unverifiable.add(("i1", "u1"))
    (cfg.secrets / "u1").write_text("pw")
    rep = run(cfg(CRED, user()), "apply")
    assert rep["targets"][0]["status"] == "incomplete" and report.exit_code(rep) == ExitCode.TARGET


def test_drift_fail_on_unknown_ignores_plain_drift(cfg, fake):
    path = cfg(doc("FakeItem", "a", targetRef="t1"))
    assert main(["drift", "-f", str(path), "--fail-on", "unknown"]) == ExitCode.OK


# --- H2: leere Secrets, atomares Anlegen -------------------------------------------------------

def test_empty_credential_never_sets_empty_password(cfg, fake):
    fake.put("i1", "FakeUser", "u1", password="oldpw")
    (cfg.secrets / "u1").write_text("")
    for policy_name in ("verify", "enforce"):
        rep = run(cfg(CRED, user(policy=policy_name)), "apply")
        assert ("Credential", "pw", "UNKNOWN") in [(o["kind"], o["id"], o["action"]) for o in rep["operations"]]
        assert fake.calls == [] and fake.store["i1"]["FakeUser"]["u1"]["password"] == "oldpw"
        assert report.exit_code(rep) == ExitCode.TARGET


def test_empty_admin_credential_is_target_error(cfg, fake):
    (cfg.secrets / "admin").write_text("\n")
    target = doc("Target", "t1", adapter="fake", instance="i1", authentication={"credentialRef": "admin"})
    path = cfg(target, doc("CredentialProvider", "files", type="file", directory=str(cfg.secrets)),
               doc("Credential", "admin", providerRef="files", path="admin"), base=False)
    rep = run(path, "plan")
    assert rep["targets"][0]["status"] == "error" and "empty" in rep["targets"][0]["reason"]


def test_file_create_is_atomic_and_never_overwrites(tmp_path):
    p = FileProvider({"directory": str(tmp_path)})
    assert p.create_if_absent({"path": "a"}, Secret("first")).reveal() == "first"
    assert stat.S_IMODE(os.stat(tmp_path / "a").st_mode) == 0o600
    assert p.create_if_absent({"path": "a"}, Secret("second")).reveal() == "first"
    assert sorted(os.listdir(tmp_path)) == ["a"]  # keine Temp-Dateien übrig


def test_file_create_failure_leaves_no_file(tmp_path, monkeypatch):
    def boom(*a):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(CredentialError):
        FileProvider({"directory": str(tmp_path)}).create_if_absent({"path": "a"}, Secret("x"))
    assert os.listdir(tmp_path) == []


# --- M3: Symlinks und Sonderdateien ------------------------------------------------------------

def test_file_provider_symlinks_and_fifo(tmp_path):
    p = FileProvider({"directory": str(tmp_path)})
    (tmp_path / "real").write_text("v")
    os.symlink(tmp_path / "real", tmp_path / "good")
    os.symlink("/nonexistent/x", tmp_path / "dang")
    os.symlink(tmp_path / "loop", tmp_path / "loop")
    os.symlink(tmp_path, tmp_path / "dir")
    os.mkfifo(tmp_path / "fifo")
    assert p.state({"path": "good"}) == PRESENT and p.read({"path": "good"}).reveal() == "v"
    for name in ("dang", "loop", "dir", "fifo"):
        state = p.state({"path": name})
        assert state == UNKNOWN and state.reason, name
    assert p.state({"path": "missing"}) == ABSENT
    with pytest.raises(CredentialError, match="regular file"):
        p.read({"path": "fifo"})  # blockiert nicht


# --- M1/M2: Adapter-Bugs, Scrubbing ------------------------------------------------------------

def _two_targets(cfg):
    (cfg.secrets / "admin").write_text(ADMIN_PW)
    targets = [doc("Target", n, adapter="fake", instance=i, authentication={"credentialRef": "admin"})
               for n, i in (("a1", "i1"), ("b2", "i2"))]
    return cfg(*targets, doc("CredentialProvider", "files", type="file", directory=str(cfg.secrets)),
               doc("Credential", "admin", providerRef="files", path="admin"),
               doc("FakeItem", "item", targetRef="a1"), base=False)


def test_unexpected_exception_is_scrubbed_target_error(cfg, fake, monkeypatch, capsys):
    original = FakeAdapter.connect

    @contextmanager
    def connect(self, target, secret, write):
        if target["instance"] == "i2":
            raise RuntimeError(f"connection failed: postgresql://admin:{secret.reveal()}@db/x")
        with original(self, target, secret, write) as s:
            yield s

    monkeypatch.setattr(FakeAdapter, "connect", connect)
    path = _two_targets(cfg)
    for fmt in ("json", "human"):
        fake.reset()
        assert main(["apply", "-f", str(path), "--format", fmt]) == ExitCode.TARGET
        out = capsys.readouterr()
        assert ADMIN_PW not in out.out + out.err and "RuntimeError" in out.out
        assert fake.calls == [("i1", "CREATE", "FakeItem", "item")]  # a1 lief trotzdem


def test_exception_after_mutation_is_partial_exit_14(cfg, fake, monkeypatch):
    @contextmanager
    def lock(self, session):
        yield
        raise RuntimeError("unlock failed")

    monkeypatch.setattr(FakeAdapter, "lock", lock)
    rep = run(cfg(doc("FakeItem", "a", targetRef="t1")), "apply")
    assert rep["targets"][0]["status"] == "partial" and report.exit_code(rep) == ExitCode.PARTIAL


def test_discovery_errors_are_scrubbed(cfg, fake, monkeypatch, capsys):
    def discover(self, session, kind, scope):
        raise TransientError(f"auth failed for password {ADMIN_PW}")

    monkeypatch.setattr(FakeAdapter, "discover", discover)
    path = _two_targets(cfg)
    assert main(["plan", "-f", str(path), "--format", "json"]) == ExitCode.OK
    out = capsys.readouterr()
    assert ADMIN_PW not in out.out + out.err and "<redacted>" in out.out
    rep = json.loads(out.out)
    assert rep["targets"][0]["inventory"]["FakeItem"]["status"] == "unknown"


def test_buggy_discover_is_unknown_not_crash(cfg, fake, monkeypatch):
    monkeypatch.setattr(FakeAdapter, "discover", lambda self, s, k, scope: 1 / 0)
    rep = run(cfg(doc("FakeItem", "a", targetRef="t1")), "apply")
    assert rep["targets"][0]["inventory"]["FakeItem"]["status"] == "unknown"
    assert report.exit_code(rep) == ExitCode.TARGET and fake.calls == []


def test_cli_internal_error_prints_type_only(cfg, monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError(f"secret {ADMIN_PW}")

    monkeypatch.setattr(engine, "run", boom)
    monkeypatch.delenv("ORDIVUS_DEBUG", raising=False)
    assert main(["plan", "-f", str(cfg())]) == ExitCode.INTERNAL
    err = capsys.readouterr().err
    assert "RuntimeError" in err and ADMIN_PW not in err and "Traceback" not in err


# --- M4/L1/L3: Config-Härtung ------------------------------------------------------------------

HEAD = "apiVersion: ordivus.dev/v1alpha1\nkind: Target\nmetadata: {name: t}\n"


@pytest.mark.parametrize("value", ["!!timestamp 2020-01-01", "!!set {a: null}", "!!binary YWJj",
                                   "!!omap [{a: 1}]", "!!pairs [{a: 1}]", "!!python/name:os.system ''"])
def test_non_json_yaml_types_are_config_errors(tmp_path, value):
    f = tmp_path / "c.yaml"
    f.write_text(HEAD + f"spec:\n  adapter: fake\n  instance: {value}\n")
    with pytest.raises(ConfigError) as e:
        config.load(f)
    assert e.value.errors[0].startswith(f"{f}:6:")


@pytest.mark.parametrize("text", ["spec: {1: x, b: y}\n", "spec: {null: x}\n"])
def test_non_string_keys_are_config_errors(tmp_path, text):
    f = tmp_path / "c.yaml"
    f.write_text(HEAD + text)
    with pytest.raises(ConfigError, match="keys must be strings"):
        config.load(f)


def test_deep_nesting_is_config_error(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(HEAD + "spec: {x: " + "[" * 5000 + "]" * 5000 + "}\n")
    with pytest.raises(ConfigError, match="nesting"):
        config.load(f)


@pytest.mark.parametrize("extra", [
    doc("Target", "t2", adapter="fake", instance="i", authentication={"credentialRef": ["a"]}),
    doc("FakeItem", "a", targetRef=["t1"]),
    doc("Credential", "c", providerRef={"x": 1}, path="p"),
    doc("CredentialProvider", "p2", type=["file"]),
    doc("ReconciliationPolicy", "g", targetRef=["t1"]),
    doc("ReconciliationPolicy", "g", targetRef="t1", scope={"resourceKinds": [["FakeItem"]]}),
    doc("FakeUser", "u", targetRef="t1", credentials={"credentialRef": ["pw"]}),
])
def test_non_string_refs_are_config_errors(cfg, extra):
    with pytest.raises(ConfigError):
        engine.prepare(config.load(cfg(extra)))


def test_generator_length_upper_bound(cfg):
    cred = doc("Credential", "c", providerRef="files", path="p", lifecycle={"generator": {"length": 10**9}})
    with pytest.raises(ConfigError, match="between"):
        engine.prepare(config.load(cfg(cred)))


def test_config_fifo_and_special_files_rejected(tmp_path):
    os.mkfifo(tmp_path / "c.yaml")
    with pytest.raises(ConfigError, match="regular file"):
        config.load(tmp_path / "c.yaml")  # blockiert nicht


def test_digest_computed_before_any_connection(cfg, fake, monkeypatch):
    calls = []
    monkeypatch.setattr(config, "digest", lambda docs: calls.append(fake.calls[:]) or "sha256:x")
    run(cfg(doc("FakeItem", "a", targetRef="t1")), "apply")
    assert calls == [[]]


# --- L2: Report-Datei --------------------------------------------------------------------------

def test_output_file_private_and_no_symlink(cfg, tmp_path, capsys):
    out = tmp_path / "r.txt"
    assert main(["plan", "-f", str(cfg()), "--output", str(out)]) == ExitCode.OK
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    os.symlink(tmp_path / "elsewhere", tmp_path / "link")
    assert main(["plan", "-f", str(cfg()), "--output", str(tmp_path / "link")]) == ExitCode.INTERNAL
    assert not (tmp_path / "elsewhere").exists()


# --- L5: Plugins ersetzen keine eingebauten Adapter --------------------------------------------

class Impostor(FakeAdapter):
    pass


def test_plugin_with_builtin_id_is_ignored(monkeypatch, caplog):
    eps = [EntryPoint("evil", "tests_evil:Impostor", "ordivus.adapters"),
           EntryPoint("fake", "ordivus.adapters.fake:FakeAdapter", "ordivus.adapters")]
    monkeypatch.setattr(EntryPoint, "load", lambda self: Impostor if self.name == "evil" else FakeAdapter)
    monkeypatch.setattr(adapters, "entry_points", lambda group: eps)
    monkeypatch.setattr(adapters, "_registry", {})
    monkeypatch.setattr(adapters, "_loaded", False)
    assert type(adapters.get("fake")) is FakeAdapter
    assert "already registered" in caplog.text


# --- Policy ------------------------------------------------------------------------------------

def test_allow_privileged_grants_reaches_check(cfg, fake, monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(FakeAdapter, "check", lambda self, s, r, allow_privileged: seen.append(allow_privileged))
    path = cfg(doc("FakeItem", "a", targetRef="t1"))
    run(path, "plan")
    pol = tmp_path / "p.yaml"
    pol.write_text("allowPrivilegedGrants: true\n")
    engine.run("plan", config.load(path), policy.load(pol))
    assert seen == [False, True]
    pol.write_text("allowPrivilegedGrants: yes\n")
    with pytest.raises(policy.PolicyError):
        policy.load(pol)


def test_openbao_provider_mount_segments():
    spec = {"endpoint": "https://b", "auth": {"method": "token", "tokenFile": "/t"}}
    for mount in ("../sys", "a//b", "kv/./x"):
        assert any("mount" in e for e in PROVIDERS["openbao-kv-v2"].validate({**spec, "mount": mount}))
    assert PROVIDERS["openbao-kv-v2"].validate({**spec, "mount": "team/kv"}) == []


# --- H3/C9/L4: kein Redirect, nur http(s), begrenzte Antworten ---------------------------------

@pytest.fixture
def servers():
    seen = []

    class Evil(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.headers.get("X-Vault-Token"), self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data": []}')

        do_POST = do_GET

        def log_message(self, *a):
            pass

    class Redirect(Evil):
        def do_GET(self):
            self.send_response(307 if self.command == "GET" else 302)
            self.send_header("Location", f"http://127.0.0.1:{evil.server_port}{self.path}")
            self.end_headers()

        do_POST = do_GET

    evil = http.server.HTTPServer(("127.0.0.1", 0), Evil)
    redirect = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    for s in (evil, redirect):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{redirect.server_port}", f"http://127.0.0.1:{evil.server_port}", seen
    for s in (evil, redirect):
        s.shutdown()
        s.server_close()


def test_no_client_follows_redirects(servers):
    url, _, seen = servers
    with pytest.raises(PermanentError, match="redirect refused"):
        openbao_http.request(url, "GET", "auth/token/lookup-self", "s.ADMIN-TOKEN")
    with pytest.raises(PermanentError, match="redirect refused"):
        clickhouse._post(clickhouse.Session(url, "admin", Secret("CH-PW"), None, 5, True), "SELECT 1 FORMAT JSON")
    with pytest.raises(PermanentError, match="redirect refused"):
        arcadedb._call(url, None, "Basic eA==", "GET", "/api/v1/server")
    assert seen == []  # kein Token, kein Passwort beim Redirect-Ziel


def test_body_cap_and_scheme(servers, monkeypatch):
    _, evil, _ = servers
    monkeypatch.setattr(net, "MAX_BODY", 4)
    with pytest.raises(PermanentError, match="exceeds"):
        openbao_http.request(evil, "GET", "x")
    with pytest.raises(PermanentError, match="http and https"):
        openbao_http.request("file:///etc", "GET", "passwd")
