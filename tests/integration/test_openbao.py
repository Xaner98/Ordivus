"""Integration gegen OpenBao im Dev-Modus (Container ``ordivus-it-openbao``, Port 18200).

Provider ``openbao-kv-v2`` (absent/unknown, CAS, Nebenläufigkeit, plan schreibt nie) und
Adapter ``openbao`` (ACL-Policies, Schutz der eigenen Policies, Read-only).
"""

import json
import os
import threading
import uuid

import pytest

from ordivus import adapters, openbao_http
from ordivus.adapters.base import CREATE, Op, PermanentError, Resource, Secret
from ordivus.adapters.fake import FakeAdapter
from ordivus.adapters.openbao import OpenBaoAdapter, canonical, render
from ordivus.core import config, engine, report
from ordivus.core.policy import OperatorPolicy
from ordivus.credentials import PROVIDERS
from ordivus.credentials.base import ABSENT, CONFLICT, PRESENT, UNKNOWN

URL = f"http://{os.environ.get('ORDIVUS_TEST_HOST', 'localhost')}:18200"
ROOT = os.environ.get("ORDIVUS_TEST_OPENBAO_TOKEN", "ordivus-it-root")


def bao(method, path, body=None, token=ROOT):
    return openbao_http.request(URL, method, path, token, body)


@pytest.fixture(scope="module", autouse=True)
def server():
    try:
        status, _ = bao("GET", "sys/health")
    except Exception:
        pytest.skip(f"OpenBao not reachable at {URL}")
    if status != 200:
        pytest.skip(f"OpenBao at {URL} not ready (HTTP {status})")


@pytest.fixture
def uid():
    return uuid.uuid4().hex[:10]


def token_with(name, hcl):
    """Legt Policy ``name`` an und liefert ein Token, das nur diese (plus default) hat."""
    assert bao("PUT", f"sys/policies/acl/{name}", {"policy": hcl})[0] == 204
    status, body = bao("POST", "auth/token/create", {"policies": [name], "ttl": "10m"})
    assert status == 200
    return body["auth"]["client_token"]


def provider(tmp_path, token=ROOT):
    file = tmp_path / f"token-{uuid.uuid4().hex}"
    file.write_text(token)
    return PROVIDERS["openbao-kv-v2"]({"type": "openbao-kv-v2", "endpoint": URL,
                                       "auth": {"method": "token", "tokenFile": str(file)}})


def versions(path):
    status, body = bao("GET", f"secret/metadata/{path}")
    return 0 if status == 404 else body["data"]["current_version"]


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def write_config(directory, docs):
    directory.mkdir(exist_ok=True)
    for f in directory.iterdir():
        f.unlink()
    for i, d in enumerate(docs):
        (directory / f"{i:02}.json").write_text(json.dumps(d))
    return directory


# --- Credential Provider ------------------------------------------------------------------------

def test_absent_create_once_then_unchanged(tmp_path, uid):
    p, ref = provider(tmp_path), {"path": f"it/{uid}/db"}
    assert p.state(ref) == ABSENT
    assert p.create_if_absent(ref, Secret("first")).reveal() == "first"
    assert p.state(ref) == PRESENT and versions(ref["path"]) == 1
    assert p.create_if_absent(ref, Secret("second")).reveal() == "first"  # CAS-Konflikt → Gewinner
    assert p.read(ref).reveal() == "first" and versions(ref["path"]) == 1


def test_concurrent_create_single_winner(tmp_path, uid):
    ref, results = {"path": f"it/{uid}/race"}, {}
    barrier = threading.Barrier(2)

    def worker(n):
        p = provider(tmp_path)
        p._login()
        barrier.wait()
        results[n] = p.create_if_absent(ref, Secret(f"value-{n}")).reveal()

    threads = [threading.Thread(target=worker, args=(n,)) for n in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results[1] == results[2] in ("value-1", "value-2")
    assert versions(ref["path"]) == 1


def test_missing_read_capability_is_unknown_never_absent(tmp_path, uid):
    ref = {"path": f"it/{uid}/hidden"}
    nothing = token_with(f"it-none-{uid}", f'path "secret/data/other-{uid}/*" {{ capabilities = ["read"] }}')
    assert provider(tmp_path, nothing).state(ref) == UNKNOWN  # Metadata 403
    meta_only = token_with(f"it-meta-{uid}", f'path "secret/metadata/it/{uid}/*" {{ capabilities = ["read"] }}')
    assert provider(tmp_path, meta_only).state(ref) == UNKNOWN  # 404, aber kein Leserecht auf data/
    both = token_with(f"it-both-{uid}", f'path "secret/+/it/{uid}/*" {{ capabilities = ["read"] }}')
    assert provider(tmp_path, both).state(ref) == ABSENT


def test_deleted_current_version_is_conflict_and_blocked(tmp_path, uid):
    p, ref = provider(tmp_path), {"path": f"it/{uid}/deleted"}
    p.create_if_absent(ref, Secret("x"))
    assert bao("DELETE", f"secret/data/{ref['path']}")[0] == 204
    assert p.state(ref) == CONFLICT and "deleted or destroyed" in p.state(ref).reason
    adapters.register(FakeAdapter)
    FakeAdapter.reset()
    (tmp_path / "token").write_text(ROOT)
    directory = write_config(tmp_path / "cfg", [
        doc("Target", "t1", adapter="fake", instance="i1"),
        doc("CredentialProvider", "bao", type="openbao-kv-v2", endpoint=URL,
            auth={"method": "token", "tokenFile": str(tmp_path / "token")}),
        doc("Credential", "pw", providerRef="bao", path=ref["path"]),
        doc("FakeUser", "u1", targetRef="t1", attrs={}, credentials={"credentialRef": "pw"})])
    rep = engine.run("apply", config.load(directory), OperatorPolicy(profile="development"))
    cred = next(o for o in rep["operations"] if o["kind"] == "Credential")
    assert cred["action"] == "BLOCKED" and "manual action required" in cred["reason"]
    assert FakeAdapter.calls == [] and versions(ref["path"]) == 1 and report.exit_code(rep) == 11
    FakeAdapter.reset()


def test_approle_login(tmp_path, uid):
    bao("POST", "sys/auth/approle", {"type": "approle"})  # 400, wenn schon aktiviert
    token_with(f"it-app-{uid}", f'path "secret/+/it/{uid}/*" {{ capabilities = ["read", "create"] }}')
    assert bao("POST", f"auth/approle/role/it-{uid}", {"token_policies": [f"it-app-{uid}"]})[0] == 204
    role_id = bao("GET", f"auth/approle/role/it-{uid}/role-id")[1]["data"]["role_id"]
    secret_id = bao("POST", f"auth/approle/role/it-{uid}/secret-id")[1]["data"]["secret_id"]
    (tmp_path / "sid").write_text(secret_id)
    p = PROVIDERS["openbao-kv-v2"]({"endpoint": URL, "auth": {
        "method": "approle", "roleId": role_id, "secretIdFile": str(tmp_path / "sid")}})
    ref = {"path": f"it/{uid}/approle"}
    assert p.state(ref) == ABSENT
    assert p.create_if_absent(ref, Secret("v")).reveal() == "v"


def test_engine_plan_and_drift_never_write_then_apply_creates(tmp_path, uid):
    adapters.register(FakeAdapter)
    FakeAdapter.reset()
    (tmp_path / "token").write_text(ROOT)
    path = f"it/{uid}/user"
    directory = write_config(tmp_path / "cfg", [
        doc("Target", "t1", adapter="fake", instance="i1"),
        doc("CredentialProvider", "bao", type="openbao-kv-v2", endpoint=URL,
            auth={"method": "token", "tokenFile": str(tmp_path / "token")}),
        doc("Credential", "pw", providerRef="bao", path=path),
        doc("FakeUser", "u1", targetRef="t1", attrs={}, credentials={"credentialRef": "pw"}),
    ])
    policy = OperatorPolicy(profile="development")  # http:// verlangt das Profil development
    for mode in ("plan", "drift"):
        rep = engine.run(mode, config.load(directory), policy)
        assert ("Credential", "pw", "CREATE_SECRET") in [(o["kind"], o["id"], o["action"]) for o in rep["operations"]]
        assert versions(path) == 0 and FakeAdapter.calls == []
    rep = engine.run("apply", config.load(directory), policy)
    assert all(o["status"] == "succeeded" for o in rep["operations"]), rep["operations"]
    assert versions(path) == 1
    status, body = bao("GET", f"secret/data/{path}")
    assert FakeAdapter.store["i1"]["FakeUser"]["u1"]["password"] == body["data"]["data"]["password"]
    FakeAdapter.reset()


# --- Policy-Adapter -----------------------------------------------------------------------------

ADMIN_HCL = ('path "sys/policies/acl" { capabilities = ["list"] }\n'
             'path "sys/policies/acl/*" { capabilities = ["create", "read", "update", "delete", "list"] }')


def policy_config(tmp_path, token, *docs, protected=()):
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "admin").write_text(token)
    return write_config(tmp_path / "cfg", [
        doc("CredentialProvider", "files", type="file", directory=str(secrets)),
        doc("Credential", "admin", providerRef="files", path="admin"),
        doc("Target", "bao", adapter="openbao", endpoint={"url": URL}, protectedPolicies=list(protected),
            authentication={"credentialRef": "admin"}),
        *docs])


def ops(rep):
    return {o["id"]: o["action"] for o in rep["operations"]}


def test_policy_lifecycle_and_self_protection(tmp_path, uid):
    admin = f"it-admin-{uid}"
    token = token_with(admin, ADMIN_HCL)
    app, guard, missing = f"it-app-{uid}", f"it-guard-{uid}", f"it-missing-{uid}"
    bao("PUT", f"sys/policies/acl/{guard}", {"policy": 'path "x" { capabilities = ["read"] }'})
    rules = [{"path": f"secret/data/{uid}/*", "capabilities": ["read", "list"]}]
    directory = policy_config(
        tmp_path, token,
        doc("OpenBaoPolicy", "app", targetRef="bao", policyName=app, rules=rules),
        doc("OpenBaoPolicy", "self", targetRef="bao", policyName=admin, policy='path "*" { capabilities = ["sudo"] }'),
        doc("OpenBaoPolicy", "guard", targetRef="bao", policyName=guard, policy="# emptied"),
        doc("OpenBaoPolicy", "default", targetRef="bao", policyName="default", policy="# emptied"),
        doc("OpenBaoPolicy", "missing", targetRef="bao", policyName=missing, policy="# new"),
        protected=[guard, missing])
    run = lambda mode: engine.run(mode, config.load(directory), OperatorPolicy())  # noqa: E731
    plan = run("plan")
    assert plan["targets"][0]["serverVersion"].startswith("OpenBao 2.")
    assert ops(plan)[app] == "CREATE"
    assert ops(plan)[admin] == ops(plan)[guard] == ops(plan)["default"] == "BLOCKED"  # Self-Escalation/-Lockout
    blocked = next(o for o in plan["operations"] if o["id"] == missing)  # geschützt, existiert noch nicht
    assert blocked["action"] == "BLOCKED" and "protected" in blocked["reason"]
    assert "root" not in ops(plan)  # undeclared system policy → IGNORE (only counted)
    assert bao("GET", f"sys/policies/acl/{app}")[0] == 404  # plan schreibt nie

    rep = run("apply")
    assert {o["status"] for o in rep["operations"] if o["id"] == app} == {"succeeded"}
    assert report.exit_code(rep) == 11 and bao("GET", f"sys/policies/acl/{missing}")[0] == 404
    assert bao("GET", f"sys/policies/acl/{admin}")[1]["data"]["policy"] == ADMIN_HCL  # eigene Policy unverändert
    assert canonical(bao("GET", f"sys/policies/acl/{app}")[1]["data"]["policy"]) == render(rules)
    assert ops(run("plan"))[app] == "NOOP"

    # anders formatiert, semantisch gleich: einmal UPDATE, danach konvergiert
    bao("PUT", f"sys/policies/acl/{app}", {"policy": render(rules).replace("  capabilities", "capabilities")})
    assert ops(run("plan"))[app] == "UPDATE"
    run("apply")
    assert ops(run("plan"))[app] == "NOOP"


def test_read_only_session_refuses_and_missing_list_is_forbidden(tmp_path, uid):
    a = OpenBaoAdapter()
    target = {"endpoint": {"url": URL}}
    with a.connect(target, Secret(token_with(f"it-admin-{uid}", ADMIN_HCL)), write=False) as session:
        assert {"root", "default", f"it-admin-{uid}"} <= session.protected
        op = Op("bao", "OpenBaoPolicy", f"it-x-{uid}", CREATE, desired=Resource("OpenBaoPolicy", "x", {"policy": "#"}))
        with pytest.raises(PermanentError, match="read-only"):
            a.apply(session, op)
    weak = token_with(f"it-weak-{uid}", 'path "secret/*" { capabilities = ["read"] }')
    directory = policy_config(tmp_path, weak)
    rep = engine.run("plan", config.load(directory), OperatorPolicy())
    assert rep["targets"][0]["inventory"]["OpenBaoPolicy"]["status"] == "forbidden"


def test_policy_name_variants_cannot_bypass_protection(tmp_path, uid):
    """OpenBao trimmt und kleinschreibt Namen: Varianten geschützter Namen sind ungültig bzw. geschützt."""
    a = OpenBaoAdapter()
    prot = f"rvw-prot-{uid}"
    bao("PUT", f"sys/policies/acl/{prot}", {"policy": 'path "x" { capabilities = ["read"] }'})
    original = bao("GET", "sys/policies/acl/default")[1]["data"]["policy"]
    target = {"endpoint": {"url": URL}, "protectedPolicies": [f" Admin-Ops-{uid} ", prot.upper()]}
    rules = [{"path": "rvw/*", "capabilities": ["read"]}]
    with a.connect(target, Secret(ROOT), write=True) as session:
        for name in ["default ", " default", "default\t", "default\n", f"{prot} ", "Default", "ｄefault",
                     "rvw q", "-x"]:
            d = {"kind": "OpenBaoPolicy", "metadata": {"name": "p"}, "spec": {"policyName": name, "rules": rules}}
            assert a.validate(d), name  # ungültiger Name: Config-Fehler, nie angewendet
        for name in ["default", prot, f"admin-ops-{uid}"]:  # Normalform geschützter Namen
            r = a.desired({"kind": "OpenBaoPolicy", "metadata": {"name": "p"},
                           "spec": {"policyName": name, "rules": rules}})
            assert a.check(session, r) and "protected" in a.check(session, r)
            with pytest.raises(PermanentError, match="protected"):
                a.apply(session, Op("bao", "OpenBaoPolicy", name, CREATE, desired=r))
        found = {r.id: r for r in a.discover(session, "OpenBaoPolicy", None).resources}
        assert found[prot].system and found["default"].system
    assert bao("GET", "sys/policies/acl/default")[1]["data"]["policy"] == original
    assert bao("GET", f"sys/policies/acl/admin-ops-{uid}")[0] == 404
    bao("DELETE", f"sys/policies/acl/{prot}")


def test_kv_v1_mount_is_unknown_never_absent(tmp_path, uid):
    mount = f"kv1-{uid}"
    assert bao("POST", f"sys/mounts/{mount}", {"type": "kv", "options": {"version": "1"}})[0] == 204
    try:
        file = tmp_path / "token"
        file.write_text(ROOT)
        p = PROVIDERS["openbao-kv-v2"]({"type": "openbao-kv-v2", "endpoint": URL, "mount": mount,
                                        "auth": {"method": "token", "tokenFile": str(file)}})
        state = p.state({"path": f"app/{uid}"})
        assert state == UNKNOWN and "KV v2" in state.reason
    finally:
        bao("DELETE", f"sys/mounts/{mount}")
    # gewöhnliches Token mit Leserecht auf dem KV-v2-Pfad: weiterhin absent
    reader = token_with(f"it-kv2-{uid}", f'path "secret/+/it/{uid}/*" {{ capabilities = ["read"] }}')
    assert provider(tmp_path, reader).state({"path": f"it/{uid}/x"}) == ABSENT


PRIVILEGED_POLICIES = {
    "sudo": 'path "secret/data/x" { capabilities = ["read", "sudo"] }',
    "sys": 'path "sys/policies/acl/*" { capabilities = ["read"] }',
    "star": 'path "*" { capabilities = ["read"] }',
    "glob": 'path "s*" { capabilities = ["list"] }',
    "plus": 'path "+/policies/acl/x" { capabilities = ["update"] }',
    "auth": 'path "auth/userpass/users/*" { capabilities = ["create", "update"] }',
    "identity": 'path "identity/entity/*" { capabilities = ["update"] }',
    "tokenglob": 'path "auth/token/*" { capabilities = ["update"] }',
    "template": 'path "{{identity.entity.name}}/*" { capabilities = ["update"] }',
    "hidden": 'path "secret/x" { capabilities = ["read"] } /* */ path "sys/*" { capabilities = ["read"]\n'
              'allowed_parameters = { "*" = [] } }',
    "json": '{"path": {"sys/*": {"capabilities": ["sudo"]}}}',
}
HARMLESS_POLICIES = {
    "app": '# app\npath "secret/data/app/*" { capabilities = ["read", "list"] } // trailing\n'
           'path "sys/*" { capabilities = ["deny"] }',
    "authread": 'path "auth/token/lookup-self" { capabilities = ["read"] }',
    "hash": 'path "secret/data/a#b" { capabilities = ["read"] }',
    "selftoken": 'path "auth/token/renew-self" { capabilities = ["update"] }\n'
                 'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
                 'path "auth/token/lookup-self" { capabilities = ["read", "update"] }',
}


def test_privileged_policies_need_operator_policy(tmp_path, uid):
    names = {k: f"it-priv-{k}-{uid}" for k in (*PRIVILEGED_POLICIES, *HARMLESS_POLICIES, "rules")}
    docs = [doc("OpenBaoPolicy", k, targetRef="bao", policyName=names[k], policy=hcl)
            for k, hcl in {**PRIVILEGED_POLICIES, **HARMLESS_POLICIES}.items()]
    docs.append(doc("OpenBaoPolicy", "rules", targetRef="bao", policyName=names["rules"],
                    rules=[{"path": "sys/mounts", "capabilities": ["read"]}]))
    directory = policy_config(tmp_path, ROOT, *docs)
    plan = engine.run("plan", config.load(directory), OperatorPolicy())
    assert {k for k, n in names.items() if ops(plan)[n] == "BLOCKED"} == {*PRIVILEGED_POLICIES, "rules"}
    allowed = engine.run("plan", config.load(directory), OperatorPolicy(allowPrivilegedGrants=True))
    assert {ops(allowed)[n] for n in names.values()} == {"CREATE"}
    rep = engine.run("apply", config.load(directory), OperatorPolicy())
    assert report.exit_code(rep) == 11
    assert all(bao("GET", f"sys/policies/acl/{names[k]}")[0] == 404 for k in (*PRIVILEGED_POLICIES, "rules"))
    for k in HARMLESS_POLICIES:
        bao("DELETE", f"sys/policies/acl/{names[k]}")


def test_export_roundtrip(tmp_path, uid):
    from roundtrip import assert_export_roundtrip

    app = f"it-export-{uid}"
    hcl = '# app\npath "secret/data/x/*" {\n  capabilities = ["read", "list"]\n}\n\npath "sys/health" {\n' \
          '  capabilities = ["sudo"]\n}  \n'
    assert bao("PUT", f"sys/policies/acl/{app}", {"policy": hcl})[0] == 204
    docs = assert_export_roundtrip(policy_config(tmp_path, ROOT), {("OpenBaoPolicy", app)}, tmp_path,
                                   allowPrivilegedGrants=True)
    assert all(d["metadata"]["name"] not in ("root", "default") for d in docs)


def test_rules_detect_sudo_and_wildcard_write_on_live_policies(tmp_path, uid):
    names = {k: f"it-rule-{k}-{uid}" for k in ("sudo", "wild", "ok", "accepted")}
    hcl = {"sudo": 'path "sys/health" { capabilities = ["sudo"] }',
           "wild": 'path "+/*" { capabilities = ["read", "update"] }',
           "ok": 'path "secret/data/x/*" { capabilities = ["read", "update"] }',
           "accepted": 'path "*" { capabilities = ["sudo", "update"] }'}
    for k, name in names.items():
        assert bao("PUT", f"sys/policies/acl/{name}", {"policy": hcl[k]})[0] == 204
    try:
        directory = policy_config(tmp_path, ROOT, doc("Rules", "compliance", targetRef="bao", rules=[
            {"id": "openbao.sudo-capability", "allow": [names["accepted"]]},
            {"id": "openbao.wildcard-write", "allow": [names["accepted"]]}]))
        rep = engine.run("drift", config.load(directory), OperatorPolicy())  # undeclared policies, read-only
        found = {(v["rule"], v["id"]) for v in rep["violations"] if v["id"].startswith("it-rule-")}
        assert found == {("openbao.sudo-capability", names["sudo"]), ("openbao.wildcard-write", names["wild"])}
        # default und root sind lesbar und nicht auffällig: beide Regeln vollständig ausgewertet
        assert [r["status"] for r in rep["rules"]] == ["complete", "complete"], rep["rules"]
        assert not {"default", "root"} & {v["id"] for v in rep["violations"]}
        assert report.exit_code(rep) == 0 and report.exit_code(rep, "violations") == 10
    finally:
        for name in names.values():
            bao("DELETE", f"sys/policies/acl/{name}")
