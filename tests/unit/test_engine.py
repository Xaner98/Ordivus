import copy
import json
import os

import pytest
from conftest import doc

from ordivus.adapters.base import Secret
from ordivus.cli import ExitCode, main
from ordivus.core import config, engine, report
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy, PolicyError

AUTHORITATIVE = doc("ReconciliationPolicy", "gov", targetRef="t1", mode="authoritative",
                    scope={"resourceKinds": ["FakeItem"]})
CRED = doc("Credential", "pw", providerRef="files", path="u1")


def user(name="u1", policy="verify", cred="pw", **attrs):
    return doc("FakeUser", name, targetRef="t1", attrs=attrs,
               credentials={"credentialRef": cred, "passwordPolicy": policy})


def run(path, mode, **policy):
    return engine.run(mode, config.load(path), OperatorPolicy(**policy))


def actions(rep):
    return [(o["kind"], o["id"], o["action"]) for o in rep["operations"]]


def test_two_applies_converge(cfg, fake):
    path = cfg(doc("FakeItem", "a", targetRef="t1", attrs={"size": 1}), CRED, user(login=True))
    first = run(path, "apply")
    assert report.exit_code(first) == 0
    assert {o["action"] for o in first["operations"]} == {"CREATE_SECRET", "CREATE"}
    assert all(o["status"] == "succeeded" for o in first["operations"])
    fake.calls.clear()
    second = run(path, "apply")
    assert fake.calls == [] and report.exit_code(second) == 0
    assert {o["action"] for o in second["operations"]} == {"NOOP"}
    assert second["summary"]["actionableDrift"] == 0 and second["targets"][0]["status"] == "in_sync"


def test_update_only_declared_attrs(cfg, fake):
    fake.put("i1", "FakeItem", "a", {"size": 1, "color": "red"})
    rep = run(cfg(doc("FakeItem", "a", targetRef="t1", attrs={"size": 2})), "apply")
    assert rep["operations"][0]["changes"] == {"size": {"old": 1, "new": 2}}
    assert fake.store["i1"]["FakeItem"]["a"]["attrs"] == {"size": 2, "color": "red"}  # unset ≠ reset


@pytest.mark.parametrize("mode", ["plan", "drift"])
def test_plan_and_drift_never_mutate(cfg, fake, mode):
    fake.put("i1", "FakeItem", "a", {"size": 1})
    fake.put("i1", "FakeItem", "x")
    fake.put("i1", "FakeUser", "u2", password="old")
    before = copy.deepcopy(fake.store)
    path = cfg(doc("FakeItem", "a", targetRef="t1", attrs={"size": 2}), CRED, user(), user("u2"), AUTHORITATIVE)
    rep = run(path, mode, allowAuthoritative=True, allowDelete=True)
    assert {"CREATE_SECRET", "CREATE", "UPDATE", "SET_PASSWORD", "DELETE"} <= {o["action"] for o in rep["operations"]}
    assert fake.store == before and fake.calls == []
    assert list(cfg.secrets.iterdir()) == []


def test_additive_keeps_unmanaged(cfg, fake):
    fake.put("i1", "FakeItem", "x")
    rep = run(cfg(doc("FakeItem", "a", targetRef="t1")), "apply", allowDelete=True)
    assert ("FakeItem", "x", "UNMANAGED") in actions(rep)
    assert "x" in fake.store["i1"]["FakeItem"]


def test_authoritative_without_operator_permission(cfg, fake):
    fake.put("i1", "FakeItem", "x")
    path = cfg(AUTHORITATIVE)
    rep = run(path, "plan")
    op = next(o for o in rep["operations"] if o["id"] == "x")
    assert op["action"] == "BLOCKED" and op["status"] == "denied"
    with pytest.raises(PolicyError):
        run(path, "apply")
    assert main(["apply", "-f", str(path)]) == ExitCode.POLICY
    assert "x" in fake.store["i1"]["FakeItem"]


def test_authoritative_delete_only_safe_objects(cfg, fake):
    fake.put("i1", "FakeItem", "x")
    fake.put("i1", "FakeItem", "native", manageable=False)
    fake.put("i1", "FakeItem", "sys", system=True)
    fake.put("i1", "FakeUser", "other")  # FakeUser nicht im Authoritative Scope
    path = cfg(AUTHORITATIVE)
    rep = run(path, "apply", allowAuthoritative=True)  # ohne allowDelete: nur Klassifikation
    assert ("FakeItem", "x", "UNDESIRABLE") in actions(rep) and fake.calls == []
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    assert set(fake.store["i1"]["FakeItem"]) == {"native", "sys"}
    assert ("FakeItem", "native", "UNDESIRABLE") in actions(rep)
    assert ("FakeUser", "other", "UNMANAGED") in actions(rep)
    assert not any(o["id"] == "sys" for o in rep["operations"]) and rep["summary"]["actions"]["IGNORE"] == 1


@pytest.mark.parametrize("status", ["partial", "forbidden", "unknown", "unsupported"])
def test_incomplete_discovery_never_deletes_or_creates(cfg, fake, status):
    fake.put("i1", "FakeItem", "x")
    fake.discovery_status[("i1", "FakeItem")] = status
    rep = run(cfg(AUTHORITATIVE, doc("FakeItem", "a", targetRef="t1")), "apply",
              allowAuthoritative=True, allowDelete=True)
    assert ("FakeItem", "x", "UNKNOWN") in actions(rep) and ("FakeItem", "a", "UNKNOWN") in actions(rep)
    assert fake.calls == [] and rep["targets"][0]["inventory"]["FakeItem"]["status"] == status


def test_excluded_counted_not_listed(cfg, fake):
    fake.put("i1", "FakeItem", "keep-1")
    fake.put("i1", "FakeItem", "keep-2")
    fake.put("i1", "FakeItem", "exact")
    fake.put("i1", "FakeItem", "x")
    policy = doc("ReconciliationPolicy", "gov", targetRef="t1", mode="authoritative",
                 scope={"resourceKinds": ["FakeItem"]},
                 exclusions={"FakeItem": {"exact": ["exact"], "glob": ["keep-*"]}})
    rep = run(cfg(policy), "apply", allowAuthoritative=True, allowDelete=True)
    assert actions(rep) == [("FakeItem", "x", "DELETE")]
    assert rep["summary"]["actions"]["IGNORE"] == 3 and len(fake.store["i1"]["FakeItem"]) == 3


def test_absent_secret_planned_then_created_once(cfg, fake):
    path = cfg(CRED, user("u1"), user("u2"))
    rep = run(path, "plan")
    assert actions(rep)[0] == ("Credential", "pw", "CREATE_SECRET")
    assert [a for a in actions(rep) if a[2] == "CREATE_SECRET"] == [("Credential", "pw", "CREATE_SECRET")]
    create = next(o for o in rep["operations"] if o["id"] == "u1")
    assert "password" not in create["changes"]  # Passwort nur über CREATE_SECRET/SET_PASSWORD sichtbar
    assert list(cfg.secrets.iterdir()) == []
    run(path, "apply")
    secret = cfg.secrets / "u1"
    value = secret.read_text()
    assert len(value) == 32 and value.isalnum() and oct(secret.stat().st_mode & 0o777) == "0o600"
    assert {u["password"] for u in fake.store["i1"]["FakeUser"].values()} == {value}
    rep = run(path, "apply")
    assert secret.read_text() == value and {o["action"] for o in rep["operations"]} == {"NOOP"}


def test_secret_absent_user_exists_resets_password(cfg, fake):  # D-023
    fake.put("i1", "FakeUser", "u1", password="old")
    rep = run(cfg(CRED, user()), "apply")
    assert actions(rep) == [("Credential", "pw", "CREATE_SECRET"), ("FakeUser", "u1", "NOOP"),
                            ("FakeUser", "u1", "SET_PASSWORD")]
    assert fake.store["i1"]["FakeUser"]["u1"]["password"] == (cfg.secrets / "u1").read_text()


def test_verify_wrong_password_sets_password(cfg, fake):
    (cfg.secrets / "u1").write_text("right\n")
    fake.put("i1", "FakeUser", "u1", password="wrong")
    path = cfg(CRED, user())
    assert ("FakeUser", "u1", "SET_PASSWORD") in actions(run(path, "drift"))
    assert main(["drift", "-f", str(path), "--fail-on", "actionable"]) == ExitCode.DRIFT
    run(path, "apply")
    assert fake.store["i1"]["FakeUser"]["u1"]["password"] == "right"
    assert ("FakeUser", "u1", "SET_PASSWORD") not in actions(run(path, "plan"))


def test_password_reset_denied_by_policy(cfg, fake):
    (cfg.secrets / "u1").write_text("right")
    fake.put("i1", "FakeUser", "u1", password="wrong")
    rep = run(cfg(CRED, user()), "apply", allowPasswordReset=False)
    op = next(o for o in rep["operations"] if o["action"] == "BLOCKED")
    assert op["status"] == "denied" and fake.calls == [] and report.exit_code(rep) == ExitCode.POLICY


def test_unverifiable_and_policies(cfg, fake):
    (cfg.secrets / "u1").write_text("right")
    fake.put("i1", "FakeUser", "u1", password="wrong")
    fake.put("i1", "FakeUser", "u2", password="wrong")
    fake.put("i1", "FakeUser", "u3", password="wrong")
    fake.unverifiable.add(("i1", "u1"))
    rep = run(cfg(CRED, user("u1"), user("u2", "set-on-create"), user("u3", "enforce")), "plan")
    assert ("FakeUser", "u1", "UNKNOWN") in actions(rep)
    assert not any(a[1] == "u2" and a[2] != "NOOP" for a in actions(rep))
    assert ("FakeUser", "u3", "SET_PASSWORD") in actions(rep)


def test_unknown_provider_state_changes_no_password(cfg, fake, tmp_path):
    fake.put("i1", "FakeUser", "u1", password="old")
    gone = doc("CredentialProvider", "gone", type="file", directory=str(tmp_path / "missing"))
    path = cfg(gone, doc("Credential", "pw", providerRef="gone", path="u1"), user(), user("new"))
    rep = run(path, "apply")
    assert ("Credential", "pw", "UNKNOWN") in actions(rep) and ("FakeUser", "new", "BLOCKED") in actions(rep)
    cred = next(o for o in rep["operations"] if o["kind"] == "Credential")
    assert "directory missing" in cred["reason"]  # Begründung des Providers im Report
    assert fake.calls == [] and fake.store["i1"]["FakeUser"]["u1"]["password"] == "old"
    assert report.exit_code(rep) == ExitCode.TARGET
    assert not (tmp_path / "missing").exists()


def test_secret_never_in_output_or_errors(cfg, fake, capsys):
    canary = "CANARY-s3cr3t-value"
    (cfg.secrets / "u1").write_text(canary)
    (cfg.secrets / "admin").write_text(canary + "-admin")
    fake.put("i1", "FakeUser", "u1", password="wrong")
    fake.fail[("i1", "SET_PASSWORD", "u1")] = f"driver said: password {canary} rejected"
    target = doc("Target", "t1", adapter="fake", instance="i1", authentication={"credentialRef": "admin"})
    path = cfg(target, doc("CredentialProvider", "files", type="file", directory=str(cfg.secrets)),
               doc("Credential", "admin", providerRef="files", path="admin"), CRED, user(), base=False)
    for fmt in ("json", "human"):
        assert main(["apply", "-f", str(path), "--format", fmt]) == ExitCode.PARTIAL
        out = capsys.readouterr()
        assert canary not in out.out + out.err and "<redacted>" in out.out
    rep = run(path, "plan")
    assert canary not in json.dumps(rep) + report.render_human(rep)
    assert repr(Secret(canary)) == str(Secret(canary)) == "***" and canary not in f"{Secret(canary)!r}"


def test_partial_failure_fail_fast_per_target(cfg, fake):
    fake.fail[("i1", "CREATE", "a")] = "boom"
    t2 = doc("Target", "t2", adapter="fake", instance="i2")
    path = cfg(t2, doc("FakeItem", "a", targetRef="t1"), doc("FakeItem", "b", targetRef="t1"),
               doc("FakeItem", "c", targetRef="t2"))
    rep = run(path, "apply")
    status = {(o["target"], o["id"]): o["status"] for o in rep["operations"]}
    assert status == {("t1", "a"): "failed", ("t1", "b"): "skipped", ("t2", "c"): "succeeded"}
    assert report.exit_code(rep) == ExitCode.PARTIAL
    assert [t["status"] for t in rep["targets"]] == ["partial", "applied"]
    assert main(["apply", "-f", str(path)]) == ExitCode.PARTIAL


def test_unverified_after_apply(cfg, fake, monkeypatch):
    monkeypatch.setattr(fake, "apply", lambda self, session, op: None)  # Adapter meldet Erfolg, ändert nichts
    rep = run(cfg(doc("FakeItem", "a", targetRef="t1")), "apply")
    assert rep["operations"][0]["status"] == "unverified" and report.exit_code(rep) == ExitCode.PARTIAL


def test_deterministic_order(cfg, fake):
    ids = ["c", "a", "b"]
    path = cfg(AUTHORITATIVE, *[doc("FakeItem", f"new-{i}", targetRef="t1") for i in ids],
               CRED, user("u2"), user("u1"))
    results = []
    for order in (ids, list(reversed(ids))):
        fake.reset()
        for i in order:
            fake.put("i1", "FakeItem", f"old-{i}")
            fake.put("i1", "FakeUser", f"old-{i}")
        results.append(actions(run(path, "plan", allowAuthoritative=True, allowDelete=True)))
    assert results[0] == results[1]
    assert results[0][0] == ("Credential", "pw", "CREATE_SECRET")
    assert results[0][-3:] == [("FakeItem", f"old-{i}", "DELETE") for i in "abc"]


def test_config_errors(cfg):
    bad = [doc("FakeItem", "a", targetRef="t1", nope=1),
           doc("FakeItem", "b", targetRef="t1", credentials={"credentialRef": "pw"}),
           doc("FakeItem", "c", targetRef="missing"),
           doc("FakeUser", "d", targetRef="t1", credentials={"credentialRef": "missing", "passwordPolicy": "x"}),
           doc("Credential", "pw", providerRef="files", path="p", lifecycle={"generator": {"length": 8}}),
           doc("ReconciliationPolicy", "p", targetRef="t1", mode="authoritative"),
           doc("Target", "t9", adapter="nope")]
    with pytest.raises(ConfigError) as e:
        engine.prepare(config.load(cfg(*bad)))
    text = "\n".join(e.value.errors)
    for needle in ["unknown field spec.nope", "does not support spec.credentials", "unknown targetRef 'missing'",
                   "unknown credentialRef 'missing'", "passwordPolicy must be", "generator.length",
                   "requires spec.scope.resourceKinds", "unknown adapter 'nope'"]:
        assert needle in text


def test_file_provider_states(tmp_path):
    from ordivus.credentials import FileProvider

    p = FileProvider({"directory": str(tmp_path)})
    assert p.state({"path": "x"}) == "absent"
    assert p.state({"path": "../x"}) == "unknown"
    assert FileProvider({"directory": str(tmp_path / "no")}).state({"path": "x"}) == "unknown"
    assert p.create_if_absent({"path": "x"}, Secret("first")).reveal() == "first"
    assert p.create_if_absent({"path": "x"}, Secret("second")).reveal() == "first"  # Konflikt: Gewinner gilt
    if os.geteuid() != 0:  # root ignoriert Dateirechte
        (tmp_path / "locked").mkdir(mode=0)
        assert FileProvider({"directory": str(tmp_path / "locked")}).state({"path": "x"}) == "unknown"


def test_declared_protected_or_unmanageable_is_blocked(cfg, fake):
    fake.put("i1", "FakeItem", "sys", {"size": 1}, system=True)
    fake.put("i1", "FakeItem", "native", {"size": 1}, manageable=False)
    fake.put("i1", "FakeItem", "other", manageable=False)
    path = cfg(doc("FakeItem", "sys", targetRef="t1", attrs={"size": 1}),
               doc("FakeItem", "native", targetRef="t1", attrs={"size": 1}), doc("FakeItem", "new", targetRef="t1"))
    rep = run(path, "apply")
    ops = {o["id"]: o for o in rep["operations"]}
    assert ops["sys"]["action"] == ops["native"]["action"] == "BLOCKED"  # auch ohne Abweichung nie NOOP
    assert ops["sys"]["system"] is True and ops["native"]["manageable"] is False
    assert ops["other"]["action"] == "UNMANAGED" and ops["other"]["manageable"] is False
    assert ops["new"]["status"] == "succeeded" and fake.calls == [("i1", "CREATE", "FakeItem", "new")]
    assert report.exit_code(rep) == ExitCode.POLICY and report.exit_code(run(path, "plan")) == 0


def test_check_hook_blocks_in_plan(cfg, fake, monkeypatch):
    monkeypatch.setattr(fake, "check", lambda self, session, r, allowed: "reserved name" if r.id == "a" else None)
    path = cfg(doc("FakeItem", "a", targetRef="t1"), doc("FakeItem", "b", targetRef="t1"))
    op = run(path, "plan")["operations"][0]
    assert (op["action"], op["reason"]) == ("BLOCKED", "reserved name")
    run(path, "apply")
    assert fake.calls == [("i1", "CREATE", "FakeItem", "b")]


def test_validate_target_is_config_error(cfg, fake, monkeypatch):
    monkeypatch.setattr(fake, "validate_target", lambda self, spec, resources: [f"{len(resources)} seen"])
    with pytest.raises(ConfigError) as e:
        engine.prepare(config.load(cfg(doc("FakeItem", "a", targetRef="t1"), doc("FakeItem", "b", targetRef="t1"))))
    assert e.value.errors == [f"{cfg.secrets.parent / 'config' / '00.json'}:1: target 't1': 2 seen"]


def test_dependencies_order_and_cycle(cfg, fake, monkeypatch):
    monkeypatch.setattr(fake, "dependencies",
                        lambda self, r: [(r.kind, d) for d in r.attrs.get("after", [])])
    fake.put("i1", "FakeItem", "x")
    fake.put("i1", "FakeItem", "y", {"after": ["x"]})
    path = cfg(AUTHORITATIVE, doc("FakeItem", "a", targetRef="t1", attrs={"after": ["c"]}),
               doc("FakeItem", "b", targetRef="t1"), doc("FakeItem", "c", targetRef="t1"),
               doc("FakeItem", "d", targetRef="t1", attrs={"after": ["e"]}),
               doc("FakeItem", "e", targetRef="t1", attrs={"after": ["d"]}))
    rep = run(path, "apply", allowAuthoritative=True, allowDelete=True)
    # Abhängigkeit zuerst (sonst Namensordnung); Löschen umgekehrt; Zyklus d <-> e nie ausgeführt
    assert [(c[1], c[3]) for c in fake.calls] == [("CREATE", "b"), ("CREATE", "c"), ("CREATE", "a"),
                                                  ("DELETE", "y"), ("DELETE", "x")]
    blocked = {o["id"]: o["reason"] for o in rep["operations"] if o["action"] == "BLOCKED"}
    assert set(blocked) == {"d", "e"} and "dependency cycle" in blocked["d"]
    assert report.exit_code(rep) == ExitCode.POLICY


def test_insecure_transport_warns_or_is_refused(cfg, fake, monkeypatch, tmp_path, caplog):
    path = cfg(doc("FakeItem", "a", targetRef="t1"))
    assert "insecureTransport" not in run(path, "plan")["targets"][0]
    monkeypatch.setattr(fake, "insecure_transport", lambda self, spec: True)
    rep = run(path, "plan")
    assert rep["targets"][0]["insecureTransport"] is True and "insecure transport" in caplog.text
    with pytest.raises(PolicyError, match="requireTls"):
        run(path, "plan", requireTls=True)
    strict = tmp_path / "strict.yaml"
    strict.write_text("requireTls: true\n")
    assert main(["apply", "-f", str(path), "--policy", str(strict)]) == ExitCode.POLICY
    assert fake.calls == []


def test_verification_discovers_each_kind_once(cfg, fake, monkeypatch):
    seen = []
    original = fake.discover
    monkeypatch.setattr(fake, "discover",
                        lambda self, s, kind, scope: seen.append(kind) or original(self, s, kind, scope))
    path = cfg(*[doc("FakeItem", f"i{n}", targetRef="t1") for n in range(5)], CRED,
               *[user(f"u{n}", cred="pw") for n in range(3)])
    rep = run(path, "apply")
    assert report.exit_code(rep) == 0 and all(o["status"] == "succeeded" for o in rep["operations"])
    assert seen == ["FakeItem", "FakeUser"] * 2  # Discovery + eine Verifikation je Kind, nicht je Op


def test_lock_held_skips_all_targets(cfg, fake, monkeypatch):
    from contextlib import contextmanager

    from ordivus import adapters
    from ordivus.adapters.base import Adapter, TransientError

    class Lockless(fake):
        id = "fake-nolock"
        lock = Adapter.lock

    released = []

    @contextmanager
    def lock(self, session):
        if session.instance == "i2":
            raise TransientError("another apply holds the lock")
        try:
            yield
        finally:
            released.append(session.instance)

    adapters.register(Lockless)
    monkeypatch.setattr(fake, "lock", lock)
    path = cfg(doc("Target", "t0", adapter="fake-nolock", instance="i0"),  # ohne Lock, läuft vor t2
               doc("Target", "t2", adapter="fake", instance="i2"),
               *[doc("FakeItem", n, targetRef=t) for n, t in (("a", "t0"), ("b", "t1"), ("c", "t2"))])
    rep = run(path, "apply")
    assert fake.calls == [] and report.exit_code(rep) == ExitCode.TARGET
    status = {t["targetId"]: t for t in rep["targets"]}
    assert status["t2"]["status"] == "error" and "holds the lock" in status["t2"]["reason"]
    for name in ("t0", "t1"):
        assert status[name]["status"] == "skipped" and "lock on target(s) 't2'" in status[name]["reason"]
    assert released == ["i1"]  # vorab genommene Sperre wird freigegeben
    assert [t["status"] for t in run(path, "plan")["targets"]] == ["drift_detected"] * 3  # plan sperrt nicht
    monkeypatch.setattr(fake, "lock", Adapter.lock)
    assert report.exit_code(run(path, "apply")) == 0 and len(fake.calls) == 3


def test_changed_before_delete_or_password_reset_is_conflict(cfg, fake, monkeypatch):
    fake.put("i1", "FakeItem", "x", {"size": 1})
    fake.put("i1", "FakeItem", "y", {"size": 1})
    fake.put("i1", "FakeUser", "u1", password="old")
    original = engine.reconcile

    def racing(*args, **kwargs):  # ein anderer Writer ändert zwischen Plan und Ausführung
        ops = original(*args, **kwargs)
        fake.put("i1", "FakeItem", "x", {"size": 2})
        del fake.store["i1"]["FakeUser"]["u1"]
        return ops

    monkeypatch.setattr(engine, "reconcile", racing)
    rep = run(cfg(AUTHORITATIVE, CRED, user()), "apply", allowAuthoritative=True, allowDelete=True)
    status = {(o["id"], o["action"]): o["status"] for o in rep["operations"]}
    assert status[("x", "DELETE")] == status[("u1", "SET_PASSWORD")] == "conflict"
    assert status[("y", "DELETE")] == "succeeded"
    assert fake.calls == [("i1", "DELETE", "FakeItem", "y")]
    assert rep["targets"][0]["status"] == "partial" and report.exit_code(rep) == ExitCode.PARTIAL


def test_blocked_status_same_in_plan_and_apply(cfg, fake):
    fake.put("i1", "FakeItem", "sys", {"size": 1}, system=True)
    path = cfg(doc("FakeItem", "sys", targetRef="t1", attrs={"size": 1}))
    assert run(path, "plan")["targets"][0]["status"] == run(path, "apply")["targets"][0]["status"] == "drift_detected"


def test_pre_write_reread_once_per_kind(cfg, fake, monkeypatch):
    seen = []
    original = fake.discover
    monkeypatch.setattr(fake, "discover",
                        lambda self, s, kind, scope: seen.append(kind) or original(self, s, kind, scope))
    for n in range(3):
        fake.put("i1", "FakeUser", f"u{n}", password="old")
    path = cfg(CRED, *[user(f"u{n}", policy="enforce") for n in range(3)])
    (cfg.secrets / "u1").write_text("new")
    rep = run(path, "apply")
    assert [o["status"] for o in rep["operations"] if o["action"] == "SET_PASSWORD"] == ["succeeded"] * 3
    assert seen == ["FakeItem", "FakeUser", "FakeUser", "FakeUser"]  # Plan, ein Re-Read, eine Verifikation
