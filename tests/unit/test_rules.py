import json

import pytest
from conftest import doc

from ordivus.adapters.base import COMPLETE, PARTIAL, Discovery, Resource
from ordivus.cli import ExitCode, main
from ordivus.core import config, engine, report, rules
from ordivus.core.config import ConfigError


def evaluate(rule, *resources, status=COMPLETE, **entry):
    kind = rules.RULES[rule].kind
    return rules.evaluate("t", [{"id": rule, **entry}], {kind: Discovery(status, list(resources))})


def flagged(result):
    return [v["id"] for v in result[1]]


def user(name, **attrs):
    return Resource("DatabaseUser", name, {"createrole": False, "superuser": False, **attrs})


def grant(grantee, on="tables-in-schema", *privileges):
    attrs = {"grantee": grantee, "database": "db", "on": on, "privileges": list(privileges),
             **({"schema": "app"} if on != "database" else {})}
    return Resource("Grant", f"{grantee}/{on}", attrs)


def policy(name, hcl):
    return Resource("OpenBaoPolicy", name, {"policy": hcl})


def test_superuser_login_with_allowlist():
    found = evaluate("postgresql.superuser-login", user("postgres", superuser=True), user("ops", superuser=True),
                     user("app"), allow=["postgres"])
    assert flagged(found) == ["ops"]
    assert found[0] == [{"rule": "postgresql.superuser-login", "target": "t", "status": "complete", "violations": 1}]
    assert found[1][0]["severity"] == "critical" and "SUPERUSER" in found[1][0]["message"]


def test_createrole_login():
    assert flagged(evaluate("postgresql.createrole-login", user("a", createrole=True), user("b"))) == ["a"]


def test_table_write_grant_checks_grantee_against_allowlist():
    found = evaluate("postgresql.table-write-grant", grant("etl", "tables-in-schema", "INSERT", "SELECT"),
                     grant("reader", "tables-in-schema", "SELECT"), grant("app", "tables-in-schema", "UPDATE"),
                     grant("x", "database", "CREATE"), allow=["app"])
    assert flagged(found) == ["etl/tables-in-schema"]
    assert "INSERT on all tables in schema 'app'" in found[1][0]["message"]


def test_openbao_sudo_capability():
    found = evaluate("openbao.sudo-capability", policy("a", 'path "sys/health" { capabilities = ["sudo"] }'),
                     policy("b", 'path "secret/*" { capabilities = ["read"] }'), policy("root", ""))
    assert flagged(found) == ["a"] and found[0][0]["status"] == "complete"


@pytest.mark.parametrize("path,caps,hit", [
    ("*", ["update"], True), ("+/*", ["delete"], True), ("sys/*", ["create"], True), ("s*", ["sudo"], True),
    ("/sys/*", ["patch"], True), ("{{identity.entity.name}}/*", ["update"], True),
    ("*", ["read", "list"], False), ("sys/policies/acl/*", ["update"], False), ("secret/*", ["update"], False),
    ("sys/capabilities-self", ["update"], False),
])
def test_openbao_wildcard_write(path, caps, hit):
    hcl = f'path "{path}" {{ capabilities = {json.dumps(caps)} }}'
    assert flagged(evaluate("openbao.wildcard-write", policy("p", hcl))) == (["p"] if hit else [])


def test_unparseable_policy_and_partial_discovery_are_incomplete_not_clean():
    found = evaluate("openbao.sudo-capability", policy("weird", 'path "x" { capabilities = ["read"] } foo = 1'))
    assert found[1] == [] and found[0][0]["status"] == "incomplete" and "'weird'" in found[0][0]["reason"]
    partial = evaluate("postgresql.superuser-login", user("ops", superuser=True), status=PARTIAL)
    assert flagged(partial) == ["ops"] and partial[0][0]["status"] == "incomplete"  # Sichtbares trotzdem gemeldet
    unread = rules.evaluate("t", [{"id": "postgresql.superuser-login"}], None, "target error")
    assert unread == ([{"rule": "postgresql.superuser-login", "target": "t", "status": "incomplete",
                        "violations": 0, "reason": "target error"}], [])
    assert rules.evaluate("t", [{"id": "postgresql.superuser-login", "enabled": False}], None) == ([], [])


# --- Konfiguration und Engine (Fake-Adapter mit Test-Regel) -----------------------------------

@pytest.fixture
def fake_rule(monkeypatch):
    monkeypatch.setitem(rules.RULES, "fake.bad-item", rules.Rule(
        "fake", "FakeItem", "high", lambda r: "item is bad" if r.attrs.get("bad") else None))


def rules_doc(*entries, **spec):
    return doc("Rules", "compliance", rules=list(entries), **spec)


@pytest.mark.parametrize("spec,message", [
    ({"rules": [{"id": "nope"}]}, "unknown rule id 'nope'"),
    ({"rules": [{"id": "fake.bad-item", "allowlist": []}]}, "unknown field 'allowlist'"),
    ({"rules": [{"id": "fake.bad-item", "allow": "x"}]}, "allow must be a list of names"),
    ({"rules": [{"id": "fake.bad-item", "enabled": "yes"}]}, "enabled must be a boolean"),
    ({"rules": []}, "spec.rules must be a non-empty list"),
    ({"rules": [{"id": "fake.bad-item"}], "targetRef": "nope"}, "unknown targetRef 'nope'"),
    ({"rules": [{"id": "postgresql.superuser-login"}], "targetRef": "t1"}, "applies to adapter 'postgresql'"),
    ({"rules": [{"id": "fake.bad-item"}, {"id": "fake.bad-item", "enabled": False}]}, "more than once"),
    ({"rules": [{"id": "fake.bad-item"}], "extra": 1}, "unknown field spec.extra"),
])
def test_rules_config_errors_with_file_and_line(cfg, fake_rule, spec, message):
    path = cfg(doc("Rules", "compliance", **spec))
    with pytest.raises(ConfigError) as e:
        engine.prepare(config.load(path))
    assert any(message in err and ".json:1:" in err for err in e.value.errors), e.value.errors


def test_violations_in_plan_drift_and_apply_without_exit_change(cfg, fake, fake_rule, capsys):
    fake.put("i1", "FakeItem", "undeclared", {"bad": True})
    fake.put("i1", "FakeItem", "fine")
    fake.put("i1", "FakeItem", "accepted", {"bad": True})
    path = cfg(doc("FakeItem", "new", targetRef="t1", attrs={"bad": True}),
               rules_doc({"id": "fake.bad-item", "allow": ["accepted"]}))
    for mode in ("plan", "drift", "apply"):
        rep = engine.run(mode, config.load(path))
        # apply: ausgewertet wird der Zustand vor den Änderungen ("new" existiert da noch nicht)
        assert [v["id"] for v in rep["violations"]] == ["undeclared"], mode
        assert rep["schemaVersion"] == "1.1" and rep["summary"]["violations"] == 1
    assert main(["drift", "-f", str(path)]) == ExitCode.OK
    assert "VIOLATION [high] fake.bad-item FakeItem/undeclared: item is bad" in capsys.readouterr().out
    assert main(["drift", "-f", str(path), "--fail-on", "violations"]) == ExitCode.DRIFT
    assert main(["plan", "-f", str(path), "--fail-on", "violations"]) == ExitCode.DRIFT
    assert main(["drift", "-f", str(path), "--fail-on", "any"]) == ExitCode.DRIFT
    fake.store["i1"]["FakeItem"]["undeclared"]["attrs"]["bad"] = False
    fake.store["i1"]["FakeItem"]["new"]["attrs"]["bad"] = False
    assert main(["drift", "-f", str(path), "--fail-on", "violations"]) == ExitCode.OK


def test_unevaluated_rules_fail_the_gate(cfg, fake, fake_rule, capsys):
    path = cfg(rules_doc({"id": "fake.bad-item"}))
    fake.discovery_status[("i1", "FakeItem")] = PARTIAL
    rep = engine.run("drift", config.load(path))
    assert rep["violations"] == [] and rep["rules"][0]["status"] == "incomplete"
    assert report.exit_code(rep, "violations") == ExitCode.DRIFT
    assert main(["drift", "-f", str(path)]) == ExitCode.OK
    assert "RULE fake.bad-item not fully evaluated: discovery of FakeItem partial" in capsys.readouterr().out
    fake.discovery_status.clear()
    fake.connect_error.add("i1")
    rep = engine.run("drift", config.load(path))
    assert rep["rules"][0] == {"rule": "fake.bad-item", "target": "t1", "status": "incomplete", "violations": 0,
                               "reason": "target error"}


def test_no_rules_configured_means_no_rule_output(cfg, fake):
    fake.put("i1", "FakeItem", "x", {"bad": True})
    rep = engine.run("drift", config.load(cfg()))
    assert rep["rules"] == rep["violations"] == [] and report.exit_code(rep, "violations") == 0
