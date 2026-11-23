import copy
import json

import pytest
import yaml
from conftest import doc

from ordivus.cli import ExitCode, main
from ordivus.core import config, engine, export
from ordivus.core.config import ConfigError
from ordivus.core.policy import OperatorPolicy

TRICKY = ["no", "on", "Yes", "off", "y", "~", "null", "", "0777", "0o17", "0x1F", "1e3", "1:30", ".inf", "-.5",
          "true", "False", "2026-01-01", "12", "+1", "a: b", "- x", "#c", "'q'", "\"d\"", "ä", "  lead", "multi\nline"]


def roundtrip(tmp_path, documents, extra=()):
    """Export-YAML plus die Basis-Dokumente erneut laden und planen."""
    (tmp_path / "config" / "exported.yaml").write_text(export.dump(documents))
    for d in extra:
        (tmp_path / "config" / f"{d['metadata']['name']}.json").write_text(json.dumps(d))
    return engine.run("plan", config.load(tmp_path / "config"), OperatorPolicy())


def test_export_roundtrips_to_noop(cfg, fake, tmp_path):
    fake.put("i1", "FakeItem", "b", {"size": 1, "tags": ["x", "y"], "nested": {"z": 1, "a": "no"}})
    fake.put("i1", "FakeItem", "a", {"color": "on"})
    fake.put("i1", "FakeItem", "sys", system=True)
    fake.put("i1", "FakeItem", "ro", manageable=False)
    fake.put("i1", "FakeUser", "u1", {"login": True}, password="secret-pw-123")
    before = copy.deepcopy(fake.store)
    result = export.run(config.load(cfg()))
    assert fake.store == before and fake.calls == []  # nur lesend
    assert [(d["kind"], d["metadata"]["name"]) for d in result.documents] == [
        ("FakeItem", "a"), ("FakeItem", "b"), ("FakeUser", "u1")]
    assert not result.incomplete
    text = export.dump(result.documents)
    assert "secret-pw-123" not in text and "credentials" not in text
    rep = roundtrip(tmp_path, result.documents)
    ops = [(o["kind"], o["id"], o["action"]) for o in rep["operations"]]
    assert ("FakeItem", "a", "NOOP") in ops and ("FakeItem", "b", "NOOP") in ops and ("FakeUser", "u1", "NOOP") in ops
    assert not {o["action"] for o in rep["operations"]} & set(engine.MUTATING)


def test_tricky_strings_survive_yaml_1_1_and_1_2():
    spec = {"l": TRICKY, "k": {t: t for t in TRICKY}}  # auch Schlüssel wie `on` müssen Strings bleiben
    data = [{"apiVersion": "x", "kind": "K", "metadata": {"name": s}, "spec": {"v": s, **spec}} for s in TRICKY]
    text = export.dump(data)
    assert list(yaml.safe_load_all(text)) == data  # YAML 1.1 (PyYAML default)
    loader = config._Loader(text)  # YAML 1.2 Core wie der Config-Loader
    try:
        parsed = []
        while loader.check_node():
            parsed.append(loader.construct_document(loader.get_node()))
    finally:
        loader.dispose()
    assert parsed == data


def test_partial_discovery_and_target_error_are_incomplete(cfg, fake, tmp_path, capsys):
    fake.put("i1", "FakeItem", "a", {"size": 1})
    fake.discovery_status[("i1", "FakeItem")] = "partial"
    path = cfg()
    assert main(["export", "-f", str(path)]) == ExitCode.TARGET
    out, err = capsys.readouterr()
    assert "name: a" in out and "partial" in err
    fake.connect_error.add("i1")
    assert main(["export", "-f", str(path)]) == ExitCode.TARGET


def test_cli_filters_output_file_and_exclusions(cfg, fake, tmp_path, capsys):
    fake.put("i1", "FakeItem", "a")
    fake.put("i1", "FakeItem", "skip-me")
    fake.put("i1", "FakeUser", "u1")
    path = cfg(doc("ReconciliationPolicy", "p", targetRef="t1", exclusions={"FakeItem": {"glob": ["skip-*"]}}))
    out = tmp_path / "out.yaml"
    assert main(["export", "-f", str(path), "--kind", "FakeItem", "--target", "t1", "-o", str(out)]) == 0
    names = [d["metadata"]["name"] for d in yaml.safe_load_all(out.read_text())]
    assert names == ["a"] and out.stat().st_mode & 0o777 == 0o600
    assert main(["export", "-f", str(path), "--kind", "Nope"]) == ExitCode.CONFIG
    assert main(["export", "-f", str(path), "--target", "nope"]) == ExitCode.CONFIG


def test_user_needs_credentials_note_and_no_secret_in_output(cfg, fake, capsys):
    fake.put("i1", "FakeUser", "u1", password="pw-canary-xyz")
    assert main(["export", "-f", str(cfg())]) == 0
    out, err = capsys.readouterr()
    assert "pw-canary-xyz" not in out + err
    assert "FakeUser 'u1': password not exported" in err


def test_not_roundtripping_object_is_skipped(cfg, fake, monkeypatch):
    fake.put("i1", "FakeItem", "a", {"size": 1})
    monkeypatch.setattr(fake, "export", lambda self, r: {"attrs": {"size": 2}})
    result = export.run(config.load(cfg()))
    assert result.documents == [] and result.incomplete


def test_same_name_on_two_targets_is_reported(cfg, fake):
    fake.put("i1", "FakeItem", "a")
    fake.put("i2", "FakeItem", "a")
    result = export.run(config.load(cfg(doc("Target", "t2", adapter="fake", instance="i2"))))
    assert len(result.documents) == 1 and result.incomplete


def test_policy_preflight_applies(cfg, tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("allowTargets: [other]\n")
    assert main(["export", "-f", str(cfg()), "--policy", str(policy)]) == ExitCode.POLICY
    with pytest.raises(ConfigError):
        export.run(config.load(cfg()), only=["missing"])


def test_adapter_bug_marks_export_incomplete(cfg, fake, monkeypatch):
    fake.put("i1", "FakeItem", "a")
    monkeypatch.setattr(fake, "export", lambda self, r: 1 / 0)
    assert export.run(config.load(cfg())).incomplete
