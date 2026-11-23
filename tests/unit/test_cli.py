import json

import pytest
from conftest import doc

from ordivus.cli import ExitCode, main


def test_validate_ok(cfg, capsys):
    assert main(["config", "validate", "-f", str(cfg(doc("FakeItem", "a", targetRef="t1")))]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "Target: 1" in out and "digest: sha256:" in out


def test_validate_semantic_error(cfg, capsys):
    assert main(["config", "validate", "-f", str(cfg(doc("FakeItem", "a", targetRef="nope")))]) == ExitCode.CONFIG
    assert "unknown targetRef 'nope'" in capsys.readouterr().err


def test_validate_invalid(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text("kind: Nope\n")
    assert main(["config", "validate", "-f", str(tmp_path)]) == ExitCode.CONFIG
    captured = capsys.readouterr()
    assert captured.out == "" and "bad.yaml:1:" in captured.err


def test_validate_missing_path(tmp_path):
    assert main(["config", "validate", "-f", str(tmp_path / "nope")]) == ExitCode.CONFIG


@pytest.mark.parametrize("argv", [[], ["config", "validate"], ["plan", "-f", "x", "--format", "xml"],
                                  ["drift", "-f", "x", "--fail-on", "changes"]])
def test_bad_args_exit_2(argv):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.startswith("ordivus ")


def test_json_lines_report(cfg, capsys):
    path = cfg(doc("FakeItem", "a", targetRef="t1", attrs={"size": 1}))
    assert main(["plan", "-f", str(path), "--format", "json"]) == ExitCode.OK
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    rep = json.loads(lines[0])
    assert rep["type"] == "report" and rep["secretsIncluded"] is False and rep["run"]["mode"] == "plan"
    assert rep["run"]["identity"] == {"value": None, "source": "unknown"}
    assert rep["operations"][0]["action"] == "CREATE"


def test_output_file(cfg, tmp_path, capsys):
    out = tmp_path / "plan.txt"
    assert main(["plan", "-f", str(cfg()), "--output", str(out)]) == ExitCode.OK
    assert capsys.readouterr().out == "" and "target t1" in out.read_text()


def test_exit_codes(cfg, fake, tmp_path, capsys):
    path = cfg(doc("FakeItem", "a", targetRef="t1"))
    assert main(["drift", "-f", str(path)]) == ExitCode.OK
    assert main(["drift", "-f", str(path), "--fail-on", "actionable"]) == ExitCode.DRIFT
    assert main(["plan", "-f", str(path), "--fail-on", "changes"]) == ExitCode.DRIFT
    assert main(["apply", "-f", str(path), "--target", "nope"]) == ExitCode.CONFIG
    assert main(["apply", "-f", str(path)]) == ExitCode.OK
    assert main(["drift", "-f", str(path), "--fail-on", "any"]) == ExitCode.OK
    fake.put("i1", "FakeItem", "x")
    assert main(["drift", "-f", str(path), "--fail-on", "actionable"]) == ExitCode.OK
    assert main(["drift", "-f", str(path), "--fail-on", "unmanaged"]) == ExitCode.DRIFT
    fake.connect_error.add("i1")
    assert main(["plan", "-f", str(path)]) == ExitCode.TARGET


def test_policy_exit_codes(cfg, tmp_path, capsys):
    deny = tmp_path / "deny.yaml"
    deny.write_text("allowTargets: [other]\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("allowDelete: yes\n")  # YAML 1.2: "yes" ist ein String
    path = cfg(doc("FakeItem", "a", targetRef="t1"))
    assert main(["plan", "-f", str(path), "--policy", str(deny)]) == ExitCode.POLICY
    assert main(["plan", "-f", str(path), "--policy", str(bad)]) == ExitCode.POLICY
    assert main(["plan", "-f", str(path), "--policy", str(tmp_path / "missing.yaml")]) == ExitCode.POLICY
    env = cfg(doc("CredentialProvider", "dev", type="env"))
    assert main(["plan", "-f", str(env)]) == ExitCode.POLICY
    dev = tmp_path / "dev.json"
    dev.write_text('{"profile": "development"}')
    assert main(["plan", "-f", str(env), "--policy", str(dev)]) == ExitCode.OK
    err = capsys.readouterr().err
    assert "development only" in err and "not allowed by operator policy" in err
