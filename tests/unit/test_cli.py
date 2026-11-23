from pathlib import Path

import pytest

from ordivus.cli import ExitCode, main

EXAMPLE = Path(__file__).parents[2] / "examples" / "basic"


def test_validate_ok(capsys):
    assert main(["config", "validate", "-f", str(EXAMPLE)]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "Target: 1" in out and "digest: sha256:" in out


def test_validate_invalid(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text("kind: Nope\n")
    assert main(["config", "validate", "-f", str(tmp_path)]) == ExitCode.CONFIG
    captured = capsys.readouterr()
    assert captured.out == "" and "bad.yaml:1:" in captured.err


def test_validate_missing_path(tmp_path):
    assert main(["config", "validate", "-f", str(tmp_path / "nope")]) == ExitCode.CONFIG


@pytest.mark.parametrize("cmd", ["plan", "drift", "apply"])
def test_stubs_not_implemented(cmd):
    assert main([cmd, "-f", "x", "--format", "json"]) == ExitCode.INTERNAL


@pytest.mark.parametrize("argv", [[], ["config", "validate"], ["plan", "-f", "x", "--format", "xml"]])
def test_bad_args_exit_2(argv):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.startswith("ordivus ")
