import math

import pytest

from ordivus.core import config


def _value(tmp_path, scalar):
    f = tmp_path / "v.yaml"
    f.write_text(
        f"apiVersion: ordivus.dev/v1alpha1\nkind: Target\nmetadata:\n  name: t\nspec:\n  v: {scalar}\n"
    )
    return config.load(f)[0].data["spec"]["v"]


@pytest.mark.parametrize(
    "scalar, expected",
    [
        ("no", "no"), ("yes", "yes"), ("on", "on"), ("off", "off"), ("y", "y"), ("n", "n"),
        ("0777", 777), ("1:30", "1:30"), ("2026-11-23", "2026-11-23"), ("0o17", 15),
        ("0x1F", 31), ("-12", -12), ("1_000", "1_000"), ("true", True), ("False", False),
        ("TRUE", True), ("null", None), ("~", None), ("", None), ("1.5", 1.5), ("1e3", 1000.0),
        (".inf", math.inf), ("-.Inf", -math.inf), ("'no'", "no"), ("<<", "<<"),
    ],
)
def test_yaml_12_core_schema(tmp_path, scalar, expected):
    assert _value(tmp_path, scalar) == expected
    assert type(_value(tmp_path, scalar)) is type(expected)


def test_nan(tmp_path):
    assert math.isnan(_value(tmp_path, ".nan"))


def _errors(tmp_path, text, name="c.yaml"):
    f = tmp_path / name
    f.write_text(text)
    with pytest.raises(config.ConfigError) as e:
        config.load(tmp_path)
    return e.value.errors


HEAD = "apiVersion: ordivus.dev/v1alpha1\nkind: Target\n"


def test_duplicate_key_reports_line(tmp_path):
    errors = _errors(tmp_path, HEAD + "metadata:\n  name: a\n  name: b\n")
    assert errors == [f"{tmp_path / 'c.yaml'}:5: duplicate key 'name'"]


def test_alias_rejected(tmp_path):
    errors = _errors(tmp_path, HEAD + "metadata: &m\n  name: a\nspec:\n  x: *m\n")
    assert errors == [f"{tmp_path / 'c.yaml'}:6: aliases are not allowed"]


def test_missing_name_reports_file_and_line(tmp_path):
    errors = _errors(tmp_path, HEAD + "metadata:\n  name: a\n---\n" + HEAD + "metadata: {}\n")
    assert errors == [f"{tmp_path / 'c.yaml'}:6: metadata.name must be a non-empty string"]


def test_structural_errors(tmp_path):
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: 7\nextra: 1\n"
    errors = _errors(tmp_path, text)
    assert len(errors) == 4
    assert all(e.startswith(f"{tmp_path / 'c.yaml'}:1: ") for e in errors)


def test_duplicate_kind_name_across_files(tmp_path):
    (tmp_path / "a.yaml").write_text(HEAD + "metadata:\n  name: a\n")
    errors = _errors(tmp_path, HEAD + "metadata:\n  name: a\n", name="b.yml")
    assert len(errors) == 1 and "duplicate Target 'a'" in errors[0]


def test_file_size_limit(tmp_path):
    errors = _errors(tmp_path, HEAD + "#" * config.MAX_FILE_BYTES)
    assert "exceeds" in errors[0]


def test_json_file(tmp_path):
    f = tmp_path / "c.json"
    f.write_text('{"apiVersion":"ordivus.dev/v1alpha1","kind":"Grant","metadata":{"name":"g"}}')
    assert config.load(f, kinds=frozenset({"Grant"}))[0].name == "g"


def test_digest_independent_of_file_and_key_order(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "a.yaml").write_text(HEAD + "metadata:\n  name: a\nspec: {x: 1, y: 2}\n")
    (one / "b.yaml").write_text(HEAD + "metadata:\n  name: b\n")
    (two / "a.yaml").write_text(HEAD + "metadata:\n  name: b\n")
    (two / "sub").mkdir()
    (two / "sub" / "z.yaml").write_text(
        "spec: {y: 2, x: 1}\nmetadata:\n  name: a\nkind: Target\napiVersion: ordivus.dev/v1alpha1\n"
    )
    assert config.digest(config.load(one)) == config.digest(config.load(two))
    (two / "a.yaml").write_text(HEAD + "metadata:\n  name: c\n")
    assert config.digest(config.load(one)) != config.digest(config.load(two))



def test_configmap_mount_hidden_dirs_skipped(tmp_path):
    """Kubernetes-ConfigMap-Layout: Dateien als Symlinks auf ..data → ..<zeitstempel>/."""
    text = "apiVersion: ordivus.dev/v1alpha1\nkind: Target\nmetadata:\n  name: t\nspec: {}\n"
    stamp = tmp_path / "..2026_11_23_10_00_00.123"
    stamp.mkdir()
    (stamp / "a.yaml").write_text(text)
    (tmp_path / "..data").symlink_to(stamp.name)
    (tmp_path / "a.yaml").symlink_to("..data/a.yaml")
    (tmp_path / ".hidden.yaml").write_text("not: [valid")
    docs = config.load(tmp_path)
    assert [d.path.name for d in docs] == ["a.yaml"] and docs[0].path.parent == tmp_path
