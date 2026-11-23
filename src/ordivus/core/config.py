"""Laden und Grundvalidierung von Ordivus-Konfigurationen (YAML/JSON, Datei oder Verzeichnis)."""

import hashlib
import json
import re
from collections.abc import Hashable
from dataclasses import dataclass
from pathlib import Path

import yaml

from ordivus import adapters

API_VERSION = "ordivus.dev/v1alpha1"
ENGINE_KINDS = frozenset({"Target", "CredentialProvider", "Credential", "ReconciliationPolicy"})
TOP_LEVEL_FIELDS = frozenset({"apiVersion", "kind", "metadata", "spec"})
SUFFIXES = (".yaml", ".yml", ".json")
MAX_FILE_BYTES = 1024 * 1024


class ConfigError(Exception):
    """Konfigurationsfehler; `errors` enthält Meldungen der Form `pfad:zeile: text`."""

    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Document:
    data: dict
    path: Path
    line: int

    @property
    def kind(self) -> str:
        return self.data["kind"]

    @property
    def name(self) -> str:
        return self.data["metadata"]["name"]


class _Loader(yaml.SafeLoader):
    """SafeLoader mit YAML-1.2-Core-Schema: `no`/`on`/`0777`/`1:30`/Daten bleiben ohne Falle."""

    yaml_implicit_resolvers = {}  # PyYAMLs 1.1-Resolver vollständig verwerfen

    def compose_node(self, parent, index):
        # Aliase werden abgelehnt: verhindert Expansion-Bomben ("billion laughs") und
        # versteckte Mehrfachverwendung; Konfigurationen sollen explizit lesbar sein.
        if self.check_event(yaml.AliasEvent):
            mark = self.peek_event().start_mark
            raise yaml.MarkedYAMLError(None, None, "aliases are not allowed", mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                break  # super() meldet unhashbare Schlüssel selbst
            if key in seen:
                raise yaml.MarkedYAMLError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)

    def construct_yaml_int(self, node):
        value = self.construct_scalar(node)
        return int(value, 0) if value.lstrip("+-")[:2] in ("0o", "0x") else int(value)


_Loader.add_constructor("tag:yaml.org,2002:int", _Loader.construct_yaml_int)
# Reihenfolge zählt: int vor float, da die float-Regex auch reine Ziffern trifft.
for _tag, _regex, _first in [
    ("bool", r"true|True|TRUE|false|False|FALSE", "tTfF"),
    ("int", r"[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+", "-+0123456789"),
    ("float", r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
              r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)", "-+.0123456789"),
    ("null", r"~|null|Null|NULL|", ["~", "n", "N", ""]),
]:
    _Loader.add_implicit_resolver(
        f"tag:yaml.org,2002:{_tag}", re.compile(rf"^(?:{_regex})$"), list(_first)
    )


def _files(path: Path) -> list[Path]:
    if path.is_dir():
        # Punkt-Pfade auslassen: ConfigMap-Mounts spiegeln jede Datei in ..data/ und ..<zeitstempel>/
        return sorted(p for p in path.rglob("*") if p.suffix in SUFFIXES and p.is_file()
                      and not any(part.startswith(".") for part in p.relative_to(path).parts))
    return [path]


def _parse_file(path: Path) -> list[Document]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ConfigError([f"{path}: file exceeds {MAX_FILE_BYTES} bytes"])
    # JSON ist eine Teilmenge von YAML 1.2; ein Parser liefert Zeilennummern für beide Formate.
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ConfigError([f"{path}: not valid UTF-8: {e}"]) from None
    loader = _Loader(text)
    docs = []
    try:
        while loader.check_node():
            node = loader.get_node()
            docs.append(Document(loader.construct_document(node), path, node.start_mark.line + 1))
    except yaml.MarkedYAMLError as e:
        if e.problem_mark is None:
            raise ConfigError([f"{path}: {e}"]) from None
        raise ConfigError([f"{path}:{e.problem_mark.line + 1}: {e.problem}"]) from None
    except yaml.YAMLError as e:
        raise ConfigError([f"{path}: {e}"]) from None
    finally:
        loader.dispose()
    return [d for d in docs if d.data is not None]  # leere Dokumente (z. B. trailing ---)


def _check(doc: Document, kinds: frozenset[str]) -> list[str]:
    where = f"{doc.path}:{doc.line}"
    data = doc.data
    if not isinstance(data, dict):
        return [f"{where}: document must be a mapping"]
    errors = [f"{where}: unknown top-level field {k!r}" for k in data if k not in TOP_LEVEL_FIELDS]
    if data.get("apiVersion") != API_VERSION:
        errors.append(f"{where}: apiVersion must be {API_VERSION!r}, got {data.get('apiVersion')!r}")
    if data.get("kind") not in kinds:
        errors.append(f"{where}: unknown or missing kind {data.get('kind')!r}")
    metadata = data.get("metadata")
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if not isinstance(name, str) or not name:
        errors.append(f"{where}: metadata.name must be a non-empty string")
    return errors


def load(path: str | Path, kinds: frozenset[str] | None = None) -> list[Document]:
    """Lädt Datei oder Verzeichnis; wirft ConfigError mit allen gefundenen Fehlern.

    `kinds`: erlaubte Kinds; Default sind Engine-Kinds plus Kinds aller registrierten Adapter.
    """
    if kinds is None:
        kinds = ENGINE_KINDS | adapters.all_kinds()
    path = Path(path)
    if not path.exists():
        raise ConfigError([f"{path}: no such file or directory"])
    docs, errors = [], []
    for file in _files(path):
        try:
            docs.extend(_parse_file(file))
        except ConfigError as e:
            errors.extend(e.errors)
    valid = []
    for doc in docs:
        problems = _check(doc, kinds)
        errors.extend(problems)
        if not problems:
            valid.append(doc)
    first_seen = {}
    for doc in valid:
        key = (doc.kind, doc.name)
        if key in first_seen:
            errors.append(f"{doc.path}:{doc.line}: duplicate {doc.kind} {doc.name!r} "
                          f"(first defined at {first_seen[key]})")
        else:
            first_seen[key] = f"{doc.path}:{doc.line}"
    if errors:
        raise ConfigError(errors)
    if not valid:
        raise ConfigError([f"{path}: no configuration documents found"])
    return valid


def digest(docs: list[Document]) -> str:
    """sha256 über kanonisches JSON; unabhängig von Datei- und Schlüsselreihenfolge."""
    ordered = [d.data for d in sorted(docs, key=lambda d: (d.kind, d.name))]
    canonical = json.dumps(ordered, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def read_documents(path: str | Path) -> list:
    """Rohdaten aller Dokumente einer YAML/JSON-Datei ohne Schema-Prüfung (z. B. Operator-Policy)."""
    return [d.data for d in _parse_file(Path(path))]
