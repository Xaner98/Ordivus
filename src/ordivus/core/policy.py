"""Operator Security Policy (§11.6): separat bereitgestellt, nicht durch die Config übersteuerbar."""

from dataclasses import dataclass, fields
from pathlib import Path

from ordivus.core import config


class PolicyError(Exception):
    """Policy-Verstoß oder unlesbare Policy (fail closed, Exit-Code 11)."""


@dataclass(frozen=True)
class OperatorPolicy:
    """Ohne Policy-Datei: alle Targets, nur additive, kein Delete, Passwort-Reset erlaubt."""

    allowTargets: tuple[str, ...] = ("*",)
    allowAuthoritative: bool = False
    allowDelete: bool = False
    allowPasswordReset: bool = True
    profile: str = "standard"

    def allows_target(self, name: str) -> bool:
        return "*" in self.allowTargets or name in self.allowTargets


def load(path: str | Path) -> OperatorPolicy:
    path = Path(path)
    try:
        if not path.is_file():
            raise PolicyError(f"{path}: policy file not found")
        docs = config.read_documents(path)
    except config.ConfigError as e:
        raise PolicyError("\n".join(e.errors)) from None
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise PolicyError(f"{path}: policy must be exactly one mapping")
    data, known = docs[0], {f.name for f in fields(OperatorPolicy)}
    errors = [f"{path}: unknown policy field {k!r}" for k in data if k not in known]
    targets = data.get("allowTargets", ["*"])
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        errors.append(f"{path}: allowTargets must be a list of strings")
    for key in ("allowAuthoritative", "allowDelete", "allowPasswordReset"):
        if not isinstance(data.get(key, False), bool):
            errors.append(f"{path}: {key} must be a boolean")
    if data.get("profile", "standard") not in ("development", "standard"):
        errors.append(f"{path}: profile must be 'development' or 'standard'")
    if errors:
        raise PolicyError("\n".join(errors))
    return OperatorPolicy(**{**data, "allowTargets": tuple(targets)})
