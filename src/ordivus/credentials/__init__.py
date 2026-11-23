"""Eingebaute Credential Provider: ``file`` (Verzeichnis + Dateiname) und ``env`` (nur Development)."""

import logging
import os
from pathlib import Path

from ordivus.adapters.base import Secret
from ordivus.credentials.base import ABSENT, PRESENT, UNKNOWN, CredentialError, CredentialProvider

log = logging.getLogger("ordivus")


def _only(spec: dict, allowed: set[str]) -> list[str]:
    return [f"unknown field spec.{k}" for k in spec if k not in allowed]


class FileProvider(CredentialProvider):
    """Ein Secret pro Datei in ``spec.directory``; ``Credential.spec.path`` ist der Dateiname."""

    type = "file"

    @classmethod
    def validate(cls, spec):
        errors = _only(spec, {"directory"})
        if not isinstance(spec.get("directory"), str) or not spec.get("directory"):
            errors.append("spec.directory must be a non-empty string")
        return errors

    def _file(self, ref) -> Path:
        name = ref["path"]
        if Path(name).name != name or name in (".", ".."):  # keine Pfade aus dem Verzeichnis heraus
            raise CredentialError(f"credential path {name!r} must be a plain file name")
        return Path(self.spec["directory"]) / name

    def state(self, ref):
        try:
            file = self._file(ref)
            return PRESENT if file.is_file() else UNKNOWN if file.exists() else (
                ABSENT if file.parent.is_dir() and os.access(file.parent, os.R_OK | os.X_OK) else UNKNOWN)
        except (OSError, CredentialError):
            return UNKNOWN

    def read(self, ref):
        try:
            text = self._file(ref).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise CredentialError(f"cannot read credential {ref['path']!r}: {type(e).__name__}") from None
        return Secret(text.removesuffix("\n"))

    def create_if_absent(self, ref, value):
        try:
            fd = os.open(self._file(ref), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self.read(ref)  # konkurrierender Lauf war schneller: dessen Wert gilt
        except OSError as e:
            raise CredentialError(f"cannot create credential {ref['path']!r}: {type(e).__name__}") from None
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value.reveal())
        return value


class EnvProvider(CredentialProvider):
    """Liest Umgebungsvariablen (``Credential.spec.path`` = Variablenname). Nur Development."""

    type = "env"
    development_only = True

    def __init__(self, spec):
        super().__init__(spec)
        log.warning("credential provider 'env' is for development only")

    @classmethod
    def validate(cls, spec):
        return _only(spec, set())

    def state(self, ref):
        return PRESENT if ref["path"] in os.environ else ABSENT

    def read(self, ref):
        if ref["path"] not in os.environ:
            raise CredentialError(f"environment variable {ref['path']!r} not set")
        return Secret(os.environ[ref["path"]])


PROVIDERS: dict[str, type[CredentialProvider]] = {p.type: p for p in (FileProvider, EnvProvider)}
