"""Eingebaute Credential Provider: ``file`` (Verzeichnis + Dateiname) und ``env`` (nur Development)."""

import logging
import os
import secrets
import stat
from pathlib import Path

from ordivus.adapters.base import Secret
from ordivus.credentials.base import ABSENT, PRESENT, UNKNOWN, CredentialError, CredentialProvider, State
from ordivus.credentials.openbao import OpenBaoKV2Provider

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
            try:
                mode = os.lstat(file).st_mode
            except FileNotFoundError:  # nur ein wirklich fehlender Eintrag ist "absent", kein kaputter Symlink
                if file.parent.is_dir() and os.access(file.parent, os.R_OK | os.X_OK):
                    return ABSENT
                return State(UNKNOWN, "credential directory missing or not readable")
            if stat.S_ISLNK(mode):
                try:
                    mode = os.stat(file).st_mode
                except OSError as e:
                    return State(UNKNOWN, f"credential {ref['path']!r} is a broken symlink ({type(e).__name__})")
            if stat.S_ISREG(mode):
                return PRESENT
            return State(UNKNOWN, f"credential {ref['path']!r} exists but is not a regular file")
        except CredentialError as e:
            return State(UNKNOWN, str(e))
        except OSError as e:
            return State(UNKNOWN, f"cannot inspect credential {ref['path']!r}: {type(e).__name__}")

    def read(self, ref):
        try:
            fd = os.open(self._file(ref), os.O_RDONLY | os.O_NONBLOCK)  # FIFO darf nicht blockieren
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise CredentialError(f"credential {ref['path']!r} is not a regular file")
                text = f.read().decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise CredentialError(f"cannot read credential {ref['path']!r}: {type(e).__name__}") from None
        return Secret(text.removesuffix("\n"))

    def create_if_absent(self, ref, value):
        """Atomar: Temp-Datei (0600) schreiben und fsyncen, dann per ``link`` unter dem Zielnamen
        veröffentlichen (scheitert, falls er existiert). Ein Abbruch hinterlässt nie eine leere Datei."""
        final = self._file(ref)
        tmp = final.with_name(f".{final.name}.{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(value.reveal())
                    f.flush()
                    os.fsync(f.fileno())
                os.link(tmp, final)
            finally:
                tmp.unlink(missing_ok=True)
        except FileExistsError:
            return self.read(ref)  # konkurrierender Lauf war schneller: dessen Wert gilt
        except OSError as e:
            raise CredentialError(f"cannot create credential {ref['path']!r}: {type(e).__name__}") from None
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
        return PRESENT if ref["path"] in os.environ else State(ABSENT, f"environment variable {ref['path']!r} not set")

    def read(self, ref):
        if ref["path"] not in os.environ:
            raise CredentialError(f"environment variable {ref['path']!r} not set")
        return Secret(os.environ[ref["path"]])


PROVIDERS: dict[str, type[CredentialProvider]] = {p.type: p for p in (FileProvider, EnvProvider, OpenBaoKV2Provider)}
