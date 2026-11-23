"""Credential-Provider-Vertrag und Passwortgenerator (§10).

Ein Provider wird aus ``CredentialProvider.spec`` gebaut. ``ref`` ist jeweils die ``spec`` eines
``Credential``-Dokuments (``providerRef``, ``path``, optional ``lifecycle``).
"""

import secrets
import string

from ordivus.adapters.base import Secret

PRESENT, ABSENT, UNKNOWN, CONFLICT = "present", "absent", "unknown", "conflict"
ALPHABETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "alphanumeric-symbol-safe": string.ascii_letters + string.digits + "-_.~",
}
MIN_LENGTH = 16


class State(str):
    """Zustand mit Begründung; vergleicht wie der Status-String (``State(UNKNOWN, "x") == UNKNOWN``)."""

    reason: str

    def __new__(cls, status: str, reason: str = ""):
        state = super().__new__(cls, status)
        state.reason = reason
        return state


class CredentialError(Exception):
    """Provider-Fehler; die Meldung enthält nie den Secret-Wert."""


class CredentialProvider:
    type: str
    development_only = False

    def __init__(self, spec: dict):
        self.spec = spec

    @classmethod
    def validate(cls, spec: dict) -> list[str]:
        """Prüft die Provider-Spec (ohne ``type``); unbekannte Felder sind Fehler."""
        return []

    def state(self, ref: dict) -> str:
        """``present``/``absent``/``unknown``/``conflict``; ``absent`` nur bei positivem Beweis.

        ``conflict``: Zustand bekannt, aber nur manuell lösbar (z. B. gelöschte aktuelle Version).
        Ein ``State`` statt des reinen Strings trägt die Begründung in den Report.
        """
        raise NotImplementedError

    def read(self, ref: dict) -> Secret:
        """Liest den Wert; wirft CredentialError, wenn das nicht geht."""
        raise NotImplementedError

    def create_if_absent(self, ref: dict, value: Secret) -> Secret:
        """Schreibt ``value`` nur, wenn nichts existiert; liefert den gültigen (ggf. fremden) Wert."""
        raise CredentialError(f"provider {self.type!r} is read-only")


def generate(length: int = 32, alphabet: str = "alphanumeric") -> Secret:
    """Zufallspasswort aus dem OS-CSPRNG."""
    chars = ALPHABETS[alphabet]
    return Secret("".join(secrets.choice(chars) for _ in range(length)))
