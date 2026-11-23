"""Gemeinsame Bausteine für Adapter: TLS-Kontext, Endpoint-Validierung, Scope-Globs.

HTTP-Transport und HTTP-Status-Abbildung liegen in ``ordivus.net``.
"""

import fnmatch
import re
import ssl

from ordivus.adapters.base import PermanentError

# Zeichen, die in einem Hostnamen eine URL/DSN umdeuten könnten (Pfad, Userinfo, Query, IPv6-Klammern)
HOST_FORBIDDEN = re.compile(r"[/@?#\\\[\]\s]")


def tls_context(tls: dict | None) -> ssl.SSLContext:
    """Verifizierender TLS-Kontext, optional mit ``tls.caFile``; unlesbare/ungültige CA → PermanentError."""
    cafile = (tls or {}).get("caFile")
    try:
        return ssl.create_default_context(cafile=cafile)
    except (OSError, ssl.SSLError, ValueError) as e:
        raise PermanentError(f"cannot load tls.caFile {cafile!r}: {type(e).__name__}") from None


def validate_endpoint(endpoint, extra=(), tls_fields=("caFile",)) -> list[str]:
    """Prüft ``spec.endpoint``: ``host``, ``port`` (1-65535), ``tls`` (Felder ``tls_fields``, ``caFile``
    als String) und unbekannte Felder; ``extra`` sind weitere erlaubte Endpoint-Felder, die der Aufrufer prüft."""
    if not isinstance(endpoint, dict):
        return ["spec.endpoint must be a mapping"]
    errors = [f"unknown field spec.endpoint.{k}" for k in endpoint if k not in {"host", "port", "tls", *extra}]
    host = endpoint.get("host")
    if not isinstance(host, str) or not host or HOST_FORBIDDEN.search(host):
        errors.append("spec.endpoint.host must be a host name or IP address (no '/', '\\', '@', '?', '#', '[', ']', "
                      "whitespace)")
    if "port" in endpoint and (type(endpoint["port"]) is not int or not 0 < endpoint["port"] < 65536):
        errors.append("spec.endpoint.port must be an integer 1-65535")
    tls = endpoint.get("tls", {})
    if not isinstance(tls, dict):
        return [*errors, "spec.endpoint.tls must be a mapping"]
    errors += [f"unknown field spec.endpoint.tls.{k}" for k in tls if k not in tls_fields]
    if "caFile" in tls and (not isinstance(tls["caFile"], str) or not tls["caFile"]):
        errors.append("spec.endpoint.tls.caFile must be a non-empty string")
    return errors


def in_scope(scope: dict | None, key: str, name: str) -> bool:
    """Ob ``name`` in ``scope[key].include`` (Globs, case-sensitiv) liegt; fehlender Filter = alles."""
    include = ((scope or {}).get(key) or {}).get("include")
    return include is None or any(fnmatch.fnmatchcase(name, g) for g in include)
