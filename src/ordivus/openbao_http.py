"""Minimaler OpenBao-HTTP-Client (urllib), geteilt von Credential Provider und Policy-Adapter.

Nur Transport: liefert ``(status, json)``. Netzwerkfehler/Timeouts werden zu ``TransientError``;
die Abbildung der HTTP-Status auf Fachzustände macht der Aufrufer. Token nur im Header, nie in
URL oder Meldung.
"""

import json
import ssl
import time
import urllib.error
import urllib.request

from ordivus.adapters.base import AuthorizationError, PermanentError, TransientError

TIMEOUT = 10
RETRIES = 3


def tls_context(tls: dict | None) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=(tls or {}).get("caFile"))


def request(url: str, method: str, path: str, token: str | None = None, body: dict | None = None,
            namespace: str | None = None, ctx: ssl.SSLContext | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{url.rstrip('/')}/v1/{path}", data, headers, method=method)
    for attempt in range(RETRIES if method == "GET" else 1):  # nur lesende Anfragen sind gefahrlos wiederholbar
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                status, raw = resp.status, resp.read()
            break
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
            break
        except (OSError, ValueError) as e:  # URLError, Timeout, TLS-Fehler, ungültige URL
            if attempt == RETRIES - 1 or method != "GET" or isinstance(e, ValueError | ssl.SSLError):
                raise TransientError(f"openbao {method} {path}: {type(e).__name__}") from None
            time.sleep(0.2 * (attempt + 1))
    try:
        return status, json.loads(raw) if raw else {}
    except ValueError:
        return status, {}


def check(status: int, body: dict, what: str) -> dict:
    """Bildet HTTP-Fehler auf Adapterfehler ab (5xx transient, 401/403 Rechte, sonst permanent)."""
    if status < 300:
        return body
    errors = "; ".join(str(e) for e in body.get("errors", []))[:300]
    message = f"{what}: HTTP {status}" + (f" ({errors})" if errors else "")
    if status >= 500:
        raise TransientError(message)
    if status in (401, 403):
        raise AuthorizationError(message)
    raise PermanentError(message)
