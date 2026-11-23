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

from ordivus import net
from ordivus.adapters.base import TransientError

TIMEOUT = 10
RETRIES = 3


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
            with net.urlopen(req, TIMEOUT, ctx) as resp:
                status, raw = resp.status, net.read(resp)
            break
        except urllib.error.HTTPError as e:
            status, raw = e.code, net.read(e)
            break
        except (OSError, ValueError) as e:  # URLError, Timeout, TLS-Fehler, ungültige URL
            if attempt == RETRIES - 1 or method != "GET" or isinstance(e, ValueError | ssl.SSLError):
                raise TransientError(f"openbao {method} {path}: {type(e).__name__}") from None
            time.sleep(0.2 * (attempt + 1))
    try:
        body = json.loads(raw) if raw else {}
    except ValueError:
        body = {}
    return status, body if isinstance(body, dict) else {}  # Vertrag: immer ein dict


def check(status: int, body: dict, what: str) -> dict:
    """Bildet HTTP-Fehler auf Adapterfehler ab (``net.status_error``)."""
    if status < 300:
        return body
    errors = body.get("errors")
    errors = "; ".join(map(str, errors))[:300] if isinstance(errors, list) else ""
    raise net.status_error(status, f"{what}: HTTP {status}" + (f" ({errors})" if errors else ""))
