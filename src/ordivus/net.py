"""Gemeinsamer HTTP-Transport (urllib) für OpenBao, ClickHouse und ArcadeDB.

Folgt nie Redirects: urllib schickte sonst ``X-Vault-Token``/``Authorization`` an das Redirect-Ziel,
auch an fremde Hosts und von https auf http. Nur http/https; Antwortkörper sind auf ``MAX_BODY`` begrenzt.
"""

import http.client
import logging
import ssl
import urllib.request
from urllib.parse import urlsplit

from ordivus.adapters.base import AdapterError, AuthorizationError, PermanentError, TransientError

MAX_BODY = 16 * 1024 * 1024
SCHEMES = ("http", "https")
log = logging.getLogger("ordivus")
_warned: set[str] = set()  # eine Warnung je Ziel und Prozess


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PermanentError(f"HTTP {code} redirect refused: Ordivus does not follow redirects "
                             "(configure the final endpoint URL)")


def urlopen(req: urllib.request.Request, timeout: float, context: ssl.SSLContext | None = None):
    """Wie ``urllib.request.urlopen``, aber ohne Redirects und nur für http/https."""
    url = urlsplit(req.full_url)
    if url.scheme not in SCHEMES:
        raise PermanentError("only http and https URLs are supported")
    # HTTP(S)_PROXY/NO_PROXY gelten (ProxyHandler); sichtbar machen, denn der Proxy sieht Klartext bzw. Ziele
    proxy = urllib.request.getproxies().get(url.scheme)
    if proxy and not urllib.request.proxy_bypass(url.hostname or "") and url.netloc not in _warned:
        _warned.add(url.netloc)
        log.warning("%s://%s is reached via proxy %s (from %s_PROXY; exclude with NO_PROXY)",
                    url.scheme, url.netloc, urlsplit(proxy).hostname, url.scheme.upper())
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
    try:
        return opener.open(req, timeout=timeout)
    except http.client.HTTPException as e:
        if isinstance(e, OSError):  # RemoteDisconnected: Aufrufer behandeln es als Verbindungsfehler
            raise
        raise TransientError(f"invalid HTTP response from {url.hostname}: {type(e).__name__}") from None


def read(fp) -> bytes:
    """Liest einen Antwortkörper (auch ``HTTPError``) mit Obergrenze."""
    try:
        body = fp.read(MAX_BODY + 1)
    except http.client.HTTPException as e:  # z. B. IncompleteRead: Verbindung mitten in der Antwort abgebrochen
        raise TransientError(f"incomplete HTTP response: {type(e).__name__}") from None
    if len(body) > MAX_BODY:
        raise PermanentError(f"response body exceeds {MAX_BODY} bytes")
    return body


def status_error(status: int, message: str) -> AdapterError:
    """Fehler für einen HTTP-Status >= 400: 5xx und 429 transient, 401/403 Rechte, sonst permanent."""
    if status >= 500 or status == 429:
        return TransientError(message)
    if status in (401, 403):
        return AuthorizationError(message)
    return PermanentError(message)
