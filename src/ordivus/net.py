"""Gemeinsamer HTTP-Transport (urllib) für OpenBao, ClickHouse und ArcadeDB.

Folgt nie Redirects: urllib schickte sonst ``X-Vault-Token``/``Authorization`` an das Redirect-Ziel,
auch an fremde Hosts und von https auf http. Nur http/https; Antwortkörper sind auf ``MAX_BODY`` begrenzt.
"""

import ssl
import urllib.request
from urllib.parse import urlsplit

from ordivus.adapters.base import PermanentError

MAX_BODY = 16 * 1024 * 1024
SCHEMES = ("http", "https")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PermanentError(f"HTTP {code} redirect refused: Ordivus does not follow redirects "
                             "(configure the final endpoint URL)")


def urlopen(req: urllib.request.Request, timeout: float, context: ssl.SSLContext | None = None):
    """Wie ``urllib.request.urlopen``, aber ohne Redirects und nur für http/https."""
    if urlsplit(req.full_url).scheme not in SCHEMES:
        raise PermanentError("only http and https URLs are supported")
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
    return opener.open(req, timeout=timeout)


def read(fp) -> bytes:
    """Liest einen Antwortkörper (auch ``HTTPError``) mit Obergrenze."""
    body = fp.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise PermanentError(f"response body exceeds {MAX_BODY} bytes")
    return body
