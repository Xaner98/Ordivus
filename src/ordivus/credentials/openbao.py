"""Credential Provider ``openbao-kv-v2`` (§10.2, §10.4, §10.6).

Ein Credential pro KV-v2-Pfad (F-04), Feld fest ``password``. Getrennt vom Policy-Adapter
(``ordivus.adapters.openbao``): eigene Konfiguration, eigene Identität.
"""

from pathlib import Path
from urllib.parse import quote

from ordivus import openbao_http
from ordivus.adapters.base import AdapterError, Secret
from ordivus.credentials.base import ABSENT, CONFLICT, PRESENT, UNKNOWN, CredentialError, CredentialProvider, State

FIELD = "password"
K8S_JWT = "/var/run/secrets/kubernetes.io/serviceaccount/token"
# method -> (Pflichtfelder, optionale Felder, Default-Mount)
AUTH = {
    "token": ({"tokenFile"}, set(), None),
    "kubernetes": ({"role"}, {"jwtFile", "mount"}, "kubernetes"),
    "approle": ({"roleId", "secretIdFile"}, {"mount"}, "approle"),
    "jwt": ({"role", "jwtFile"}, {"mount"}, "jwt"),
}


def _str(value) -> bool:
    return isinstance(value, str) and bool(value)


class OpenBaoKV2Provider(CredentialProvider):
    type = "openbao-kv-v2"

    def __init__(self, spec):
        super().__init__(spec)
        # Klartext-HTTP nur im Profil development (Engine prüft das vor der ersten Verbindung).
        self.development_only = spec["endpoint"].startswith("http://")
        self._token: str | None = None
        self._ctx = None

    @classmethod
    def validate(cls, spec):
        errors = [f"unknown field spec.{k}" for k in spec if k not in {"endpoint", "mount", "namespace", "tls", "auth"}]
        endpoint = spec.get("endpoint")
        if not _str(endpoint) or not endpoint.startswith(("https://", "http://")):
            errors.append("spec.endpoint must be an http(s) URL")
        for key in ("mount", "namespace"):
            if key in spec and not _str(spec[key]):
                errors.append(f"spec.{key} must be a non-empty string")
        tls = spec.get("tls", {})
        if not isinstance(tls, dict) or set(tls) - {"caFile"} or not all(_str(v) for v in tls.values()):
            errors.append("spec.tls must be a mapping with optional string caFile")
        auth = spec.get("auth")
        if not isinstance(auth, dict) or auth.get("method") not in AUTH:
            return [*errors, f"spec.auth.method must be one of {sorted(AUTH)}"]
        required, optional, _ = AUTH[auth["method"]]
        errors += [f"unknown field spec.auth.{k}" for k in auth if k not in required | optional | {"method"}]
        errors += [f"spec.auth.{k} must be a non-empty string" for k in sorted(required | optional)
                   if (k in required or k in auth) and not _str(auth.get(k))]
        return errors

    # --- HTTP und Login --------------------------------------------------------------------------

    def _call(self, method, path, body=None, token=True):
        if self._ctx is None:
            self._ctx = openbao_http.tls_context(self.spec.get("tls"))
        return openbao_http.request(self.spec["endpoint"], method, path, self._login() if token else None,
                                    body, self.spec.get("namespace"), self._ctx)

    def _login(self) -> str:
        """Token lazily holen und nur für diesen Lauf im Speicher halten."""
        if self._token:
            return self._token
        auth = self.spec["auth"]
        try:
            if auth["method"] == "token":
                self._token = Path(auth["tokenFile"]).read_text(encoding="utf-8").strip()
                return self._token
            if auth["method"] == "approle":
                body = {"role_id": auth["roleId"],
                        "secret_id": Path(auth["secretIdFile"]).read_text(encoding="utf-8").strip()}
            else:
                body = {"role": auth["role"],
                        "jwt": Path(auth.get("jwtFile", K8S_JWT)).read_text(encoding="utf-8").strip()}
        except OSError as e:
            raise CredentialError(f"openbao auth {auth['method']}: cannot read credential file ({type(e).__name__})") \
                from None
        mount = auth.get("mount", AUTH[auth["method"]][2])
        status, data = self._call("POST", f"auth/{quote(mount)}/login", body, token=False)
        try:
            self._token = openbao_http.check(status, data, f"openbao login ({auth['method']})")["auth"]["client_token"]
        except AdapterError as e:
            raise CredentialError(str(e)) from None
        except (KeyError, TypeError):
            raise CredentialError(f"openbao login ({auth['method']}): no client token in response") from None
        return self._token

    def _path(self, ref, kind):
        if any(part in ("", ".", "..") for part in ref["path"].strip("/").split("/")):
            raise CredentialError(f"credential path {ref['path']!r} must not contain empty, '.' or '..' segments")
        return f"{quote(self.spec.get('mount', 'secret'))}/{kind}/{quote(ref['path'].strip('/'))}"

    # --- Vertrag ---------------------------------------------------------------------------------

    def state(self, ref):
        status, body = self._call("GET", self._path(ref, "metadata"))
        if status == 200:
            meta = body.get("data") or {}
            version = (meta.get("versions") or {}).get(str(meta.get("current_version")))
            if version and not version.get("destroyed") and not version.get("deletion_time"):
                return PRESENT
            # Metadaten ohne lesbare aktuelle Version: cas=0 schlüge fehl, Wert ist weg → manuell klären.
            return State(CONFLICT, "current version deleted or destroyed; restore or remove the path manually")
        if status != 404:  # 403, 5xx, alles andere: kein Beweis für "fehlt"
            return State(UNKNOWN, f"metadata read returned HTTP {status}")
        paths = [self._path(ref, "metadata"), self._path(ref, "data")]
        status, body = self._call("POST", "sys/capabilities-self", {"paths": paths})
        caps = body.get("data") or body
        readable = status == 200 and all({"read", "root"} & set(caps.get(p) or []) for p in paths)
        return ABSENT if readable else State(UNKNOWN, "metadata not found, but read capability on the path is "
                                                      "missing or unverifiable")

    def read(self, ref):
        try:
            data = openbao_http.check(*self._call("GET", self._path(ref, "data")), f"read {ref['path']!r}")
            value = data["data"]["data"][FIELD]
        except AdapterError as e:
            raise CredentialError(str(e)) from None
        except (KeyError, TypeError):
            raise CredentialError(f"credential {ref['path']!r} has no string field {FIELD!r}") from None
        if not isinstance(value, str):
            raise CredentialError(f"credential {ref['path']!r} has no string field {FIELD!r}")
        return Secret(value)

    def create_if_absent(self, ref, value):
        body = {"options": {"cas": 0}, "data": {FIELD: value.reveal()}}
        try:
            status, data = self._call("POST", self._path(ref, "data"), body)
            if status == 400 and "check-and-set" in " ".join(str(e) for e in data.get("errors", [])):
                return self.read(ref)  # konkurrierender Lauf war schneller: dessen Wert gilt, nie überschreiben
            openbao_http.check(status, data, f"create {ref['path']!r}")
        except AdapterError as e:
            raise CredentialError(str(e)) from None
        return value
