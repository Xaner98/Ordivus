"""Keycloak-Adapter über die Admin REST API (nur Standardbibliothek).

Target-Spec: ``endpoint: {host, port, path, tls: {caFile}}``, ``login: {realm (master), username | clientId}``,
optional ``scope: {realms|roles|groups|clients: {include: [glob]}}``. ``username`` → Password Grant mit
``admin-cli``; ``clientId`` → Client Credentials (Service Account). Das Target-Secret ist Passwort bzw.
Client Secret. Kinds: ``KeycloakRealm``, ``KeycloakRealmRole``, ``KeycloakGroup`` (nur Top-Level),
``KeycloakClient`` (OIDC; Client Secret über ``spec.credentials``). Benutzer werden nicht verwaltet.

IDs: Realm = Realm-Name, sonst ``<realm>/<name>`` bzw. ``<realm>/<clientId>``.
Keycloak-PUTs ersetzen Repräsentationen: immer GET, nur deklarierte Felder ändern, PUT.
Eigene Rechte stehen nicht im Token (admin-cli nutzt Lightweight Tokens), sondern werden über die
effektiven Rollen-Mappings des eigenen Benutzers gelesen; ohne sie ist die Discovery ``partial``.
"""

import hmac
import http.client
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field

from ordivus import net
from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    SET_PASSWORD,
    UPDATE,
    Adapter,
    AdapterError,
    AuthorizationError,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

REALM, ROLE, GROUP, CLIENT = "KeycloakRealm", "KeycloakRealmRole", "KeycloakGroup", "KeycloakClient"
MASTER = "master"
# 24 ist die älteste Major-Version mit der hier genutzten Admin-API (Top-Level-Gruppen mit Paging seit 23,
# realm_client-Attribut); ältere Versionen sind upstream ohne Support. Getestet mit 26.4.
MIN_VERSION = 24
TIMEOUT, PAGE = 30, 100
REALM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
SYSTEM_ROLES = frozenset({"offline_access", "uma_authorization"})
MASTER_ROLES = frozenset({"admin", "create-realm"})  # globale Admin-Rollen im master-Realm
SYSTEM_CLIENTS = frozenset({"account", "account-console", "admin-cli", "broker", "realm-management",
                            "security-admin-console"})
# Rollen der Admin-Clients (realm-management bzw. <realm>-realm in master), die die Discovery vollständig machen
NEEDS = {ROLE: {"view-realm", "manage-realm"}, GROUP: {"view-users", "manage-users"},
         CLIENT: {"view-clients", "manage-clients"}}
REALM_FIELDS = {"enabled": bool, "displayName": str, "registrationAllowed": bool, "resetPasswordAllowed": bool,
                "rememberMe": bool, "verifyEmail": bool, "loginWithEmailAllowed": bool, "sslRequired": str}
CLIENT_FIELDS = {"enabled": bool, "protocol": str, "publicClient": bool, "redirectUris": list, "webOrigins": list,
                 "standardFlowEnabled": bool, "directAccessGrantsEnabled": bool, "serviceAccountsEnabled": bool}
SPEC = {REALM: dict(REALM_FIELDS), ROLE: {"realm": str, "name": str, "description": str, "composites": list},
        GROUP: {"realm": str, "name": str, "realmRoles": list},
        CLIENT: {"realm": str, "clientId": str, **CLIENT_FIELDS}}
LISTS = ("composites", "realmRoles", "redirectUris", "webOrigins")  # als sortierte Mengen verglichen
log = logging.getLogger("ordivus")


def split(id: str) -> tuple[str, str]:
    realm, _, name = id.partition("/")
    return realm, name


def q(name: str) -> str:
    return urllib.parse.quote(name, safe="")


@dataclass
class Session:
    base: str
    context: ssl.SSLContext | None
    write: bool
    login: dict
    secret: Secret | None
    token: str = ""
    expires: float = 0.0
    version: str | None = None
    own_id: str | None = None
    own_roles: frozenset | None = None  # effektive Realm-Rollen der eigenen Anmeldung im Login-Realm
    realms: list | None = None  # sichtbare Realm-Repräsentationen (Cache je Lauf)
    perms: dict = field(default_factory=dict)  # realm -> effektive Admin-Rollen
    admin_clients: dict = field(default_factory=dict)  # realm -> UUIDs der Admin-Clients oder None (unbekannt)
    roles: dict = field(default_factory=dict)  # (realm, name) -> {"composites": set, "admin": bool | None}
    roles_done: set = field(default_factory=set)  # Realms mit vollständig gelesenen Rollen

    @property
    def login_realm(self) -> str:
        return self.login.get("realm", MASTER)

    @property
    def master_admin(self) -> bool:
        return self.login_realm == MASTER and "admin" in (self.own_roles or ())


def _http(base, context, method, path, headers, data=None, query=None):
    """Ein HTTP-Aufruf; liefert (Status, JSON). Fehler ohne Secret-Inhalte (Token, Passwort)."""
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    request = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **headers})
    where = f"{method} {path}"
    try:
        with net.urlopen(request, TIMEOUT, context) as response:
            return response.status, json.loads(net.read(response) or b"null")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(net.read(e) or b"null")
        except ValueError:
            payload = None
        return e.code, payload
    except (TimeoutError, urllib.error.URLError, ConnectionError, http.client.HTTPException) as e:
        raise TransientError(f"{where}: {type(e).__name__}: {getattr(e, 'reason', e)}") from None
    except ValueError as e:
        raise PermanentError(f"{where}: invalid JSON response ({type(e).__name__})") from None


def _check(status, payload, where, ok=()):
    if 200 <= status < 300 or status in ok:
        return payload
    detail = None
    if isinstance(payload, dict):
        detail = payload.get("errorMessage") or payload.get("error")
    raise net.status_error(status, f"{where}: HTTP {status}" + (f": {str(detail)[:200]}" if detail else ""))


def _list(payload, where, key="name") -> list:
    """Liste von Objekten mit String-``key``; jede andere Form ist ein Fehler, nie eine leere Liste."""
    if not isinstance(payload, list) or not all(isinstance(x, dict) and isinstance(x.get(key), str) for x in payload):
        raise PermanentError(f"{where}: unexpected response (no list of objects with {key!r})")
    return payload


def _names(values) -> list:
    return sorted(set(values or []))


def _client_attrs(rep: dict) -> dict:
    attrs = {f: rep.get(f) for f in CLIENT_FIELDS if f in rep}
    attrs.update({f: _names(rep.get(f)) for f in ("redirectUris", "webOrigins")})
    return attrs


class KeycloakAdapter(Adapter):
    id = "keycloak"
    api_version = 1
    kinds = (REALM, ROLE, GROUP, CLIENT)
    password_kinds = (CLIENT,)

    # --- Konfiguration ----------------------------------------------------------------------------

    def validate(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        if kind == "Target":
            return self._validate_target(spec)
        fields = SPEC[kind]
        errors = [f"unknown field spec.{k}" for k in spec if k not in fields]
        for k, v in spec.items():
            if k not in fields:
                continue
            if type(v) is not fields[k]:
                errors.append(f"spec.{k} must be a {fields[k].__name__}")
            elif fields[k] is list and not all(isinstance(x, str) and x for x in v):
                errors.append(f"spec.{k} must be a list of non-empty strings")
        if kind == REALM:
            if not REALM_NAME.fullmatch(doc["metadata"]["name"]):
                errors.append("metadata.name (realm) must match [A-Za-z0-9][A-Za-z0-9_.-]* (max 100)")
            if spec.get("sslRequired", "all") not in ("none", "external", "all"):
                errors.append("spec.sslRequired must be one of none, external, all")
            return errors
        if not isinstance(spec.get("realm"), str) or not REALM_NAME.fullmatch(spec["realm"]):
            errors.append("spec.realm is required and must match [A-Za-z0-9][A-Za-z0-9_.-]* (max 100)")
        key = "clientId" if kind == CLIENT else "name"
        name = spec.get(key, doc["metadata"]["name"])
        if not isinstance(name, str) or not name or not name.isprintable() or (kind == GROUP and "/" in name):
            errors.append(f"spec.{key} must be a printable non-empty string"
                          + (" without '/'" if kind == GROUP else ""))
        if spec.get("protocol", "openid-connect") != "openid-connect":
            errors.append("spec.protocol: only openid-connect is supported")
        return errors

    @staticmethod
    def _validate_target(spec):
        errors = [f"unknown field spec.{k}" for k in spec if k not in ("endpoint", "login", "scope")]
        endpoint = spec.get("endpoint")
        errors += common.validate_endpoint(endpoint, extra=("path",))
        if isinstance(endpoint, dict) and "path" in endpoint and (
                not isinstance(endpoint["path"], str) or not re.fullmatch(r"(/[A-Za-z0-9_.-]+)*", endpoint["path"])):
            errors.append("spec.endpoint.path must be like /auth (segments of [A-Za-z0-9_.-])")
        login = spec.get("login")
        if not isinstance(login, dict) or set(login) - {"realm", "username", "clientId"} or \
                ("username" in login) == ("clientId" in login) or \
                not all(isinstance(v, str) and v for v in login.values()):
            errors.append("spec.login must be a mapping with optional realm and exactly one of username "
                          "(password grant via admin-cli) or clientId (client credentials)")
        elif not REALM_NAME.fullmatch(login.get("realm", MASTER)):
            errors.append("spec.login.realm must match [A-Za-z0-9][A-Za-z0-9_.-]*")
        scope = spec.get("scope", {})
        if not isinstance(scope, dict):
            return [*errors, "spec.scope must be a mapping"]
        for key, value in scope.items():
            if key not in ("realms", "roles", "groups", "clients"):
                errors.append(f"unknown field spec.scope.{key}")
            elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(
                    value.get("include", []), list) or not all(isinstance(g, str) for g in value.get("include", [])):
                errors.append(f"spec.scope.{key} must be {{include: [glob, ...]}}")
        return errors

    def desired(self, doc):
        spec, kind, name = doc.get("spec") or {}, doc["kind"], doc["metadata"]["name"]
        attrs = {k: (_names(v) if k in LISTS else v) for k, v in spec.items() if k not in ("realm", "name", "clientId")}
        if kind == REALM:
            return Resource(kind, name, attrs)
        return Resource(kind, f"{spec['realm']}/{spec.get('clientId' if kind == CLIENT else 'name', name)}", attrs)

    def export(self, resource):
        if resource.kind == REALM:
            return dict(resource.attrs)
        realm, name = split(resource.id)
        return {"realm": realm, "clientId" if resource.kind == CLIENT else "name": name, **resource.attrs}

    def validate_target(self, target, resources):
        errors, login = [], target.get("login") or {}
        login_realm = login.get("realm", MASTER)
        for r in resources:
            realm = r.id if r.kind == REALM else split(r.id)[0]
            if not common.in_scope(target.get("scope"), "realms", realm):
                errors.append(f"{r.kind} {r.id!r}: realm {realm!r} is outside spec.scope.realms")
            if login_realm != MASTER and realm != login_realm:
                errors.append(f"{r.kind} {r.id!r}: a login in realm {login_realm!r} can only manage that realm")
            if r.kind == CLIENT and r.password_ref and r.attrs.get("publicClient") is True:
                errors.append(f"{r.kind} {r.id!r}: spec.credentials requires a confidential client "
                              "(publicClient: false)")
        return errors

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None

    # --- Verbindung -------------------------------------------------------------------------------

    @contextmanager
    def connect(self, target, secret, write):
        if secret is None:
            raise PermanentError("keycloak target requires spec.authentication.credentialRef")
        endpoint = target["endpoint"]
        tls = endpoint.get("tls")
        host = f"[{endpoint['host']}]" if ":" in endpoint["host"] else endpoint["host"]
        port = endpoint.get("port", 8080 if tls is None else 8443)
        base = f"{'http' if tls is None else 'https'}://{host}:{port}{endpoint.get('path', '')}"
        session = Session(base, None if tls is None else common.tls_context(tls), write, target["login"], secret)
        self._login(session)
        info = self._get(session, "/admin/serverinfo", ok=(403,))
        version = ((info or {}).get("systemInfo") or {}).get("version") if isinstance(info, dict) else None
        if isinstance(version, str) and version:
            major = re.match(r"(\d+)", version)
            if major and int(major.group(1)) < MIN_VERSION:
                raise PermanentError(f"Keycloak {version} is not supported (minimum {MIN_VERSION})")
            session.version = f"Keycloak {version}"
        else:
            log.warning("keycloak: server version not readable (needs master admin or view-system)")
        self._whoami(session)
        yield session

    def server_version(self, session):
        return session.version

    def _login(self, session):
        """Token holen (Password Grant via admin-cli oder Client Credentials); Token nur im Header."""
        login = session.login
        if "username" in login:
            form = {"grant_type": "password", "client_id": "admin-cli", "username": login["username"],
                    "password": session.secret.reveal()}
        else:
            form = {"grant_type": "client_credentials", "client_id": login["clientId"],
                    "client_secret": session.secret.reveal()}
        path = f"/realms/{q(session.login_realm)}/protocol/openid-connect/token"
        status, payload = _http(session.base, session.context, "POST", path,
                                {"Content-Type": "application/x-www-form-urlencoded"},
                                urllib.parse.urlencode(form).encode())
        if status in (400, 401) and isinstance(payload, dict):  # invalid_grant/unauthorized_client = Login abgelehnt
            raise AuthorizationError(f"login to realm {session.login_realm!r} failed: HTTP {status}: "
                                     f"{str(payload.get('error'))[:100]}")
        payload = _check(status, payload, "token request")
        if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str):
            raise PermanentError("token request: unexpected response (no access_token)")
        session.token = payload["access_token"]
        expires_in = payload.get("expires_in")
        session.expires = time.monotonic() + (expires_in if isinstance(expires_in, int) else 60)

    def _request(self, session, method, path, body=None, query=None, ok=()):
        if method != "GET" and not session.write:  # Read-only-Session: niemals schreibende Requests
            raise PermanentError(f"{method} {path} refused on read-only session")
        data = None if body is None else json.dumps(body).encode()
        for attempt in (1, 2):
            if time.monotonic() > session.expires - 10:
                self._login(session)
            status, payload = _http(session.base, session.context, method, path,
                                    {"Authorization": f"Bearer {session.token}", "Content-Type": "application/json"},
                                    data, query)
            if status != 401 or attempt == 2:
                return _check(status, payload, f"{method} {path}", ok)
            session.expires = 0  # Token abgelaufen/widerrufen: einmal neu anmelden

    def _get(self, session, path, query=None, ok=()):
        return self._request(session, "GET", path, query=query, ok=ok)

    def _paged(self, session, path, query=None, key="name"):
        out, first = [], 0
        while True:
            page = _list(self._get(session, path, {**(query or {}), "first": first, "max": PAGE}), f"GET {path}", key)
            out += page
            if len(page) < PAGE:
                return out
            first += PAGE

    def _r(self, realm):
        return f"/admin/realms/{q(realm)}"

    def _whoami(self, session):
        """Eigene Benutzer-ID und effektive Realm-Rollen; unlesbar → None (Discovery dann partial)."""
        realm = session.login_realm
        try:
            if "username" in session.login:
                users = _list(self._get(session, f"{self._r(realm)}/users",
                                        {"username": session.login["username"], "exact": "true"}), "own user", "id")
                users = [u for u in users if u.get("username") == session.login["username"].lower()]
                session.own_id = users[0]["id"] if len(users) == 1 else None
            else:
                uuid = self._client_uuid(session, realm, session.login["clientId"])
                user = self._get(session, f"{self._r(realm)}/clients/{uuid}/service-account-user") if uuid else None
                session.own_id = user.get("id") if isinstance(user, dict) else None
            if session.own_id:
                path = f"{self._r(realm)}/users/{q(session.own_id)}/role-mappings/realm/composite"
                roles = _list(self._get(session, path), "own realm roles")
                session.own_roles = frozenset(r["name"] for r in roles)
        except AdapterError as e:
            log.warning("keycloak: cannot read own role mappings (%s); discovery will be partial", type(e).__name__)

    def _client_uuid(self, session, realm, client_id):
        found = _list(self._get(session, f"{self._r(realm)}/clients", {"clientId": client_id}), "find client", "id")
        found = [c for c in found if c.get("clientId") == client_id]
        return found[0]["id"] if found else None

    def _perms(self, session, realm) -> frozenset:
        """Effektive Admin-Rollen für ``realm`` (Rollen des Admin-Clients); unbekannt = leer."""
        if realm not in session.perms:
            perms = frozenset()
            try:
                if session.master_admin:
                    perms = frozenset(set().union(*NEEDS.values()))
                elif session.own_id and (session.login_realm == MASTER or realm == session.login_realm):
                    owner = session.login_realm
                    client = f"{realm}-realm" if owner == MASTER else "realm-management"
                    uuid = self._client_uuid(session, owner, client)
                    if uuid:
                        path = f"{self._r(owner)}/users/{session.own_id}/role-mappings/clients/{uuid}/composite"
                        perms = frozenset(r["name"] for r in _list(self._get(session, path), "own client roles"))
            except AdapterError as e:
                log.warning("keycloak: cannot read own permissions in realm %r (%s)", realm, type(e).__name__)
            session.perms[realm] = perms
        return session.perms[realm]

    def _admin_clients(self, session, realm):
        """UUIDs der Clients, deren Rollen Realms verwalten (realm_client=true); None = nicht feststellbar."""
        if realm not in session.admin_clients:
            uuids = None
            try:
                query = ({"clientId": "-realm", "search": "true"} if realm == MASTER
                         else {"clientId": "realm-management"})
                found = _list(self._get(session, f"{self._r(realm)}/clients", query), "admin clients", "id")
                uuids = {c["id"] for c in found if (c.get("attributes") or {}).get("realm_client") == "true"} or None
            except AdapterError:
                pass
            session.admin_clients[realm] = uuids
        return session.admin_clients[realm]

    # --- Discovery --------------------------------------------------------------------------------

    def _realms(self, session) -> list:
        if session.realms is None:
            if session.login_realm == MASTER:
                session.realms = _list(self._get(session, "/admin/realms"), "list realms", "realm")
            else:  # eine Anmeldung außerhalb von master sieht nur den eigenen Realm
                rep = self._get(session, self._r(session.login_realm))
                session.realms = _list([rep], "read realm", "realm")
        return session.realms

    def _realms_complete(self, session):
        if session.login_realm != MASTER:
            return True, ""  # nur dieser Realm ist erreichbar; validate_target erlaubt keine anderen
        if session.master_admin:
            return True, ""
        return False, "only the master 'admin' role sees all realms"

    def _new_realm(self, session, realm) -> bool:
        """Realm fehlt in einer vollständigen Realm-Liste: wird in diesem Lauf erst angelegt, enthält also nichts."""
        return self._realms_complete(session)[0] and realm not in {r["realm"] for r in self._realms(session)}

    def discover(self, session, kind, scope):
        realms = [r for r in self._realms(session) if common.in_scope(scope, "realms", r["realm"])]
        complete, reason = self._realms_complete(session)
        if kind == REALM:
            if session.login_realm != MASTER:
                complete, reason = False, f"a login in realm {session.login_realm!r} sees no other realms"
            resources = [Resource(REALM, r["realm"], {f: r.get(f) for f in REALM_FIELDS if f in r},
                                  manageable=bool(REALM_NAME.fullmatch(r["realm"])), system=r["realm"] == MASTER)
                         for r in realms]
            return Discovery(COMPLETE if complete else PARTIAL, resources, reason)
        resources, missing = [], []
        for realm in (r["realm"] for r in realms):
            if not REALM_NAME.fullmatch(realm):
                missing.append(realm)
                continue
            if not self._perms(session, realm) & NEEDS[kind]:
                missing.append(realm)
            resources += {ROLE: self._roles, GROUP: self._groups, CLIENT: self._clients}[kind](session, realm, scope)
        if missing:
            complete, reason = False, f"missing {sorted(NEEDS[kind])} (or unsupported name) in realm(s) {missing}"
        return Discovery(COMPLETE if complete else PARTIAL, resources, reason)

    def _system_role(self, session, realm, name):
        return (name in SYSTEM_ROLES or name == f"default-roles-{realm.lower()}"
                or (realm == MASTER and name in MASTER_ROLES)
                or (realm == session.login_realm and (session.own_roles is None or name in session.own_roles)))

    def _roles(self, session, realm, scope):
        base, admin = self._r(realm), self._admin_clients(session, realm)
        out = []
        for rep in self._paged(session, f"{base}/roles", {"briefRepresentation": "false"}):
            composites, client_ids = set(), set()
            if rep.get("composite"):
                for c in _list(self._get(session, f"{base}/roles-by-id/{q(rep['id'])}/composites"), "composites"):
                    (client_ids.add(c.get("containerId")) if c.get("clientRole") else composites.add(c["name"]))
            # admin: True = enthält Admin-Client-Rollen, None = Client-Rollen unbekannter Herkunft
            privileged = bool(client_ids & admin) if admin is not None else (None if client_ids else False)
            session.roles[(realm, rep["name"])] = {"composites": composites, "admin": privileged}
            if common.in_scope(scope, "roles", rep["name"]):
                out.append(Resource(ROLE, f"{realm}/{rep['name']}",
                                    {"description": rep.get("description") or "", "composites": sorted(composites)},
                                    system=self._system_role(session, realm, rep["name"])))
        session.roles_done.add(realm)
        return out

    def _groups(self, session, realm, scope):
        return [Resource(GROUP, f"{realm}/{g['name']}", {"realmRoles": _names(g.get("realmRoles"))})
                for g in self._paged(session, f"{self._r(realm)}/groups", {"briefRepresentation": "false"})
                if common.in_scope(scope, "groups", g["name"])]

    def _system_client(self, session, realm, rep):
        return (rep["clientId"] in SYSTEM_CLIENTS or (rep.get("attributes") or {}).get("realm_client") == "true"
                or (realm == MASTER and rep["clientId"].endswith("-realm"))
                or (realm == session.login_realm and rep["clientId"] == session.login.get("clientId")))

    def _clients(self, session, realm, scope):
        return [Resource(CLIENT, f"{realm}/{c['clientId']}", _client_attrs(c),
                         manageable=c.get("protocol", "openid-connect") == "openid-connect",
                         system=self._system_client(session, realm, c))
                for c in self._paged(session, f"{self._r(realm)}/clients", key="clientId")
                if common.in_scope(scope, "clients", c["clientId"])]

    # --- Planung ----------------------------------------------------------------------------------

    def _privileged_role(self, session, realm, name, seen=None) -> str | None:
        """Grund, warum die Realm-Rolle Admin-Rechte vermittelt (transitiv über Composites), sonst None."""
        seen = seen if seen is not None else set()
        if name in seen:
            return None
        seen.add(name)
        if realm == MASTER and name in MASTER_ROLES:
            return f"master role {name!r}"
        info = session.roles.get((realm, name))
        if info is None:
            if realm in session.roles_done or self._new_realm(session, realm):
                return None
            return f"roles of realm {realm!r} could not be read"
        if info["admin"] is not False:
            return (f"role {name!r} contains realm administration client roles" if info["admin"] else
                    f"role {name!r} contains client roles that cannot be classified")
        return next((why for c in sorted(info["composites"])
                     if (why := self._privileged_role(session, realm, c, seen))), None)

    def check(self, session, resource, allow_privileged=False):
        kind, attrs = resource.kind, resource.attrs
        if kind == REALM:
            return "the master realm is protected" if resource.id == MASTER else None
        realm, name = split(resource.id)
        if kind == ROLE and self._system_role(session, realm, name):
            if session.own_roles is None:
                return "own role mappings not readable: roles of the login realm are protected"
            return f"role {name!r} is protected (built-in or held by the Ordivus login)"
        if kind == CLIENT and self._system_client(session, realm, {"clientId": name}):
            return f"client {name!r} is protected (built-in or the Ordivus login)"
        if allow_privileged:
            return None
        try:
            why = None
            roles = attrs.get("composites" if kind == ROLE else "realmRoles", [])
            if kind in (ROLE, GROUP) and realm == MASTER and roles:
                why = "role mappings in the master realm"
            elif kind in (ROLE, GROUP):
                why = next((w for r in roles if (w := self._privileged_role(session, realm, r))), None)
            elif kind == CLIENT and attrs.get("serviceAccountsEnabled") is not False and \
                    not self._new_realm(session, realm):
                why = self._privileged_service_account(session, realm, name)
        except AdapterError as e:
            why = f"privilege check failed ({type(e).__name__})"
        return f"privileged: {why}; requires operator policy allowPrivilegedGrants" if why else None

    def _privileged_service_account(self, session, realm, client_id):
        uuid = self._client_uuid(session, realm, client_id)
        if uuid is None:
            return None  # neuer Client: Service Account ohne Rollen (außer Default-Rollen)
        base = self._r(realm)
        user = self._get(session, f"{base}/clients/{uuid}/service-account-user", ok=(400, 404))
        if not isinstance(user, dict) or not user.get("id"):
            return None  # Service Accounts (noch) nicht aktiviert
        mappings = self._get(session, f"{base}/users/{q(user['id'])}/role-mappings")
        if not isinstance(mappings, dict):
            raise PermanentError("service account role mappings: unexpected response")
        admin = self._admin_clients(session, realm)
        clients = {m.get("id") for m in (mappings.get("clientMappings") or {}).values() if isinstance(m, dict)}
        if clients and (admin is None or clients & admin):
            return f"service account of {client_id!r} holds realm administration client roles"
        realm_roles = [r.get("name") for r in mappings.get("realmMappings") or [] if isinstance(r, dict)]
        return next((f"service account of {client_id!r}: {w}" for r in realm_roles
                     if (w := self._privileged_role(session, realm, r))), None)

    def dependencies(self, resource):
        if resource.kind == REALM:
            return []
        realm, _ = split(resource.id)
        roles = resource.attrs.get("composites", []) + resource.attrs.get("realmRoles", [])
        return [(REALM, realm), *((ROLE, f"{realm}/{r}") for r in roles)]

    # --- Ausführung -------------------------------------------------------------------------------

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        if self.check(session, op.desired or op.observed, allow_privileged=True):  # zweite Sperre neben check()
            raise PermanentError(f"{op.kind} {op.id!r} is protected")
        if op.observed is not None and (op.observed.system or not op.observed.manageable):
            raise PermanentError(f"{op.kind} {op.id!r} is protected")
        handler = {REALM: self._apply_realm, ROLE: self._apply_role, GROUP: self._apply_group,
                   CLIENT: self._apply_client}[op.kind]
        handler(session, op)

    def _merge_put(self, session, path, changes: dict):
        """Keycloak-PUT ersetzt die Repräsentation: aktuellen Stand lesen, nur ``changes`` setzen, zurückschreiben."""
        rep = self._get(session, path)
        if not isinstance(rep, dict):
            raise PermanentError(f"GET {path}: unexpected response")
        self._request(session, "PUT", path, {**rep, **changes})

    def _apply_realm(self, session, op):
        path = self._r(op.id)
        session.realms = None  # Realm-Liste neu lesen (Verifikation, Folge-Ops im neuen Realm)
        if op.action == CREATE:
            self._request(session, "POST", "/admin/realms", {"realm": op.id, **op.desired.attrs}, ok=(409,))
        elif op.action == UPDATE:
            self._merge_put(session, path, {f: new for f, (_, new) in op.changes.items()})
        elif op.action == DELETE:
            self._request(session, "DELETE", path, ok=(404,))

    def _role_reps(self, session, realm, names):
        return [self._get(session, f"{self._r(realm)}/roles/{q(n)}") for n in names]

    def _apply_role(self, session, op):
        realm, name = split(op.id)
        path = f"{self._r(realm)}/roles/{q(name)}"
        if op.action == DELETE:
            self._request(session, "DELETE", path, ok=(404,))
            return
        attrs = op.desired.attrs
        if op.action == CREATE:
            body = {"name": name, **({"description": attrs["description"]} if "description" in attrs else {})}
            self._request(session, "POST", f"{self._r(realm)}/roles", body, ok=(409,))
            old, new = [], attrs.get("composites")
        else:
            if "description" in op.changes:
                self._merge_put(session, path, {"description": attrs["description"]})
            old, new = op.changes.get("composites", (None, None))
        if new is not None:
            if add := sorted(set(new) - set(old or [])):
                self._request(session, "POST", f"{path}/composites", self._role_reps(session, realm, add))
            if remove := sorted(set(old or []) - set(new)):
                self._request(session, "DELETE", f"{path}/composites", self._role_reps(session, realm, remove))

    def _group_id(self, session, realm, name):
        found = self._get(session, f"{self._r(realm)}/groups", {"search": name, "exact": "true"})
        found = [g for g in _list(found, "find group") if g.get("path") == f"/{name}"]
        if not found:
            raise PermanentError(f"group {realm}/{name} not found")
        return found[0]["id"]

    def _apply_group(self, session, op):
        realm, name = split(op.id)
        if op.action == CREATE:
            self._request(session, "POST", f"{self._r(realm)}/groups", {"name": name}, ok=(409,))
        path = f"{self._r(realm)}/groups/{q(self._group_id(session, realm, name))}"
        if op.action == DELETE:
            self._request(session, "DELETE", path, ok=(404,))
            return
        old, new = ([], op.desired.attrs.get("realmRoles")) if op.action == CREATE else \
            op.changes.get("realmRoles", (None, None))
        if new is not None:
            if add := sorted(set(new) - set(old or [])):
                self._request(session, "POST", f"{path}/role-mappings/realm", self._role_reps(session, realm, add))
            if remove := sorted(set(old or []) - set(new)):
                self._request(session, "DELETE", f"{path}/role-mappings/realm", self._role_reps(session, realm, remove))

    def _apply_client(self, session, op):
        realm, client_id = split(op.id)
        if op.action == CREATE:
            body = {"clientId": client_id, **op.desired.attrs}
            if op.password is not None:
                body["secret"] = op.password.reveal()
            self._request(session, "POST", f"{self._r(realm)}/clients", body, ok=(409,))
            return
        uuid = self._client_uuid(session, realm, client_id)
        if uuid is None:
            if op.action == DELETE:
                return
            raise PermanentError(f"client {op.id!r} not found")
        path = f"{self._r(realm)}/clients/{q(uuid)}"
        if op.action == UPDATE:
            self._merge_put(session, path, {f: new for f, (_, new) in op.changes.items()})
        elif op.action == SET_PASSWORD:
            self._merge_put(session, path, {"secret": op.password.reveal()})
        elif op.action == DELETE:
            self._request(session, "DELETE", path, ok=(404,))

    def verify_password(self, session, target, resource, password):
        """Vergleicht das Client Secret (GET client-secret); öffentliche/JWT-Clients → None."""
        if resource.kind != CLIENT or resource.attrs.get("publicClient"):
            return None
        realm, client_id = split(resource.id)
        uuid = self._client_uuid(session, realm, client_id)
        if uuid is None:
            return None
        secret = self._get(session, f"{self._r(realm)}/clients/{q(uuid)}/client-secret")
        value = secret.get("value") if isinstance(secret, dict) else None
        if not isinstance(value, str) or not value:
            return None
        return hmac.compare_digest(value.encode(), password.reveal().encode())
