"""Grafana-Adapter über die HTTP-API (nur Standardbibliothek), je Target genau eine Organisation.

Target-Spec: ``endpoint: {host, port (3000), tls: {caFile}}``, ``orgId`` (Default 1, gesendet als
``X-Grafana-Org-Id``), optional ``username`` (dann Basic Auth mit dem Secret als Passwort, sonst ist
das Secret ein Service-Account-Token und geht als Bearer), optional
``scope: {teams|folders|serviceAccounts: {include: [glob]}}``.

Kinds: ``GrafanaTeam`` (``email``, ``members`` = Logins bestehender Benutzer), ``GrafanaFolder``
(id = Folder-UID; ``title``, ``permissions`` = Team/Basisrolle → View/Edit/Admin) und
``GrafanaServiceAccount`` (``role``, ``isDisabled``; Tokens bewusst nicht). Doku: ``docs/adapters/grafana.md``.
"""

import base64
import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import quote

from ordivus import net
from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    PARTIAL,
    UPDATE,
    Adapter,
    AuthorizationError,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)

TEAM, FOLDER, SA = "GrafanaTeam", "GrafanaFolder", "GrafanaServiceAccount"
MIN_VERSION = (10, 0)
FOLDER_UID = re.compile(r"[A-Za-z0-9_-]{1,40}")
PROTECTED_FOLDERS = frozenset({"general", "sharedwithme"})  # eingebauter General-Folder, virtueller "Shared with me"
LEVELS = ("View", "Edit", "Admin")
FOLDER_ROLES = ("Viewer", "Editor")  # Admin hat ohnehin Admin auf allen Foldern
SA_ROLES = ("None", "Viewer", "Editor", "Admin")
FIELDS = {TEAM: {"email", "members"}, FOLDER: {"title", "permissions"}, SA: {"role", "isDisabled"}}
SCOPE_KEYS = {TEAM: "teams", FOLDER: "folders", SA: "serviceAccounts"}
READ = {TEAM: ("teams:read", "teams"), FOLDER: ("folders:read", "folders"),
        SA: ("serviceaccounts:read", "serviceaccounts")}
PAGE = 1000
TIMEOUT = 30


@dataclass
class Session:
    base: str
    context: ssl.SSLContext | None
    auth: Secret  # kompletter Authorization-Header
    org_id: int
    write: bool
    version: str = ""
    own_sa: str | None = None  # Name des eigenen Service Accounts (Token-Login)
    permissions: dict = field(default_factory=dict)  # eigene RBAC-Rechte: Aktion → Scopes
    org_users: dict | None = None  # Login → userId, bei Bedarf geladen


def _base(target: dict) -> tuple[str, ssl.SSLContext | None]:
    endpoint = target["endpoint"]
    tls = endpoint.get("tls")
    context = None if tls is None else common.tls_context(tls)
    host = endpoint["host"]
    host = f"[{host}]" if ":" in host else host
    return f"{'https' if tls is not None else 'http'}://{host}:{endpoint.get('port', 3000)}", context


def _call(session, method, path, body=None, query=None):
    """Ein HTTP-Aufruf; liefert (Status, JSON). Wirft AdapterError ohne Secret-Inhalte."""
    url = session.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": session.auth.reveal(), "X-Grafana-Org-Id": str(session.org_id),
        "Content-Type": "application/json", "Accept": "application/json"})
    where = f"{method} {path}"
    try:
        with net.urlopen(request, TIMEOUT, session.context) as response:
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


def _request(session, method, path, body=None, query=None, ok=()):
    if method != "GET" and not session.write:  # Read-only-Session: niemals schreibende Requests
        raise PermanentError(f"{method} {path} refused on read-only session")
    status, payload = _call(session, method, path, body, query)
    if 200 <= status < 300 or status in ok:
        return payload
    detail = payload.get("message") if isinstance(payload, dict) else None
    raise net.status_error(status, f"{method} {path}: HTTP {status}" + (f": {str(detail)[:200]}" if detail else ""))


def _paged(session, path, key, query=None, size="perpage"):
    """Alle Seiten einer Such-API; ``key`` None = Antwort ist selbst die Liste. Andere Formen sind Fehler."""
    items, page = [], 1
    while True:
        body = _request(session, "GET", path, query={**(query or {}), size: PAGE, "page": page})
        batch = body if key is None else body.get(key) if isinstance(body, dict) else None
        if not isinstance(batch, list) or not all(isinstance(x, dict) for x in batch):
            raise PermanentError(f"GET {path}: unexpected response (no list of objects)")
        items += batch
        if len(batch) < PAGE:
            return items
        page += 1


def _reads_all(permissions: dict, action: str, prefix: str) -> bool:
    """Ob die eigenen Rechte ``action`` auf allen Objekten erlauben (sonst ist die Suche gefiltert)."""
    return any(s in ("*", f"{prefix}:*", f"{prefix}:uid:*", f"{prefix}:id:*") for s in permissions.get(action) or [])


def _perm_key(p: dict) -> tuple[str, str]:
    return ("team", p["team"]) if "team" in p else ("role", p["role"])


def _perms(entries: list[dict]) -> list[dict]:
    """Direkt gesetzte Team-/Basisrollen-Rechte eines Folders, sortiert. Benutzer-, Service-Account-,
    geerbte und feste (nicht verwaltete) Einträge zählen nicht dazu und bleiben unberührt."""
    out = []
    for e in entries:
        if not e.get("isManaged") or e.get("isInherited"):
            continue
        if e.get("teamId"):
            out.append({"team": str(e.get("team")), "permission": e.get("permission")})
        elif e.get("builtInRole"):
            out.append({"role": e["builtInRole"], "permission": e.get("permission")})
    return sorted(out, key=_perm_key)


def _id(item: dict, where: str) -> int:
    if type(item.get("id")) is not int:
        raise PermanentError(f"{where}: unexpected response (no numeric id)")
    return item["id"]


class GrafanaAdapter(Adapter):
    id = "grafana"
    api_version = 1
    kinds = (TEAM, FOLDER, SA)

    def validate(self, doc):
        spec, kind = doc.get("spec") or {}, doc["kind"]
        if kind == "Target":
            return self._validate_target(spec)
        name = doc["metadata"]["name"]
        errors = [f"unknown field spec.{k}" for k in spec if k not in FIELDS[kind]]
        if kind == FOLDER:
            if not FOLDER_UID.fullmatch(name):
                errors.append("metadata.name is the folder uid and must match [A-Za-z0-9_-]{1,40}")
            if not isinstance(spec.get("title"), str) or not spec["title"].strip():
                errors.append("spec.title must be a non-empty string")
            return errors + self._validate_permissions(spec.get("permissions", []))
        if not name.isprintable() or not name.strip():
            errors.append("metadata.name must be printable and not blank")
        if kind == TEAM:
            if "email" in spec and not isinstance(spec["email"], str):
                errors.append("spec.email must be a string")
            members = spec.get("members", [])
            if not isinstance(members, list) or not all(isinstance(m, str) and m for m in members):
                errors.append("spec.members must be a list of user logins")
            return errors
        if "role" in spec and spec["role"] not in SA_ROLES:
            errors.append(f"spec.role must be one of {list(SA_ROLES)}")
        if "isDisabled" in spec and not isinstance(spec["isDisabled"], bool):
            errors.append("spec.isDisabled must be true or false")
        return errors

    @staticmethod
    def _validate_permissions(perms):
        if not isinstance(perms, list):
            return ["spec.permissions must be a list"]
        errors, seen = [], set()
        for i, p in enumerate(perms):
            where = f"spec.permissions[{i}]"
            if not isinstance(p, dict) or set(p) not in ({"team", "permission"}, {"role", "permission"}):
                errors.append(f"{where} must have exactly 'permission' and one of 'team' or 'role'")
                continue
            if p["permission"] not in LEVELS:
                errors.append(f"{where}.permission must be one of {list(LEVELS)}")
            if "role" in p and p["role"] not in FOLDER_ROLES:
                errors.append(f"{where}.role must be one of {list(FOLDER_ROLES)}")
            if "team" in p and (not isinstance(p["team"], str) or not p["team"]):
                errors.append(f"{where}.team must be a team name")
            elif _perm_key(p) in seen:
                errors.append(f"{where}: duplicate entry for {' '.join(_perm_key(p))}")
            else:
                seen.add(_perm_key(p))
        return errors

    @staticmethod
    def _validate_target(spec):
        errors = [f"unknown field spec.{k}" for k in spec if k not in ("endpoint", "orgId", "username", "scope")]
        errors += common.validate_endpoint(spec.get("endpoint"))
        if "orgId" in spec and (type(spec["orgId"]) is not int or spec["orgId"] < 1):
            errors.append("spec.orgId must be a positive integer")
        if "username" in spec and (not isinstance(spec["username"], str) or not spec["username"]
                                   or ":" in spec["username"]):
            errors.append("spec.username must be a non-empty string without ':'")
        scope = spec.get("scope", {})
        if not isinstance(scope, dict):
            return [*errors, "spec.scope must be a mapping"]
        for key, value in scope.items():
            if key not in SCOPE_KEYS.values():
                errors.append(f"unknown field spec.scope.{key}")
            elif not isinstance(value, dict) or set(value) - {"include"} or not isinstance(
                    value.get("include", []), list) or not all(isinstance(g, str) for g in value.get("include", [])):
                errors.append(f"spec.scope.{key} must be {{include: [glob, ...]}}")
        return errors

    def validate_target(self, target, resources):
        # außerhalb des Scopes nie entdeckt: ein CREATE träfe auf ein bestehendes Objekt
        return [f"{r.kind} {r.id!r} is outside spec.scope.{SCOPE_KEYS[r.kind]}" for r in resources
                if not common.in_scope(target.get("scope"), SCOPE_KEYS[r.kind], r.id)]

    def desired(self, doc):
        spec, kind = dict(doc.get("spec") or {}), doc["kind"]
        if "members" in spec:
            spec["members"] = sorted(set(spec["members"]))
        if "permissions" in spec:
            spec["permissions"] = sorted(({**p} for p in spec["permissions"]), key=_perm_key)
        return Resource(kind, doc["metadata"]["name"], spec)

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None  # ohne tls: http://

    def check(self, session, resource, allow_privileged=False):
        attrs = resource.attrs
        if resource.kind == FOLDER:
            if resource.id.lower() in PROTECTED_FOLDERS:
                return f"folder {resource.id!r} is protected (built-in)"
            admins = [p.get("team") or p.get("role") for p in attrs.get("permissions", [])
                      if p["permission"] == "Admin"]
            if admins and not allow_privileged:
                return (f"folder permission Admin for {admins} (may change folder permissions) not permitted by "
                        "operator policy allowPrivilegedGrants")
        elif resource.kind == SA:
            if resource.id == session.own_sa:
                return f"service account {resource.id!r} is protected (the Ordivus login)"
            if attrs.get("role") == "Admin" and not allow_privileged:
                return "service account role Admin not permitted by operator policy allowPrivilegedGrants"
        elif "members" in attrs:
            try:
                users = self._org_users(session)
            except AuthorizationError:
                return "cannot resolve team members: identity lacks org.users:read"
            if missing := [m for m in attrs["members"] if m not in users]:
                return (f"user(s) {missing} do not exist in organisation {session.org_id} "
                        "(Ordivus does not create users)")
        return None

    def _org_users(self, session) -> dict:
        if session.org_users is None:
            users = _paged(session, "/api/org/users/search", "orgUsers")
            session.org_users = {u["login"]: u["userId"] for u in users if isinstance(u.get("login"), str)}
        return session.org_users

    @contextmanager
    def connect(self, target, secret, write):
        if secret is None:
            raise PermanentError("grafana target requires spec.authentication.credentialRef "
                                 "(service account token, or password with spec.username)")
        base, context = _base(target)
        if "username" in target:
            auth = "Basic " + base64.b64encode(f"{target['username']}:{secret.reveal()}".encode()).decode()
        else:
            auth = "Bearer " + secret.reveal()
        session = Session(base, context, Secret(auth), target.get("orgId", 1), write)
        build = (_request(session, "GET", "/api/frontend/settings") or {}).get("buildInfo") or {}
        version = build.get("version") if isinstance(build.get("version"), str) else ""
        m = re.match(r"(\d+)\.(\d+)", version)
        if not m:
            raise PermanentError("cannot read Grafana version from /api/frontend/settings")
        if tuple(map(int, m.groups())) < MIN_VERSION:
            raise PermanentError(f"Grafana {version} is not supported (minimum {'.'.join(map(str, MIN_VERSION))})")
        session.version = f"Grafana {version}"
        try:
            org = _request(session, "GET", "/api/org")
        except AuthorizationError:  # ohne orgs:read; Grafana bindet dann jeden Request an den Header oder lehnt ab
            org = {"id": session.org_id}
        if not isinstance(org, dict) or org.get("id") != session.org_id:  # Header ignoriert → falsche Organisation
            raise PermanentError(f"connected to organisation {org.get('id') if isinstance(org, dict) else None}, "
                                 f"expected orgId {session.org_id}")
        me = _request(session, "GET", "/api/user")
        if isinstance(me, dict) and str(me.get("uid", "")).startswith("service-account:"):
            session.own_sa = me.get("name")
        perms = _request(session, "GET", "/api/access-control/user/permissions")
        session.permissions = perms if isinstance(perms, dict) else {}
        yield session

    def server_version(self, session):
        return session.version

    def discover(self, session, kind, scope):
        action, prefix = READ[kind]
        key = SCOPE_KEYS[kind]
        if kind == TEAM:
            resources = []
            for t in _paged(session, "/api/teams/search", "teams"):
                if not isinstance(t.get("name"), str) or not common.in_scope(scope, key, t["name"]):
                    continue
                members = self._members(session, _id(t, "teams"))
                resources.append(Resource(kind, t["name"], {"email": t.get("email") or "", "members": sorted(members)},
                                          manageable=not t.get("isProvisioned")))
        elif kind == FOLDER:
            resources = []
            for f in _paged(session, "/api/search", None, {"type": "dash-folder"}, size="limit"):
                uid = f.get("uid")
                if not isinstance(uid, str) or not common.in_scope(scope, key, uid):
                    continue
                folder = _request(session, "GET", f"/api/folders/{quote(uid, safe='')}")
                entries = _request(session, "GET", f"/api/access-control/folders/{quote(uid, safe='')}")
                if not isinstance(folder, dict) or not isinstance(entries, list) or not all(
                        isinstance(e, dict) for e in entries):
                    raise PermanentError(f"folder {uid!r}: unexpected response")
                # shortcut: nur managedBy (Git Sync/Provisioning) gilt als nicht verwaltbar; weitere Marker ergänzen
                resources.append(Resource(kind, uid, {"title": folder.get("title"), "permissions": _perms(entries)},
                                          manageable=not folder.get("managedBy"),
                                          system=uid.lower() in PROTECTED_FOLDERS))
        else:
            resources = [Resource(kind, s["name"], {"role": s.get("role"), "isDisabled": bool(s.get("isDisabled"))},
                                  system=s["name"] == session.own_sa or bool(s.get("isExternal")))
                         for s in _paged(session, "/api/serviceaccounts/search", "serviceAccounts")
                         if isinstance(s.get("name"), str) and common.in_scope(scope, key, s["name"])]
        if not _reads_all(session.permissions, action, prefix):  # Suche liefert dann nur Sichtbares
            return Discovery(PARTIAL, resources, f"identity lacks {action} on {prefix}:*")
        return Discovery(COMPLETE, resources)

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        attrs, new = (op.desired.attrs if op.desired else {}), {f: v for f, (_, v) in op.changes.items()}
        if op.kind == TEAM:
            if op.action == CREATE:
                team = _request(session, "POST", "/api/teams", {"name": op.id, "email": attrs.get("email", "")})
                if "members" in attrs:  # auch der Ersteller wird von Grafana Mitglied: auf Soll bringen
                    self._set_members(session, _id({"id": (team or {}).get("teamId")}, "create team"), attrs["members"])
                return
            tid = self._team_id(session, op.id)
            if op.action == UPDATE:
                if "email" in new:
                    _request(session, "PUT", f"/api/teams/{tid}", {"name": op.id, "email": new["email"]})
                if "members" in new:
                    self._set_members(session, tid, new["members"])
            elif op.action == DELETE:
                _request(session, "DELETE", f"/api/teams/{tid}", ok=(404,))
        elif op.kind == FOLDER:
            if op.id.lower() in PROTECTED_FOLDERS:  # zweite Sperre neben check()
                raise PermanentError(f"folder {op.id!r} is protected")
            path = f"/api/folders/{quote(op.id, safe='')}"
            if op.action == CREATE:
                _request(session, "POST", "/api/folders", {"uid": op.id, "title": attrs["title"]})
                new = attrs  # Grafana vergibt beim Anlegen Standardrechte: auf Soll bringen
            elif op.action == DELETE:  # löscht auch alle Dashboards im Folder; Alert-Regeln verhindern es (kein force)
                _request(session, "DELETE", path, ok=(404,))
                return
            elif "title" in new:
                _request(session, "PUT", path, {"title": new["title"], "overwrite": True})
            if "permissions" in new:
                self._set_permissions(session, op.id, new["permissions"])
        elif op.kind == SA:
            if op.id == session.own_sa:
                raise PermanentError(f"service account {op.id!r} is protected")
            if op.action == CREATE:
                _request(session, "POST", "/api/serviceaccounts", {"name": op.id, **attrs})
            elif op.action == UPDATE:
                _request(session, "PATCH", f"/api/serviceaccounts/{self._sa_id(session, op.id)}", new)
            elif op.action == DELETE:
                _request(session, "DELETE", f"/api/serviceaccounts/{self._sa_id(session, op.id)}", ok=(404,))

    @staticmethod
    def _team_id(session, name) -> int:
        teams = _request(session, "GET", "/api/teams/search", query={"name": name}).get("teams") or []
        match = [t for t in teams if isinstance(t, dict) and t.get("name") == name]
        if len(match) != 1:
            raise PermanentError(f"team {name!r} not found")
        return _id(match[0], "teams")

    @staticmethod
    def _sa_id(session, name) -> int:
        match = [s for s in _paged(session, "/api/serviceaccounts/search", "serviceAccounts", {"query": name})
                 if s.get("name") == name]
        if len(match) != 1:
            raise PermanentError(f"service account {name!r} not found")
        return _id(match[0], "service accounts")

    @staticmethod
    def _members(session, tid) -> dict:
        """Login → userId aller Mitglieder (auch Team-Admins) eines Teams."""
        members = _request(session, "GET", f"/api/teams/{tid}/members")
        if not isinstance(members, list) or not all(
                isinstance(m, dict) and isinstance(m.get("login"), str) and type(m.get("userId")) is int
                for m in members):
            raise PermanentError("team members: unexpected response")
        return {m["login"]: m["userId"] for m in members}

    def _set_members(self, session, tid, logins):
        current = self._members(session, tid)
        users = self._org_users(session)
        for login in sorted(set(logins) - current.keys()):
            if login not in users:
                raise PermanentError(f"user {login!r} does not exist in organisation {session.org_id}")
            _request(session, "POST", f"/api/teams/{tid}/members", {"userId": users[login]})
        for login in sorted(current.keys() - set(logins)):
            _request(session, "DELETE", f"/api/teams/{tid}/members/{current[login]}", ok=(404,))

    def _set_permissions(self, session, uid, desired):
        base = f"/api/access-control/folders/{quote(uid, safe='')}"
        entries = _request(session, "GET", base)
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise PermanentError(f"folder {uid!r} permissions: unexpected response")
        team_ids = {e.get("team"): e.get("teamId") for e in entries if e.get("teamId")}
        current = {_perm_key(p): p["permission"] for p in _perms(entries)}
        want = {_perm_key(p): p["permission"] for p in desired}
        for kind, name in sorted(want.keys() | current.keys()):
            level = want.get((kind, name), "")  # "" entfernt den Eintrag
            if level == current.get((kind, name), ""):
                continue
            if kind == "team":
                path = f"{base}/teams/{int(team_ids.get(name) or self._team_id(session, name))}"
            else:
                path = f"{base}/builtInRoles/{quote(name, safe='')}"
            _request(session, "POST", path, {"permission": level})
