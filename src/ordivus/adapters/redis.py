"""Redis-Adapter: ACL-Benutzer als ``DatabaseUser`` (Redis ab 7.0, Valkey 8).

Target-Spec::

    endpoint: {host, port (6379), tls: {caFile}}   # tls vorhanden → TLS (rediss)
    username: admin                                  # Admin-User; Passwort über authentication
    persist: none | aclSave | configRewrite          # Default none (nur im Speicher)

Ressource ``DatabaseUser`` (id = Benutzername), spec: ``enabled`` (Default true), ``keys``,
``channels``, ``commands``. Nur deklarierte Felder werden verglichen und geschrieben; nicht
deklarierte Regeln bleiben am Server unverändert (unset ≠ reset, wie in der Engine).
Normalisierung bildet nach, wie Redis Regeln selbst zusammenfasst (siehe ``_commands``), damit
Soll und ``ACL GETUSER`` stabil gleich sind. Doku: ``docs/adapters/redis.md``.
"""

import hashlib
import re
from contextlib import contextmanager
from dataclasses import dataclass
from dataclasses import field as dc_field

from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    SET_PASSWORD,
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

KIND = "DatabaseUser"
FIELDS = {"enabled", "keys", "channels", "commands"}
PERSIST = ("none", "aclSave", "configRewrite")
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}")
COMMAND = re.compile(r"[+-](@[a-z0-9_-]+|[a-z0-9_.-]+(\|[a-z0-9_.-]+)?)")
ALIASES = {"allcommands": "+@all", "nocommands": "-@all"}
KEY_PREFIX = re.compile(r"%(R|W|RW)~")
MIN_VERSION = (7, 0)  # ACL-Selektoren und GETUSER-Format (keys/channels als Regel-String) ab Redis 7.0
PRIVILEGED_CATEGORIES = ("admin", "dangerous")  # allowPrivilegedGrants: jeder Befehl daraus ist privilegiert


# --- Normalisierung (gemeinsam für Soll und Ist) -------------------------------------------------

def _pattern_error(p) -> str | None:
    if not isinstance(p, str) or not p or not p.isprintable() or any(c.isspace() for c in p):
        return f"pattern {p!r} must be a non-empty string without whitespace or control characters"
    return None


def _keys(items: list[str]) -> list[str]:
    """``p``/``~p``/``%RW~p`` → ``p``; ``%R~p``/``%W~p`` bleiben. Gleiche Muster werden wie in Redis
    zusammengeführt (R+W = RW); ein RW-``*`` ersetzt alle anderen Muster."""
    perms: dict[str, set] = {}
    for item in items:
        m = KEY_PREFIX.match(item)
        flags, pattern = (set(m.group(1)), item[m.end():]) if m else ({"R", "W"}, item.removeprefix("~"))
        perms.setdefault(pattern, set()).update(flags)
    if perms.get("*") == {"R", "W"}:
        return ["*"]
    return sorted(p if f == {"R", "W"} else f"%{''.join(sorted(f))}~{p}" for p, f in perms.items())


def _channels(items: list[str]) -> list[str]:
    patterns = {i.removeprefix("&") for i in items}
    return ["*"] if "*" in patterns else sorted(patterns)


def _commands(rules: list[str]) -> list[str]:
    """Simuliert die Zusammenfassung von Redis (empirisch, Redis 8): ``+@all``/``-@all`` setzen die
    Liste zurück; eine Regel ersetzt frühere Regeln für denselben Namen, ein Befehl auch frühere
    Regeln seiner Subcommands. Ergebnis beginnt immer mit ``+@all`` oder ``-@all``."""
    base, out = "-@all", []
    for rule in rules:
        rule = ALIASES.get(rule.lower(), rule.lower())
        if rule in ("+@all", "-@all"):
            base, out = rule, []
            continue
        name = rule[1:]
        sub = not name.startswith("@") and "|" not in name
        out = [r for r in out if r[1:] != name and not (sub and r[1:].startswith(name + "|"))]
        out.append(rule)
    return [base, *out]


def _attrs(spec: dict) -> dict:
    attrs = {"enabled": spec.get("enabled", True)}
    for field, norm in (("keys", _keys), ("channels", _channels), ("commands", _commands)):
        if field in spec:
            attrs[field] = norm(spec[field])
    return attrs


def _allowed(commands: list[str], command: str, category) -> bool:
    """Ob die normalisierte Regelliste ``command`` (``cmd`` oder ``cmd|sub``) ganz oder teilweise erlaubt;
    ``category(name)`` liefert die Befehle einer Kategorie (ACL CAT). Spätere Regeln gewinnen, wie in Redis."""
    allowed = commands[0] == "+@all"
    for rule in commands[1:]:
        name = rule[1:]
        # +parent|sub erlaubt einen Teil von parent: ACL CAT listet bei Modulbefehlen (ft.config) nur den Parent
        part = rule[0] == "+" and name.partition("|")[0] == command
        hit = command in category(name[1:]) if name.startswith("@") else \
            command == name or part or ("|" not in name and command.startswith(name + "|"))
        if hit:
            allowed = rule[0] == "+"
    return allowed


def _rules(attrs: dict) -> list[str]:
    """ACL-SETUSER-Regeln nur für die übergebenen Felder; jede Feldgruppe beginnt mit ihrem Reset."""
    rules = []
    if "enabled" in attrs:
        rules.append("on" if attrs["enabled"] else "off")
    if "keys" in attrs:
        rules += ["resetkeys", *(k if k.startswith("%") else f"~{k}" for k in attrs["keys"])]
    if "channels" in attrs:
        rules += ["resetchannels", *(f"&{c}" for c in attrs["channels"])]
    if "commands" in attrs:
        rules += attrs["commands"]  # beginnt mit +@all/-@all und setzt damit die Befehle zurück
    return rules


# --- Adapter ------------------------------------------------------------------------------------

@dataclass
class RedisSession:
    client: object
    write: bool
    protected: frozenset
    persist: str
    categories: dict = dc_field(default_factory=dict)  # ACL CAT je Kategorie, pro Session gecacht
    version: str | None = None


def _pairs(reply):
    """RESP2 liefert Maps als flache Liste ``[key, value, ...]``, RESP3 als dict (je nach redis-py-Version)."""
    return dict(zip(reply[::2], reply[1::2], strict=True)) if isinstance(reply, list) else reply


def _getuser(client, name: str) -> dict | None:
    info = _pairs(client.execute_command("ACL", "GETUSER", name))
    if info is not None and info.get("selectors"):
        info["selectors"] = [_pairs(sel) for sel in info["selectors"]]
    return info


def _server_version(info: dict) -> tuple[str, tuple]:
    """``INFO server`` → (``"Redis 8.0.2"``/``"Valkey 8.1.0"``, Redis-kompatible Version als Tupel)."""
    compat = re.match(r"(\d+)\.(\d+)", str(info.get("redis_version", "")))  # Valkey meldet 7.2.4
    if info.get("server_name") == "valkey":
        shown = f"Valkey {info.get('valkey_version', info.get('redis_version'))}"
    else:
        shown = f"Redis {info.get('redis_version')}"
    return shown, tuple(int(x) for x in compat.groups()) if compat else (0, 0)


def _error(e: Exception, secret: Secret | None = None) -> Exception:
    import redis

    msg = f"{type(e).__name__}: {e}"
    if secret is not None and secret.reveal():
        msg = msg.replace(secret.reveal(), "<redacted>")
    if isinstance(e, redis.exceptions.AuthenticationError | redis.exceptions.NoPermissionError) \
            or "NOPERM" in str(e) or "WRONGPASS" in str(e):
        return AuthorizationError(msg)
    if isinstance(e, redis.exceptions.ConnectionError | redis.exceptions.TimeoutError):
        return TransientError(msg)
    return PermanentError(msg)


def _endpoint(target: dict) -> tuple:
    ep = target.get("endpoint", {})
    return ep["host"], ep.get("port", 6379)


class RedisAdapter(Adapter):
    id = "redis"
    api_version = 1
    kinds = (KIND,)
    password_kinds = (KIND,)

    def validate(self, doc):
        spec, errors = doc.get("spec") or {}, []
        if doc["kind"] == "Target":
            errors += [f"unknown field spec.{k}" for k in spec if k not in {"endpoint", "username", "persist"}]
            ep = spec.get("endpoint")
            if not isinstance(ep, dict):
                return [*errors, "spec.endpoint must be a mapping"]
            errors += common.validate_endpoint(ep)
            if not isinstance(spec.get("username", "default"), str) or not spec.get("username", "default"):
                errors.append("spec.username must be a non-empty string")
            if spec.get("persist", "none") not in PERSIST:
                errors.append(f"spec.persist must be one of {list(PERSIST)}")
            return errors
        name = doc["metadata"]["name"]
        if not isinstance(name, str) or not USERNAME.fullmatch(name):
            errors.append(f"metadata.name {name!r} is not a valid Redis user name "
                          "(ASCII letters, digits, . _ @ : -; must start with a letter or digit)")
        for k in spec:
            if k == "selectors":
                errors.append("spec.selectors is not supported (see docs/adapters/redis.md)")
            elif k not in FIELDS:
                errors.append(f"unknown field spec.{k}")
        if not isinstance(spec.get("enabled", True), bool):
            errors.append("spec.enabled must be a boolean")
        for field in ("keys", "channels", "commands"):
            items = spec.get(field, [])
            if not isinstance(items, list):
                errors.append(f"spec.{field} must be a list of strings")
                continue
            for item in items:
                if field == "commands":
                    ok = isinstance(item, str) and (item.lower() in ALIASES or COMMAND.fullmatch(item.lower()))
                    if not ok:
                        errors.append(f"spec.commands: invalid rule {item!r} (expected +cmd, -cmd, "
                                      "+cmd|sub, +@category, allcommands or nocommands)")
                elif problem := _pattern_error(item):
                    errors.append(f"spec.{field}: {problem}")
        return errors

    def desired(self, doc):
        return Resource(KIND, doc["metadata"]["name"], _attrs(doc.get("spec") or {}))

    @contextmanager
    def connect(self, target, secret, write):
        import redis  # Extra ordivus[redis]; absoluter Import → redis-py, nicht dieses Modul

        tls = target["endpoint"].get("tls")
        username = target.get("username", "default")
        host, port = _endpoint(target)
        client = redis.Redis(
            host=host, port=port, username=username, password=secret.reveal() if secret else None,
            ssl=tls is not None, ssl_ca_certs=(tls or {}).get("caFile"), ssl_check_hostname=True,
            decode_responses=True,
            socket_timeout=10, socket_connect_timeout=10)
        persist = target.get("persist", "none")
        try:
            client.ping()
            info = client.info("server")
            version, compat = _server_version(info)
            if compat < MIN_VERSION:
                raise PermanentError(f"{version} is not supported (minimum Redis 7.0)")
            if write and persist != "none":  # vor jeder Änderung prüfen, ob Persistenz überhaupt geht
                aclfile = client.config_get("aclfile").get("aclfile")
                if persist == "aclSave" and not aclfile:
                    raise PermanentError("persist aclSave requires 'aclfile' to be configured on the server")
                if persist == "configRewrite" and not info.get("config_file"):
                    raise PermanentError("persist configRewrite requires the server to run with a config file")
                if persist == "configRewrite" and aclfile:  # CONFIG REWRITE schreibt Benutzer dann nicht mit
                    raise PermanentError("persist configRewrite does not persist users when 'aclfile' is "
                                         "configured on the server; use persist: aclSave")
            yield RedisSession(client, write, frozenset({"default", username}), persist, version=version)
        except redis.exceptions.RedisError as e:
            raise _error(e, secret) from None
        finally:
            client.close()

    def server_version(self, session):
        return session.version

    def _category(self, session, name: str) -> frozenset:
        if name not in session.categories:
            session.categories[name] = frozenset(
                c.lower() for c in session.client.execute_command("ACL", "CAT", name))
        return session.categories[name]

    def _privileged(self, session, commands: list[str]) -> set:
        category = lambda name: self._category(session, name)  # noqa: E731
        candidates = set().union(*(category(c) for c in PRIVILEGED_CATEGORIES))
        return {c for c in candidates if _allowed(commands, c, category)}

    def check(self, session, resource, allow_privileged=False):
        import redis

        if resource.id in session.protected:
            return f"user {resource.id!r} is protected (default or the Ordivus login)"
        if allow_privileged or "commands" not in resource.attrs:
            return None
        try:
            added = self._privileged(session, resource.attrs["commands"])
            if added:  # nur neu hinzukommende Rechte sperren; bestehende bleiben unangetastet erlaubt
                info = _getuser(session.client, resource.id)
                if info is not None:
                    added -= self._privileged(session, _commands(info["commands"].split()))
        except redis.exceptions.RedisError as e:
            return f"cannot resolve ACL categories to check for privileged commands ({type(e).__name__})"
        if added:
            shown = ", ".join(sorted(added)[:8]) + (", ..." if len(added) > 8 else "")
            return (f"privileged commands (@admin/@dangerous: {shown}) not permitted by operator policy "
                    "allowPrivilegedGrants")
        return None

    def discover(self, session, kind, scope):
        import redis

        resources = []
        try:
            for name in session.client.acl_users():
                info = _getuser(session.client, name)
                if info is None:  # zwischen USERS und GETUSER gelöscht
                    continue
                attrs = {
                    "enabled": "on" in info["flags"],
                    "keys": _keys(info["keys"].split()),
                    "channels": _channels(info["channels"].split()),
                    "commands": _commands(info["commands"].split()),
                }
                if info.get("selectors"):  # nur zur Sichtbarkeit; nie verglichen oder geschrieben
                    attrs["selectors"] = [" ".join(f"{k}={v}" for k, v in s.items()) for s in info["selectors"]]
                resources.append(Resource(KIND, name, attrs, system=name in session.protected))
        except redis.exceptions.RedisError as e:
            raise _error(e) from None
        return Discovery(COMPLETE, resources)

    def apply(self, session, op: Op):
        import redis

        if not session.write:
            raise PermanentError("read-only session: refusing to modify Redis ACL")
        if op.id in session.protected or not USERNAME.fullmatch(op.id):
            raise PermanentError(f"refusing to modify protected or invalid user {op.id!r}")
        pw = [f">{op.password.reveal()}"] if op.password else []
        if op.action == CREATE:
            cmd = ["ACL", "SETUSER", op.id, "reset", *_rules(op.desired.attrs), *pw]
        elif op.action == UPDATE:
            cmd = ["ACL", "SETUSER", op.id, *_rules({f: new for f, (_, new) in op.changes.items()})]
        elif op.action == SET_PASSWORD:
            cmd = ["ACL", "SETUSER", op.id, "resetpass", *pw]
        elif op.action == DELETE:
            cmd = ["ACL", "DELUSER", op.id]
        else:
            raise PermanentError(f"unsupported action {op.action}")
        try:
            session.client.execute_command(*cmd)
            if session.persist == "aclSave":
                session.client.execute_command("ACL", "SAVE")
            elif session.persist == "configRewrite":
                session.client.config_rewrite()
        except redis.exceptions.RedisError as e:
            raise _error(e, op.password) from None

    def verify_password(self, session, target, resource, password: Secret):
        # Vergleich gegen die SHA-256-Hashes aus ACL GETUSER, ohne Login-Versuch; Hashes nie in attrs.
        # shortcut: no AUTH fallback when ACL GETUSER fails (engine reports unverifiable), add one if a
        # target hides ACL GETUSER output.
        import redis

        try:
            info = _getuser(session.client, resource.id)
        except redis.exceptions.RedisError as e:
            raise _error(e) from None
        if info is None:
            return None
        if "nopass" in info["flags"]:
            return False  # jedes Passwort würde akzeptiert: gilt als nicht durchgesetzt
        return hashlib.sha256(password.reveal().encode()).hexdigest() in info["passwords"]

    def insecure_transport(self, target):
        return target["endpoint"].get("tls") is None
