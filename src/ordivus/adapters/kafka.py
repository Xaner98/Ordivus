"""Kafka-Adapter: SCRAM-Benutzer (``KafkaUser``) und ACLs (``KafkaAcl``) über die Admin-API (Kafka 2.7+,
getestet mit 4.1 im KRaft-Modus). Nutzerdoku: ``docs/adapters/kafka.md``.

Target-Spec::

    bootstrapServers: ["host:port", ...]
    securityProtocol: SASL_SSL | SASL_PLAINTEXT      # Default SASL_SSL
    mechanism: SCRAM-SHA-512 | SCRAM-SHA-256         # Anmeldung von Ordivus
    username: ordivus-admin                          # Passwort über authentication
    tls: {caFile}                                    # nur SASL_SSL
    scram: {mechanism, iterations}                   # für verwaltete Benutzer
    superUsers: ["User:admin"]                       # Spiegel von super.users (vom Broker nicht lesbar)
    scope: {principals: {include}, resources: {include}}

Mechanismus und Iterationen gelten pro Target, nicht pro Benutzer: Kafka kann einen SCRAM-Credential nur
mit Passwort schreiben, die Engine übergibt das Passwort aber nur bei CREATE/SET_PASSWORD. Eine Abweichung
zählt daher als „Passwort weicht ab“ (``verify``) und wird mit SET_PASSWORD behoben.

ACLs: ein ``KafkaAcl`` ist ein Bindungsschlüssel (Principal, Ressource, Muster, Host, Erlaubnis) mit der
Liste seiner Operationen, wie ``Grant`` im PostgreSQL-Adapter. Kafka-ACLs sind unveränderlich; ein UPDATE
legt fehlende Operationen an und löscht entfernte.
"""

import json
import logging
import re
import socket
import ssl
from contextlib import contextmanager
from dataclasses import dataclass

from ordivus.adapters import common
from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    SET_PASSWORD,
    UNSUPPORTED,
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

USER, ACL = "KafkaUser", "KafkaAcl"
MECHANISMS = ("SCRAM-SHA-512", "SCRAM-SHA-256")
PROTOCOLS = ("SASL_SSL", "SASL_PLAINTEXT")
MIN_VERSION = (2, 7)  # KIP-554: SCRAM-Credentials über die Admin-API (Describe/AlterUserScramCredentials)
TIMEOUT_MS = 10000
RESOURCE_TYPES = ("TOPIC", "GROUP", "CLUSTER", "TRANSACTIONAL_ID", "DELEGATION_TOKEN", "USER")
PATTERN_TYPES = ("LITERAL", "PREFIXED")
PERMISSIONS = ("ALLOW", "DENY")
OPERATIONS = ("ALL", "READ", "WRITE", "CREATE", "DELETE", "ALTER", "DESCRIBE", "CLUSTER_ACTION",
              "DESCRIBE_CONFIGS", "ALTER_CONFIGS", "IDEMPOTENT_WRITE", "CREATE_TOKENS", "DESCRIBE_TOKENS")
PRIVILEGED_OPS = {"ALL", "ALTER", "ALTER_CONFIGS", "CLUSTER_ACTION"}
WILDCARD_WRITE_OPS = {"ALL", "WRITE", "CREATE", "DELETE", "ALTER", "ALTER_CONFIGS"}
# Benutzernamen: keine Steuerzeichen/Leerzeichen; ',' und '=' sind in SCRAM-Namen Sonderzeichen
USERNAME = re.compile(r"[^\s,=:*]{1,255}")
PRINCIPAL = re.compile(r"[A-Za-z][A-Za-z0-9]*:[^\s]{1,255}")
POLICY = "requires operator policy allowPrivilegedGrants"


# --- Validierung ----------------------------------------------------------------------------------

def _servers(value) -> list[str]:
    if not isinstance(value, list) or not value:
        return ["spec.bootstrapServers must be a non-empty list of 'host:port' strings"]
    errors = []
    for s in value:
        host, _, port = s.rpartition(":") if isinstance(s, str) else ("", "", "")
        if not host or common.HOST_FORBIDDEN.search(host) or not port.isdigit() or not 0 < int(port) < 65536:
            errors.append(f"spec.bootstrapServers: {s!r} is not 'host:port'")
    return errors


def _validate_target(spec: dict) -> list[str]:
    known = {"bootstrapServers", "securityProtocol", "mechanism", "username", "tls", "scram", "superUsers", "scope"}
    errors = [f"unknown field spec.{k}" for k in spec if k not in known] + _servers(spec.get("bootstrapServers"))
    protocol = spec.get("securityProtocol", "SASL_SSL")
    if protocol not in PROTOCOLS:
        errors.append(f"spec.securityProtocol must be one of {list(PROTOCOLS)}")
    if spec.get("mechanism", MECHANISMS[0]) not in MECHANISMS:
        errors.append(f"spec.mechanism must be one of {list(MECHANISMS)}")
    if not isinstance(spec.get("username"), str) or not USERNAME.fullmatch(spec["username"]):
        errors.append("spec.username must be a Kafka user name")
    tls = spec.get("tls", {})
    if "tls" in spec and protocol != "SASL_SSL":
        errors.append("spec.tls requires securityProtocol SASL_SSL")
    if not isinstance(tls, dict):
        errors.append("spec.tls must be a mapping")
    else:
        errors += [f"unknown field spec.tls.{k}" for k in tls if k != "caFile"]
        if "caFile" in tls and (not isinstance(tls["caFile"], str) or not tls["caFile"]):
            errors.append("spec.tls.caFile must be a non-empty string")
    scram = spec.get("scram", {})
    if not isinstance(scram, dict):
        errors.append("spec.scram must be a mapping")
    else:
        errors += [f"unknown field spec.scram.{k}" for k in scram if k not in ("mechanism", "iterations")]
        if scram.get("mechanism", MECHANISMS[0]) not in MECHANISMS:
            errors.append(f"spec.scram.mechanism must be one of {list(MECHANISMS)}")
        it = scram.get("iterations", 4096)
        if type(it) is not int or not 4096 <= it <= 16384:  # Grenzen des Brokers
            errors.append("spec.scram.iterations must be an integer 4096-16384")
    supers = spec.get("superUsers", [])
    if not isinstance(supers, list) or not all(isinstance(p, str) and PRINCIPAL.fullmatch(p) for p in supers):
        errors.append("spec.superUsers must be a list of principals like 'User:admin'")
    scope = spec.get("scope", {})
    if not isinstance(scope, dict):
        return [*errors, "spec.scope must be a mapping"]
    for key, sub in scope.items():
        if key not in ("principals", "resources"):
            errors.append(f"unknown field spec.scope.{key}")
        elif not isinstance(sub, dict) or set(sub) - {"include"} or not isinstance(sub.get("include", []), list) \
                or not all(isinstance(g, str) for g in sub.get("include", [])):
            errors.append(f"spec.scope.{key} must be a mapping with 'include' (list of globs)")
    return errors


def _validate_acl(spec: dict) -> list[str]:
    known = {"principal", "resourceType", "resourceName", "patternType", "operations", "permission", "host"}
    errors = [f"unknown field spec.{k}" for k in spec if k not in known]
    if not isinstance(spec.get("principal"), str) or not PRINCIPAL.fullmatch(spec["principal"]):
        errors.append("spec.principal must be a principal like 'User:app'")
    rtype = spec.get("resourceType")
    if not isinstance(rtype, str) or rtype.upper() not in RESOURCE_TYPES:
        errors.append(f"spec.resourceType must be one of {list(RESOURCE_TYPES)}")
    name = spec.get("resourceName")
    if not isinstance(name, str) or not name or not name.isprintable():
        errors.append("spec.resourceName must be a non-empty string")
    elif isinstance(rtype, str) and rtype.upper() == "CLUSTER" and name != "kafka-cluster":
        errors.append("spec.resourceName must be 'kafka-cluster' for resourceType CLUSTER")
    for key, allowed, default in (("patternType", PATTERN_TYPES, "LITERAL"), ("permission", PERMISSIONS, "ALLOW")):
        if not isinstance(spec.get(key, default), str) or spec.get(key, default).upper() not in allowed:
            errors.append(f"spec.{key} must be one of {list(allowed)}")
    if str(spec.get("patternType", "LITERAL")).upper() == "PREFIXED" and name == "*":
        errors.append("spec.resourceName '*' is only valid with patternType LITERAL")
    ops = spec.get("operations")
    if not isinstance(ops, list) or not ops or not all(isinstance(o, str) and o.upper() in OPERATIONS for o in ops):
        errors.append(f"spec.operations must be a non-empty list of {list(OPERATIONS)}")
    host = spec.get("host", "*")
    if not isinstance(host, str) or not host or common.HOST_FORBIDDEN.search(host.replace(":", "")):
        errors.append("spec.host must be '*' or an IP address")
    return errors


def _acl_key(a: dict) -> str:
    return json.dumps([a["principal"], a["resourceType"], a["patternType"], a["resourceName"], a["permission"],
                       a["host"]], ensure_ascii=False, separators=(",", ":"))


def _acl_attrs(spec: dict) -> dict:
    return {"principal": spec["principal"], "resourceType": spec["resourceType"].upper(),
            "resourceName": spec["resourceName"], "patternType": spec.get("patternType", "LITERAL").upper(),
            "permission": spec.get("permission", "ALLOW").upper(), "host": spec.get("host", "*"),
            "operations": sorted({o.upper() for o in spec["operations"]})}


def _privileged_acl(a: dict, super_users: set) -> str | None:
    """Grund, warum die ACL privilegiert ist (allowPrivilegedGrants), sonst None."""
    if a["principal"] in super_users:
        return f"principal {a['principal']} is a super user"
    if a["permission"] == "DENY":  # DENY gewährt nichts; nur ein Wildcard-Principal sperrt auch Ordivus aus
        return "DENY for all principals (User:*) also applies to the Ordivus login" \
            if a["principal"].endswith(":*") else None
    if a["resourceType"] == "CLUSTER":
        return "ACLs on the Cluster resource are privileged"
    if a["resourceType"] == "USER":
        return "ACLs on User resources allow creating tokens for other users"
    if found := sorted(PRIVILEGED_OPS & set(a["operations"])):
        return f"operations {', '.join(found)} are privileged"
    if a["resourceName"] == "*" and (found := sorted(WILDCARD_WRITE_OPS & set(a["operations"]))):
        return f"{', '.join(found)} on all {a['resourceType']} resources ('*') is privileged"
    return None


# --- Verbindung und Fehler ------------------------------------------------------------------------

@dataclass
class KafkaSession:
    admin: object
    target: dict
    write: bool
    version: tuple
    cluster_ops: frozenset
    users: dict | None = None  # zuletzt gesehene SCRAM-Credentials (für check/apply)


def _error(e: Exception, secret: Secret | None = None) -> Exception:
    import kafka.errors as ke

    msg = f"{type(e).__name__}: {e}"[:300]
    if secret is not None and secret.reveal():
        msg = msg.replace(secret.reveal(), "<redacted>")
    if isinstance(e, ke.AuthorizationError | ke.SaslAuthenticationFailedError):
        return AuthorizationError(msg)
    if isinstance(e, ke.RetriableError | ke.KafkaConnectionError | OSError):
        return TransientError(msg)
    return PermanentError(msg)


def _result_error(message: str) -> Exception:
    """Fehlertext aus einer Antwort pro Eintrag (AlterUserScramCredentials)."""
    text = message[:300]
    return AuthorizationError(text) if "permission" in text.lower() or "authoriz" in text.lower() \
        else PermanentError(text)


def _tls(target: dict):
    return common.tls_context(target.get("tls")) if target.get("securityProtocol", "SASL_SSL") == "SASL_SSL" else None


def _call(sock, proto, request):
    """Eine Anfrage senden und genau ihre Antwort lesen (blockierend, mit Socket-Timeout)."""
    request.API_VERSION = 1  # v1 von SaslHandshake/SaslAuthenticate gibt es seit Kafka 1.0, nicht flexibel kodiert
    proto.send_request(request)
    sock.sendall(proto.send_bytes())
    while True:
        data = sock.recv(65536)
        if not data:
            raise ConnectionError("connection closed by broker")
        if out := proto.receive_bytes(data):
            return out[0][1]


def _scram_login(sock, user: str, password: Secret, mechanism: str) -> bool | None:
    # shortcut: uses kafka-python internals (KafkaProtocol, ScramClient), pinned by the extra to <4.
    from kafka.net.sasl.scram import ScramClient
    from kafka.protocol.parser import KafkaProtocol
    from kafka.protocol.sasl import SaslAuthenticateRequest, SaslHandshakeRequest

    proto = KafkaProtocol(client_id="ordivus")
    handshake = _call(sock, proto, SaslHandshakeRequest(mechanism=mechanism))
    if handshake.error_code or mechanism not in handshake.mechanisms:
        return None
    scram = ScramClient(user, password.reveal(), mechanism)
    for message, process in ((scram.first_message, scram.process_server_first_message),
                             (scram.final_message, scram.process_server_final_message)):
        answer = _call(sock, proto, SaslAuthenticateRequest(message()))
        if answer.error_code:
            return False if answer.error_code == 58 else None  # 58 = SASL_AUTHENTICATION_FAILED
        process(answer.auth_bytes)
    return True


def _sasl_login(target: dict, user: str, password: Secret, mechanism: str) -> bool | None:
    """Ein SCRAM-Login über eine blockierende Verbindung zum ersten erreichbaren Bootstrap-Server.

    True: angemeldet. False: der Broker meldet ausdrücklich SASL_AUTHENTICATION_FAILED.
    None: nicht entscheidbar (Mechanismus am Listener nicht aktiv, andere Fehler). Netzfehler werfen
    TransientError. Eigene Verbindung statt kafka-python-Client: dessen Event-Loop verliert die
    Fehlerantwort oft, wenn der Broker direkt danach die Verbindung schließt.
    """
    ctx, last = _tls(target), None
    for server in target["bootstrapServers"]:
        host, _, port = server.rpartition(":")
        try:
            sock = socket.create_connection((host, int(port)), timeout=TIMEOUT_MS / 1000)
        except OSError as e:
            last = e
            continue
        try:
            if ctx is not None:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            return _scram_login(sock, user, password, mechanism)
        except ssl.SSLError as e:  # Zertifikat/TLS-Konfiguration: wiederholt sich ohne Änderung
            raise PermanentError(f"TLS handshake with {server} failed: {type(e).__name__}") from None
        except OSError as e:
            raise TransientError(f"SASL login to {server} failed: {type(e).__name__}") from None
        except Exception as e:  # Protokollfehler, ungültige Server-Signatur: nicht entscheidbar
            logging.getLogger("ordivus").warning("SASL login check to %s inconclusive: %s", server, type(e).__name__)
            return None
        finally:
            sock.close()
    raise TransientError(f"no bootstrap server reachable: {type(last).__name__}")


class KafkaAdapter(Adapter):
    id = "kafka"
    api_version = 1
    kinds = (USER, ACL)
    password_kinds = (USER,)

    def validate(self, doc):
        spec = doc.get("spec") or {}
        if doc["kind"] == "Target":
            return _validate_target(spec)
        if doc["kind"] == ACL:
            return _validate_acl(spec)
        errors = [f"unknown field spec.{k}" for k in spec if k != "name"]
        name = spec.get("name", doc["metadata"]["name"])
        if not isinstance(name, str) or not USERNAME.fullmatch(name):
            errors.append(f"user name {name!r} is invalid (no whitespace, ',', '=', ':', '*'; at most 255 characters)")
        return errors

    def desired(self, doc):
        spec = doc.get("spec") or {}
        if doc["kind"] == ACL:
            attrs = _acl_attrs(spec)
            return Resource(ACL, _acl_key(attrs), attrs)
        return Resource(USER, spec.get("name", doc["metadata"]["name"]), {})

    def export(self, resource):
        # SCRAM-Mechanismen/Iterationen sind Passwortdetails, kein Spec-Feld
        return dict(resource.attrs) if resource.kind == ACL else {}

    def insecure_transport(self, target):
        return target.get("securityProtocol", "SASL_SSL") != "SASL_SSL"

    @contextmanager
    def connect(self, target, secret, write):
        from kafka import KafkaAdminClient

        # Treiberlogs nicht unformatiert auf stderr; Fehler kommen als Exceptions an
        logging.getLogger("kafka").setLevel(logging.CRITICAL)
        if secret is None:
            raise PermanentError("spec.authentication.credentialRef is required")
        mechanism = target.get("mechanism", MECHANISMS[0])
        # Vorab-Login: kafka-python meldet falsche Zugangsdaten sonst nur als Bootstrap-Timeout
        if _sasl_login(target, target["username"], secret, mechanism) is False:
            raise AuthorizationError(f"SASL authentication failed for user {target['username']!r}")
        try:
            admin = KafkaAdminClient(
                bootstrap_servers=target["bootstrapServers"], client_id="ordivus",
                security_protocol=target.get("securityProtocol", "SASL_SSL"), ssl_context=_tls(target),
                sasl_mechanism=mechanism, sasl_plain_username=target["username"],
                sasl_plain_password=secret.reveal(), request_timeout_ms=TIMEOUT_MS, bootstrap_timeout_ms=TIMEOUT_MS)
        except Exception as e:
            raise _error(e, secret) from None
        try:
            version = admin._manager.broker_version  # aus ApiVersions abgeleitet
            if version is None or tuple(version) < MIN_VERSION:
                shown = ".".join(map(str, version)) if version else "unknown"
                raise PermanentError(f"Kafka {shown} is not supported (minimum 2.7)")
            try:
                ops = frozenset(admin.describe_cluster().get("authorized_operations") or ())
            except Exception as e:
                raise _error(e, secret) from None
            yield KafkaSession(admin, target, write, tuple(version), ops)
        finally:
            admin.close()

    def server_version(self, session):
        return "Kafka " + ".".join(map(str, session.version))

    # --- Discovery ---

    def _protected(self, session) -> tuple[str, set]:
        own = f"User:{session.target['username']}"
        return own, {own, *session.target.get("superUsers", [])}

    def discover(self, session, kind, scope):
        import kafka.errors as ke
        from kafka.admin import (
            ACLFilter,
            ACLOperation,
            ACLPermissionType,
            ACLResourcePatternType,
            ResourcePatternFilter,
            ResourceType,
        )

        if "DESCRIBE" not in session.cluster_ops:  # sonst antwortet der Broker teils gar nicht (Timeout)
            raise AuthorizationError("DESCRIBE on the Cluster resource is required to list users and ACLs")
        _, protected = self._protected(session)
        try:
            if kind == USER:
                users = {u: info for u, info in session.admin.describe_user_scram_credentials().items()
                         if not info["error"]}
                session.users = {u: {ci["mechanism"].name.replace("_", "-"): ci["iterations"]
                                     for ci in info["credential_infos"]} for u, info in users.items()}
                return Discovery(COMPLETE, [
                    Resource(USER, u, {"credentials": creds}, system=f"User:{u}" in protected)
                    for u, creds in sorted(session.users.items()) if common.in_scope(scope, "principals", f"User:{u}")])
            acls, _ = session.admin.describe_acls(ACLFilter(
                None, None, ACLOperation.ANY, ACLPermissionType.ANY,
                ResourcePatternFilter(ResourceType.ANY, None, ACLResourcePatternType.ANY)))
        except ke.SecurityDisabledError:
            return Discovery(UNSUPPORTED, [], "no authorizer configured on the broker")
        except Exception as e:
            raise _error(e) from None
        grouped: dict[str, dict] = {}
        for acl in acls:
            attrs = {"principal": acl.principal, "resourceType": acl.resource_pattern.resource_type.name,
                     "resourceName": acl.resource_pattern.resource_name,
                     "patternType": acl.resource_pattern.pattern_type.name,
                     "permission": acl.permission_type.name, "host": acl.host}
            if not (common.in_scope(scope, "principals", attrs["principal"])
                    and common.in_scope(scope, "resources", attrs["resourceName"])):
                continue
            entry = grouped.setdefault(_acl_key(attrs), {**attrs, "operations": []})
            entry["operations"] = sorted({*entry["operations"], acl.operation.name})
        return Discovery(COMPLETE, [Resource(ACL, k, a, system=a["principal"] in protected)
                                    for k, a in sorted(grouped.items())])

    # --- Planung ---

    def check(self, session, resource, allow_privileged=False):
        own, _ = self._protected(session)
        supers = set(session.target.get("superUsers", []))
        scope = session.target.get("scope")
        principal = f"User:{resource.id}" if resource.kind == USER else resource.attrs["principal"]
        if principal == own:
            return f"{principal} is the Ordivus login (protected)"
        if not common.in_scope(scope, "principals", principal):  # auch mit Freigabe nie
            return f"principal {principal} is outside spec.scope.principals"
        if resource.kind == USER:
            if principal in supers and not allow_privileged:
                return f"{principal} is a super user; {POLICY}"
            if resource.password_ref is None and session.users is not None and resource.id not in session.users:
                return "a new KafkaUser needs spec.credentials (a SCRAM user exists only with a password)"
            return None
        if not common.in_scope(scope, "resources", resource.attrs["resourceName"]):
            return f"resource {resource.attrs['resourceName']!r} is outside spec.scope.resources"
        if not allow_privileged and (why := _privileged_acl(resource.attrs, supers)):
            return f"{why}; {POLICY}"
        return None

    def verify_password(self, session, target, resource, password):
        scram = target.get("scram", {})
        mechanism, iterations = scram.get("mechanism", MECHANISMS[0]), scram.get("iterations", 4096)
        if resource.attrs.get("credentials") != {mechanism: iterations}:
            return False  # anderer Mechanismus/Iterationen: nur mit dem Passwort neu schreibbar
        return _sasl_login(target, resource.id, password, mechanism)

    # --- Ausführung ---

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session: refusing to modify Kafka")
        resource = op.desired or op.observed
        principal = f"User:{op.id}" if op.kind == USER else resource.attrs["principal"]
        if principal == self._protected(session)[0]:
            raise PermanentError(f"refusing to modify the Ordivus login {principal}")
        try:
            if op.kind == USER:
                self._apply_user(session, op)
            else:
                self._apply_acl(session, op)
        except AdapterError:
            raise
        except Exception as e:
            raise _error(e, op.password) from None

    def _alter(self, session, alteration):
        result = session.admin.alter_user_scram_credentials([alteration])
        if message := next(iter(result.values()), None):
            raise _result_error(message)

    def _apply_user(self, session, op: Op):
        from kafka.admin import UserScramCredentialDeletion, UserScramCredentialUpsertion

        scram = session.target.get("scram", {})
        mechanism = scram.get("mechanism", MECHANISMS[0])
        if op.action == DELETE:
            others = list(op.observed.attrs.get("credentials", {}))
        elif op.action in (CREATE, SET_PASSWORD):
            if op.password is None:
                raise PermanentError("a KafkaUser can only be written with a password (spec.credentials)")
            self._alter(session, UserScramCredentialUpsertion(op.id, mechanism, op.password.reveal(),
                                                              iterations=scram.get("iterations", 4096)))
            others = [m for m in (op.observed.attrs.get("credentials", {}) if op.observed else {}) if m != mechanism]
        else:
            raise PermanentError(f"unsupported action {op.action} for {USER}")
        for m in others:  # Kafka erlaubt je Benutzer nur eine Änderung pro Anfrage
            self._alter(session, UserScramCredentialDeletion(op.id, m))

    def _apply_acl(self, session, op: Op):
        import kafka.errors as ke
        from kafka.admin import ACL as KAcl
        from kafka.admin import (
            ACLFilter,
            ACLOperation,
            ACLPermissionType,
            ACLResourcePatternType,
            ResourcePattern,
            ResourceType,
        )

        a = (op.desired or op.observed).attrs
        if op.action == CREATE:
            add, remove = a["operations"], []
        elif op.action == UPDATE:
            old, new = op.changes["operations"]
            add, remove = sorted(set(new) - set(old)), sorted(set(old) - set(new))
        elif op.action == DELETE:
            add, remove = [], op.observed.attrs["operations"]
        else:
            raise PermanentError(f"unsupported action {op.action} for {ACL}")
        pattern = ResourcePattern(ResourceType[a["resourceType"]], a["resourceName"],
                                  ACLResourcePatternType[a["patternType"]])

        def binding(cls, operation):
            return cls(a["principal"], a["host"], ACLOperation[operation], ACLPermissionType[a["permission"]], pattern)

        if add:
            failed = session.admin.create_acls([binding(KAcl, o) for o in add])["failed"]
            if failed:
                raise _error(failed[0]())
        if remove:
            for _, _, error in session.admin.delete_acls([binding(ACLFilter, o) for o in remove]):
                if error is not ke.NoError:
                    raise _error(error())
