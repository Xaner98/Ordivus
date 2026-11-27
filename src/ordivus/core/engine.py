"""Reconciliation Engine: Config → Sollmodell, Discovery, Vergleich, Policy, Ausführung (§6, §8, §10).

`plan` und `drift` öffnen nur Read-only-Sessions und rufen keine schreibenden Provider-Methoden auf;
nur `apply` erzeugt Secrets und ruft `Adapter.apply`.
"""

import fnmatch
import heapq
import logging
from collections import Counter, defaultdict
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from ordivus import adapters
from ordivus.adapters.base import (
    BLOCKED,
    COMPLETE,
    CREATE,
    CREATE_SECRET,
    DELETE,
    DISCOVERY_STATUSES,
    FORBIDDEN,
    IGNORE,
    NOOP,
    SET_PASSWORD,
    UNDESIRABLE,
    UNKNOWN,
    UNMANAGED,
    UPDATE,
    Adapter,
    AdapterError,
    AuthorizationError,
    Discovery,
    Op,
    Resource,
    Secret,
)
from ordivus.core import config, report, rules
from ordivus.core.config import ConfigError, Document
from ordivus.core.policy import OperatorPolicy, PolicyError
from ordivus.credentials import PROVIDERS
from ordivus.credentials.base import (
    ABSENT,
    ALPHABETS,
    CONFLICT,
    MIN_LENGTH,
    PRESENT,
    CredentialError,
    CredentialProvider,
    State,
    generate,
)
from ordivus.credentials.base import UNKNOWN as CRED_UNKNOWN

log = logging.getLogger("ordivus")
MODES = ("plan", "drift", "apply")
MUTATING = (CREATE_SECRET, CREATE, UPDATE, DELETE, SET_PASSWORD)
PASSWORD_POLICIES = ("verify", "enforce", "set-on-create")
MAX_LENGTH = 1024  # Obergrenze für generierte Passwörter


@dataclass
class Credential:
    name: str
    spec: dict
    provider: CredentialProvider | None


@dataclass
class Target:
    name: str
    spec: dict
    adapter: Adapter | None
    auth: str | None = None
    desired: list[Resource] = field(default_factory=list)
    password_policy: dict[tuple[str, str], str] = field(default_factory=dict)
    policy: dict | None = None  # spec der ReconciliationPolicy
    rules: list[dict] = field(default_factory=list)  # Einträge aus Rules-Dokumenten (auch enabled: false)


@dataclass
class Model:
    targets: dict[str, Target]
    credentials: dict[str, Credential]
    providers: dict[str, CredentialProvider]
    known: list[Secret] = field(default_factory=list)  # alle in diesem Lauf gelesenen Secrets (Scrubbing)


# --- Validierung ------------------------------------------------------------------------------

def _ref(value) -> str | None:
    """Referenzen sind Strings; alles andere (Listen, Mappings) gilt als nicht gefunden statt TypeError."""
    return value if isinstance(value, str) else None


def _unknown(spec: dict, allowed: set[str], where: str, prefix: str = "spec") -> list[str]:
    return [f"{where}: unknown field {prefix}.{k}" for k in spec if k not in allowed]


def _strip(data: dict, keys: tuple[str, ...]) -> dict:
    return {**data, "spec": {k: v for k, v in (data.get("spec") or {}).items() if k not in keys}}


def _matcher_errors(value, where: str, prefix: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{where}: {prefix} must be a mapping with 'exact' and/or 'glob'"]
    errors = _unknown(value, {"exact", "glob"}, where, prefix)
    for key in ("exact", "glob"):
        items = value.get(key, [])
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            errors.append(f"{where}: {prefix}.{key} must be a list of strings")
    return errors


def _matches(matcher: dict | None, name: str) -> bool:
    if not matcher:
        return False
    return name in matcher.get("exact", []) or any(fnmatch.fnmatchcase(name, g) for g in matcher.get("glob", []))


def _check_policy(spec: dict, target: Target, where: str) -> list[str]:
    errors = _unknown(spec, {"targetRef", "mode", "scope", "exclusions"}, where)
    kinds = target.adapter.kinds
    if spec.get("mode", "additive") not in ("additive", "authoritative"):
        errors.append(f"{where}: spec.mode must be 'additive' or 'authoritative'")
    scope = spec.get("scope", {})
    if not isinstance(scope, dict):
        return [*errors, f"{where}: spec.scope must be a mapping"]
    resource_kinds = scope.get("resourceKinds", [])
    if not isinstance(resource_kinds, list) or not all(isinstance(k, str) for k in resource_kinds) \
            or not set(resource_kinds) <= set(kinds):
        errors.append(f"{where}: spec.scope.resourceKinds must be a list of {list(kinds)}")
    for key, value in scope.items():
        if key != "resourceKinds":
            errors += [f"{where}: unknown field spec.scope.{key}"] if key not in kinds else \
                _matcher_errors(value, where, f"spec.scope.{key}")
    exclusions = spec.get("exclusions", {})
    if not isinstance(exclusions, dict):
        return [*errors, f"{where}: spec.exclusions must be a mapping"]
    for key, value in exclusions.items():
        errors += [f"{where}: unknown field spec.exclusions.{key}"] if key not in kinds else \
            _matcher_errors(value, where, f"spec.exclusions.{key}")
    if spec.get("mode") == "authoritative" and not resource_kinds:
        errors.append(f"{where}: authoritative mode requires spec.scope.resourceKinds (§6.2)")
    return errors


def _check_credential(spec: dict, providers: dict, where: str) -> list[str]:
    errors = _unknown(spec, {"providerRef", "path", "lifecycle"}, where)
    if _ref(spec.get("providerRef")) not in providers:
        errors.append(f"{where}: unknown providerRef {spec.get('providerRef')!r}")
    if not isinstance(spec.get("path"), str) or not spec.get("path"):
        errors.append(f"{where}: spec.path must be a non-empty string")
    lifecycle = spec.get("lifecycle", {})
    if not isinstance(lifecycle, dict):
        return [*errors, f"{where}: spec.lifecycle must be a mapping"]
    errors += _unknown(lifecycle, {"generator"}, where, "spec.lifecycle")
    gen = lifecycle.get("generator", {})
    if not isinstance(gen, dict):
        return [*errors, f"{where}: spec.lifecycle.generator must be a mapping"]
    errors += _unknown(gen, {"length", "alphabet"}, where, "spec.lifecycle.generator")
    length = gen.get("length", 32)
    if type(length) is not int or not MIN_LENGTH <= length <= MAX_LENGTH:
        errors.append(f"{where}: generator.length must be an integer between {MIN_LENGTH} and {MAX_LENGTH}")
    if gen.get("alphabet", "alphanumeric") not in ALPHABETS:
        errors.append(f"{where}: generator.alphabet must be one of {sorted(ALPHABETS)}")
    return errors


def prepare(docs: list[Document]) -> Model:
    """Semantische Validierung (Referenzen, Adapter-Specs) und Aufbau des Sollmodells."""
    errors, by_kind = [], defaultdict(list)
    for doc in docs:
        if not isinstance(doc.data.get("spec", {}), dict):
            errors.append(f"{doc.path}:{doc.line}: spec must be a mapping")
        else:
            by_kind[doc.kind if doc.kind in config.ENGINE_KINDS else "resource"].append(doc)

    def spec(doc):
        return doc.data.get("spec") or {}

    def where(doc):
        return f"{doc.path}:{doc.line}"

    providers, provider_docs = {}, {d.name for d in by_kind["CredentialProvider"]}
    for doc in by_kind["CredentialProvider"]:
        cls = PROVIDERS.get(_ref(spec(doc).get("type")))
        if cls is None:
            errors.append(f"{where(doc)}: spec.type must be one of {sorted(PROVIDERS)}")
            continue
        problems = cls.validate({k: v for k, v in spec(doc).items() if k != "type"})
        errors += [f"{where(doc)}: {p}" for p in problems]
        if not problems:
            providers[doc.name] = cls(spec(doc))

    credentials = {}
    for doc in by_kind["Credential"]:
        problems = _check_credential(spec(doc), provider_docs, where(doc))
        errors += problems
        credentials[doc.name] = Credential(doc.name, spec(doc), providers.get(_ref(spec(doc).get("providerRef"))))

    targets, target_where = {}, {}
    for doc in by_kind["Target"]:
        s = spec(doc)
        adapter = adapters.get(s["adapter"]) if isinstance(s.get("adapter"), str) else None
        target = targets[doc.name] = Target(doc.name, s, adapter)
        target_where[doc.name] = where(doc)
        if adapter is None:
            errors.append(f"{where(doc)}: unknown adapter {s.get('adapter')!r}")
            continue
        auth = s.get("authentication", {})
        if not isinstance(auth, dict):
            errors.append(f"{where(doc)}: spec.authentication must be a mapping")
        else:
            errors += _unknown(auth, {"credentialRef"}, where(doc), "spec.authentication")
            target.auth = _ref(auth.get("credentialRef"))
            if auth.get("credentialRef") is not None and target.auth not in credentials:
                errors.append(f"{where(doc)}: unknown credentialRef {auth.get('credentialRef')!r}")
        errors += [f"{where(doc)}: {p}" for p in adapter.validate(_strip(doc.data, ("adapter", "authentication")))]

    for doc in by_kind["ReconciliationPolicy"]:
        target = targets.get(_ref(spec(doc).get("targetRef")))
        if target is None:
            errors.append(f"{where(doc)}: unknown targetRef {spec(doc).get('targetRef')!r}")
        elif target.adapter is not None:
            if target.policy is not None:
                errors.append(f"{where(doc)}: more than one ReconciliationPolicy for target {target.name!r}")
            errors += _check_policy(spec(doc), target, where(doc))
            target.policy = spec(doc)

    for doc in by_kind["Rules"]:
        s, ref = spec(doc), spec(doc).get("targetRef")
        errors += _unknown(s, {"targetRef", "rules"}, where(doc))
        if ref is not None and _ref(ref) not in targets:
            errors.append(f"{where(doc)}: unknown targetRef {ref!r}")
            continue
        if not isinstance(s.get("rules"), list) or not s["rules"]:
            errors.append(f"{where(doc)}: spec.rules must be a non-empty list")
            continue
        for i, entry in enumerate(s["rules"]):
            if problems := rules.check_entry(entry, f"{where(doc)}: spec.rules[{i}]"):
                errors += problems
                continue
            adapter = rules.RULES[entry["id"]].adapter
            if ref is not None and targets[ref].adapter is not None and targets[ref].adapter.id != adapter:
                errors.append(f"{where(doc)}: spec.rules[{i}]: rule {entry['id']!r} applies to adapter "
                              f"{adapter!r}, target {ref!r} uses {targets[ref].adapter.id!r}")
                continue
            for target in [targets[ref]] if ref is not None else \
                    [t for t in targets.values() if t.adapter is not None and t.adapter.id == adapter]:
                if any(e["id"] == entry["id"] for e in target.rules):
                    errors.append(f"{where(doc)}: spec.rules[{i}]: rule {entry['id']!r} configured more than "
                                  f"once for target {target.name!r}")
                else:
                    target.rules.append(entry)

    for doc in by_kind["resource"]:
        s, target = spec(doc), targets.get(_ref(spec(doc).get("targetRef")))
        if target is None:
            errors.append(f"{where(doc)}: unknown targetRef {s.get('targetRef')!r}")
            continue
        if target.adapter is None:
            continue
        if doc.kind not in target.adapter.kinds:
            errors.append(f"{where(doc)}: kind {doc.kind} not supported by adapter {target.adapter.id!r}")
            continue
        creds = s.get("credentials")
        if creds is not None:
            if doc.kind not in target.adapter.password_kinds:
                errors.append(f"{where(doc)}: kind {doc.kind} does not support spec.credentials")
                continue
            if not isinstance(creds, dict):
                errors.append(f"{where(doc)}: spec.credentials must be a mapping")
                continue
            errors += _unknown(creds, {"credentialRef", "passwordPolicy"}, where(doc), "spec.credentials")
            if _ref(creds.get("credentialRef")) not in credentials:
                errors.append(f"{where(doc)}: unknown credentialRef {creds.get('credentialRef')!r}")
            if creds.get("passwordPolicy", "verify") not in PASSWORD_POLICIES:
                errors.append(f"{where(doc)}: passwordPolicy must be one of {list(PASSWORD_POLICIES)}")
        stripped = _strip(doc.data, ("targetRef", "credentials"))
        problems = target.adapter.validate(stripped)
        errors += [f"{where(doc)}: {p}" for p in problems]
        if problems:
            continue
        resource = replace(target.adapter.desired(stripped), password_ref=creds and creds.get("credentialRef"))
        if any((r.kind, r.id) == (resource.kind, resource.id) for r in target.desired):
            errors.append(f"{where(doc)}: duplicate {resource.kind} {resource.id!r} on target {target.name!r}")
        target.desired.append(resource)
        if creds:
            target.password_policy[(resource.kind, resource.id)] = creds.get("passwordPolicy", "verify")

    for name, target in targets.items():  # dokumentübergreifende Prüfung je Target
        if target.adapter is not None:
            errors += [f"{target_where[name]}: target {name!r}: {p}"
                       for p in target.adapter.validate_target(target.spec, target.desired)]

    if errors:
        raise ConfigError(errors)
    return Model(targets, credentials, providers)


# --- Discovery und Vergleich --------------------------------------------------------------------

def _discover(target: Target, session, kind: str) -> Discovery:
    try:
        found = target.adapter.discover(session, kind, target.spec.get("scope"))
    except AuthorizationError as e:
        return Discovery(FORBIDDEN, [], str(e))
    except AdapterError as e:
        return Discovery("unknown", [], f"{type(e).__name__}: {e}")
    except Exception as e:  # Adapter-Bug: Kind bleibt unbekannt, der Lauf geht weiter (Meldung wird zentral gescrubbt)
        log.error("target %s: discovery of %s failed: %s: %s", target.name, kind, type(e).__name__, e)
        return Discovery("unknown", [], f"internal error: {type(e).__name__}: {e}")
    if not isinstance(found, Discovery) or found.status not in DISCOVERY_STATUSES:
        return Discovery("unknown", [], "adapter returned an invalid discovery result")
    return found


def _read(cred: Credential, known: list[Secret]) -> Secret:
    return _nonempty(cred, cred.provider.read(cred.spec), known)


def _nonempty(cred: Credential, value, known: list[Secret]) -> Secret:
    """Leere Secrets nie verwenden: ein abgebrochenes Anlegen o. Ä. würde sonst ein leeres Passwort setzen."""
    if not isinstance(value, Secret) or not value.reveal():
        raise CredentialError(f"credential {cred.name!r} is empty or invalid")
    known.append(value)
    return value


def _state(cred: Credential) -> State:
    try:
        state = cred.provider.state(cred.spec)
    except (AdapterError, CredentialError) as e:  # jeder Providerfehler ist "unknown", nie "absent"
        state = State(CRED_UNKNOWN, f"{type(e).__name__}: {e}")
    except Exception as e:
        state = State(CRED_UNKNOWN, type(e).__name__)
    state = state if isinstance(state, State) else State(state)
    if state in (CRED_UNKNOWN, CONFLICT):
        log.warning("credential %r: state %s (%s)", cred.name, state, state.reason or "no reason given")
    return state


def _password_ops(target: Target, session, op: Op, model: Model, policy: OperatorPolicy) -> list[Op]:
    """Passwort-Operationen für eine deklarierte Ressource mit `spec.credentials` (§10.5, §10.6)."""
    cred = model.credentials[op.desired.password_ref]
    password_policy = target.password_policy[(op.kind, op.id)]
    state, out, value = _state(cred), [], None
    if state == PRESENT:  # früh lesen: ein unlesbarer oder leerer Wert ist "unknown", bevor etwas geplant wird
        try:
            value = _read(cred, model.known)
        except (AdapterError, CredentialError) as e:
            state = State(CRED_UNKNOWN, f"{type(e).__name__}: {e}")
    if state in (CRED_UNKNOWN, CONFLICT):  # conflict: nur manuell lösbar → BLOCKED statt UNKNOWN
        reason = state.reason or f"credential state {state}"
        cop = Op(target.name, "Credential", cred.name, UNKNOWN, reason=reason)
        if state == CONFLICT:
            cop.action, cop.status, cop.reason = BLOCKED, "skipped", f"manual action required: {reason}"
        out.append(cop)
        if op.action == CREATE:
            op.action, op.status, op.reason = BLOCKED, "skipped", f"credential {cred.name!r}: {reason}"
        return out
    if state == ABSENT:  # D-023: Secret fehlt → anlegen und am bestehenden User durchsetzen
        out.append(Op(target.name, "Credential", cred.name, CREATE_SECRET, reason=state.reason))
        reset = op.observed is not None
    elif op.observed is None or password_policy == "set-on-create":
        reset = False
    elif password_policy == "enforce":
        reset = True
    else:
        try:
            equal = target.adapter.verify_password(session, target.spec, op.observed, value)
        except AdapterError as e:
            log.warning("%s %s: password check failed (%s)", op.kind, op.id, type(e).__name__)
            equal = None
        if equal is None:
            out.append(Op(target.name, op.kind, op.id, UNKNOWN, desired=op.desired, observed=op.observed,
                          reason="password unverifiable"))
        reset = equal is False
    if reset:
        p = Op(target.name, op.kind, op.id, SET_PASSWORD, desired=op.desired, observed=op.observed)
        if not policy.allowPasswordReset:
            p.action, p.status, p.reason = BLOCKED, "denied", "password reset not permitted by operator policy"
        out.append(p)
    return out


def reconcile(target: Target, found: dict[str, Discovery], model: Model, policy: OperatorPolicy,
              session=None) -> list[Op]:
    """Reconciliation-Matrix §6.1; Ergebnis deterministisch sortiert (Ausführungsreihenfolge)."""
    rp = target.policy or {}
    scope, exclusions = rp.get("scope", {}), rp.get("exclusions", {})
    authoritative = rp.get("mode") == "authoritative"
    ops = []
    for kind in target.adapter.kinds:
        discovery = found[kind]
        complete = discovery.status == COMPLETE
        observed = {r.id: r for r in discovery.resources}
        declared = {r.id: r for r in target.desired if r.kind == kind}
        for id, want in declared.items():
            have = observed.get(id)
            op = Op(target.name, kind, id, NOOP, desired=want, observed=have)
            if have is not None:
                op.changes = {f: (have.attrs.get(f), v) for f, v in sorted(want.attrs.items())
                              if have.attrs.get(f) != v}
            if blocked := target.adapter.check(session, want, policy.allowPrivilegedGrants):
                op.action, op.status, op.reason = BLOCKED, "skipped", blocked
            elif have is None:
                op.action, op.reason = (CREATE, "") if complete else (UNKNOWN, f"discovery {discovery.status}")
            elif have.system or not have.manageable:  # auch ohne Abweichung: nie als NOOP "verwaltet" melden
                op.action, op.status = BLOCKED, "skipped"
                op.reason = "protected system object" if have.system else "not manageable by adapter"
            elif op.changes:
                op.action = UPDATE
            ops.append(op)
            if want.password_ref and op.action in (CREATE, UPDATE, NOOP):
                ops += _password_ops(target, session, op, model, policy)
        for id, have in observed.items():
            if id in declared:
                continue
            op = Op(target.name, kind, id, UNMANAGED, observed=have)
            in_scope = kind in scope.get("resourceKinds", []) and (kind not in scope or _matches(scope[kind], id))
            if have.system or _matches(exclusions.get(kind), id):
                op.action = IGNORE
            elif not complete:
                op.action, op.reason = UNKNOWN, f"discovery {discovery.status}"
            elif authoritative and in_scope:
                if not policy.allowAuthoritative:
                    op.action, op.status = BLOCKED, "denied"
                    op.reason = "authoritative mode not permitted by operator policy"
                elif policy.allowDelete and have.manageable:
                    op.action = DELETE
                else:
                    op.action = UNDESIRABLE
                    op.reason = "not manageable by adapter" if not have.manageable else ""
            ops.append(op)
    rank = {k: i for i, k in enumerate(target.adapter.kinds)}

    def order(op):
        if op.kind == "Credential":  # Secrets vor allen Ressourcen, die sie verwenden
            return (0, 0, op.id, op.action == SET_PASSWORD, op.action)
        if op.action == DELETE:  # Löschungen zuletzt, in umgekehrter Kind-Reihenfolge
            return (2, -rank[op.kind], op.id, False, op.action)
        return (1, rank[op.kind], op.id, op.action == SET_PASSWORD, op.action)

    unique = {(o.kind, o.id, o.action): o for o in reversed(ops)}  # ein CREATE_SECRET je Credential
    result = _dependency_order(target.adapter, sorted(unique.values(), key=order))
    for op in result:
        if op.action in MUTATING and op.status is None:
            op.status = "planned"
    return result


def _dependency_order(adapter: Adapter, ops: list[Op]) -> list[Op]:
    """Stabile topologische Sortierung: Abhängigkeiten gehen vor, sonst bleibt die Reihenfolge von ``ops``.

    Anlegen/Ändern folgt ``Adapter.dependencies``, Löschen läuft umgekehrt. Ops in einem Zyklus (und
    alles, was davon abhängt) werden BLOCKED.
    """
    targets = defaultdict(list)  # (kind, id, ist DELETE) -> Indizes der Ops, von denen andere abhängen können
    for i, o in enumerate(ops):
        if o.action in (CREATE, UPDATE, DELETE):
            targets[(o.kind, o.id, o.action == DELETE)].append(i)
    after = defaultdict(set)  # i -> Ops, die erst nach i laufen dürfen
    for i, o in enumerate(ops):
        if o.action in (CREATE, UPDATE, SET_PASSWORD, DELETE):
            for kind, id in adapter.dependencies(o.desired or o.observed):
                for j in targets[(kind, id, o.action == DELETE)]:
                    if j != i and o.action == DELETE:  # abhängige Ressource zuerst löschen
                        after[i].add(j)
                    elif j != i:
                        after[j].add(i)
    pending = Counter(j for js in after.values() for j in js)
    ready = [i for i in range(len(ops)) if not pending[i]]
    heapq.heapify(ready)
    done = []
    while ready:
        i = heapq.heappop(ready)
        done.append(i)
        for j in after[i]:
            pending[j] -= 1
            if not pending[j]:
                heapq.heappush(ready, j)
    stuck = [i for i in range(len(ops)) if pending[i] > 0]
    names = ", ".join(f"{ops[i].kind}/{ops[i].id}" for i in stuck)
    for i in stuck:
        ops[i].action, ops[i].status, ops[i].reason = BLOCKED, "skipped", f"dependency cycle among {names}"
    return [ops[i] for i in done + stuck]


# --- Ausführung ---------------------------------------------------------------------------------

def _verify(target: Target, session, op: Op, found: Discovery, password: Secret | None) -> bool:
    """Prüft eine ausgeführte Op gegen die erneute Discovery ihres Kinds; False = Ergebnis weicht ab."""
    have = next((r for r in found.resources if r.id == op.id), None)
    if op.action == DELETE:
        return found.status == COMPLETE and have is None
    if have is None:
        return False
    if password is not None:
        try:
            if target.adapter.verify_password(session, target.spec, have, password) is False:
                return False
        except AdapterError:
            pass  # nicht prüfbar ist kein Gegenbeweis
    return op.action == SET_PASSWORD or all(have.attrs.get(f) == v for f, v in op.desired.attrs.items())


def _conflict(found: Discovery, op: Op) -> str | None:
    """Prüft DELETE/SET_PASSWORD gegen eine frische Discovery (TOCTOU); Grund, falls der Plan nicht mehr passt."""
    have = next((r for r in found.resources if r.id == op.id), None)
    if have is None or (op.action == DELETE and found.status != COMPLETE):
        return f"changed since plan: re-read found {'nothing' if have is None else 'object'} " \
               f"(discovery {found.status})"
    if have.system or not have.manageable:
        return "changed since plan: object is now protected or not manageable"
    if op.action == DELETE and have.attrs != op.observed.attrs:
        return "changed since plan: attributes differ"
    return None


def _scrub(text: str, secrets: list[Secret]) -> str:
    for value in sorted({s.reveal() for s in secrets if s.reveal()}, key=len, reverse=True):
        text = text.replace(value, report.REDACTED)
    return text


def _scrub_all(value, secrets: list[Secret]):
    """Scrubbt jeden String im Report-Modell (Gründe aus Discovery, Providern, Adapter-Bugs …)."""
    if isinstance(value, str):
        return _scrub(value, secrets)
    if isinstance(value, dict):
        return {k: _scrub_all(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_all(v, secrets) for v in value]
    return value


class _ScrubFilter(logging.Filter):
    def __init__(self, secrets: list[Secret]):
        super().__init__()
        self.secrets = secrets

    def filter(self, record):
        record.msg, record.args = _scrub(record.getMessage(), self.secrets), ()
        return True


def _execute(target: Target, session, ops: list[Op], model: Model) -> None:
    """Führt mutierende Ops der Reihe nach aus; nach einem Fehler werden die übrigen übersprungen.

    Verifiziert wird danach gebündelt: eine Discovery je betroffenem Kind statt je Op.
    """
    created: dict[str, Secret] = {}
    fresh: dict[str, Discovery] = {}  # Re-Read je Kind vor DELETE/SET_PASSWORD
    applied: list[tuple[Op, Secret | None]] = []
    failed = False
    for op in ops:
        if op.action not in MUTATING:
            continue
        if failed:
            op.status, op.reason = "skipped", "previous operation on this target failed"
            continue
        try:
            if op.action == CREATE_SECRET:
                cred = model.credentials[op.id]
                gen = cred.spec.get("lifecycle", {}).get("generator", {})
                created[op.id] = _nonempty(cred, cred.provider.create_if_absent(
                    cred.spec, generate(gen.get("length", 32), gen.get("alphabet", "alphanumeric"))), model.known)
                op.status = "succeeded" if _state(cred) == PRESENT else "unverified"
                continue
            if op.action in (DELETE, SET_PASSWORD) and op.kind not in fresh:
                fresh[op.kind] = _discover(target, session, op.kind)
            if op.action in (DELETE, SET_PASSWORD) and (reason := _conflict(fresh[op.kind], op)):
                op.status, op.reason = "conflict", reason
                log.warning("target %s: %s %s/%s not executed: %s", target.name, op.action, op.kind, op.id, reason)
                continue
            ref = op.desired.password_ref if op.desired else None
            if ref and op.action in (CREATE, SET_PASSWORD):
                cred = model.credentials[ref]
                op.password = created.get(ref) or _read(cred, model.known)
            target.adapter.apply(session, op)
            if op.action in (CREATE, UPDATE):  # DELETE/SET_PASSWORD ändern nur ihr eigenes, schon geprüftes Objekt
                fresh.pop(op.kind, None)
            op.status = "unverified"  # bis die Verifikation unten das Ergebnis beobachtet
            applied.append((op, op.password))
        except Exception as e:  # jeder Fehler (auch Adapter-Bugs) stoppt dieses Target, nicht den Lauf
            failed, op.status = True, "failed"
            op.reason = f"{type(e).__name__}: {e}"  # Scrubbing zentral in run()
        finally:
            op.password = None
    found = {kind: _discover(target, session, kind) for kind in dict.fromkeys(op.kind for op, _ in applied)}
    for op, password in applied:
        try:
            if _verify(target, session, op, found[op.kind], password):
                op.status = "succeeded"
        except Exception as e:  # Adapter-Bug in der Prüfung: bleibt "unverified"
            log.error("target %s: verifying %s/%s failed: %s", target.name, op.kind, op.id, type(e).__name__)


def _open(target: Target, model: Model, write: bool) -> tuple[ExitStack, object, Exception | None, bool]:
    """Verbindet (und sperrt in apply); liefert (Stack, Session, Fehler, Lock nicht erhalten)."""
    stack, stage = ExitStack(), "connect"
    try:
        secret = _read(model.credentials[target.auth], model.known) if target.auth else None
        session = stack.enter_context(target.adapter.connect(target.spec, secret, write))
        stage = "lock"
        if write:
            stack.enter_context(target.adapter.lock(session))
        return stack, session, None, False
    except Exception as e:
        with suppress(Exception):  # der ursprüngliche Fehler zählt
            stack.close()
        return stack, None, e, stage == "lock"


def _run_target(mode: str, target: Target, model: Model, policy: OperatorPolicy,
                opened=None) -> tuple[dict, list[Op], tuple[list, list]]:
    """``opened``: Ergebnis von ``_open`` aus der Lock-Vorphase, sonst wird hier verbunden.

    Regeln werden gegen die Discovery vor allen Änderungen ausgewertet (auch in apply)."""
    info = {"targetId": target.name, "adapter": target.adapter.id, "inventory": {}, "status": "error"}
    if target.adapter.insecure_transport(target.spec):
        info["insecureTransport"] = True
    ops: list[Op] = []
    checked = None
    write = mode == "apply"
    try:
        stack, session, error, _ = opened or _open(target, model, write)
        if error:
            raise error
        with stack:
            if (server := target.adapter.server_version(session)) is not None:
                info["serverVersion"] = server
            found = {kind: _discover(target, session, kind) for kind in target.adapter.kinds}
            info["inventory"] = {k: {"status": d.status, "count": len(d.resources), **({"reason": d.reason}
                                 if d.reason else {})} for k, d in found.items()}
            checked = rules.evaluate(target.name, target.rules, found)
            ops = reconcile(target, found, model, policy, session)
            if write:
                _execute(target, session, ops, model)
    except Exception as e:  # auch Adapter-Bugs: dieses Target ist Fehler, die übrigen laufen weiter
        expected = isinstance(e, AdapterError | CredentialError)
        info["reason"] = f"{'' if expected else 'internal error: '}{type(e).__name__}: {e}"
        log.error("target %s: %s", target.name, info["reason"])
        if write and any(o.status in ("succeeded", "unverified") for o in ops):
            info["status"] = "partial"  # schon etwas geändert: Exit 14 statt 13
        for o in ops:
            if write and o.status == "planned":
                o.status, o.reason = "skipped", "target aborted"
        return info, ops, checked or rules.evaluate(target.name, target.rules, None, "target error")
    info["status"] = report.target_status(mode, info["inventory"], ops,
                                          (target.policy or {}).get("mode") == "authoritative")
    return info, ops, checked


def preflight(mode: str, model: Model, policy: OperatorPolicy, only: list[str] | None) -> list[str]:
    """Gewählte Targets (sortiert); ConfigError/PolicyError vor der ersten Verbindung (§11.6)."""
    names = sorted(model.targets)
    if only:
        missing = sorted(set(only) - set(names))
        if missing:
            raise ConfigError([f"unknown target {n!r}" for n in missing])
        names = sorted(set(only))
    # Policy fail closed vor der ersten Verbindung (§11.6)
    for name, provider in model.providers.items():
        if provider.development_only and policy.profile != "development":
            raise PolicyError(f"credential provider {name!r} ({provider.type}) requires profile 'development'")
    for name in names:
        if not policy.allows_target(name):
            raise PolicyError(f"target {name!r} not allowed by operator policy")
        if (model.targets[name].policy or {}).get("mode") == "authoritative" and not policy.allowAuthoritative \
                and mode != "export":
            if mode == "apply":
                raise PolicyError(f"target {name!r}: authoritative mode not permitted by operator policy")
            log.warning("target %s: authoritative mode not permitted by operator policy", name)
        if model.targets[name].adapter.insecure_transport(model.targets[name].spec):
            if policy.requireTls:
                raise PolicyError(f"target {name!r}: insecure transport (no TLS or no certificate verification) "
                                  "not permitted by operator policy requireTls")
            log.warning("target %s: insecure transport (no TLS or no certificate verification)", name)
    return names


def run(mode: str, docs: list[Document], policy: OperatorPolicy | None = None,
        only: list[str] | None = None) -> dict:
    """Führt plan/drift/apply aus und liefert das Report-Modell (§15.1).

    Wirft ConfigError (Exit 12) und PolicyError (Exit 11) vor jeder Verbindung zu einem Target.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    policy = policy or OperatorPolicy()
    started = datetime.now(UTC)
    digest = config.digest(docs)  # vor jeder Verbindung: nicht serialisierbare Configs scheitern ohne Mutation
    model = prepare(docs)
    names = preflight(mode, model, policy, only)
    targets, ops, results, violations, scrub = [], [], [], [], _ScrubFilter(model.known)
    log.addFilter(scrub)
    opened = {}  # apply: alle sperrbaren Targets vorab verbinden und sperren, bevor irgendwo geschrieben wird
    try:
        if mode == "apply":
            opened = {n: _open(model.targets[n], model, True) for n in names
                      if type(model.targets[n].adapter).lock is not Adapter.lock}
        held = [n for n, o in opened.items() if o[3]]  # Lock hält ein anderer apply
        for name in names:
            if held and name not in held:
                targets.append({"targetId": name, "adapter": model.targets[name].adapter.id, "inventory": {},
                                "status": "skipped", "reason": "not run: lock on target(s) "
                                f"{', '.join(map(repr, held))} is held by another apply"})
                checked = rules.evaluate(name, model.targets[name].rules, None, "target skipped")
            else:
                info, target_ops, checked = _run_target(mode, model.targets[name], model, policy,
                                                        opened.pop(name, None))
                targets.append(info)
                ops += target_ops
            results += checked[0]
            violations += checked[1]
    finally:
        for stack, *_ in opened.values():  # übersprungene Targets: Sperre und Verbindung sofort freigeben
            with suppress(Exception):
                stack.close()
        log.removeFilter(scrub)
    return _scrub_all(report.build(mode, started, datetime.now(UTC), digest, targets, ops, results, violations),
                      model.known)
