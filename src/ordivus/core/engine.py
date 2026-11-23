"""Reconciliation Engine: Config → Sollmodell, Discovery, Vergleich, Policy, Ausführung (§6, §8, §10).

`plan` und `drift` öffnen nur Read-only-Sessions und rufen keine schreibenden Provider-Methoden auf;
nur `apply` erzeugt Secrets und ruft `Adapter.apply`.
"""

import fnmatch
import logging
from collections import defaultdict
from contextlib import nullcontext
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
from ordivus.core import config, report
from ordivus.core.config import ConfigError, Document
from ordivus.core.policy import OperatorPolicy, PolicyError
from ordivus.credentials import PROVIDERS
from ordivus.credentials.base import (
    ABSENT,
    ALPHABETS,
    MIN_LENGTH,
    PRESENT,
    CredentialError,
    CredentialProvider,
    generate,
)
from ordivus.credentials.base import UNKNOWN as CRED_UNKNOWN

log = logging.getLogger("ordivus")
MODES = ("plan", "drift", "apply")
MUTATING = (CREATE_SECRET, CREATE, UPDATE, DELETE, SET_PASSWORD)
PASSWORD_POLICIES = ("verify", "enforce", "set-on-create")


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


@dataclass
class Model:
    targets: dict[str, Target]
    credentials: dict[str, Credential]
    providers: dict[str, CredentialProvider]


# --- Validierung ------------------------------------------------------------------------------

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
    if not isinstance(resource_kinds, list) or not set(resource_kinds) <= set(kinds):
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
    if spec.get("providerRef") not in providers:
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
    if type(length) is not int or length < MIN_LENGTH:
        errors.append(f"{where}: generator.length must be an integer >= {MIN_LENGTH}")
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
        cls = PROVIDERS.get(spec(doc).get("type"))
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
        credentials[doc.name] = Credential(doc.name, spec(doc), providers.get(spec(doc).get("providerRef")))

    targets = {}
    for doc in by_kind["Target"]:
        s = spec(doc)
        adapter = adapters.get(s["adapter"]) if isinstance(s.get("adapter"), str) else None
        target = targets[doc.name] = Target(doc.name, s, adapter)
        if adapter is None:
            errors.append(f"{where(doc)}: unknown adapter {s.get('adapter')!r}")
            continue
        auth = s.get("authentication", {})
        if not isinstance(auth, dict):
            errors.append(f"{where(doc)}: spec.authentication must be a mapping")
        else:
            errors += _unknown(auth, {"credentialRef"}, where(doc), "spec.authentication")
            target.auth = auth.get("credentialRef")
            if target.auth is not None and target.auth not in credentials:
                errors.append(f"{where(doc)}: unknown credentialRef {target.auth!r}")
        errors += [f"{where(doc)}: {p}" for p in adapter.validate(_strip(doc.data, ("adapter", "authentication")))]

    for doc in by_kind["ReconciliationPolicy"]:
        target = targets.get(spec(doc).get("targetRef"))
        if target is None:
            errors.append(f"{where(doc)}: unknown targetRef {spec(doc).get('targetRef')!r}")
        elif target.adapter is not None:
            if target.policy is not None:
                errors.append(f"{where(doc)}: more than one ReconciliationPolicy for target {target.name!r}")
            errors += _check_policy(spec(doc), target, where(doc))
            target.policy = spec(doc)

    for doc in by_kind["resource"]:
        s, target = spec(doc), targets.get(spec(doc).get("targetRef"))
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
            if creds.get("credentialRef") not in credentials:
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
    if found.status not in DISCOVERY_STATUSES:
        return Discovery("unknown", [], f"adapter returned invalid status {found.status!r}")
    return found


def _state(cred: Credential) -> str:
    try:
        return cred.provider.state(cred.spec)
    except Exception as e:  # jeder Providerfehler ist "unknown", nie "absent"
        log.warning("credential %r: state unknown (%s)", cred.name, type(e).__name__)
        return CRED_UNKNOWN


def _password_ops(target: Target, op: Op, model: Model, policy: OperatorPolicy) -> list[Op]:
    """Passwort-Operationen für eine deklarierte Ressource mit `spec.credentials` (§10.5, §10.6)."""
    cred = model.credentials[op.desired.password_ref]
    password_policy = target.password_policy[(op.kind, op.id)]
    state, out = _state(cred), []
    if state == CRED_UNKNOWN:
        out.append(Op(target.name, "Credential", cred.name, UNKNOWN, reason="credential state unknown"))
        if op.action == CREATE:
            op.action, op.status, op.reason = BLOCKED, "skipped", "credential state unknown"
        return out
    if state == ABSENT:  # D-023: Secret fehlt → anlegen und am bestehenden User durchsetzen
        out.append(Op(target.name, "Credential", cred.name, CREATE_SECRET))
        reset = op.observed is not None
    elif op.observed is None or password_policy == "set-on-create":
        reset = False
    elif password_policy == "enforce":
        reset = True
    else:
        try:
            equal = target.adapter.verify_password(target.spec, op.observed, cred.provider.read(cred.spec))
        except (AdapterError, CredentialError) as e:
            log.warning("%s %s: password check failed (%s)", op.kind, op.id, type(e).__name__)
            equal = None
        if equal is None:
            out.append(Op(target.name, op.kind, op.id, UNKNOWN, observed=op.observed, reason="password unverifiable"))
        reset = equal is False
    if reset:
        p = Op(target.name, op.kind, op.id, SET_PASSWORD, desired=op.desired, observed=op.observed)
        if not policy.allowPasswordReset:
            p.action, p.status, p.reason = BLOCKED, "denied", "password reset not permitted by operator policy"
        out.append(p)
    return out


def reconcile(target: Target, found: dict[str, Discovery], model: Model, policy: OperatorPolicy) -> list[Op]:
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
            if have is None:
                op.action, op.reason = (CREATE, "") if complete else (UNKNOWN, f"discovery {discovery.status}")
            else:
                op.changes = {f: (have.attrs.get(f), v) for f, v in sorted(want.attrs.items())
                              if have.attrs.get(f) != v}
                if op.changes and have.manageable and not have.system:
                    op.action = UPDATE
                elif op.changes:
                    op.action, op.status, op.reason = BLOCKED, "skipped", "not manageable by adapter"
            ops.append(op)
            if want.password_ref and op.action in (CREATE, UPDATE, NOOP):
                ops += _password_ops(target, op, model, policy)
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
    result = sorted(unique.values(), key=order)
    for op in result:
        if op.action in MUTATING and op.status is None:
            op.status = "planned"
    return result


# --- Ausführung ---------------------------------------------------------------------------------

def _verify(target: Target, session, op: Op) -> bool:
    """Liest die Ressource nach der Operation erneut; False = Ergebnis weicht ab."""
    # shortcut: re-discovers the whole kind per op, upgrade to a per-resource read when inventories get large.
    found = _discover(target, session, op.kind)
    have = next((r for r in found.resources if r.id == op.id), None)
    if op.action == DELETE:
        return found.status == COMPLETE and have is None
    if have is None:
        return False
    if op.password is not None:
        try:
            if target.adapter.verify_password(target.spec, have, op.password) is False:
                return False
        except AdapterError:
            pass  # nicht prüfbar ist kein Gegenbeweis
    return op.action == SET_PASSWORD or all(have.attrs.get(f) == v for f, v in op.desired.attrs.items())


def _scrub(text: str, secrets: list[Secret]) -> str:
    for s in secrets:
        if s.reveal():
            text = text.replace(s.reveal(), "<redacted>")
    return text


def _execute(target: Target, session, ops: list[Op], model: Model, known: list[Secret]) -> None:
    """Führt mutierende Ops der Reihe nach aus; nach einem Fehler werden die übrigen übersprungen."""
    created: dict[str, Secret] = {}
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
                created[op.id] = cred.provider.create_if_absent(
                    cred.spec, generate(gen.get("length", 32), gen.get("alphabet", "alphanumeric")))
                known.append(created[op.id])
                op.status = "succeeded" if _state(cred) == PRESENT else "unverified"
                continue
            ref = op.desired.password_ref if op.desired else None
            if ref and op.action in (CREATE, SET_PASSWORD):
                cred = model.credentials[ref]
                op.password = created.get(ref) or cred.provider.read(cred.spec)
                known.append(op.password)
            target.adapter.apply(session, op)
            op.status = "succeeded" if _verify(target, session, op) else "unverified"
        except Exception as e:  # jeder Fehler (auch Adapter-Bugs) stoppt dieses Target, nicht den Lauf
            failed, op.status = True, "failed"
            op.reason = _scrub(f"{type(e).__name__}: {e}", known)
        finally:
            op.password = None


def _run_target(mode: str, target: Target, model: Model, policy: OperatorPolicy) -> tuple[dict, list[Op]]:
    info = {"targetId": target.name, "adapter": target.adapter.id, "inventory": {}, "status": "error"}
    ops: list[Op] = []
    known: list[Secret] = []
    try:
        secret = None
        if target.auth:
            cred = model.credentials[target.auth]
            secret = cred.provider.read(cred.spec)
            known.append(secret)
        write = mode == "apply"
        with target.adapter.connect(target.spec, secret, write) as session, \
                (target.adapter.lock(session) if write else nullcontext()):
            found = {kind: _discover(target, session, kind) for kind in target.adapter.kinds}
            info["inventory"] = {k: {"status": d.status, "count": len(d.resources), **({"reason": d.reason}
                                 if d.reason else {})} for k, d in found.items()}
            ops = reconcile(target, found, model, policy)
            if write:
                _execute(target, session, ops, model, known)
    except (AdapterError, CredentialError) as e:
        info["reason"] = _scrub(f"{type(e).__name__}: {e}", known)
        log.error("target %s: %s", target.name, info["reason"])
        return info, ops
    info["status"] = report.target_status(mode, info["inventory"], ops)
    return info, ops


def run(mode: str, docs: list[Document], policy: OperatorPolicy | None = None,
        only: list[str] | None = None) -> dict:
    """Führt plan/drift/apply aus und liefert das Report-Modell (§15.1).

    Wirft ConfigError (Exit 12) und PolicyError (Exit 11) vor jeder Verbindung zu einem Target.
    """
    assert mode in MODES
    policy = policy or OperatorPolicy()
    started = datetime.now(UTC)
    model = prepare(docs)
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
        if (model.targets[name].policy or {}).get("mode") == "authoritative" and not policy.allowAuthoritative:
            if mode == "apply":
                raise PolicyError(f"target {name!r}: authoritative mode not permitted by operator policy")
            log.warning("target %s: authoritative mode not permitted by operator policy", name)
    targets, ops = [], []
    for name in names:
        info, target_ops = _run_target(mode, model.targets[name], model, policy)
        targets.append(info)
        ops += target_ops
    return report.build(mode, started, datetime.now(UTC), config.digest(docs), targets, ops)
