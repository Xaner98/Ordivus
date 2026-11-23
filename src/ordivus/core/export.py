"""`ordivus export`: Ist-Zustand der Targets als Ordivus-Konfiguration (§35, Roadmap 1).

Nur lesend wie `plan`: Read-only-Sessions, keine Provider-Schreibzugriffe. Jedes ausgegebene Dokument wird
vorab durch ``Adapter.validate``/``desired`` zurückgeführt; was dabei nicht exakt das beobachtete Objekt
ergibt, wird nicht ausgegeben (sonst würde ein späteres `apply` es ändern).
"""

import logging
from dataclasses import dataclass, field

import yaml

from ordivus.adapters.base import COMPLETE
from ordivus.core import config, engine
from ordivus.core.config import ConfigError, Document
from ordivus.core.policy import OperatorPolicy

log = logging.getLogger("ordivus")


@dataclass
class Result:
    documents: list[dict] = field(default_factory=list)
    incomplete: bool = False  # Target-Fehler, unvollständige Discovery oder nicht exportierbare Objekte


def run(docs: list[Document], policy: OperatorPolicy | None = None, only: list[str] | None = None,
        kinds: list[str] | None = None) -> Result:
    """Wirft ConfigError (Exit 12) und PolicyError (Exit 11) vor jeder Verbindung."""
    policy = policy or OperatorPolicy()
    model = engine.prepare(docs)
    names = engine.preflight("export", model, policy, only)
    if kinds and (unknown := set(kinds) - {k for n in names for k in model.targets[n].adapter.kinds}):
        raise ConfigError([f"kind {k!r} not supported by the selected targets" for k in sorted(unknown)])
    result, seen = Result(), set()
    scrub = engine._ScrubFilter(model.known)
    log.addFilter(scrub)
    try:
        for name in names:
            try:
                _target(model.targets[name], model, kinds, result, seen)
            except Exception as e:  # wie im Plan: ein Adapter-Bug bricht nur dieses Target ab
                log.error("target %s: internal error: %s: %s", name, type(e).__name__, e)
                result.incomplete = True
    finally:
        log.removeFilter(scrub)
    result.documents = engine._scrub_all(result.documents, model.known)
    return result


def _target(target: engine.Target, model: engine.Model, kinds: list[str] | None, result: Result, seen: set) -> None:
    adapter, exclusions = target.adapter, (target.policy or {}).get("exclusions", {})
    stack, session, error, _ = engine._open(target, model, write=False)
    if error:
        log.error("target %s: %s: %s", target.name, type(error).__name__, error)
        result.incomplete = True
        return
    with stack:
        for kind in adapter.kinds:
            if kinds and kind not in kinds:
                continue
            found = engine._discover(target, session, kind)
            if found.status != COMPLETE:
                log.warning("target %s: discovery of %s %s%s; exported only what is visible", target.name, kind,
                            found.status, f" ({found.reason})" if found.reason else "")
                result.incomplete = True
            for r in sorted(found.resources, key=lambda r: r.id):
                if r.system or engine._matches(exclusions.get(kind), r.id):
                    continue  # wie IGNORE im Plan
                if not r.manageable:
                    log.warning("target %s: %s %r skipped: not manageable by adapter", target.name, kind, r.id)
                    continue
                if doc := _document(target, session, r, result):
                    if (kind, r.id) in seen:
                        log.warning("target %s: %s %r skipped: same name already exported from another target "
                                    "(export the targets separately)", target.name, kind, r.id)
                        result.incomplete = True
                        continue
                    seen.add((kind, r.id))
                    result.documents.append(doc)


def _document(target: engine.Target, session, r, result: Result) -> dict | None:
    adapter, what = target.adapter, f"target {target.name}: {r.kind} {r.id!r}"
    spec = adapter.export(r)
    stripped = {"apiVersion": config.API_VERSION, "kind": r.kind, "metadata": {"name": r.id}, "spec": spec}
    problems = adapter.validate(stripped)
    desired = None if problems else adapter.desired(stripped)
    if desired is None or desired.id != r.id or any(r.attrs.get(f) != v for f, v in desired.attrs.items()):
        log.warning("%s skipped: cannot be expressed as configuration%s", what,
                    f" ({'; '.join(problems)})" if problems else "")
        result.incomplete = True
        return None
    if reason := adapter.check(session, desired, True):
        log.warning("%s skipped: %s", what, reason)  # geschützt (eigener Login, eingebaute Objekte)
        return None
    if reason := adapter.check(session, desired, False):
        log.warning("%s: %s", what, reason)
    if r.kind in adapter.password_kinds:
        log.warning("%s: password not exported; add spec.credentials.credentialRef to manage it", what)
    return {**stripped, "spec": {"targetRef": target.name, **spec}}


class _Dumper(yaml.SafeDumper):
    """Quotet Strings, die YAML 1.1 (PyYAML-Default) *oder* 1.2 Core als Nicht-String lesen würde."""

    yaml_implicit_resolvers = {k: list(v) for k, v in yaml.SafeDumper.yaml_implicit_resolvers.items()}


for _first, _resolvers in config._Loader.yaml_implicit_resolvers.items():
    for _tag, _regex in _resolvers:
        _Dumper.add_implicit_resolver(_tag, _regex, [_first])


def _str(dumper, value):  # mehrzeilige Texte (z. B. HCL-Policies) als lesbarer Literal-Block
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _str)


def dump(documents: list[dict]) -> str:
    return yaml.dump_all(documents, Dumper=_Dumper, sort_keys=True, allow_unicode=True, explicit_start=True,
                         default_flow_style=False, width=1000)
