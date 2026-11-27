"""Eingebaute Compliance-Regeln gegen den beobachteten Zustand (§35 Punkt 2).

Jede Regel liest genau ein Kind eines Adapters aus der Discovery des Laufs (keine eigenen Abfragen) und
prüft jedes beobachtete Objekt, deklariert oder nicht. Unvollständige Discovery oder nicht prüfbare Objekte
ergeben Status ``incomplete``, nie "keine Verstöße".
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from ordivus.adapters import openbao
from ordivus.adapters.base import COMPLETE, Discovery, Resource

ENTRY_FIELDS = {"id", "enabled", "allow"}
PG_WRITE = ("DELETE", "INSERT", "TRUNCATE", "UPDATE")


class Unevaluable(Exception):
    """Objekt kann von der Regel nicht sicher geprüft werden (z. B. unverständlicher Policy-Text)."""


@dataclass(frozen=True)
class Rule:
    adapter: str
    kind: str
    severity: str
    check: Callable[[Resource], str | None]  # Verstoß-Text oder None; Unevaluable, wenn nicht prüfbar
    subject: Callable[[Resource], str] = lambda r: r.id  # Name, gegen den `allow` geprüft wird


def _table_writes(r: Resource) -> str | None:
    if r.attrs.get("on") != "tables-in-schema":
        return None
    found = [p for p in PG_WRITE if p in r.attrs.get("privileges", [])]
    return f"{', '.join(found)} on all tables in schema {r.attrs['schema']!r} of database " \
           f"{r.attrs['database']!r} for role {r.attrs['grantee']!r}" if found else None


def _bao_rules(r: Resource) -> list[tuple[str, list[str]]]:
    rules = openbao.parse(r.attrs.get("policy", ""))
    if rules is None:
        raise Unevaluable("policy text is not plain 'path \"...\" { capabilities = [...] }' blocks")
    return rules


def _bao_sudo(r: Resource) -> str | None:
    paths = [p for p, caps in _bao_rules(r) if "sudo" in caps]
    return f"grants sudo on {', '.join(map(repr, paths))}" if paths else None


def _broad(path: str) -> bool:
    """Wildcard-Pfad, der den ganzen Namensraum oder ganz ``sys/`` abdeckt (``*``, ``+/*``, ``sys/*``, ``s*`` …)."""
    pattern = re.sub(r"\{\{.*?\}\}", "*", path).lstrip("/")  # Templates wie * (wie openbao.privileged)
    literal = re.split(r"[*+]", pattern, maxsplit=1)[0]
    return literal != pattern and "sys/".startswith(literal)


def _bao_wildcard(r: Resource) -> str | None:
    found = [f"{p!r} ({', '.join(sorted(set(caps) & openbao.WRITE))})" for p, caps in _bao_rules(r)
             if _broad(p) and set(caps) & openbao.WRITE]
    return f"grants write capabilities on wildcard path {', '.join(found)}" if found else None


RULES = {
    "postgresql.superuser-login": Rule("postgresql", "DatabaseUser", "critical",
                                       lambda r: "login role has SUPERUSER" if r.attrs.get("superuser") else None),
    "postgresql.createrole-login": Rule("postgresql", "DatabaseUser", "high",
                                        lambda r: "login role has CREATEROLE" if r.attrs.get("createrole") else None),
    "postgresql.table-write-grant": Rule("postgresql", "Grant", "high", _table_writes,
                                         lambda r: r.attrs["grantee"]),
    "openbao.sudo-capability": Rule("openbao", "OpenBaoPolicy", "high", _bao_sudo),
    "openbao.wildcard-write": Rule("openbao", "OpenBaoPolicy", "critical", _bao_wildcard),
}


def check_entry(entry, where: str) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{where} must be a mapping with 'id'"]
    errors = [f"{where}: unknown field {k!r}" for k in entry if k not in ENTRY_FIELDS]
    if entry.get("id") not in RULES:
        errors.append(f"{where}: unknown rule id {entry.get('id')!r} (known: {', '.join(sorted(RULES))})")
    if not isinstance(entry.get("enabled", True), bool):
        errors.append(f"{where}.enabled must be a boolean")
    allow = entry.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(a, str) for a in allow):
        errors.append(f"{where}.allow must be a list of names")
    return errors


def evaluate(target: str, entries: list[dict], found: dict[str, Discovery] | None,
             reason: str = "") -> tuple[list[dict], list[dict]]:
    """(Regel-Ergebnisse, Verstöße) eines Targets; ``found`` None = Target nicht gelesen (``reason``)."""
    results, violations = [], []
    for entry in (e for e in entries if e.get("enabled", True)):
        rule, allow = RULES[entry["id"]], set(entry.get("allow", []))
        discovery = (found or {}).get(rule.kind)
        problems = [reason or "target not read"] if discovery is None else \
            [] if discovery.status == COMPLETE else [f"discovery of {rule.kind} {discovery.status}"]
        count = 0
        for r in sorted(discovery.resources if discovery else [], key=lambda r: r.id):
            if rule.subject(r) in allow:
                continue
            try:
                message = rule.check(r)
            except Unevaluable as e:
                problems.append(f"{r.kind} {r.id!r}: {e}")
                continue
            if message:
                count += 1
                violations.append({"rule": entry["id"], "target": target, "kind": r.kind, "id": r.id,
                                   "severity": rule.severity, "message": message})
        results.append({"rule": entry["id"], "target": target, "status": "incomplete" if problems else "complete",
                        "violations": count, **({"reason": "; ".join(problems)} if problems else {})})
    return results, violations
