"""Report-Modell (§15.1), Exit-Code-Ableitung und Renderer (JSON Lines, Human) desselben Modells."""

import json
from collections import Counter
from importlib.metadata import version

from ordivus.adapters.base import (
    BLOCKED,
    CREATE,
    CREATE_SECRET,
    DELETE,
    IGNORE,
    NOOP,
    SET_PASSWORD,
    UNDESIRABLE,
    UNKNOWN,
    UNMANAGED,
    UPDATE,
    Op,
)

SCHEMA_VERSION = "1.0"
ACTIONS = (NOOP, CREATE_SECRET, CREATE, UPDATE, SET_PASSWORD, DELETE, UNMANAGED, UNDESIRABLE, IGNORE,
           UNKNOWN, BLOCKED)
ACTIONABLE = (CREATE_SECRET, CREATE, UPDATE, SET_PASSWORD, DELETE)
REDACTED = "<redacted>"


def _op(op: Op) -> dict:
    changes = {f: {"old": old, "new": new} for f, (old, new) in op.changes.items()}
    if op.action == CREATE and op.desired:
        changes = {f: {"old": None, "new": v} for f, v in sorted(op.desired.attrs.items())}
    if op.action == SET_PASSWORD:  # Passwörter nur über SET_PASSWORD/CREATE_SECRET sichtbar, nie bei CREATE
        changes["password"] = {"old": REDACTED, "new": REDACTED}
    out = {"target": op.target, "kind": op.kind, "id": op.id, "action": op.action, "status": op.status,
           "changes": changes}
    if op.observed and not op.observed.manageable:
        out["manageable"] = False
    if op.observed and op.observed.system:
        out["system"] = True
    return {**out, "reason": op.reason} if op.reason else out


def target_status(mode: str, inventory: dict, ops: list[Op]) -> str:
    if mode == "apply":
        if any(o.status in ("failed", "unverified", "skipped") and o.action in ACTIONABLE for o in ops):
            return "partial"
        return "applied" if any(o.status == "succeeded" for o in ops) else "in_sync"
    if any(o.action in ACTIONABLE or o.action == BLOCKED for o in ops):
        return "drift_detected"
    if any(i["status"] != "complete" for i in inventory.values()) or any(o.action == UNKNOWN for o in ops):
        return "incomplete"
    return "in_sync"


def build(mode, started, finished, digest: str, targets: list[dict], ops: list[Op]) -> dict:
    counts = Counter(o.action for o in ops)
    statuses = Counter(o.status for o in ops)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "run": {
            "mode": mode,
            "startedAt": started.isoformat().replace("+00:00", "Z"),
            "finishedAt": finished.isoformat().replace("+00:00", "Z"),
            "configDigest": digest,
            "engineVersion": version("ordivus"),
            "identity": {"value": None, "source": "unknown"},
        },
        "summary": {
            "actions": {a: counts[a] for a in ACTIONS},
            "actionableDrift": sum(counts[a] for a in ACTIONABLE),
            "failed": statuses["failed"],
            "unverified": statuses["unverified"],
            "targetErrors": sum(t["status"] == "error" for t in targets),
        },
        "targets": targets,
        "operations": [_op(o) for o in ops if o.action != IGNORE],  # Exclusions nur gezählt (§5.2)
        "secretsIncluded": False,
    }


def exit_code(report: dict, fail_on: str | None = None) -> int:
    """14 Teilausführung > 13 Target/Credential > 11 Policy-Verweigerung > 10 Schwelle > 0."""
    ops, summary, apply = report["operations"], report["summary"], report["run"]["mode"] == "apply"
    if summary["failed"] or summary["unverified"]:
        return 14
    if summary["targetErrors"] or (apply and any(o["kind"] == "Credential" and o["action"] == UNKNOWN for o in ops)):
        return 13
    # BLOCKED gibt es in apply nur an deklarierten Ressourcen (Authoritative-Verbot bricht vorher ab)
    if apply and any(o["status"] == "denied" or o["action"] == BLOCKED for o in ops):
        return 11
    actions = summary["actions"]
    exceeded = {
        None: False,
        "changes": summary["actionableDrift"] > 0,
        "actionable": summary["actionableDrift"] > 0,
        "unmanaged": summary["actionableDrift"] + actions[UNMANAGED] + actions[UNDESIRABLE] > 0,
        "any": any(o["action"] != NOOP for o in ops),
    }[fail_on]
    return 10 if exceeded else 0


def render_json(report: dict) -> str:
    return json.dumps({"type": "report", **report}, default=str, separators=(",", ":"))


def _value(v) -> str:
    return json.dumps(v, default=str)


def render_human(report: dict) -> str:
    run = report["run"]
    lines = [f"ordivus {run['mode']}  config {run['configDigest']}  engine {run['engineVersion']}"]
    for t in report["targets"]:
        inventory = ", ".join(f"{k} {i['status']} ({i['count']})" for k, i in t["inventory"].items())
        lines.append(f"\ntarget {t['targetId']} [{t['adapter']}]: {t['status']}"
                     + (f" - {t['reason']}" if t.get("reason") else ""))
        if inventory:
            lines.append(f"  inventory: {inventory}")
        for o in report["operations"]:
            if o["target"] != t["targetId"] or o["action"] == NOOP:
                continue
            status = f" [{o['status']}]" if o["status"] else ""
            lines.append(f"  {o['action']:<14} {o['kind']}/{o['id']}{status}"
                         + (f"  ({o['reason']})" if o.get("reason") else ""))
            lines += [f"      {f}: {_value(c['old'])} -> {_value(c['new'])}" for f, c in o["changes"].items()]
    s = report["summary"]
    counts = " ".join(f"{a}={n}" for a, n in s["actions"].items() if n)
    lines.append(f"\nsummary: {counts or 'nothing'}; actionable={s['actionableDrift']} "
                 f"failed={s['failed']} unverified={s['unverified']} targetErrors={s['targetErrors']}")
    return "\n".join(lines)
