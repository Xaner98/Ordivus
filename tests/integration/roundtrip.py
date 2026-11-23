"""Gemeinsamer Round-trip-Nachweis für `ordivus export`: export → mit den Engine-Dokumenten erneut laden → plan."""

import json
from pathlib import Path

from ordivus.core import config, engine, export
from ordivus.core.policy import OperatorPolicy


def assert_export_roundtrip(path, expected: set[tuple[str, str]], tmp: Path, extra=None, **policy) -> list[dict]:
    """Exportiert die Targets aus ``path``; ``expected`` (kind, id) müssen exportiert sein und im Plan NOOP
    ergeben, kein Plan-Op darf mutieren. ``extra(doc)`` darf exportierte Dokumente ergänzen (z. B. credentials)."""
    docs = config.load(path)
    result = export.run(docs, OperatorPolicy(**policy))
    assert not result.incomplete
    exported = {(d["kind"], d["metadata"]["name"]) for d in result.documents}
    assert expected <= exported, expected - exported
    out = tmp / "exported"
    out.mkdir()
    for i, d in enumerate(d.data for d in docs if d.kind in config.ENGINE_KINDS):
        (out / f"{i:02}.json").write_text(json.dumps(d))
    (out / "resources.yaml").write_text(export.dump([extra(d) if extra else d for d in result.documents]))
    rep = engine.run("plan", config.load(out), OperatorPolicy(**policy))
    actions = {(o["kind"], o["id"]): o["action"] for o in rep["operations"]}
    assert not {a for a in actions.values() if a in engine.MUTATING or a in ("BLOCKED", "UNKNOWN")}, rep["operations"]
    assert all(actions.get(key) == "NOOP" for key in exported), [(k, actions.get(k)) for k in exported]
    return result.documents
