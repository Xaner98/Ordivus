"""Adapter-Registry: lädt Adapter aus der Entry-Point-Gruppe `ordivus.adapters` (§9.6)."""

import logging
from importlib.metadata import entry_points

from ordivus.adapters.base import Adapter

log = logging.getLogger("ordivus")
_registry: dict[str, Adapter] = {}
_loaded = False


def register(adapter_cls: type[Adapter]) -> Adapter:
    """Registriert eine Adapter-Klasse (Entry Points oder Tests); gleiche ID überschreibt."""
    _registry[adapter_cls.id] = adapter_cls()
    return _registry[adapter_cls.id]


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    for ep in entry_points(group="ordivus.adapters"):
        try:
            register(ep.load())
        except Exception as e:  # defektes Plugin darf andere Adapter nicht blockieren
            log.warning("cannot load adapter %r: %s: %s", ep.name, type(e).__name__, e)


def get(adapter_id: str) -> Adapter | None:
    _load()
    return _registry.get(adapter_id)


def all_kinds() -> frozenset[str]:
    _load()
    return frozenset(k for a in _registry.values() for k in a.kinds)
