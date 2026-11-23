"""Adapter-Registry: lädt Adapter aus der Entry-Point-Gruppe `ordivus.adapters` (§9.6)."""

import logging
from importlib.metadata import entry_points

from ordivus.adapters.base import API_VERSION, Adapter

log = logging.getLogger("ordivus")
_registry: dict[str, Adapter] = {}
_loaded = False


def _problem(cls) -> str | None:
    """Grund, warum ``cls`` kein ladbarer Adapter für diesen Vertrag ist, sonst None."""
    if not (isinstance(cls, type) and issubclass(cls, Adapter)):
        return "not a subclass of ordivus.adapters.base.Adapter"
    if not isinstance(getattr(cls, "id", None), str) or not cls.id:
        return "id must be a non-empty string"
    kinds = getattr(cls, "kinds", None)
    if not isinstance(kinds, tuple | list) or not kinds or not all(isinstance(k, str) and k for k in kinds):
        return "kinds must be a non-empty tuple of strings"
    if cls.api_version != API_VERSION:
        return f"built for contract {cls.api_version}, engine supports {API_VERSION}"
    return None


def register(adapter_cls: type[Adapter]) -> Adapter | None:
    """Registriert eine Adapter-Klasse (Tests); gleiche ID überschreibt. Entry Points nutzen ``_load``.
    Ungültige Klassen werden mit Warnung übersprungen (None)."""
    if problem := _problem(adapter_cls):
        log.warning("adapter %s skipped: %s", getattr(adapter_cls, "__name__", repr(adapter_cls)), problem)
        return None
    _registry[adapter_cls.id] = adapter_cls()
    return _registry[adapter_cls.id]


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    # Eingebaute zuerst: ein Plugin mit derselben ID ersetzt nie einen eingebauten Adapter
    for ep in sorted(entry_points(group="ordivus.adapters"), key=lambda ep: not ep.value.startswith("ordivus.")):
        try:
            cls = ep.load()
            if problem := _problem(cls):
                log.warning("adapter %r (%s) skipped: %s", ep.name, ep.value, problem)
                continue
            if cls.id in _registry:
                if type(_registry[cls.id]) is not cls:
                    log.warning("adapter %r from entry point %r ignored: id already registered", cls.id, ep.value)
                continue
            register(cls)
        except Exception as e:  # defektes Plugin darf andere Adapter nicht blockieren
            log.warning("cannot load adapter %r: %s: %s", ep.name, type(e).__name__, e)


def get(adapter_id: str) -> Adapter | None:
    _load()
    return _registry.get(adapter_id)


def all_kinds() -> frozenset[str]:
    _load()
    return frozenset(k for a in _registry.values() for k in a.kinds)
