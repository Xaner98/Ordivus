"""In-Memory-Referenzadapter für Tests und Demos. Zustand lebt nur im Prozess.

Target-Spec: ``{adapter: fake, instance: <name>}``. Kinds: ``FakeItem`` (spec.attrs frei),
``FakeUser`` (spec.attrs frei, Passwort über ``spec.credentials``).
Teststeuerung über Klassenattribute: ``store``, ``discovery_status``, ``fail``, ``unverifiable``,
``connect_error``, ``calls``; ``reset()`` setzt alles zurück.
"""

from contextlib import contextmanager
from dataclasses import dataclass

from ordivus.adapters.base import (
    COMPLETE,
    CREATE,
    DELETE,
    SET_PASSWORD,
    UPDATE,
    Adapter,
    Discovery,
    Op,
    PermanentError,
    Resource,
    Secret,
    TransientError,
)


@dataclass
class FakeSession:
    instance: str
    write: bool


class FakeAdapter(Adapter):
    id = "fake"
    api_version = 1
    kinds = ("FakeItem", "FakeUser")
    password_kinds = ("FakeUser",)

    # instance -> kind -> id -> {"attrs": dict, "password": str|None, "manageable": bool, "system": bool}
    store: dict = {}
    discovery_status: dict = {}  # (instance, kind) -> status
    fail: dict = {}  # (instance, action, id) -> Fehlermeldung
    unverifiable: set = set()  # (instance, id): verify_password liefert None
    connect_error: set = set()  # instances
    calls: list = []  # (instance, action, kind, id)

    @classmethod
    def reset(cls):
        for name in ("store", "discovery_status", "fail"):
            setattr(cls, name, {})
        cls.unverifiable, cls.connect_error, cls.calls = set(), set(), []

    @classmethod
    def put(cls, instance, kind, id, attrs=None, password=None, manageable=True, system=False):
        cls.store.setdefault(instance, {}).setdefault(kind, {})[id] = {
            "attrs": dict(attrs or {}), "password": password, "manageable": manageable, "system": system}

    def validate(self, doc):
        spec = doc.get("spec") or {}
        allowed = {"instance"} if doc["kind"] == "Target" else {"attrs"}
        errors = [f"unknown field spec.{k}" for k in spec if k not in allowed]
        if doc["kind"] == "Target" and not isinstance(spec.get("instance"), str):
            errors.append("spec.instance must be a string")
        if not isinstance(spec.get("attrs", {}), dict):
            errors.append("spec.attrs must be a mapping")
        return errors

    def desired(self, doc):
        return Resource(doc["kind"], doc["metadata"]["name"], dict((doc.get("spec") or {}).get("attrs", {})))

    @contextmanager
    def connect(self, target, secret, write):
        if target["instance"] in self.connect_error:
            raise TransientError(f"cannot connect to fake instance {target['instance']!r}")
        yield FakeSession(target["instance"], write)

    def discover(self, session, kind, scope):
        objects = self.store.get(session.instance, {}).get(kind, {})
        resources = [Resource(kind, id, dict(o["attrs"]), manageable=o["manageable"], system=o["system"])
                     for id, o in objects.items()]
        return Discovery(self.discovery_status.get((session.instance, kind), COMPLETE), resources)

    def apply(self, session, op: Op):
        if not session.write:
            raise PermanentError("read-only session")
        self.calls.append((session.instance, op.action, op.kind, op.id))
        if (session.instance, op.action, op.id) in self.fail:
            raise PermanentError(self.fail[(session.instance, op.action, op.id)])
        objects = self.store.setdefault(session.instance, {}).setdefault(op.kind, {})
        password = op.password.reveal() if op.password else None
        if op.action == CREATE:
            self.put(session.instance, op.kind, op.id, op.desired.attrs, password)
        elif op.action == UPDATE:
            objects[op.id]["attrs"].update({f: new for f, (_, new) in op.changes.items()})
        elif op.action == DELETE:
            del objects[op.id]
        elif op.action == SET_PASSWORD:
            objects[op.id]["password"] = password

    def verify_password(self, session, target, resource, password: Secret):
        if (target["instance"], resource.id) in self.unverifiable:
            return None
        obj = self.store.get(target["instance"], {}).get(resource.kind, {}).get(resource.id)
        return None if obj is None else obj["password"] == password.reveal()
