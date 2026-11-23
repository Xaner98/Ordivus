"""Adapter contract (SDK API 1). Adapter authors only need this file.

An adapter translates between Ordivus resources and one kind of target system. The engine
owns everything else: config loading, diffing, policies, ordering, credentials, reports.

Lifecycle per run and target:

1. ``validate(doc)`` for the Target doc and each resource doc bound to the target (config time).
2. ``desired(doc)`` for each resource doc: normalize into a ``Resource``.
3. ``connect(target, secret, write)``; in apply additionally ``lock(session)``.
4. ``discover(session, kind, scope)`` once per kind in ``kinds``.
5. apply only: ``apply(session, op)`` per operation, followed by ``discover`` again to verify.
6. ``verify_password`` where a resource carries ``spec.credentials`` with policy ``verify``.

Rules every adapter must keep:

- ``plan``/``drift`` use ``write=False`` sessions; nothing reachable from a read-only session
  may mutate the target (use read-only transactions or refuse in ``apply``).
- Never put secret values into exceptions, logs or attrs. ``Secret`` prints as ``***``.
- Quote identifiers with the driver's quoting API; never build statements from raw strings.
- Raise ``TransientError``/``PermanentError``/``AuthorizationError`` for target failures.
  Any other exception is treated as an internal bug.
- Import optional drivers lazily (inside ``connect``) so a missing extra does not break
  loading of other adapters.
- Register the class under the entry point group ``ordivus.adapters`` in ``pyproject.toml``.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, ClassVar

# Operation actions. Mutating ones are passed to Adapter.apply; the rest are report-only.
CREATE, UPDATE, DELETE, SET_PASSWORD = "CREATE", "UPDATE", "DELETE", "SET_PASSWORD"
CREATE_SECRET = "CREATE_SECRET"  # executed by the engine against the credential provider
NOOP, UNMANAGED, UNDESIRABLE, IGNORE, UNKNOWN, BLOCKED = (
    "NOOP", "UNMANAGED", "UNDESIRABLE", "IGNORE", "UNKNOWN", "BLOCKED")

# Discovery status per kind (§6.5). Only "complete" allows CREATE and DELETE decisions.
COMPLETE, PARTIAL, FORBIDDEN, UNSUPPORTED = "complete", "partial", "forbidden", "unsupported"
DISCOVERY_STATUSES = (COMPLETE, PARTIAL, FORBIDDEN, UNSUPPORTED, "unknown")


class Secret:
    """Opaque secret value. ``repr``/``str`` are ``***``; use ``reveal()`` only at the driver call."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "***"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Secret cannot be pickled")


class AdapterError(Exception):
    """Base class for target errors. The message must never contain secret values."""


class TransientError(AdapterError):
    """Temporary failure (timeout, connection reset, lock busy); a later run may succeed."""


class PermanentError(AdapterError):
    """Failure that will repeat without a config or target change (constraint, unsupported)."""


class AuthorizationError(AdapterError):
    """Missing privileges. In ``discover`` the engine reports the kind as ``forbidden``."""


@dataclass(frozen=True)
class Resource:
    """One desired or observed object.

    ``id`` is the natural key within ``kind`` on the target (e.g. the user name); desired and
    observed resources are matched by ``(kind, id)``. ``attrs`` hold normalized, JSON-compatible
    values; the engine compares only attrs present in the desired resource, so leaving a field
    out of ``desired`` means "not managed", never "reset". Never put passwords into attrs.

    Observed resources set ``manageable=False`` when the adapter cannot change them (e.g. a user
    from a config file) and ``system=True`` for native protected objects; both are never deleted
    and ``system`` objects that are not declared are reported as ``IGNORE``.
    ``password_ref`` is set by the engine (name of the Credential doc); adapters leave it None.
    """

    kind: str
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    password_ref: str | None = None
    manageable: bool = True
    system: bool = False


@dataclass(frozen=True)
class Discovery:
    """Result of listing one kind. ``status`` is one of DISCOVERY_STATUSES.

    Report ``complete`` only when every object of the kind within ``scope`` is in ``resources``.
    A permission problem is ``forbidden`` (or raise AuthorizationError), never an empty list.
    """

    status: str
    resources: list[Resource] = field(default_factory=list)
    reason: str = ""


@dataclass
class Op:
    """One operation. For ``apply`` the adapter reads ``action``, ``kind``, ``id`` and:

    - CREATE: ``desired.attrs``; ``password`` if the resource has credentials.
    - UPDATE: ``changes`` = ``{field: (old, new)}``, apply only these fields.
    - DELETE: ``observed``.
    - SET_PASSWORD: ``password``.

    ``status``/``reason`` belong to the engine.
    """

    target: str
    kind: str
    id: str
    action: str
    desired: Resource | None = None
    observed: Resource | None = None
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    password: Secret | None = None
    status: str | None = None
    reason: str = ""


class Adapter:
    """Base class for adapters. Subclasses set ``id`` and ``kinds`` and implement the methods."""

    id: ClassVar[str]
    # shortcut: kind order instead of a full dependency DAG, upgrade when kinds need cross-ordering.
    # Creates/updates run in this order, deletes in reverse (e.g. Database, DatabaseRole,
    # DatabaseUser, Grant).
    kinds: ClassVar[tuple[str, ...]]
    # Kinds that accept ``spec.credentials`` (a managed password), e.g. ("DatabaseUser",).
    password_kinds: ClassVar[tuple[str, ...]] = ()

    def validate(self, doc: dict) -> list[str]:
        """Check the adapter-specific part of a doc; return error messages (empty = valid).

        ``doc`` is the whole document (``kind``, ``metadata``, ``spec``). Engine-owned spec keys
        are removed beforehand: ``adapter``/``authentication`` on Target, ``targetRef``/
        ``credentials`` on resources. Every remaining unknown field must be an error.
        Called for the Target doc and for each resource doc of this adapter.
        """
        return []

    def desired(self, doc: dict) -> Resource:
        """Normalize a validated resource doc (same stripped form as ``validate``)."""
        raise NotImplementedError

    @contextmanager
    def connect(self, target: dict, secret: Secret | None, write: bool):
        """Yield a session for ``target`` (the Target spec) as context manager.

        ``secret`` is the admin credential from ``spec.authentication.credentialRef`` (None if
        not configured). ``write=False`` sessions must be unable to mutate. Raise AdapterError
        subclasses on failure; the engine reports the target as error (exit code 13).
        """
        raise NotImplementedError
        yield

    def discover(self, session, kind: str, scope: dict | None) -> Discovery:
        """List all objects of ``kind``. ``scope`` is the Target's ``spec.scope`` (adapter-defined
        format, validated by ``validate``); objects outside it must not be returned."""
        raise NotImplementedError

    def apply(self, session, op: Op) -> None:
        """Execute one mutating op (CREATE, UPDATE, DELETE, SET_PASSWORD) on a write session.

        Must be idempotent where the native API allows. The engine re-discovers afterwards
        and marks the op ``unverified`` if the result differs.
        """
        raise NotImplementedError

    def verify_password(self, target: dict, resource: Resource, password: Secret) -> bool | None:
        """Check ``password`` against the observed ``resource`` by a login attempt.

        True: password matches. False: target positively reports a wrong password.
        None: cannot tell (login not possible for another reason, not supported). Default None.
        """
        return None

    @contextmanager
    def lock(self, session):
        """Hold a target-native lock (e.g. advisory lock) during apply. Default: no lock."""
        yield
