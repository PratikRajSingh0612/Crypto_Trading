"""The explicit adapter catalog (Stage 6 plan section 3.5; specification 8.1, 8.2).

``AdapterCatalogEntry`` is the core-owned, configuration-shaped record of one
registered adapter executable (trust class K, unpublished, so it carries no
envelope version): the pinned adapter identity, the pinned engine identity, an
absolute local Windows executable path, the executable's SHA-256 and bounded,
non-secret runtime metadata. ``executable_path`` reuses the ``ExecutablePath``
alias and additionally requires a drive-rooted absolute path with no ``..``
segment; that rule is ``validate_absolute_local_executable_path`` and the
``AbsoluteLocalExecutablePath`` alias, defined once here because Task 2's
``AdapterCommand`` paths apply the same rule. ``runtime_metadata`` reuses the
bounded JSON value union of ``domain.diagnostics`` and its secret-key rejection,
so ``adapters`` needs no ``configuration`` import. Executable paths come only
from this catalog (specification 14.1), which is what makes the catalog the
single source of executable locations.

``AdapterCatalog`` is the specification 8.2 port, verbatim. ``FrozenAdapterCatalog``
is the pure concrete catalog, a frozen dataclass: at most ``MAX_CATALOG_ENTRIES``
entries, unique and sorted on ``(adapter_name, adapter_version)`` (the
``AdaptersConfig`` rule), validated at construction. ``get`` returns a ``Failure``
carrying ``ADAPTER.UNAVAILABLE`` with the requested identity in ``details`` for a
missing entry, because an unregistered adapter is an ordinary availability fact
(specification 21.2.1), and the diagnostic's instant comes from the injected
``Clock``, read exactly once per miss and never on a hit. A lookup identity that
is not a built-in string, or is longer than a ``Diagnostic`` detail string can
carry, is a caller error raised by name, so the ``Failure`` path can never
surface a validation error and no constructible ``Failure`` is ever refused
(every registered identity is far shorter). The catalog never scans a directory,
opens a file or reads the environment; the composition root (Stage 10) projects
``AdapterEntryConfig`` rows into entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Annotated, Final, Protocol, runtime_checkable

from pydantic import AfterValidator, Field, field_validator

from crypto_lab.adapters.diagnostics import ADAPTER_UNAVAILABLE, stage6_failure
from crypto_lab.adapters.limits import MAX_CATALOG_ENTRIES
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import ExecutablePath
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    MAX_DETAIL_COLLECTION,
    MAX_DETAIL_NODES,
    MAX_DETAIL_STRING,
    DiagnosticDetailKey,
    DiagnosticDetailValue,
    _inspect_details,
)
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.identifiers import NormalizedIdentifier, Sha256
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Result, Success
from crypto_lab.domain.versioning import SemanticVersion

SOURCE_COMPONENT: Final = "adapters.catalog"
_ABSOLUTE_DRIVE_PREFIX: Final = re.compile(r"^[A-Za-z]:[\\/]")
_SEPARATORS: Final = re.compile(r"[\\/]")


def validate_absolute_local_executable_path(value: str) -> str:
    """Plan 3.5: a drive-rooted absolute local Windows path with no ``..`` segment.

    Purely textual and layered over the ``ExecutablePath`` rules (no edge
    whitespace, no control character); nothing is resolved or opened.
    """
    if _ABSOLUTE_DRIVE_PREFIX.match(value) is None:
        raise ValueError("executable path must be an absolute local Windows path")
    if ".." in _SEPARATORS.split(value):
        raise ValueError("executable path must not contain a '..' segment")
    return value


#: ``ExecutablePath`` plus the absolute-local rule above; the type of every
#: core-selected absolute path an adapter command carries (plan 3.5 and 3.7).
AbsoluteLocalExecutablePath = Annotated[
    ExecutablePath,
    AfterValidator(validate_absolute_local_executable_path),
]


class AdapterCatalogEntry(CanonicalModel):
    """One explicitly registered adapter executable (plan section 3.5)."""

    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine: EngineIdentity
    executable_path: AbsoluteLocalExecutablePath
    executable_hash: Sha256
    runtime_metadata: Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]

    @field_validator("runtime_metadata")
    @classmethod
    def validate_runtime_metadata(
        cls,
        value: dict[DiagnosticDetailKey, DiagnosticDetailValue],
    ) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
        """The ``Diagnostic.details`` rules: bounds, depth and secret-like keys."""
        nodes = _inspect_details(value)
        if nodes > MAX_DETAIL_NODES:
            raise ValueError("runtime metadata contains too many nodes")
        if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
            raise ValueError("runtime metadata exceeds maximum encoded bytes")
        return value


@runtime_checkable
class AdapterCatalog(Protocol):
    """Specification 8.1: explicitly registered adapter executables; never a scan."""

    def get(
        self,
        adapter_name: str,
        adapter_version: str,
    ) -> Result[AdapterCatalogEntry]:
        """Return the registered entry; a missing identity is a ``Failure``."""

    def list_registered(self) -> tuple[AdapterCatalogEntry, ...]:
        """Return every registered entry in deterministic order."""


@dataclass(frozen=True, slots=True)
class FrozenAdapterCatalog:
    """The pure, clock-injected catalog of plan section 3.5.

    A frozen dataclass: the only state is the validated entry tuple and the
    injected clock, and neither can be reassigned. Construction fails on a
    non-tuple, a non-entry item, a non-``Clock``, more than
    ``MAX_CATALOG_ENTRIES`` entries, a duplicate identity or an unsorted pair.
    The clock takes no part in equality or ``repr``.
    """

    entries: tuple[AdapterCatalogEntry, ...]
    clock: Clock = field(kw_only=True, compare=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple:
            raise TypeError("catalog entries must be a tuple")
        for entry in self.entries:
            if not isinstance(entry, AdapterCatalogEntry):
                raise TypeError("catalog entries must be AdapterCatalogEntry records")
        if not isinstance(self.clock, Clock):
            raise TypeError("catalog requires an injected Clock")
        if len(self.entries) > MAX_CATALOG_ENTRIES:
            raise ValueError(f"catalog holds at most {MAX_CATALOG_ENTRIES} entries")
        identities = tuple(
            (entry.adapter_name, entry.adapter_version) for entry in self.entries
        )
        if len(set(identities)) != len(identities):
            raise ValueError(
                "catalog entries must be unique on (adapter_name, adapter_version)"
            )
        if identities != tuple(sorted(identities)):
            raise ValueError(
                "catalog entries must be sorted by (adapter_name, adapter_version)"
            )

    def get(
        self,
        adapter_name: str,
        adapter_version: str,
    ) -> Result[AdapterCatalogEntry]:
        """Specification 8.2 verbatim; a miss is ``ADAPTER.UNAVAILABLE``."""
        if type(adapter_name) is not str or type(adapter_version) is not str:
            raise TypeError("catalog lookups take built-in strings")
        # An identity longer than a `Diagnostic` detail string cannot be echoed in
        # the miss diagnostic; refusing it by name keeps the miss path from ever
        # surfacing a validation error. Every registered identity is far shorter
        # (`NormalizedIdentifier` 128, `SemanticVersion` 64 characters).
        if len(adapter_name) > MAX_DETAIL_STRING or len(adapter_version) > (
            MAX_DETAIL_STRING
        ):
            raise ValueError("catalog lookup identity exceeds the detail string bound")
        for entry in self.entries:
            if (
                entry.adapter_name == adapter_name
                and entry.adapter_version == adapter_version
            ):
                return Success(outcome="SUCCESS", value=entry)
        return stage6_failure(
            ADAPTER_UNAVAILABLE,
            "adapter is not registered in the catalog",
            source_component=SOURCE_COMPONENT,
            timestamp_utc=self.clock.now_utc(),
            details={
                "adapter_name": adapter_name,
                "adapter_version": adapter_version,
            },
        )

    def list_registered(self) -> tuple[AdapterCatalogEntry, ...]:
        """The sorted registered entries."""
        return self.entries
