"""Stage 10 Task 3: application orchestration, transaction joining,
explicit input registration, D02 catalog construction, descriptor negotiation,
compatibility resolution, queue-freeze snapshot preparation and audit gate.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.capabilities.models import (
    ApproximationDeclaration,
    CompatibilityResult,
)
from crypto_lab.capabilities.policy import CompatibilityPolicy
from crypto_lab.capabilities.resolver import CompatibilityResolver
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.capability_requirements import CapabilityRequirement
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.experiment import EngineIdentity, SelectedEngineSlot
from crypto_lab.domain.financial import PositiveDecimal
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import NormalizedIdentifier, Sha256
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryPolicy
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.strategy.loader import StrategyLoader
from crypto_lab.strategy.versioning import StrategyVersion

__all__ = [
    "ApplicationAuditPort",
    "DatasetConfinementReader",
    "ExplicitExperimentInput",
    "JoinedUnitOfWork",
    "QueueFreezeSnapshot",
    "build_adapter_catalog_entry",
    "prepare_queue_freeze_snapshot",
    "register_dataset_input",
    "register_strategy_input",
    "resolve_slot_compatibility",
    "stage_qualified_input_evidence",
    "verify_descriptor_negotiation",
]

_SOURCE_COMPONENT = "experiments.application"
_SUPPORTED_PROTOCOL_VERSION = "1.0.0"
_SUPPORTED_CAPABILITY_VOCABULARY = "capabilities/v1"
_EPOCH_UTC = datetime(2026, 1, 1, tzinfo=UTC)


def _app_failure(
    code: str,
    message: str,
    *,
    observed_at_utc: datetime,
    category: DiagnosticCategory = DiagnosticCategory.USER_CONFIGURATION,
) -> Failure:
    identity = _uuid4_shaped(
        profile_hash(
            HashingProfile.DIAGNOSTIC_IDENTITY_V1,
            {
                "error_code": code,
                "category": category.value,
                "severity": DiagnosticSeverity.ERROR.value,
                "source_component": _SOURCE_COMPONENT,
                "message": message,
                "retriable": False,
                "details": {},
                "causal_diagnostic_ids": [],
            },
        )
    )
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            Diagnostic(
                schema_version="1.0.0",
                diagnostic_id=f"diag_{identity}",
                error_code=code,
                category=category,
                severity=DiagnosticSeverity.ERROR,
                message=message,
                source_component=_SOURCE_COMPONENT,
                retriable=False,
                timestamp_utc=observed_at_utc,
                details={},
                causal_diagnostic_ids=(),
            ),
        ),
    )


@runtime_checkable
class ApplicationAuditPort(Protocol):
    """Port for checking and recording required application audit facts."""

    def supports_action(self, action_name: str) -> bool:
        """Return True iff ``action_name`` is in the closed audit vocabulary."""

    def record(self, action_name: str, details: dict[str, Any]) -> Result[None]:
        """Record an audit event for ``action_name``."""


@runtime_checkable
class DatasetConfinementReader(Protocol):
    """Port for physical dataset confinement checks prior to open/registration."""

    def read_confined(self, relative_path: str) -> Result[bytes]:
        """Validate confinement and read dataset bytes, or refuse with Failure."""


@runtime_checkable
class InputEvidenceStore(Protocol):
    """Minimal staging seam for qualified canonical input evidence."""

    def stage_candidate(
        self,
        *,
        owner_kind: str,
        payload: bytes,
        expected_hash: str,
    ) -> Result[str]:
        """Stage canonical input evidence bytes matching ``expected_hash``."""


class ExplicitExperimentInput(CanonicalModel):
    """Strict typed boundary model for explicit CLI experiment inputs."""

    strategy_id: NormalizedIdentifier
    initial_capital_quote: PositiveDecimal
    observed_at_utc: CalendarValidUtcDateTime


class QueueFreezeSnapshot(CanonicalModel):
    """Frozen configuration/retry/compatibility snapshot for queue freeze."""

    material_base_configuration_hash: Sha256
    configuration_audit_hash: Sha256
    retry_policy: RetryPolicy
    slot_compatibility: dict[str, str]


class _JoinedTransaction(UnitOfWork):
    """Inner transaction view that defers commit and marks outer join doomed."""

    def __init__(self, parent: JoinedUnitOfWork, inner: UnitOfWork) -> None:
        self._parent = parent
        self._inner = inner
        self._committed = False

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        return self._inner.diagnostics

    def begin(self) -> UnitOfWork:
        return self

    def commit(self) -> Result[None]:
        if self._parent.is_doomed:
            now = (
                self._parent.clock.now_utc()
                if self._parent.clock is not None
                else _EPOCH_UTC
            )
            return _app_failure(
                "PERSISTENCE.CONCURRENCY_CONFLICT",
                "joined transaction is doomed",
                observed_at_utc=now,
                category=DiagnosticCategory.PERSISTENCE,
            )
        self._committed = True
        return Success(outcome="SUCCESS", value=None)

    def rollback(self) -> None:
        if not self._committed:
            self._parent.doom()


class JoinedUnitOfWork:
    """Transaction-joining facade preserving ``UnitOfWork`` over one outer tx."""

    def __init__(self, root: UnitOfWork, *, clock: Clock | None = None) -> None:
        self._root = root
        self.clock = clock
        self._doomed = False

    @property
    def is_doomed(self) -> bool:
        return self._doomed

    def doom(self) -> None:
        self._doomed = True

    @contextmanager
    def session(self) -> Iterator[UnitOfWork]:
        self._doomed = False
        outer_tx = self._root.begin()
        joined_tx = _JoinedTransaction(self, outer_tx)
        try:
            yield joined_tx
            if not self._doomed:
                committed = outer_tx.commit()
                if isinstance(committed, Failure):
                    self._doomed = True
        except Exception:
            self._doomed = True
            raise
        finally:
            outer_tx.rollback()


def build_adapter_catalog_entry(
    *,
    adapter_name: str,
    adapter_version: str,
    executable_path: str,
    executable_hash: str,
    runtime_metadata: Mapping[str, Any],
    observed_at_utc: datetime,
) -> Result[AdapterCatalogEntry]:
    """D02: validate ``engine_identity`` and build ``AdapterCatalogEntry``."""
    copied_meta: dict[str, Any] = deepcopy(dict(runtime_metadata))
    raw_identity = copied_meta.pop("engine_identity", None)
    if not isinstance(raw_identity, Mapping):
        return _app_failure(
            "CONFIG.CATALOG_ENTRY_INVALID",
            "runtime_metadata must include an engine_identity mapping",
            observed_at_utc=observed_at_utc,
        )
    try:
        engine = EngineIdentity.model_validate(dict(raw_identity))
        entry = AdapterCatalogEntry.model_validate(
            {
                "adapter_name": adapter_name,
                "adapter_version": adapter_version,
                "engine": engine,
                "executable_path": executable_path,
                "executable_hash": executable_hash,
                "runtime_metadata": copied_meta,
            }
        )
    except ValidationError as exc:
        return _app_failure(
            "CONFIG.CATALOG_ENTRY_INVALID",
            f"invalid adapter catalog entry: {exc}",
            observed_at_utc=observed_at_utc,
        )
    return Success(outcome="SUCCESS", value=entry)


def register_strategy_input(
    *,
    source_bytes: bytes,
    source_name: str,
    claimed_content_hash: str | None,
    observed_at_utc: datetime,
) -> Result[StrategyVersion]:
    """Load strategy bytes via ``StrategyLoader.load`` and verify recomputed hash."""
    loaded = StrategyLoader.load(source_bytes, source_name, observed_at_utc)
    if isinstance(loaded, Failure):
        return loaded
    if (
        claimed_content_hash is not None
        and loaded.value.content_hash != claimed_content_hash
    ):
        return _app_failure(
            "CORE.INPUT_HASH_MISMATCH",
            "claimed strategy content_hash does not match recomputed hash",
            observed_at_utc=observed_at_utc,
        )
    return loaded


def register_dataset_input(
    *,
    relative_path: str,
    confinement_reader: DatasetConfinementReader,
    observed_at_utc: datetime,
) -> Result[bytes]:
    """Verify dataset confinement via ``confinement_reader`` before opening/reading."""
    read_res = confinement_reader.read_confined(relative_path)
    if isinstance(read_res, Failure):
        return _app_failure(
            "CORE.DATASET_CONFINEMENT_REFUSED",
            f"dataset path {relative_path} failed confinement",
            observed_at_utc=observed_at_utc,
        )
    return read_res


def verify_descriptor_negotiation(
    *,
    descriptor: AdapterDescriptor,
    catalog_entry: AdapterCatalogEntry,
    slot: SelectedEngineSlot,
    observed_at_utc: datetime,
) -> Result[None]:
    """Verify descriptor protocol/vocabulary versions and catalog/slot agreement."""
    if _SUPPORTED_PROTOCOL_VERSION not in descriptor.supported_protocol_versions:
        return _app_failure(
            "ADAPTER.NEGOTIATION_MISMATCH",
            f"unsupported protocol versions {descriptor.supported_protocol_versions}",
            observed_at_utc=observed_at_utc,
        )
    if descriptor.capability_vocabulary_version != _SUPPORTED_CAPABILITY_VOCABULARY:
        return _app_failure(
            "ADAPTER.NEGOTIATION_MISMATCH",
            "unsupported capability vocabulary "
            f"{descriptor.capability_vocabulary_version}",
            observed_at_utc=observed_at_utc,
        )
    if (
        descriptor.adapter_name != catalog_entry.adapter_name
        or descriptor.adapter_version != catalog_entry.adapter_version
        or descriptor.engine.engine_name != catalog_entry.engine.engine_name
        or descriptor.engine.engine_version != catalog_entry.engine.engine_version
        or descriptor.executable_hash != catalog_entry.executable_hash
        or slot.adapter.adapter_name != descriptor.adapter_name
        or slot.adapter.adapter_version != descriptor.adapter_version
        or slot.engine.engine_name != descriptor.engine.engine_name
        or slot.engine.engine_version != descriptor.engine.engine_version
    ):
        return _app_failure(
            "ADAPTER.NEGOTIATION_MISMATCH",
            "descriptor, catalog entry, and selected engine slot disagree",
            observed_at_utc=observed_at_utc,
        )
    return Success(outcome="SUCCESS", value=None)


def resolve_slot_compatibility(
    *,
    requirements: tuple[CapabilityRequirement, ...],
    descriptor: AdapterDescriptor,
    availability: RuntimeAvailabilityObservation,
    comparison_level: ComparisonLevel,
    policy: CompatibilityPolicy,
    approximations: tuple[ApproximationDeclaration, ...],
) -> Result[CompatibilityResult]:
    """Delegate pure compatibility resolution to ``CompatibilityResolver.resolve``."""
    return CompatibilityResolver.resolve(
        requirements,
        descriptor,
        availability,
        comparison_level,
        policy,
        approximations,
    )


def prepare_queue_freeze_snapshot(
    *,
    material_base_configuration_hash: str,
    configuration_audit_hash: str,
    retry_policy: RetryPolicy,
    slot_compatibility: Mapping[str, str],
    observed_at_utc: datetime | None = None,
) -> Result[QueueFreezeSnapshot]:
    """Build and validate the immutable queue-freeze snapshot."""
    try:
        snapshot = QueueFreezeSnapshot.model_validate(
            {
                "material_base_configuration_hash": material_base_configuration_hash,
                "configuration_audit_hash": configuration_audit_hash,
                "retry_policy": retry_policy,
                "slot_compatibility": dict(slot_compatibility),
            }
        )
    except ValidationError as exc:
        return _app_failure(
            "CORE.IMMUTABLE_INPUT_MISMATCH",
            f"invalid queue freeze snapshot: {exc}",
            observed_at_utc=observed_at_utc or _EPOCH_UTC,
            category=DiagnosticCategory.INTERNAL_INVARIANT,
        )
    return Success(outcome="SUCCESS", value=snapshot)


def stage_qualified_input_evidence(
    *,
    owner_kind: str,
    payload: bytes,
    expected_hash: str,
    store: InputEvidenceStore,
    observed_at_utc: datetime | None = None,
) -> Result[str]:
    """Verify payload digest equals ``expected_hash`` before staging evidence."""
    if sha256_bytes(payload) != expected_hash:
        return _app_failure(
            "ARTIFACT.VALIDATION_FAILED",
            f"{owner_kind} input snapshot bytes differ from expected hash",
            observed_at_utc=observed_at_utc or _EPOCH_UTC,
            category=DiagnosticCategory.ARTIFACT_CORRUPTION,
        )
    return store.stage_candidate(
        owner_kind=owner_kind,
        payload=payload,
        expected_hash=expected_hash,
    )
