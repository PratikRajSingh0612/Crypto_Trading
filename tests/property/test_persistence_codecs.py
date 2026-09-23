"""Codec and constraint properties of the Stage 8 row codecs (plan 7.3, Task 3).

Hypothesis composes the doubles' ``sample_*`` builders with drawn variations --
every state of each lifecycle enum, each ``MISSING``-typed field present or
absent where the state allows, canonical ``Decimal`` magnitudes, timestamps with
and without microseconds across the E5 range, non-ASCII text in bounded text
fields, every ``RunEvent`` payload class, every ``ArtifactOwnerRef`` variant and
``Diagnostic.details`` documents -- and proves, for every record of plan 3.1:
encode -> decode is the identity (canonical equality, so ``MISSING`` and ``[]``
survive) and decode -> encode reproduces the same column values; the canonical
bytes of the decoded record equal the input's; every ``NULL`` column corresponds
to a ``MISSING`` field and vice versa with no top-level ``null`` inside any
encoded JSON snapshot; a row with one column moved out of its domain is refused
on decode with ``CORE.INVARIANT_VIOLATION`` naming the table and identity; a
drawn acyclic batch of diagnostics recorded in a drawn order converges to the
same ``diagnostic_causes`` relation with both edge counts zero (reading 23); and a
drawn ``ConfigSnapshot`` frozen on a ``DRAFT`` row reads back equal while an
altered data column is refused by ``get`` and the schema-version column admits
no other value at the ``UPDATE`` itself.

Declared test-local choices: decoders take the injected ``FixedClock`` as the
keyword ``clock`` (the plan's sketch omits it; a ``Failure`` diagnostic must be
stamped from an injected clock and ``codecs.py`` reads none); ``_row`` is a
read-only mapping, the shape a SQLAlchemy ``RowMapping`` presents, and the real
schema round trip is proven in the registries suite; the two database-backed
properties open one migrated database per example under
``tmp_path_factory.mktemp`` (a session-scoped fixture, so no function-scoped
health check is suppressed) and close it in ``finally``; ``deadline=None`` where
strict models are validated repeatedly (the repository's measured convention).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import insert, text
from sqlalchemy.exc import IntegrityError

from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    ArtifactProducedPayload,
    DiagnosticPayload,
    FinalResultPayload,
    HeartbeatPayload,
    ProgressPayload,
    ProtocolWarning,
    ResourceObservation,
    RunEvent,
    WarningPayload,
    run_event_content_hash,
)
from crypto_lab.adapters.vocabulary import (
    AdapterDiagnosticCategory,
    ProtocolEventType,
    SemanticStatus,
)
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
)
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.datasets.hashing import dataset_metadata_hash
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    FeeAssumptions,
    SlippageAssumptions,
    SlippageModel,
)
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.records import Money
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
)
from crypto_lab.domain.time import format_utc
from crypto_lab.persistence.codecs import (
    _flag,
    _instant_or_null,
    decode_artifact_owner,
    decode_command_invocation,
    decode_dataset,
    decode_dataset_partition,
    decode_diagnostic,
    decode_engine_run,
    decode_experiment,
    decode_observation,
    decode_retry_decision,
    decode_run_event,
    decode_strategy_version,
    egress_payload_command_invocation,
    encode_artifact_owner,
    encode_command_invocation,
    encode_dataset,
    encode_dataset_partition,
    encode_diagnostic,
    encode_engine_run,
    encode_engine_slots,
    encode_experiment,
    encode_observation,
    encode_retry_decision,
    encode_run_event,
    encode_strategy_version,
    load_snapshot,
    micros_to_utc_text,
    utc_to_micros,
)
from crypto_lab.persistence.diagnostics import INVARIANT_VIOLATION
from crypto_lab.persistence.registries import (
    SqliteConfigurationSnapshotWriter,
    SqliteDiagnosticRecorder,
)
from crypto_lab.persistence.schema import ExperimentRow
from crypto_lab.strategy.versioning import StrategyVersion
from doubles.experiments import (
    ATTEMPT_TOKEN,
    AVAIL_A,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    UUID_A,
    FixedClock,
    sample_allowed_retry_decision,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_decision,
    sample_retry_policy,
    sample_run,
    sequential_diagnostic_id,
)
from persistence_support.harness import (
    causal_edges,
    code,
    ok,
    open_test_database,
    sample_dataset_with_partitions,
    sample_strategy_version,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState
_MIN_INSTANT_MICROS: Final = -62_135_596_800_000_000
_MAX_INSTANT_MICROS: Final = 253_402_300_799_999_999
_MAX_DETAIL_BYTES: Final = 16_384


def _clock() -> FixedClock:
    return FixedClock(INSTANT)


def _row(values: Mapping[str, object]) -> Mapping[str, object]:
    """A read-only row mapping: the shape a SQLAlchemy ``RowMapping`` presents."""
    return MappingProxyType(dict(values))


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


# --------------------------------------------------------------------------
# Strategies
# --------------------------------------------------------------------------

#: The whole E5 range: ``0001-01-01T00:00:00Z`` through ``9999-12-31T23:59:59.999999Z``.
#: Hypothesis takes naive bounds and attaches the drawn ``UTC`` itself, so the
#: naive ``datetime.min``/``datetime.max`` extremes are the API, not a bare read.
_FULL_RANGE: Final = st.datetimes(
    min_value=datetime.min,  # noqa: DTZ901
    max_value=datetime.max,  # noqa: DTZ901
    timezones=st.just(UTC),
)
#: Record instants leave room for the builders' derived instants (a seven-day
#: RUN timeout, a one-hour expiry, a revision's seconds).
_RECORD_RANGE: Final = st.datetimes(
    min_value=datetime.min + timedelta(days=1),  # noqa: DTZ901
    max_value=datetime.max - timedelta(days=10),  # noqa: DTZ901
    timezones=st.just(UTC),
)
_RATES: Final = st.sampled_from(["0", "1", "0.001", "0.5", "0.000000000000000001"]).map(
    Decimal
)
_AMOUNTS: Final = st.sampled_from(
    ["1", "10000", "0.00000001", "1" + "0" * 40, "123456789.987654321"]
).map(Decimal)
#: ``codec="utf-8"`` admits only encodable characters (no lone surrogate); NUL
#: is excluded because SQLite's ``length()`` stops at it, so a NUL-bearing text
#: could not satisfy the bounded-text CHECKs of the real tables.
_TEXT: Final = st.text(
    alphabet=st.characters(codec="utf-8", exclude_characters="\x00"),
    min_size=1,
    max_size=48,
)
_DETAIL_KEYS: Final = st.sampled_from([f"key_{index}" for index in range(6)])
_DETAIL_LEAVES: Final = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.text(
        alphabet=st.characters(codec="utf-8", exclude_characters="\x00"), max_size=32
    ),
)
_HEX: Final = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
#: The ``CorrelationId`` grammar of ``artifacts/ownership.py``.
_CORRELATION_IDS: Final = st.from_regex(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}", fullmatch=True
)
_COUNTERS: Final = st.integers(min_value=0, max_value=2**53 - 1)


def utc_instants() -> st.SearchStrategy[datetime]:
    """Instants across the whole E5 range, with and without microseconds."""
    return st.one_of(
        _FULL_RANGE, _FULL_RANGE.map(lambda value: value.replace(microsecond=0))
    )


def record_instants() -> st.SearchStrategy[datetime]:
    return st.one_of(
        _RECORD_RANGE, _RECORD_RANGE.map(lambda value: value.replace(microsecond=0))
    )


def _detail_values(depth: int) -> st.SearchStrategy[object]:
    if depth == 0:
        return _DETAIL_LEAVES
    nested = _detail_values(depth - 1)
    return st.one_of(
        _DETAIL_LEAVES,
        st.lists(nested, max_size=3),
        st.dictionaries(_DETAIL_KEYS, nested, max_size=3),
    )


_DETAILS: Final = st.dictionaries(_DETAIL_KEYS, _detail_values(3), max_size=4)


@st.composite
def experiment_records(draw: st.DrawFn) -> ExperimentRecord:
    state = draw(st.sampled_from(list(ExperimentState)))
    model = draw(st.sampled_from(list(SlippageModel)))
    slippage = (
        SlippageAssumptions(model=model, basis_points=Decimal("5"))
        if model is SlippageModel.FIXED_BASIS_POINTS
        else SlippageAssumptions(model=model)
    )
    draft = sample_draft(
        comparison_level=draw(st.sampled_from(list(ComparisonLevel))),
        fee_assumptions=FeeAssumptions(
            maker_fee_rate=draw(_RATES), taker_fee_rate=draw(_RATES)
        ),
        slippage_assumptions=slippage,
        starting_balance=Money(
            schema_version="1.0.0", currency="USDT", amount=draw(_AMOUNTS)
        ),
    )
    include_compatibility = (
        draw(st.booleans()) if state is ExperimentState.CANCELLED else None
    )
    return sample_experiment(
        state,
        draft=draft,
        include_compatibility=include_compatibility,
        revision=draw(st.integers(min_value=0, max_value=12)),
        created_at_utc=draw(record_instants()),
    )


@st.composite
def engine_run_records(draw: st.DrawFn) -> EngineRunRecord:
    state = draw(st.sampled_from(list(EngineRunState)))
    predecessor_dependent = {_R.FAILED, _R.CANCELLED, _R.TIMED_OUT, _R.NOT_APPLICABLE}
    observed = draw(st.booleans()) if state in predecessor_dependent else None
    return sample_run(
        state,
        attempt_number=draw(st.integers(min_value=1, max_value=5)),
        observed=observed,
        revision=draw(st.integers(min_value=0, max_value=12)),
        created_at_utc=draw(record_instants()),
    )


_TIMEOUT_BOUND: Final = {
    CommandKind.DESCRIBE: 300,
    CommandKind.VALIDATE: 1800,
    CommandKind.RUN: 604800,
}
_EXIT_VALUES: Final = st.sampled_from(
    [0, 10, 20, 30, 40, 50, 60, 70, 1, -1, 4294967295, -2147483648]
)


@st.composite
def command_invocation_records(draw: st.DrawFn) -> CommandInvocationRecord:
    kind = draw(st.sampled_from(list(CommandKind)))
    state = draw(st.sampled_from(list(CommandInvocationState)))
    via: CommandInvocationState | None = None
    if state is _C.CANCELLED:
        via = draw(st.sampled_from([_C.PENDING, _C.STARTING, _C.RUNNING]))
    elif state is _C.TIMED_OUT:
        via = draw(st.sampled_from([_C.STARTING, _C.RUNNING]))
    return sample_invocation(
        state,
        kind=kind,
        via=via,
        timeout_seconds=draw(st.integers(min_value=1, max_value=_TIMEOUT_BOUND[kind])),
        native_exit_value=draw(_EXIT_VALUES),
        created_at_utc=draw(record_instants()),
    )


@st.composite
def retry_decision_records(draw: st.DrawFn) -> RetryDecisionRecord:
    shape = draw(
        st.sampled_from(
            ["denied_budget", "denied_hard_block", "allowed", "unavailable"]
        )
    )
    decided = draw(record_instants())
    if shape == "denied_budget":
        return sample_retry_decision(decided_at_utc=decided)
    if shape == "denied_hard_block":
        return RetryDecisionRecord.model_validate(
            {
                "schema_version": "1.0.0",
                "experiment_id": EXPERIMENT_ID,
                "logical_slot_id": sample_retry_decision().logical_slot_id,
                "predecessor_run_id": RUN_ID,
                "experiment_spec_hash": "a" * 64,
                "retry_policy": sample_retry_policy(),
                "created_attempt_count": 1,
                "predecessor_terminal_state": _R.FAILED,
                "primary_terminal_diagnostic_id": sample_retry_decision(
                    decided_at_utc=decided
                ).primary_terminal_diagnostic_id,
                "outcome": RetryDecisionOutcome.DENIED,
                "denial_reason": RetryDenialReason.HARD_BLOCKED_OUTCOME,
                "hard_block_error_code": "CORE.INVARIANT_VIOLATION",
                "decided_at_utc": decided,
            }
        )
    if shape == "allowed":
        return sample_allowed_retry_decision(
            predecessor_terminal_state=draw(st.sampled_from([_R.FAILED, _R.TIMED_OUT])),
            decided_at_utc=decided,
        )
    return sample_allowed_retry_decision(
        predecessor_terminal_state=_R.UNAVAILABLE,
        availability_observation_id=AVAIL_A,
        decided_at_utc=decided,
    )


def _event_payload(draw: st.DrawFn, event_type: ProtocolEventType) -> object:
    if event_type is ProtocolEventType.HEARTBEAT:
        if draw(st.booleans()):
            return HeartbeatPayload(
                activity_counter=draw(_COUNTERS),
                phase="warmup",
                resource_observation=ResourceObservation(
                    cpu_seconds=Decimal("1.5"), resident_memory_bytes=draw(_COUNTERS)
                ),
            )
        return HeartbeatPayload(activity_counter=draw(_COUNTERS), phase="warmup")
    if event_type is ProtocolEventType.PROGRESS:
        completed = draw(st.integers(min_value=0, max_value=10**9))
        if draw(st.booleans()):
            return ProgressPayload(
                phase="load",
                completed_units=completed,
                total_units=completed + draw(st.integers(min_value=0, max_value=10**9)),
                percentage=Decimal(str(draw(st.integers(min_value=0, max_value=100)))),
            )
        return ProgressPayload(phase="load", completed_units=completed)
    if event_type is ProtocolEventType.WARNING:
        return WarningPayload(
            warning=ProtocolWarning(
                warning_code="ADAPTER.SLOW_START",
                message=draw(_TEXT),
                impact=draw(_TEXT),
                prevented_comparison_levels=draw(
                    st.sampled_from(
                        [(), (ComparisonLevel.LEVEL_1,), (ComparisonLevel.LEVEL_2,)]
                    )
                ),
            )
        )
    if event_type is ProtocolEventType.DIAGNOSTIC:
        return DiagnosticPayload(
            diagnostic=AdapterDiagnostic(
                error_code="ENGINE.RUNTIME_FAILURE",
                category=AdapterDiagnosticCategory.ENGINE_RUNTIME,
                severity=draw(st.sampled_from(list(DiagnosticSeverity))),
                message=draw(_TEXT),
                retriable=draw(st.booleans()),
                details={},
                causal_event_ids=(),
            )
        )
    if event_type is ProtocolEventType.ARTIFACT_PRODUCED:
        return ArtifactProducedPayload(
            relative_path="out/result.json",
            artifact_kind="equity.curve",
            media_type="application/json",
            declared_size_bytes=draw(_COUNTERS),
            declared_sha256=draw(_HEX),
        )
    return FinalResultPayload(
        manifest_relative_path="adapter-result-manifest.json",
        source_adapter_result_manifest_hash=draw(_HEX),
        semantic_status=draw(st.sampled_from(list(SemanticStatus))),
    )


@st.composite
def run_events(draw: st.DrawFn) -> RunEvent:
    event_type = draw(st.sampled_from(list(ProtocolEventType)))
    draft = RunEvent.model_construct(
        schema_version="1.0.0",
        protocol_version="1.0.0",
        event_id=f"evt_{UUID_A}",
        invocation_id=INVOCATION_ID,
        run_id=RUN_ID,
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        sequence=draw(st.integers(min_value=1, max_value=1_000_000)),
        event_type=event_type,
        timestamp_utc=draw(record_instants()),
        payload=_event_payload(draw, event_type),
        received_at_utc=draw(record_instants()),
        wire_event_hash=draw(_HEX),
        content_hash="0" * 64,
    )
    document = draft.model_dump(mode="python")
    document["content_hash"] = run_event_content_hash(draft)
    return RunEvent.model_validate(document)


@st.composite
def observations(draw: st.DrawFn) -> Any:
    return sample_observation(
        available=draw(st.booleans()), observed_at_utc=draw(record_instants())
    )


_COMMAND_CATEGORIES: Final = frozenset(
    {
        DiagnosticCategory.ENGINE_RUNTIME,
        DiagnosticCategory.PROTOCOL,
        DiagnosticCategory.TIMEOUT,
        DiagnosticCategory.CANCELLATION,
    }
)


@st.composite
def diagnostics(draw: st.DrawFn) -> Diagnostic:
    category = draw(st.sampled_from(list(DiagnosticCategory)))
    experiment_present = draw(st.booleans())
    run_present = experiment_present and draw(st.booleans())
    invocation_present = category in _COMMAND_CATEGORIES or draw(st.booleans())
    causes = sorted(draw(st.sets(st.integers(min_value=1, max_value=40), max_size=32)))
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "diagnostic_id": sequential_diagnostic_id(0),
        "severity": draw(st.sampled_from(list(DiagnosticSeverity))),
        "error_code": "ENGINE.RUNTIME_FAILURE",
        "category": category,
        "message": draw(_TEXT),
        "source_component": "doubles.experiments",
        "retriable": draw(st.booleans()),
        "timestamp_utc": draw(record_instants()),
        "details": draw(_DETAILS),
        "causal_diagnostic_ids": tuple(sequential_diagnostic_id(c) for c in causes),
    }
    if experiment_present:
        payload["experiment_id"] = EXPERIMENT_ID
    if run_present:
        payload["run_id"] = RUN_ID
    if invocation_present:
        payload["invocation_id"] = INVOCATION_ID
    if draw(st.booleans()):
        payload["engine"] = "engine.alpha"
    return Diagnostic.model_validate(payload)


@st.composite
def strategy_versions(draw: st.DrawFn) -> StrategyVersion:
    payload = sample_strategy_version().model_dump(mode="python")
    payload["created_at_utc"] = draw(record_instants())
    payload["source_provenance"] = {
        **payload["source_provenance"],
        "source_name": draw(
            st.sampled_from(["sma_cross_long.valid.yaml", "other.valid.yaml"])
        ),
        "observed_at_utc": draw(record_instants()),
    }
    return StrategyVersion.model_validate(payload)


@st.composite
def datasets(draw: st.DrawFn) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    descriptor, partitions = sample_dataset_with_partitions()
    data_type = draw(st.sampled_from([DatasetDataType.OHLCV, DatasetDataType.TRADES]))
    payload = descriptor.model_dump(mode="python")
    payload["data_type"] = data_type
    payload["created_at_utc"] = draw(record_instants())
    if data_type is DatasetDataType.OHLCV:
        payload["timeframe"] = draw(st.sampled_from(["1m", "1h", "1d"]))
    else:
        payload.pop("timeframe", None)
    if draw(st.booleans()):
        payload["imported_at_utc"] = draw(record_instants())
    else:
        payload.pop("imported_at_utc", None)
    unhashed = DatasetDescriptor.model_validate(payload)
    payload["content_hash"] = dataset_metadata_hash(unhashed, partitions)
    return DatasetDescriptor.model_validate(payload), partitions


@st.composite
def artifact_owners(draw: st.DrawFn) -> ArtifactOwnerRef:
    kind = draw(
        st.sampled_from(
            ["RUN", "EXPERIMENT", "DATASET", "STRATEGY", "ADAPTER", "SYSTEM"]
        )
    )
    if kind == "RUN":
        if draw(st.booleans()):
            return RunArtifactOwner(
                owner_kind="RUN",
                experiment_id=EXPERIMENT_ID,
                run_id=RUN_ID,
                invocation_id=INVOCATION_ID,
            )
        return RunArtifactOwner(
            owner_kind="RUN", experiment_id=EXPERIMENT_ID, run_id=RUN_ID
        )
    if kind == "EXPERIMENT":
        return ExperimentArtifactOwner(
            owner_kind="EXPERIMENT", experiment_id=EXPERIMENT_ID
        )
    if kind == "DATASET":
        return DatasetArtifactOwner(owner_kind="DATASET", dataset_id=f"ds_{UUID_A}")
    if kind == "STRATEGY":
        if draw(st.booleans()):
            return StrategyArtifactOwner(
                owner_kind="STRATEGY", strategy_version_id=f"strv_{UUID_A}"
            )
        return StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_hash="1" * 64
        )
    if kind == "ADAPTER":
        if draw(st.booleans()):
            return AdapterArtifactOwner(
                owner_kind="ADAPTER",
                adapter_name="adapter.alpha",
                adapter_version="1.0.0",
                engine_name="engine.alpha",
                engine_version="2.3.4",
            )
        return AdapterArtifactOwner(
            owner_kind="ADAPTER", adapter_name="adapter.alpha", adapter_version="1.0.0"
        )
    return SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component="persistence",
        correlation_id=draw(_CORRELATION_IDS),
    )


@st.composite
def causal_batches(draw: st.DrawFn) -> tuple[tuple[Diagnostic, ...], tuple[int, ...]]:
    """An acyclic batch of at most eight diagnostics and a drawn recording order."""
    size = draw(st.integers(min_value=1, max_value=8))
    batch: list[Diagnostic] = []
    for index in range(size):
        causes: list[int] = []
        if index:
            causes = sorted(
                draw(
                    st.sets(
                        st.integers(min_value=0, max_value=index - 1), max_size=index
                    )
                )
            )
        batch.append(
            sample_diagnostic(
                diagnostic_id=sequential_diagnostic_id(index),
                causal_diagnostic_ids=tuple(
                    sequential_diagnostic_id(c) for c in causes
                ),
            )
        )
    order = draw(st.permutations(list(range(size))))
    return tuple(batch), tuple(order)


@st.composite
def application_configs(draw: st.DrawFn) -> ApplicationConfig:
    return ApplicationConfig.model_validate(
        {
            "scheduler": {
                "max_concurrent_runs": draw(st.integers(min_value=1, max_value=8)),
                "retry": {
                    "maximum_attempts_per_slot": draw(
                        st.integers(min_value=1, max_value=5)
                    ),
                    "retry_delay_seconds": draw(
                        st.integers(min_value=0, max_value=300)
                    ),
                },
            },
            "process": {
                "cancellation_grace_seconds": draw(
                    st.integers(min_value=0, max_value=300)
                )
            },
        }
    )


# --------------------------------------------------------------------------
# The per-record case table
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Case:
    """One record's codec pair with its N1 column map and out-of-domain mutations."""

    table: str
    identity_column: str
    records: st.SearchStrategy[Any]
    encode: Callable[[Any], Mapping[str, object]]
    decode: Callable[..., Success[Any] | Failure]
    null_columns: Mapping[str, tuple[str, ...]]
    json_columns: tuple[str, ...]
    mutations: tuple[tuple[str, object], ...]


_OWNER_COLUMNS: Final = (
    "experiment_id",
    "run_id",
    "invocation_id",
    "dataset_id",
    "strategy_version_id",
    "strategy_version_hash",
    "adapter_name",
    "adapter_version",
    "engine_name",
    "engine_version",
    "core_component",
    "correlation_id",
)
_CASES: Final[tuple[_Case, ...]] = (
    _Case(
        "experiments",
        "experiment_id",
        experiment_records(),
        encode_experiment,
        decode_experiment,
        {
            "slot_compatibility": ("slot_compatibility",),
            "cancellation_correlation_id": ("cancellation_correlation_id",),
        },
        ("spec", "slot_compatibility"),
        (
            ("state", "BOGUS"),
            ("spec_hash", "0" * 63),
            ("spec", "{"),
            ("spec", "[]"),
            ("slot_compatibility", "null"),
            ("created_at_utc", _MAX_INSTANT_MICROS + 1),
            ("revision", -1),
            ("revision", True),
            ("experiment_id", "exp_bogus"),
        ),
    ),
    _Case(
        "engine_runs",
        "run_id",
        engine_run_records(),
        encode_engine_run,
        decode_engine_run,
        {
            "predecessor_run_id": ("predecessor_run_id",),
            "retry_reason": ("retry_reason",),
            "primary_terminal_diagnostic_id": ("primary_terminal_diagnostic_id",),
            "availability_observation_id": ("availability_observation_id",),
        },
        (),
        (
            ("state", "BOGUS"),
            ("attempt_number", 6),
            ("attempt_token_hash", "x" * 64),
            ("adapter_version", ""),
            ("created_at_utc", _MIN_INSTANT_MICROS - 1),
            ("run_id", "run_bogus"),
        ),
    ),
    _Case(
        "command_invocations",
        "invocation_id",
        command_invocation_records(),
        encode_command_invocation,
        decode_command_invocation,
        {
            "run_id": ("run_id",),
            "deadline_utc": ("deadline_utc",),
            "launch_attempted_at_utc": ("launch_attempted_at_utc",),
            "process_started_at_utc": ("process_started_at_utc",),
            "pid_identity": (
                "pid",
                "creation_identity",
                "executable_path",
                "executable_hash",
                "supervisor_instance_id",
            ),
            "completed_at_utc": ("completed_at_utc",),
            "native_exit_value": ("native_exit_value",),
            "process_exit_category": ("process_exit_category",),
            "cleanup_completed_at_utc": ("cleanup_completed_at_utc",),
            "stderr_artifact_id": ("stderr_artifact_id",),
            "primary_diagnostic_id": ("primary_diagnostic_id",),
        },
        ("diagnostic_ids",),
        (
            ("state", "BOGUS"),
            ("timeout_seconds", 0),
            ("process_created", 2),
            ("diagnostic_ids", "{}"),
            ("diagnostic_ids", '["diag_b", "diag_a"]'),
            ("pid", 0),
            ("invocation_id", "inv_bogus"),
        ),
    ),
    _Case(
        "run_events",
        "event_id",
        run_events(),
        encode_run_event,
        decode_run_event,
        {},
        ("payload",),
        (
            ("event_type", "BOGUS"),
            ("sequence", 0),
            ("payload", "{}"),
            ("content_hash", "0" * 64),
            ("protocol_version", "2.0.0"),
            ("event_id", "evt_bogus"),
        ),
    ),
    _Case(
        "retry_decisions",
        "predecessor_run_id",
        retry_decision_records(),
        encode_retry_decision,
        decode_retry_decision,
        {
            "denial_reason": ("denial_reason",),
            "hard_block_error_code": ("hard_block_error_code",),
            "availability_observation_id": ("availability_observation_id",),
            "retry_not_before_utc": ("retry_not_before_utc",),
            "reserved_successor_attempt_number": ("reserved_successor_attempt_number",),
        },
        ("retry_policy",),
        (
            ("outcome", "BOGUS"),
            ("created_attempt_count", 0),
            ("retry_policy", '{"x": 1.5}'),
            ("retry_policy", "["),
            ("predecessor_terminal_state", "SUCCEEDED"),
            ("predecessor_run_id", "run_bogus"),
        ),
    ),
    _Case(
        "runtime_availability_observations",
        "availability_observation_id",
        observations(),
        encode_observation,
        decode_observation,
        {"reason_code": ("reason_code",)},
        (),
        (
            ("available", 2),
            ("operating_system", "BOGUS"),
            ("expires_at_utc", _MIN_INSTANT_MICROS),
            ("content_sha256", "0" * 64),
            ("availability_observation_id", "avail_bogus"),
        ),
    ),
    _Case(
        "diagnostics",
        "diagnostic_id",
        diagnostics(),
        encode_diagnostic,
        decode_diagnostic,
        {
            "experiment_id": ("experiment_id",),
            "run_id": ("run_id",),
            "invocation_id": ("invocation_id",),
            "engine": ("engine",),
        },
        # ``details`` is the one free-form document whose leaves may lawfully be
        # JSON null (plan 3.1), so only the identifier array joins the null check.
        ("causal_diagnostic_ids",),
        (
            ("severity", "BOGUS"),
            ("details", "[]"),
            ("details", '{"password": 1}'),
            ("causal_diagnostic_ids", '["diag_b", "diag_a"]'),
            ("retriable", 2),
            ("message", ""),
            ("diagnostic_id", "diag_bogus"),
        ),
    ),
    _Case(
        "strategy_versions",
        "content_hash",
        strategy_versions(),
        encode_strategy_version,
        decode_strategy_version,
        {},
        ("record",),
        (("record", "{"), ("record", "{}"), ("record", "[]"), ("record", "null")),
    ),
    _Case(
        "datasets",
        "dataset_id",
        datasets().map(lambda pair: pair[0]),
        encode_dataset,
        decode_dataset,
        {"timeframe": ("timeframe",)},
        ("record",),
        (("record", "{"), ("record", "{}"), ("record", "1.5")),
    ),
    _Case(
        "dataset_partitions",
        "partition_id",
        datasets().map(lambda pair: pair[1][0]),
        encode_dataset_partition,
        decode_dataset_partition,
        {},
        ("record",),
        (("record", "{"), ("record", "{}")),
    ),
    _Case(
        "artifact_owners",
        "owner_hash",
        artifact_owners(),
        encode_artifact_owner,
        decode_artifact_owner,
        {column: (column,) for column in _OWNER_COLUMNS},
        (),
        (
            ("owner_kind", "BOGUS"),
            ("owner_hash", "0" * 64),
            ("experiment_id", "exp_bogus"),
            ("correlation_id", ""),
        ),
    ),
)
_CASE_IDS: Final = [case.table for case in _CASES]


# --------------------------------------------------------------------------
# The plan Task 3 Step 1 sketches
# --------------------------------------------------------------------------


@given(records=engine_run_records())
@settings(max_examples=120, deadline=None)
def test_engine_run_records_round_trip_losslessly(records: EngineRunRecord) -> None:
    decoded = decode_engine_run(_row(encode_engine_run(records)), clock=_clock())
    assert isinstance(decoded, Success)
    assert decoded.value == records
    assert canonical_json_bytes(decoded.value) == canonical_json_bytes(records)


@given(instant=utc_instants())
def test_timestamps_round_trip_to_the_microsecond(instant: datetime) -> None:
    micros = utc_to_micros(instant)
    assert micros_to_utc_text(micros) == format_utc(instant)


def test_a_null_column_is_missing_and_never_null_on_egress() -> None:
    values = encode_command_invocation(sample_invocation(_C.PENDING))
    assert values["deadline_utc"] is None
    payload = egress_payload_command_invocation(_row(values))
    assert "deadline_utc" not in payload
    assert None not in payload.values()


# --------------------------------------------------------------------------
# Plan 7.3 properties over every record
# --------------------------------------------------------------------------


@given(earlier=utc_instants(), later=utc_instants())
def test_the_column_integer_is_monotone_in_the_instant(
    earlier: datetime, later: datetime
) -> None:
    if earlier > later:
        earlier, later = later, earlier
    assert (utc_to_micros(earlier) < utc_to_micros(later)) == (earlier < later)
    assert (utc_to_micros(earlier) == utc_to_micros(later)) == (earlier == later)
    assert _MIN_INSTANT_MICROS <= utc_to_micros(earlier) <= _MAX_INSTANT_MICROS


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
@settings(max_examples=60, deadline=None)
@given(data=st.data())
def test_every_record_round_trips_losslessly_through_its_codec(
    case: _Case, data: st.DataObject
) -> None:
    record = data.draw(case.records)
    values = case.encode(record)
    decoded = case.decode(_row(values), clock=_clock())
    assert isinstance(decoded, Success), decoded
    assert decoded.value == record
    assert canonical_json_bytes(decoded.value) == canonical_json_bytes(record)
    assert case.encode(decoded.value) == values
    dumped = record.model_dump(mode="json")
    expected_null = {
        column
        for field, columns in case.null_columns.items()
        if field not in dumped
        for column in columns
    }
    assert {
        column for column, value in values.items() if value is None
    } == expected_null
    for column in case.json_columns:
        value = values[column]
        if value is None:
            continue
        document = json.loads(str(value))
        if isinstance(document, dict):
            assert None not in document.values()


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
@settings(max_examples=40, deadline=None)
@given(data=st.data())
def test_a_mutated_row_is_refused_on_decode_naming_the_table_and_identity(
    case: _Case, data: st.DataObject
) -> None:
    record = data.draw(case.records)
    column, replacement = data.draw(st.sampled_from(case.mutations))
    values = dict(case.encode(record))
    values[column] = replacement
    refused = case.decode(_row(values), clock=_clock())
    assert code(refused) == INVARIANT_VIOLATION
    details = _details(refused)
    assert details["table"] == case.table
    assert details["identity"] == str(values[case.identity_column])
    assert isinstance(details["location"], str)
    assert details["location"]


@given(record=experiment_records())
@settings(max_examples=60, deadline=None)
def test_engine_slots_project_the_spec_slots_of_an_experiment(
    record: ExperimentRecord,
) -> None:
    rows = encode_engine_slots(record)
    expected = tuple(
        {
            "experiment_id": record.experiment_id,
            "logical_slot_id": slot.logical_slot_id,
            "slot_ordinal": slot.slot_ordinal,
            "adapter_name": slot.adapter.adapter_name,
            "adapter_version": slot.adapter.adapter_version,
            "engine_name": slot.engine.engine_name,
            "engine_version": slot.engine.engine_version,
        }
        for slot in record.spec.selected_engine_slots
    )
    assert rows == expected
    spec_document = json.loads(str(encode_experiment(record)["spec"]))
    assert [
        slot["logical_slot_id"] for slot in spec_document["selected_engine_slots"]
    ] == [row["logical_slot_id"] for row in rows]


def test_scalar_encodings_refuse_foreign_inputs() -> None:
    """The E3/E5/E7 helpers guard the ingress of a defective record and the
    egress of a foreign column value; each refusal is typed, never a silent coercion."""
    with pytest.raises(TypeError, match="built-in integer"):
        micros_to_utc_text(True)
    with pytest.raises(TypeError, match="built-in integer"):
        micros_to_utc_text("0")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="E5 range"):
        micros_to_utc_text(_MAX_INSTANT_MICROS + 1)
    with pytest.raises(ValueError, match="non-finite"):
        load_snapshot("NaN")
    with pytest.raises(ValueError, match="non-finite"):
        load_snapshot("[Infinity]")
    with pytest.raises(TypeError, match="built-in bool"):
        _flag(1)
    with pytest.raises(TypeError, match="datetime or MISSING"):
        _instant_or_null("2026-09-07T12:00:00Z")


def test_a_row_missing_a_column_or_holding_a_foreign_type_is_refused() -> None:
    """Reading 10: a malformed column names itself as the error location."""
    absent = decode_diagnostic(_row({}), clock=_clock())
    assert code(absent) == INVARIANT_VIOLATION
    assert _details(absent)["table"] == "diagnostics"
    assert _details(absent)["location"] == "schema_version"
    values = dict(encode_experiment(sample_experiment(_E.DRAFT)))
    values["state"] = 5
    foreign = decode_experiment(_row(values), clock=_clock())
    assert code(foreign) == INVARIANT_VIOLATION
    assert _details(foreign)["identity"] == EXPERIMENT_ID
    assert _details(foreign)["location"] == "state"


def test_a_partially_null_process_identity_is_refused_on_egress() -> None:
    """Rule N5: the five flattened ``ProcessIdentity`` columns are all ``NULL`` or
    all present; a row with only ``pid`` filled cannot rebuild the nested value."""
    values = dict(encode_command_invocation(sample_invocation(_C.PENDING)))
    assert all(values[column] is None for column in ("pid", "creation_identity"))
    values["pid"] = 4242
    refused = decode_command_invocation(_row(values), clock=_clock())
    assert code(refused) == INVARIANT_VIOLATION
    assert _details(refused)["table"] == "command_invocations"
    assert _details(refused)["identity"] == INVOCATION_ID
    assert _details(refused)["location"] == "pid"


def test_encoding_refuses_a_present_finalization_deadline() -> None:
    """Rule N4: the one forced-``MISSING`` field has no column."""
    base = sample_run(_R.PENDING)
    impossible = EngineRunRecord.model_construct(
        **{**dict(base), "finalization_deadline_utc": INSTANT}
    )
    with pytest.raises(ValueError, match="finalization_deadline_utc"):
        encode_engine_run(impossible)


_DEEP_DETAILS: Final[dict[str, object]] = {
    "k": {"k": {"k": {"k": {"k": {"k": {"k": {"k": 1}}}}}}}
}
_WIDE_DETAILS: Final[dict[str, object]] = {
    **{f"list_{index}": list(range(62)) for index in range(4)},
    "flag": True,
}
_LONG_DETAILS: Final[dict[str, object]] = {
    f"k{index}": "x" * 2000 for index in range(8)
}


@pytest.mark.parametrize(
    "details",
    [_DEEP_DETAILS, _WIDE_DETAILS, _LONG_DETAILS],
    ids=["depth", "nodes", "bytes"],
)
def test_details_documents_at_the_bounds_round_trip(details: dict[str, object]) -> None:
    assert len(canonical_json_bytes(details)) <= _MAX_DETAIL_BYTES
    diagnostic = Diagnostic.model_validate(
        {**sample_diagnostic().model_dump(mode="python"), "details": details}
    )
    values = encode_diagnostic(diagnostic)
    decoded = decode_diagnostic(_row(values), clock=_clock())
    assert ok(decoded) == diagnostic
    assert encode_diagnostic(ok(decoded)) == values


# --------------------------------------------------------------------------
# The two database-backed properties (reading 23; reading 22)
# --------------------------------------------------------------------------


@given(batch=causal_batches())
@settings(max_examples=15, deadline=None)
def test_causal_edges_converge_under_every_recording_order(
    batch: tuple[tuple[Diagnostic, ...], tuple[int, ...]],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    records, order = batch
    database = open_test_database(tmp_path_factory.mktemp("edges"), clock=_clock())
    try:
        recorder = SqliteDiagnosticRecorder(database, clock=_clock())
        for index in order:
            assert isinstance(recorder.record(records[index]), Success)
        expected = {
            (record.diagnostic_id, cause)
            for record in records
            for cause in record.model_dump(mode="json")["causal_diagnostic_ids"]
        }
        edges = causal_edges(database)
        assert set(edges) == expected
        assert len(edges) == len(expected)
        report = database.consistency_report()
        assert (report.causal_edge_mismatches, report.unresolved_causal_references) == (
            0,
            0,
        )
    finally:
        database.close()


_SNAPSHOT_DATA_COLUMNS: Final = (
    "configuration_snapshot_json",
    "configuration_audit_hash",
    "material_base_configuration_hash",
)


@given(config=application_configs(), column=st.sampled_from(_SNAPSHOT_DATA_COLUMNS))
@settings(max_examples=12, deadline=None)
def test_a_frozen_snapshot_round_trips_and_an_altered_data_column_is_refused(
    config: ApplicationConfig,
    column: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    snapshot = snapshot_configuration(config)
    altered: str = (
        json.dumps(json.loads(snapshot.configuration_json), indent=1)
        if column == "configuration_snapshot_json"
        else "0" * 64
    )
    database = open_test_database(tmp_path_factory.mktemp("snapshot"), clock=_clock())
    try:
        with database.connection() as connection:
            connection.execute(
                insert(ExperimentRow).values(
                    **encode_experiment(sample_experiment(_E.DRAFT))
                )
            )
            writer = SqliteConfigurationSnapshotWriter(connection, clock=_clock())
            assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)
            assert ok(writer.get(EXPERIMENT_ID)) == snapshot
            # ``column`` is one of the three fixed data-column names above.
            connection.execute(
                text(f"UPDATE experiments SET {column} = :v WHERE experiment_id = :e"),  # noqa: S608
                {"v": altered, "e": EXPERIMENT_ID},
            )
            tampered = writer.get(EXPERIMENT_ID)
            assert code(tampered) == INVARIANT_VIOLATION
            assert _details(tampered)["table"] == "experiments"
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "UPDATE experiments SET configuration_snapshot_schema_version"
                        " = '2.0.0' WHERE experiment_id = :e"
                    ),
                    {"e": EXPERIMENT_ID},
                )
            connection.rollback()
    finally:
        database.close()
