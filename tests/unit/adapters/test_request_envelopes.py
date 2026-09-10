"""Stage 6 Task 2: request envelopes and request material (Stage 6 plan section 3.6,
4, 5.1-5.2 and 6.1).

`EngineRunRequest` is the token-bearing wire payload of one attempt and
`AdapterCommandRequestEnvelope` the command-discriminated wrapper the launcher
writes; `DescribeRequestPayload` is the token-free describe payload. The request
identity `request_hash` is the `ADAPTER_REQUEST_V1` profile over the pre-attempt
material alone, so it is computable before the run exists (`request_material_hash`)
and recomputable from the finished request (`request_hash_of`), and every field
minted by or after `create_attempt` is a named exclusion. The raw attempt token
appears exactly once, inside the payload, never in `repr`, never in an error, and
only `request_envelope_bytes` emits it.
"""

from __future__ import annotations

import ast
import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any, Final, Literal, get_args

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import commands, envelopes
from crypto_lab.adapters.envelopes import (
    AUTHORIZED_ROOT,
    AdapterCommandRequestEnvelope,
    DescribeRequestPayload,
    EngineRunRequest,
    NegotiatedVersions,
    RunConfigurationSnapshot,
    SanitizedEngineRunRequest,
    WorkDirectoryReference,
    build_engine_run_request,
    build_request_envelope,
    payload_hash_of,
    request_envelope_bytes,
    request_hash_of,
    request_material_hash,
    sanitize_engine_run_request,
)
from crypto_lab.adapters.limits import (
    MAX_APPROXIMATIONS,
    PROTOCOL_LIMITS_DEFAULT,
    ProtocolLimits,
)
from crypto_lab.adapters.vocabulary import NEGOTIABLE_SCHEMA_NAMES
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import command_timeout_bounds
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import (
    MAX_APPROXIMATION_IDS,
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
)
from crypto_lab.domain.hashing import (
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.records import Money
from crypto_lab.domain.results import Success
from crypto_lab.experiments.requests import AttemptCreationRequest
from crypto_lab.experiments.run_service import create_attempt
from doubles.experiments import (
    ADAPTER_BETA,
    ATTEMPT_TOKEN,
    DATASET_HASH,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    STRATEGY_HASH,
    THIRD_RUN_ID,
    UUID_C,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_experiment,
    sample_invocation,
    sample_run,
    sample_slot_compatibility,
)

_CREATED: Final = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_OTHER_TOKEN: Final = "B" * 32
_APPROXIMATION: Final = f"appx_{UUID_C}"
_VERSION: Final = "1.0.0"
_MODES: Final[tuple[Literal["python", "json"], ...]] = ("python", "json")

_DESCRIBE_FIELDS: Final = (
    "bootstrap_schema_version",
    "adapter_name",
    "adapter_version",
    "executable_hash",
    "core_supported_protocol_versions",
    "core_supported_schema_versions",
    "core_capability_vocabulary_versions",
)
_SNAPSHOT_FIELDS: Final = (
    "starting_balance",
    "fee_assumptions",
    "slippage_assumptions",
    "execution_assumptions",
    "comparison_level",
    "approximation_ids",
    "limits",
)
_NEGOTIATED_FIELDS: Final = (
    "protocol_version",
    "schema_versions",
    "capability_vocabulary_version",
)
_REQUEST_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "request_id",
    "experiment_id",
    "run_id",
    "logical_slot_id",
    "attempt_number",
    "attempt_token",
    "strategy_version_hash",
    "dataset_version_hash",
    "adapter",
    "engine",
    "configuration_snapshot",
    "configuration_hash",
    "comparison_level",
    "negotiated_versions",
    "assigned_work_dir",
    "experiment_spec_hash",
    "request_hash",
    "created_at_utc",
)
_SANITIZED_FIELDS: Final = tuple(
    "attempt_token_hash" if name == "attempt_token" else name
    for name in _REQUEST_FIELDS
)
_ENVELOPE_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "request_id",
    "invocation_id",
    "command",
    "created_at_utc",
    "timeout_seconds",
    "deadline_utc",
    "payload_hash",
    "payload",
)
#: Plan section 4: every field minted by or after ``create_attempt``.
_EXCLUDED_FIELDS: Final = (
    "run_id",
    "request_id",
    "attempt_token",
    "assigned_work_dir",
    "created_at_utc",
)
#: Plan section 14 Task 2: the Task 2 public surface of ``crypto_lab.adapters``.
_TASK2_EXPORTS: Final = frozenset(
    {
        "AdapterCommand",
        "AdapterCommandRequestEnvelope",
        "DescribeRequestPayload",
        "EngineRunRequest",
        "NegotiatedVersions",
        "RunConfigurationSnapshot",
        "SanitizedEngineRunRequest",
        "WorkDirectoryReference",
        "argument_array",
        "build_engine_run_request",
        "build_request_envelope",
        "payload_hash_of",
        "request_envelope_bytes",
        "request_hash_of",
        "request_material_hash",
        "sanitize_engine_run_request",
    }
)
#: The standard-library subset of the Stage 3 allowlist that reaches no
#: filesystem, environment, clock, random or process source, plus pydantic and
#: the project itself (the Task 1 rule, extended by ``datetime`` for ``timedelta``).
_PURE_ROOTS: Final = frozenset(
    {"__future__", "datetime", "enum", "re", "typing", "pydantic", "crypto_lab"}
)


# --- Fixture material -----------------------------------------------------------


def _schema_versions(version: str = _VERSION) -> tuple[SupportedSchemaVersion, ...]:
    return tuple(
        SupportedSchemaVersion(schema_name=name, schema_version=version)
        for name in NEGOTIABLE_SCHEMA_NAMES
    )


def _negotiated(**overrides: object) -> NegotiatedVersions:
    payload: dict[str, object] = {
        "protocol_version": _VERSION,
        "schema_versions": _schema_versions(),
        "capability_vocabulary_version": "capabilities/v1",
    }
    payload.update(overrides)
    return NegotiatedVersions.model_validate(payload)


def _describe(**overrides: object) -> DescribeRequestPayload:
    payload: dict[str, object] = {
        "bootstrap_schema_version": _VERSION,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_hash": "e" * 64,
        "core_supported_protocol_versions": ("1.0.0",),
        "core_supported_schema_versions": _schema_versions(),
        "core_capability_vocabulary_versions": ("capabilities/v1",),
    }
    payload.update(overrides)
    return DescribeRequestPayload.model_validate(payload)


def _experiment(*, approximated: bool = False) -> ExperimentRecord:
    """A ``QUEUED`` experiment whose slot A is ``SUPPORTED`` or approximated."""
    if not approximated:
        return sample_experiment(ExperimentState.QUEUED)
    return sample_experiment(
        ExperimentState.QUEUED,
        slot_compatibility=sample_slot_compatibility(
            outcomes={SLOT_A: CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION}
        ),
    )


def _material(
    experiment: ExperimentRecord | None = None,
    *,
    slot: str = SLOT_A,
    attempt_number: int = 1,
    negotiated: NegotiatedVersions | None = None,
    limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT,
) -> str:
    return request_material_hash(
        experiment=_experiment() if experiment is None else experiment,
        logical_slot_id=slot,
        attempt_number=attempt_number,
        negotiated=_negotiated() if negotiated is None else negotiated,
        limits=limits,
    )


def _run(
    request_hash: str,
    *,
    run_id: str = RUN_ID,
    slot: str = SLOT_A,
    attempt_number: int = 1,
    experiment_id: str = EXPERIMENT_ID,
    adapter: AdapterIdentity | None = None,
    engine: EngineIdentity | None = None,
) -> EngineRunRecord:
    overrides: dict[str, object] = {}
    if adapter is not None:
        overrides["adapter"] = adapter
    if engine is not None:
        overrides["engine"] = engine
    return sample_run(
        EngineRunState.PENDING,
        run_id=run_id,
        experiment_id=experiment_id,
        logical_slot_id=slot,
        attempt_number=attempt_number,
        request_hash=request_hash,
        attempt_token=ATTEMPT_TOKEN,
        **overrides,  # type: ignore[arg-type]
    )


def _token(run_id: str = RUN_ID, token: str = ATTEMPT_TOKEN) -> AttemptTokenMaterial:
    return AttemptTokenMaterial(run_id=run_id, attempt_token=token)


def _request(
    experiment: ExperimentRecord | None = None,
    *,
    run_id: str = RUN_ID,
    slot: str = SLOT_A,
    attempt_number: int = 1,
    negotiated: NegotiatedVersions | None = None,
    limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT,
    created_at_utc: datetime = _CREATED,
) -> EngineRunRequest:
    """The canonical construction path: material hash, run record, then request."""
    experiment = _experiment() if experiment is None else experiment
    negotiated = _negotiated() if negotiated is None else negotiated
    material = _material(
        experiment,
        slot=slot,
        attempt_number=attempt_number,
        negotiated=negotiated,
        limits=limits,
    )
    adapter = ADAPTER_BETA if slot == SLOT_B else None
    engine = ENGINE_BETA if slot == SLOT_B else None
    return build_engine_run_request(
        run=_run(
            material,
            run_id=run_id,
            slot=slot,
            attempt_number=attempt_number,
            adapter=adapter,
            engine=engine,
        ),
        experiment=experiment,
        token=_token(run_id),
        negotiated=negotiated,
        limits=limits,
        created_at_utc=created_at_utc,
    )


def _with(request: EngineRunRequest, **changes: object) -> EngineRunRequest:
    """``request`` with ``changes`` applied and ``request_hash`` recomputed.

    The draft is assembled without validation so the profile can be evaluated
    over the changed material; the returned model is fully validated, so the
    recomputed hash is proven to be the one the validator accepts.
    """
    fields: dict[str, Any] = dict(request)
    fields.update(changes)
    draft = EngineRunRequest.model_construct(**fields)
    payload = draft.model_dump(mode="python")
    payload["request_hash"] = request_hash_of(draft)
    return EngineRunRequest.model_validate(payload)


def _revalidated(request: EngineRunRequest, **changes: object) -> EngineRunRequest:
    """``request`` with ``changes`` applied and ``request_hash`` left as it was."""
    payload = request.model_dump(mode="python")
    payload.update(changes)
    return EngineRunRequest.model_validate(payload)


def _run_invocation(
    request: EngineRunRequest,
    *,
    kind: CommandKind = CommandKind.RUN,
    state: CommandInvocationState = CommandInvocationState.STARTING,
    timeout_seconds: int = 120,
    **overrides: object,
) -> Any:
    payload: dict[str, object] = {
        "kind": kind,
        "run_id": request.run_id,
        "adapter_name": request.adapter.adapter_name,
        "adapter_version": request.adapter.adapter_version,
        "request_hash": request.request_hash,
        "timeout_seconds": timeout_seconds,
    }
    payload.update(overrides)
    return sample_invocation(state, **payload)  # type: ignore[arg-type]


def _describe_invocation(
    payload: DescribeRequestPayload,
    *,
    state: CommandInvocationState = CommandInvocationState.STARTING,
    **overrides: object,
) -> Any:
    fields: dict[str, object] = {
        "kind": CommandKind.DESCRIBE,
        "adapter_name": payload.adapter_name,
        "adapter_version": payload.adapter_version,
        "request_hash": request_hash_of(payload),
        "timeout_seconds": 60,
    }
    fields.update(overrides)
    return sample_invocation(state, **fields)  # type: ignore[arg-type]


def _envelope(
    payload: DescribeRequestPayload | EngineRunRequest | None = None,
    *,
    kind: CommandKind = CommandKind.RUN,
) -> AdapterCommandRequestEnvelope:
    if payload is None:
        payload = _describe() if kind is CommandKind.DESCRIBE else _request()
    if isinstance(payload, DescribeRequestPayload):
        return build_request_envelope(
            invocation=_describe_invocation(payload), payload=payload
        )
    return build_request_envelope(
        invocation=_run_invocation(payload, kind=kind), payload=payload
    )


def _reenveloped(
    envelope: AdapterCommandRequestEnvelope, **changes: object
) -> AdapterCommandRequestEnvelope:
    payload = envelope.model_dump(mode="python")
    payload.update(changes)
    return AdapterCommandRequestEnvelope.model_validate(payload)


def _is_missing(value: object) -> bool:
    return repr(value) == "MISSING"


def _expected_material_payload(
    experiment: ExperimentRecord,
    *,
    approximation_ids: list[str],
    attempt_number: int = 1,
) -> dict[str, Any]:
    """Plan section 4 restated by hand, as an oracle independent of the module."""
    spec = experiment.spec
    return {
        "experiment_id": experiment.experiment_id,
        "logical_slot_id": SLOT_A,
        "attempt_number": attempt_number,
        "strategy_version_hash": STRATEGY_HASH,
        "dataset_version_hash": DATASET_HASH,
        "configuration_hash": spec.configuration_hash,
        "experiment_spec_hash": experiment.spec_hash,
        "adapter": {"adapter_name": "adapter.alpha", "adapter_version": "1.0.0"},
        "engine": {"engine_name": "engine.alpha", "engine_version": "2.3.4"},
        "configuration_snapshot": {
            "starting_balance": {
                "schema_version": "1.0.0",
                "currency": "USDT",
                "amount": "10000",
            },
            "fee_assumptions": {"maker_fee_rate": "0.001", "taker_fee_rate": "0.002"},
            "slippage_assumptions": {
                "model": "FIXED_BASIS_POINTS",
                "basis_points": "5",
            },
            "execution_assumptions": {
                "signal_to_order_timing": "NEXT_BAR_OPEN",
                "bar_order_priority": "EXITS_BEFORE_ENTRIES",
                "fill_convention": "FULL_FILL",
                "price_precision": 2,
                "quantity_precision": 8,
                "rounding_mode": "ROUND_HALF_EVEN",
            },
            "comparison_level": "LEVEL_2",
            "approximation_ids": approximation_ids,
            "limits": {
                "max_event_bytes": 1_048_576,
                "max_manifest_bytes": 16_777_216,
                "max_stderr_bytes": 52_428_800,
                "heartbeat_interval_seconds": 15,
                "missing_heartbeat_seconds": 45,
            },
        },
        "comparison_level": "LEVEL_2",
        "negotiated_versions": {
            "protocol_version": "1.0.0",
            "schema_versions": [
                {"schema_name": name, "schema_version": "1.0.0"}
                for name in NEGOTIABLE_SCHEMA_NAMES
            ],
            "capability_vocabulary_version": "capabilities/v1",
        },
        "assigned_work_dir": {"authorized_root": "RUNTIME_ROOT"},
    }


# --- Inventory, field order and purity ----------------------------------------------


def test_the_package_exports_the_task_two_surface_sorted() -> None:
    """The package surface gains exactly the Task 2 names, kept in the RUF022
    isort-style order: constants, then classes, then functions, each sorted."""
    exported = adapters_package.__all__
    assert _TASK2_EXPORTS <= set(exported)
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    assert AUTHORIZED_ROOT == "RUNTIME_ROOT"


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (DescribeRequestPayload, _DESCRIBE_FIELDS),
        (WorkDirectoryReference, ("authorized_root", "relative_path")),
        (RunConfigurationSnapshot, _SNAPSHOT_FIELDS),
        (NegotiatedVersions, _NEGOTIATED_FIELDS),
        (EngineRunRequest, _REQUEST_FIELDS),
        (SanitizedEngineRunRequest, _SANITIZED_FIELDS),
        (AdapterCommandRequestEnvelope, _ENVELOPE_FIELDS),
    ],
    ids=lambda value: value.__name__ if isinstance(value, type) else "fields",
)
def test_each_model_declares_exactly_the_plan_fields_in_order_all_required(
    model: type[Any], expected: tuple[str, ...]
) -> None:
    assert tuple(model.model_fields) == expected
    for field in model.model_fields.values():
        assert field.is_required()


def test_nested_value_objects_carry_no_envelope_version() -> None:
    """Plan 3.1: nested value objects carry no ``schema_version``; the describe
    payload carries ``bootstrap_schema_version`` instead (spec 14.2)."""
    for model in (WorkDirectoryReference, RunConfigurationSnapshot, NegotiatedVersions):
        assert "schema_version" not in model.model_fields
    assert "schema_version" not in DescribeRequestPayload.model_fields
    assert "protocol_version" not in DescribeRequestPayload.model_fields


@pytest.mark.parametrize("module", [envelopes, commands], ids=lambda m: m.__name__)
def test_each_task_two_module_imports_only_pure_roots(module: ModuleType) -> None:
    """Preventive (begins green once the module exists): plan 2.6 design rules
    and section 13. No filesystem, environment, clock, random, process or
    ``types`` root; only ``domain`` and ``adapters`` inside the project."""
    source = Path(module.__file__ or "").read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots: set[str] = set()
    project_packages: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                project_packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called not in {"open", "now", "utcnow", "today"}, ast.dump(node)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert project_packages <= {"domain", "adapters"}, sorted(project_packages)
    assert "subprocess" not in source


def test_the_raw_token_annotation_lives_on_exactly_one_request_field() -> None:
    """Section 13: the Stage 6 guard allowlists the classes that may carry a
    field annotated ``AttemptToken``; in Task 2 that is ``EngineRunRequest``
    alone, and ``commands.py`` carries no token text at all."""
    source = Path(envelopes.__file__ or "").read_text(encoding="utf-8")
    tree = ast.parse(source)
    carriers: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(
                    statement.target, ast.Name
                ):
                    annotation = ast.unparse(statement.annotation)
                    if "AttemptToken" in annotation:
                        carriers.append((node.name, statement.target.id))
    assert carriers == [("EngineRunRequest", "attempt_token")]
    command_source = Path(commands.__file__ or "").read_text(encoding="utf-8")
    assert "attempt_token" not in command_source
    assert "AttemptToken" not in command_source


# --- DescribeRequestPayload -----------------------------------------------------------


def test_the_describe_payload_is_strict_frozen_closed_and_token_free() -> None:
    payload = _describe()
    with pytest.raises(ValidationError, match="frozen"):
        payload.adapter_version = "2.0.0"
    dumped = payload.model_dump(mode="python")
    dumped["attempt_token"] = _OTHER_TOKEN
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        DescribeRequestPayload.model_validate(dumped)
    assert _OTHER_TOKEN not in str(captured.value)
    with pytest.raises(ValidationError, match="bootstrap_schema_version"):
        _describe(bootstrap_schema_version="2.0.0")
    assert DescribeRequestPayload.model_validate(payload.model_dump()) == payload
    assert DescribeRequestPayload.model_validate_json(payload.model_dump_json()) == (
        payload
    )
    assert "attempt_token" not in canonical_json_bytes(payload).decode()


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("core_supported_protocol_versions", (), "at least 1"),
        ("core_supported_protocol_versions", ("1.0.0",) * 33, "at most 32"),
        ("core_supported_protocol_versions", ("1.0.0", "1.0.0"), "unique"),
        ("core_supported_protocol_versions", ("1.1.0", "1.0.0"), "sorted"),
        ("core_supported_protocol_versions", ("1.10.0", "1.9.0"), "sorted"),
        ("core_supported_schema_versions", (), "at least 1"),
        ("core_supported_schema_versions", _schema_versions() * 26, "at most 128"),
        ("core_supported_schema_versions", _schema_versions() * 2, "unique"),
        (
            "core_supported_schema_versions",
            tuple(reversed(_schema_versions())),
            "sorted",
        ),
        (
            "core_supported_schema_versions",
            (
                SupportedSchemaVersion(schema_name="a", schema_version="1.10.0"),
                SupportedSchemaVersion(schema_name="a", schema_version="1.9.0"),
            ),
            "sorted",
        ),
        ("core_capability_vocabulary_versions", (), "at least 1"),
        (
            "core_capability_vocabulary_versions",
            tuple(f"capabilities/v{index}" for index in range(1, 10)),
            "at most 8",
        ),
        (
            "core_capability_vocabulary_versions",
            ("capabilities/v1", "capabilities/v1"),
            "unique",
        ),
        (
            "core_capability_vocabulary_versions",
            ("capabilities/v2", "capabilities/v1"),
            "sorted",
        ),
        (
            "core_capability_vocabulary_versions",
            ("capabilities/v10", "capabilities/v9"),
            "sorted",
        ),
    ],
)
def test_the_describe_collections_are_bounded_sorted_and_unique(
    field: str, value: object, reason: str
) -> None:
    with pytest.raises(ValidationError, match=reason):
        _describe(**{field: value})


def test_the_describe_collections_sort_numerically_not_lexically() -> None:
    """``1.9.0`` precedes ``1.10.0`` and ``v9`` precedes ``v10`` (plan 3.8 rule)."""
    payload = _describe(
        core_supported_protocol_versions=("1.9.0", "1.10.0"),
        core_supported_schema_versions=(
            SupportedSchemaVersion(schema_name="a", schema_version="1.9.0"),
            SupportedSchemaVersion(schema_name="a", schema_version="1.10.0"),
            SupportedSchemaVersion(schema_name="b", schema_version="0.1.0"),
        ),
        core_capability_vocabulary_versions=("capabilities/v9", "capabilities/v10"),
    )
    assert payload.core_supported_protocol_versions == ("1.9.0", "1.10.0")


def test_the_describe_identity_is_the_adapter_request_profile_over_the_payload() -> (
    None
):
    """Plan section 4: for ``DESCRIBE`` the ``ADAPTER_REQUEST_V1`` payload is the
    canonical describe payload, computable before the invocation exists."""
    payload = _describe()
    expected = profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1, payload.model_dump(mode="json")
    )
    assert request_hash_of(payload) == expected
    assert request_hash_of(payload) == request_hash_of(_describe())
    assert request_hash_of(_describe(adapter_version="1.0.1")) != expected
    assert request_hash_of(payload) != payload_hash_of(payload)
    assert payload_hash_of(payload) == sha256_bytes(canonical_json_bytes(payload))


def test_request_hash_of_refuses_any_other_type() -> None:
    with pytest.raises(TypeError, match="request material"):
        request_hash_of(_negotiated())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="request material"):
        request_hash_of(_describe().model_dump())  # type: ignore[arg-type]


# --- Nested value objects ------------------------------------------------------------


@pytest.mark.parametrize(
    "relative_path",
    ["C:/runs/x", "/runs/x", "runs/../x", "runs\\x", "../x", "", "runs/x:stream"],
)
def test_the_work_directory_reference_accepts_only_safe_relative_paths(
    relative_path: str,
) -> None:
    with pytest.raises(ValidationError):
        WorkDirectoryReference(
            authorized_root="RUNTIME_ROOT", relative_path=relative_path
        )
    accepted = WorkDirectoryReference(
        authorized_root="RUNTIME_ROOT", relative_path=f"runs/{RUN_ID}/work"
    )
    assert accepted.relative_path == f"runs/{RUN_ID}/work"


def test_the_work_directory_reference_admits_one_authorized_root_label() -> None:
    # Preventive: the field literal and the builder's constant are one value.
    annotation = WorkDirectoryReference.model_fields["authorized_root"].annotation
    assert get_args(annotation) == (AUTHORIZED_ROOT,)
    with pytest.raises(ValidationError, match="authorized_root"):
        WorkDirectoryReference.model_validate(
            {"authorized_root": "C:/runtime", "relative_path": "runs/x/work"}
        )
    with pytest.raises(ValidationError, match="authorized_root"):
        WorkDirectoryReference.model_validate(
            {"authorized_root": "runtime_root", "relative_path": "runs/x/work"}
        )


def _snapshot(**overrides: object) -> RunConfigurationSnapshot:
    spec = _experiment().spec
    payload: dict[str, object] = {
        "starting_balance": spec.starting_balance,
        "fee_assumptions": spec.fee_assumptions,
        "slippage_assumptions": spec.slippage_assumptions,
        "execution_assumptions": spec.execution_assumptions,
        "comparison_level": spec.comparison_level,
        "approximation_ids": (),
        "limits": PROTOCOL_LIMITS_DEFAULT,
    }
    payload.update(overrides)
    return RunConfigurationSnapshot.model_validate(payload)


def test_the_snapshot_requires_a_positive_balance_and_canonical_approximations() -> (
    None
):
    for amount in (Decimal("0"), Decimal("-1")):
        with pytest.raises(ValidationError, match="positive"):
            _snapshot(
                starting_balance=Money(
                    schema_version="1.0.0", currency="USDT", amount=amount
                )
            )
    with pytest.raises(ValidationError, match="unique"):
        _snapshot(approximation_ids=(_APPROXIMATION, _APPROXIMATION))
    other = f"appx_{RUN_ID.removeprefix('run_')}"
    with pytest.raises(ValidationError, match="sorted"):
        _snapshot(
            approximation_ids=tuple(sorted((_APPROXIMATION, other), reverse=True))
        )
    with pytest.raises(ValidationError, match="at most"):
        _snapshot(
            approximation_ids=tuple(
                f"appx_{index:08x}-0000-4000-8000-000000000000"
                for index in range(MAX_APPROXIMATIONS + 1)
            )
        )
    accepted = _snapshot(approximation_ids=tuple(sorted((_APPROXIMATION, other))))
    assert len(accepted.approximation_ids) == 2
    dumped = accepted.model_dump(mode="python")
    dumped["extra"] = 1
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RunConfigurationSnapshot.model_validate(dumped)


def test_negotiated_versions_pin_exactly_the_five_negotiable_names() -> None:
    assert len(NEGOTIABLE_SCHEMA_NAMES) == 5
    negotiated = _negotiated()
    assert tuple(item.schema_name for item in negotiated.schema_versions) == (
        NEGOTIABLE_SCHEMA_NAMES
    )
    versions = _schema_versions()
    with pytest.raises(ValidationError, match=r"at least 5|exactly the"):
        _negotiated(schema_versions=versions[:4])
    with pytest.raises(ValidationError, match=r"at most 5|exactly the"):
        _negotiated(
            schema_versions=(
                *versions,
                SupportedSchemaVersion(
                    schema_name="protocol.extra", schema_version="1.0.0"
                ),
            )
        )
    with pytest.raises(ValidationError, match="exactly the"):
        _negotiated(
            schema_versions=(
                *versions[:4],
                SupportedSchemaVersion(
                    schema_name="protocol.other", schema_version="1.0.0"
                ),
            )
        )
    with pytest.raises(ValidationError, match="exactly the"):
        _negotiated(schema_versions=(*versions[:4], versions[0]))
    with pytest.raises(ValidationError, match="sorted"):
        _negotiated(schema_versions=tuple(reversed(versions)))
    with pytest.raises(ValidationError, match="protocol_version"):
        _negotiated(protocol_version="1.0.1")
    with pytest.raises(ValidationError, match="capability_vocabulary_version"):
        _negotiated(capability_vocabulary_version="v1")


# --- EngineRunRequest -----------------------------------------------------------------


def test_a_built_request_carries_the_derived_identity_hash_and_work_directory() -> None:
    experiment = _experiment()
    material = _material(experiment)
    request = _request(experiment)
    assert request.schema_version == "1.0.0"
    assert request.protocol_version == "1.0.0"
    assert request.request_id == request_id_for(RUN_ID)
    assert request.run_id == RUN_ID
    assert request.experiment_id == EXPERIMENT_ID
    assert request.logical_slot_id == SLOT_A
    assert request.attempt_number == 1
    assert request.attempt_token == ATTEMPT_TOKEN
    assert request.strategy_version_hash == STRATEGY_HASH
    assert request.dataset_version_hash == DATASET_HASH
    assert request.adapter == AdapterIdentity(
        adapter_name="adapter.alpha", adapter_version="1.0.0"
    )
    assert request.engine == EngineIdentity(
        engine_name="engine.alpha", engine_version="2.3.4"
    )
    assert request.configuration_hash == experiment.spec.configuration_hash
    assert request.experiment_spec_hash == experiment.spec_hash
    assert request.comparison_level is experiment.spec.comparison_level
    assert request.configuration_snapshot.comparison_level is request.comparison_level
    assert request.configuration_snapshot.limits == PROTOCOL_LIMITS_DEFAULT
    assert request.configuration_snapshot.approximation_ids == ()
    assert request.negotiated_versions == _negotiated()
    assert request.assigned_work_dir == WorkDirectoryReference(
        authorized_root="RUNTIME_ROOT", relative_path=f"runs/{RUN_ID}/work"
    )
    assert request.request_hash == material
    assert request_hash_of(request) == material
    assert request.created_at_utc == _CREATED


def test_the_request_hash_is_the_profile_over_exactly_the_plan_material() -> None:
    """The plan section 4 payload restated by hand, so the composition itself is
    pinned rather than only the module's agreement with itself."""
    plain = _experiment()
    approximated = _experiment(approximated=True)
    assert _material(plain) == profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1,
        _expected_material_payload(plain, approximation_ids=[]),
    )
    assert _material(approximated) == profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1,
        _expected_material_payload(approximated, approximation_ids=[_APPROXIMATION]),
    )
    assert _material(plain, attempt_number=2) == profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1,
        _expected_material_payload(plain, approximation_ids=[], attempt_number=2),
    )
    assert _material(plain) != _material(approximated)


def test_the_builder_copies_approximation_ids_from_the_frozen_slot() -> None:
    request = _request(_experiment(approximated=True))
    assert request.configuration_snapshot.approximation_ids == (_APPROXIMATION,)
    assert _request().configuration_snapshot.approximation_ids == ()


def test_the_material_hash_is_computable_before_the_run_exists_and_equal_after() -> (
    None
):
    """Plan 6.1 steps 1 and 2 driven through the merged ``create_attempt``: the
    hash handed to the attempt is the hash the finished request recomputes."""
    store = InMemoryBackingStore()
    experiment = _experiment()
    transaction = InMemoryUnitOfWork(store).begin()
    assert isinstance(transaction.experiments.add(experiment), Success)
    assert isinstance(transaction.commit(), Success)
    material = _material(experiment)
    created = create_attempt(
        AttemptCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            expected_experiment_revision=experiment.revision,
            request_hash=material,
        ),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(INSTANT),
        identity_source=SequentialIdentitySource("task2"),
    )
    assert isinstance(created, Success), created
    creation = created.value
    run = creation.attempt
    assert run.request_hash == material
    assert not _is_missing(creation.attempt_token)
    token = creation.attempt_token
    request = build_engine_run_request(
        run=run,
        experiment=creation.experiment,
        token=token,
        negotiated=_negotiated(),
        limits=PROTOCOL_LIMITS_DEFAULT,
        created_at_utc=_CREATED,
    )
    assert request.run_id == run.run_id
    assert request.request_id == request_id_for(run.run_id)
    assert request.request_hash == run.request_hash == material
    assert request_hash_of(request) == material
    assert attempt_token_hash(request.attempt_token) == run.attempt_token_hash
    assert request.assigned_work_dir.relative_path == f"runs/{run.run_id}/work"
    # The experiment record moved to RUNNING at a new revision; the material did not.
    assert creation.experiment.state is ExperimentState.RUNNING
    assert _material(creation.experiment) == material


@pytest.mark.parametrize("field", _EXCLUDED_FIELDS)
def test_each_named_exclusion_leaves_the_request_hash_unchanged(field: str) -> None:
    """Plan section 4: every field minted by or after ``create_attempt`` is outside
    the profile, so a valid request differing only in that field shares the hash."""
    request = _request()
    replacements: dict[str, object] = {
        "run_id": OTHER_RUN_ID,
        "request_id": request_id_for(OTHER_RUN_ID),
        "attempt_token": _OTHER_TOKEN,
        "assigned_work_dir": WorkDirectoryReference(
            authorized_root="RUNTIME_ROOT", relative_path=f"runs/{OTHER_RUN_ID}/work"
        ),
        "created_at_utc": _CREATED + timedelta(days=1),
    }
    changed = _revalidated(request, **{field: replacements[field]})
    assert getattr(changed, field) != getattr(request, field)
    assert changed.request_hash == request.request_hash
    assert request_hash_of(changed) == request_hash_of(request)


def _material_mutations() -> list[tuple[str, object]]:
    base = _request()
    other_limits = ProtocolLimits.model_validate(
        {**PROTOCOL_LIMITS_DEFAULT.model_dump(), "heartbeat_interval_seconds": 16}
    )
    return [
        ("experiment_id", OTHER_EXPERIMENT_ID),
        ("logical_slot_id", SLOT_B),
        ("attempt_number", 2),
        ("strategy_version_hash", "3" * 64),
        ("dataset_version_hash", "4" * 64),
        ("adapter", ADAPTER_BETA),
        ("engine", ENGINE_BETA),
        (
            "configuration_snapshot",
            RunConfigurationSnapshot.model_validate(
                {**dict(base.configuration_snapshot), "limits": other_limits}
            ),
        ),
        ("configuration_hash", "5" * 64),
        ("experiment_spec_hash", "6" * 64),
        (
            "negotiated_versions",
            _negotiated(capability_vocabulary_version="capabilities/v2"),
        ),
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    _material_mutations(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_each_material_field_changes_the_request_hash(
    field: str, value: object
) -> None:
    request = _request()
    changed = _with(request, **{field: value})
    assert getattr(changed, field) != getattr(request, field)
    assert changed.request_hash != request.request_hash
    with pytest.raises(ValidationError, match="request_hash"):
        _revalidated(request, **{field: value})


def test_comparison_level_changes_the_hash_and_must_agree_with_the_snapshot() -> None:
    request = _request()
    level = ComparisonLevel.LEVEL_1
    snapshot = RunConfigurationSnapshot.model_validate(
        {**dict(request.configuration_snapshot), "comparison_level": level}
    )
    changed = _with(request, comparison_level=level, configuration_snapshot=snapshot)
    assert changed.request_hash != request.request_hash
    with pytest.raises(ValidationError, match="comparison_level"):
        _with(request, comparison_level=level)
    with pytest.raises(ValidationError, match="comparison_level"):
        _with(request, configuration_snapshot=snapshot)


def test_the_authorized_root_is_material_and_the_relative_path_is_not() -> None:
    """``assigned_work_dir.authorized_root`` enters the profile; its single admitted
    value means the profile cannot be moved through it, which is asserted by the
    hand-built payload rather than by a second value."""
    request = _request()
    payload = _expected_material_payload(_experiment(), approximation_ids=[])
    assert request_hash_of(request) == profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1, payload
    )
    payload["assigned_work_dir"]["relative_path"] = (
        request.assigned_work_dir.relative_path
    )
    assert request_hash_of(request) != profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1, payload
    )
    # Dict-level sensitivity of the one-valued root label: changed or removed.
    changed_root = _expected_material_payload(_experiment(), approximation_ids=[])
    changed_root["assigned_work_dir"]["authorized_root"] = "OTHER_ROOT"
    assert request_hash_of(request) != profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1, changed_root
    )
    removed_root = _expected_material_payload(_experiment(), approximation_ids=[])
    del removed_root["assigned_work_dir"]
    assert request_hash_of(request) != profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1, removed_root
    )


def test_a_request_whose_hash_does_not_recompute_is_rejected_without_the_token() -> (
    None
):
    request = _request()
    with pytest.raises(ValidationError, match="request_hash") as captured:
        _revalidated(request, request_hash="0" * 64)
    assert ATTEMPT_TOKEN not in str(captured.value)
    assert ATTEMPT_TOKEN not in repr(captured.value)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("schema_version", "2.0.0", "schema_version"),
        ("protocol_version", "1.0.1", "protocol_version"),
        ("attempt_number", 0, "attempt_number"),
        ("attempt_number", 6, "attempt_number"),
        ("attempt_token", "short", "attempt_token"),
        ("attempt_token", "not url safe!" * 3, "attempt_token"),
        ("request_id", f"run_{UUID_C}", "request_id"),
        ("run_id", f"req_{UUID_C}", "run_id"),
        ("created_at_utc", "2026-02-30T00:00:00Z", "created_at_utc"),
    ],
)
def test_request_fields_are_strictly_typed_and_bounded(
    field: str, value: object, reason: str
) -> None:
    payload = _request().model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError, match=reason) as captured:
        EngineRunRequest.model_validate_json(json.dumps(payload))
    assert ATTEMPT_TOKEN not in str(captured.value)


def test_the_request_is_frozen_closed_and_round_trips_in_both_modes() -> None:
    request = _request()
    with pytest.raises(ValidationError, match="frozen"):
        request.attempt_number = 2
    with pytest.raises(ValidationError, match="frozen"):
        request.configuration_snapshot.limits = PROTOCOL_LIMITS_DEFAULT
    dumped = request.model_dump(mode="python")
    dumped["attempt_token_hash"] = attempt_token_hash(ATTEMPT_TOKEN)
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EngineRunRequest.model_validate(dumped)
    assert EngineRunRequest.model_validate(request.model_dump()) == request
    assert EngineRunRequest.model_validate_json(request.model_dump_json()) == request
    assert (
        EngineRunRequest.model_validate_json(
            json.dumps(request.model_dump(mode="json"))
        )
        == request
    )
    assert canonical_json_bytes(request) == canonical_json_bytes(_request())


def test_the_raw_token_is_hidden_from_repr_and_str_but_dumped_exactly_once() -> None:
    request = _request()
    assert ATTEMPT_TOKEN not in repr(request)
    assert ATTEMPT_TOKEN not in str(request)
    assert "attempt_token" not in repr(request)
    for mode in _MODES:
        dumped = request.model_dump(mode=mode)
        assert dumped["attempt_token"] == ATTEMPT_TOKEN
        assert json.dumps(dumped, default=str).count(ATTEMPT_TOKEN) == 1
    assert canonical_json_bytes(request).count(ATTEMPT_TOKEN.encode()) == 1


# --- build_engine_run_request and request_material_hash rejections --------------------


def test_the_builder_rejects_a_token_that_belongs_to_another_run() -> None:
    foreign = "Zq7pT2vK9mN4rS6wX1yB3cD5fG8hJ0kL"
    with pytest.raises(ValueError, match=r"token.*run") as captured:
        build_engine_run_request(
            run=_run(_material()),
            experiment=_experiment(),
            token=_token(OTHER_RUN_ID, foreign),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )
    assert foreign not in str(captured.value)
    assert ATTEMPT_TOKEN not in str(captured.value)


def test_the_builder_rejects_a_token_whose_hash_is_not_the_runs() -> None:
    """Specification 15.6 and 15.7: the computed token hash must match the durable
    ``attempt_token_hash``; a token wrapped with the right ``run_id`` but the wrong
    value is refused, and neither token reaches the error text."""
    foreign = "Zq7pT2vK9mN4rS6wX1yB3cD5fG8hJ0kL"
    with pytest.raises(ValueError, match="attempt token") as captured:
        build_engine_run_request(
            run=_run(_material()),
            experiment=_experiment(),
            token=_token(RUN_ID, foreign),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )
    assert foreign not in str(captured.value)
    assert ATTEMPT_TOKEN not in str(captured.value)
    assert "belong" in str(captured.value)


def test_the_builder_rejects_a_run_of_another_experiment() -> None:
    with pytest.raises(ValueError, match="experiment"):
        build_engine_run_request(
            run=_run(_material(), experiment_id=OTHER_EXPERIMENT_ID),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )


def test_the_builder_rejects_a_slot_that_is_not_selected_by_the_spec() -> None:
    with pytest.raises(ValueError, match="selected slot"):
        build_engine_run_request(
            run=_run(_material(), slot=SLOT_C),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )
    with pytest.raises(ValueError, match="selected slot"):
        _material(slot=SLOT_C)


def test_request_material_needs_the_frozen_slot_compatibility() -> None:
    """An experiment before ``QUEUED`` has no frozen slot, so no request material."""
    with pytest.raises(ValueError, match="slot_compatibility"):
        _material(sample_experiment(ExperimentState.VALIDATED))


def test_the_builder_rejects_a_run_whose_adapter_or_engine_is_not_the_slots() -> None:
    material = _material()
    with pytest.raises(ValueError, match="adapter"):
        build_engine_run_request(
            run=_run(material, adapter=ADAPTER_BETA),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )
    with pytest.raises(ValueError, match="engine"):
        build_engine_run_request(
            run=_run(material, engine=ENGINE_BETA),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )


def test_the_builder_rejects_a_run_whose_request_hash_is_not_the_material() -> None:
    with pytest.raises(ValueError, match="request_hash") as captured:
        build_engine_run_request(
            run=_run("a" * 64),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )
    assert ATTEMPT_TOKEN not in str(captured.value)
    # A different negotiation or limit snapshot is different material too.
    with pytest.raises(ValueError, match="request_hash"):
        build_engine_run_request(
            run=_run(_material()),
            experiment=_experiment(),
            token=_token(),
            negotiated=_negotiated(capability_vocabulary_version="capabilities/v2"),
            limits=PROTOCOL_LIMITS_DEFAULT,
            created_at_utc=_CREATED,
        )


def test_the_builder_serves_the_second_slot_and_a_successor_attempt() -> None:
    request = _request(slot=SLOT_B)
    assert request.adapter == ADAPTER_BETA
    assert request.engine == ENGINE_BETA
    assert request.logical_slot_id == SLOT_B
    successor = _material(attempt_number=2)
    run = sample_run(
        EngineRunState.PENDING,
        run_id=THIRD_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
        request_hash=successor,
        attempt_token=_OTHER_TOKEN,
    )
    built = build_engine_run_request(
        run=run,
        experiment=_experiment(),
        token=_token(THIRD_RUN_ID, _OTHER_TOKEN),
        negotiated=_negotiated(),
        limits=PROTOCOL_LIMITS_DEFAULT,
        created_at_utc=_CREATED,
    )
    assert built.attempt_number == 2
    assert built.request_hash == successor != _material()


def test_request_material_hash_takes_a_built_in_bounded_attempt_number() -> None:
    with pytest.raises(TypeError, match="attempt_number"):
        _material(attempt_number=True)
    for attempt_number in (0, 6):
        with pytest.raises(ValueError, match="attempt_number"):
            _material(attempt_number=attempt_number)


# --- SanitizedEngineRunRequest -------------------------------------------------------


def test_the_sanitized_request_substitutes_the_token_hash_and_keeps_the_identity() -> (
    None
):
    request = _request()
    sanitized = sanitize_engine_run_request(request)
    assert isinstance(sanitized, SanitizedEngineRunRequest)
    assert tuple(dict(sanitized)) == _SANITIZED_FIELDS
    assert sanitized.attempt_token_hash == attempt_token_hash(ATTEMPT_TOKEN)
    assert sanitized.request_hash == request.request_hash
    assert request_hash_of(sanitized) == request_hash_of(request)
    for mode in _MODES:
        dumped = sanitized.model_dump(mode=mode)
        assert "attempt_token" not in dumped
        assert ATTEMPT_TOKEN not in json.dumps(dumped, default=str)
    assert ATTEMPT_TOKEN.encode() not in canonical_json_bytes(sanitized)
    assert ATTEMPT_TOKEN not in repr(sanitized)
    for name in _REQUEST_FIELDS:
        if name != "attempt_token":
            assert getattr(sanitized, name) == getattr(request, name)


def test_the_sanitized_request_refuses_a_raw_token_and_a_stale_hash() -> None:
    sanitized = sanitize_engine_run_request(_request())
    dumped = sanitized.model_dump(mode="python")
    dumped["attempt_token"] = ATTEMPT_TOKEN
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        SanitizedEngineRunRequest.model_validate(dumped)
    assert ATTEMPT_TOKEN not in str(captured.value)
    dumped = sanitized.model_dump(mode="python")
    dumped["request_hash"] = "0" * 64
    with pytest.raises(ValidationError, match="request_hash"):
        SanitizedEngineRunRequest.model_validate(dumped)
    dumped = sanitized.model_dump(mode="python")
    dumped["comparison_level"] = ComparisonLevel.LEVEL_1
    with pytest.raises(ValidationError, match="comparison_level"):
        SanitizedEngineRunRequest.model_validate(dumped)
    with pytest.raises(TypeError, match="EngineRunRequest"):
        sanitize_engine_run_request(sanitized)  # type: ignore[arg-type]


# --- AdapterCommandRequestEnvelope -------------------------------------------------


def test_a_run_envelope_is_built_from_the_starting_invocation() -> None:
    request = _request()
    invocation = _run_invocation(request)
    envelope = build_request_envelope(invocation=invocation, payload=request)
    assert envelope.schema_version == "1.0.0"
    assert envelope.protocol_version == "1.0.0"
    assert envelope.request_id == request.request_id
    assert envelope.invocation_id == invocation.invocation_id
    assert envelope.command is CommandKind.RUN
    assert envelope.created_at_utc == invocation.launch_attempted_at_utc
    assert envelope.timeout_seconds == invocation.timeout_seconds == 120
    assert envelope.deadline_utc == invocation.deadline_utc
    assert envelope.deadline_utc == envelope.created_at_utc + timedelta(seconds=120)
    assert envelope.payload_hash == payload_hash_of(request)
    assert envelope.payload == request
    validate = build_request_envelope(
        invocation=_run_invocation(request, kind=CommandKind.VALIDATE), payload=request
    )
    assert validate.command is CommandKind.VALIDATE
    assert validate.payload_hash == envelope.payload_hash


def test_a_describe_envelope_anchors_its_request_id_on_the_invocation() -> None:
    payload = _describe()
    invocation = _describe_invocation(payload)
    envelope = build_request_envelope(invocation=invocation, payload=payload)
    assert envelope.command is CommandKind.DESCRIBE
    assert envelope.request_id == request_id_for(invocation.invocation_id)
    assert envelope.request_id != request_id_for(RUN_ID)
    assert envelope.payload == payload
    assert envelope.payload_hash == payload_hash_of(payload)
    assert envelope.created_at_utc == invocation.launch_attempted_at_utc
    assert envelope.timeout_seconds == 60
    repeated = build_request_envelope(
        invocation=_describe_invocation(payload, invocation_id=OTHER_INVOCATION_ID),
        payload=payload,
    )
    assert repeated.request_id == request_id_for(OTHER_INVOCATION_ID)
    assert repeated.payload_hash == envelope.payload_hash


@pytest.mark.parametrize(
    "state",
    [
        CommandInvocationState.PENDING,
        CommandInvocationState.RUNNING,
        CommandInvocationState.EXITED,
    ],
)
def test_the_envelope_builder_requires_a_starting_invocation(
    state: CommandInvocationState,
) -> None:
    request = _request()
    with pytest.raises(ValueError, match="STARTING"):
        build_request_envelope(
            invocation=_run_invocation(request, state=state), payload=request
        )
    payload = _describe()
    with pytest.raises(ValueError, match="STARTING"):
        build_request_envelope(
            invocation=_describe_invocation(payload, state=state), payload=payload
        )


def test_the_envelope_builder_pairs_only_the_invocations_own_payload() -> None:
    request = _request()
    payload = _describe()
    with pytest.raises(ValueError, match="DESCRIBE"):
        build_request_envelope(
            invocation=_describe_invocation(payload, request_hash=request.request_hash),
            payload=request,
        )
    with pytest.raises(ValueError, match="DESCRIBE"):
        build_request_envelope(
            invocation=_run_invocation(request, request_hash=request_hash_of(payload)),
            payload=payload,
        )
    with pytest.raises(TypeError, match="payload"):
        build_request_envelope(
            invocation=_run_invocation(request),
            payload=request.model_dump(),  # type: ignore[arg-type]
        )
    # Preventive (begins green): Stage 5 admission pins the run's request_hash
    # only for RUN, so the envelope builder is where a divergent VALIDATE hash
    # is first refused (plan 6.2 assigns the run's hash to both).
    with pytest.raises(ValueError, match="request_hash"):
        build_request_envelope(
            invocation=_run_invocation(
                request, kind=CommandKind.VALIDATE, request_hash="a" * 64
            ),
            payload=request,
        )
    with pytest.raises(ValueError, match="run_id"):
        build_request_envelope(
            invocation=_run_invocation(request, run_id=OTHER_RUN_ID), payload=request
        )
    with pytest.raises(ValueError, match="request_hash"):
        build_request_envelope(
            invocation=_run_invocation(request, request_hash="a" * 64), payload=request
        )
    with pytest.raises(ValueError, match="adapter"):
        build_request_envelope(
            invocation=_run_invocation(request, adapter_version="1.0.1"),
            payload=request,
        )
    with pytest.raises(ValueError, match="request_hash"):
        build_request_envelope(
            invocation=_describe_invocation(payload, request_hash="a" * 64),
            payload=payload,
        )
    with pytest.raises(ValueError, match="adapter"):
        build_request_envelope(
            invocation=_describe_invocation(payload, adapter_name="adapter.beta"),
            payload=payload,
        )


def test_the_envelope_builder_requires_the_derived_request_id() -> None:
    """Plan 6.1 and 9.2 check (3): the run request identity is
    ``request_id_for(run_id)``; the launch chokepoint refuses a payload carrying
    a foreign or drawn identity so an honest adapter is never blamed for it."""
    request = _request()
    foreign = _revalidated(request, request_id=request_id_for(OTHER_RUN_ID))
    assert foreign.request_hash == request.request_hash
    with pytest.raises(ValueError, match="request_id") as captured:
        build_request_envelope(invocation=_run_invocation(foreign), payload=foreign)
    assert ATTEMPT_TOKEN not in str(captured.value)
    with pytest.raises(ValueError, match="request_id"):
        build_request_envelope(
            invocation=_run_invocation(foreign, kind=CommandKind.VALIDATE),
            payload=foreign,
        )


def test_the_envelope_rejects_a_command_payload_mismatch_in_both_directions() -> None:
    run_envelope = _envelope()
    describe_envelope = _envelope(kind=CommandKind.DESCRIBE)
    with pytest.raises(ValidationError, match="DESCRIBE"):
        _reenveloped(run_envelope, command=CommandKind.DESCRIBE, timeout_seconds=60)
    with pytest.raises(ValidationError, match="DESCRIBE"):
        _reenveloped(describe_envelope, command=CommandKind.VALIDATE)
    with pytest.raises(ValidationError, match="DESCRIBE"):
        _reenveloped(describe_envelope, command=CommandKind.RUN)
    with pytest.raises(ValidationError, match="DESCRIBE"):
        _reenveloped(run_envelope, payload=describe_envelope.payload)


@pytest.mark.parametrize(
    ("kind", "timeout_seconds"),
    [
        (CommandKind.DESCRIBE, 0),
        (CommandKind.DESCRIBE, 301),
        (CommandKind.VALIDATE, 0),
        (CommandKind.VALIDATE, 1801),
        (CommandKind.RUN, 0),
        (CommandKind.RUN, 604801),
    ],
)
def test_the_envelope_timeout_stays_within_the_kinds_bounds(
    kind: CommandKind, timeout_seconds: int
) -> None:
    envelope = _envelope(kind=kind)
    with pytest.raises(ValidationError, match="timeout_seconds"):
        _reenveloped(
            envelope,
            timeout_seconds=timeout_seconds,
            deadline_utc=envelope.created_at_utc + timedelta(seconds=timeout_seconds),
        )
    bounds = command_timeout_bounds(kind)
    for edge in (bounds.minimum_seconds, bounds.maximum_seconds):
        accepted = _reenveloped(
            envelope,
            timeout_seconds=edge,
            deadline_utc=envelope.created_at_utc + timedelta(seconds=edge),
        )
        assert accepted.timeout_seconds == edge


def test_the_envelope_deadline_equals_creation_plus_timeout() -> None:
    envelope = _envelope()
    for delta in (timedelta(seconds=1), timedelta(seconds=-1), timedelta(days=1)):
        with pytest.raises(ValidationError, match="deadline_utc"):
            _reenveloped(envelope, deadline_utc=envelope.deadline_utc + delta)
    with pytest.raises(ValidationError, match="deadline_utc"):
        _reenveloped(envelope, created_at_utc=envelope.created_at_utc + timedelta(1))


def test_the_envelope_payload_hash_and_request_id_must_agree_with_the_payload() -> None:
    envelope = _envelope()
    with pytest.raises(ValidationError, match="payload_hash") as captured:
        _reenveloped(envelope, payload_hash="0" * 64)
    assert ATTEMPT_TOKEN not in str(captured.value)
    with pytest.raises(ValidationError, match="request_id"):
        _reenveloped(envelope, request_id=request_id_for(OTHER_RUN_ID))
    # Swapping in another run's payload moves both the hash and the identity.
    other = _request(run_id=OTHER_RUN_ID)
    with pytest.raises(ValidationError, match=r"request_id|payload_hash"):
        _reenveloped(envelope, payload=other)
    with pytest.raises(ValidationError, match="payload_hash"):
        _reenveloped(envelope, payload=other, request_id=other.request_id)
    moved = _reenveloped(
        envelope,
        payload=other,
        request_id=other.request_id,
        payload_hash=payload_hash_of(other),
    )
    assert moved.payload == other


def test_the_envelope_header_is_closed_and_never_carries_the_token() -> None:
    """Spec 14.3: the token appears exactly once inside the payload and is
    prohibited in the envelope header; every unknown header field is rejected."""
    envelope = _envelope()
    for extra in ("attempt_token", "run_id", "experiment_id", "environment"):
        dumped = envelope.model_dump(mode="python")
        dumped[extra] = _OTHER_TOKEN
        with pytest.raises(ValidationError, match="extra_forbidden") as captured:
            AdapterCommandRequestEnvelope.model_validate(dumped)
        assert _OTHER_TOKEN not in str(captured.value)
        assert ATTEMPT_TOKEN not in str(captured.value)
    with pytest.raises(ValidationError, match="frozen"):
        envelope.command = CommandKind.VALIDATE
    for version in ("schema_version", "protocol_version"):
        with pytest.raises(ValidationError, match=version):
            _reenveloped(envelope, **{version: "2.0.0"})


def test_request_envelope_bytes_carry_the_token_exactly_once_and_round_trip() -> None:
    run_envelope = _envelope()
    describe_envelope = _envelope(kind=CommandKind.DESCRIBE)
    run_bytes = request_envelope_bytes(run_envelope)
    describe_bytes = request_envelope_bytes(describe_envelope)
    assert run_bytes == canonical_json_bytes(run_envelope)
    assert run_bytes.count(ATTEMPT_TOKEN.encode()) == 1
    assert describe_bytes.count(ATTEMPT_TOKEN.encode()) == 0
    assert b"attempt_token" not in describe_bytes
    assert run_bytes.startswith(b'{"command":"RUN","created_at_utc":"')
    assert ATTEMPT_TOKEN not in repr(run_envelope)
    assert ATTEMPT_TOKEN not in str(run_envelope)
    assert AdapterCommandRequestEnvelope.model_validate_json(run_bytes) == run_envelope
    assert (
        AdapterCommandRequestEnvelope.model_validate_json(describe_bytes)
        == describe_envelope
    )
    assert request_envelope_bytes(_envelope()) == run_bytes
    with pytest.raises(TypeError, match="AdapterCommandRequestEnvelope"):
        request_envelope_bytes(run_envelope.payload)  # type: ignore[arg-type]


def test_the_envelope_bytes_are_bounded_by_construction() -> None:
    """R12 observation: no plan constant bounds the envelope; every field is
    bounded, and the sample stays far below the event ceiling."""
    assert len(request_envelope_bytes(_envelope())) < 8_192
    assert len(request_envelope_bytes(_envelope(kind=CommandKind.DESCRIBE))) < 4_096


def test_the_published_envelope_schema_pins_the_command_payload_pairing() -> None:
    """Plan 3.6: three ``if``/``then`` clauses make the pairing exactly
    expressible, so the committed bytes of Task 9 will reject a swapped payload."""
    schema = TypeAdapter(AdapterCommandRequestEnvelope).json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    clauses = [clause for clause in schema.get("allOf", []) if "if" in clause]
    assert len(clauses) == 3
    pairing = {
        clause["if"]["properties"]["command"]["const"]: clause["then"]["properties"][
            "payload"
        ]["$ref"]
        for clause in clauses
    }
    assert pairing == {
        "DESCRIBE": "#/$defs/DescribeRequestPayload",
        "VALIDATE": "#/$defs/EngineRunRequest",
        "RUN": "#/$defs/EngineRunRequest",
    }
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"] == {
        "const": "1.0.0",
        "title": "Schema Version",
        "type": "string",
    }
    validator = Draft202012Validator(schema)
    run_document = json.loads(request_envelope_bytes(_envelope()))
    describe_document = json.loads(
        request_envelope_bytes(_envelope(kind=CommandKind.DESCRIBE))
    )
    assert validator.is_valid(run_document)
    assert validator.is_valid(describe_document)
    swapped_run = {**run_document, "command": "DESCRIBE"}
    swapped_describe = {**describe_document, "command": "RUN"}
    assert not validator.is_valid(swapped_run)
    assert not validator.is_valid(swapped_describe)
    assert not validator.is_valid({**run_document, "attempt_token": ATTEMPT_TOKEN})
    serialization = TypeAdapter(AdapterCommandRequestEnvelope).json_schema(
        mode="serialization"
    )
    assert serialization == schema
    for rendered in (schema, serialization):
        for clause in clauses:
            target = clause["then"]["properties"]["payload"]["$ref"]
            assert target.removeprefix("#/$defs/") in rendered["$defs"]


def test_the_published_envelope_schema_pins_the_kinds_timeout_maximum() -> None:
    """Plan 12.3: every exactly expressible rule is published. The per-command
    timeout ceiling (300 / 1800 / 604800) rides on the same three clauses, so the
    committed bytes reject what the runtime rejects; the floor is the field's."""
    schema = TypeAdapter(AdapterCommandRequestEnvelope).json_schema(mode="validation")
    clauses = [clause for clause in schema["allOf"] if "if" in clause]
    maxima = {
        clause["if"]["properties"]["command"]["const"]: clause["then"]["properties"][
            "timeout_seconds"
        ]["maximum"]
        for clause in clauses
    }
    assert maxima == {
        kind.value: command_timeout_bounds(kind).maximum_seconds for kind in CommandKind
    }
    assert schema["properties"]["timeout_seconds"]["minimum"] == 1
    validator = Draft202012Validator(schema)
    describe_document = json.loads(
        request_envelope_bytes(_envelope(kind=CommandKind.DESCRIBE))
    )
    assert validator.is_valid({**describe_document, "timeout_seconds": 300})
    assert not validator.is_valid({**describe_document, "timeout_seconds": 301})
    assert not validator.is_valid({**describe_document, "timeout_seconds": 0})
    run_document = json.loads(request_envelope_bytes(_envelope()))
    assert validator.is_valid({**run_document, "timeout_seconds": 604800})
    assert not validator.is_valid({**run_document, "timeout_seconds": 604801})
    validate_document = {**run_document, "command": "VALIDATE"}
    assert validator.is_valid({**validate_document, "timeout_seconds": 1800})
    assert not validator.is_valid({**validate_document, "timeout_seconds": 1801})


def test_the_published_negotiated_versions_pin_the_five_names_by_position() -> None:
    """Plan 5.2 and 12.3: sorted by name over a closed five-name set fixes every
    position, so the exact-names rule is published as ``prefixItems`` and each
    position still validates as a ``SupportedSchemaVersion``."""
    schema = TypeAdapter(NegotiatedVersions).json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    field = schema["properties"]["schema_versions"]
    assert field["minItems"] == 5
    assert field["maxItems"] == 5
    assert field["uniqueItems"] is True
    assert field["items"] == {"$ref": "#/$defs/SupportedSchemaVersion"}
    prefix = field["prefixItems"]
    names = [item["allOf"][1]["properties"]["schema_name"]["const"] for item in prefix]
    assert names == list(NEGOTIABLE_SCHEMA_NAMES)
    for item in prefix:
        assert item["allOf"][0] == {"$ref": "#/$defs/SupportedSchemaVersion"}
        assert item["allOf"][1]["required"] == ["schema_name"]
    validator = Draft202012Validator(schema)
    document = _negotiated().model_dump(mode="json")
    assert validator.is_valid(document)
    swapped = {
        **document,
        "schema_versions": list(reversed(document["schema_versions"])),
    }
    assert not validator.is_valid(swapped)
    foreign = {
        **document,
        "schema_versions": [
            *document["schema_versions"][:4],
            {"schema_name": "protocol.other", "schema_version": "1.0.0"},
        ],
    }
    assert not validator.is_valid(foreign)
    malformed = {
        **document,
        "schema_versions": [
            *document["schema_versions"][:4],
            {"schema_name": NEGOTIABLE_SCHEMA_NAMES[4], "schema_version": "x"},
        ],
    }
    assert not validator.is_valid(malformed)
    nested = TypeAdapter(AdapterCommandRequestEnvelope).json_schema(mode="validation")
    nested_negotiated = nested["$defs"]["NegotiatedVersions"]["properties"]
    assert nested_negotiated["schema_versions"]["prefixItems"] == prefix
    assert TypeAdapter(NegotiatedVersions).json_schema(mode="serialization") == schema


def test_payload_hashes_are_reproducible_with_the_standard_library_alone() -> None:
    """Preventive (begins green): plan 4 makes ``payload_hash`` stdlib-reproducible
    so a conforming adapter can verify it with ``hashlib`` and ``json.dumps``."""
    for payload in (_describe(), _request()):
        document = payload.model_dump(mode="json")
        assert payload_hash_of(payload) == _stdlib_digest(document)
    envelope = _envelope()
    parsed = json.loads(request_envelope_bytes(envelope))
    assert parsed["payload_hash"] == _stdlib_digest(parsed["payload"])


def _stdlib_digest(document: object) -> str:
    """The plan 4 recipe: ``hashlib`` over ``json.dumps`` in canonical form."""
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_the_approximation_bound_equals_the_frozen_slot_bound() -> None:
    """Preventive (begins green): ``approximation_ids`` are copied verbatim from
    ``SlotCompatibility``, so the snapshot bound must equal the domain bound."""
    assert MAX_APPROXIMATIONS == MAX_APPROXIMATION_IDS
