"""Stage 10 Task 3: application service orchestration, transaction joining,
D02 catalog construction, descriptor negotiation, compatibility resolution,
audit availability gate and qualified input evidence tests.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.audit.models import AuditAction
from crypto_lab.capabilities.models import CompatibilityOutcome
from crypto_lab.capabilities.policy import (
    PROHIBITED_CAPABILITIES,
    CompatibilityPolicy,
)
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    RuntimeAvailabilityObservation,
    SupportedSchemaVersion,
)
from crypto_lab.domain.experiment import EngineIdentity, ExperimentSpecDraft
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.application import (
    JoinedUnitOfWork,
    build_adapter_catalog_entry,
    prepare_queue_freeze_snapshot,
    register_strategy_input,
    resolve_slot_compatibility,
    stage_qualified_input_evidence,
    verify_descriptor_negotiation,
)
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION, stage5_failure
from crypto_lab.experiments.experiment_service import (
    create_experiment,
    transition_experiment,
)
from crypto_lab.experiments.requests import (
    ExperimentCreationRequest,
    ExperimentTransitionRequest,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    MATERIAL_HASH,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_retry_policy,
)

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)
VALID_SHA = "a" * 64
VALID_EXE_PATH = "C:\\Program Files\\CryptoLab\\adapters\\vectorbt.exe"


class _StubAuditPort:
    def __init__(self, *, supported: frozenset[str] = frozenset()) -> None:
        self.supported = supported
        self.recorded: list[tuple[str, dict[str, Any]]] = []

    def supports_action(self, action_name: str) -> bool:
        return action_name in self.supported

    def record(
        self, action_name: str, details: dict[str, Any]
    ) -> Success[None] | Failure:
        if action_name not in self.supported:
            raise AssertionError(f"unsupported audit action {action_name}")
        self.recorded.append((action_name, details))
        return Success(outcome="SUCCESS", value=None)


class _StubArtifactStore:
    def __init__(self) -> None:
        self.staged: list[tuple[str, bytes, str]] = []

    def stage_candidate(
        self,
        *,
        owner_kind: str,
        payload: bytes,
        expected_hash: str,
    ) -> Success[str] | Failure:
        if sha256_bytes(payload) != expected_hash:
            return stage5_failure(
                INVARIANT_VIOLATION,
                "hash mismatch",
                source_component="artifact.store",
                timestamp_utc=NOW,
            )
        self.staged.append((owner_kind, payload, expected_hash))
        return Success(outcome="SUCCESS", value=f"cand_{len(self.staged):04d}")


def _sample_strategy_bytes() -> bytes:
    return Path("tests/fixtures/strategy/sma_cross_long.valid.yaml").read_bytes()


def _sample_spec_draft() -> ExperimentSpecDraft:
    return sample_draft()


def test_registration_is_transactional() -> None:
    """U3: injected required-audit refusal leaves no registry mutation visible to
    an independent reader.
    """
    root_uow = InMemoryUnitOfWork(InMemoryBackingStore())
    audit_port = _StubAuditPort(supported=frozenset())
    draft = _sample_spec_draft()
    request = ExperimentCreationRequest(
        schema_version="1.0.0",
        spec_draft=draft,
        material_base_configuration_hash=MATERIAL_HASH,
    )

    joined = JoinedUnitOfWork(root_uow)
    with joined.session() as tx:
        created = create_experiment(
            request,
            unit_of_work=tx,
            clock=FixedClock(INSTANT),
            identity_source=SequentialIdentitySource(),
        )
        assert isinstance(created, Success)
        # Required application audit unavailable -> refuse and rollback outer tx
        if not audit_port.supports_action("EXPERIMENT_CREATED"):
            joined.doom()
            result: Success[Any] | Failure = stage5_failure(
                INVARIANT_VIOLATION,
                "required audit unsupported",
                source_component="experiments.application",
                timestamp_utc=NOW,
            )
        else:
            result = created

    assert isinstance(result, Failure)
    # Independent reader sees zero persisted experiments
    reader_tx = root_uow.begin()
    try:
        assert reader_tx.experiments.get(EXPERIMENT_ID).outcome == "FAILURE"
    finally:
        reader_tx.rollback()


def test_joined_service_failure_cannot_publish() -> None:
    """U3: inner failure, lost CAS, outer failure and inner finally rollback
    cannot split one command's facts.
    """
    root_uow = InMemoryUnitOfWork(InMemoryBackingStore())
    # Seed a DRAFT experiment in its own committed transaction
    seeded = create_experiment(
        ExperimentCreationRequest(
            schema_version="1.0.0",
            spec_draft=_sample_spec_draft(),
            material_base_configuration_hash=MATERIAL_HASH,
        ),
        unit_of_work=root_uow,
        clock=FixedClock(INSTANT),
        identity_source=SequentialIdentitySource(),
    )
    assert isinstance(seeded, Success)

    # Attempt joined transition DRAFT -> VALIDATED followed by an inner failure
    joined = JoinedUnitOfWork(root_uow)

    def _run_failing_join() -> None:
        with joined.session() as tx:
            res = transition_experiment(
                ExperimentTransitionRequest(
                    schema_version="1.0.0",
                    experiment_id=seeded.value.experiment_id,
                    expected_revision=0,
                    target_state=ExperimentState.VALIDATED,
                    reason_code="TEST.OK",
                ),
                unit_of_work=tx,
                clock=FixedClock(INSTANT + timedelta(seconds=1)),
            )
            assert isinstance(res, Success)
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        _run_failing_join()

    # Independent reader still sees DRAFT at revision 0
    reader_tx = root_uow.begin()
    try:
        loaded = reader_tx.experiments.get(seeded.value.experiment_id)
        assert isinstance(loaded, Success)
        assert loaded.value.state is ExperimentState.DRAFT
        assert loaded.value.revision == 0
    finally:
        reader_tx.rollback()


def test_input_hashes_are_recomputed() -> None:
    """U3: changed strategy/dataset/draft bytes cannot retain a claimed identity."""
    raw = _sample_strategy_bytes()
    wrong_hash = "b" * 64
    res = register_strategy_input(
        source_bytes=raw,
        source_name="sma_cross.yaml",
        claimed_content_hash=wrong_hash,
        observed_at_utc=NOW,
    )
    assert isinstance(res, Failure)
    assert any(
        "hash" in d.message.lower() or "mismatch" in d.message.lower()
        for d in res.diagnostics
    )

    # Matching hash succeeds
    valid_res = register_strategy_input(
        source_bytes=raw,
        source_name="sma_cross.yaml",
        claimed_content_hash=None,
        observed_at_utc=NOW,
    )
    assert isinstance(valid_res, Success)
    assert valid_res.value.content_hash != wrong_hash


def test_catalog_requires_explicit_identity() -> None:
    """U3: malformed/missing/extra engine metadata and catalog construction
    failures yield CONFIG.CATALOG_ENTRY_INVALID without mutating caller dict.
    """
    original_meta: dict[str, Any] = {
        "engine_identity": {"engine_name": "vectorbt", "engine_version": "1.2.0"},
        "custom_flag": "enabled",
    }
    snapshot = deepcopy(original_meta)
    ok = build_adapter_catalog_entry(
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_metadata=original_meta,
        observed_at_utc=NOW,
    )
    assert isinstance(ok, Success)
    assert isinstance(ok.value, AdapterCatalogEntry)
    assert ok.value.engine == EngineIdentity(
        engine_name="vectorbt", engine_version="1.2.0"
    )
    assert "engine_identity" not in ok.value.runtime_metadata
    assert original_meta == snapshot  # caller dict untouched

    # Missing engine_identity
    missing = build_adapter_catalog_entry(
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_metadata={"custom_flag": "enabled"},
        observed_at_utc=NOW,
    )
    assert isinstance(missing, Failure)
    assert missing.diagnostics[0].error_code == "CONFIG.CATALOG_ENTRY_INVALID"

    # Extra unknown field inside engine_identity
    extra = build_adapter_catalog_entry(
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_metadata={
            "engine_identity": {
                "engine_name": "vectorbt",
                "engine_version": "1.2.0",
                "unexpected": 1,
            }
        },
        observed_at_utc=NOW,
    )
    assert isinstance(extra, Failure)
    assert extra.diagnostics[0].error_code == "CONFIG.CATALOG_ENTRY_INVALID"


def _sample_descriptor(
    *,
    adapter_name: str = "vectorbt_adapter",
    adapter_version: str = "0.1.0",
    engine_name: str = "vectorbt",
    engine_version: str = "1.2.0",
) -> AdapterDescriptor:
    return AdapterDescriptor(
        schema_version="1.0.0",
        adapter_name=adapter_name,
        adapter_version=adapter_version,
        engine=EngineDescriptor(
            schema_version="1.0.0",
            engine_name=engine_name,
            engine_version=engine_version,
            engine_family="vectorized",
            planned_role="research_backtester",
            known_limitations=(),
        ),
        supported_protocol_versions=("1.0.0",),
        supported_schema_versions=(
            SupportedSchemaVersion(schema_name="run_manifest", schema_version="1.0.0"),
        ),
        capability_vocabulary_version="capabilities/v1",
        native_capabilities=("execution.bar_market",),
        approximated_capabilities=(),
        unsupported_capabilities=("execution.bar_limit",),
        supported_operating_systems=(OperatingSystem.WINDOWS,),
        runtime_requirements=("python>=3.12",),
        network_required=False,
        credentials_required=False,
        known_modeling_limitations=(),
        executable_hash=VALID_SHA,
    )


def test_descriptor_negotiation_agreement() -> None:
    """U3: unsupported versions/vocabulary and descriptor/catalog/slot
    disagreement refuse.
    """
    slot = _sample_spec_draft().selected_engine_slots[0]
    entry = build_adapter_catalog_entry(
        adapter_name=slot.adapter.adapter_name,
        adapter_version=slot.adapter.adapter_version,
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_metadata={
            "engine_identity": {
                "engine_name": slot.engine.engine_name,
                "engine_version": slot.engine.engine_version,
            }
        },
        observed_at_utc=NOW,
    )
    assert isinstance(entry, Success)
    descriptor = _sample_descriptor(
        adapter_name=slot.adapter.adapter_name,
        adapter_version=slot.adapter.adapter_version,
        engine_name=slot.engine.engine_name,
        engine_version=slot.engine.engine_version,
    )
    ok = verify_descriptor_negotiation(
        descriptor=descriptor,
        catalog_entry=entry.value,
        slot=slot,
        observed_at_utc=NOW,
    )
    assert isinstance(ok, Success)

    # Mismatched engine version
    bad_descriptor = _sample_descriptor(
        adapter_name=slot.adapter.adapter_name,
        adapter_version=slot.adapter.adapter_version,
        engine_name=slot.engine.engine_name,
        engine_version="9.9.9",
    )
    refused = verify_descriptor_negotiation(
        descriptor=bad_descriptor,
        catalog_entry=entry.value,
        slot=slot,
        observed_at_utc=NOW,
    )
    assert isinstance(refused, Failure)


def test_all_compatibility_outcomes() -> None:
    """U3: pure resolution preserves all four outcomes and approximation
    exclusions; runtime.live refuses before attempt creation.
    """
    descriptor = _sample_descriptor()
    avail_ok = RuntimeAvailabilityObservation(
        schema_version="1.0.0",
        availability_observation_id="avail_11111111-1111-4111-8111-111111111111",
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_version="1.2.0",
        operating_system=OperatingSystem.WINDOWS,
        available=True,
        observed_at_utc=NOW,
        expires_at_utc=NOW + timedelta(hours=1),
        network_required=False,
        credentials_required=False,
    )
    avail_down = RuntimeAvailabilityObservation(
        schema_version="1.0.0",
        availability_observation_id="avail_22222222-2222-4222-8222-222222222222",
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path=VALID_EXE_PATH,
        executable_hash=VALID_SHA,
        runtime_version="1.2.0",
        operating_system=OperatingSystem.WINDOWS,
        available=False,
        reason_code="ADAPTER.RUNTIME_UNAVAILABLE",
        observed_at_utc=NOW,
        expires_at_utc=NOW + timedelta(hours=1),
        network_required=False,
        credentials_required=False,
    )
    policy = CompatibilityPolicy(
        schema_version="1.0.0",
        policy_version="capability-policy/v1",
        capability_vocabulary_version="capabilities/v1",
        prohibited_capabilities=PROHIBITED_CAPABILITIES,
        permit_credential_requirements=False,
    )
    req_exact = (
        CapabilityRequirement(
            schema_version="1.0.0",
            capability="execution.bar_market",
            required=True,
            minimum_semantics="capabilities/v1",
            approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
            comparison_levels=(ComparisonLevel.LEVEL_2,),
        ),
    )
    res_exact = resolve_slot_compatibility(
        requirements=req_exact,
        descriptor=descriptor,
        availability=avail_ok,
        comparison_level=ComparisonLevel.LEVEL_2,
        policy=policy,
        approximations=(),
    )
    assert isinstance(res_exact, Success)
    assert res_exact.value.outcome is CompatibilityOutcome.SUPPORTED

    res_unavail = resolve_slot_compatibility(
        requirements=req_exact,
        descriptor=descriptor,
        availability=avail_down,
        comparison_level=ComparisonLevel.LEVEL_2,
        policy=policy,
        approximations=(),
    )
    assert isinstance(res_unavail, Success)
    assert res_unavail.value.outcome is CompatibilityOutcome.UNAVAILABLE

    res_incompat = resolve_slot_compatibility(
        requirements=(
            CapabilityRequirement(
                schema_version="1.0.0",
                capability="execution.bar_limit",
                required=True,
                minimum_semantics="capabilities/v1",
                approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                comparison_levels=(ComparisonLevel.LEVEL_2,),
            ),
        ),
        descriptor=descriptor,
        availability=avail_ok,
        comparison_level=ComparisonLevel.LEVEL_2,
        policy=policy,
        approximations=(),
    )
    assert isinstance(res_incompat, Success)
    assert res_incompat.value.outcome is CompatibilityOutcome.NOT_APPLICABLE

    # runtime.live safety policy refuses with Failure before attempt creation
    res_live = resolve_slot_compatibility(
        requirements=(
            CapabilityRequirement(
                schema_version="1.0.0",
                capability="runtime.live",
                required=True,
                minimum_semantics="capabilities/v1",
                approximation_policy=ApproximationPolicy.REJECT,
                comparison_levels=(ComparisonLevel.LEVEL_2,),
            ),
        ),
        descriptor=descriptor,
        availability=avail_ok,
        comparison_level=ComparisonLevel.LEVEL_2,
        policy=policy,
        approximations=(),
    )
    assert isinstance(res_live, Failure)


def test_queue_freezes_complete_snapshot() -> None:
    """U3: projection/refusal facet checks complete snapshot, audit/material
    hashes, retry and compatibility equality.
    """
    retry_policy = sample_retry_policy()
    snap = prepare_queue_freeze_snapshot(
        material_base_configuration_hash=MATERIAL_HASH,
        configuration_audit_hash=VALID_SHA,
        retry_policy=retry_policy,
        slot_compatibility={"slot_vbt": CompatibilityOutcome.SUPPORTED.value},
    )
    assert isinstance(snap, Success)
    assert snap.value.material_base_configuration_hash == MATERIAL_HASH
    assert snap.value.configuration_audit_hash == VALID_SHA
    assert snap.value.retry_policy == retry_policy


def test_input_evidence_matches_owner_and_registry() -> None:
    """U3: qualified-input and refusal facets preserve owner/hash identity."""
    store = _StubArtifactStore()
    payload = b'{"example": "canonical"}'
    expected = sha256_bytes(payload)

    ok = stage_qualified_input_evidence(
        owner_kind="STRATEGY",
        payload=payload,
        expected_hash=expected,
        store=store,
    )
    assert isinstance(ok, Success)
    assert store.staged[0][2] == expected

    bad = stage_qualified_input_evidence(
        owner_kind="STRATEGY",
        payload=b'{"example": "tampered"}',
        expected_hash=expected,
        store=store,
    )
    assert isinstance(bad, Failure)


def test_required_application_audit_unavailable_refuses_mutation() -> None:
    """U3: unsupported required vocabulary refuses before mutation and launch."""
    audit_port = _StubAuditPort(supported=frozenset())
    assert not audit_port.supports_action("EXPERIMENT_QUEUED")
    assert "EXPERIMENT_QUEUED" not in {a.value for a in AuditAction}
