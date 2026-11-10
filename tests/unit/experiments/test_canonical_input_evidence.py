"""Stage 9 Task 7 correction (the ruling of 2026-11-10): the three input
snapshot kinds of plan 4.6 answer the canonical contract of the ruling of
2026-11-09 against their authoritative source facts.

``input_snapshot_evidence`` stages caller-supplied canonical bytes -- the
``CanonicalHashEnvelope`` whose SHA-256 is the registry fact -- under the
``AUDIT`` correlation: the frozen ``ConfigSnapshot`` of an experiment
(``configuration-snapshot``, ``EXPERIMENT_INPUT``, ``CONFIGURATION_AUDIT_V1``),
the registered dataset's material metadata (``dataset-manifest``,
``DATASET_INPUT``, ``DATASET_METADATA_V1``) and the registered strategy
version's identity payload (``strategy-snapshot``, ``STRATEGY_INPUT``,
``STRATEGY_VERSION_V1``). Every such envelope carries digests and identifiers,
so the whole-content token-shape rule refused every one of them (the Task 8
finding). The production qualifier now establishes the kind's contract --
the envelope model re-serializing to the very bytes, the kind's hashing
profile, the owner's own registry row read through the transaction, the
digest equal to that row's fact and the payload restating the row's typed
record -- and names the records' uncontrolled strings for the field-level rule.
A declared kind, a parse, or a digest that merely matches a registered row
confers nothing on its own; content that is not the envelope keeps the
whole-content protection; a snapshot owner takes no attempt token material.

The Task 8 correction of the configuration contract: the frozen configuration's
strings are classified by their declared key position, never by their value.
The two token-shaped ``RetryPolicy`` field names are controlled only as keys of
``scheduler.retry``, and the ``executable_hash`` of an adapter entry (declared
``Sha256``) is controlled only at ``adapters.entries[*].executable_hash``; the
same literal as a path value, a runtime-metadata key or a runtime-metadata
value -- and every runtime-metadata string, digest-shaped or not -- stays
uncontrolled and is held to the token-shape rule.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Final, cast

import pytest
from pydantic import BaseModel
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    CandidateArtifact,
    CandidateArtifactProducerKind,
)
from crypto_lab.artifacts.ownership import (
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    StrategyArtifactOwner,
)
from crypto_lab.artifacts.ports import (
    CanonicalEvidenceQualifier,
    CanonicalQualification,
)
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.audit.redaction import contains_token_shape
from crypto_lab.configuration.models import (
    AdapterEntryConfig,
    AdaptersConfig,
    ApplicationConfig,
    PathsConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.snapshot import ConfigSnapshot, snapshot_configuration
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import Sha256
from crypto_lab.domain.lifecycle import RetryTerminalState
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryPolicy
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION
from crypto_lab.experiments.finalization import (
    INPUT_SNAPSHOT_KINDS,
    INPUT_SNAPSHOT_ROLES,
    EvidenceRegistrar,
    finalize_evidence,
    input_snapshot_evidence,
)
from crypto_lab.persistence.diagnostics import WRITE_FAILED, persistence_failure
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategyVersion,
    strategy_version_hash,
    strategy_version_identifier,
)
from doubles.artifacts import (
    AUDIT_EVENT_ID,
    FIXTURE_TOKEN,
    STRATEGY_VERSION_ID,
    sample_candidate,
)
from doubles.experiments import EXPERIMENT_ID, INSTANT, RUN_ID, UUID_B, FixedClock
from persistence_support.artifacts import (
    FinalizationFixture,
    configuration_audit_bytes,
    dataset_identity_bytes,
    strategy_identity_bytes,
)
from persistence_support.harness import (
    commit,
    ok,
    sample_dataset_with_partitions,
    sample_strategy_version,
)

type _SnapshotOwner = (
    ExperimentArtifactOwner | DatasetArtifactOwner | StrategyArtifactOwner
)
_F = ArtifactFinalizationPurpose
_P = CandidateArtifactProducerKind
_KINDS: Final = ("EXPERIMENT", "DATASET", "STRATEGY")
_SHAPED_TEXT: Final = "Q" * 40
_UNREGISTERED_HASH: Final = "3" * 64
_HEX_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_AUDIT_PREFIX: Final = "AUDIT"
#: The ``RetryPolicy`` field name the configuration restates at
#: ``scheduler.retry`` that is itself a run of 35 url-safe characters:
#: token-shaped wherever the positional rule does not control it.
_RETRY_LITERAL: Final = "automatically_retry_terminal_states"
_LONG_RETRY_LITERAL: Final = "require_fresh_availability_observation_for_unavailable"
_ALPHA_HASH: Final = sha256_bytes(b"the alpha adapter executable")
_BETA_HASH: Final = sha256_bytes(b"the beta adapter executable")
_BENIGN_METADATA: Final[dict[str, Any]] = {
    "vendor": "Example Vendor",
    "threads": 4,
    "verbose": True,
    "flags": ["fast"],
    "nested": {"mode": "batch"},
}


def _adapter_entry(
    name: str = "adapter.alpha",
    *,
    executable_hash: str = _ALPHA_HASH,
    runtime_metadata: dict[str, Any] | None = None,
) -> AdapterEntryConfig:
    """A validated adapter entry of the configuration contract: the declared
    ``executable_hash`` beside operator-chosen path text and runtime metadata."""
    return AdapterEntryConfig(
        adapter_name=name,
        adapter_version="1.0.0",
        executable_path=rf"C:\adapters\{name}\adapter.exe",
        executable_hash=executable_hash,
        runtime_metadata=dict(
            _BENIGN_METADATA if runtime_metadata is None else runtime_metadata
        ),
    )


def _adapter_configuration(*entries: AdapterEntryConfig) -> ApplicationConfig:
    return ApplicationConfig(adapters=AdaptersConfig(entries=entries))


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), (
        "; ".join(f"{item.error_code}: {item.message}" for item in result.diagnostics)
        if isinstance(result, Failure)
        else repr(result)
    )
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].error_code


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


@dataclass(frozen=True, slots=True)
class _Facts:
    """The authoritative rows a snapshot qualifies against: the frozen
    configuration of the planted experiment, the registered dataset with its
    partitions and the registered strategy version."""

    snapshot: ConfigSnapshot
    descriptor: DatasetDescriptor
    partitions: tuple[DatasetPartition, ...]
    version: StrategyVersion

    def owner(self, kind: str) -> _SnapshotOwner:
        if kind == "EXPERIMENT":
            return ExperimentArtifactOwner(
                owner_kind="EXPERIMENT", experiment_id=EXPERIMENT_ID
            )
        if kind == "DATASET":
            return DatasetArtifactOwner(
                owner_kind="DATASET", dataset_id=self.descriptor.dataset_id
            )
        assert kind == "STRATEGY", kind
        return StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_hash=self.version.content_hash
        )

    def payload(self, kind: str) -> bytes:
        if kind == "EXPERIMENT":
            return configuration_audit_bytes(self.snapshot)
        if kind == "DATASET":
            return dataset_identity_bytes(self.descriptor, self.partitions)
        assert kind == "STRATEGY", kind
        return strategy_identity_bytes(self.version)

    def fact(self, kind: str) -> str:
        if kind == "EXPERIMENT":
            return self.snapshot.configuration_audit_hash
        if kind == "DATASET":
            return self.descriptor.content_hash
        assert kind == "STRATEGY", kind
        return self.version.content_hash


@pytest.fixture
def production(tmp_path: Path) -> Iterator[FinalizationFixture]:
    opened = FinalizationFixture.open(
        tmp_path, clock=FixedClock(INSTANT), production=True
    )
    try:
        opened.plant_run()
        yield opened
    finally:
        opened.close()


def _register_facts(
    fixture: FinalizationFixture,
    *,
    freeze: bool = True,
    config: ApplicationConfig | None = None,
) -> _Facts:
    """Register the dataset and the strategy version through the registry ports
    and, unless ``freeze`` is false, freeze the configuration snapshot of
    ``config`` (the compiled defaults unless given) for the planted experiment
    through the snapshot writer."""
    descriptor, partitions = sample_dataset_with_partitions()
    version = sample_strategy_version()
    snapshot = snapshot_configuration(ApplicationConfig() if config is None else config)
    transaction = fixture.begin()
    try:
        ok(transaction.datasets.register(descriptor, partitions))
        ok(transaction.strategy_versions.register(version))
        if freeze:
            ok(transaction.configuration_snapshots.freeze(EXPERIMENT_ID, snapshot))
        commit(transaction)
    finally:
        transaction.rollback()
    return _Facts(
        snapshot=snapshot,
        descriptor=descriptor,
        partitions=partitions,
        version=version,
    )


def _freeze(fixture: FinalizationFixture, snapshot: ConfigSnapshot) -> None:
    transaction = fixture.begin()
    try:
        ok(transaction.configuration_snapshots.freeze(EXPERIMENT_ID, snapshot))
        commit(transaction)
    finally:
        transaction.rollback()


def _strategy_variant(
    version: StrategyVersion, *, description: str, seconds: int
) -> StrategyVersion:
    """A second registered version of the fixture's strategy: the same
    specification with another ``description`` (an uncontrolled free-text
    field), created ``seconds`` later so the registry admits it."""
    document = version.strategy_spec.model_dump(mode="json")
    document["description"] = description
    spec = StrategySpec.model_validate_json(canonical_json_bytes(document))
    content_hash = strategy_version_hash(spec)
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_identifier(content_hash),
        strategy_id=spec.strategy_id,
        content_hash=content_hash,
        strategy_spec=spec,
        extension_hashes=version.extension_hashes,
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=INSTANT + timedelta(seconds=seconds),
        source_provenance=version.source_provenance,
    )


def _register_version(fixture: FinalizationFixture, version: StrategyVersion) -> None:
    transaction = fixture.begin()
    try:
        ok(transaction.strategy_versions.register(version))
        commit(transaction)
    finally:
        transaction.rollback()


def _envelope(profile: HashingProfile, payload: dict[str, Any]) -> bytes:
    return canonical_json_bytes(
        CanonicalHashEnvelope(
            schema_version="1.0.0", hashing_profile=profile, payload=payload
        )
    )


def _correlation(fixture: FinalizationFixture) -> EvidenceCorrelation:
    return EvidenceCorrelation(
        kind=_AUDIT_PREFIX, audit_event_id=fixture.audit_ids.new_audit_event_id()
    )


def _stage(
    fixture: FinalizationFixture,
    owner: _SnapshotOwner,
    payload: bytes,
    *,
    expected_hash: str | None = None,
) -> tuple[CandidateArtifact, EvidenceCorrelation]:
    """The one production entry point; the staging boundary checks the bytes
    against ``expected_hash`` (their own digest unless given), never against
    the registry -- the qualifier does that at finalization."""
    correlation = _correlation(fixture)
    staged = input_snapshot_evidence(
        owner,
        payload,
        sha256_bytes(payload) if expected_hash is None else expected_hash,
        correlation.correlation_id,
        store=fixture.roots.store,
        unit_of_work=fixture.unit_of_work(),
        clock=fixture.clock,
    )
    return _ok(staged), correlation


def _finalize(
    fixture: FinalizationFixture,
    candidate: CandidateArtifact,
    correlation: EvidenceCorrelation,
    *,
    token: AttemptTokenMaterial | MISSING = MISSING,  # type: ignore[valid-type]
) -> Result[Any]:
    return finalize_evidence(
        (candidate,), correlation, finalizer=fixture.finalizer(), token=token
    )


def _validated_details(fixture: FinalizationFixture) -> list[dict[str, Any]]:
    return [
        dict(event.details)
        for event in fixture.durable().audit_events
        if event.action.value == "ARTIFACT_VALIDATED"
    ]


def _refused(
    fixture: FinalizationFixture,
    candidate: CandidateArtifact,
    correlation: EvidenceCorrelation,
    code: str,
    fragment: str,
) -> None:
    """The finalization refused with ``code`` and a bounded message naming
    ``fragment`` and no digest; the candidate quarantined, nothing registered."""
    refused = _finalize(fixture, candidate, correlation)
    assert _code(refused) == code, _message(refused)
    message = _message(refused)
    assert fragment in message, message
    assert _HEX_DIGEST.search(message) is None, message
    after = fixture.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert all(
        ref.source_candidate_artifact_id != candidate.candidate_artifact_id
        for ref in after.refs
    )


@pytest.mark.parametrize("kind", _KINDS)
def test_each_input_snapshot_qualifies_against_its_registry_fact(
    production: FinalizationFixture, kind: str
) -> None:
    """The ruling applied to the three input roles: the envelope over the
    authoritative row's own material qualifies (``canonical``), registers under
    the owner with the registry fact as its content hash, is scanned for no
    exact token (a snapshot owner has none) and touches no run row."""
    facts = _register_facts(production)
    before = production.durable()
    payload = facts.payload(kind)
    assert sha256_bytes(payload) == facts.fact(kind)
    candidate, correlation = _stage(
        production, facts.owner(kind), payload, expected_hash=facts.fact(kind)
    )
    assert candidate.artifact_kind == INPUT_SNAPSHOT_KINDS[kind]
    assert candidate.source_role is INPUT_SNAPSHOT_ROLES[kind]
    finalized = _ok(_finalize(production, candidate, correlation))
    assert finalized.journal_state == "REGISTERED"
    (mapping,) = finalized.candidate_to_artifact_refs
    assert mapping.content_hash == facts.fact(kind)
    after = production.durable()
    (ref,) = after.refs
    assert ref.artifact_id == mapping.artifact_id
    assert ref.source_role is INPUT_SNAPSHOT_ROLES[kind]
    assert ref.content_hash == facts.fact(kind)
    assert after.candidate_states[candidate.candidate_artifact_id] == "FINALIZING"
    assert after.run == before.run
    assert after.quarantine_entries == ()
    (details,) = _validated_details(production)
    assert (details["canonical"], details["exact_scan"]) == (True, False)


def test_a_declared_kind_a_parse_or_a_matching_digest_alone_never_qualifies(
    production: FinalizationFixture,
) -> None:
    """Content that is not the envelope answers no contract and keeps the
    whole-content protection: loose token-free JSON under the kind registers as
    non-canonical, a non-canonical serialization of a genuine envelope is
    token-shaped material; the qualifier is closed to the candidate shape -- a
    RESULT candidate wearing the kind, or a core candidate of a run owner
    wearing it, never qualifies."""
    facts = _register_facts(production)
    loose, correlation = _stage(
        production, facts.owner("EXPERIMENT"), b'{"note": "not the model"}\n'
    )
    registered = _ok(_finalize(production, loose, correlation))
    assert registered.journal_state == "REGISTERED"
    (details,) = _validated_details(production)
    assert (details["canonical"], details["exact_scan"]) == (False, False)
    dataset_bytes = facts.payload("DATASET")
    pretty = json.dumps(json.loads(dataset_bytes), indent=2).encode("utf-8")
    assert pretty != dataset_bytes
    assert sha256_bytes(pretty) != facts.fact("DATASET")
    spaced, correlation = _stage(production, facts.owner("DATASET"), pretty)
    _refused(
        production, spaced, correlation, SECURITY_SENSITIVE_MATERIAL_LEAKAGE, "token"
    )
    qualifier = production.registrar
    assert isinstance(qualifier, CanonicalEvidenceQualifier)
    labelled = sample_candidate(artifact_kind=INPUT_SNAPSHOT_KINDS["DATASET"])
    assert labelled.producer_kind is _P.ADAPTER
    assert not isinstance(
        _ok(qualifier.qualify_evidence(labelled, (dataset_bytes,))),
        CanonicalQualification,
    )
    audit_event_id = production.audit_ids.new_audit_event_id()
    leaf = f"{INPUT_SNAPSHOT_KINDS['EXPERIMENT']}.json"
    run_owned = sample_candidate(
        "RUN",
        _F.EVIDENCE,
        producer=_P.CORE,
        artifact_kind=INPUT_SNAPSHOT_KINDS["EXPERIMENT"],
        staging_relative_path=f"{_AUDIT_PREFIX}/{audit_event_id}/{leaf}",
    )
    verdict = qualifier.qualify_evidence(run_owned, (facts.payload("EXPERIMENT"),))
    assert _code(verdict) == ARTIFACT_VALIDATION_FAILED
    assert "owner" in _message(verdict)


def test_authoritative_fact_mismatches_are_refused_at_schema(
    production: FinalizationFixture,
) -> None:
    """Envelopes that are the model but disagree with the facts are
    ``ARTIFACT.VALIDATION_FAILED`` and quarantined: an experiment whose
    configuration is not frozen, a genuine dataset envelope under the
    configuration kind (another profile), a tampered strategy payload whose
    digest names no registered version, and forged provenance -- one registered
    version's owner carrying another registered version's bytes. An owner
    naming an unregistered version is refused at the staging boundary by the
    owner registry before any candidate row exists."""
    facts = _register_facts(production, freeze=False)
    unfrozen, correlation = _stage(
        production, facts.owner("EXPERIMENT"), facts.payload("EXPERIMENT")
    )
    _refused(production, unfrozen, correlation, ARTIFACT_VALIDATION_FAILED, "frozen")
    _freeze(production, facts.snapshot)
    other_profile, correlation = _stage(
        production, facts.owner("EXPERIMENT"), facts.payload("DATASET")
    )
    _refused(
        production, other_profile, correlation, ARTIFACT_VALIDATION_FAILED, "profile"
    )
    document = json.loads(facts.payload("STRATEGY"))
    document["payload"]["strategy_spec"]["display_name"] = "Another Name"
    tampered_bytes = _envelope(HashingProfile.STRATEGY_VERSION_V1, document["payload"])
    assert sha256_bytes(tampered_bytes) != facts.fact("STRATEGY")
    tampered, correlation = _stage(production, facts.owner("STRATEGY"), tampered_bytes)
    _refused(production, tampered, correlation, ARTIFACT_VALIDATION_FAILED, "registry")
    other = _strategy_variant(facts.version, description="Another text.", seconds=1)
    _register_version(production, other)
    forged, correlation = _stage(
        production, facts.owner("STRATEGY"), strategy_identity_bytes(other)
    )
    _refused(production, forged, correlation, ARTIFACT_VALIDATION_FAILED, "owner")
    unregistered = StrategyArtifactOwner(
        owner_kind="STRATEGY", strategy_version_hash=_UNREGISTERED_HASH
    )
    refused = input_snapshot_evidence(
        unregistered,
        facts.payload("STRATEGY"),
        facts.fact("STRATEGY"),
        production.audit_ids.new_audit_event_id(),
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert isinstance(refused, Failure)
    # The owner registry (its rows are restricted to registered versions)
    # refuses the row before any candidate is inserted; the four refused
    # candidates above are the only rows.
    assert len(production.durable().candidates) == 4


def test_uncontrolled_strings_of_a_registered_record_follow_the_shape_rule(
    production: FinalizationFixture,
) -> None:
    """A registered strategy whose free-text description is a 40-character
    url-safe run: the envelope is the model and agrees with every fact, yet the
    field-level rule over the record's uncontrolled strings refuses it as
    token-shaped material; the digests in its controlled fields were never the
    reason (the fixture's own version registers beside it)."""
    facts = _register_facts(production)
    shaped = _strategy_variant(facts.version, description=_SHAPED_TEXT, seconds=1)
    _register_version(production, shaped)
    owner = StrategyArtifactOwner(
        owner_kind="STRATEGY", strategy_version_hash=shaped.content_hash
    )
    payload = strategy_identity_bytes(shaped)
    assert sha256_bytes(payload) == shaped.content_hash
    candidate, correlation = _stage(production, owner, payload)
    _refused(
        production,
        candidate,
        correlation,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        "uncontrolled",
    )
    clean, correlation = _stage(
        production, facts.owner("STRATEGY"), facts.payload("STRATEGY")
    )
    assert _ok(_finalize(production, clean, correlation)).journal_state == "REGISTERED"


def test_snapshot_owners_take_no_attempt_token_material(
    production: FinalizationFixture,
) -> None:
    """The exact raw-token scan applies where material is applicable: a
    snapshot owner has no run, so material handed to its finalization is the
    invariant and nothing is written; the token-free finalization then
    qualifies and reports no exact scan."""
    facts = _register_facts(production)
    candidate, correlation = _stage(
        production, facts.owner("EXPERIMENT"), facts.payload("EXPERIMENT")
    )
    material = AttemptTokenMaterial(run_id=RUN_ID, attempt_token=FIXTURE_TOKEN)
    refused = _finalize(production, candidate, correlation, token=material)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "takes no attempt token" in _message(refused)
    after = production.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "CANDIDATE"
    assert after.refs == ()
    assert after.journal == ()
    registered = _ok(_finalize(production, candidate, correlation))
    assert registered.journal_state == "REGISTERED"
    (details,) = _validated_details(production)
    assert (details["canonical"], details["exact_scan"]) == (True, False)


# --------------------------------------------------------------------------
# The Task 8 correction of the configuration contract through the production
# route: the frozen configuration's strings are classified by declared key
# position, never by value.
# --------------------------------------------------------------------------


def _finalizes_canonically(fixture: FinalizationFixture, facts: _Facts) -> None:
    """The frozen configuration's envelope qualifies (``canonical``) and
    registers under the audit hash; nothing is quarantined."""
    candidate, correlation = _stage(
        fixture,
        facts.owner("EXPERIMENT"),
        facts.payload("EXPERIMENT"),
        expected_hash=facts.fact("EXPERIMENT"),
    )
    finalized = _ok(_finalize(fixture, candidate, correlation))
    assert finalized.journal_state == "REGISTERED"
    (mapping,) = finalized.candidate_to_artifact_refs
    assert mapping.content_hash == facts.fact("EXPERIMENT")
    after = fixture.durable()
    assert after.quarantine_entries == ()
    (details,) = _validated_details(fixture)
    assert (details["canonical"], details["exact_scan"]) == (True, False)


def test_retry_policy_names_are_admissible_at_their_declared_key_position(
    production: FinalizationFixture,
) -> None:
    """The legitimate-key case: a frozen configuration whose non-default retry
    section carries both token-shaped ``RetryPolicy`` field names as the keys
    of ``scheduler.retry`` finalizes canonically (the retained positive that
    the correction must keep)."""
    config = ApplicationConfig(
        scheduler=SchedulerConfig(
            max_concurrent_runs=2,
            retry=RetryConfig(
                maximum_attempts_per_slot=3,
                automatically_retry_terminal_states=(
                    RetryTerminalState.FAILED,
                    RetryTerminalState.TIMED_OUT,
                ),
                retry_delay_seconds=30,
            ),
        )
    )
    facts = _register_facts(production, config=config)
    retry = json.loads(facts.snapshot.configuration_json)["scheduler"]["retry"]
    assert {_RETRY_LITERAL, _LONG_RETRY_LITERAL} <= set(retry)
    _finalizes_canonically(production, facts)


@pytest.mark.parametrize(
    "placement", ["path value", "runtime-metadata key", "runtime-metadata value"]
)
def test_a_retry_policy_name_as_uncontrolled_content_is_refused(
    production: FinalizationFixture, placement: str
) -> None:
    """The Task 8 defect: the token-shaped ``RetryPolicy`` field-name literal
    placed where the contract declares free text -- a path value, a dynamic
    runtime-metadata key or a runtime-metadata value -- is uncontrolled content
    and refused by the field-level rule, although the same literal is the
    contract's own key at ``scheduler.retry`` of the very same document."""
    if placement == "path value":
        config = ApplicationConfig(paths=PathsConfig(runtime_root=_RETRY_LITERAL))
    elif placement == "runtime-metadata key":
        config = _adapter_configuration(
            _adapter_entry(runtime_metadata={_RETRY_LITERAL: "an operator note"})
        )
    else:
        config = _adapter_configuration(
            _adapter_entry(runtime_metadata={"note": _RETRY_LITERAL})
        )
    facts = _register_facts(production, config=config)
    assert facts.snapshot.configuration_json.count(_RETRY_LITERAL) == 2
    candidate, correlation = _stage(
        production,
        facts.owner("EXPERIMENT"),
        facts.payload("EXPERIMENT"),
        expected_hash=facts.fact("EXPERIMENT"),
    )
    _refused(
        production,
        candidate,
        correlation,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        "uncontrolled",
    )


def test_a_frozen_configuration_with_adapter_entries_finalizes_on_its_facts(
    production: FinalizationFixture,
) -> None:
    """The reported rejection: a frozen configuration carrying adapter entries
    -- each with its declared ``executable_hash`` (``Sha256``, token-shaped by
    construction) and benign runtime metadata -- finalizes canonically under
    the audit hash. Another validated configuration -- the same entries under
    another declared hash -- is the model, carries no uncontrolled token-shaped
    text, and is refused because it disagrees with the frozen row."""
    config = _adapter_configuration(
        _adapter_entry("adapter.alpha"),
        _adapter_entry("adapter.beta", executable_hash=_BETA_HASH),
    )
    facts = _register_facts(production, config=config)
    assert facts.snapshot.configuration_json.count(_ALPHA_HASH) == 1
    assert facts.snapshot.configuration_json.count(_BETA_HASH) == 1
    _finalizes_canonically(production, facts)
    other = snapshot_configuration(
        _adapter_configuration(
            _adapter_entry("adapter.alpha", executable_hash=_BETA_HASH),
            _adapter_entry("adapter.beta", executable_hash=_BETA_HASH),
        )
    )
    assert other.configuration_audit_hash != facts.fact("EXPERIMENT")
    mismatched, correlation = _stage(
        production, facts.owner("EXPERIMENT"), configuration_audit_bytes(other)
    )
    _refused(
        production,
        mismatched,
        correlation,
        ARTIFACT_VALIDATION_FAILED,
        "frozen configuration",
    )


@pytest.mark.parametrize(
    "metadata",
    [
        pytest.param({"note": _SHAPED_TEXT}, id="shaped value"),
        pytest.param({_SHAPED_TEXT: "an operator note"}, id="shaped key"),
        pytest.param({"nested": {"digest": _BETA_HASH}}, id="digest-shaped value"),
    ],
)
def test_uncontrolled_runtime_metadata_keeps_the_shape_rule(
    production: FinalizationFixture, metadata: dict[str, Any]
) -> None:
    """The negative controls of the adapter case: the same configuration with
    one token-shaped string planted in an entry's runtime metadata -- a value, a
    dynamic key, or a digest in the very grammar ``executable_hash`` declares --
    is refused as uncontrolled content: runtime metadata is never controlled,
    whatever its values look like."""
    config = _adapter_configuration(
        _adapter_entry(runtime_metadata={**_BENIGN_METADATA, **metadata})
    )
    facts = _register_facts(production, config=config)
    candidate, correlation = _stage(
        production,
        facts.owner("EXPERIMENT"),
        facts.payload("EXPERIMENT"),
        expected_hash=facts.fact("EXPERIMENT"),
    )
    _refused(
        production,
        candidate,
        correlation,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        "uncontrolled",
    )


# --------------------------------------------------------------------------
# The fact checks over a stub transaction: the refusals the registry rows
# cannot be planted for -- the owner rows are restricted to registered rows and
# the registries validate what they store -- answered by planted records.
# --------------------------------------------------------------------------


class _Reader:
    """One registry member of the stub transaction, answering planted results
    whatever identity it is asked for."""

    def __init__(
        self, answer: Result[Any], partitions: Result[Any] | None = None
    ) -> None:
        self._answer = answer
        self._partitions = partitions

    def get(self, experiment_id: str) -> Result[Any]:
        return self._answer

    def get_by_hash(self, content_hash: str) -> Result[Any]:
        return self._answer

    def list_partitions(self, dataset_id: str) -> Result[Any]:
        assert self._partitions is not None, "no partitions were planted"
        return self._partitions


class _StubTransaction:
    """The three readers the input snapshot contracts consult, and the
    ``rollback`` the qualifier releases them with; nothing else."""

    def __init__(self, reader: _Reader) -> None:
        self.configuration_snapshots = reader
        self.strategy_versions = reader
        self.datasets = reader
        self.rolled_back = 0

    def rollback(self) -> None:
        self.rolled_back += 1


@dataclass(frozen=True, slots=True)
class _Record:
    """A registry answer that is no pydantic model."""

    content_hash: str
    dataset_id: str = ""
    strategy_version_id: str = ""
    strategy_spec: Any = None
    extension_hashes: tuple[str, ...] = ()


class _FloatingVersion(BaseModel):
    """A version-shaped model carrying a leaf the classifier does not know."""

    content_hash: str
    strategy_version_id: str
    strategy_spec: StrategySpec
    extension_hashes: tuple[str, ...]
    weight: float


def _success(value: Any) -> Success[Any]:
    return Success[Any](outcome="SUCCESS", value=value)


def _unregistered_facts() -> _Facts:
    descriptor, partitions = sample_dataset_with_partitions()
    return _Facts(
        snapshot=snapshot_configuration(ApplicationConfig()),
        descriptor=descriptor,
        partitions=partitions,
        version=sample_strategy_version(),
    )


def _candidate(kind: str, owner: _SnapshotOwner) -> CandidateArtifact:
    """A staged-looking ``CORE`` ``EVIDENCE`` candidate of the kind under
    ``owner`` with the contract's role and leaf."""
    leaf = f"{INPUT_SNAPSHOT_KINDS[kind]}.json"
    return sample_candidate(
        kind,
        _F.EVIDENCE,
        INPUT_SNAPSHOT_ROLES[kind],
        _P.CORE,
        owner=owner,
        artifact_kind=INPUT_SNAPSHOT_KINDS[kind],
        staging_relative_path=f"{_AUDIT_PREFIX}/{AUDIT_EVENT_ID}/{leaf}",
    )


def _qualify(
    fixture: FinalizationFixture,
    reader: _Reader,
    candidate: CandidateArtifact,
    *records: bytes,
) -> Result[Any]:
    """The production qualifier over a stub transaction answering ``reader``;
    the transaction is released exactly once."""
    stub = _StubTransaction(reader)
    registrar = EvidenceRegistrar(
        fixture.auditor, fixture.clock, transactions=lambda: cast("Any", stub)
    )
    verdict = registrar.qualify_evidence(candidate, records)
    assert stub.rolled_back == 1
    return verdict


def _disagrees(verdict: Result[Any], subject: str) -> None:
    assert _code(verdict) == ARTIFACT_VALIDATION_FAILED, _message(verdict)
    assert subject in _message(verdict), _message(verdict)


def _absent(verdict: Result[Any]) -> None:
    assert not isinstance(_ok(verdict), CanonicalQualification)


def _qualified(verdict: Result[Any]) -> CanonicalQualification:
    qualified = _ok(verdict)
    assert isinstance(qualified, CanonicalQualification)
    assert qualified.records == 1
    return qualified


def test_frozen_configuration_answers_decide_the_experiment_contract(
    production: FinalizationFixture,
) -> None:
    """The configuration check against planted snapshot rows: a storage-class
    read keeps its posture, no frozen snapshot, a snapshot whose text is not
    JSON or whose hash is not a string, a digest other than the snapshot's and
    a second record all refuse or answer no contract; the genuine row qualifies
    with the retry policy's field names controlled and every other key held."""
    facts = _unregistered_facts()
    candidate = _candidate("EXPERIMENT", facts.owner("EXPERIMENT"))
    payload = facts.payload("EXPERIMENT")
    storage = persistence_failure(
        WRITE_FAILED, message="the row could not be read", clock=production.clock
    )
    unreadable = _qualify(production, _Reader(storage), candidate, payload)
    assert _code(unreadable) == WRITE_FAILED
    _disagrees(
        _qualify(production, _Reader(_success(MISSING)), candidate, payload),
        "frozen configuration",
    )
    not_json = facts.snapshot.model_copy(update={"configuration_json": "{not json"})
    _disagrees(
        _qualify(production, _Reader(_success(not_json)), candidate, payload),
        "frozen configuration",
    )
    no_hash = facts.snapshot.model_copy(update={"configuration_audit_hash": 7})
    _disagrees(
        _qualify(production, _Reader(_success(no_hash)), candidate, payload),
        "frozen configuration",
    )
    document = json.loads(payload)
    document["payload"]["schema_version"] = "9.9.9"
    altered = _envelope(HashingProfile.CONFIGURATION_AUDIT_V1, document["payload"])
    genuine = _Reader(_success(facts.snapshot))
    _disagrees(
        _qualify(production, genuine, candidate, altered), "frozen configuration"
    )
    _absent(_qualify(production, genuine, candidate, payload, payload))
    qualified = _qualified(_qualify(production, genuine, candidate, payload))
    assert "heartbeat_interval_seconds" in qualified.uncontrolled_strings
    assert "automatically_retry_terminal_states" not in qualified.uncontrolled_strings
    assert not any(contains_token_shape(t) for t in qualified.uncontrolled_strings)


def _document_keys(value: object, out: set[str]) -> None:
    """Every object key of a decoded document outside the dynamic
    ``runtime_metadata`` mappings -- the contract's declared keys."""
    if isinstance(value, dict):
        for key, item in value.items():
            out.add(key)
            if key != "runtime_metadata":
                _document_keys(item, out)
    elif isinstance(value, list):
        for item in value:
            _document_keys(item, out)


def test_the_configuration_classification_is_positional(
    production: FinalizationFixture,
) -> None:
    """The exact classification of one frozen configuration document in which
    the token-shaped ``RetryPolicy`` literal occurs four times -- as the
    declared key of ``scheduler.retry``, as a path value, as a runtime-metadata
    key and as a runtime-metadata value -- and the ``Sha256`` grammar twice --
    as the declared ``executable_hash`` and as a runtime-metadata value: the
    declared positions alone are controlled; the three content occurrences and
    the metadata digest are uncontrolled, as are the adapter's name, its path
    text and every other key of the document."""
    config = ApplicationConfig(
        paths=PathsConfig(runtime_root=_RETRY_LITERAL),
        scheduler=SchedulerConfig(
            retry=RetryConfig(
                automatically_retry_terminal_states=(RetryTerminalState.FAILED,)
            )
        ),
        adapters=AdaptersConfig(
            entries=(
                _adapter_entry(
                    runtime_metadata={_RETRY_LITERAL: _RETRY_LITERAL, "d": _BETA_HASH}
                ),
            )
        ),
    )
    snapshot = snapshot_configuration(config)
    facts = replace(_unregistered_facts(), snapshot=snapshot)
    payload = facts.payload("EXPERIMENT")
    assert payload.count(_RETRY_LITERAL.encode("utf-8")) == 4
    assert payload.count(_ALPHA_HASH.encode("utf-8")) == 1
    assert payload.count(_BETA_HASH.encode("utf-8")) == 1
    candidate = _candidate("EXPERIMENT", facts.owner("EXPERIMENT"))
    qualified = _qualified(
        _qualify(production, _Reader(_success(snapshot)), candidate, payload)
    )
    strings = qualified.uncontrolled_strings
    assert strings.count(_RETRY_LITERAL) == 3
    assert _LONG_RETRY_LITERAL not in strings
    assert "maximum_attempts_per_slot" not in strings
    assert strings.count(_ALPHA_HASH) == 0
    assert strings.count(_BETA_HASH) == 1
    assert "adapter.alpha" in strings
    assert r"C:\adapters\adapter.alpha\adapter.exe" in strings
    assert "FAILED" in strings
    declared = {"executable_hash", "runtime_metadata", "heartbeat_interval_seconds"}
    assert declared <= set(strings)
    assert "d" in strings
    # Document order (canonical JSON sorts keys): the adapter entry's metadata
    # key, its value and its digest precede the path value under ``paths``.
    assert [t for t in strings if contains_token_shape(t)] == [
        _RETRY_LITERAL,
        _RETRY_LITERAL,
        _BETA_HASH,
        _RETRY_LITERAL,
    ]


def test_the_mirrored_positions_are_the_configuration_contracts_declarations() -> None:
    """The positions the qualifier mirrors are the configuration contract's own
    declarations: ``scheduler.retry`` is the ``RetryConfig`` whose keys are the
    ``RetryPolicy`` fields less the envelope version, ``adapters.entries`` is a
    tuple of ``AdapterEntryConfig`` whose ``executable_hash`` is declared
    ``Sha256``, and the token-shaped declared keys of a complete document are
    exactly the two retry names."""
    assert ApplicationConfig.model_fields["scheduler"].annotation is SchedulerConfig
    assert SchedulerConfig.model_fields["retry"].annotation is RetryConfig
    assert set(RetryConfig.model_fields) == set(RetryPolicy.model_fields) - {
        "schema_version"
    }
    assert ApplicationConfig.model_fields["adapters"].annotation is AdaptersConfig
    assert (
        AdaptersConfig.model_fields["entries"].annotation
        == tuple[AdapterEntryConfig, ...]
    )
    hash_field = AdapterEntryConfig.model_fields["executable_hash"]
    declared_hash: object = hash_field.annotation
    assert declared_hash is Sha256
    document = json.loads(
        snapshot_configuration(
            _adapter_configuration(_adapter_entry())
        ).configuration_json
    )
    keys: set[str] = set()
    _document_keys(document, keys)
    assert {key for key in keys if contains_token_shape(key)} == {
        _RETRY_LITERAL,
        _LONG_RETRY_LITERAL,
    }


def test_registry_answers_decide_the_dataset_contract(
    production: FinalizationFixture,
) -> None:
    """The dataset check against planted registry answers: no row under the
    digest, a row whose hash is not the digest, another dataset's row (forged
    provenance), a storage-class partition read, no partitions, a partition
    count the payload does not restate and a row that is no model refuse; the
    genuine row and partitions qualify."""
    facts = _unregistered_facts()
    candidate = _candidate("DATASET", facts.owner("DATASET"))
    payload = facts.payload("DATASET")
    descriptor, partitions = facts.descriptor, facts.partitions
    missing = persistence_failure(
        INVARIANT_VIOLATION, message="no such row", clock=production.clock
    )
    storage = persistence_failure(
        WRITE_FAILED, message="the rows could not be read", clock=production.clock
    )
    _disagrees(_qualify(production, _Reader(missing), candidate, payload), "registry")
    other_hash = descriptor.model_copy(update={"content_hash": "0" * 64})
    _disagrees(
        _qualify(production, _Reader(_success(other_hash)), candidate, payload),
        "registry fact",
    )
    other_dataset = descriptor.model_copy(update={"dataset_id": f"ds_{UUID_B}"})
    _disagrees(
        _qualify(production, _Reader(_success(other_dataset)), candidate, payload),
        "owner",
    )
    reader = _Reader(_success(descriptor), partitions=storage)
    assert _code(_qualify(production, reader, candidate, payload)) == WRITE_FAILED
    for planted in ((), partitions[:1]):
        reader = _Reader(_success(descriptor), partitions=_success(planted))
        _disagrees(_qualify(production, reader, candidate, payload), "registry record")
    bare = _Record(
        content_hash=descriptor.content_hash, dataset_id=descriptor.dataset_id
    )
    reader = _Reader(_success(bare), partitions=_success(partitions))
    _disagrees(_qualify(production, reader, candidate, payload), "registry record")
    reader = _Reader(_success(descriptor), partitions=_success(partitions))
    qualified = _qualified(_qualify(production, reader, candidate, payload))
    assert "fixture.source" in qualified.uncontrolled_strings
    assert descriptor.content_hash not in qualified.uncontrolled_strings
    assert not any(contains_token_shape(t) for t in qualified.uncontrolled_strings)


def test_registry_answers_decide_the_strategy_contract(
    production: FinalizationFixture,
) -> None:
    """The strategy check against planted registry answers: no row under the
    digest, a row whose hash is not the digest, an owner naming another version
    identifier, extension hashes the payload does not restate, a row that is no
    model and a model carrying a leaf the classifier does not know (both answer
    no contract); an owner naming the version by its identifier qualifies."""
    facts = _unregistered_facts()
    version = facts.version
    by_hash = _candidate("STRATEGY", facts.owner("STRATEGY"))
    by_id = _candidate(
        "STRATEGY",
        StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_id=version.strategy_version_id
        ),
    )
    other_id = _candidate(
        "STRATEGY",
        StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_id=STRATEGY_VERSION_ID
        ),
    )
    assert STRATEGY_VERSION_ID != version.strategy_version_id
    payload = facts.payload("STRATEGY")
    missing = persistence_failure(
        INVARIANT_VIOLATION, message="no such row", clock=production.clock
    )
    _disagrees(_qualify(production, _Reader(missing), by_hash, payload), "registry")
    other_hash = version.model_copy(update={"content_hash": "0" * 64})
    _disagrees(
        _qualify(production, _Reader(_success(other_hash)), by_hash, payload),
        "registry fact",
    )
    genuine = _Reader(_success(version))
    _disagrees(_qualify(production, genuine, other_id, payload), "owner")
    for extension_hashes in (("1" * 64,), ["not", "a", "tuple"]):
        doctored = version.model_copy(update={"extension_hashes": extension_hashes})
        _disagrees(
            _qualify(production, _Reader(_success(doctored)), by_hash, payload),
            "registry record",
        )
    bare = _Record(
        content_hash=version.content_hash,
        strategy_version_id=version.strategy_version_id,
        strategy_spec=version.strategy_spec,
        extension_hashes=version.extension_hashes,
    )
    _absent(_qualify(production, _Reader(_success(bare)), by_hash, payload))
    floating = _FloatingVersion(
        content_hash=version.content_hash,
        strategy_version_id=version.strategy_version_id,
        strategy_spec=version.strategy_spec,
        extension_hashes=version.extension_hashes,
        weight=1.5,
    )
    _absent(_qualify(production, _Reader(_success(floating)), by_hash, payload))
    qualified = _qualified(_qualify(production, genuine, by_id, payload))
    assert "SMA Cross Long" in qualified.uncontrolled_strings
    assert version.content_hash not in qualified.uncontrolled_strings
    assert not any(contains_token_shape(t) for t in qualified.uncontrolled_strings)
