"""Stage 9 Task 1: the candidate/reference record family (plan 3.1, 3.2, 3.1.1).

Every payload is validated in JSON mode through ``model_validate_json`` so the
strict ``CanonicalModel`` configuration is exercised exactly as the published
schema is: enum values are strings, timestamps are canonical ``Z`` text, and an
absent field is an absent key, never ``null``.
"""

from __future__ import annotations

import json
from itertools import product
from typing import Any, cast

import pytest
from pydantic import ValidationError

from crypto_lab.adapters.events import _MEDIA_TYPE_PATTERN
from crypto_lab.adapters.paths import (
    RELATIVE_CANDIDATE_PATH_PATTERN,
    validate_relative_candidate_path,
)
from crypto_lab.artifacts.models import (
    CANDIDATE_ARTIFACT_TRANSITIONS,
    EVIDENCE_ROLES,
    MAX_VALIDATION_OBSERVATIONS,
    MEDIA_TYPE_PATTERN,
    PERMITTED_ROLE_TUPLES,
    RELATIVE_STAGING_PATH_PATTERN,
    RESULT_ROLES,
    ArtifactFinalizationPurpose,
    ArtifactOwnerKind,
    ArtifactRef,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactRuleViolation,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
    ValidationObservation,
    assert_candidate_transition,
    finalized_relative_path_for,
    owner_kind_of,
    validate_finalized_relative_path,
    validate_relative_staging_path,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
from crypto_lab.domain.hashing import artifact_id_for

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_RUN2 = "run_22345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"
_EVT = "evt_12345678-1234-4234-8234-123456789abc"
_AMF = "amf_12345678-1234-4234-8234-123456789abc"
_DIAG = "diag_12345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_CAND2 = "cand_22345678-1234-4234-8234-123456789abc"
_FIN = "fin_12345678-1234-4234-8234-123456789abc"
_RMF = "rmf_12345678-1234-4234-8234-123456789abc"
_HASH = "a" * 64
_HASH2 = "b" * 64
_T0 = "2026-08-10T01:02:03Z"
_T1 = "2026-08-10T01:02:08Z"
_EARLIER = "2026-08-10T01:02:00Z"

_S = CandidateArtifactState
_P = CandidateArtifactProducerKind
_F = ArtifactFinalizationPurpose
_R = ArtifactSourceRole
_K = ArtifactOwnerKind


def _owner(kind: str = "RUN", *, invocation: bool = True) -> dict[str, Any]:
    owners: dict[str, dict[str, Any]] = {
        "RUN": {"owner_kind": "RUN", "experiment_id": _EXP, "run_id": _RUN},
        "EXPERIMENT": {"owner_kind": "EXPERIMENT", "experiment_id": _EXP},
        "DATASET": {"owner_kind": "DATASET", "dataset_id": _DS},
        "STRATEGY": {"owner_kind": "STRATEGY", "strategy_version_id": _STRV},
        "ADAPTER": {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        "SYSTEM": {
            "owner_kind": "SYSTEM",
            "core_component": "artifacts",
            "correlation_id": "stage9",
        },
    }
    owner = dict(owners[kind])
    if kind == "RUN" and invocation:
        owner["invocation_id"] = _INV
    return owner


def _observation(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "observed_at_utc": _T0,
        "stage": "PATH",
        "outcome": "PASSED",
    }
    payload.update(overrides)
    return payload


def _failed_observation() -> dict[str, Any]:
    return _observation(
        stage="SIZE", outcome="FAILED", error_code="ARTIFACT.VALIDATION_FAILED"
    )


def _candidate(**overrides: Any) -> dict[str, Any]:
    """An adapter-produced ``RUN``-owned ``RESULT`` candidate (row 1 of 3.1.1)."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "candidate_artifact_id": _CAND,
        "owner": _owner(),
        "finalization_purpose": "RESULT",
        "source_role": "ENGINE_NATIVE_RESULT",
        "producer_kind": "ADAPTER",
        "artifact_kind": "engine-native-report",
        "staging_relative_path": "results/native.bin",
        "state": "CANDIDATE",
        "adapter_declared_size": 12,
        "adapter_declared_hash": _HASH,
        "adapter_declared_media_type": "application/octet-stream",
        "validation_observations": [],
        "source_event_id": _EVT,
        "created_at_utc": _T0,
        "updated_at_utc": _T0,
        "revision": 1,
    }
    payload.update(overrides)
    return payload


def _core_candidate(**overrides: Any) -> dict[str, Any]:
    """A core-produced ``RUN``-owned ``EVIDENCE`` candidate (row 3 of 3.1.1)."""
    payload = _candidate(
        finalization_purpose="EVIDENCE",
        source_role="CORE_EVIDENCE",
        producer_kind="CORE",
        artifact_kind="stderr-capture",
        staging_relative_path=f"INVOCATION/{_INV}/stderr.txt",
    )
    for declared in (
        "adapter_declared_size",
        "adapter_declared_hash",
        "adapter_declared_media_type",
        "source_event_id",
    ):
        del payload[declared]
    payload.update(overrides)
    return payload


def _ref(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id_for(_CAND, _HASH),
        "owner": _owner(),
        "finalization_purpose": "RESULT",
        "artifact_kind": "engine-native-report",
        "finalized_relative_path": finalized_relative_path_for(_HASH),
        "content_hash": _HASH,
        "size_bytes": 12,
        "media_type": "application/octet-stream",
        "source_role": "ENGINE_NATIVE_RESULT",
        "source_candidate_artifact_id": _CAND,
        "producer_kind": "ADAPTER",
        "validation_profile": "artifact-validation/v1",
        "created_at_utc": _T0,
        "finalized_at_utc": _T1,
        "state": "FINALIZED",
    }
    payload.update(overrides)
    return payload


def _mapping(candidate: str = _CAND, content_hash: str = _HASH) -> dict[str, Any]:
    return {
        "candidate_artifact_id": candidate,
        "artifact_id": artifact_id_for(candidate, content_hash),
        "content_hash": content_hash,
        "size_bytes": 12,
        "deduplicated": False,
    }


def _result(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_id": _FIN,
        "finalization_purpose": "RESULT",
        "owner": _owner(),
        "journal_state": "REGISTERED",
        "candidate_to_artifact_refs": [_mapping()],
        "run_manifest_id": _RMF,
        "run_manifest_hash": _HASH2,
        "registered_at_utc": _T1,
        "replayed": False,
    }
    payload.update(overrides)
    return payload


def _load_candidate(payload: dict[str, Any]) -> CandidateArtifact:
    return CandidateArtifact.model_validate_json(json.dumps(payload))


def _load_ref(payload: dict[str, Any]) -> ArtifactRef:
    return ArtifactRef.model_validate_json(json.dumps(payload))


def _rejects(
    model: type[Any], payload: dict[str, Any], match: str | None = None
) -> None:
    with pytest.raises(ValidationError, match=match):
        model.model_validate_json(json.dumps(payload))


def _without(payload: dict[str, Any], *names: str) -> dict[str, Any]:
    trimmed = dict(payload)
    for name in names:
        del trimmed[name]
    return trimmed


# --- Enums, roles and the owner-kind projection ------------------------------------


def test_enum_memberships_exact() -> None:
    assert tuple(member.value for member in _S) == (
        "CANDIDATE",
        "VALIDATING",
        "FINALIZING",
        "QUARANTINED",
        "CORRUPT",
    )
    assert tuple(member.value for member in _P) == ("ADAPTER", "CORE")
    assert tuple(member.value for member in _F) == ("RESULT", "EVIDENCE")
    assert tuple(member.value for member in _R) == (
        "ENGINE_NATIVE_RESULT",
        "NORMALIZED_RESULT",
        "CORE_EVIDENCE",
        "ADAPTER_DESCRIPTOR_EVIDENCE",
        "DATASET_INPUT",
        "STRATEGY_INPUT",
        "EXPERIMENT_INPUT",
    )
    assert tuple(member.value for member in _K) == (
        "RUN",
        "EXPERIMENT",
        "DATASET",
        "STRATEGY",
        "ADAPTER",
        "SYSTEM",
    )
    assert RESULT_ROLES == frozenset({_R.ENGINE_NATIVE_RESULT, _R.NORMALIZED_RESULT})
    assert EVIDENCE_ROLES == frozenset(_R) - RESULT_ROLES
    assert RESULT_ROLES.isdisjoint(EVIDENCE_ROLES)
    for kind in _K:
        owner = ARTIFACT_OWNER_ADAPTER.validate_json(json.dumps(_owner(kind.value)))
        assert owner_kind_of(owner) is kind


def test_the_role_table_is_exactly_the_nine_tuples_of_the_seven_rows() -> None:
    expected = {
        (_F.RESULT, _P.ADAPTER, _R.ENGINE_NATIVE_RESULT, _K.RUN),
        (_F.RESULT, _P.CORE, _R.NORMALIZED_RESULT, _K.RUN),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.RUN),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.SYSTEM),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.ADAPTER),
        (_F.EVIDENCE, _P.CORE, _R.ADAPTER_DESCRIPTOR_EVIDENCE, _K.ADAPTER),
        (_F.EVIDENCE, _P.CORE, _R.DATASET_INPUT, _K.DATASET),
        (_F.EVIDENCE, _P.CORE, _R.STRATEGY_INPUT, _K.STRATEGY),
        (_F.EVIDENCE, _P.CORE, _R.EXPERIMENT_INPUT, _K.EXPERIMENT),
    }
    assert PERMITTED_ROLE_TUPLES == frozenset(expected)
    assert len(PERMITTED_ROLE_TUPLES) == 9
    assert len({row[:3] for row in PERMITTED_ROLE_TUPLES}) == 7
    accepted = 0
    for purpose, producer, role, kind in product(_F, _P, _R, _K):
        try:
            validate_role_combination(purpose, producer, role, kind)
        except ValueError:
            continue
        accepted += 1
    assert accepted == 9
    with pytest.raises(ValueError, match="not a permitted"):
        validate_role_combination(_F.EVIDENCE, _P.ADAPTER, _R.CORE_EVIDENCE, _K.RUN)


# --- Grammars shared with the adapter package, restated locally -------------------


def test_restated_grammars_equal_the_adapter_package_patterns() -> None:
    """``artifacts`` may not import ``adapters``; the restated text must be
    identical so the two grammars cannot drift."""
    assert RELATIVE_STAGING_PATH_PATTERN == RELATIVE_CANDIDATE_PATH_PATTERN
    assert MEDIA_TYPE_PATTERN == _MEDIA_TYPE_PATTERN
    assert finalized_relative_path_for(_HASH) == f"objects/aa/{_HASH}"
    with pytest.raises(ValueError, match="64 lowercase hex"):
        finalized_relative_path_for("A" * 64)
    with pytest.raises(TypeError, match="content hash must be a built-in string"):
        finalized_relative_path_for(cast("str", b"a" * 64))
    # The finalized grammar, called directly: the shape, then the shard.
    assert validate_finalized_relative_path(f"objects/aa/{_HASH}") == (
        f"objects/aa/{_HASH}"
    )
    with pytest.raises(ValueError, match="objects/<hh>/<sha256>"):
        validate_finalized_relative_path("results/native.bin")
    with pytest.raises(ValueError, match="shard must equal the hash prefix"):
        validate_finalized_relative_path(f"objects/bb/{_HASH}")


@pytest.mark.parametrize(
    "path",
    [
        "",
        "a" * 513,
        "/".join(["a"] * 33),
        "results//native.bin",
        "results/./native.bin",
        "results/../native.bin",
        "a" * 256,
        "results/native bin",
        "results/native.",
        "CON.txt",
        "results/lpt1/native.bin",
    ],
    ids=[
        "empty",
        "over-length",
        "over-segments",
        "empty-segment",
        "dot",
        "dot-dot",
        "over-segment-length",
        "forbidden-character",
        "trailing-dot",
        "reserved-stem",
        "reserved-stem-segment",
    ],
)
def test_restated_staging_grammar_refuses_rule_for_rule_with_adapters(
    path: str,
) -> None:
    """Each rule of the restated grammar fires on the input that fires the same
    rule of ``adapters/paths.py`` and names it with the same text."""
    with pytest.raises(ValueError, match="staging path") as ours:
        validate_relative_staging_path(path)
    with pytest.raises(ValueError, match="candidate path") as theirs:
        validate_relative_candidate_path(path)
    assert str(ours.value).replace("staging path", "candidate path") == str(
        theirs.value
    )


def test_restated_staging_grammar_refuses_a_non_string_like_adapters() -> None:
    with pytest.raises(TypeError, match="staging path must be a built-in string"):
        validate_relative_staging_path(cast("str", b"results/native.bin"))
    with pytest.raises(TypeError, match="candidate path must be a built-in string"):
        validate_relative_candidate_path(cast("str", b"results/native.bin"))


# --- Candidate states, edges and the immutable fields -----------------------------


_TERMINAL = (_S.QUARANTINED, _S.CORRUPT)


def _stored(state: _S) -> CandidateArtifact:
    observations = [_failed_observation()] if state in _TERMINAL else []
    return _load_candidate(
        _candidate(state=state.value, validation_observations=observations)
    )


def _replacement(
    stored: CandidateArtifact, state: _S, **overrides: Any
) -> CandidateArtifact:
    payload = json.loads(stored.model_dump_json())
    observations = list(payload["validation_observations"])
    if state in _TERMINAL and not observations:
        observations.append(_failed_observation())
    payload.update(
        state=state.value,
        validation_observations=observations,
        revision=stored.revision + 1,
        updated_at_utc=_T1,
    )
    payload.update(overrides)
    return _load_candidate(payload)


def test_candidate_states_and_forbidden_transitions() -> None:
    """Plan 4.3 names six edges; every other ordered pair of the 25 is refused,
    and the reflexive ``FINALIZING`` pair is lawful only beside a registered
    candidate-to-artifact mapping (specification 19.2: the consumed candidate
    stays an immutable historical ``FINALIZING`` record linked to the new ref)."""
    edges = {
        (_S.CANDIDATE, _S.VALIDATING),
        (_S.CANDIDATE, _S.QUARANTINED),
        (_S.VALIDATING, _S.FINALIZING),
        (_S.VALIDATING, _S.QUARANTINED),
        (_S.VALIDATING, _S.CORRUPT),
        (_S.FINALIZING, _S.QUARANTINED),
    }
    assert CANDIDATE_ARTIFACT_TRANSITIONS.transitions == frozenset(edges)
    assert CANDIDATE_ARTIFACT_TRANSITIONS.terminal_states == set(_TERMINAL)
    mapping = CandidateFinalization.model_validate_json(json.dumps(_mapping()))
    foreign_mapping = CandidateFinalization.model_validate_json(
        json.dumps(_mapping(_CAND2))
    )
    allowed = 0
    forbidden = 0
    for current, target in product(_S, _S):
        stored = _stored(current)
        replacement = _replacement(stored, target)
        if (current, target) in edges:
            assert_candidate_transition(stored, replacement)
            allowed += 1
        elif current is target is _S.FINALIZING:
            with pytest.raises(CandidateArtifactRuleViolation, match="registered"):
                assert_candidate_transition(stored, replacement)
            with pytest.raises(CandidateArtifactRuleViolation, match="registered"):
                assert_candidate_transition(
                    stored, replacement, registered_mapping=foreign_mapping
                )
            assert_candidate_transition(stored, replacement, registered_mapping=mapping)
        else:
            with pytest.raises(CandidateArtifactRuleViolation):
                assert_candidate_transition(stored, replacement)
            forbidden += 1
    assert allowed == 6
    assert forbidden == 25 - 6 - 1
    # A registered mapping licenses only the reflexive FINALIZING pair: neither
    # another reflexive pair nor a permitted edge accepts one.
    stored = _stored(_S.CANDIDATE)
    with pytest.raises(CandidateArtifactRuleViolation, match="registered"):
        assert_candidate_transition(
            stored, _replacement(stored, _S.CANDIDATE), registered_mapping=mapping
        )
    validating = _stored(_S.VALIDATING)
    with pytest.raises(CandidateArtifactRuleViolation, match="accompanies only"):
        assert_candidate_transition(
            validating,
            _replacement(validating, _S.FINALIZING),
            registered_mapping=mapping,
        )


@pytest.mark.parametrize(
    ("base", "changes"),
    [
        ("adapter", {"candidate_artifact_id": _CAND2}),
        ("adapter", {"owner": {**_owner(), "run_id": _RUN2}}),
        ("adapter", {"artifact_kind": "other-kind"}),
        ("adapter", {"staging_relative_path": "results/other.bin"}),
        ("adapter", {"adapter_declared_size": 13}),
        ("adapter", {"adapter_declared_hash": _HASH2}),
        ("adapter", {"adapter_declared_media_type": "text/plain"}),
        ("adapter", {"created_at_utc": _EARLIER}),
        # Each replacement below is shape-valid on its own, so only the pair rule
        # can refuse it: the purpose, role, producer and owner are immutable.
        (
            "core",
            {"finalization_purpose": "RESULT", "source_role": "NORMALIZED_RESULT"},
        ),
        ("core", {"source_role": "DATASET_INPUT", "owner": _owner("DATASET")}),
        ("core", {"owner": _owner("SYSTEM")}),
        (
            "core",
            {
                "producer_kind": "ADAPTER",
                "finalization_purpose": "RESULT",
                "source_role": "ENGINE_NATIVE_RESULT",
                "adapter_declared_size": 12,
                "adapter_declared_hash": _HASH,
                "adapter_declared_media_type": "text/plain",
            },
        ),
    ],
)
def test_candidate_immutable_fields_hold_across_every_edge(
    base: str, changes: dict[str, Any]
) -> None:
    stored = _load_candidate(_candidate() if base == "adapter" else _core_candidate())
    payload = json.loads(stored.model_dump_json())
    payload.update(state="VALIDATING", revision=2, updated_at_utc=_T1)
    payload.update(changes)
    replacement = _load_candidate(payload)
    with pytest.raises(CandidateArtifactRuleViolation, match="immutable"):
        assert_candidate_transition(stored, replacement)


def test_candidate_transition_bookkeeping_and_accumulating_observations() -> None:
    stored = _stored(_S.CANDIDATE)
    with pytest.raises(CandidateArtifactRuleViolation, match="revision"):
        assert_candidate_transition(
            stored, _replacement(stored, _S.VALIDATING, revision=3)
        )
    later = _load_candidate(_candidate(updated_at_utc=_T1))
    with pytest.raises(CandidateArtifactRuleViolation, match="updated_at_utc"):
        assert_candidate_transition(
            later, _replacement(later, _S.VALIDATING, updated_at_utc=_T0)
        )
    observed = _replacement(
        stored, _S.VALIDATING, validation_observations=[_observation()]
    )
    assert_candidate_transition(stored, observed)
    dropped = _replacement(observed, _S.FINALIZING, validation_observations=[])
    with pytest.raises(CandidateArtifactRuleViolation, match="accumulate"):
        assert_candidate_transition(observed, dropped)
    terminal = _replacement(stored, _S.QUARANTINED)
    with pytest.raises(CandidateArtifactRuleViolation, match="terminal"):
        assert_candidate_transition(terminal, _replacement(terminal, _S.QUARANTINED))
    with pytest.raises(TypeError, match="CandidateArtifact"):
        assert_candidate_transition(stored, "replacement")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mapping",
    [object(), None, _mapping()],
    ids=["object", "none", "mapping-shaped-dict"],
)
def test_reflexive_finalizing_refuses_a_wrongly_typed_mapping(mapping: object) -> None:
    """A supplied ``registered_mapping`` must be a ``CandidateFinalization``
    record; a bare object, ``None`` and a mapping-shaped dictionary are refused
    with the ``TypeError`` the record arguments raise, never admitted."""
    stored = _stored(_S.FINALIZING)
    replacement = _replacement(stored, _S.FINALIZING)
    with pytest.raises(TypeError, match="CandidateFinalization"):
        assert_candidate_transition(stored, replacement, registered_mapping=mapping)


# --- Producer-governed fields -------------------------------------------------------


def test_producer_governed_fields() -> None:
    assert _load_candidate(_candidate()).producer_kind is _P.ADAPTER
    for declared in (
        "adapter_declared_size",
        "adapter_declared_hash",
        "adapter_declared_media_type",
    ):
        _rejects(CandidateArtifact, _without(_candidate(), declared), "ADAPTER")
    _rejects(
        CandidateArtifact, _candidate(owner=_owner(invocation=False)), "invocation"
    )
    _rejects(CandidateArtifact, _candidate(owner=_owner("EXPERIMENT")))
    _rejects(CandidateArtifact, _candidate(finalization_purpose="EVIDENCE"))
    _rejects(CandidateArtifact, _candidate(source_role="CORE_EVIDENCE"))
    _rejects(CandidateArtifact, _candidate(source_role="NORMALIZED_RESULT"))
    core = _load_candidate(_core_candidate())
    assert not isinstance(core.adapter_declared_size, int)
    assert not isinstance(core.source_event_id, str)
    for declared, value in (
        ("adapter_declared_size", 12),
        ("adapter_declared_hash", _HASH),
        ("adapter_declared_media_type", "text/plain"),
        ("source_event_id", _EVT),
    ):
        _rejects(CandidateArtifact, _core_candidate(**{declared: value}), "CORE")
    # Row 2: the core-produced normalized RESULT keeps the RUN-with-invocation owner.
    normalized = _load_candidate(
        _core_candidate(
            finalization_purpose="RESULT",
            source_role="NORMALIZED_RESULT",
            artifact_kind="normalized-result",
        )
    )
    assert normalized.source_role is _R.NORMALIZED_RESULT
    _rejects(
        CandidateArtifact,
        _core_candidate(
            finalization_purpose="RESULT",
            source_role="NORMALIZED_RESULT",
            owner=_owner(invocation=False),
        ),
        "invocation",
    )


def test_adapter_cannot_declare_evidence_owner_role_or_path() -> None:
    _rejects(CandidateArtifact, _candidate(finalization_purpose="EVIDENCE"))
    for kind in ("EXPERIMENT", "DATASET", "STRATEGY", "ADAPTER", "SYSTEM"):
        _rejects(CandidateArtifact, _candidate(owner=_owner(kind)))
    for role in EVIDENCE_ROLES:
        _rejects(CandidateArtifact, _candidate(source_role=role.value))
    # Only the core constructs a finalized path (specification 15.5).
    _rejects(
        CandidateArtifact,
        _candidate(finalized_relative_path=finalized_relative_path_for(_HASH)),
        "extra",
    )
    _rejects(CandidateArtifact, _candidate(staging_relative_path="../escape.bin"))
    _rejects(CandidateArtifact, _candidate(staging_relative_path="results\\native.bin"))
    _rejects(CandidateArtifact, _candidate(staging_relative_path="results:ads.bin"))


def test_owner_variants_each_carry_their_evidence_role() -> None:
    accepted = {
        ("CORE_EVIDENCE", "RUN"),
        ("CORE_EVIDENCE", "SYSTEM"),
        ("CORE_EVIDENCE", "ADAPTER"),
        ("ADAPTER_DESCRIPTOR_EVIDENCE", "ADAPTER"),
        ("DATASET_INPUT", "DATASET"),
        ("STRATEGY_INPUT", "STRATEGY"),
        ("EXPERIMENT_INPUT", "EXPERIMENT"),
    }
    seen: set[tuple[str, str]] = set()
    for role, kind in product(
        (member.value for member in EVIDENCE_ROLES), (member.value for member in _K)
    ):
        payload = _core_candidate(source_role=role, owner=_owner(kind))
        try:
            candidate = _load_candidate(payload)
        except ValidationError:
            continue
        assert owner_kind_of(candidate.owner).value == kind
        seen.add((role, kind))
    assert seen == accepted


# --- Core staging paths, manifest association and observations ---------------------


def test_core_staging_path_is_correlation_scoped() -> None:
    for path in (
        f"INVOCATION/{_INV}/stderr.txt",
        f"DIAGNOSTIC/{_DIAG}/report.jsonl",
        "AUDIT/audit_12345678-1234-4234-8234-123456789abc/snapshot.json",
        f"INVOCATION/{_INV}/nested/deeper/file.bin",
    ):
        scoped = _load_candidate(_core_candidate(staging_relative_path=path))
        assert scoped.state is _S.CANDIDATE
    for path in (
        "stderr.txt",
        f"INVOCATION/{_INV}",
        f"INVOCATION/{_RUN}/stderr.txt",
        f"AUDIT/{_INV}/stderr.txt",
        f"OTHER/{_INV}/stderr.txt",
        f"invocation/{_INV}/stderr.txt",
    ):
        _rejects(CandidateArtifact, _core_candidate(staging_relative_path=path), "corr")


def test_source_adapter_manifest_id_is_permitted_only_after_validation_starts() -> None:
    _rejects(CandidateArtifact, _candidate(source_adapter_manifest_id=_AMF), "manifest")
    _rejects(
        CandidateArtifact,
        _core_candidate(state="VALIDATING", source_adapter_manifest_id=_AMF),
        "manifest",
    )
    for state in ("VALIDATING", "FINALIZING"):
        associated = _load_candidate(
            _candidate(state=state, source_adapter_manifest_id=_AMF)
        )
        assert associated.source_adapter_manifest_id == _AMF
    validating = _load_candidate(_candidate(state="VALIDATING"))
    assert not isinstance(validating.source_adapter_manifest_id, str)


def test_validation_observation_rules() -> None:
    _rejects(ValidationObservation, _observation(outcome="FAILED"), "error_code")
    _rejects(ValidationObservation, _observation(stage="HASH"), "HASH")
    hashed = ValidationObservation.model_validate_json(
        json.dumps(
            _observation(stage="HASH", observed_size_bytes=12, observed_sha256=_HASH)
        )
    )
    assert hashed.observed_sha256 == _HASH
    _rejects(ValidationObservation, _observation(stage="MOVE", diagnostic_id=None))
    _rejects(ValidationObservation, _observation(stage="OTHER"))
    _rejects(ValidationObservation, _observation(observed_size_bytes=-1))
    for terminal in ("QUARANTINED", "CORRUPT"):
        _rejects(CandidateArtifact, _candidate(state=terminal), "observation")
        _rejects(
            CandidateArtifact,
            _candidate(state=terminal, validation_observations=[_observation()]),
            "observation",
        )
        failed = _load_candidate(
            _candidate(state=terminal, validation_observations=[_failed_observation()])
        )
        assert failed.state.value == terminal
    assert MAX_VALIDATION_OBSERVATIONS == 64
    too_many = [_observation()] * (MAX_VALIDATION_OBSERVATIONS + 1)
    _rejects(CandidateArtifact, _candidate(validation_observations=too_many))


def test_candidate_bookkeeping_fields() -> None:
    _rejects(CandidateArtifact, _candidate(updated_at_utc=_EARLIER), "updated_at_utc")
    _rejects(CandidateArtifact, _candidate(revision=0))
    _rejects(CandidateArtifact, _candidate(state="FINALIZED"))
    _rejects(CandidateArtifact, _candidate(adapter_declared_size=2**53))
    assert _load_candidate(_candidate(updated_at_utc=_T1, revision=7)).revision == 7


# --- The finalized reference -------------------------------------------------------


def test_artifact_ref_every_field_required_and_finalized() -> None:
    reference = _load_ref(_ref())
    assert reference.state == "FINALIZED"
    for field in _ref():
        _rejects(ArtifactRef, _without(_ref(), field))
    for state in ("CANDIDATE", "VALIDATING", "FINALIZING", "QUARANTINED", "CORRUPT"):
        _rejects(ArtifactRef, _ref(state=state))
    _rejects(ArtifactRef, _candidate(), "extra")
    _rejects(CandidateArtifact, _ref(), "extra")
    _rejects(
        ArtifactRef, _ref(artifact_id=artifact_id_for(_CAND2, _HASH)), "artifact_id"
    )
    _rejects(ArtifactRef, _ref(content_hash=_HASH2), "finalized_relative_path")
    _rejects(ArtifactRef, _ref(finalized_relative_path=f"objects/ab/{_HASH}"))
    _rejects(ArtifactRef, _ref(finalized_relative_path="results/native.bin"))
    _rejects(ArtifactRef, _ref(finalized_at_utc=_EARLIER), "finalized_at_utc")
    _rejects(ArtifactRef, _ref(size_bytes=-1))
    _rejects(ArtifactRef, _ref(size_bytes=2**53))
    _rejects(ArtifactRef, _ref(validation_profile="artifact-validation/v2"))
    _rejects(ArtifactRef, _ref(media_type="not a media type"))


def test_artifact_ref_purpose_rules_follow_the_role_table() -> None:
    evidence = _ref(
        finalization_purpose="EVIDENCE",
        source_role="CORE_EVIDENCE",
        producer_kind="CORE",
        artifact_kind="stderr-capture",
    )
    assert _load_ref(evidence).finalization_purpose is _F.EVIDENCE
    _rejects(ArtifactRef, {**evidence, "producer_kind": "ADAPTER"})
    _rejects(ArtifactRef, {**evidence, "source_role": "ENGINE_NATIVE_RESULT"})
    _rejects(ArtifactRef, _ref(owner=_owner("EXPERIMENT")))
    _rejects(ArtifactRef, _ref(owner=_owner(invocation=False)), "invocation")
    _rejects(ArtifactRef, _ref(source_role="CORE_EVIDENCE"))
    for kind in ("SYSTEM", "ADAPTER"):
        assert _load_ref({**evidence, "owner": _owner(kind)}).owner.owner_kind == kind
    dataset = _load_ref(
        {**evidence, "owner": _owner("DATASET"), "source_role": "DATASET_INPUT"}
    )
    assert dataset.source_role is _R.DATASET_INPUT
    _rejects(ArtifactRef, {**evidence, "owner": _owner("DATASET")})


# --- Unknown fields and implicit None -----------------------------------------------


def test_unknown_fields_and_implicit_none_rejected() -> None:
    _rejects(CandidateArtifact, _candidate(unexpected=1), "extra")
    _rejects(ArtifactRef, _ref(unexpected=1), "extra")
    _rejects(FinalizationResult, _result(unexpected=1), "extra")
    _rejects(CandidateFinalization, {**_mapping(), "unexpected": 1}, "extra")
    for field in (
        "adapter_declared_size",
        "adapter_declared_hash",
        "adapter_declared_media_type",
        "source_event_id",
        "source_adapter_manifest_id",
    ):
        _rejects(CandidateArtifact, _candidate(**{field: None}))
    _rejects(CandidateArtifact, _candidate(state=None))
    _rejects(ArtifactRef, _ref(media_type=None))
    for field in ("run_manifest_id", "run_manifest_hash"):
        _rejects(FinalizationResult, _result(**{field: None}))
    loaded = _load_candidate(_core_candidate())
    assert "null" not in loaded.model_dump_json()
    assert None not in loaded.model_dump(mode="python").values()


# --- The finalization result and its mappings ---------------------------------------


def test_finalization_result_purpose_governed_fields() -> None:
    result = FinalizationResult.model_validate_json(json.dumps(_result()))
    assert result.run_manifest_id == _RMF
    for field in ("run_manifest_id", "run_manifest_hash"):
        _rejects(FinalizationResult, _without(_result(), field), "RESULT")
    evidence = _without(
        _result(finalization_purpose="EVIDENCE", owner=_owner("SYSTEM")),
        "run_manifest_id",
        "run_manifest_hash",
    )
    loaded_evidence = FinalizationResult.model_validate_json(json.dumps(evidence))
    assert loaded_evidence.replayed is False
    _rejects(FinalizationResult, {**evidence, "run_manifest_id": _RMF}, "EVIDENCE")
    _rejects(FinalizationResult, {**evidence, "run_manifest_hash": _HASH2}, "EVIDENCE")
    _rejects(FinalizationResult, _result(owner=_owner("SYSTEM")), "RUN")
    _rejects(FinalizationResult, _result(owner=_owner(invocation=False)), "invocation")
    _rejects(FinalizationResult, _result(journal_state="MOVED"))
    _rejects(FinalizationResult, _result(candidate_to_artifact_refs=[]))
    _rejects(
        FinalizationResult,
        _result(candidate_to_artifact_refs=[_mapping(), _mapping()]),
        "unique",
    )
    two = FinalizationResult.model_validate_json(
        json.dumps(
            _result(candidate_to_artifact_refs=[_mapping(), _mapping(_CAND2, _HASH2)])
        )
    )
    assert len(two.candidate_to_artifact_refs) == 2
    _rejects(
        CandidateFinalization,
        {**_mapping(), "artifact_id": artifact_id_for(_CAND2, _HASH)},
        "artifact_id",
    )
    _rejects(CandidateFinalization, {**_mapping(), "size_bytes": -1})
