"""Stage 9 Task 1: the purpose-discriminated finalization journal entry, its move
records and its monotonic state order (plan 3.1 rows ``FinalizationJournalEntry``,
``PlannedMove``, ``ObservedMove``; readings 12 and 13; 23.3.1:1715-1723)."""

from __future__ import annotations

import json
from datetime import datetime
from itertools import product
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_lab.artifacts.journal import (
    FINALIZATION_JOURNAL_TRANSITIONS,
    FinalizationJournalEntry,
    FinalizationJournalRuleViolation,
    FinalizationJournalState,
    ObservedMove,
    PlannedMove,
    assert_journal_transition,
)
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    finalized_relative_path_for,
)
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER, artifact_owner_hash
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.domain.hashing import (
    candidate_set_hash_for,
    finalization_id_for,
    finalization_identity,
)

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_RUN2 = "run_22345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_INV2 = "inv_22345678-1234-4234-8234-123456789abc"
_DIAG = "diag_12345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_CAND2 = "cand_22345678-1234-4234-8234-123456789abc"
_HASH = "a" * 64
_HASH2 = "b" * 64
_TOKEN_HASH = "c" * 64
_SOURCE_HASH = "d" * 64
_SANITIZED_HASH = "e" * 64
_T0 = "2026-08-10T01:02:03Z"
_T1 = "2026-08-10T01:02:08Z"
_T2 = "2026-08-10T01:02:13Z"
_DEADLINE = "2026-08-10T01:07:03Z"
_PAST_DEADLINE = "2026-08-10T01:07:04Z"
_EARLIER = "2026-08-10T01:02:00Z"
_IDS = (_CAND, _CAND2)
_J = FinalizationJournalState


def _run_owner(*, invocation: bool = True) -> dict[str, Any]:
    owner: dict[str, Any] = {"owner_kind": "RUN", "experiment_id": _EXP, "run_id": _RUN}
    if invocation:
        owner["invocation_id"] = _INV
    return owner


def _system_owner() -> dict[str, Any]:
    return {
        "owner_kind": "SYSTEM",
        "core_component": "artifacts",
        "correlation_id": "s9",
    }


def _adapter_owner() -> dict[str, Any]:
    return {"owner_kind": "ADAPTER", "adapter_name": "a", "adapter_version": "1.0.0"}


def _diagnostic_correlation() -> dict[str, Any]:
    return {"kind": "DIAGNOSTIC", "diagnostic_id": _DIAG}


def _planned(candidate: str, content_hash: str) -> dict[str, Any]:
    return {
        "candidate_artifact_id": candidate,
        "staging_relative_path": f"results/{candidate[-4:]}.bin",
        "finalized_relative_path": finalized_relative_path_for(content_hash),
        "expected_sha256": content_hash,
        "expected_size_bytes": 12,
    }


def _observed(candidate: str, content_hash: str, **overrides: Any) -> dict[str, Any]:
    payload = {
        **_planned(candidate, content_hash),
        "observed_sha256": content_hash,
        "observed_size_bytes": 12,
        "deduplicated": False,
    }
    payload.update(overrides)
    return payload


_PLANNED = [_planned(_CAND, _HASH), _planned(_CAND2, _HASH2)]
_OBSERVED = [_observed(_CAND, _HASH), _observed(_CAND2, _HASH2)]


def _result_identity(**overrides: str) -> str:
    fields = {
        "run_id": _RUN,
        "run_invocation_id": _INV,
        "attempt_token_hash": _TOKEN_HASH,
        "source_adapter_result_manifest_hash": _SOURCE_HASH,
        "sanitized_adapter_result_manifest_hash": _SANITIZED_HASH,
    }
    fields.update(overrides)
    return finalization_identity("RESULT", **fields)


def _retokened_id() -> str:
    return finalization_id_for(_result_identity(attempt_token_hash="f" * 64))


def _result_entry(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_id": finalization_id_for(_result_identity()),
        "finalization_purpose": "RESULT",
        "owner": _run_owner(),
        "source_role": "ENGINE_NATIVE_RESULT",
        "candidate_artifact_ids": list(_IDS),
        "candidate_set_hash": candidate_set_hash_for(_IDS),
        "state": "PREPARED",
        "prepared_at_utc": _T0,
        "finalization_deadline_utc": _DEADLINE,
        "lease_expires_at_utc": _T2,
        "expected_run_revision": 4,
        "expected_invocation_revision": 6,
        "run_id": _RUN,
        "run_invocation_id": _INV,
        "attempt_token_hash": _TOKEN_HASH,
        "source_adapter_result_manifest_hash": _SOURCE_HASH,
        "sanitized_adapter_result_manifest_hash": _SANITIZED_HASH,
        "planned_paths": _PLANNED,
        "observed": [],
        "updated_at_utc": _T0,
        "revision": 1,
    }
    payload.update(overrides)
    return payload


def _evidence_entry(**overrides: Any) -> dict[str, Any]:
    owner = overrides.pop("owner", _system_owner())
    correlation = overrides.pop(
        "correlation", {"kind": "DIAGNOSTIC", "diagnostic_id": _DIAG}
    )
    owner_hash = artifact_owner_hash(
        ARTIFACT_OWNER_ADAPTER.validate_json(json.dumps(owner))
    )
    if isinstance(correlation, dict):
        identity = finalization_identity(
            "EVIDENCE",
            owner_hash=owner_hash,
            correlation_kind=correlation["kind"],
            correlation_id=next(v for k, v in correlation.items() if k != "kind"),
            candidate_set_hash=candidate_set_hash_for(_IDS),
        )
    else:
        identity = _HASH
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_id": finalization_id_for(identity),
        "finalization_purpose": "EVIDENCE",
        "owner": owner,
        "source_role": "CORE_EVIDENCE",
        "candidate_artifact_ids": list(_IDS),
        "candidate_set_hash": candidate_set_hash_for(_IDS),
        "state": "PREPARED",
        "prepared_at_utc": _T0,
        "lease_expires_at_utc": _T2,
        "correlation": correlation,
        "planned_paths": _PLANNED,
        "observed": [],
        "updated_at_utc": _T0,
        "revision": 1,
    }
    payload.update(overrides)
    return payload


def _load(payload: dict[str, Any]) -> FinalizationJournalEntry:
    return FinalizationJournalEntry.model_validate_json(json.dumps(payload))


def _rejects(payload: dict[str, Any], match: str | None = None) -> None:
    with pytest.raises(ValidationError, match=match):
        _load(payload)


def _without(payload: dict[str, Any], *names: str) -> dict[str, Any]:
    trimmed = dict(payload)
    for name in names:
        del trimmed[name]
    return trimmed


_RESULT_ONLY = (
    "finalization_deadline_utc",
    "expected_run_revision",
    "expected_invocation_revision",
    "run_id",
    "run_invocation_id",
    "attempt_token_hash",
    "source_adapter_result_manifest_hash",
    "sanitized_adapter_result_manifest_hash",
)


def test_purpose_governed_fields() -> None:
    result = _load(_result_entry())
    assert not isinstance(result.correlation, EvidenceCorrelation)
    assert isinstance(result.finalization_deadline_utc, datetime)
    for field in _RESULT_ONLY:
        _rejects(_without(_result_entry(), field), "RESULT")
    _rejects(_result_entry(correlation=_diagnostic_correlation()), "RESULT")
    evidence = _load(_evidence_entry())
    assert not isinstance(evidence.run_id, str)
    assert not isinstance(evidence.finalization_deadline_utc, datetime)
    _rejects(_without(_evidence_entry(), "correlation"), "EVIDENCE")
    for field in _RESULT_ONLY:
        value = _result_entry()[field]
        _rejects(_evidence_entry(**{field: value}), "EVIDENCE")
    # RESULT owner facts equal the top-level facts and carry the invocation.
    _rejects(_result_entry(owner=_run_owner(invocation=False)), "invocation")
    _rejects(_result_entry(owner={**_run_owner(), "run_id": _RUN2}), "run_id")
    _rejects(
        _result_entry(owner={**_run_owner(), "invocation_id": _INV2}),
        "invocation_id must equal run_invocation_id",
    )
    _rejects(_result_entry(owner=_system_owner()))
    _rejects(_result_entry(source_role="CORE_EVIDENCE"))
    _rejects(_evidence_entry(source_role="ENGINE_NATIVE_RESULT"))
    _rejects(_evidence_entry(owner=_system_owner(), source_role="DATASET_INPUT"))
    _rejects(
        _evidence_entry(
            source_role="ADAPTER_DESCRIPTOR_EVIDENCE",
            owner=_adapter_owner(),
            correlation=_diagnostic_correlation(),
        ),
        "correlation",
    )
    for field in _result_entry():
        _rejects(_without(_result_entry(), field))
    _rejects(_result_entry(unexpected=1), "extra")
    for field in _RESULT_ONLY:
        _rejects(_result_entry(**{field: None}))
    _rejects(_evidence_entry(correlation=None))


def test_identities_and_candidate_facts_are_recomputed() -> None:
    foreign = finalization_id_for(_HASH2)
    _rejects(_result_entry(finalization_id=foreign), "finalization_id")
    _rejects(_result_entry(attempt_token_hash="f" * 64), "finalization_id")
    recomputed = _result_entry(
        attempt_token_hash="f" * 64,
        finalization_id=_retokened_id(),
    )
    assert _load(recomputed).attempt_token_hash == "f" * 64
    _rejects(_evidence_entry(finalization_id=foreign), "finalization_id")
    single_hash = candidate_set_hash_for((_CAND,))
    _rejects(_result_entry(candidate_set_hash=single_hash), "candidate_set")
    _rejects(_result_entry(candidate_artifact_ids=[_CAND2, _CAND]), "sorted")
    _rejects(_result_entry(candidate_artifact_ids=[_CAND, _CAND]), "unique")
    _rejects(_result_entry(candidate_artifact_ids=[]))
    _rejects(_result_entry(planned_paths=[_planned(_CAND, _HASH)]), "planned")
    _rejects(_result_entry(planned_paths=list(reversed(_PLANNED))), "planned")
    _rejects(_result_entry(planned_paths=[]), "planned")
    _rejects(_result_entry(revision=0))
    _rejects(_result_entry(updated_at_utc=_EARLIER), "updated_at_utc")
    mismatched = {
        **_planned(_CAND, _HASH),
        "finalized_relative_path": f"objects/aa/{_HASH2}",
    }
    with pytest.raises(ValidationError, match="finalized_relative_path"):
        PlannedMove.model_validate_json(json.dumps(mismatched))
    # A well-formed finalized path addressing another hash is the move's own rule,
    # not the path grammar's shard rule.
    other_target = {
        **_planned(_CAND, _HASH),
        "finalized_relative_path": finalized_relative_path_for(_HASH2),
    }
    with pytest.raises(ValidationError, match="must address expected_sha256"):
        PlannedMove.model_validate_json(json.dumps(other_target))
    with pytest.raises(ValidationError):
        PlannedMove.model_validate_json(
            json.dumps({**_planned(_CAND, _HASH), "staging_relative_path": "../x"})
        )
    with pytest.raises(ValidationError):
        ObservedMove.model_validate_json(
            json.dumps(_observed(_CAND, _HASH, observed_size_bytes=-1))
        )


def _entry_in(state: _J, **overrides: Any) -> dict[str, Any]:
    payload = _result_entry(state=state.value)
    if state in (_J.MOVED, _J.REGISTERED):
        payload["observed"] = _OBSERVED
    if state is _J.ABANDONED:
        payload["abandon_reason"] = "ARTIFACT.FINALIZATION_TIMED_OUT"
    payload.update(overrides)
    return payload


def _moved(**overrides: Any) -> FinalizationJournalEntry:
    """A MOVED successor of the default PREPARED entry, revision 2."""
    payload = _entry_in(_J.MOVED, revision=2, updated_at_utc=_T1)
    payload.update(overrides)
    return _load(payload)


def test_state_order_and_abandon_reason() -> None:
    edges = {
        (_J.PREPARED, _J.MOVED),
        (_J.PREPARED, _J.ABANDONED),
        (_J.MOVED, _J.REGISTERED),
        (_J.MOVED, _J.ABANDONED),
    }
    assert FINALIZATION_JOURNAL_TRANSITIONS.transitions == frozenset(edges)
    assert FINALIZATION_JOURNAL_TRANSITIONS.terminal_states == {
        _J.REGISTERED,
        _J.ABANDONED,
    }
    assert tuple(member.value for member in _J) == (
        "PREPARED",
        "MOVED",
        "REGISTERED",
        "ABANDONED",
    )
    # ABANDONED <=> abandon_reason (reading 12).
    _rejects(_without(_entry_in(_J.ABANDONED), "abandon_reason"), "abandon_reason")
    for state in (_J.PREPARED, _J.MOVED, _J.REGISTERED):
        _rejects(
            _entry_in(state, abandon_reason="ARTIFACT.MOVE_FAILED"), "abandon_reason"
        )
    _rejects(_entry_in(_J.ABANDONED, abandon_reason="lowercase"))
    # MOVED/REGISTERED cover every planned move with equal observed facts; PREPARED
    # has observed nothing; ABANDONED may hold a partial or mismatched record.
    first = _observed(_CAND, _HASH)
    wrong_hash = _observed(_CAND2, _HASH2, observed_sha256="f" * 64)
    wrong_size = _observed(_CAND2, _HASH2, observed_size_bytes=13)
    for state in (_J.MOVED, _J.REGISTERED):
        _rejects(_entry_in(state, observed=[]), "observed")
        _rejects(_entry_in(state, observed=[first]), "observed")
        _rejects(_entry_in(state, observed=[first, wrong_hash]), "observed")
        _rejects(_entry_in(state, observed=[first, wrong_size]), "observed")
    _rejects(_entry_in(_J.PREPARED, observed=_OBSERVED), "observed")
    mismatch = _observed(_CAND, _HASH, observed_sha256="f" * 64)
    abandoned = _load(_entry_in(_J.ABANDONED, observed=[mismatch]))
    assert abandoned.observed[0].observed_sha256 == "f" * 64
    _rejects(_entry_in(_J.ABANDONED, observed=[first, first]))
    unplanned = _observed("cand_32345678-1234-4234-8234-123456789abc", _HASH)
    _rejects(_entry_in(_J.ABANDONED, observed=[unplanned]), "planned")
    resized = _observed(_CAND, _HASH, expected_size_bytes=99)
    _rejects(_entry_in(_J.ABANDONED, observed=[resized]), "planned")

    allowed = 0
    forbidden = 0
    for current, target in product(_J, _J):
        stored = _load(_entry_in(current))
        # The observed moves accumulate, so an ABANDONED successor of a MOVED entry
        # keeps the moves the entry had observed.
        carries = target in (_J.MOVED, _J.REGISTERED) or (
            target is _J.ABANDONED and current in (_J.MOVED, _J.REGISTERED)
        )
        carried = _OBSERVED if carries else []
        replacement = _load(
            _entry_in(target, revision=2, updated_at_utc=_T1, observed=carried)
        )
        if (current, target) in edges:
            assert_journal_transition(stored, replacement)
            allowed += 1
        elif current is target and current in (_J.PREPARED, _J.MOVED):
            # A same-state write is the lease renewal of plan 4.1 and nothing else.
            renewed = _load(
                _entry_in(
                    target,
                    revision=2,
                    updated_at_utc=_T1,
                    observed=carried,
                    lease_expires_at_utc=_DEADLINE,
                )
            )
            assert_journal_transition(stored, renewed)
            with pytest.raises(FinalizationJournalRuleViolation, match="lease"):
                assert_journal_transition(stored, replacement)
        else:
            with pytest.raises(FinalizationJournalRuleViolation):
                assert_journal_transition(stored, replacement)
            forbidden += 1
    assert allowed == 4
    assert forbidden == 16 - 4 - 2
    stored = _load(_entry_in(_J.PREPARED))
    assert_journal_transition(stored, _moved())
    with pytest.raises(FinalizationJournalRuleViolation, match="revision"):
        assert_journal_transition(stored, _moved(revision=3))
    later = _load(_entry_in(_J.PREPARED, updated_at_utc=_T1))
    with pytest.raises(FinalizationJournalRuleViolation, match="updated_at_utc"):
        assert_journal_transition(later, _moved(updated_at_utc=_T0))
    with pytest.raises(FinalizationJournalRuleViolation, match="finalization_id"):
        assert_journal_transition(
            stored,
            _moved(attempt_token_hash="f" * 64, finalization_id=_retokened_id()),
        )
    with pytest.raises(FinalizationJournalRuleViolation, match="immutable"):
        assert_journal_transition(stored, _moved(expected_run_revision=5))
    with pytest.raises(FinalizationJournalRuleViolation, match="immutable"):
        assert_journal_transition(stored, _moved(prepared_at_utc=_EARLIER))
    # Observed moves accumulate in order: a REGISTERED successor that restates the
    # same moves in another order is refused even though it covers every plan.
    moved = _moved()
    reordered = _load(
        _entry_in(
            _J.REGISTERED,
            revision=3,
            updated_at_utc=_T2,
            observed=list(reversed(_OBSERVED)),
        )
    )
    with pytest.raises(FinalizationJournalRuleViolation, match="accumulate"):
        assert_journal_transition(moved, reordered)
    with pytest.raises(TypeError, match="FinalizationJournalEntry"):
        assert_journal_transition(stored, "replacement")  # type: ignore[arg-type]


def test_lease_never_past_deadline() -> None:
    at_deadline = _load(_result_entry(lease_expires_at_utc=_DEADLINE))
    assert at_deadline.lease_expires_at_utc == at_deadline.finalization_deadline_utc
    _rejects(_result_entry(lease_expires_at_utc=_PAST_DEADLINE), "deadline")
    _rejects(_result_entry(finalization_deadline_utc=_EARLIER), "deadline")
    # EVIDENCE has no deadline (reading 13): the lease is bounded by nothing here.
    evidence = _load(_evidence_entry(lease_expires_at_utc=_PAST_DEADLINE))
    assert not isinstance(evidence.finalization_deadline_utc, datetime)
    stored = _load(_entry_in(_J.PREPARED))
    # Renewal never extends the deadline and never moves the lease backwards.
    with pytest.raises(FinalizationJournalRuleViolation, match="immutable"):
        assert_journal_transition(
            stored,
            _load(
                _entry_in(
                    _J.PREPARED,
                    revision=2,
                    updated_at_utc=_T1,
                    finalization_deadline_utc=_PAST_DEADLINE,
                    lease_expires_at_utc=_PAST_DEADLINE,
                )
            ),
        )
    with pytest.raises(FinalizationJournalRuleViolation, match="lease"):
        assert_journal_transition(
            stored,
            _load(
                _entry_in(
                    _J.PREPARED,
                    revision=2,
                    updated_at_utc=_T1,
                    lease_expires_at_utc=_T1,
                )
            ),
        )
    # A terminal entry accepts no further write.
    registered = _load(_entry_in(_J.REGISTERED))
    with pytest.raises(FinalizationJournalRuleViolation, match="terminal"):
        assert_journal_transition(
            registered, _load(_entry_in(_J.REGISTERED, revision=2, updated_at_utc=_T1))
        )


def test_identity_hash_refuses_an_entry_lacking_its_purpose_fields() -> None:
    """``identity_hash`` is public; on a record built without validation it refuses
    to hash a purpose whose 17.2 fields are absent rather than hash a stand-in."""
    evidence = FinalizationJournalEntry.model_construct(
        finalization_purpose=ArtifactFinalizationPurpose.EVIDENCE
    )
    with pytest.raises(ValueError, match="carries a correlation"):
        evidence.identity_hash()
    result = FinalizationJournalEntry.model_construct(
        finalization_purpose=ArtifactFinalizationPurpose.RESULT
    )
    with pytest.raises(ValueError, match="every RESULT field"):
        result.identity_hash()
    assert _load(_result_entry()).identity_hash() == _result_identity()
