"""The purpose-discriminated finalization journal entry and its move records.

Stage 9 plan section 3.1 (rows ``FinalizationJournalEntry``, ``PlannedMove``,
``ObservedMove``), 3.2 (``FinalizationJournalState``) and 4.1's lease renewal,
under specification 23.3.1:1715-1723 and readings 12 and 13. The journal is the
durable bridge between the filesystem and the database: ``PREPARED`` holds only
the fields its purpose allows, ``MOVED`` records the observed finalized hashes
and paths, ``REGISTERED`` closes it and ``ABANDONED`` is the "reconcile or
quarantine" terminal carrying its ``abandon_reason`` code.

Rules that live here:

- **Purpose-governed fields** -- a ``RESULT`` entry carries the run, invocation,
  token hash, both manifest hashes, the finalization deadline and the two
  expected revisions and no correlation; an ``EVIDENCE`` entry carries the typed
  correlation and none of those (its lease has no deadline, reading 13).
- **Recomputed identities** -- ``finalization_id`` is
  ``finalization_id_for(finalization_identity(...))`` over the purpose-specific
  17.2 tuple and ``candidate_set_hash`` recomputes from the sorted candidate ids.
- **Planned and observed moves** -- ``planned_paths`` names exactly the candidate
  ids in sorted order (phase 3 moves in that order); ``observed`` names a subset
  of the planned moves with equal planned facts, is empty at ``PREPARED``, covers
  every planned move with equal observed hash and size at ``MOVED`` and
  ``REGISTERED``, and may hold a partial or mismatched record at ``ABANDONED``
  (the mismatch that abandoned it).
- **Deadline and lease** -- ``lease_expires_at_utc`` never passes
  ``finalization_deadline_utc`` when the latter exists and the deadline never
  precedes ``prepared_at_utc``.
- **Monotonic state order** -- ``FINALIZATION_JOURNAL_TRANSITIONS`` holds the four
  edges; ``assert_journal_transition`` is the pure record-pair predicate. The one
  reflexive write it admits is the lease renewal of a ``PREPARED`` or ``MOVED``
  entry, which advances ``lease_expires_at_utc`` and nothing else; the deadline,
  every identity and every planned fact are immutable and ``observed`` only grows.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.artifacts.models import (
    MAX_CANDIDATE_ARTIFACTS,
    RESULT_ROLES,
    ArtifactFinalizationPurpose,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    FinalizedRelativePath,
    RelativeStagingPath,
    Revision,
    SizeBytes,
    finalized_relative_path_for,
    owner_kind_of,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import (
    ArtifactOwnerRef,
    RunArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.requests import (
    CandidateArtifactIds,
    EvidenceCorrelation,
    PositiveRevision,
    validate_evidence_correlation_kind,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.hashing import (
    candidate_set_hash_for,
    finalization_id_for,
    finalization_identity,
)
from crypto_lab.domain.identifiers import (
    CandidateArtifactId,
    FinalizationId,
    InvocationId,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import TransitionTable
from crypto_lab.domain.time import CalendarValidUtcDateTime


class FinalizationJournalState(StrEnum):
    PREPARED = "PREPARED"
    MOVED = "MOVED"
    REGISTERED = "REGISTERED"
    ABANDONED = "ABANDONED"


_J: Final = FinalizationJournalState
_F: Final = ArtifactFinalizationPurpose

#: 23.3.1:1719-1723: 4 states, 16 ordered pairs, 4 permitted.
FINALIZATION_JOURNAL_TRANSITIONS: Final = TransitionTable(
    FinalizationJournalState,
    frozenset(
        {
            (_J.PREPARED, _J.MOVED),
            (_J.PREPARED, _J.ABANDONED),
            (_J.MOVED, _J.REGISTERED),
            (_J.MOVED, _J.ABANDONED),
        }
    ),
)
_RESULT_ONLY_FIELDS: Final[tuple[str, ...]] = (
    "finalization_deadline_utc",
    "expected_run_revision",
    "expected_invocation_revision",
    "run_id",
    "run_invocation_id",
    "attempt_token_hash",
    "source_adapter_result_manifest_hash",
    "sanitized_adapter_result_manifest_hash",
)
#: Everything but ``state``, ``abandon_reason``, ``observed``,
#: ``lease_expires_at_utc``, ``updated_at_utc`` and ``revision``.
_JOURNAL_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "finalization_purpose",
    "owner",
    "source_role",
    "candidate_artifact_ids",
    "candidate_set_hash",
    "prepared_at_utc",
    *_RESULT_ONLY_FIELDS,
    "correlation",
    "planned_paths",
)
_MOVE_FACTS: Final[tuple[str, ...]] = (
    "staging_relative_path",
    "finalized_relative_path",
    "expected_sha256",
    "expected_size_bytes",
)


def _is_missing(value: object) -> bool:
    return value is MISSING


class PlannedMove(CanonicalModel):
    """One candidate's planned move, fixed in phase 1 (plan 4.3)."""

    candidate_artifact_id: CandidateArtifactId
    staging_relative_path: RelativeStagingPath
    finalized_relative_path: FinalizedRelativePath
    expected_sha256: Sha256
    expected_size_bytes: SizeBytes

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.finalized_relative_path != finalized_relative_path_for(
            self.expected_sha256
        ):
            raise ValueError("finalized_relative_path must address expected_sha256")
        return self


class ObservedMove(PlannedMove):
    """A planned move plus the facts re-observed in place after it (reading 18)."""

    observed_sha256: Sha256
    observed_size_bytes: SizeBytes
    deduplicated: bool

    @property
    def matches_plan(self) -> bool:
        return (
            self.observed_sha256 == self.expected_sha256
            and self.observed_size_bytes == self.expected_size_bytes
        )


def _journal_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"finalization_purpose": {"const": "RESULT"}}},
            "then": {
                "required": list(_RESULT_ONLY_FIELDS),
                "not": {"required": ["correlation"]},
            },
        },
        {
            "if": {"properties": {"finalization_purpose": {"const": "EVIDENCE"}}},
            "then": {
                "required": ["correlation"],
                "not": {
                    "anyOf": [{"required": [name]} for name in _RESULT_ONLY_FIELDS]
                },
            },
        },
        {
            "if": {"properties": {"state": {"const": "ABANDONED"}}},
            "then": {"required": ["abandon_reason"]},
            "else": {"not": {"required": ["abandon_reason"]}},
        },
    ]


class FinalizationJournalEntry(CanonicalModel):
    """23.3.1:1715: the purpose-discriminated bridge for one owner and candidate set."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_journal_schema_extra
    )

    schema_version: Literal["1.0.0"]
    finalization_id: FinalizationId
    finalization_purpose: ArtifactFinalizationPurpose
    owner: ArtifactOwnerRef
    source_role: ArtifactSourceRole
    candidate_artifact_ids: CandidateArtifactIds
    candidate_set_hash: Sha256
    state: FinalizationJournalState
    abandon_reason: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    prepared_at_utc: CalendarValidUtcDateTime
    finalization_deadline_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    lease_expires_at_utc: CalendarValidUtcDateTime
    expected_run_revision: PositiveRevision | MISSING = MISSING  # type: ignore[valid-type]
    expected_invocation_revision: PositiveRevision | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    run_invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    attempt_token_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    source_adapter_result_manifest_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    sanitized_adapter_result_manifest_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    correlation: EvidenceCorrelation | MISSING = MISSING  # type: ignore[valid-type]
    planned_paths: tuple[PlannedMove, ...] = Field(
        min_length=1, max_length=MAX_CANDIDATE_ARTIFACTS
    )
    observed: tuple[ObservedMove, ...] = Field(max_length=MAX_CANDIDATE_ARTIFACTS)
    updated_at_utc: CalendarValidUtcDateTime
    revision: Revision

    @field_validator("candidate_artifact_ids")
    @classmethod
    def validate_candidate_artifact_ids(
        cls, value: tuple[CandidateArtifactId, ...]
    ) -> tuple[CandidateArtifactId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("candidate_artifact_ids must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("candidate_artifact_ids must be sorted")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        self._validate_purpose_fields()
        self._validate_identities()
        self._validate_moves()
        if (self.state is _J.ABANDONED) != (not _is_missing(self.abandon_reason)):
            raise ValueError("abandon_reason is present exactly for an ABANDONED entry")
        deadline = self.finalization_deadline_utc
        if not _is_missing(deadline):
            if deadline < self.prepared_at_utc:
                raise ValueError(
                    "finalization_deadline_utc must not precede prepared_at_utc"
                )
            if self.lease_expires_at_utc > deadline:
                raise ValueError(
                    "lease_expires_at_utc must not pass the finalization deadline"
                )
        if self.updated_at_utc < self.prepared_at_utc:
            raise ValueError("updated_at_utc must not precede prepared_at_utc")
        return self

    def _validate_purpose_fields(self) -> None:
        present = tuple(
            name for name in _RESULT_ONLY_FIELDS if not _is_missing(getattr(self, name))
        )
        if self.finalization_purpose is _F.RESULT:
            if len(present) != len(_RESULT_ONLY_FIELDS) or not _is_missing(
                self.correlation
            ):
                raise ValueError(
                    "a RESULT entry carries the run, invocation, token hash, both "
                    "manifest hashes, the deadline and both expected revisions, and "
                    "no correlation"
                )
            if self.source_role not in RESULT_ROLES:
                raise ValueError("a RESULT entry carries a result role")
            if not isinstance(self.owner, RunArtifactOwner) or _is_missing(
                self.owner.invocation_id
            ):
                raise ValueError(
                    "a RESULT entry requires a RUN owner with invocation_id"
                )
            if self.owner.run_id != self.run_id:
                raise ValueError("owner.run_id must equal run_id")
            if self.owner.invocation_id != self.run_invocation_id:
                raise ValueError("owner.invocation_id must equal run_invocation_id")
            return
        correlation = self.correlation
        if present or not isinstance(correlation, EvidenceCorrelation):
            raise ValueError(
                "an EVIDENCE entry carries a correlation and none of the RESULT fields"
            )
        owner_kind = owner_kind_of(self.owner)
        validate_role_combination(
            _F.EVIDENCE,
            CandidateArtifactProducerKind.CORE,
            self.source_role,
            owner_kind,
        )
        validate_evidence_correlation_kind(
            self.source_role, owner_kind, correlation.kind
        )

    def _validate_identities(self) -> None:
        if self.candidate_set_hash != candidate_set_hash_for(
            self.candidate_artifact_ids
        ):
            raise ValueError(
                "candidate_set_hash must equal "
                "candidate_set_hash_for(candidate_artifact_ids)"
            )
        if self.finalization_id != finalization_id_for(self.identity_hash()):
            raise ValueError(
                "finalization_id must equal "
                "finalization_id_for(finalization_identity(...))"
            )

    def _validate_moves(self) -> None:
        planned_ids = tuple(move.candidate_artifact_id for move in self.planned_paths)
        if planned_ids != self.candidate_artifact_ids:
            raise ValueError(
                "planned_paths must name exactly candidate_artifact_ids in sorted order"
            )
        planned_by_id = {
            move.candidate_artifact_id: move for move in self.planned_paths
        }
        observed_ids = [move.candidate_artifact_id for move in self.observed]
        if len(set(observed_ids)) != len(observed_ids):
            raise ValueError("observed moves must be unique on candidate_artifact_id")
        for move in self.observed:
            planned = planned_by_id.get(move.candidate_artifact_id)
            if planned is None or any(
                getattr(move, fact) != getattr(planned, fact) for fact in _MOVE_FACTS
            ):
                raise ValueError(
                    "every observed move restates one planned move's candidate, paths "
                    "and expected facts"
                )
        if self.state is _J.PREPARED and self.observed:
            raise ValueError("a PREPARED entry has observed no move")
        if self.state in (_J.MOVED, _J.REGISTERED) and (
            set(observed_ids) != set(planned_ids)
            or not all(move.matches_plan for move in self.observed)
        ):
            raise ValueError(
                "a MOVED or REGISTERED entry requires observed moves covering every "
                "planned move with equal observed hash and size"
            )

    def identity_hash(self) -> Sha256:
        """The purpose-specific 17.2 identity ``finalization_id`` derives from."""
        if self.finalization_purpose is _F.RESULT:
            return finalization_identity(
                "RESULT",
                run_id=_string(self.run_id),
                run_invocation_id=_string(self.run_invocation_id),
                attempt_token_hash=_string(self.attempt_token_hash),
                source_adapter_result_manifest_hash=_string(
                    self.source_adapter_result_manifest_hash
                ),
                sanitized_adapter_result_manifest_hash=_string(
                    self.sanitized_adapter_result_manifest_hash
                ),
            )
        correlation = self.correlation
        if not isinstance(correlation, EvidenceCorrelation):
            raise ValueError("an EVIDENCE entry carries a correlation")
        return finalization_identity(
            "EVIDENCE",
            owner_hash=artifact_owner_hash(self.owner),
            correlation_kind=correlation.kind,
            correlation_id=correlation.correlation_id,
            candidate_set_hash=self.candidate_set_hash,
        )


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("a RESULT entry carries every RESULT field")
    return value


class FinalizationJournalRuleViolation(ValueError):
    """A record pair that breaks the journal's monotonic order or immutability."""


def assert_journal_transition(
    stored: FinalizationJournalEntry,
    replacement: FinalizationJournalEntry,
) -> None:
    """Is ``stored -> replacement`` a lawful journal write? Pure over its arguments.

    Checks, in report order: one identity; ``stored`` not terminal; a permitted
    edge of ``FINALIZATION_JOURNAL_TRANSITIONS`` or the reflexive lease renewal
    of a ``PREPARED``/``MOVED`` entry (``lease_expires_at_utc`` strictly later);
    every immutable field unchanged; ``observed`` grown by prefix; revision plus
    one; ``updated_at_utc`` not moved backwards.
    """
    if not isinstance(stored, FinalizationJournalEntry) or not isinstance(
        replacement, FinalizationJournalEntry
    ):
        raise TypeError(
            "stored and replacement must be FinalizationJournalEntry records"
        )
    if replacement.finalization_id != stored.finalization_id:
        raise FinalizationJournalRuleViolation(
            "stored and replacement must share one finalization_id"
        )
    if stored.state in FINALIZATION_JOURNAL_TRANSITIONS.terminal_states:
        raise FinalizationJournalRuleViolation(
            f"a terminal journal entry ({stored.state.value}) accepts no further write"
        )
    if stored.state is replacement.state:
        if replacement.lease_expires_at_utc <= stored.lease_expires_at_utc:
            raise FinalizationJournalRuleViolation(
                "a same-state journal write is a lease renewal and must advance "
                "lease_expires_at_utc"
            )
    elif not FINALIZATION_JOURNAL_TRANSITIONS.is_allowed(
        stored.state, replacement.state
    ):
        raise FinalizationJournalRuleViolation(
            f"{stored.state.value} -> {replacement.state.value} is not a permitted "
            "journal edge"
        )
    for name in _JOURNAL_IMMUTABLE_FIELDS:
        if getattr(replacement, name) != getattr(stored, name):
            raise FinalizationJournalRuleViolation(
                f"{name} is immutable across every journal write"
            )
    if replacement.observed[: len(stored.observed)] != stored.observed:
        raise FinalizationJournalRuleViolation(
            "observed moves accumulate: the stored observed moves stay a prefix"
        )
    if replacement.revision != stored.revision + 1:
        raise FinalizationJournalRuleViolation(
            "an accepted journal write increments revision by exactly one"
        )
    if replacement.updated_at_utc < stored.updated_at_utc:
        raise FinalizationJournalRuleViolation("updated_at_utc never moves backwards")


__all__ = (
    "FINALIZATION_JOURNAL_TRANSITIONS",
    "FinalizationJournalEntry",
    "FinalizationJournalRuleViolation",
    "FinalizationJournalState",
    "ObservedMove",
    "PlannedMove",
    "assert_journal_transition",
)
