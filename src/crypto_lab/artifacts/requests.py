"""The two typed finalization requests and the typed evidence correlation.

Stage 9 plan section 3.1 (rows ``ResultFinalizationRequest``,
``EvidenceFinalizationRequest``, ``EvidenceCorrelation``) under specification
17.2: ``RESULT`` finalization is idempotent on ``(RESULT, run_id,
run_invocation_id, attempt_token_hash, source_adapter_result_manifest_hash,
sanitized_adapter_result_manifest_hash)`` and ``EVIDENCE`` separately on
``(EVIDENCE, owner_hash, correlation_kind, correlation_id, candidate_set_hash)``;
each request carries its ``idempotency_key`` and the key must recompute through
``finalization_identity`` (reading 17), so a RESULT key never satisfies the
EVIDENCE identity and vice versa. Every purpose-foreign field is unknown to the
other request (``extra="forbid"``), and the correlation is a typed record --
``kind`` plus exactly the matching identifier -- never a bare string.

The correlation column of plan 3.1.1 is enforced here because the request is
the first record that carries both the role and the correlation: the
descriptor evidence of an ``ADAPTER`` owner and the ``CORE_EVIDENCE`` an
``ADAPTER`` owner may carry (the describe stderr, 23.3.1:1703) name an
``INVOCATION``; the three input snapshots name an ``AUDIT`` or a ``DIAGNOSTIC``;
``CORE_EVIDENCE`` of a ``RUN`` or ``SYSTEM`` owner names any of the three. That
the named invocation is a ``DESCRIBE`` of that adapter is a stored fact the
finalizer checks in phase 0 (plan 4.3).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.artifacts.models import (
    MAX_CANDIDATE_ARTIFACTS,
    ArtifactFinalizationPurpose,
    ArtifactOwnerKind,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    owner_kind_of,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import (
    ArtifactOwnerRef,
    RunArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import candidate_set_hash_for, finalization_identity
from crypto_lab.domain.identifiers import (
    AuditEventId,
    CandidateArtifactId,
    DiagnosticId,
    ExperimentId,
    InvocationId,
    RunId,
    Sha256,
)

type EvidenceCorrelationKind = Literal["INVOCATION", "DIAGNOSTIC", "AUDIT"]
type CandidateArtifactIds = Annotated[
    tuple[CandidateArtifactId, ...],
    Field(
        min_length=1,
        max_length=MAX_CANDIDATE_ARTIFACTS,
        json_schema_extra={"uniqueItems": True},
    ),
]
type PositiveRevision = Annotated[int, Field(strict=True, ge=1)]
type FinalizationTimeoutSeconds = Annotated[int, Field(strict=True, ge=1, le=3600)]

_R: Final = ArtifactSourceRole
_ALL_KINDS: Final[frozenset[str]] = frozenset({"INVOCATION", "DIAGNOSTIC", "AUDIT"})
_SNAPSHOT_KINDS: Final[frozenset[str]] = frozenset({"AUDIT", "DIAGNOSTIC"})
_INVOCATION_ONLY: Final[frozenset[str]] = frozenset({"INVOCATION"})
#: Plan 3.1.1, the correlation column, keyed by evidence role.
PERMITTED_CORRELATION_KINDS: Final[Mapping[ArtifactSourceRole, frozenset[str]]] = {
    _R.CORE_EVIDENCE: _ALL_KINDS,
    _R.ADAPTER_DESCRIPTOR_EVIDENCE: _INVOCATION_ONLY,
    _R.DATASET_INPUT: _SNAPSHOT_KINDS,
    _R.STRATEGY_INPUT: _SNAPSHOT_KINDS,
    _R.EXPERIMENT_INPUT: _SNAPSHOT_KINDS,
}
_CORRELATION_FIELDS: Final[dict[str, str]] = {
    "INVOCATION": "invocation_id",
    "DIAGNOSTIC": "diagnostic_id",
    "AUDIT": "audit_event_id",
}


def _is_missing(value: object) -> bool:
    return value is MISSING


def _sorted_unique(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError("candidate_artifact_ids must be unique")
    if value != tuple(sorted(value)):
        raise ValueError("candidate_artifact_ids must be sorted")
    return value


def _correlation_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"kind": {"const": kind}}},
            "then": {
                "required": [field],
                "not": {
                    "anyOf": [
                        {"required": [other]}
                        for other_kind, other in _CORRELATION_FIELDS.items()
                        if other_kind != kind
                    ]
                },
            },
        }
        for kind, field in _CORRELATION_FIELDS.items()
    ]


class EvidenceCorrelation(CanonicalModel):
    """The typed evidence correlation of 17.2: ``kind`` plus exactly its identifier."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_correlation_schema_extra
    )

    kind: EvidenceCorrelationKind
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]
    audit_event_id: AuditEventId | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_exactly_one_identifier(self) -> Self:
        present = tuple(
            field
            for field in _CORRELATION_FIELDS.values()
            if not _is_missing(getattr(self, field))
        )
        if present != (_CORRELATION_FIELDS[self.kind],):
            raise ValueError(
                "an evidence correlation carries exactly the identifier matching "
                "its kind"
            )
        return self

    @property
    def correlation_id(self) -> str:
        """The one identifier the ``kind`` names."""
        value = getattr(self, _CORRELATION_FIELDS[self.kind])
        if not isinstance(value, str):
            raise ValueError("an evidence correlation names exactly one identifier")
        return value


class ResultFinalizationRequest(CanonicalModel):
    """The ``RESULT`` branch request (plan 3.1): the ``RUN``-with-invocation owner
    whose identities equal the top-level identities, the 17.2 tuple, the two
    success statuses, the sorted candidate set with its hash, the bounded
    finalization timeout and the recomputed idempotency key."""

    schema_version: Literal["1.0.0"]
    finalization_purpose: Literal["RESULT"]
    owner: RunArtifactOwner
    experiment_id: ExperimentId
    run_id: RunId
    run_invocation_id: InvocationId
    expected_run_revision: PositiveRevision
    expected_invocation_revision: PositiveRevision
    attempt_token_hash: Sha256
    source_adapter_result_manifest_hash: Sha256
    sanitized_adapter_result_manifest_hash: Sha256
    semantic_status: Literal["SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"]
    candidate_artifact_ids: CandidateArtifactIds
    candidate_set_hash: Sha256
    finalization_timeout_seconds: FinalizationTimeoutSeconds
    idempotency_key: Sha256

    @field_validator("candidate_artifact_ids")
    @classmethod
    def validate_candidate_artifact_ids(
        cls, value: tuple[CandidateArtifactId, ...]
    ) -> tuple[CandidateArtifactId, ...]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_identities(self) -> Self:
        if self.owner.experiment_id != self.experiment_id:
            raise ValueError("owner.experiment_id must equal experiment_id")
        if self.owner.run_id != self.run_id:
            raise ValueError("owner.run_id must equal run_id")
        if self.owner.invocation_id != self.run_invocation_id:
            raise ValueError("owner.invocation_id must equal run_invocation_id")
        if self.candidate_set_hash != candidate_set_hash_for(
            self.candidate_artifact_ids
        ):
            raise ValueError(
                "candidate_set_hash must equal "
                "candidate_set_hash_for(candidate_artifact_ids)"
            )
        expected = finalization_identity(
            "RESULT",
            run_id=self.run_id,
            run_invocation_id=self.run_invocation_id,
            attempt_token_hash=self.attempt_token_hash,
            source_adapter_result_manifest_hash=(
                self.source_adapter_result_manifest_hash
            ),
            sanitized_adapter_result_manifest_hash=(
                self.sanitized_adapter_result_manifest_hash
            ),
        )
        if self.idempotency_key != expected:
            raise ValueError(
                "idempotency_key must equal finalization_identity over the RESULT tuple"
            )
        return self


def validate_evidence_correlation_kind(
    source_role: ArtifactSourceRole,
    owner_kind: ArtifactOwnerKind,
    correlation_kind: str,
) -> None:
    """Plan 3.1.1's correlation column for one evidence role and owner."""
    permitted = PERMITTED_CORRELATION_KINDS.get(source_role, frozenset())
    if owner_kind is ArtifactOwnerKind.ADAPTER:
        permitted = permitted & _INVOCATION_ONLY
    if correlation_kind not in permitted:
        raise ValueError(
            f"correlation kind {correlation_kind} is not permitted for "
            f"{source_role.value} evidence of a {owner_kind.value} owner"
        )


class EvidenceFinalizationRequest(CanonicalModel):
    """The ``EVIDENCE`` branch request (plan 3.1): any owner variant the role
    table admits for the role, the sorted candidate set with its hash, the typed
    correlation permitted for the role and owner, and the recomputed key over
    ``(EVIDENCE, owner_hash, correlation.kind, correlation.correlation_id,
    candidate_set_hash)``."""

    schema_version: Literal["1.0.0"]
    finalization_purpose: Literal["EVIDENCE"]
    owner: ArtifactOwnerRef
    source_role: ArtifactSourceRole
    candidate_artifact_ids: CandidateArtifactIds
    candidate_set_hash: Sha256
    correlation: EvidenceCorrelation
    idempotency_key: Sha256

    @field_validator("candidate_artifact_ids")
    @classmethod
    def validate_candidate_artifact_ids(
        cls, value: tuple[CandidateArtifactId, ...]
    ) -> tuple[CandidateArtifactId, ...]:
        return _sorted_unique(value)

    @model_validator(mode="after")
    def validate_identities(self) -> Self:
        owner_kind = owner_kind_of(self.owner)
        validate_role_combination(
            ArtifactFinalizationPurpose.EVIDENCE,
            CandidateArtifactProducerKind.CORE,
            self.source_role,
            owner_kind,
        )
        validate_evidence_correlation_kind(
            self.source_role, owner_kind, self.correlation.kind
        )
        if self.candidate_set_hash != candidate_set_hash_for(
            self.candidate_artifact_ids
        ):
            raise ValueError(
                "candidate_set_hash must equal "
                "candidate_set_hash_for(candidate_artifact_ids)"
            )
        expected = finalization_identity(
            "EVIDENCE",
            owner_hash=artifact_owner_hash(self.owner),
            correlation_kind=self.correlation.kind,
            correlation_id=self.correlation.correlation_id,
            candidate_set_hash=self.candidate_set_hash,
        )
        if self.idempotency_key != expected:
            raise ValueError(
                "idempotency_key must equal finalization_identity over the EVIDENCE "
                "tuple"
            )
        return self


__all__ = (
    "PERMITTED_CORRELATION_KINDS",
    "CandidateArtifactIds",
    "EvidenceCorrelation",
    "EvidenceCorrelationKind",
    "EvidenceFinalizationRequest",
    "FinalizationTimeoutSeconds",
    "PositiveRevision",
    "ResultFinalizationRequest",
    "validate_evidence_correlation_kind",
)
