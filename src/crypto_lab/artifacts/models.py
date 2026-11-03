"""Candidate and finalized artifact records, their enums and the role table.

Stage 9 plan sections 3.1, 3.1.1 and 3.2 under specification sections 11.3,
11.5, 15.5, 19.2 and 24.3. Placement follows plan 2.3: the artifact records live
in ``crypto_lab.artifacts`` and import ``domain`` alone (specification 27.1), so
the two grammars shared with ``adapters`` -- the relative candidate-path grammar
of ``adapters/paths.py`` and the media-type grammar of ``adapters/events.py`` --
are restated here verbatim and pinned equal by test rather than imported.

Five kinds of rule live here.

1. **Vocabulary** -- the five enums of plan 3.2 and the role partition
   ``RESULT_ROLES``/``EVIDENCE_ROLES``; ``owner_kind_of`` projects the existing
   owner discriminators of ``artifacts/ownership.py`` onto ``ArtifactOwnerKind``.
2. **The role table** -- ``PERMITTED_ROLE_TUPLES`` is plan 3.1.1 as data: the nine
   ``(purpose, producer, role, owner_kind)`` tuples of its seven rows, and
   ``validate_role_combination`` is the single refusal every record and request
   applies. An ``ADAPTER`` owner with ``CORE_EVIDENCE`` is admitted here; the
   ``DESCRIBE`` correlation it requires is a finalizer fact (plan 4.3 phase 0).
3. **Record shape** -- ``CandidateArtifact`` (producer-governed declared fields,
   the correlation-scoped core staging path, the manifest-association rule, the
   terminal-observation rule) and ``ArtifactRef`` (every field required, the
   content-addressed finalized path, the derived ``artifact_id``); the two shapes
   are disjoint so neither payload inhabits the other type.
4. **Transition** -- ``CANDIDATE_ARTIFACT_TRANSITIONS`` holds the six edges plan
   4.3 drives (phase 0 ``CANDIDATE -> QUARANTINED``; phase 1 ``CANDIDATE ->
   VALIDATING`` and ``VALIDATING -> QUARANTINED | CORRUPT``; phase 2
   ``VALIDATING -> FINALIZING``; phase 3 ``FINALIZING -> QUARANTINED``), and
   ``assert_candidate_transition`` is the pure record-pair predicate over it. The
   reflexive ``FINALIZING`` pair is lawful only beside a registered
   ``CandidateFinalization`` mapping for that candidate (specification 19.2: the
   consumed candidate stays an immutable historical ``FINALIZING`` record linked
   to the new reference); every other reflexive pair is refused.
5. **The finalization outcome** -- ``FinalizationResult`` with its purpose-governed
   run-manifest fields and the ``CandidateFinalization`` mappings whose
   ``artifact_id`` recomputes from the candidate and content hash (reading 17).

Declared readings applied here: ``source_adapter_manifest_id`` is a permission
(present only for an ``ADAPTER`` candidate at ``VALIDATING`` or later), not a
requirement, because a candidate quarantined before its manifest is validated
has none; a ``CORE`` candidate's staging path carries its correlation as its
first two segments (``<correlation_kind>/<correlation_id>/...``, plan 4.6) and
that is checked lexically against the typed identifier prefixes.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.artifacts.ownership import ArtifactOwnerRef, RunArtifactOwner
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.hashing import artifact_id_for
from crypto_lab.domain.identifiers import (
    AdapterManifestId,
    ArtifactId,
    CandidateArtifactId,
    DiagnosticId,
    EventId,
    FinalizationId,
    NormalizedIdentifier,
    RunManifestId,
    Sha256,
    exact_string_schema,
    validate_prefixed_uuid4,
)
from crypto_lab.domain.lifecycle import TransitionTable
from crypto_lab.domain.time import CalendarValidUtcDateTime

# --- Vocabulary (plan 3.2) -----------------------------------------------------------


class CandidateArtifactState(StrEnum):
    CANDIDATE = "CANDIDATE"
    VALIDATING = "VALIDATING"
    FINALIZING = "FINALIZING"
    QUARANTINED = "QUARANTINED"
    CORRUPT = "CORRUPT"


class CandidateArtifactProducerKind(StrEnum):
    ADAPTER = "ADAPTER"
    CORE = "CORE"


class ArtifactFinalizationPurpose(StrEnum):
    RESULT = "RESULT"
    EVIDENCE = "EVIDENCE"


class ArtifactSourceRole(StrEnum):
    ENGINE_NATIVE_RESULT = "ENGINE_NATIVE_RESULT"
    NORMALIZED_RESULT = "NORMALIZED_RESULT"
    CORE_EVIDENCE = "CORE_EVIDENCE"
    ADAPTER_DESCRIPTOR_EVIDENCE = "ADAPTER_DESCRIPTOR_EVIDENCE"
    DATASET_INPUT = "DATASET_INPUT"
    STRATEGY_INPUT = "STRATEGY_INPUT"
    EXPERIMENT_INPUT = "EXPERIMENT_INPUT"


class ArtifactOwnerKind(StrEnum):
    RUN = "RUN"
    EXPERIMENT = "EXPERIMENT"
    DATASET = "DATASET"
    STRATEGY = "STRATEGY"
    ADAPTER = "ADAPTER"
    SYSTEM = "SYSTEM"


_S: Final = CandidateArtifactState
_P: Final = CandidateArtifactProducerKind
_F: Final = ArtifactFinalizationPurpose
_R: Final = ArtifactSourceRole
_K: Final = ArtifactOwnerKind

RESULT_ROLES: Final[frozenset[ArtifactSourceRole]] = frozenset(
    {_R.ENGINE_NATIVE_RESULT, _R.NORMALIZED_RESULT}
)
EVIDENCE_ROLES: Final[frozenset[ArtifactSourceRole]] = frozenset(_R) - RESULT_ROLES

#: Plan 3.1.1, the single authority, as data: the nine tuples of its seven rows
#: (row 3 contributes the three ``CORE_EVIDENCE`` owners, every other row one).
PERMITTED_ROLE_TUPLES: Final[
    frozenset[
        tuple[
            ArtifactFinalizationPurpose,
            CandidateArtifactProducerKind,
            ArtifactSourceRole,
            ArtifactOwnerKind,
        ]
    ]
] = frozenset(
    {
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
)


def owner_kind_of(owner: ArtifactOwnerRef) -> ArtifactOwnerKind:
    """Project an owner variant's literal discriminator onto ``ArtifactOwnerKind``."""
    return ArtifactOwnerKind(owner.owner_kind)


def validate_role_combination(
    purpose: ArtifactFinalizationPurpose,
    producer: CandidateArtifactProducerKind,
    role: ArtifactSourceRole,
    owner_kind: ArtifactOwnerKind,
) -> None:
    """Refuse every ``(purpose, producer, role, owner)`` tuple outside plan 3.1.1."""
    if (purpose, producer, role, owner_kind) not in PERMITTED_ROLE_TUPLES:
        raise ValueError(
            f"({purpose.value}, {producer.value}, {role.value}, {owner_kind.value}) "
            "is not a permitted purpose, producer, role and owner combination"
        )


# --- Grammars restated from ``adapters`` (plan 2.6: no ``adapters`` import) ----------

#: ``adapters/limits.py`` bounds and the ``adapters/paths.py`` grammar, restated.
MAX_RELATIVE_PATH_CHARACTERS: Final = 512
MAX_PATH_SEGMENTS: Final = 32
MAX_SEGMENT_CHARACTERS: Final = 255
_SEGMENT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESERVED_STEMS: Final[frozenset[str]] = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)
_RESERVED_STEM_LOOKAHEAD: Final = (
    r"(?!(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\.|/|(?![\s\S])))"
)
_PUBLISHED_SEGMENT: Final = (
    _RESERVED_STEM_LOOKAHEAD
    + r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,"
    + str(MAX_SEGMENT_CHARACTERS - 2)
    + r"}[A-Za-z0-9_-])?"
)
#: Byte-equal to ``adapters.paths.RELATIVE_CANDIDATE_PATH_PATTERN`` (pinned by test).
RELATIVE_STAGING_PATH_PATTERN: Final = (
    "^"
    + _PUBLISHED_SEGMENT
    + "(?:/"
    + _PUBLISHED_SEGMENT
    + "){0,"
    + str(MAX_PATH_SEGMENTS - 1)
    + "}$"
)
#: Byte-equal to ``adapters.events._MEDIA_TYPE_PATTERN`` (pinned by test).
MEDIA_TYPE_PATTERN: Final = (
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
MAX_MEDIA_TYPE_CHARACTERS: Final = 255
#: ``adapters.limits.MAX_CANDIDATE_ARTIFACTS`` and ``MAX_DECLARED_SIZE_BYTES``.
MAX_CANDIDATE_ARTIFACTS: Final = 256
MAX_SIZE_BYTES: Final = 2**53 - 1
#: Plan 3.1: the observation ceiling of one candidate.
MAX_VALIDATION_OBSERVATIONS: Final = 64
ARTIFACT_VALIDATION_PROFILE: Final = "artifact-validation/v1"
_FINALIZED_PATH_PATTERN: Final = r"^objects/[0-9a-f]{2}/[0-9a-f]{64}$"
_SHA256_HEX: Final = frozenset("0123456789abcdef")
#: The typed correlation prefixes a CORE staging path begins with (plan 4.6).
_CORRELATION_PREFIXES: Final[dict[str, str]] = {
    "INVOCATION": "inv_",
    "DIAGNOSTIC": "diag_",
    "AUDIT": "audit_",
}


def validate_relative_staging_path(value: str) -> str:
    """The ``adapters/paths.py`` section 3.3 grammar, restated rule for rule."""
    if type(value) is not str:
        raise TypeError("staging path must be a built-in string")
    if not 1 <= len(value) <= MAX_RELATIVE_PATH_CHARACTERS:
        raise ValueError(
            f"staging path length must be 1 through {MAX_RELATIVE_PATH_CHARACTERS}"
        )
    segments = value.split("/")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise ValueError(f"staging path has more than {MAX_PATH_SEGMENTS} segments")
    for segment in segments:
        if not segment:
            raise ValueError("staging path segment must not be empty")
        if segment in {".", ".."}:
            raise ValueError("staging path segment must not be '.' or '..'")
        if len(segment) > MAX_SEGMENT_CHARACTERS:
            raise ValueError(
                f"staging path segment exceeds {MAX_SEGMENT_CHARACTERS} characters"
            )
        if _SEGMENT.fullmatch(segment) is None:
            raise ValueError("staging path segment contains a forbidden character")
        if segment.endswith("."):
            raise ValueError("staging path segment must not end in '.'")
        if segment.partition(".")[0].upper() in _RESERVED_STEMS:
            raise ValueError("staging path segment uses a reserved Windows device name")
    return value


def finalized_relative_path_for(content_hash: str) -> str:
    """The content-addressed finalized path ``objects/<hh>/<sha256>`` (plan 6.2)."""
    if type(content_hash) is not str:
        raise TypeError("content hash must be a built-in string")
    if len(content_hash) != 64 or not set(content_hash) <= _SHA256_HEX:
        raise ValueError("content hash must be 64 lowercase hex digits")
    return f"objects/{content_hash[:2]}/{content_hash}"


def validate_finalized_relative_path(value: str) -> str:
    """Only the core constructs this shape; the shard equals the hash prefix."""
    if re.fullmatch(_FINALIZED_PATH_PATTERN, value) is None:
        raise ValueError("finalized path must be objects/<hh>/<sha256>")
    if value != finalized_relative_path_for(value.rsplit("/", 1)[-1]):
        raise ValueError("finalized path shard must equal the hash prefix")
    return value


type RelativeStagingPath = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=MAX_RELATIVE_PATH_CHARACTERS,
    ),
    AfterValidator(validate_relative_staging_path),
    WithJsonSchema(
        exact_string_schema(
            RELATIVE_STAGING_PATH_PATTERN,
            min_length=1,
            max_length=MAX_RELATIVE_PATH_CHARACTERS,
        )
    ),
]
type FinalizedRelativePath = Annotated[
    str,
    StringConstraints(strict=True, pattern=_FINALIZED_PATH_PATTERN),
    AfterValidator(validate_finalized_relative_path),
    WithJsonSchema(exact_string_schema(_FINALIZED_PATH_PATTERN)),
]
type MediaType = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=MAX_MEDIA_TYPE_CHARACTERS,
        pattern=MEDIA_TYPE_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            MEDIA_TYPE_PATTERN, min_length=3, max_length=MAX_MEDIA_TYPE_CHARACTERS
        )
    ),
]
type SizeBytes = Annotated[int, Field(strict=True, ge=0, le=MAX_SIZE_BYTES)]
type Revision = Annotated[int, Field(strict=True, ge=1)]
type ValidationProfile = Literal["artifact-validation/v1"]


def _is_missing(value: object) -> bool:
    return value is MISSING


def _hash_segment(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _require_run_owner_with_invocation(owner: ArtifactOwnerRef, subject: str) -> None:
    if not isinstance(owner, RunArtifactOwner) or _is_missing(owner.invocation_id):
        raise ValueError(f"{subject} requires a RUN owner with invocation_id")


# --- Validation observations (plan 3.1, nested) ---------------------------------------

type ValidationStage = Literal[
    "PATH", "SIZE", "MEDIA", "SCHEMA", "REDACTION", "HASH", "SEMANTIC", "MOVE"
]
type ValidationOutcome = Literal["PASSED", "FAILED"]


class ValidationObservation(CanonicalModel):
    """One validation step's outcome; ``FAILED`` names its code and a passed
    ``HASH`` step carries the independently observed size and digest."""

    observed_at_utc: CalendarValidUtcDateTime
    stage: ValidationStage
    outcome: ValidationOutcome
    observed_size_bytes: SizeBytes | MISSING = MISSING  # type: ignore[valid-type]
    observed_sha256: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    error_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_outcome_fields(self) -> Self:
        if self.outcome == "FAILED" and _is_missing(self.error_code):
            raise ValueError("a FAILED observation requires error_code")
        if (
            self.stage == "HASH"
            and self.outcome == "PASSED"
            and (
                _is_missing(self.observed_size_bytes)
                or _is_missing(self.observed_sha256)
            )
        ):
            raise ValueError(
                "a passed HASH observation requires observed_size_bytes and "
                "observed_sha256"
            )
        return self


# --- The candidate (plan 3.1) ---------------------------------------------------------

_DECLARED_FIELDS: Final[tuple[str, ...]] = (
    "adapter_declared_size",
    "adapter_declared_hash",
    "adapter_declared_media_type",
)


def _candidate_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"producer_kind": {"const": "ADAPTER"}}},
            "then": {"required": list(_DECLARED_FIELDS)},
        },
        {
            "if": {"properties": {"producer_kind": {"const": "CORE"}}},
            "then": {
                "not": {"anyOf": [{"required": [name]} for name in _DECLARED_FIELDS]}
            },
        },
    ]


class CandidateArtifact(CanonicalModel):
    """Specification 11.3: the core-owned lifecycle record for bytes in staging.

    The shape rules of plan 3.1: the role table; an ``ADAPTER`` producer is a
    ``RUN``-owned ``RESULT`` candidate with its invocation and all three declared
    fields; a ``CORE`` producer carries no declared field and no source event and
    stages under ``<correlation_kind>/<correlation_id>/``; the adapter manifest
    association is permitted only once validation has started; a terminal
    candidate names the observation that failed it; bookkeeping is monotonic.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_candidate_schema_extra
    )

    schema_version: Literal["1.0.0"]
    candidate_artifact_id: CandidateArtifactId
    owner: ArtifactOwnerRef
    finalization_purpose: ArtifactFinalizationPurpose
    source_role: ArtifactSourceRole
    producer_kind: CandidateArtifactProducerKind
    artifact_kind: NormalizedIdentifier
    staging_relative_path: RelativeStagingPath
    state: CandidateArtifactState
    adapter_declared_size: SizeBytes | MISSING = MISSING  # type: ignore[valid-type]
    adapter_declared_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    adapter_declared_media_type: MediaType | MISSING = MISSING  # type: ignore[valid-type]
    validation_observations: tuple[ValidationObservation, ...] = Field(
        max_length=MAX_VALIDATION_OBSERVATIONS
    )
    source_event_id: EventId | MISSING = MISSING  # type: ignore[valid-type]
    source_adapter_manifest_id: AdapterManifestId | MISSING = MISSING  # type: ignore[valid-type]
    created_at_utc: CalendarValidUtcDateTime
    updated_at_utc: CalendarValidUtcDateTime
    revision: Revision

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        validate_role_combination(
            self.finalization_purpose,
            self.producer_kind,
            self.source_role,
            owner_kind_of(self.owner),
        )
        if self.finalization_purpose is _F.RESULT:
            _require_run_owner_with_invocation(self.owner, "a RESULT candidate")
        declared_present = tuple(
            name for name in _DECLARED_FIELDS if not _is_missing(getattr(self, name))
        )
        if self.producer_kind is _P.ADAPTER:
            if len(declared_present) != len(_DECLARED_FIELDS):
                raise ValueError(
                    "an ADAPTER producer requires adapter_declared_size, "
                    "adapter_declared_hash and adapter_declared_media_type"
                )
        else:
            if declared_present or not _is_missing(self.source_event_id):
                raise ValueError(
                    "a CORE producer carries no adapter-declared field and no "
                    "source_event_id"
                )
            _require_correlation_scoped_path(self.staging_relative_path)
        if not _is_missing(self.source_adapter_manifest_id) and (
            self.producer_kind is not _P.ADAPTER or self.state is _S.CANDIDATE
        ):
            raise ValueError(
                "source_adapter_manifest_id is permitted only for an ADAPTER candidate "
                "at VALIDATING or later"
            )
        if self.state in (_S.QUARANTINED, _S.CORRUPT) and not any(
            not _is_missing(observation.error_code)
            for observation in self.validation_observations
        ):
            raise ValueError(
                "a QUARANTINED or CORRUPT candidate requires an observation with "
                "error_code"
            )
        if self.updated_at_utc < self.created_at_utc:
            raise ValueError("updated_at_utc must not precede created_at_utc")
        return self


def _require_correlation_scoped_path(path: str) -> None:
    segments = path.split("/")
    if len(segments) < 3:
        raise ValueError(
            "a CORE staging path begins with <correlation_kind>/<correlation_id>/"
        )
    prefix = _CORRELATION_PREFIXES.get(segments[0])
    if prefix is None:
        raise ValueError(
            "a CORE staging path's first segment is the correlation kind "
            "INVOCATION, DIAGNOSTIC or AUDIT"
        )
    try:
        validate_prefixed_uuid4(segments[1], prefix)
    except ValueError as error:
        raise ValueError(
            "a CORE staging path's second segment is the typed correlation identifier"
        ) from error


# --- The finalized reference (plan 3.1) -----------------------------------------------


def _ref_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"finalization_purpose": {"const": "EVIDENCE"}}},
            "then": {"properties": {"producer_kind": {"const": "CORE"}}},
        }
    ]


class ArtifactRef(CanonicalModel):
    """Specification 11.3: the authoritative finalized identity and provenance.

    Every field is required; ``state`` is the literal ``FINALIZED``; the finalized
    path is the content-addressed ``objects/<hh>/<content_hash>``; ``artifact_id``
    recomputes from the source candidate and the content hash (reading 17); the
    role table and the RESULT invocation rule hold exactly as for the candidate.
    A candidate payload fails here on its unknown ``state`` and
    ``staging_relative_path``.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(json_schema_extra=_ref_schema_extra)

    schema_version: Literal["1.0.0"]
    artifact_id: ArtifactId
    owner: ArtifactOwnerRef
    finalization_purpose: ArtifactFinalizationPurpose
    artifact_kind: NormalizedIdentifier
    finalized_relative_path: FinalizedRelativePath
    content_hash: Sha256
    size_bytes: SizeBytes
    media_type: MediaType
    source_role: ArtifactSourceRole
    source_candidate_artifact_id: CandidateArtifactId
    producer_kind: CandidateArtifactProducerKind
    validation_profile: ValidationProfile
    created_at_utc: CalendarValidUtcDateTime
    finalized_at_utc: CalendarValidUtcDateTime
    state: Literal["FINALIZED"]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        validate_role_combination(
            self.finalization_purpose,
            self.producer_kind,
            self.source_role,
            owner_kind_of(self.owner),
        )
        if self.finalization_purpose is _F.RESULT:
            _require_run_owner_with_invocation(self.owner, "a RESULT reference")
        if _hash_segment(self.finalized_relative_path) != self.content_hash:
            raise ValueError("finalized_relative_path must address content_hash")
        if self.artifact_id != artifact_id_for(
            self.source_candidate_artifact_id, self.content_hash
        ):
            raise ValueError(
                "artifact_id must equal artifact_id_for(source_candidate_artifact_id, "
                "content_hash)"
            )
        if self.finalized_at_utc < self.created_at_utc:
            raise ValueError("finalized_at_utc must not precede created_at_utc")
        return self


# --- The finalization outcome (plan 3.1) ----------------------------------------------


class CandidateFinalization(CanonicalModel):
    """One candidate-to-reference mapping of a registered finalization."""

    candidate_artifact_id: CandidateArtifactId
    artifact_id: ArtifactId
    content_hash: Sha256
    size_bytes: SizeBytes
    deduplicated: bool

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.artifact_id != artifact_id_for(
            self.candidate_artifact_id, self.content_hash
        ):
            raise ValueError(
                "artifact_id must equal artifact_id_for(candidate_artifact_id, "
                "content_hash)"
            )
        return self


_RUN_MANIFEST_FIELDS: Final[tuple[str, ...]] = ("run_manifest_id", "run_manifest_hash")


def _result_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {"properties": {"finalization_purpose": {"const": "RESULT"}}},
            "then": {"required": list(_RUN_MANIFEST_FIELDS)},
        },
        {
            "if": {"properties": {"finalization_purpose": {"const": "EVIDENCE"}}},
            "then": {
                "not": {
                    "anyOf": [{"required": [name]} for name in _RUN_MANIFEST_FIELDS]
                }
            },
        },
    ]


class FinalizationResult(CanonicalModel):
    """The ``REGISTERED`` outcome ``finalize`` returns, replayed or fresh (plan 3.1,
    29.6): a ``RESULT`` carries both run-manifest facts and an ``EVIDENCE`` neither."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_result_schema_extra
    )

    schema_version: Literal["1.0.0"]
    finalization_id: FinalizationId
    finalization_purpose: ArtifactFinalizationPurpose
    owner: ArtifactOwnerRef
    journal_state: Literal["REGISTERED"]
    candidate_to_artifact_refs: tuple[CandidateFinalization, ...] = Field(
        min_length=1, max_length=MAX_CANDIDATE_ARTIFACTS
    )
    run_manifest_id: RunManifestId | MISSING = MISSING  # type: ignore[valid-type]
    run_manifest_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    registered_at_utc: CalendarValidUtcDateTime
    replayed: bool

    @field_validator("candidate_to_artifact_refs")
    @classmethod
    def validate_mappings_unique(
        cls, value: tuple[CandidateFinalization, ...]
    ) -> tuple[CandidateFinalization, ...]:
        candidates = {mapping.candidate_artifact_id for mapping in value}
        artifacts = {mapping.artifact_id for mapping in value}
        if len(candidates) != len(value) or len(artifacts) != len(value):
            raise ValueError(
                "candidate_to_artifact_refs must be unique on candidate_artifact_id "
                "and artifact_id"
            )
        return value

    @model_validator(mode="after")
    def validate_purpose_fields(self) -> Self:
        present = tuple(
            name
            for name in _RUN_MANIFEST_FIELDS
            if not _is_missing(getattr(self, name))
        )
        if self.finalization_purpose is _F.RESULT:
            _require_run_owner_with_invocation(self.owner, "a RESULT finalization")
            if len(present) != len(_RUN_MANIFEST_FIELDS):
                raise ValueError(
                    "a RESULT finalization carries run_manifest_id and "
                    "run_manifest_hash"
                )
        elif present:
            raise ValueError("an EVIDENCE finalization carries no run manifest fact")
        return self


# --- Transitions (plan 3.1 "immutable fields across assert_candidate_transition") -----

#: Plan 4.3 phases 0 through 3: 5 states, 25 ordered pairs, 6 permitted.
CANDIDATE_ARTIFACT_TRANSITIONS: Final = TransitionTable(
    CandidateArtifactState,
    frozenset(
        {
            (_S.CANDIDATE, _S.VALIDATING),
            (_S.CANDIDATE, _S.QUARANTINED),
            (_S.VALIDATING, _S.FINALIZING),
            (_S.VALIDATING, _S.QUARANTINED),
            (_S.VALIDATING, _S.CORRUPT),
            (_S.FINALIZING, _S.QUARANTINED),
        }
    ),
)
#: Plan 3.1: identity, owner, purpose, role, producer, kind, path, the declared
#: fields and ``created_at_utc`` never change across a transition.
_CANDIDATE_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "candidate_artifact_id",
    "owner",
    "finalization_purpose",
    "source_role",
    "producer_kind",
    "artifact_kind",
    "staging_relative_path",
    *_DECLARED_FIELDS,
    "created_at_utc",
)


class CandidateArtifactRuleViolation(ValueError):
    """A record pair that breaks a candidate lifecycle rule."""


def assert_candidate_transition(
    stored: CandidateArtifact,
    replacement: CandidateArtifact,
    *,
    registered_mapping: CandidateFinalization | MISSING = MISSING,  # type: ignore[valid-type]
) -> None:
    """Is ``stored -> replacement`` a lawful candidate write? Pure over its arguments.

    Checks, in report order: the records are ``CandidateArtifact`` instances and a
    supplied ``registered_mapping`` is a ``CandidateFinalization`` (``TypeError``
    otherwise); one identity; ``stored`` not terminal; a permitted edge of
    ``CANDIDATE_ARTIFACT_TRANSITIONS``, or the reflexive ``FINALIZING`` pair
    beside ``registered_mapping`` naming this candidate; the immutable fields
    unchanged; observations accumulated (the stored tuple is a prefix of the
    replacement's); revision plus one; ``updated_at_utc`` not moved backwards.
    """
    if not isinstance(stored, CandidateArtifact) or not isinstance(
        replacement, CandidateArtifact
    ):
        raise TypeError("stored and replacement must be CandidateArtifact records")
    if not _is_missing(registered_mapping) and not isinstance(
        registered_mapping, CandidateFinalization
    ):
        raise TypeError(
            "registered_mapping must be a CandidateFinalization record when supplied"
        )
    if replacement.candidate_artifact_id != stored.candidate_artifact_id:
        raise CandidateArtifactRuleViolation(
            "candidate_artifact_id is immutable: stored and replacement must share one"
        )
    if stored.state in CANDIDATE_ARTIFACT_TRANSITIONS.terminal_states:
        raise CandidateArtifactRuleViolation(
            f"a terminal candidate ({stored.state.value}) accepts no further write"
        )
    if stored.state is replacement.state:
        if stored.state is not _S.FINALIZING or _is_missing(registered_mapping):
            raise CandidateArtifactRuleViolation(
                f"{stored.state.value} -> {replacement.state.value} is not a candidate "
                "edge; only a FINALIZING record linked to a registered mapping is "
                "restated"
            )
        if (
            isinstance(registered_mapping, CandidateFinalization)
            and registered_mapping.candidate_artifact_id != stored.candidate_artifact_id
        ):
            raise CandidateArtifactRuleViolation(
                "the registered mapping must name the restated FINALIZING candidate"
            )
    else:
        if not _is_missing(registered_mapping):
            raise CandidateArtifactRuleViolation(
                "a registered mapping accompanies only the reflexive FINALIZING write"
            )
        if not CANDIDATE_ARTIFACT_TRANSITIONS.is_allowed(
            stored.state, replacement.state
        ):
            raise CandidateArtifactRuleViolation(
                f"{stored.state.value} -> {replacement.state.value} is not a permitted "
                "candidate edge"
            )
    for name in _CANDIDATE_IMMUTABLE_FIELDS:
        if getattr(replacement, name) != getattr(stored, name):
            raise CandidateArtifactRuleViolation(
                f"{name} is immutable across every candidate transition"
            )
    observed = len(stored.validation_observations)
    if replacement.validation_observations[:observed] != stored.validation_observations:
        raise CandidateArtifactRuleViolation(
            "validation observations accumulate: the stored observations stay a prefix"
        )
    if replacement.revision != stored.revision + 1:
        raise CandidateArtifactRuleViolation(
            "an accepted candidate write increments revision by exactly one"
        )
    if replacement.updated_at_utc < stored.updated_at_utc:
        raise CandidateArtifactRuleViolation("updated_at_utc never moves backwards")


__all__ = (
    "ARTIFACT_VALIDATION_PROFILE",
    "CANDIDATE_ARTIFACT_TRANSITIONS",
    "EVIDENCE_ROLES",
    "MAX_CANDIDATE_ARTIFACTS",
    "MAX_MEDIA_TYPE_CHARACTERS",
    "MAX_PATH_SEGMENTS",
    "MAX_RELATIVE_PATH_CHARACTERS",
    "MAX_SEGMENT_CHARACTERS",
    "MAX_SIZE_BYTES",
    "MAX_VALIDATION_OBSERVATIONS",
    "MEDIA_TYPE_PATTERN",
    "PERMITTED_ROLE_TUPLES",
    "RELATIVE_STAGING_PATH_PATTERN",
    "RESULT_ROLES",
    "ArtifactFinalizationPurpose",
    "ArtifactOwnerKind",
    "ArtifactRef",
    "ArtifactSourceRole",
    "CandidateArtifact",
    "CandidateArtifactProducerKind",
    "CandidateArtifactRuleViolation",
    "CandidateArtifactState",
    "CandidateFinalization",
    "FinalizationResult",
    "FinalizedRelativePath",
    "MediaType",
    "RelativeStagingPath",
    "Revision",
    "SizeBytes",
    "ValidationObservation",
    "ValidationProfile",
    "assert_candidate_transition",
    "finalized_relative_path_for",
    "owner_kind_of",
    "validate_finalized_relative_path",
    "validate_relative_staging_path",
    "validate_role_combination",
)
