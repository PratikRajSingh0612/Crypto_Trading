"""The phase-1 candidate checks: size, media, schema, redaction and hash.

Stage 9 plan 4.3 phase 1 and 6.4 under specification 14.7, 19.2 step 2, 19.3:1417
and 24.3 (readings 18 and 19). ``validate_candidate`` runs, in the order of the
``ValidationStage`` literal: ``PATH`` (the confinement rechecked and its identity
compared), ``SIZE`` (the observed size against the candidate ceiling, against the
adapter's declaration and, for a JSON kind, against the parse ceiling -- bounded
before anything is parsed), ``MEDIA`` (the closed admitted set), ``SCHEMA`` (a
JSON kind read -- exactly its observed size, through the store's handle bridge
``read_confined``, the ``fstat`` identity of the one open handle compared with the
confined identity before and after the read -- and decoded as strict UTF-8 into
one well-formed document with no repeated key, no non-standard constant and no
lone surrogate in any key or value at any depth -- and then discarded: the
document is bytes to this layer, nothing in it is read or acted on, 24.3:1775;
only the digest of the bytes decoded is kept, for ``HASH`` to bind), ``REDACTION``
(the raw attempt token for either purpose whenever its material is available, a
token-shaped run for unqualified text ``EVIDENCE``, so a digest-looking
placeholder is never mistaken for absence, and the field-level rule over a
qualified canonical record's uncontrolled strings) and ``HASH`` (the streamed
digest and scan through the store's handle
bridge ``scan_confined`` -- plan 4.1 and reading 18: the store, the one ``os``
importer, opens the candidate once, compares the ``fstat`` identity of that handle
with the confined identity before and after the ``ContentHasher`` port streams it
together with the ``AttemptTokenMaterial | MISSING`` it was given, so a substitute
swapped in around the open or a file that changed while hashing is refused by the
handle itself; the ``lstat`` identity is rechecked by path after the handle
closes, the digest of the bytes decoded at ``SCHEMA`` must equal the streamed
digest -- the schema verdict holds for no other bytes -- and the adapter's
declared hash is compared). Each step leaves a ``ValidationObservation``.

Declared readings: the observations accompany both outcomes (``CandidateValidation``
carries them beside the ``Result``) because a ``Failure`` cannot carry them and the
finalizer reads the failed observation's code together with its stage -- a proven
mismatch at ``SIZE`` or ``HASH`` (``ARTIFACT.VALIDATION_FAILED``: a size or a hash
differing from the declaration, a file changed while hashing) is ``CORRUPT``, a
refusal at any other stage is ``QUARANTINED``, and a storage failure is neither;
a ``CORE`` candidate's media type is supplied by its producer through
``media_type`` because the record carries no declaration, while an ``ADAPTER``
candidate's is its declaration and a supplied value is refused; an ``OSError``
while the candidate is read for the schema check or the hash proves nothing about
its content, so it is ``ARTIFACT.MOVE_FAILED`` at that stage -- reading 26's
storage-failure posture (``PERSISTENCE``, not retriable), the failed observation
still recorded and the message naming neither path nor bytes -- and never a
corruption classification; an identity that differs at the ``SCHEMA`` handle is
the bridge's ``ARTIFACT.VALIDATION_FAILED`` recorded at ``SCHEMA``, the posture of
the same finding at ``PATH``.

The canonical evidence ruling of 2026-11-09 (``docs/decisions/2026-11-09-stage9-
canonical-evidence-validation-clarification.md``). Plan 4.6 producers write
canonical JSON and JSON Lines whose identifiers and digests are themselves 32+
character url-safe runs, so the whole-content token-shape scan refused every one
of them. The validation therefore accepts an optional ``CanonicalEvidenceQualifier``
(plan 4.1 port, answered by the producer-owning composition): a ``CORE``
``EVIDENCE`` candidate of a canonical medium (one JSON document, JSON Lines, or a
``text/plain`` stderr capture that is one well-formed document) at or below the
parse ceiling is read once through the handle bridge, its records are checked
strict document by strict document (JSON Lines: a final newline, no empty record,
every line one strict document -- the ruling validates every record) and offered
to the qualifier. A qualified candidate skips the whole-content shape scan; its
uncontrolled strings -- what the qualifier could not bind to a closed grammar --
are held to the same shape rule field by field; an unqualified candidate keeps
the whole-content protection; content the qualifier establishes as the model but
disagreeing with the authoritative facts is ``ARTIFACT.VALIDATION_FAILED`` at
``SCHEMA`` (a quarantine), and facts it could not read are the storage posture.
Independently of qualification, the exact raw token is scanned for whenever the
material is available for either purpose -- ``AttemptTokenMaterial`` of the
owner's run, never of another -- over the streamed bytes and over every string of
a document already decoded (so alternate JSON escaping hides nothing); a candidate
scanned without material is reported as such (``exact_token_scanned``) and never
as a successful exact scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from pydantic import InstanceOf, TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    artifact_failure,
)
from crypto_lab.artifacts.hashing import TOKEN_SHAPE_PATTERN, ContentHasher
from crypto_lab.artifacts.models import (
    MAX_SIZE_BYTES,
    ArtifactFinalizationPurpose,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    MediaType,
    ValidationObservation,
    ValidationStage,
    finalized_relative_path_for,
    owner_kind_of,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.artifacts.paths import ConfinedPath, FileIdentity, recheck_confined_path
from crypto_lab.artifacts.ports import (
    CanonicalEvidenceQualifier,
    CanonicalQualification,
)
from crypto_lab.artifacts.store import read_confined, scan_confined
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import artifact_id_for, sha256_bytes
from crypto_lab.domain.identifiers import ExperimentId, InvocationId, RunId
from crypto_lab.domain.results import Failure, Result, Success

#: Plan 6.4 size ceilings: candidates up to the exact JSON number space, JSON kinds
#: parsed only at or below 16 MiB, stderr evidence 50 MiB, manifests 16 MiB.
MAX_CANDIDATE_BYTES: Final = MAX_SIZE_BYTES
MAX_JSON_PARSE_BYTES: Final = 16 * 2**20
MAX_MANIFEST_BYTES: Final = 16 * 2**20
MAX_STDERR_EVIDENCE_BYTES: Final = 50 * 2**20
#: The closed media set (plan Task 4 ``test_media_type_closed_set``): the two
#: adapter declarations of the fake adapters, the text kinds core evidence takes
#: and the one binary kind.
ADMITTED_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/json",
        "application/x-ndjson",
        "text/plain",
        "text/csv",
        "application/octet-stream",
    }
)
TEXT_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {"application/json", "application/x-ndjson", "text/plain", "text/csv"}
)
JSON_MEDIA_TYPES: Final[frozenset[str]] = frozenset({"application/json"})
NDJSON_MEDIA_TYPE: Final = "application/x-ndjson"
#: The media of the plan 4.6 producers whose content the canonical evidence
#: ruling of 2026-11-09 lets a qualifier establish: one JSON document, JSON
#: Lines, or the stderr kind's structured fallback record inside ``text/plain``.
CANONICAL_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {"application/json", NDJSON_MEDIA_TYPE, "text/plain"}
)
#: The audit redaction's token shape as the hasher restates it (plan 2.6), for
#: the field-level rule over a qualified record's uncontrolled strings.
_TOKEN_SHAPE: Final = re.compile(TOKEN_SHAPE_PATTERN)
_MEDIA_TYPE_ADAPTER: TypeAdapter[str] = TypeAdapter(MediaType)
_P: Final = ArtifactFinalizationPurpose
_K: Final = CandidateArtifactProducerKind


@dataclass(frozen=True, slots=True)
class ValidationCeilings:
    """The per-candidate byte ceilings the caller supplies (plan 6.4)."""

    max_bytes: int = MAX_CANDIDATE_BYTES
    max_parse_bytes: int = MAX_JSON_PARSE_BYTES

    def __post_init__(self) -> None:
        if type(self.max_bytes) is not int or type(self.max_parse_bytes) is not int:
            raise TypeError("ceilings must be built-in integers")
        if self.max_bytes < 1 or self.max_parse_bytes < 1:
            raise ValueError("ceilings must be positive")
        if self.max_parse_bytes > self.max_bytes:
            raise ValueError("the parse ceiling must not exceed the candidate ceiling")


DEFAULT_CEILINGS: Final = ValidationCeilings()


@dataclass(frozen=True, slots=True)
class ValidatedCandidate:
    """The core-observed facts of a validated candidate (19.2 step 4's inputs)."""

    candidate_artifact_id: str
    artifact_id: str
    content_hash: str
    size_bytes: int
    media_type: str
    finalized_relative_path: str
    identity: FileIdentity
    observations: tuple[ValidationObservation, ...]
    #: The ruling of 2026-11-09: whether the exact raw token was scanned for
    #: (its material was available) and whether the content was qualified
    #: canonical; a token-free validation is never reported as an exact scan.
    exact_token_scanned: bool
    canonical: bool


@dataclass(frozen=True, slots=True)
class CandidateValidation:
    """The observations of every step taken, beside the ``Result``."""

    observations: tuple[ValidationObservation, ...]
    result: Result[ValidatedCandidate]


def _object_without_repeated_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("JSON object repeats a key")
        document[key] = value
    return document


def _reject_constant(name: str) -> object:
    raise ValueError(f"JSON constant {name} is not permitted")


def _reject_lone_surrogates(value: object) -> None:
    """Walk the decoded document: every string -- a value or an object key, at
    any depth -- must encode as UTF-8, which a lone surrogate cannot."""
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, list):
        for item in value:
            _reject_lone_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_lone_surrogates(key)
            _reject_lone_surrogates(item)


class _NotWellFormed(ValueError):
    """A strict-document refusal; its text is the message the observation records."""


def _decode_strict(data: bytes) -> object:
    """Decode bytes already read as one strict document -- UTF-8, no repeated
    key, no non-standard constant, no lone surrogate at any depth -- and return
    it. The document is inert to this layer (24.3:1775): it is inspected only
    for the raw token and offered, as bytes, to the canonical qualifier."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _NotWellFormed("JSON candidate is not valid UTF-8") from None
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_without_repeated_keys,
            parse_constant=_reject_constant,
        )
        _reject_lone_surrogates(document)
    except (ValueError, RecursionError):
        raise _NotWellFormed("JSON candidate is not a well-formed document") from None
    return document


def _split_records(data: bytes) -> tuple[tuple[bytes, ...], tuple[object, ...]]:
    """JSON Lines under the ruling: at least one record, every record one strict
    document on its own line, the last line terminated, no empty record. The
    records are returned as the bytes offered to the qualifier beside their
    decoded twins for the raw-token inspection."""
    if not data:
        raise _NotWellFormed("JSON Lines candidate carries no record")
    if not data.endswith(b"\n"):
        raise _NotWellFormed("JSON Lines candidate does not end with a newline")
    records: list[bytes] = []
    documents: list[object] = []
    for index, line in enumerate(data[:-1].split(b"\n"), start=1):
        if not line:
            raise _NotWellFormed(f"JSON Lines record {index} is an empty record")
        try:
            documents.append(_decode_strict(line))
        except _NotWellFormed:
            raise _NotWellFormed(
                f"JSON Lines record {index} is not a well-formed document"
            ) from None
        records.append(line)
    return tuple(records), tuple(documents)


def _contains_text(value: object, needle: str) -> bool:
    """Whether ``needle`` occurs in any string of a decoded document -- a value
    or an object key, at any depth (the ruling's decoded-string inspection)."""
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(_contains_text(item, needle) for item in value)
    if isinstance(value, dict):
        return any(
            needle in key or _contains_text(item, needle) for key, item in value.items()
        )
    return False


def _check_token_contract(
    candidate: CandidateArtifact,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
) -> None:
    """A ``RESULT`` candidate requires its own run's material; an ``EVIDENCE``
    candidate admits its own run's material when the caller has it (the ruling of
    2026-11-09) and takes none for an owner without a run; the material is handed
    on to the hasher port as given (plan 4.1) -- no token bytes are derived here."""
    if not isinstance(token, AttemptTokenMaterial):
        if candidate.finalization_purpose is _P.RESULT:
            raise ValueError("a RESULT candidate requires the attempt token material")
        return
    owner = candidate.owner
    if not isinstance(owner, RunArtifactOwner):
        raise ValueError(
            f"an EVIDENCE candidate of a {owner_kind_of(owner).value} owner takes no "
            "attempt token"
        )
    if owner.run_id != token.run_id:
        raise ValueError("the attempt token belongs to another run")


def _expected_media_type(
    candidate: CandidateArtifact,
    media_type: str | MISSING,  # type: ignore[valid-type]
) -> str:
    if candidate.producer_kind is _K.ADAPTER:
        if isinstance(media_type, str):
            raise ValueError(
                "an ADAPTER candidate declares its media type; "
                "media_type must be absent"
            )
        return cast("str", candidate.adapter_declared_media_type)
    if not isinstance(media_type, str):
        raise ValueError("media_type is required for a CORE candidate")
    try:
        return _MEDIA_TYPE_ADAPTER.validate_python(media_type)
    except ValidationError as error:
        raise ValueError("media_type is not a media type") from error


def validate_candidate(
    candidate: CandidateArtifact,
    confined: ConfinedPath,
    *,
    hasher: ContentHasher,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    ceilings: ValidationCeilings,
    now_utc: datetime,
    media_type: str | MISSING = MISSING,  # type: ignore[valid-type]
    canonical: CanonicalEvidenceQualifier | MISSING = MISSING,  # type: ignore[valid-type]
) -> CandidateValidation:
    """Plan 4.3 phase 1 over one confined candidate; see the module docstring."""
    if not isinstance(candidate, CandidateArtifact):
        raise TypeError("candidate must be a CandidateArtifact")
    if not isinstance(confined, ConfinedPath):
        raise TypeError("confined must be a ConfinedPath")
    if not isinstance(hasher, ContentHasher):
        raise TypeError("hasher must implement ContentHasher")
    if not isinstance(ceilings, ValidationCeilings):
        raise TypeError("ceilings must be a ValidationCeilings")
    if canonical is not MISSING and not isinstance(
        canonical, CanonicalEvidenceQualifier
    ):
        raise TypeError("canonical must implement CanonicalEvidenceQualifier")
    if confined.relative != candidate.staging_relative_path:
        raise ValueError("the confined path is not the candidate's staging path")
    _check_token_contract(candidate, token)
    media = _expected_media_type(candidate, media_type)
    adapter = candidate.producer_kind is _K.ADAPTER
    result_purpose = candidate.finalization_purpose is _P.RESULT
    owner = candidate.owner
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    if isinstance(owner, RunArtifactOwner):
        experiment_id = owner.experiment_id
        run_id = owner.run_id
        invocation_id = owner.invocation_id
    observations: list[ValidationObservation] = []

    def passed(
        stage: ValidationStage,
        *,
        size_bytes: int | None = None,
        sha256: str | None = None,
    ) -> None:
        facts: dict[str, object] = {
            "observed_at_utc": now_utc,
            "stage": stage,
            "outcome": "PASSED",
        }
        if size_bytes is not None:
            facts["observed_size_bytes"] = size_bytes
        if sha256 is not None:
            facts["observed_sha256"] = sha256
        observations.append(ValidationObservation.model_validate(facts))

    def failed(stage: ValidationStage, code: str, message: str) -> CandidateValidation:
        failure = artifact_failure(
            code,
            message=message,
            invocation_id=invocation_id,
            run_id=run_id,
            experiment_id=experiment_id,
            now_utc=now_utc,
        )
        observations.append(
            ValidationObservation(
                observed_at_utc=now_utc,
                stage=stage,
                outcome="FAILED",
                error_code=code,
                diagnostic_id=failure.diagnostics[0].diagnostic_id,
            )
        )
        return CandidateValidation(observations=tuple(observations), result=failure)

    # PATH: the confinement again and its identity (reading 18).
    rechecked = recheck_confined_path(confined, now_utc=now_utc)
    if isinstance(rechecked, Failure):
        diagnostic = rechecked.diagnostics[0]
        return failed("PATH", diagnostic.error_code, diagnostic.message)
    passed("PATH")
    # SIZE: bounded before anything is parsed (24.3:1773).
    size = confined.identity.st_size
    if size > ceilings.max_bytes:
        return failed(
            "SIZE", ARTIFACT_VALIDATION_FAILED, "candidate size exceeds the ceiling"
        )
    if adapter and candidate.adapter_declared_size != size:
        return failed(
            "SIZE",
            ARTIFACT_VALIDATION_FAILED,
            "candidate size differs from the adapter declaration",
        )
    if media in JSON_MEDIA_TYPES and size > ceilings.max_parse_bytes:
        return failed(
            "SIZE",
            ARTIFACT_VALIDATION_FAILED,
            "candidate exceeds the parse ceiling for a JSON kind",
        )
    passed("SIZE", size_bytes=size)
    # MEDIA: the closed set.
    if media not in ADMITTED_MEDIA_TYPES:
        return failed(
            "MEDIA",
            ARTIFACT_VALIDATION_FAILED,
            "media type is outside the admitted set",
        )
    passed("MEDIA")
    # The ruling of 2026-11-09: a CORE EVIDENCE candidate of a canonical medium at
    # or below the parse ceiling is offered to the qualifier (an adapter's bytes
    # and a RESULT never are; a larger candidate keeps the whole-content rule).
    qualifier: CanonicalEvidenceQualifier | None = None
    if (
        isinstance(canonical, CanonicalEvidenceQualifier)
        and not adapter
        and not result_purpose
        and media in CANONICAL_MEDIA_TYPES
        and size <= ceilings.max_parse_bytes
    ):
        qualifier = canonical
    # SCHEMA: JSON kinds -- and a candidate offered to the qualifier -- are read,
    # exactly the observed size, already at or below the parse ceiling, through
    # the store's handle bridge, whose ``fstat`` identity is compared before and
    # after the read (reading 18), and decoded as strict documents whose shape is
    # otherwise inert bytes (24.3:1775). A read that fails proves nothing about
    # the document: a storage failure (reading 26); a handle whose identity
    # differs is the bridge's refusal, at this stage. The digest of the bytes
    # decoded is kept so that HASH can bind the verdict to the bytes it streams.
    # JSON Lines are checked record by record; stderr text is offered only when it
    # is one well-formed document (the structured fallback), otherwise it is free
    # text under the whole-content rule.
    schema_digest: str | None = None
    qualification: CanonicalQualification | None = None
    decoded: tuple[object, ...] = ()
    offered: tuple[bytes, ...] | None = None
    if media in JSON_MEDIA_TYPES or qualifier is not None:
        read = read_confined(confined, limit=size, now_utc=now_utc)
        if isinstance(read, Failure):
            diagnostic = read.diagnostics[0]
            if diagnostic.error_code == ARTIFACT_MOVE_FAILED:
                return failed(
                    "SCHEMA", ARTIFACT_MOVE_FAILED, "JSON candidate could not be read"
                )
            return failed("SCHEMA", diagnostic.error_code, diagnostic.message)
        document = read.value
        schema_digest = sha256_bytes(document)
        if media in JSON_MEDIA_TYPES or media == NDJSON_MEDIA_TYPE:
            try:
                if media == NDJSON_MEDIA_TYPE:
                    offered, decoded = _split_records(document)
                else:
                    decoded, offered = (_decode_strict(document),), (document,)
            except _NotWellFormed as refusal:
                return failed("SCHEMA", ARTIFACT_VALIDATION_FAILED, str(refusal))
        else:
            try:
                decoded, offered = (_decode_strict(document),), (document,)
            except _NotWellFormed:
                offered = None  # free text: never offered, the whole-content rule
    if offered is not None and qualifier is not None:
        answer = qualifier.qualify_evidence(candidate, offered)
        if isinstance(answer, Failure):
            diagnostic = answer.diagnostics[0]
            if diagnostic.error_code.startswith("PERSISTENCE."):
                return failed(
                    "SCHEMA",
                    ARTIFACT_MOVE_FAILED,
                    "canonical facts could not be read",
                )
            return failed("SCHEMA", ARTIFACT_VALIDATION_FAILED, diagnostic.message)
        if isinstance(answer.value, CanonicalQualification):
            qualification = answer.value
    if offered is not None:
        passed("SCHEMA")
    # REDACTION and HASH: one stream (plan 6.4) through the store's handle bridge
    # (plan 4.1, reading 18): the ``fstat`` identity of the one open handle is
    # compared with the confined identity before and after the port streams it, so
    # a substitute swapped in around the open is refused by the handle itself. A
    # stream that fails hashed nothing and proved nothing: a storage failure
    # (reading 26). Either refusal is re-minted here with the owner correlation.
    # The exact raw token is scanned for whenever material is available, for
    # either purpose; the whole-content shape rule runs over unqualified text.
    streamed = scan_confined(
        confined,
        hasher,
        token,
        detect_token_shape=(
            not result_purpose and qualification is None and media in TEXT_MEDIA_TYPES
        ),
        now_utc=now_utc,
    )
    if isinstance(streamed, Failure):
        if streamed.diagnostics[0].error_code == ARTIFACT_MOVE_FAILED:
            return failed(
                "HASH",
                ARTIFACT_MOVE_FAILED,
                "candidate could not be read while hashing",
            )
        return failed(
            "HASH", ARTIFACT_VALIDATION_FAILED, "candidate changed while hashing"
        )
    scan = streamed.value
    if isinstance(token, AttemptTokenMaterial) and (
        scan.token_found
        or any(_contains_text(item, token.attempt_token) for item in decoded)
    ):
        return failed(
            "REDACTION",
            SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
            "candidate carries the raw attempt token",
        )
    if qualification is not None and any(
        _TOKEN_SHAPE.search(text) is not None
        for text in qualification.uncontrolled_strings
    ):
        return failed(
            "REDACTION",
            SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
            "a canonical record carries token-shaped material in an uncontrolled field",
        )
    if not result_purpose and scan.token_shape_found:
        return failed(
            "REDACTION",
            SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
            "candidate carries token-shaped material",
        )
    passed("REDACTION")
    # HASH: the identity by path once the handle has closed, the streamed size
    # against the observed one, and the schema verdict bound to the streamed
    # bytes -- a digest differing from the one decoded at SCHEMA means the bytes
    # judged well-formed are not the bytes hashed.
    after = recheck_confined_path(confined, now_utc=now_utc)
    if (
        isinstance(after, Failure)
        or scan.size_bytes != size
        or (schema_digest is not None and schema_digest != scan.sha256)
    ):
        return failed(
            "HASH", ARTIFACT_VALIDATION_FAILED, "candidate changed while hashing"
        )
    if adapter and candidate.adapter_declared_hash != scan.sha256:
        return failed(
            "HASH",
            ARTIFACT_VALIDATION_FAILED,
            "content hash differs from the adapter declaration",
        )
    passed("HASH", size_bytes=scan.size_bytes, sha256=scan.sha256)
    validated = ValidatedCandidate(
        candidate_artifact_id=candidate.candidate_artifact_id,
        artifact_id=artifact_id_for(candidate.candidate_artifact_id, scan.sha256),
        content_hash=scan.sha256,
        size_bytes=scan.size_bytes,
        media_type=media,
        finalized_relative_path=finalized_relative_path_for(scan.sha256),
        identity=confined.identity,
        observations=tuple(observations),
        exact_token_scanned=isinstance(token, AttemptTokenMaterial),
        canonical=qualification is not None,
    )
    return CandidateValidation(
        observations=tuple(observations),
        result=Success[InstanceOf[ValidatedCandidate]](
            outcome="SUCCESS", value=validated
        ),
    )


__all__ = (
    "ADMITTED_MEDIA_TYPES",
    "CANONICAL_MEDIA_TYPES",
    "DEFAULT_CEILINGS",
    "JSON_MEDIA_TYPES",
    "MAX_CANDIDATE_BYTES",
    "MAX_JSON_PARSE_BYTES",
    "MAX_MANIFEST_BYTES",
    "MAX_STDERR_EVIDENCE_BYTES",
    "NDJSON_MEDIA_TYPE",
    "TEXT_MEDIA_TYPES",
    "CandidateValidation",
    "ValidatedCandidate",
    "ValidationCeilings",
    "validate_candidate",
)
