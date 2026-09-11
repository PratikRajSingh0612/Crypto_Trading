"""Validation results, result manifests and the sanitized manifest (Stage 6 plan
sections 3.10, 3.11, 4, 8, 12.4, 13; specification 10.2, 10.3, 11.3, 11.5, 14.1,
14.7, 15.7, 19.4, 21.2.1).

**Records.** ``AdapterValidationResult`` is the untrusted ``validate`` output file
(trust class W, token-free by contract; specification 11.3 row in order): the two
exact version literals, the request, invocation, run and attempt-hash identity, the
``ValidationOutcome``, bounded adapter diagnostics, the adapter's instant and the
exact-byte ``result_hash``. ``AdapterResultManifest`` is the untrusted ``run``
result file (trust class W, token-bearing): the adapter-minted manifest identity, the
experiment, run and run-command invocation, the raw attempt token (hidden from
``repr``), the ``SemanticStatus``, start and completion, the specification 10.3
``RunProvenance``, the candidate declarations, metrics, diagnostics, warnings and
approximations. ``SanitizedAdapterResultManifest`` is the core-preserved
representation (trust class C): the token replaced by ``attempt_token_hash``, every
staging path replaced by a core-derived ``CandidateArtifactId``, the exact-byte
``source_adapter_result_manifest_hash`` retained as provenance and its own
``sanitized_adapter_result_manifest_hash``. The status coupling -- ``SUCCEEDED``
carries no warning, ``SUCCEEDED_WITH_WARNINGS`` at least one, every non-success
status at least one diagnostic and no candidate -- is a validator on both manifests
and is published as the same ``if``/``then`` clauses (plan 3.10, 12.4).

**Identity.** ``validation_result_hash`` is ``sha256(canonical_json_bytes(result
without result_hash))``, exact-byte and stdlib-reproducible outside the profile
envelope (plan 4). ``sanitized_manifest_hash`` is the
``SANITIZED_ADAPTER_RESULT_MANIFEST_V1`` profile over the canonical sanitized content
with only the self-hash omitted (specification 10.2). Candidate identities are
``candidate_artifact_id_for(run_id, invocation_id, relative_path)`` -- derived by the
core, never chosen by the adapter. The source hash is over the exact manifest bytes
and the sanitized hash over canonical JSON, so the two cannot coincide by
construction.

**The parsers.** ``parse_validation_result`` and ``parse_result_manifest`` are the
byte-level halves of plan 3.11: the command-specific ceiling before any decoding
(specification 14.7), strict UTF-8, ``json`` with the Task 3 repeated-key hook, the
permissive ``OutputHeader`` read only from a JSON object, the version check
(``PROTOCOL.UNSUPPORTED_VERSION``), redaction of the decoded object with the run's
token before strict validation (specification 14.7 "sanitized and revalidated"), and
strict validation over the redacted object. Each returns a typed parse outcome
(trust class P) and never raises on adapter-controlled bytes. Record-level
reconciliation -- identity against the records, the exit table, the event
declarations -- is Task 6's; the parsers record, the reconcilers decide.

Task-local readings, declared rather than inferred silently:

- ``OutputHeader.attempt_token_hash``: a raw top-level ``attempt_token`` that is a
  string of 1..1024 UTF-8-encodable characters is hashed at once and only the hash
  is stored (plan 3.11). For the validation result alone -- token-free by contract,
  its identity the declared ``attempt_token_hash`` field (specification 14.1
  "attempt-hash identity", compared by the reconciler even when the strict model is
  absent) -- a top-level ``attempt_token_hash`` that is a 64-character lowercase hex
  string is otherwise carried as declared. A manifest proves identity by possessing
  the raw token, so its header reads no declared hash (a stale writer knows every
  core record's hash without the token) and an absent or wrongly typed token is
  ``MISSING``, which reports identity at plan 9.2 check (3). Anything else is
  ``MISSING``. The header never carries the raw value: its text fields are read
  redacted with the run's token, so an adapter that misplaces the token in an
  identity or version field cannot echo it through a parse outcome, and the
  redacted identity differs from every record (a token is never a lawful identity).
- A validation result is token-free by contract (plan 3.10). ``parse_validation_result``
  enforces ``redactions > 0 => result MISSING and PROTOCOL.VALIDATION_RESULT_INVALID``
  explicitly, before strict validation, so an adapter that computed ``result_hash``
  over the redacted spelling cannot pass; ``ValidationResultParse`` pins the rule.
- ``redact_validation_result`` reuses ``redact_payload`` and additionally redacts a
  top-level ``attempt_token`` value (through a one-element list, where the walk applies
  no exemption), so there is one redaction algorithm and no exempt key in a
  validation result. A key collapse (``ValueError``) or a walk past the interpreter's
  recursion depth (``RecursionError``) is the parser's generic failure code with
  ``redactions == 0``: no count exists and the parse carries no text.
- The version check precedes redaction, so ``PROTOCOL.UNSUPPORTED_VERSION`` carries
  ``redactions == 0``; the parse carries only the redacted header text, so no
  unredacted adapter text leaves. A NaN or infinite leaf survives ``json.loads``,
  keeps the header and
  fails at the ``allow_nan=False`` re-serialization (the Task 3 posture: the header
  is absent only for oversized, non-UTF-8 or non-object bytes).
- The path-located classification: a strict-validation error located at
  ``("candidate_artifacts", <index>, "relative_path")`` with a type other than
  ``missing`` is ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` and wins over every other error
  in the document; an absent path, a non-object declaration, or a key spelled
  ``relative_path`` anywhere else is ``ARTIFACT.RESULT_MANIFEST_INVALID``.
- ``SanitizedAdapterResultManifest.candidate_declarations`` is canonicalized in
  ``candidate_artifact_id`` order and must equal ``candidate_artifact_ids``
  positionally (declaration order is non-semantic, plan 3.1), so the record is
  deterministic under any wire declaration order.
- ``sanitize_result_manifest`` matches each manifest declaration to the summary's
  accepted ``ARTIFACT_PRODUCED`` declaration by ``relative_path`` and requires the
  other four fields to agree; a declaration without its event, or a disagreeing one,
  is a caller error (plan 9.2: the function is never called in that case). Extra
  accepted declarations -- the abandoned candidates of a non-success manifest -- are
  ignored. The self-hash is computed over a ``model_construct`` draft through the same
  ``sanitized_manifest_hash`` the validator calls, so the hash payload is assembled
  in exactly one place; the returned record is fully validated.
- The parsers compare no identity against the records (plan 3.11 separates
  byte-level parsing from record-level reconciliation, and no identity code is among
  the parse failure codes); a manifest carrying another attempt's token parses to a
  W-class ``ManifestParse.manifest`` whose header hash the Task 6 reconciler rejects.
- ``RunProvenance.attempt_number`` is bounded ``1..MAX_ATTEMPTS_PER_SLOT`` (the
  ``EngineRunRequest`` rule); ``candidate_artifacts`` and ``candidate_metrics`` keep
  adapter order and are unique on their key (published as whole-value
  ``uniqueItems``, a sound partial tightening); ``approximations`` is sorted unique.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, ClassVar, Final, Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.adapters.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    PROTOCOL_UNSUPPORTED_VERSION,
    PROTOCOL_VALIDATION_RESULT_INVALID,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    MediaType,
    ProtocolEventSummary,
    ProtocolWarning,
)
from crypto_lab.adapters.limits import (
    MAX_ADAPTER_DIAGNOSTICS,
    MAX_APPROXIMATIONS,
    MAX_CANDIDATE_ARTIFACTS,
    MAX_CANDIDATE_METRICS,
    MAX_DECLARED_SIZE_BYTES,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    MAX_WARNINGS,
    PROTOCOL_VERSION,
)
from crypto_lab.adapters.negotiation import _is_utf8_text, _object_without_repeated_keys
from crypto_lab.adapters.paths import RelativeCandidatePath
from crypto_lab.adapters.sanitization import redact_attempt_token, redact_payload
from crypto_lab.adapters.vocabulary import SemanticStatus, ValidationOutcome
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.financial import CanonicalDecimal
from crypto_lab.domain.hashing import (
    HashingProfile,
    attempt_token_hash,
    candidate_artifact_id_for,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import (
    AdapterManifestId,
    ApproximationId,
    AttemptToken,
    CandidateArtifactId,
    EventId,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    NormalizedIdentifier,
    RequestId,
    RunId,
    Sha256,
)
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

#: The permissive header bound: a header value longer than any strict alias could
#: accept reads as MISSING so the identity check reports absence (plan 3.11).
_MAX_HEADER_TEXT_CHARACTERS: Final = 128
#: The ``attempt_token_hash`` bound: a raw token is 1 through 1024 characters.
_MAX_TOKEN_CHARACTERS: Final = 1024
_HEX_DIGITS: Final = frozenset("0123456789abcdef")
_SELF_HASH_FIELD: Final = "sanitized_adapter_result_manifest_hash"
#: Only ever placed on the pre-hash draft the sanitizer hashes; never returned.
_PLACEHOLDER_HASH: Final = "0" * 64
_HEADER_TEXT_KEYS: Final[tuple[str, ...]] = (
    "protocol_version",
    "schema_version",
    "invocation_id",
    "run_id",
    "request_id",
)
#: Plan 3.11: the codes each parse can record.
_VALIDATION_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {PROTOCOL_VALIDATION_RESULT_INVALID, PROTOCOL_UNSUPPORTED_VERSION}
)
_MANIFEST_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {
        ARTIFACT_RESULT_MANIFEST_INVALID,
        PROTOCOL_UNSUPPORTED_VERSION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
    }
)
#: Plan 3.10: the outcomes that owe a diagnostic and the statuses that owe one.
_DIAGNOSED_OUTCOMES: Final[tuple[ValidationOutcome, ...]] = (
    ValidationOutcome.NOT_APPLICABLE,
    ValidationOutcome.UNAVAILABLE,
    ValidationOutcome.INVALID,
)
_NON_SUCCESS_STATUSES: Final[tuple[SemanticStatus, ...]] = (
    SemanticStatus.FAILED,
    SemanticStatus.CANCELLED,
    SemanticStatus.TIMED_OUT,
    SemanticStatus.NOT_APPLICABLE,
    SemanticStatus.UNAVAILABLE,
)
_HeaderText = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=_MAX_HEADER_TEXT_CHARACTERS
    ),
]


def _is_missing(value: object) -> bool:
    return value is MISSING


def _unique_sorted_identifiers(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


# --- Nested value objects (plan 3.10) -------------------------------------------------


class RunProvenance(CanonicalModel):
    """The specification 10.3 provenance the manifest echoes (plan 3.10; nested).

    Every value is one the request handed the adapter, so the reconciler compares
    each against its own inputs (plan 9.2 check 5).
    """

    experiment_spec_hash: Sha256
    request_hash: Sha256
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    configuration_hash: Sha256
    adapter: AdapterIdentity
    engine: EngineIdentity
    negotiated_versions: NegotiatedVersions
    comparison_level: ComparisonLevel
    logical_slot_id: LogicalSlotId
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)


class CandidateArtifactDeclaration(CanonicalModel):
    """One declared candidate in the manifest: the five ``ArtifactProducedPayload``
    fields (plan 3.10; trust class W). A lexically valid path is still untrusted."""

    relative_path: RelativeCandidatePath
    artifact_kind: NormalizedIdentifier
    media_type: MediaType
    declared_size_bytes: int = Field(ge=0, le=MAX_DECLARED_SIZE_BYTES)
    declared_sha256: Sha256


def _metric_schema_extra(schema: JsonSchemaValue) -> None:
    """Plan 12.4: ``value_status`` ``DEFINED`` iff ``value`` present, published."""
    schema.setdefault("allOf", []).extend(
        (
            {
                "if": {
                    "properties": {"value_status": {"const": "DEFINED"}},
                    "required": ["value_status"],
                },
                "then": {"required": ["value"]},
            },
            {
                "if": {
                    "properties": {"value_status": {"const": "UNDEFINED"}},
                    "required": ["value_status"],
                },
                "then": {"not": {"required": ["value"]}},
            },
        )
    )


class CandidateMetric(CanonicalModel):
    """A declared normalized metric (plan 3.10); not the deferred ``MetricValue``.

    A missing or undefined value uses the explicit ``value_status`` rather than
    ``NaN`` (specification 11.3): ``DEFINED`` exactly when ``value`` is present.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_metric_schema_extra
    )

    metric_name: NormalizedIdentifier
    value: CanonicalDecimal | MISSING = MISSING  # type: ignore[valid-type]
    value_status: Literal["DEFINED", "UNDEFINED"]
    unit: NormalizedIdentifier
    methodology_version: SemanticVersion
    comparison_level: ComparisonLevel

    @model_validator(mode="after")
    def validate_value_status(self) -> Self:
        if (self.value_status == "DEFINED") is _is_missing(self.value):
            raise ValueError(
                "value_status DEFINED requires value and UNDEFINED prohibits it"
            )
        return self


# --- The validation result (plan 3.10) ------------------------------------------------


def _validation_schema_extra(schema: JsonSchemaValue) -> None:
    """Plan 12.4: the three diagnosed outcomes require a diagnostic, published."""
    schema.setdefault("allOf", []).extend(
        {
            "if": {
                "properties": {"outcome": {"const": outcome.value}},
                "required": ["outcome"],
            },
            "then": {"properties": {"diagnostics": {"minItems": 1}}},
        }
        for outcome in _DIAGNOSED_OUTCOMES
    )


class AdapterValidationResult(CanonicalModel):
    """The untrusted ``validate`` output (plan 3.10; specification 11.3 row in order).

    Trust class W and token-free by contract: it carries ``attempt_token_hash``, and
    a raw token found anywhere in one is a contract violation the parser records.
    ``NOT_APPLICABLE``, ``UNAVAILABLE`` and ``INVALID`` require at least one
    diagnostic; ``result_hash`` must recompute over the document as written.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_validation_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    request_id: RequestId
    invocation_id: InvocationId
    run_id: RunId
    attempt_token_hash: Sha256
    outcome: ValidationOutcome
    diagnostics: tuple[AdapterDiagnostic, ...] = Field(
        max_length=MAX_ADAPTER_DIAGNOSTICS
    )
    validated_at_utc: CalendarValidUtcDateTime
    result_hash: Sha256

    @model_validator(mode="after")
    def validate_outcome_and_result_hash(self) -> Self:
        if self.outcome in _DIAGNOSED_OUTCOMES and not self.diagnostics:
            raise ValueError(
                "a NOT_APPLICABLE, UNAVAILABLE or INVALID validation result requires "
                "at least one diagnostic"
            )
        if self.result_hash != validation_result_hash(self):
            raise ValueError(
                "result_hash must equal the SHA-256 of the canonical result without "
                "result_hash"
            )
        return self


def validation_result_hash(result: AdapterValidationResult) -> Sha256:
    """Plan 4: ``sha256(canonical_json_bytes(result without result_hash))``.

    Exact-byte and stdlib-reproducible, deliberately outside the profile envelope,
    so a conforming adapter computes it with ``hashlib`` and ``json.dumps`` over its
    canonical-form document. Material: every field but ``result_hash``.
    """
    if not isinstance(result, AdapterValidationResult):
        raise TypeError("result must be an AdapterValidationResult")
    payload = result.model_dump(mode="python")
    del payload["result_hash"]
    return sha256_bytes(canonical_json_bytes(payload))


# --- The permissive header and the parse outcomes (plan 3.11) -------------------------


class OutputHeader(CanonicalModel):
    """The permissively read output-file header (plan 3.11; nested, never published).

    ``extra="ignore"``. Each field is present only when the document carried a value
    of the right type within its bound, so a wrongly typed, empty or over-long
    identity reads as ``MISSING`` and the reconciler's identity check reports
    absence. A raw token is hashed at once; only the hash is stored (plan 13).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    protocol_version: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    schema_version: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    run_id: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    request_id: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    attempt_token_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]


def _read_header(
    document: dict[str, object], token: str, *, declared_hash: bool
) -> OutputHeader:
    """Read each header field whose value has the right type and bound, redacted
    with the run's ``token`` so no parse outcome can carry the raw token even when
    the adapter misplaces it in an identity or version field; hash a raw
    ``attempt_token`` at once (plan 3.11), else, only when ``declared_hash`` is
    true -- the token-free validation result, whose identity is its declared
    ``attempt_token_hash`` -- carry a declared hash of the right shape. A manifest
    proves identity by possessing the raw token, so its header reads no declared
    hash. A redacted identity differs from every record and reports identity."""
    facts: dict[str, object] = {}
    for key in _HEADER_TEXT_KEYS:
        value = document.get(key)
        if (
            type(value) is str
            and 1 <= len(value) <= _MAX_HEADER_TEXT_CHARACTERS
            and _is_utf8_text(value)
        ):
            redacted, _ = redact_attempt_token(value, token)
            if 1 <= len(redacted) <= _MAX_HEADER_TEXT_CHARACTERS:
                facts[key] = redacted
    raw_token = document.get("attempt_token")
    if (
        type(raw_token) is str
        and 1 <= len(raw_token) <= _MAX_TOKEN_CHARACTERS
        and _is_utf8_text(raw_token)
    ):
        facts["attempt_token_hash"] = attempt_token_hash(raw_token)
    elif declared_hash:
        declared = document.get("attempt_token_hash")
        if type(declared) is str and _is_utf8_text(declared):
            # Redacted before the shape check: a token that is itself lowercase hex
            # could be padded into a hash-shaped value and echoed here otherwise.
            declared, _ = redact_attempt_token(declared, token)
            if len(declared) == 64 and set(declared) <= _HEX_DIGITS:
                facts["attempt_token_hash"] = declared
    return OutputHeader.model_validate(facts)


def _unsupported_version(header: OutputHeader) -> bool:
    """Whether the header names a readable version the core does not support."""
    return any(
        not _is_missing(version) and version != supported
        for version, supported in (
            (header.protocol_version, PROTOCOL_VERSION),
            (header.schema_version, SCHEMA_VERSION),
        )
    )


def _require_parse_shape(
    *,
    header: object,
    parsed: object,
    failure_code: object,
    codes: frozenset[str],
    generic: str,
    label: str,
    kind: str,
) -> None:
    """The invariants shared by both parse outcomes (the ``DescriptorParse`` shape)."""
    parsed_present = not _is_missing(parsed)
    failure_present = not _is_missing(failure_code)
    header_present = not _is_missing(header)
    if parsed_present is failure_present:
        raise ValueError(
            f"exactly one of {label} and failure_code is present on a parse"
        )
    if parsed_present:
        if not header_present:
            raise ValueError(f"a parsed {label} requires a header agreeing with it")
        return
    if failure_code not in codes:
        raise ValueError(f"failure_code must be a {kind} parse code")
    if not header_present and failure_code != generic:
        raise ValueError(f"a parse without a header records {generic}")
    unsupported = header_present and _unsupported_version(cast("OutputHeader", header))
    if failure_code == PROTOCOL_UNSUPPORTED_VERSION and not unsupported:
        raise ValueError(
            "PROTOCOL.UNSUPPORTED_VERSION requires a readable unsupported version in "
            "the header"
        )
    if unsupported and failure_code != PROTOCOL_UNSUPPORTED_VERSION:
        raise ValueError(
            "a readable unsupported version records PROTOCOL.UNSUPPORTED_VERSION"
        )


class ValidationResultParse(CanonicalModel):
    """The byte-level outcome of one validation output file (plan 3.11; class P).

    Exactly one of ``result`` and ``failure_code`` is present; ``header`` is absent
    only for oversized, non-UTF-8 or non-object bytes, which are always
    ``PROTOCOL.VALIDATION_RESULT_INVALID``; a present result agrees with its header;
    ``redactions > 0`` always accompanies that code with ``result`` absent, because a
    validation result is token-free by contract (plan 3.10).
    """

    byte_length: int = Field(ge=0)
    source_hash: Sha256
    header: OutputHeader | MISSING = MISSING  # type: ignore[valid-type]
    result: AdapterValidationResult | MISSING = MISSING  # type: ignore[valid-type]
    failure_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    redactions: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        _require_parse_shape(
            header=self.header,
            parsed=self.result,
            failure_code=self.failure_code,
            codes=_VALIDATION_FAILURE_CODES,
            generic=PROTOCOL_VALIDATION_RESULT_INVALID,
            label="result",
            kind="validation",
        )
        if not _is_missing(self.result):
            result = self.result
            header = self.header
            if (
                header.protocol_version != result.protocol_version
                or header.schema_version != result.schema_version
                or header.invocation_id != result.invocation_id
                or header.run_id != result.run_id
                or header.request_id != result.request_id
                or header.attempt_token_hash != result.attempt_token_hash
            ):
                raise ValueError("a parsed result requires a header agreeing with it")
        if (
            self.redactions > 0
            and self.failure_code != PROTOCOL_VALIDATION_RESULT_INVALID
        ):
            raise ValueError(
                "redactions on a validation result require "
                "PROTOCOL.VALIDATION_RESULT_INVALID with no result"
            )
        return self


# --- The result manifest (plan 3.10) --------------------------------------------------


def _status_coupling_clauses(
    candidate_fields: tuple[str, ...],
) -> list[JsonSchemaValue]:
    """Plan 3.10 and 12.4: the status coupling as ``if``/``then`` clauses."""
    empty_candidates: dict[str, JsonValue] = {
        field: {"maxItems": 0} for field in candidate_fields
    }
    return [
        {
            "if": {
                "properties": {
                    "semantic_status": {"const": SemanticStatus.SUCCEEDED.value}
                },
                "required": ["semantic_status"],
            },
            "then": {"properties": {"warnings": {"maxItems": 0}}},
        },
        {
            "if": {
                "properties": {
                    "semantic_status": {
                        "const": SemanticStatus.SUCCEEDED_WITH_WARNINGS.value
                    }
                },
                "required": ["semantic_status"],
            },
            "then": {"properties": {"warnings": {"minItems": 1}}},
        },
        {
            "if": {
                "properties": {
                    "semantic_status": {
                        "enum": [status.value for status in _NON_SUCCESS_STATUSES]
                    }
                },
                "required": ["semantic_status"],
            },
            "then": {
                "properties": {"diagnostics": {"minItems": 1}, **empty_candidates}
            },
        },
    ]


def _wire_manifest_schema_extra(schema: JsonSchemaValue) -> None:
    schema.setdefault("allOf", []).extend(
        _status_coupling_clauses(("candidate_artifacts",))
    )


def _sanitized_manifest_schema_extra(schema: JsonSchemaValue) -> None:
    schema.setdefault("allOf", []).extend(
        _status_coupling_clauses(("candidate_artifact_ids", "candidate_declarations"))
    )


def _require_status_coupling(
    status: SemanticStatus,
    *,
    warnings: tuple[ProtocolWarning, ...],
    diagnostics: tuple[AdapterDiagnostic, ...],
    candidate_count: int,
) -> None:
    """Plan 3.10, restated verbatim on both manifests."""
    if status is SemanticStatus.SUCCEEDED and warnings:
        raise ValueError("a SUCCEEDED manifest carries no warning")
    if status is SemanticStatus.SUCCEEDED_WITH_WARNINGS and not warnings:
        raise ValueError(
            "a SUCCEEDED_WITH_WARNINGS manifest carries at least one warning"
        )
    if status in _NON_SUCCESS_STATUSES:
        if not diagnostics:
            raise ValueError("a non-success manifest carries at least one diagnostic")
        if candidate_count:
            raise ValueError("a non-success manifest declares no candidate artifact")


def _unique_metric_names(
    value: tuple[CandidateMetric, ...],
) -> tuple[CandidateMetric, ...]:
    names = [metric.metric_name for metric in value]
    if len(set(names)) != len(names):
        raise ValueError("candidate metrics must be unique on metric_name")
    return value


class AdapterResultManifest(CanonicalModel):
    """The untrusted ``run`` result file (plan 3.10; specification 11.3 row in order).

    Trust class W and token-bearing: the raw token is required, hidden from ``repr``
    and never persisted; ``sanitize_result_manifest`` builds the core representation.
    Completion does not precede start; declarations are unique on ``relative_path``
    and metrics on ``metric_name``; approximations are sorted identities; the status
    coupling holds.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_wire_manifest_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    adapter_manifest_id: AdapterManifestId
    experiment_id: ExperimentId
    run_id: RunId
    invocation_id: InvocationId
    attempt_token: AttemptToken = Field(repr=False)
    semantic_status: SemanticStatus
    started_at_utc: CalendarValidUtcDateTime
    completed_at_utc: CalendarValidUtcDateTime
    provenance: RunProvenance
    candidate_artifacts: tuple[CandidateArtifactDeclaration, ...] = Field(
        max_length=MAX_CANDIDATE_ARTIFACTS, json_schema_extra={"uniqueItems": True}
    )
    candidate_metrics: tuple[CandidateMetric, ...] = Field(
        max_length=MAX_CANDIDATE_METRICS, json_schema_extra={"uniqueItems": True}
    )
    diagnostics: tuple[AdapterDiagnostic, ...] = Field(
        max_length=MAX_ADAPTER_DIAGNOSTICS
    )
    warnings: tuple[ProtocolWarning, ...] = Field(max_length=MAX_WARNINGS)
    approximations: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATIONS, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("candidate_artifacts")
    @classmethod
    def validate_candidate_artifacts(
        cls, value: tuple[CandidateArtifactDeclaration, ...]
    ) -> tuple[CandidateArtifactDeclaration, ...]:
        paths = [declaration.relative_path for declaration in value]
        if len(set(paths)) != len(paths):
            raise ValueError("candidate artifacts must be unique on relative_path")
        return value

    @field_validator("candidate_metrics")
    @classmethod
    def validate_candidate_metrics(
        cls, value: tuple[CandidateMetric, ...]
    ) -> tuple[CandidateMetric, ...]:
        return _unique_metric_names(value)

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls, value: tuple[ApproximationId, ...]
    ) -> tuple[ApproximationId, ...]:
        return _unique_sorted_identifiers(value, "approximation identifiers")

    @model_validator(mode="after")
    def validate_order_and_status(self) -> Self:
        if self.completed_at_utc < self.started_at_utc:
            raise ValueError("completed_at_utc must not precede started_at_utc")
        _require_status_coupling(
            self.semantic_status,
            warnings=self.warnings,
            diagnostics=self.diagnostics,
            candidate_count=len(self.candidate_artifacts),
        )
        return self


class ManifestParse(CanonicalModel):
    """The byte-level outcome of one result manifest file (plan 3.11; class P).

    Exactly one of ``manifest`` (trust class W, transient, its token hidden) and
    ``failure_code`` is present; ``header`` is absent only for oversized, non-UTF-8
    or non-object bytes, which are always ``ARTIFACT.RESULT_MANIFEST_INVALID``; a
    present manifest agrees with its header; ``redactions`` counts the in-place
    redactions of the run's token from the manifest's text.
    """

    byte_length: int = Field(ge=0)
    source_hash: Sha256
    header: OutputHeader | MISSING = MISSING  # type: ignore[valid-type]
    manifest: AdapterResultManifest | MISSING = MISSING  # type: ignore[valid-type]
    failure_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    redactions: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        _require_parse_shape(
            header=self.header,
            parsed=self.manifest,
            failure_code=self.failure_code,
            codes=_MANIFEST_FAILURE_CODES,
            generic=ARTIFACT_RESULT_MANIFEST_INVALID,
            label="manifest",
            kind="manifest",
        )
        if not _is_missing(self.manifest):
            manifest = self.manifest
            header = self.header
            if (
                header.protocol_version != manifest.protocol_version
                or header.schema_version != manifest.schema_version
                or header.invocation_id != manifest.invocation_id
                or header.run_id != manifest.run_id
                or header.attempt_token_hash
                != attempt_token_hash(manifest.attempt_token)
            ):
                raise ValueError("a parsed manifest requires a header agreeing with it")
        return self


# --- The sanitized manifest (plan 3.10, 4) --------------------------------------------


class SanitizedCandidateArtifactDeclaration(CanonicalModel):
    """A declaration with its core-derived identity and source event; no path
    (plan 3.10; trust class C). Declared size, hash and media type stay claims."""

    candidate_artifact_id: CandidateArtifactId
    source_event_id: EventId
    artifact_kind: NormalizedIdentifier
    media_type: MediaType
    declared_size_bytes: int = Field(ge=0, le=MAX_DECLARED_SIZE_BYTES)
    declared_sha256: Sha256


class SanitizedAdapterResultManifest(CanonicalModel):
    """The core-preserved representation of a validated adapter result (plan 3.10;
    specification 11.3 row in order, with the aligned declarations).

    Trust class C: ``attempt_token_hash`` in the token's place, candidate identities
    in the paths' place, the exact-byte source hash as provenance and its own
    canonical self-hash, which must recompute. The status coupling of the wire
    manifest is restated verbatim; ``candidate_declarations`` is in identity order
    and equals ``candidate_artifact_ids`` positionally. Never implies success by
    itself and never authorizes finalization (specification 19.4).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_sanitized_manifest_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    adapter_manifest_id: AdapterManifestId
    experiment_id: ExperimentId
    run_id: RunId
    invocation_id: InvocationId
    attempt_token_hash: Sha256
    semantic_status: SemanticStatus
    started_at_utc: CalendarValidUtcDateTime
    completed_at_utc: CalendarValidUtcDateTime
    provenance: RunProvenance
    candidate_artifact_ids: tuple[CandidateArtifactId, ...] = Field(
        max_length=MAX_CANDIDATE_ARTIFACTS, json_schema_extra={"uniqueItems": True}
    )
    candidate_declarations: tuple[SanitizedCandidateArtifactDeclaration, ...] = Field(
        max_length=MAX_CANDIDATE_ARTIFACTS, json_schema_extra={"uniqueItems": True}
    )
    candidate_metrics: tuple[CandidateMetric, ...] = Field(
        max_length=MAX_CANDIDATE_METRICS, json_schema_extra={"uniqueItems": True}
    )
    diagnostics: tuple[AdapterDiagnostic, ...] = Field(
        max_length=MAX_ADAPTER_DIAGNOSTICS
    )
    warnings: tuple[ProtocolWarning, ...] = Field(max_length=MAX_WARNINGS)
    approximations: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATIONS, json_schema_extra={"uniqueItems": True}
    )
    source_adapter_result_manifest_hash: Sha256
    sanitized_adapter_result_manifest_hash: Sha256

    @field_validator("candidate_artifact_ids")
    @classmethod
    def validate_candidate_artifact_ids(
        cls, value: tuple[CandidateArtifactId, ...]
    ) -> tuple[CandidateArtifactId, ...]:
        return _unique_sorted_identifiers(value, "candidate_artifact_ids")

    @field_validator("candidate_metrics")
    @classmethod
    def validate_candidate_metrics(
        cls, value: tuple[CandidateMetric, ...]
    ) -> tuple[CandidateMetric, ...]:
        return _unique_metric_names(value)

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls, value: tuple[ApproximationId, ...]
    ) -> tuple[ApproximationId, ...]:
        return _unique_sorted_identifiers(value, "approximation identifiers")

    @model_validator(mode="after")
    def validate_order_status_identities_and_hash(self) -> Self:
        if self.completed_at_utc < self.started_at_utc:
            raise ValueError("completed_at_utc must not precede started_at_utc")
        _require_status_coupling(
            self.semantic_status,
            warnings=self.warnings,
            diagnostics=self.diagnostics,
            candidate_count=len(self.candidate_artifact_ids)
            + len(self.candidate_declarations),
        )
        identities = tuple(
            declaration.candidate_artifact_id
            for declaration in self.candidate_declarations
        )
        if identities != self.candidate_artifact_ids:
            raise ValueError(
                "candidate_declarations identities must equal candidate_artifact_ids "
                "in order"
            )
        if self.sanitized_adapter_result_manifest_hash != sanitized_manifest_hash(self):
            raise ValueError(
                "sanitized_adapter_result_manifest_hash must equal the recomputed "
                "SANITIZED_ADAPTER_RESULT_MANIFEST_V1 hash of the sanitized content"
            )
        return self


def sanitized_manifest_hash(manifest: SanitizedAdapterResultManifest) -> Sha256:
    """Plan 4: the ``SANITIZED_ADAPTER_RESULT_MANIFEST_V1`` identity of a sanitized
    manifest over its canonical content with only the self-hash omitted."""
    if not isinstance(manifest, SanitizedAdapterResultManifest):
        raise TypeError("manifest must be a SanitizedAdapterResultManifest")
    content = manifest.model_dump(mode="json")
    del content[_SELF_HASH_FIELD]
    return profile_hash(
        HashingProfile.SANITIZED_ADAPTER_RESULT_MANIFEST_V1,
        cast("dict[str, JsonValue]", content),
    )


def sanitize_result_manifest(
    output: ManifestParse, protocol_summary: ProtocolEventSummary
) -> SanitizedAdapterResultManifest:
    """Plan 3.10, 4 and 9.2: the core representation of a parsed manifest.

    Every declaration is matched to the accepted ``ARTIFACT_PRODUCED`` declaration
    with the same ``relative_path`` (unique on both sides) and must agree with it;
    its identity is ``candidate_artifact_id_for`` and its source event the accepted
    event's. The raw token becomes its hash, the exact-byte source hash is retained
    and the self-hash is computed over the assembled content. Pure over its
    arguments; a declaration without its event is a caller error.
    """
    if not isinstance(output, ManifestParse):
        raise TypeError("output must be a ManifestParse")
    if not isinstance(protocol_summary, ProtocolEventSummary):
        raise TypeError("protocol_summary must be a ProtocolEventSummary")
    manifest = output.manifest
    if _is_missing(manifest):
        raise ValueError("sanitize_result_manifest requires a parsed manifest")
    accepted = {
        record.payload.relative_path: record
        for record in protocol_summary.artifact_declarations
    }
    declarations: list[SanitizedCandidateArtifactDeclaration] = []
    for declaration in manifest.candidate_artifacts:
        record = accepted.get(declaration.relative_path)
        if record is None:
            raise ValueError(
                "a manifest declaration has no accepted ARTIFACT_PRODUCED event"
            )
        payload = record.payload
        if (
            payload.artifact_kind,
            payload.media_type,
            payload.declared_size_bytes,
            payload.declared_sha256,
        ) != (
            declaration.artifact_kind,
            declaration.media_type,
            declaration.declared_size_bytes,
            declaration.declared_sha256,
        ):
            raise ValueError(
                "a manifest declaration differs from its accepted ARTIFACT_PRODUCED "
                "event"
            )
        declarations.append(
            SanitizedCandidateArtifactDeclaration(
                candidate_artifact_id=candidate_artifact_id_for(
                    manifest.run_id, manifest.invocation_id, declaration.relative_path
                ),
                source_event_id=record.event_id,
                artifact_kind=declaration.artifact_kind,
                media_type=declaration.media_type,
                declared_size_bytes=declaration.declared_size_bytes,
                declared_sha256=declaration.declared_sha256,
            )
        )
    declarations.sort(key=lambda item: item.candidate_artifact_id)
    fields: dict[str, Any] = {
        "schema_version": manifest.schema_version,
        "protocol_version": manifest.protocol_version,
        "adapter_manifest_id": manifest.adapter_manifest_id,
        "experiment_id": manifest.experiment_id,
        "run_id": manifest.run_id,
        "invocation_id": manifest.invocation_id,
        "attempt_token_hash": attempt_token_hash(manifest.attempt_token),
        "semantic_status": manifest.semantic_status,
        "started_at_utc": manifest.started_at_utc,
        "completed_at_utc": manifest.completed_at_utc,
        "provenance": manifest.provenance,
        "candidate_artifact_ids": tuple(
            declaration.candidate_artifact_id for declaration in declarations
        ),
        "candidate_declarations": tuple(declarations),
        "candidate_metrics": manifest.candidate_metrics,
        "diagnostics": manifest.diagnostics,
        "warnings": manifest.warnings,
        "approximations": manifest.approximations,
        "source_adapter_result_manifest_hash": output.source_hash,
    }
    draft = SanitizedAdapterResultManifest.model_construct(
        **fields, sanitized_adapter_result_manifest_hash=_PLACEHOLDER_HASH
    )
    return SanitizedAdapterResultManifest.model_validate(
        {**fields, _SELF_HASH_FIELD: sanitized_manifest_hash(draft)}
    )


# --- The parsers (plan 3.11) ----------------------------------------------------------


def redact_validation_result(document: JsonValue, token: str) -> tuple[JsonValue, int]:
    """Redact every string of a decoded validation result, with no exempt key.

    Plan 3.10: a validation result is token-free by contract, so the top-level
    ``attempt_token`` value ``redact_payload`` retains for a manifest is redacted
    here too, through the same walk (a one-element list applies no exemption).
    Returns a new document and the number of occurrences replaced.
    """
    redacted, count = redact_payload(document, token)
    if type(redacted) is dict and "attempt_token" in redacted:
        wrapped, extra = redact_payload([redacted["attempt_token"]], token)
        redacted = {**redacted, "attempt_token": cast("list[JsonValue]", wrapped)[0]}
        count += extra
    return redacted, count


def _require_parser_arguments(
    output_bytes: object, max_bytes: object, ceiling: int, token: object
) -> None:
    if type(output_bytes) is not bytes:
        raise TypeError("output_bytes must be bytes")
    if type(max_bytes) is not int:
        raise TypeError("max_bytes must be a built-in integer")
    if not 1 <= max_bytes <= ceiling:
        raise ValueError(f"max_bytes must be within 1..{ceiling}")
    if type(token) is not str:
        raise TypeError("token must be a built-in string")
    if not 1 <= len(token) <= _MAX_TOKEN_CHARACTERS:
        raise ValueError(f"token length must be 1 through {_MAX_TOKEN_CHARACTERS}")


def _decode_object(output_bytes: bytes) -> dict[str, object] | None:
    """The decoded JSON object, or ``None`` for non-UTF-8, non-JSON, repeated-key,
    too-deep or non-object bytes (plan 3.11: such bytes carry no header)."""
    try:
        document = json.loads(
            output_bytes.decode("utf-8"),
            object_pairs_hook=_object_without_repeated_keys,
        )
    except (ValueError, RecursionError):
        return None
    if type(document) is not dict:
        return None
    return cast("dict[str, object]", document)


def _serialized(redacted: JsonValue) -> bytes | None:
    """The redacted object re-serialized for strict JSON-mode validation, or ``None``
    when it cannot be (a non-finite leaf, a depth past the interpreter's limit)."""
    try:
        return json.dumps(redacted, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return None


def parse_validation_result(
    output_bytes: bytes, *, max_bytes: int, token: str
) -> ValidationResultParse:
    """Plan 3.11: the byte-level half of the ``validate`` flow.

    Ceiling before decoding; strict UTF-8 and one JSON object (repeated keys refused)
    or no header; the permissive header; a readable unsupported version is
    ``PROTOCOL.UNSUPPORTED_VERSION``; any redaction of the run's ``token`` is
    ``PROTOCOL.VALIDATION_RESULT_INVALID`` with no result; otherwise strict validation
    yields the result or that code. Pure over its arguments; no adapter byte enters
    an error message and the raw token is never stored.
    """
    _require_parser_arguments(
        output_bytes, max_bytes, MAX_VALIDATION_RESULT_BYTES, token
    )
    facts: dict[str, object] = {
        "byte_length": len(output_bytes),
        "source_hash": sha256_bytes(output_bytes),
        "redactions": 0,
    }
    if len(output_bytes) > max_bytes:
        return ValidationResultParse.model_validate(
            {**facts, "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID}
        )
    document = _decode_object(output_bytes)
    if document is None:
        return ValidationResultParse.model_validate(
            {**facts, "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID}
        )
    header = _read_header(document, token, declared_hash=True)
    facts["header"] = header
    invalid = {**facts, "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID}
    if _unsupported_version(header):
        return ValidationResultParse.model_validate(
            {**facts, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    try:
        redacted, redactions = redact_validation_result(
            cast("JsonValue", document), token
        )
    except (ValueError, RecursionError):
        return ValidationResultParse.model_validate(invalid)
    if redactions > 0:
        return ValidationResultParse.model_validate(
            {**invalid, "redactions": redactions}
        )
    serialized = _serialized(redacted)
    if serialized is None:
        return ValidationResultParse.model_validate(invalid)
    try:
        result = AdapterValidationResult.model_validate_json(serialized)
    except (ValidationError, ValueError, RecursionError):
        return ValidationResultParse.model_validate(invalid)
    return ValidationResultParse.model_validate({**facts, "result": result})


def _path_located(error: ValidationError) -> bool:
    """Whether a manifest validation error is located at a declaration's own present
    ``relative_path`` (plan 3.11; the same mapping as the event parser)."""
    for item in error.errors():
        location = item["loc"]
        if (
            len(location) >= 3
            and location[-3] == "candidate_artifacts"
            and type(location[-2]) is int
            and location[-1] == "relative_path"
            and item["type"] != "missing"
        ):
            return True
    return False


def parse_result_manifest(
    output_bytes: bytes, *, max_bytes: int, token: str
) -> ManifestParse:
    """Plan 3.11: the byte-level half of the ``run`` result flow.

    Ceiling before decoding; strict UTF-8 and one JSON object (repeated keys refused)
    or no header; the permissive header, which hashes the manifest's own token at
    once; a readable unsupported version is ``PROTOCOL.UNSUPPORTED_VERSION``; every
    text field is redacted in place with the run's ``token`` (the manifest's own
    ``attempt_token`` key retained verbatim for the hash comparison) and the count is
    carried; strict validation over the redacted object yields the manifest,
    ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` for an error at a declaration's path, or
    ``ARTIFACT.RESULT_MANIFEST_INVALID``. Pure over its arguments; no adapter byte
    enters an error message.
    """
    _require_parser_arguments(output_bytes, max_bytes, MAX_RESULT_MANIFEST_BYTES, token)
    facts: dict[str, object] = {
        "byte_length": len(output_bytes),
        "source_hash": sha256_bytes(output_bytes),
        "redactions": 0,
    }
    if len(output_bytes) > max_bytes:
        return ManifestParse.model_validate(
            {**facts, "failure_code": ARTIFACT_RESULT_MANIFEST_INVALID}
        )
    document = _decode_object(output_bytes)
    if document is None:
        return ManifestParse.model_validate(
            {**facts, "failure_code": ARTIFACT_RESULT_MANIFEST_INVALID}
        )
    header = _read_header(document, token, declared_hash=False)
    facts["header"] = header
    invalid = {**facts, "failure_code": ARTIFACT_RESULT_MANIFEST_INVALID}
    if _unsupported_version(header):
        return ManifestParse.model_validate(
            {**facts, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    try:
        redacted, redactions = redact_payload(cast("JsonValue", document), token)
    except (ValueError, RecursionError):
        return ManifestParse.model_validate(invalid)
    facts["redactions"] = redactions
    invalid["redactions"] = redactions
    serialized = _serialized(redacted)
    if serialized is None:
        return ManifestParse.model_validate(invalid)
    try:
        manifest = AdapterResultManifest.model_validate_json(serialized)
    except ValidationError as error:
        if _path_located(error):
            return ManifestParse.model_validate(
                {**facts, "failure_code": ARTIFACT_PATH_BOUNDARY_VIOLATION}
            )
        return ManifestParse.model_validate(invalid)
    except (ValueError, RecursionError):
        return ManifestParse.model_validate(invalid)
    return ManifestParse.model_validate({**facts, "manifest": manifest})
