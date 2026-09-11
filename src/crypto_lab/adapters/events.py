"""Protocol events, the sanitized run event, the staged line parser and the
invocation event ledger (Stage 6 plan sections 3.9, 3.11, 4, 7.1-7.5; specification
8.2, 10.2, 11.3, 11.5, 14.4, 14.7, 21.2.1).

**Records.** ``ProtocolEventEnvelope`` is the untrusted temporary wire record parsed
from one adapter stdout line (trust class W, token-bearing; specification 11.3 field
order, ``schema_version`` first). Its ``payload`` is a six-way union selected by
``event_type`` -- ``HeartbeatPayload``, ``ProgressPayload``, ``WarningPayload``,
``DiagnosticPayload``, ``ArtifactProducedPayload``, ``FinalResultPayload`` -- and the
pairing is both a validator and six published ``if``/``then`` clauses.
``AdapterDiagnostic`` and ``ProtocolWarning`` report in the adapter's own namespace
(``ADAPTER.`` or ``ENGINE.``) and the three categories an adapter may claim, so a wire
diagnostic cannot spoof a core code or a hard-blocking category (plan 3.9).
``RunEvent`` is the authoritative sanitized event (trust class C): the same content
with ``attempt_token_hash`` in the token's place plus the core's ``received_at_utc``,
the exact-byte ``wire_event_hash`` and the canonical ``content_hash``.

**Identity.** ``content_hash`` is the ``RUN_EVENT_CONTENT_V1`` profile over the ten
content fields -- the nine adapter-authored fields and the core-derived
``attempt_token_hash`` -- with the named exclusions ``content_hash``,
``received_at_utc`` and ``wire_event_hash`` (plan 4; specification 10.2), so an
identical replay under an advanced clock or re-serialized with other whitespace has
the same content.
``wire_event_hash`` is ``sha256`` over the exact line bytes without the terminator,
a source-provenance fingerprint and never a content hash.

**The parser.** ``parse_protocol_line`` receives one framed unit -- the bytes up to
and including one ``\\n``, or an unterminated trailing fragment -- and applies plan
7.4's order: the byte limit over the bytes without the terminator (rule 4, before any
decoding); the framing rules 1-3 (a missing terminator, an interior ``\\n`` or ``\\r``,
an empty line, a byte-order mark, invalid UTF-8 or a first byte other than ``{`` are
``PROTOCOL.STDOUT_CONTAMINATION``); JSON decoding with repeated keys, ``NaN`` and
``Infinity`` refused (a failure is ``PROTOCOL.MALFORMED_JSONL``); a permissive header
read that hashes the line's raw token at once and stores only the hash; the version
check (``PROTOCOL.UNSUPPORTED_VERSION``); the identity and sequence phase of plan 7.3
(``PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`` for a wrong or absent ``invocation_id``, a
member the command kind may not emit, a wrong ``run_id`` or token, an absent or
out-of-range ``sequence`` or a gap; a non-member ``event_type`` falls through to strict
validation); redaction of the decoded object with the line's own, hash-verified token,
exempting only the envelope's ``attempt_token`` key; strict validation over the
redacted object, classifying an error located at a present ``relative_path`` or
``manifest_relative_path`` as ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` and every other
failure as ``PROTOCOL.MALFORMED_JSONL``; the replay decision for a repeated sequence
(identical content is ``EventReplayed``, otherwise a conflicting duplicate); then, for
a new sequence, the plan 7.2 rules -- nothing after ``FINAL_RESULT``, no reused
``event_id``, a non-decreasing heartbeat counter, no repeated declared path and the
three collection bounds -- and finally the ``RunEvent``. No untyped dictionary leaves
the parser: the result is the discriminated ``LineOutcome`` union.

**The ledger.** ``InvocationEventLedger`` is a pure fold over line outcomes;
``from_events`` rebuilds it from persisted events so a restart cannot duplicate an
accepted event, and ``summary`` projects ``ProtocolEventSummary``. Its live-only
redaction total takes no part in equality.

Task-local readings, declared rather than inferred silently:

- The parser's token for redaction and for the rejection sample is the line's own
  ``attempt_token`` and only after its hash equals the acceptance context's; before
  that point (too large, contamination, malformed framing, unsupported version, a
  failed identity) no verified token exists, so the ``ContaminationSample`` carries only
  ``byte_length`` and ``source_hash`` (specification 14.7). A post-identity sample is
  drawn from the redacted decoded object, never from the wire text, because a JSON
  escape can spell the token without a literal occurrence.
- A redaction walk or a re-serialization that exceeds the interpreter's recursion
  depth on a document the JSON decoder accepted is ``PROTOCOL.MALFORMED_JSONL``; the
  parser is total over a framed line and never lets an exception escape.
- ``EventAcceptanceContext`` holds the injected ``Clock`` (the ``FrozenAdapterCatalog``
  precedent) and the parser reads it exactly once per line, for ``received_at_utc`` and
  the rejection diagnostic's ``timestamp_utc``.
- Rejection diagnostics carry ``invocation_id`` alone: the context has no experiment
  correlation and ``Diagnostic`` refuses a ``run_id`` without one; ``details`` carry the
  line's ``byte_length`` and ``source_hash``, never adapter text, so identities are a
  function of the line and the rule that fired.
- ``frame_protocol_lines`` is the pure incremental framer (its carry-over is
  ``pending_bytes``); an unterminated tail over ``max_event_bytes`` is emitted early so
  memory stays bounded and the parser rejects it as too large.
- ``completed_units`` and ``total_units`` are bounded ``0..MAX_COUNTER`` beside the
  plan's ``>= 0`` (plan 3.2, "exact in JSON number space").
- ``ProtocolEventSummary.last_sequence`` equals ``accepted_count`` (sequences are
  contiguous from one) and its declarations are unique on ``relative_path``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, ClassVar, Final, Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.adapters.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
    stage6_diagnostic,
)
from crypto_lab.adapters.limits import (
    MAX_ADAPTER_DIAGNOSTICS,
    MAX_CANDIDATE_ARTIFACTS,
    MAX_CAUSAL_EVENT_IDS,
    MAX_COUNTER,
    MAX_DECLARED_SIZE_BYTES,
    MAX_EVENT_LINE_BYTES,
    MAX_SEQUENCE,
    MAX_WARNINGS,
    PROTOCOL_VERSION,
)
from crypto_lab.adapters.negotiation import _is_utf8_text, _object_without_repeated_keys
from crypto_lab.adapters.paths import RelativeCandidatePath
from crypto_lab.adapters.sanitization import (
    ContaminationSample,
    contamination_sample,
    redact_payload,
)
from crypto_lab.adapters.vocabulary import (
    AdapterDiagnosticCategory,
    ProtocolEventType,
    SemanticStatus,
)
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.comparison_levels import (
    ComparisonLevel,
    sorted_comparison_level_enum,
)
from crypto_lab.domain.descriptors import BoundedText
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    MAX_DETAIL_COLLECTION,
    MAX_DETAIL_NODES,
    BoundedMessage,
    Diagnostic,
    DiagnosticDetailKey,
    DiagnosticDetailValue,
    DiagnosticSeverity,
    _inspect_details,
)
from crypto_lab.domain.financial import NonNegativeDecimal
from crypto_lab.domain.hashing import (
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import (
    AttemptToken,
    EventId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.time import CalendarValidUtcDateTime, format_utc

#: The component the parser's rejection diagnostics name.
SOURCE_COMPONENT: Final = "adapters.events"
#: Plan 3.9: an adapter reports facts in its own namespace.
_ADAPTER_CODE_PATTERN: Final = r"^(?:ADAPTER|ENGINE)(?:\.[A-Z][A-Z0-9_]*)+$"
#: Plan 3.9: the RFC 6838 shape, lowercase.
_MEDIA_TYPE_PATTERN: Final = (
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_MAX_MEDIA_TYPE_CHARACTERS: Final = 255
#: The permissive header bounds: a header value longer than any strict alias could
#: accept reads as MISSING so the identity phase reports absence (plan 3.11).
_MAX_HEADER_TEXT_CHARACTERS: Final = 128
#: The ``attempt_token_hash`` bound: a raw token is 1 through 1024 characters.
_MAX_TOKEN_CHARACTERS: Final = 1024
_HEX_DIGITS: Final = frozenset("0123456789abcdef")
_PATH_FIELDS: Final = frozenset({"relative_path", "manifest_relative_path"})
#: Plan 6.2: the members each command kind may emit; DESCRIBE emits none.
_PERMITTED_EVENT_TYPES: Final[dict[CommandKind, frozenset[ProtocolEventType]]] = {
    CommandKind.VALIDATE: frozenset(
        {
            ProtocolEventType.HEARTBEAT,
            ProtocolEventType.PROGRESS,
            ProtocolEventType.WARNING,
            ProtocolEventType.DIAGNOSTIC,
        }
    ),
    CommandKind.RUN: frozenset(ProtocolEventType),
}

AdapterErrorCode = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=3, max_length=128, pattern=_ADAPTER_CODE_PATTERN
    ),
    WithJsonSchema(
        exact_string_schema(_ADAPTER_CODE_PATTERN, min_length=3, max_length=128)
    ),
]
type MediaType = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=_MAX_MEDIA_TYPE_CHARACTERS,
        pattern=_MEDIA_TYPE_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _MEDIA_TYPE_PATTERN, min_length=3, max_length=_MAX_MEDIA_TYPE_CHARACTERS
        )
    ),
]
_CounterValue = Annotated[int, Field(strict=True, ge=0, le=MAX_COUNTER)]
_DeclaredSize = Annotated[int, Field(strict=True, ge=0, le=MAX_DECLARED_SIZE_BYTES)]
_HeaderText = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=_MAX_HEADER_TEXT_CHARACTERS
    ),
]


def _is_missing(value: object) -> bool:
    return value is MISSING


# --- Adapter-authored value objects (plan 3.9) ---------------------------------------


class AdapterDiagnostic(CanonicalModel):
    """An adapter-reported diagnostic inside an event or manifest (plan 3.9).

    Trust class W inside a wire record, C after sanitization, one shape. It has no
    identity, source component, correlation or timestamp: those are core-derived
    when a later stage persists it, and the envelope carries the instant. The code
    is in the adapter's namespace and the category one of the three an adapter may
    claim.
    """

    error_code: AdapterErrorCode
    category: AdapterDiagnosticCategory
    severity: DiagnosticSeverity
    message: BoundedMessage
    retriable: bool
    details: Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    causal_event_ids: tuple[EventId, ...] = Field(
        max_length=MAX_CAUSAL_EVENT_IDS, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("details")
    @classmethod
    def validate_details(
        cls, value: dict[DiagnosticDetailKey, DiagnosticDetailValue]
    ) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
        """The ``Diagnostic`` detail rules: node and byte bounds, no secret-like key."""
        nodes = _inspect_details(value)
        if nodes > MAX_DETAIL_NODES:
            raise ValueError("diagnostic details contain too many nodes")
        if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
            raise ValueError("diagnostic details exceed maximum encoded bytes")
        return value

    @field_validator("causal_event_ids")
    @classmethod
    def validate_causal_event_ids(
        cls, value: tuple[EventId, ...]
    ) -> tuple[EventId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("causal event identifiers must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("causal event identifiers must be sorted")
        return value


class ProtocolWarning(CanonicalModel):
    """An adapter warning with its comparison-level effect (plan 3.9)."""

    warning_code: AdapterErrorCode
    message: BoundedMessage
    impact: BoundedText
    prevented_comparison_levels: tuple[ComparisonLevel, ...] = Field(
        max_length=len(ComparisonLevel),
        json_schema_extra={"uniqueItems": True, "enum": sorted_comparison_level_enum()},
    )

    @field_validator("prevented_comparison_levels")
    @classmethod
    def validate_prevented_levels(
        cls, value: tuple[ComparisonLevel, ...]
    ) -> tuple[ComparisonLevel, ...]:
        if len(set(value)) != len(value):
            raise ValueError("prevented comparison levels must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("prevented comparison levels must be sorted")
        return value


def _resource_observation_schema_extra(schema: JsonSchemaValue) -> None:
    """Plan 3.9 and 12.4: at least one field present, published as ``anyOf``."""
    schema["anyOf"] = [
        {"required": ["resident_memory_bytes"]},
        {"required": ["cpu_seconds"]},
    ]


class ResourceObservation(CanonicalModel):
    """An optional bounded resource observation on a heartbeat (plan 3.9)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_resource_observation_schema_extra
    )

    resident_memory_bytes: _DeclaredSize | MISSING = MISSING  # type: ignore[valid-type]
    cpu_seconds: NonNegativeDecimal | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_at_least_one_field(self) -> Self:
        if _is_missing(self.resident_memory_bytes) and _is_missing(self.cpu_seconds):
            raise ValueError(
                "at least one of resident_memory_bytes and cpu_seconds must be present"
            )
        return self


# --- The six payloads (plan 3.9) ----------------------------------------------------


class HeartbeatPayload(CanonicalModel):
    """Liveness evidence: a monotonic activity counter and the current phase."""

    activity_counter: int = Field(ge=0, le=MAX_COUNTER)
    phase: NormalizedIdentifier
    resource_observation: ResourceObservation | MISSING = MISSING  # type: ignore[valid-type]


class ProgressPayload(CanonicalModel):
    """Informational progress; never used to infer success (specification 15.3)."""

    phase: NormalizedIdentifier
    completed_units: int = Field(ge=0, le=MAX_COUNTER)
    total_units: _CounterValue | MISSING = MISSING  # type: ignore[valid-type]
    percentage: NonNegativeDecimal | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_units_and_percentage(self) -> Self:
        if (
            not _is_missing(self.total_units)
            and self.total_units < self.completed_units
        ):
            raise ValueError("total_units must be at least completed_units")
        if not _is_missing(self.percentage) and self.percentage > 100:
            raise ValueError("percentage must not exceed 100")
        return self


class WarningPayload(CanonicalModel):
    """A recorded warning that must reappear in a run's manifest (plan 7.2)."""

    warning: ProtocolWarning


class DiagnosticPayload(CanonicalModel):
    """A recorded adapter diagnostic (plan 7.2)."""

    diagnostic: AdapterDiagnostic


class ArtifactProducedPayload(CanonicalModel):
    """One declared candidate: a relative path, kind, media type, size and checksum.

    A lexically valid path is still untrusted; containment is Stage 7 and 9 work.
    """

    relative_path: RelativeCandidatePath
    artifact_kind: NormalizedIdentifier
    media_type: MediaType
    declared_size_bytes: int = Field(ge=0, le=MAX_DECLARED_SIZE_BYTES)
    declared_sha256: Sha256


class FinalResultPayload(CanonicalModel):
    """A pointer to the adapter result manifest; never authoritative by itself."""

    manifest_relative_path: RelativeCandidatePath
    source_adapter_result_manifest_hash: Sha256
    semantic_status: SemanticStatus


_EventPayload = (
    HeartbeatPayload
    | ProgressPayload
    | WarningPayload
    | DiagnosticPayload
    | ArtifactProducedPayload
    | FinalResultPayload
)
#: The payload class each event type selects, in the union's annotation order.
_PAYLOAD_OF: Final[dict[ProtocolEventType, type[CanonicalModel]]] = {
    ProtocolEventType.HEARTBEAT: HeartbeatPayload,
    ProtocolEventType.PROGRESS: ProgressPayload,
    ProtocolEventType.WARNING: WarningPayload,
    ProtocolEventType.DIAGNOSTIC: DiagnosticPayload,
    ProtocolEventType.ARTIFACT_PRODUCED: ArtifactProducedPayload,
    ProtocolEventType.FINAL_RESULT: FinalResultPayload,
}


def _require_payload_pairing(
    event_type: ProtocolEventType, payload: CanonicalModel
) -> None:
    expected = _PAYLOAD_OF[event_type]
    if type(payload) is not expected:
        raise ValueError(
            f"event_type {event_type.value} selects a {expected.__name__} payload"
        )


def _event_pairing_schema_extra(schema: JsonSchemaValue) -> None:
    """Publish the event-type/payload pairing as six ``if``/``then`` clauses.

    Plan 3.9: the pairing is exactly expressible. Pydantic renders ``payload`` as a
    bare six-member ``anyOf`` in annotation order; each clause pins one member by the
    ``event_type`` constant. The branch references are the ones pydantic just emitted
    (the ``envelopes.py`` precedent): a hand-built ``#/$defs/...`` would dangle.
    """
    branches = schema["properties"]["payload"].get("anyOf")
    expected_names = [model.__name__ for model in _PAYLOAD_OF.values()]
    if (
        not isinstance(branches, list)
        or len(branches) != len(expected_names)
        or any(set(branch) != {"$ref"} for branch in branches)
    ):
        raise RuntimeError("the emitted payload union is not a bare anyOf of $refs")
    references: list[str] = []
    for model_name, branch in zip(expected_names, branches, strict=True):
        reference = branch["$ref"]
        emitted_name = str(reference).rsplit("/", 1)[-1].split("-", 1)[0]
        if not isinstance(reference, str) or not (
            emitted_name == model_name or emitted_name.endswith(f"__{model_name}")
        ):
            raise RuntimeError(
                "the payload union branches are not in annotation order: "
                f"{[branch['$ref'] for branch in branches]!r}"
            )
        references.append(reference)
    schema.setdefault("allOf", []).extend(
        {
            "if": {
                "properties": {"event_type": {"const": event_type.value}},
                "required": ["event_type"],
            },
            "then": {"properties": {"payload": {"$ref": reference}}},
        }
        for event_type, reference in zip(_PAYLOAD_OF, references, strict=True)
    )


class ProtocolEventEnvelope(CanonicalModel):
    """The untrusted temporary wire record of one stdout line (plan 3.9).

    Specification 11.3 field order, ``schema_version`` first. Trust class W and
    token-bearing: the raw token is required, hidden from ``repr`` and never
    persisted; the sanitized ``RunEvent`` replaces it with its hash.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_event_pairing_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    event_id: EventId
    invocation_id: InvocationId
    run_id: RunId
    attempt_token: AttemptToken = Field(repr=False)
    sequence: int = Field(ge=1, le=MAX_SEQUENCE)
    event_type: ProtocolEventType
    timestamp_utc: CalendarValidUtcDateTime
    payload: _EventPayload

    @model_validator(mode="after")
    def validate_payload_pairing(self) -> Self:
        _require_payload_pairing(self.event_type, self.payload)
        return self


class RunEvent(CanonicalModel):
    """The authoritative sanitized event (plan 3.9; specification 11.3 row in order).

    Trust class C: ``attempt_token_hash`` in the token's place, the sanitized payload,
    the core receipt instant, the exact-byte ``wire_event_hash`` and the canonical
    ``content_hash``, which must recompute over the ten content fields.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_event_pairing_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    event_id: EventId
    invocation_id: InvocationId
    run_id: RunId
    attempt_token_hash: Sha256
    sequence: int = Field(ge=1, le=MAX_SEQUENCE)
    event_type: ProtocolEventType
    timestamp_utc: CalendarValidUtcDateTime
    payload: _EventPayload
    received_at_utc: CalendarValidUtcDateTime
    wire_event_hash: Sha256
    content_hash: Sha256

    @model_validator(mode="after")
    def validate_pairing_and_content_hash(self) -> Self:
        _require_payload_pairing(self.event_type, self.payload)
        if self.content_hash != run_event_content_hash(self):
            raise ValueError(
                "content_hash must equal the recomputed RUN_EVENT_CONTENT_V1 hash of "
                "the sanitized event content"
            )
        return self


def _content_payload(
    *,
    event_id: str,
    invocation_id: str,
    run_id: str,
    attempt_token_hash: str,
    sequence: int,
    event_type: ProtocolEventType,
    timestamp_utc: datetime,
    payload: CanonicalModel,
) -> dict[str, JsonValue]:
    """The ``RUN_EVENT_CONTENT_V1`` payload of plan 4, assembled in one place.

    The nine adapter-authored fields and the core-derived ``attempt_token_hash``;
    ``received_at_utc``, ``wire_event_hash`` and ``content_hash`` never enter.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "event_id": event_id,
        "invocation_id": invocation_id,
        "run_id": run_id,
        "attempt_token_hash": attempt_token_hash,
        "sequence": sequence,
        "event_type": event_type.value,
        "timestamp_utc": format_utc(timestamp_utc),
        "payload": cast("JsonValue", payload.model_dump(mode="json")),
    }


def run_event_content_hash(event: RunEvent) -> Sha256:
    """Recompute the ``RUN_EVENT_CONTENT_V1`` identity of a run event (plan 4)."""
    if not isinstance(event, RunEvent):
        raise TypeError("event must be a RunEvent")
    return profile_hash(
        HashingProfile.RUN_EVENT_CONTENT_V1,
        _content_payload(
            event_id=event.event_id,
            invocation_id=event.invocation_id,
            run_id=event.run_id,
            attempt_token_hash=event.attempt_token_hash,
            sequence=event.sequence,
            event_type=event.event_type,
            timestamp_utc=event.timestamp_utc,
            payload=event.payload,
        ),
    )


# --- Line outcomes (plan 7.4) ---------------------------------------------------------


class EventAccepted(CanonicalModel):
    """A new sequence accepted: the sanitized event and the redactions it took."""

    outcome: Literal["ACCEPTED"]
    event: RunEvent
    redactions: int = Field(ge=0)


class EventReplayed(CanonicalModel):
    """An identical replay of an accepted sequence: the stored event, no write."""

    outcome: Literal["REPLAYED"]
    event: RunEvent


class EventRejected(CanonicalModel):
    """A rejected line: the Stage 6 diagnostic and the redacted or byte-only sample."""

    outcome: Literal["REJECTED"]
    diagnostic: Diagnostic
    sample: ContaminationSample


type LineOutcome = Annotated[
    EventAccepted | EventReplayed | EventRejected, Field(discriminator="outcome")
]


# --- The summary and the ledger (plan 3.11, 7.5) -----------------------------------


class ArtifactDeclarationRecord(CanonicalModel):
    """One accepted ``ARTIFACT_PRODUCED`` declaration with the event that carried it."""

    event_id: EventId
    payload: ArtifactProducedPayload


class ProtocolEventSummary(CanonicalModel):
    """The ledger's projection for reconciliation (plan 3.11; trust class P)."""

    accepted_count: int = Field(ge=0, le=MAX_SEQUENCE)
    last_sequence: int = Field(ge=0, le=MAX_SEQUENCE)
    artifact_declarations: tuple[ArtifactDeclarationRecord, ...] = Field(
        max_length=MAX_CANDIDATE_ARTIFACTS
    )
    warnings: tuple[ProtocolWarning, ...] = Field(max_length=MAX_WARNINGS)
    final_result: FinalResultPayload | MISSING = MISSING  # type: ignore[valid-type]
    adapter_diagnostics: tuple[AdapterDiagnostic, ...] = Field(
        max_length=MAX_ADAPTER_DIAGNOSTICS
    )
    redactions: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_contiguity_and_uniqueness(self) -> Self:
        if self.last_sequence != self.accepted_count:
            raise ValueError(
                "last_sequence must equal accepted_count: sequences are contiguous"
            )
        paths = [record.payload.relative_path for record in self.artifact_declarations]
        if len(set(paths)) != len(paths):
            raise ValueError("artifact declarations must be unique on relative_path")
        return self


@dataclass(frozen=True, slots=True)
class InvocationEventLedger:
    """The accepted events of one invocation as a pure fold (plan 7.5).

    ``events`` holds the accepted ``RunEvent`` per sequence, so index ``n - 1`` is
    sequence ``n``; the derived facts the plan 7.2 rules need are kept beside them.
    ``redactions`` is the live-only total ``from_events`` initialises to zero and takes
    no part in equality. A fresh ledger is the default construction.

    ``accept`` enforces structure alone (the successor sequence, one invocation, an
    unused ``event_id``); the plan 7.2 stream rules are the parser's, applied before
    an event reaches the ledger, so ``from_events`` trusts a persisted tuple to be
    parser-produced and a tuple that is not may fail its ``summary`` bounds.
    """

    events: tuple[RunEvent, ...] = ()
    event_ids: frozenset[str] = frozenset()
    artifact_paths: frozenset[str] = frozenset()
    warning_count: int = 0
    diagnostic_count: int = 0
    #: ``-1`` while no heartbeat was accepted; counters are non-negative.
    last_heartbeat_counter: int = -1
    final_result_accepted: bool = False
    redactions: int = field(default=0, compare=False)

    @property
    def last_sequence(self) -> int:
        """The highest accepted sequence, zero for a fresh ledger."""
        return len(self.events)

    def accept(self, outcome: LineOutcome) -> InvocationEventLedger:
        """The successor ledger: unchanged for a replay or rejection."""
        if isinstance(outcome, EventReplayed | EventRejected):
            return self
        if not isinstance(outcome, EventAccepted):
            raise TypeError("outcome must be a LineOutcome member")
        event = outcome.event
        if event.sequence != self.last_sequence + 1:
            raise ValueError(
                f"event sequence {event.sequence} is not the successor of "
                f"{self.last_sequence}"
            )
        if self.events and event.invocation_id != self.events[0].invocation_id:
            raise ValueError("the event belongs to another invocation than the ledger")
        if event.event_id in self.event_ids:
            raise ValueError("the event_id was already accepted by this ledger")
        payload = event.payload
        return InvocationEventLedger(
            events=(*self.events, event),
            event_ids=self.event_ids | {event.event_id},
            artifact_paths=(
                self.artifact_paths | {payload.relative_path}
                if isinstance(payload, ArtifactProducedPayload)
                else self.artifact_paths
            ),
            warning_count=self.warning_count + isinstance(payload, WarningPayload),
            diagnostic_count=(
                self.diagnostic_count + isinstance(payload, DiagnosticPayload)
            ),
            last_heartbeat_counter=(
                payload.activity_counter
                if isinstance(payload, HeartbeatPayload)
                else self.last_heartbeat_counter
            ),
            final_result_accepted=(
                self.final_result_accepted or isinstance(payload, FinalResultPayload)
            ),
            redactions=self.redactions + outcome.redactions,
        )

    @classmethod
    def from_events(cls, events: tuple[RunEvent, ...]) -> InvocationEventLedger:
        """Rebuild the ledger of persisted events; restart cannot duplicate one."""
        if type(events) is not tuple:
            raise TypeError("events must be a tuple of RunEvent")
        ledger = cls()
        for event in events:
            if not isinstance(event, RunEvent):
                raise TypeError("events must be a tuple of RunEvent")
            ledger = ledger.accept(
                EventAccepted(outcome="ACCEPTED", event=event, redactions=0)
            )
        return ledger

    def summary(self) -> ProtocolEventSummary:
        """Project the ledger for reconciliation (plan 3.11)."""
        declarations: list[ArtifactDeclarationRecord] = []
        warnings: list[ProtocolWarning] = []
        diagnostics: list[AdapterDiagnostic] = []
        final_result: FinalResultPayload | None = None
        for event in self.events:
            payload = event.payload
            if isinstance(payload, ArtifactProducedPayload):
                declarations.append(
                    ArtifactDeclarationRecord(event_id=event.event_id, payload=payload)
                )
            elif isinstance(payload, WarningPayload):
                warnings.append(payload.warning)
            elif isinstance(payload, DiagnosticPayload):
                diagnostics.append(payload.diagnostic)
            elif isinstance(payload, FinalResultPayload):
                final_result = payload
        facts: dict[str, object] = {
            "accepted_count": len(self.events),
            "last_sequence": len(self.events),
            "artifact_declarations": tuple(declarations),
            "warnings": tuple(warnings),
            "adapter_diagnostics": tuple(diagnostics),
            "redactions": self.redactions,
        }
        if final_result is not None:
            facts["final_result"] = final_result
        return ProtocolEventSummary.model_validate(facts)


# --- The acceptance context (plan 7.4) ------------------------------------------------


def _require_max_event_bytes(value: object) -> int:
    if type(value) is not int:
        raise TypeError("max_event_bytes must be a built-in integer")
    if not 1 <= value <= MAX_EVENT_LINE_BYTES:
        raise ValueError(f"max_event_bytes must be within 1..{MAX_EVENT_LINE_BYTES}")
    return value


@dataclass(frozen=True, slots=True)
class EventAcceptanceContext:
    """What the parser needs to accept one line of one live invocation (plan 7.4).

    The invocation must be ``RUNNING`` and of kind ``VALIDATE`` or ``RUN``; the run's
    ``attempt_token_hash`` is the durable hash the header's token is compared with;
    ``max_event_bytes`` is the request snapshot's limit; ``ledger`` is the state of
    plan 7.5; ``clock`` is the injected receipt clock, read once per line and taking
    no part in equality or ``repr``.
    """

    invocation: CommandInvocationRecord
    attempt_token_hash: Sha256
    max_event_bytes: int
    ledger: InvocationEventLedger
    clock: Clock = field(kw_only=True, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.invocation, CommandInvocationRecord):
            raise TypeError("invocation must be a CommandInvocationRecord")
        if self.invocation.state is not CommandInvocationState.RUNNING:
            raise ValueError(
                "the parser is defined for a RUNNING invocation, not "
                f"{self.invocation.state.value}"
            )
        if self.invocation.command_kind not in _PERMITTED_EVENT_TYPES:
            raise ValueError(
                "stdout events are defined for a VALIDATE or RUN invocation, not "
                f"{self.invocation.command_kind.value}"
            )
        if type(self.attempt_token_hash) is not str:
            raise TypeError("attempt_token_hash must be a built-in string")
        if len(self.attempt_token_hash) != 64 or not (
            set(self.attempt_token_hash) <= _HEX_DIGITS
        ):
            raise ValueError("attempt_token_hash must be a lowercase SHA-256 digest")
        _require_max_event_bytes(self.max_event_bytes)
        if not isinstance(self.ledger, InvocationEventLedger):
            raise TypeError("ledger must be an InvocationEventLedger")
        if not isinstance(self.clock, Clock):
            raise TypeError("clock must implement the Clock protocol")
        if self.ledger.events and (
            self.ledger.events[0].invocation_id != self.invocation.invocation_id
        ):
            raise ValueError("the ledger belongs to another invocation")


# --- The framer (plan 7.1 rules 1 and 3) ---------------------------------------------


def frame_protocol_lines(
    pending_bytes: bytes, chunk: bytes, *, max_event_bytes: int
) -> tuple[tuple[bytes, ...], bytes]:
    """Split ``pending_bytes + chunk`` into complete lines and the new carry-over.

    Every complete line keeps its ``\\n`` terminator. An unterminated tail longer
    than ``max_event_bytes`` is emitted at once without a terminator, so the parser
    rejects it as too large and no unbounded buffer forms; a shorter tail is carried
    forward. At end of stream the caller hands a non-empty carry-over to
    ``parse_protocol_line``, which rejects the fragment as contamination (rule 3); an
    empty carry-over is normal.
    """
    if type(pending_bytes) is not bytes or type(chunk) is not bytes:
        raise TypeError("pending_bytes and chunk must be bytes")
    _require_max_event_bytes(max_event_bytes)
    joined = pending_bytes + chunk
    lines: list[bytes] = []
    start = 0
    while True:
        end = joined.find(b"\n", start)
        if end < 0:
            break
        lines.append(joined[start : end + 1])
        start = end + 1
    remainder = joined[start:]
    if len(remainder) > max_event_bytes:
        lines.append(remainder)
        remainder = b""
    return tuple(lines), remainder


# --- The staged parser (plan 7.4) -----------------------------------------------------


class _EventHeader(CanonicalModel):
    """The permissively read event header (plan 7.4; never published or persisted).

    ``extra="ignore"``. Each field is present only when the line carried a value of
    the right type within its bound; the raw token is hashed at once and only the
    hash is stored, so no header class carries the raw token (plan 13).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    protocol_version: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    schema_version: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    run_id: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    sequence: int | MISSING = MISSING  # type: ignore[valid-type]
    event_type: _HeaderText | MISSING = MISSING  # type: ignore[valid-type]
    attempt_token_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]


_HEADER_TEXT_KEYS: Final[tuple[str, ...]] = (
    "protocol_version",
    "schema_version",
    "invocation_id",
    "run_id",
    "event_type",
)


def _read_header(document: dict[str, object]) -> _EventHeader:
    """Read each header field whose value has the right type and bound (plan 3.11)."""
    facts: dict[str, object] = {}
    for key in _HEADER_TEXT_KEYS:
        value = document.get(key)
        if (
            type(value) is str
            and 1 <= len(value) <= _MAX_HEADER_TEXT_CHARACTERS
            and _is_utf8_text(value)
        ):
            facts[key] = value
    sequence = document.get("sequence")
    if type(sequence) is int:
        facts["sequence"] = sequence
    token = document.get("attempt_token")
    if (
        type(token) is str
        and 1 <= len(token) <= _MAX_TOKEN_CHARACTERS
        and _is_utf8_text(token)
    ):
        facts["attempt_token_hash"] = attempt_token_hash(token)
    return _EventHeader.model_validate(facts)


def _reject_constant(name: str) -> object:
    raise ValueError(f"JSON constant {name} is not permitted")


def _event_type_member(text: object) -> ProtocolEventType | None:
    if type(text) is not str:
        return None
    try:
        return ProtocolEventType(text)
    except ValueError:
        return None


def _path_located(error: ValidationError, expected: type[CanonicalModel]) -> bool:
    """Whether a payload validation error is located at a present path field."""
    for item in error.errors():
        location = item["loc"]
        if not location:
            continue
        last = location[-1]
        if (
            isinstance(last, str)
            and last in _PATH_FIELDS
            and last in expected.model_fields
            and item["type"] != "missing"
        ):
            return True
    return False


def _validate_envelope(
    redacted: dict[str, JsonValue], event_type: ProtocolEventType | None
) -> tuple[ProtocolEventEnvelope | None, str]:
    """Strict validation of the redacted object; the path-located classification.

    The payload is validated first against the class the header's ``event_type``
    selects, so an error at a present ``relative_path`` or ``manifest_relative_path``
    is ``ARTIFACT.PATH_BOUNDARY_VIOLATION``; then the whole envelope is validated in
    JSON mode over the re-serialized object; any other failure is malformed.
    """
    try:
        serialized = json.dumps(redacted, ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, RecursionError):
        return None, PROTOCOL_MALFORMED_JSONL
    if event_type is not None:
        expected = _PAYLOAD_OF[event_type]
        payload_document = redacted.get("payload")
        if type(payload_document) is dict:
            # A subtree of a document that just serialized always serializes.
            try:
                expected.model_validate_json(
                    json.dumps(
                        payload_document, ensure_ascii=False, allow_nan=False
                    ).encode("utf-8")
                )
            except ValidationError as error:
                if _path_located(error, expected):
                    return None, ARTIFACT_PATH_BOUNDARY_VIOLATION
    try:
        return ProtocolEventEnvelope.model_validate_json(serialized), ""
    except (ValidationError, ValueError, RecursionError):
        return None, PROTOCOL_MALFORMED_JSONL


@dataclass(frozen=True, slots=True)
class _Rejecter:
    """Builds the ``EventRejected`` of one line: the diagnostic and the sample.

    ``verified`` is the line's hash-verified token together with the object the
    line decoded to, present only once the identity phase has passed, so the sample
    is drawn from the redacted decoded object rather than from the wire text. The
    raw line stays out of the repr: it may carry the token.
    """

    body: bytes = field(repr=False)
    invocation_id: str
    received_at_utc: datetime

    def __call__(
        self,
        code: str,
        message: str,
        *,
        verified: tuple[str, JsonValue] | None = None,
    ) -> EventRejected:
        if verified is None:
            sample = ContaminationSample(
                byte_length=len(self.body), source_hash=sha256_bytes(self.body)
            )
        else:
            token, decoded = verified
            sample = contamination_sample(self.body, token, decoded=decoded)
        diagnostic = stage6_diagnostic(
            code,
            message,
            source_component=SOURCE_COMPONENT,
            timestamp_utc=self.received_at_utc,
            invocation_id=self.invocation_id,
            details={"byte_length": len(self.body), "source_hash": sample.source_hash},
        )
        return EventRejected(outcome="REJECTED", diagnostic=diagnostic, sample=sample)


def parse_protocol_line(
    line: bytes, *, acceptance: EventAcceptanceContext
) -> LineOutcome:
    """Plan 7.4: classify one framed stdout unit as accepted, replayed or rejected.

    ``line`` is one framed unit: the bytes up to and including one ``\\n``, or an
    unterminated trailing fragment. Pure over its arguments apart from exactly one
    read of the acceptance context's clock; nothing is written and no adapter byte
    enters an error message.
    """
    if type(line) is not bytes:
        raise TypeError("line must be bytes")
    if not isinstance(acceptance, EventAcceptanceContext):
        raise TypeError("acceptance must be an EventAcceptanceContext")
    received_at_utc = acceptance.clock.now_utc()
    invocation = acceptance.invocation
    terminated = line.endswith(b"\n")
    body = line[:-1] if terminated else line
    reject = _Rejecter(body, invocation.invocation_id, received_at_utc)

    # Rule 4: the byte limit, before any decoding.
    if len(body) > acceptance.max_event_bytes:
        return reject(PROTOCOL_EVENT_TOO_LARGE, "stdout line exceeds max_event_bytes")
    # Rules 1-3: framing.
    if not terminated:
        return reject(
            PROTOCOL_STDOUT_CONTAMINATION,
            "stdout ended with an unterminated fragment",
        )
    if not body:
        return reject(PROTOCOL_STDOUT_CONTAMINATION, "stdout carried an empty line")
    if b"\n" in body or b"\r" in body:
        return reject(
            PROTOCOL_STDOUT_CONTAMINATION,
            "stdout line carries a carriage return or an interior line feed",
        )
    if body[:1] != b"{":
        return reject(
            PROTOCOL_STDOUT_CONTAMINATION,
            "stdout line does not begin with a JSON object",
        )
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return reject(PROTOCOL_STDOUT_CONTAMINATION, "stdout line is not valid UTF-8")
    # JSON decoding: repeated keys and non-standard constants are refused.
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_without_repeated_keys,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        return reject(PROTOCOL_MALFORMED_JSONL, "stdout line is not a JSON object")
    # The line began with ``{`` and decoded, so the root is an object.
    header = _read_header(document)
    decoded = cast("JsonValue", document)
    # The version check precedes identity (specification 14.4).
    for version, supported in (
        (header.protocol_version, PROTOCOL_VERSION),
        (header.schema_version, SCHEMA_VERSION),
    ):
        if not _is_missing(version) and version != supported:
            return reject(
                PROTOCOL_UNSUPPORTED_VERSION,
                "event names a protocol or schema version the core does not support",
            )
    # Identity and sequence (plan 7.3).
    if (
        _is_missing(header.invocation_id)
        or header.invocation_id != invocation.invocation_id
    ):
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event invocation_id is missing or is not the live invocation",
        )
    event_type = _event_type_member(header.event_type)
    if (
        event_type is not None
        and event_type not in _PERMITTED_EVENT_TYPES[invocation.command_kind]
    ):
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event type is not permitted for the invocation's command kind",
        )
    if _is_missing(header.run_id) or header.run_id != invocation.run_id:
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event run_id is missing or is not the invocation's run",
        )
    if (
        _is_missing(header.attempt_token_hash)
        or header.attempt_token_hash != acceptance.attempt_token_hash
    ):
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event attempt token is missing or is not the run's attempt token",
        )
    verified_token = document["attempt_token"]
    if type(verified_token) is not str:  # pragma: no cover - the hash proves a str
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event attempt token is missing or is not the run's attempt token",
        )
    sequence = header.sequence
    if _is_missing(sequence) or not 1 <= sequence <= MAX_SEQUENCE:
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event sequence is missing or outside 1..MAX_SEQUENCE",
            verified=(verified_token, decoded),
        )
    ledger = acceptance.ledger
    last = ledger.last_sequence
    if sequence > last + 1:
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event sequence skips the next expected sequence",
            verified=(verified_token, decoded),
        )
    # Redaction before strict validation (plan 7.4, 7.6).
    try:
        redacted, redactions = redact_payload(decoded, verified_token)
    except (ValueError, RecursionError):
        return reject(
            PROTOCOL_MALFORMED_JSONL,
            "event object cannot be redacted without losing a member",
            verified=(verified_token, decoded),
        )
    envelope, code = _validate_envelope(
        cast("dict[str, JsonValue]", redacted), event_type
    )
    if envelope is None:
        message = (
            "event declares a candidate path outside the relative candidate grammar"
            if code == ARTIFACT_PATH_BOUNDARY_VIOLATION
            else "event does not validate as a protocol event envelope"
        )
        return reject(code, message, verified=(verified_token, decoded))
    content_hash = profile_hash(
        HashingProfile.RUN_EVENT_CONTENT_V1,
        _content_payload(
            event_id=envelope.event_id,
            invocation_id=envelope.invocation_id,
            run_id=envelope.run_id,
            attempt_token_hash=acceptance.attempt_token_hash,
            sequence=envelope.sequence,
            event_type=envelope.event_type,
            timestamp_utc=envelope.timestamp_utc,
            payload=envelope.payload,
        ),
    )
    # A repeated sequence: the replay decision precedes every additional rule.
    if sequence <= last:
        stored = ledger.events[sequence - 1]
        if stored.content_hash == content_hash:
            return EventReplayed(outcome="REPLAYED", event=stored)
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            "event repeats an accepted sequence with different content",
            verified=(verified_token, decoded),
        )
    # The plan 7.2 additional rules for a new sequence.
    payload = envelope.payload
    violation: str | None = None
    if ledger.final_result_accepted:
        violation = "no event may follow FINAL_RESULT"
    elif envelope.event_id in ledger.event_ids:
        violation = "event_id was already accepted at another sequence"
    elif isinstance(payload, HeartbeatPayload):
        if payload.activity_counter < ledger.last_heartbeat_counter:
            violation = "heartbeat activity_counter decreased"
    elif isinstance(payload, ArtifactProducedPayload):
        if payload.relative_path in ledger.artifact_paths:
            violation = "artifact relative_path was already declared"
        elif len(ledger.artifact_paths) >= MAX_CANDIDATE_ARTIFACTS:
            violation = "artifact declarations exceed MAX_CANDIDATE_ARTIFACTS"
    elif isinstance(payload, WarningPayload):
        if ledger.warning_count >= MAX_WARNINGS:
            violation = "warnings exceed MAX_WARNINGS"
    elif isinstance(payload, DiagnosticPayload):
        if ledger.diagnostic_count >= MAX_ADAPTER_DIAGNOSTICS:
            violation = "diagnostics exceed MAX_ADAPTER_DIAGNOSTICS"
    if violation is not None:
        return reject(
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            violation,
            verified=(verified_token, decoded),
        )
    event = RunEvent.model_validate(
        {
            "schema_version": envelope.schema_version,
            "protocol_version": envelope.protocol_version,
            "event_id": envelope.event_id,
            "invocation_id": envelope.invocation_id,
            "run_id": envelope.run_id,
            "attempt_token_hash": acceptance.attempt_token_hash,
            "sequence": envelope.sequence,
            "event_type": envelope.event_type,
            "timestamp_utc": envelope.timestamp_utc,
            "payload": payload,
            "received_at_utc": received_at_utc,
            "wire_event_hash": sha256_bytes(body),
            "content_hash": content_hash,
        }
    )
    return EventAccepted(outcome="ACCEPTED", event=event, redactions=redactions)
