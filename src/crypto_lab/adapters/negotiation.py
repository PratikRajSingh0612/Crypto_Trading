"""Bootstrap descriptor envelope, protocol negotiation and the describe parse and
observation projections (Stage 6 plan sections 3.8, 3.11, 5.1-5.4; specification
8.2, 11.3, 11.5, 14.2, 21.2.1).

``BootstrapDescriptorEnvelope`` is the untrusted ``describe`` output file (trust
class W, token-free): the specification 14.2 fixed header --
``bootstrap_schema_version``, adapter and engine identity, executable hash, supported
protocol and schema versions, the plural capability-vocabulary versions and the
descriptor payload hash -- around the nested ``AdapterDescriptor``. Every header
field must equal the descriptor field it mirrors, the descriptor's single vocabulary
must be among the declared vocabularies, and ``descriptor_payload_hash`` must
recompute as ``sha256(canonical_json_bytes(descriptor))`` (plan 4: exact-byte and
stdlib-reproducible, outside the profile envelope). ``CoreProtocolSupport`` (trust
class K) is what the core supports; ``CORE_PROTOCOL_SUPPORT`` pins protocol
``1.0.0``, the five negotiable schema names at ``1.0.0`` and ``capabilities/v1``
under policy ``negotiation/v1``.

``negotiate_protocol`` is pure (specification 14.2): every candidate tuple is the
numerically sorted intersection of the core's and the adapter's declarations, the
protocol selection is ``highest_common_stable_version``, every negotiable schema
name must have a common version and the numerically highest is selected, and the
vocabulary selection is the numerically highest common ``capabilities/vN``, which
must also be the vocabulary the descriptor's capability claims were made in. Any
empty intersection or vocabulary disagreement fails closed: outcome ``FAILED``,
no selected field, ``reason_codes == ("ADAPTER.UNAVAILABLE",)`` (specification
21.2.1 "version negotiation empty"). The core never guesses a version and never
downgrades. ``negotiated_versions_of`` projects a ``NEGOTIATED`` result into the
``NegotiatedVersions`` the request pins.

``NegotiationResult`` (trust class C) is the specification 11.3 row plus
``adapter_version`` and the 14.2 policy version. ``reason_codes`` is the plan's
**declared deviation** from the 11.3 minimum field name ``diagnostics`` (plan 3.8,
12.4 register): a ``Diagnostic`` would need an invocation this pure function does
not see and would nest the legacy timestamp grammar into a published schema.

``parse_bootstrap_descriptor`` is the byte-level half of the ``describe`` flow
(plan 3.11, 5.4): the byte ceiling is applied before any decoding, the bytes are
decoded as strict UTF-8 and parsed with ``json``, a JSON object yields the
permissively read ``DescriptorHeader`` (each field kept only when it is a string
within its bound, ``MISSING`` otherwise, so a wrongly typed or over-long identity
reports absence at the reconciler's identity check), an unsupported readable
``bootstrap_schema_version`` is ``PROTOCOL.UNSUPPORTED_VERSION``, and strict
validation of the same bytes yields either the envelope or
``PROTOCOL.DESCRIBE_OUTPUT_INVALID``. Oversized, non-UTF-8 and non-object bytes carry
no header at all. Record-level reconciliation (``reconcile_describe``) is Task 6.

``describe_availability_observation`` projects any terminal describe into the Stage 4
``RuntimeAvailabilityObservation`` (plan 5.4): ``available`` is true exactly for
verdict ``DESCRIBED``; otherwise the caller's ``primary_code`` -- the reconciliation's
primary after ``EXITED`` or ``PROCESS.DESCRIBE_TIMED_OUT`` for a describe whose
deadline won -- is the ``reason_code``. Network and credential flags are copied from
the descriptor when present and are ``False`` otherwise. Identity, instants and
runtime facts are caller-supplied; nothing here reads a clock.

Task-local readings, declared rather than inferred silently:

- The sort helpers and the vocabulary ordinal are imported from
  ``adapters/envelopes.py`` so the describe, bootstrap and negotiation collections
  share one order (``1.9.0`` before ``1.10.0``; ``capabilities/v9`` before ``v10``).
- The envelope's ``supported_protocol_versions`` (1..32) and
  ``supported_schema_versions`` (1..128) bounds mirror the descriptor's, because
  header/descriptor equality requires it; ``capability_vocabulary_versions`` is 1..8.
- ``CoreProtocolSupport.protocol_versions`` is a ``SemanticVersion`` tuple rather than
  a literal so numeric selection is testable; ``negotiated_versions_of`` refuses a
  selection other than ``PROTOCOL_VERSION`` by name because the request pins the
  literal. Its ``schema_versions`` must name exactly the negotiable five, each at
  least once (several versions per name are permitted).
- ``NegotiationResult`` additionally requires every selected value to be a member of
  its candidate tuple (specification 11.3 "selected values belong to intersections"),
  ``selected_schema_versions`` to name exactly the five negotiable names once each
  (so ``negotiated_versions_of`` is total on ``NEGOTIATED``), and every candidate
  schema name to be negotiable (candidates are intersections with the core's set).
- ``DescriptorHeader`` bounds are the strict alias maxima (128 for the identifier,
  64 for the versions and the hash); an empty, wrongly typed, longer or
  non-UTF-8-encodable value (a lone surrogate escape ``json`` accepts and
  pydantic-core refuses) is read as ``MISSING``, so the header never raises.
- ``parse_bootstrap_descriptor`` decodes strict UTF-8 before ``json.loads`` so UTF-16
  is rejected rather than auto-detected (a UTF-8 byte-order mark survives the decode
  and is refused by the JSON parser), rejects a repeated object key at any depth as
  non-object bytes (the permissive and the strict parser could otherwise keep
  different values and the header would misreport identity), treats ``ValueError``
  (``JSONDecodeError``, ``UnicodeDecodeError``, the repeated key) and
  ``RecursionError`` as non-object bytes, and validates with ``model_validate_json``
  over the same bytes (JSON mode; strict python mode would reject the decoded lists).
  ``max_bytes`` is bounded by the compiled ``MAX_DESCRIPTOR_OUTPUT_BYTES`` ceiling.
- ``describe_availability_observation`` takes every input keyword-only without
  defaults, requires a descriptor for ``DESCRIBED``, requires the descriptor's
  identity to equal the supplied catalog identity, requires ``primary_code`` to be a
  Stage 6 code and refuses ``PROCESS.CANCELLED`` (plan 5.4: a cancelled describe mints
  no observation).
- Published exactly (for the Task 9 register): ``uniqueItems`` on every sorted-unique
  tuple; on ``NegotiationResult`` the ``NEGOTIATED``/``FAILED`` biconditional as two
  ``if``/``then`` clauses, the five names by position on ``selected_schema_versions``
  and the negotiable-name enumeration on ``candidate_schema_versions`` items.
  Runtime-only: numeric sortedness, selected-in-candidates, header/descriptor
  equality, ``descriptor_payload_hash`` recomputation, the vocabulary membership.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    PROCESS_CANCELLED,
    PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    PROTOCOL_UNSUPPORTED_VERSION,
    STAGE6_DIAGNOSTIC_CODES,
)
from crypto_lab.adapters.envelopes import (
    NegotiatedVersions,
    _unique_sorted_schema_versions,
    _unique_sorted_versions,
    _unique_sorted_vocabularies,
    _vocabulary_ordinal,
)
from crypto_lab.adapters.limits import MAX_DESCRIPTOR_OUTPUT_BYTES, PROTOCOL_VERSION
from crypto_lab.adapters.versioning import highest_common_stable_version
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    NegotiationOutcome,
    ReconciliationVerdict,
)
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_names import VocabularyVersion
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    ExecutablePath,
    OperatingSystem,
    RuntimeAvailabilityObservation,
    SupportedSchemaVersion,
)
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    NormalizedIdentifier,
    Sha256,
)
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

#: Specification 14.2: the negotiation policy version a ``NegotiationResult`` records.
NEGOTIATION_POLICY_VERSION: Final = "negotiation/v1"
#: Specification 13.1: the initial capability vocabulary the core supports.
_CORE_VOCABULARY_VERSION: Final = "capabilities/v1"
#: The merged ``AdapterDescriptor`` collection bounds, mirrored on the envelope.
_MAX_PROTOCOL_VERSIONS: Final = 32
_MAX_SCHEMA_VERSIONS: Final = 128
#: Plan 3.8: the bootstrap envelope's vocabulary bound and the reason-code bound.
_MAX_VOCABULARY_VERSIONS: Final = 8
_MAX_REASON_CODES: Final = 8
_NEGOTIABLE_COUNT: Final = len(NEGOTIABLE_SCHEMA_NAMES)
_NEGOTIABLE_SET: Final[frozenset[str]] = frozenset(NEGOTIABLE_SCHEMA_NAMES)
#: Plan 3.11: the two codes a descriptor parse can record.
_DESCRIPTOR_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {PROTOCOL_DESCRIBE_OUTPUT_INVALID, PROTOCOL_UNSUPPORTED_VERSION}
)
#: Plan 5.4: the two verdicts a describe reconciliation can reach.
_DESCRIBE_VERDICTS: Final[frozenset[ReconciliationVerdict]] = frozenset(
    {ReconciliationVerdict.DESCRIBED, ReconciliationVerdict.DESCRIBE_UNAVAILABLE}
)
#: The strict alias maxima (``NormalizedIdentifier`` 128; ``SemanticVersion`` and
#: ``Sha256`` 64): a header value longer than the alias could ever accept is read as
#: ``MISSING`` so the identity check reports absence (plan 3.11).
_MAX_HEADER_IDENTIFIER_CHARACTERS: Final = 128
_MAX_HEADER_VERSION_CHARACTERS: Final = 64
_MAX_HEADER_HASH_CHARACTERS: Final = 64
_SELECTED_FIELDS: Final[tuple[str, ...]] = (
    "selected_protocol_version",
    "selected_schema_versions",
    "selected_vocabulary_version",
)

_HeaderIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=_MAX_HEADER_IDENTIFIER_CHARACTERS
    ),
]
_HeaderVersion = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=_MAX_HEADER_VERSION_CHARACTERS
    ),
]
_HeaderHash = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=_MAX_HEADER_HASH_CHARACTERS
    ),
]
_SelectedSchemaVersions = Annotated[
    tuple[SupportedSchemaVersion, ...],
    Field(
        min_length=_NEGOTIABLE_COUNT,
        max_length=_NEGOTIABLE_COUNT,
        json_schema_extra={"uniqueItems": True},
    ),
]


def _is_missing(value: object) -> bool:
    return value is MISSING


def _descriptor_payload_hash(descriptor: AdapterDescriptor) -> Sha256:
    """Plan 4: ``sha256(canonical_json_bytes(descriptor))``, exact-byte and
    stdlib-reproducible, deliberately outside the profile envelope."""
    return sha256_bytes(canonical_json_bytes(descriptor))


def _require_negotiable_names(
    value: tuple[SupportedSchemaVersion, ...], label: str
) -> tuple[SupportedSchemaVersion, ...]:
    if any(item.schema_name not in _NEGOTIABLE_SET for item in value):
        raise ValueError(f"{label} may name only the negotiable schema names")
    return value


# --- The bootstrap descriptor envelope --------------------------------------------


class BootstrapDescriptorEnvelope(CanonicalModel):
    """The untrusted ``describe`` output (plan 3.8; specification 14.2 fixed fields).

    Trust class W and token-free. ``bootstrap_schema_version`` replaces
    ``schema_version`` (plan 3.1). Every header field mirrors a descriptor field,
    the descriptor's vocabulary is among the declared vocabularies and the payload
    hash recomputes; each collection is bounded, unique and numerically sorted.
    """

    bootstrap_schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion
    executable_hash: Sha256
    supported_protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1,
        max_length=_MAX_PROTOCOL_VERSIONS,
        json_schema_extra={"uniqueItems": True},
    )
    supported_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1,
        max_length=_MAX_SCHEMA_VERSIONS,
        json_schema_extra={"uniqueItems": True},
    )
    capability_vocabulary_versions: tuple[VocabularyVersion, ...] = Field(
        min_length=1,
        max_length=_MAX_VOCABULARY_VERSIONS,
        json_schema_extra={"uniqueItems": True},
    )
    descriptor_payload_hash: Sha256
    descriptor: AdapterDescriptor

    @field_validator("supported_protocol_versions")
    @classmethod
    def validate_protocol_versions(
        cls, value: tuple[SemanticVersion, ...]
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "supported protocol versions")

    @field_validator("supported_schema_versions")
    @classmethod
    def validate_schema_versions(
        cls, value: tuple[SupportedSchemaVersion, ...]
    ) -> tuple[SupportedSchemaVersion, ...]:
        return _unique_sorted_schema_versions(value, "supported schema versions")

    @field_validator("capability_vocabulary_versions")
    @classmethod
    def validate_vocabulary_versions(
        cls, value: tuple[VocabularyVersion, ...]
    ) -> tuple[VocabularyVersion, ...]:
        return _unique_sorted_vocabularies(value, "capability vocabulary versions")

    @model_validator(mode="after")
    def validate_header_mirrors_descriptor(self) -> Self:
        """Plan 3.8: the seven mirrored fields, the vocabulary membership and the
        payload hash. Messages name fields, never values."""
        descriptor = self.descriptor
        engine = descriptor.engine
        mirrored: tuple[tuple[str, str, object, object], ...] = (
            (
                "adapter_name",
                "adapter_name",
                self.adapter_name,
                descriptor.adapter_name,
            ),
            (
                "adapter_version",
                "adapter_version",
                self.adapter_version,
                descriptor.adapter_version,
            ),
            ("engine_name", "engine.engine_name", self.engine_name, engine.engine_name),
            (
                "engine_version",
                "engine.engine_version",
                self.engine_version,
                engine.engine_version,
            ),
            (
                "executable_hash",
                "executable_hash",
                self.executable_hash,
                descriptor.executable_hash,
            ),
            (
                "supported_protocol_versions",
                "supported_protocol_versions",
                self.supported_protocol_versions,
                descriptor.supported_protocol_versions,
            ),
            (
                "supported_schema_versions",
                "supported_schema_versions",
                self.supported_schema_versions,
                descriptor.supported_schema_versions,
            ),
        )
        for header_field, descriptor_field, header_value, described in mirrored:
            if header_value != described:
                raise ValueError(
                    f"{header_field} must equal the descriptor's {descriptor_field}"
                )
        if descriptor.capability_vocabulary_version not in (
            self.capability_vocabulary_versions
        ):
            raise ValueError(
                "the descriptor's capability_vocabulary_version must be among "
                "capability_vocabulary_versions"
            )
        if self.descriptor_payload_hash != _descriptor_payload_hash(descriptor):
            raise ValueError(
                "descriptor_payload_hash must equal the SHA-256 of the canonical "
                "descriptor"
            )
        return self


# --- Core support and negotiation ---------------------------------------------------


class CoreProtocolSupport(CanonicalModel):
    """What the core supports (plan 3.8; trust class K, so no envelope version).

    The five negotiable schema names must each appear at least once; several
    versions of one name are permitted so negotiation selects the highest.
    """

    protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1, max_length=_MAX_PROTOCOL_VERSIONS
    )
    schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1, max_length=_MAX_SCHEMA_VERSIONS
    )
    vocabulary_versions: tuple[VocabularyVersion, ...] = Field(
        min_length=1, max_length=_MAX_VOCABULARY_VERSIONS
    )
    negotiation_policy_version: Literal["negotiation/v1"]

    @field_validator("protocol_versions")
    @classmethod
    def validate_protocol_versions(
        cls, value: tuple[SemanticVersion, ...]
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "core protocol versions")

    @field_validator("schema_versions")
    @classmethod
    def validate_schema_versions(
        cls, value: tuple[SupportedSchemaVersion, ...]
    ) -> tuple[SupportedSchemaVersion, ...]:
        _unique_sorted_schema_versions(value, "core schema versions")
        if {item.schema_name for item in value} != _NEGOTIABLE_SET:
            raise ValueError(
                "core schema_versions must name exactly the negotiable schema names"
            )
        return value

    @field_validator("vocabulary_versions")
    @classmethod
    def validate_vocabulary_versions(
        cls, value: tuple[VocabularyVersion, ...]
    ) -> tuple[VocabularyVersion, ...]:
        return _unique_sorted_vocabularies(value, "core vocabulary versions")


#: Plan 3.8 and 5.2: protocol ``1.0.0``, the five negotiable names at ``1.0.0``,
#: ``capabilities/v1``, policy ``negotiation/v1``.
CORE_PROTOCOL_SUPPORT: Final = CoreProtocolSupport(
    protocol_versions=(PROTOCOL_VERSION,),
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version=SCHEMA_VERSION)
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    vocabulary_versions=(_CORE_VOCABULARY_VERSION,),
    negotiation_policy_version=NEGOTIATION_POLICY_VERSION,
)


def _negotiation_result_schema_extra(schema: JsonSchemaValue) -> None:
    """Publish the exactly expressible rules of plan 3.8 and 12.4.

    Two ``if``/``then`` clauses over ``outcome`` (``NEGOTIATED`` requires the three
    selected fields and an empty ``reason_codes``; ``FAILED`` forbids each selected
    field and requires a reason), the five names by position on
    ``selected_schema_versions`` and the negotiable-name enumeration on the
    ``candidate_schema_versions`` items. The element references are the ones pydantic
    emitted (the ``envelopes.py`` precedent); a hand-built ``#/$defs/...`` would dangle.
    """
    properties = schema["properties"]
    selected = properties["selected_schema_versions"]
    selected_items = selected.get("items")
    if not isinstance(selected_items, dict) or set(selected_items) != {"$ref"}:
        raise RuntimeError(
            "the emitted selected_schema_versions items is not a bare $ref"
        )
    selected["prefixItems"] = [
        {
            "allOf": [
                {"$ref": selected_items["$ref"]},
                {
                    "properties": {"schema_name": {"const": name}},
                    "required": ["schema_name"],
                },
            ]
        }
        for name in NEGOTIABLE_SCHEMA_NAMES
    ]
    candidates = properties["candidate_schema_versions"]
    candidate_items = candidates.get("items")
    if not isinstance(candidate_items, dict) or set(candidate_items) != {"$ref"}:
        raise RuntimeError(
            "the emitted candidate_schema_versions items is not a bare $ref"
        )
    candidates["items"] = {
        "allOf": [
            {"$ref": candidate_items["$ref"]},
            {
                "properties": {"schema_name": {"enum": list(NEGOTIABLE_SCHEMA_NAMES)}},
                "required": ["schema_name"],
            },
        ]
    }
    negotiated = NegotiationOutcome.NEGOTIATED.value
    failed = NegotiationOutcome.FAILED.value
    schema.setdefault("allOf", []).extend(
        (
            {
                "if": {
                    "properties": {"outcome": {"const": negotiated}},
                    "required": ["outcome"],
                },
                "then": {
                    "required": list(_SELECTED_FIELDS),
                    "properties": {"reason_codes": {"maxItems": 0}},
                },
            },
            {
                "if": {
                    "properties": {"outcome": {"const": failed}},
                    "required": ["outcome"],
                },
                "then": {
                    "not": {
                        "anyOf": [{"required": [name]} for name in _SELECTED_FIELDS]
                    },
                    "properties": {"reason_codes": {"minItems": 1}},
                },
            },
        )
    )


class NegotiationResult(CanonicalModel):
    """Deterministic protocol, schema and vocabulary selection (plan 3.8).

    Specification 11.3's row plus ``adapter_version`` and the 14.2 policy version.
    Trust class C. ``NEGOTIATED`` carries every selected value, each a member of its
    candidate intersection, and no reason code; ``FAILED`` carries no selected value
    and at least one reason code. ``reason_codes`` is the declared deviation from
    the 11.3 field name ``diagnostics`` (module docstring).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_negotiation_result_schema_extra
    )

    schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    candidate_protocol_versions: tuple[SemanticVersion, ...] = Field(
        max_length=_MAX_PROTOCOL_VERSIONS, json_schema_extra={"uniqueItems": True}
    )
    candidate_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        max_length=_MAX_SCHEMA_VERSIONS, json_schema_extra={"uniqueItems": True}
    )
    candidate_vocabulary_versions: tuple[VocabularyVersion, ...] = Field(
        max_length=_MAX_VOCABULARY_VERSIONS, json_schema_extra={"uniqueItems": True}
    )
    selected_protocol_version: SemanticVersion | MISSING = MISSING  # type: ignore[valid-type]
    selected_schema_versions: _SelectedSchemaVersions | MISSING = MISSING  # type: ignore[valid-type]
    selected_vocabulary_version: VocabularyVersion | MISSING = MISSING  # type: ignore[valid-type]
    negotiation_policy_version: Literal["negotiation/v1"]
    outcome: NegotiationOutcome
    reason_codes: tuple[ErrorCode, ...] = Field(
        max_length=_MAX_REASON_CODES, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("candidate_protocol_versions")
    @classmethod
    def validate_candidate_protocol_versions(
        cls, value: tuple[SemanticVersion, ...]
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "candidate protocol versions")

    @field_validator("candidate_schema_versions")
    @classmethod
    def validate_candidate_schema_versions(
        cls, value: tuple[SupportedSchemaVersion, ...]
    ) -> tuple[SupportedSchemaVersion, ...]:
        _unique_sorted_schema_versions(value, "candidate schema versions")
        return _require_negotiable_names(value, "candidate schema versions")

    @field_validator("candidate_vocabulary_versions")
    @classmethod
    def validate_candidate_vocabulary_versions(
        cls, value: tuple[VocabularyVersion, ...]
    ) -> tuple[VocabularyVersion, ...]:
        return _unique_sorted_vocabularies(value, "candidate vocabulary versions")

    @field_validator("selected_schema_versions")
    @classmethod
    def validate_selected_schema_versions(
        cls, value: tuple[SupportedSchemaVersion, ...]
    ) -> tuple[SupportedSchemaVersion, ...]:
        if _is_missing(value):
            return value
        _unique_sorted_schema_versions(value, "selected schema versions")
        if tuple(item.schema_name for item in value) != NEGOTIABLE_SCHEMA_NAMES:
            raise ValueError(
                "selected_schema_versions must name exactly the negotiable schema "
                "names, once each"
            )
        return value

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(
        cls, value: tuple[ErrorCode, ...]
    ) -> tuple[ErrorCode, ...]:
        if len(set(value)) != len(value):
            raise ValueError("reason codes must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("reason codes must be sorted")
        return value

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        """Plan 3.8 biconditionals, then specification 11.3 membership."""
        present = tuple(
            not _is_missing(getattr(self, name)) for name in _SELECTED_FIELDS
        )
        if self.outcome is NegotiationOutcome.NEGOTIATED:
            if not all(present) or self.reason_codes:
                raise ValueError(
                    "a NEGOTIATED result carries every selected version and no "
                    "reason code"
                )
            if self.selected_protocol_version not in self.candidate_protocol_versions:
                raise ValueError("selected_protocol_version must be a candidate")
            if any(
                item not in self.candidate_schema_versions
                for item in self.selected_schema_versions
            ):
                raise ValueError("every selected schema version must be a candidate")
            if self.selected_vocabulary_version not in (
                self.candidate_vocabulary_versions
            ):
                raise ValueError("selected_vocabulary_version must be a candidate")
        elif any(present) or not self.reason_codes:
            raise ValueError(
                "a FAILED result carries no selected version and at least one "
                "reason code"
            )
        return self


def negotiate_protocol(
    envelope: BootstrapDescriptorEnvelope,
    support: CoreProtocolSupport = CORE_PROTOCOL_SUPPORT,
) -> NegotiationResult:
    """Plan 5.3: the pure deterministic selection (specification 14.2).

    Protocol candidates are the numerically sorted intersection and the selection is
    ``highest_common_stable_version``; every negotiable schema name needs a common
    version and the numerically highest is selected; the vocabulary selection is the
    numerically highest common version and must equal the descriptor's own. Any
    failure records ``ADAPTER.UNAVAILABLE`` and leaves every selected field absent;
    the candidate intersections are recorded either way.
    """
    if not isinstance(envelope, BootstrapDescriptorEnvelope):
        raise TypeError("envelope must be a BootstrapDescriptorEnvelope")
    if not isinstance(support, CoreProtocolSupport):
        raise TypeError("support must be a CoreProtocolSupport")

    protocol_candidates = tuple(
        sorted(
            set(support.protocol_versions) & set(envelope.supported_protocol_versions),
            key=parse_semantic_version,
        )
    )
    selected_protocol = highest_common_stable_version(
        support.protocol_versions, envelope.supported_protocol_versions
    )

    core_pairs = {
        (item.schema_name, item.schema_version) for item in support.schema_versions
    }
    adapter_pairs = {
        (item.schema_name, item.schema_version)
        for item in envelope.supported_schema_versions
    }
    schema_candidates = tuple(
        SupportedSchemaVersion(schema_name=name, schema_version=version)
        for name, version in sorted(
            core_pairs & adapter_pairs,
            key=lambda pair: (pair[0], parse_semantic_version(pair[1])),
        )
    )
    highest_by_name: dict[str, str] = {}
    for item in schema_candidates:
        current = highest_by_name.get(item.schema_name)
        if current is None or parse_semantic_version(item.schema_version) > (
            parse_semantic_version(current)
        ):
            highest_by_name[item.schema_name] = item.schema_version
    selected_schemas: tuple[SupportedSchemaVersion, ...] | None = None
    if all(name in highest_by_name for name in NEGOTIABLE_SCHEMA_NAMES):
        selected_schemas = tuple(
            SupportedSchemaVersion(
                schema_name=name, schema_version=highest_by_name[name]
            )
            for name in NEGOTIABLE_SCHEMA_NAMES
        )

    vocabulary_candidates = tuple(
        sorted(
            set(support.vocabulary_versions)
            & set(envelope.capability_vocabulary_versions),
            key=_vocabulary_ordinal,
        )
    )
    selected_vocabulary = vocabulary_candidates[-1] if vocabulary_candidates else None
    if selected_vocabulary != envelope.descriptor.capability_vocabulary_version:
        selected_vocabulary = None

    negotiated = (
        selected_protocol is not None
        and selected_schemas is not None
        and selected_vocabulary is not None
    )
    outcome = NegotiationOutcome.NEGOTIATED if negotiated else NegotiationOutcome.FAILED
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "adapter_name": envelope.adapter_name,
        "adapter_version": envelope.adapter_version,
        "candidate_protocol_versions": protocol_candidates,
        "candidate_schema_versions": schema_candidates,
        "candidate_vocabulary_versions": vocabulary_candidates,
        "negotiation_policy_version": support.negotiation_policy_version,
        "outcome": outcome,
        "reason_codes": () if negotiated else (ADAPTER_UNAVAILABLE,),
    }
    if negotiated:
        payload["selected_protocol_version"] = selected_protocol
        payload["selected_schema_versions"] = selected_schemas
        payload["selected_vocabulary_version"] = selected_vocabulary
    return NegotiationResult.model_validate(payload)


def negotiated_versions_of(result: NegotiationResult) -> NegotiatedVersions:
    """Plan 5.3: project a ``NEGOTIATED`` result into the request's pinned versions.

    A ``FAILED`` result projects nothing, and a selection other than
    ``PROTOCOL_VERSION`` is refused by name because ``NegotiatedVersions`` pins the
    literal the core supports (plan 5.1).
    """
    if not isinstance(result, NegotiationResult):
        raise TypeError("result must be a NegotiationResult")
    if result.outcome is not NegotiationOutcome.NEGOTIATED:
        raise ValueError("a FAILED negotiation projects no negotiated versions")
    if result.selected_protocol_version != PROTOCOL_VERSION:
        raise ValueError(
            f"selected protocol version {result.selected_protocol_version} is not the "
            f"protocol version {PROTOCOL_VERSION} the request pins"
        )
    return NegotiatedVersions(
        protocol_version=PROTOCOL_VERSION,
        schema_versions=result.selected_schema_versions,
        capability_vocabulary_version=result.selected_vocabulary_version,
    )


# --- The describe output parse ------------------------------------------------------


class DescriptorHeader(CanonicalModel):
    """The permissively read describe header (plan 3.11; nested, never published).

    ``extra="ignore"``: unknown keys are not a header failure. Each field is present
    only when the document carried a string within the strict alias bound, so a
    wrongly typed, empty or over-long identity reads as ``MISSING`` and the
    reconciler's identity check reports absence.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    bootstrap_schema_version: _HeaderVersion | MISSING = MISSING  # type: ignore[valid-type]
    adapter_name: _HeaderIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    adapter_version: _HeaderVersion | MISSING = MISSING  # type: ignore[valid-type]
    executable_hash: _HeaderHash | MISSING = MISSING  # type: ignore[valid-type]


_HEADER_BOUNDS: Final[tuple[tuple[str, int], ...]] = (
    ("bootstrap_schema_version", _MAX_HEADER_VERSION_CHARACTERS),
    ("adapter_name", _MAX_HEADER_IDENTIFIER_CHARACTERS),
    ("adapter_version", _MAX_HEADER_VERSION_CHARACTERS),
    ("executable_hash", _MAX_HEADER_HASH_CHARACTERS),
)


def _is_utf8_text(value: str) -> bool:
    """Whether ``value`` can be UTF-8 encoded.

    ``json.loads`` accepts a lone surrogate escape such as ``\\ud800`` and yields a
    string that neither pydantic-core nor ``canonical_json_bytes`` can represent;
    such a value is read as ``MISSING`` so the header never raises.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _descriptor_header(document: dict[str, object]) -> DescriptorHeader:
    """Read each header field when it is a UTF-8 string within its bound, else omit
    it (plan 3.11: the header readers never fail on a JSON object)."""
    payload: dict[str, str] = {}
    for key, bound in _HEADER_BOUNDS:
        value = document.get(key)
        if type(value) is str and 1 <= len(value) <= bound and _is_utf8_text(value):
            payload[key] = value
    return DescriptorHeader.model_validate(payload)


def _object_without_repeated_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """``json.loads`` object hook: a repeated key at any depth is not a JSON object
    under the protocol, because the permissive and the strict parser could keep
    different values of it and the header would then misreport identity."""
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("repeated JSON object key")
        document[key] = value
    return document


class DescriptorParse(CanonicalModel):
    """The byte-level outcome of one describe output file (plan 3.11; trust class P).

    Exactly one of ``envelope`` and ``failure_code`` is present. ``header`` is absent
    only for oversized, non-UTF-8 or non-object bytes, which are always
    ``PROTOCOL.DESCRIBE_OUTPUT_INVALID``; a present envelope agrees with its header;
    ``PROTOCOL.UNSUPPORTED_VERSION`` is recorded exactly when the header carries a
    readable version other than ``1.0.0``.
    """

    byte_length: int = Field(ge=0)
    source_hash: Sha256
    header: DescriptorHeader | MISSING = MISSING  # type: ignore[valid-type]
    envelope: BootstrapDescriptorEnvelope | MISSING = MISSING  # type: ignore[valid-type]
    failure_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        envelope_present = not _is_missing(self.envelope)
        failure_present = not _is_missing(self.failure_code)
        header_present = not _is_missing(self.header)
        if envelope_present is failure_present:
            raise ValueError(
                "exactly one of envelope and failure_code is present on a parse"
            )
        if envelope_present:
            envelope = self.envelope
            header = self.header
            if not header_present or (
                header.bootstrap_schema_version != envelope.bootstrap_schema_version
                or header.adapter_name != envelope.adapter_name
                or header.adapter_version != envelope.adapter_version
                or header.executable_hash != envelope.executable_hash
            ):
                raise ValueError("a parsed envelope requires a header agreeing with it")
            return self
        if self.failure_code not in _DESCRIPTOR_FAILURE_CODES:
            raise ValueError("failure_code must be a describe parse code")
        if not header_present and self.failure_code != PROTOCOL_DESCRIBE_OUTPUT_INVALID:
            raise ValueError(
                "a parse without a header records PROTOCOL.DESCRIBE_OUTPUT_INVALID"
            )
        unsupported = header_present and (
            not _is_missing(self.header.bootstrap_schema_version)
            and self.header.bootstrap_schema_version != SCHEMA_VERSION
        )
        if self.failure_code == PROTOCOL_UNSUPPORTED_VERSION and not unsupported:
            raise ValueError(
                "PROTOCOL.UNSUPPORTED_VERSION requires a readable unsupported "
                "bootstrap_schema_version in the header"
            )
        if unsupported and self.failure_code != PROTOCOL_UNSUPPORTED_VERSION:
            raise ValueError(
                "a readable unsupported version records PROTOCOL.UNSUPPORTED_VERSION"
            )
        return self


def parse_bootstrap_descriptor(
    output_bytes: bytes,
    *,
    max_bytes: int,
) -> DescriptorParse:
    """Plan 3.11 and 5.4: the byte-level half of the describe flow.

    The ceiling is applied before any decoding (specification 14.7); oversized,
    non-UTF-8 and non-object bytes carry no header; a JSON object is read
    permissively into the header, an unsupported readable version is
    ``PROTOCOL.UNSUPPORTED_VERSION``, and strict validation of the same bytes
    yields the envelope or ``PROTOCOL.DESCRIBE_OUTPUT_INVALID``. Pure over its
    arguments; nothing is opened and no adapter byte enters an error message.
    """
    if type(output_bytes) is not bytes:
        raise TypeError("output_bytes must be bytes")
    if type(max_bytes) is not int:
        raise TypeError("max_bytes must be a built-in integer")
    if not 1 <= max_bytes <= MAX_DESCRIPTOR_OUTPUT_BYTES:
        raise ValueError(f"max_bytes must be within 1..{MAX_DESCRIPTOR_OUTPUT_BYTES}")
    facts: dict[str, object] = {
        "byte_length": len(output_bytes),
        "source_hash": sha256_bytes(output_bytes),
    }
    invalid = {**facts, "failure_code": PROTOCOL_DESCRIBE_OUTPUT_INVALID}
    if len(output_bytes) > max_bytes:
        return DescriptorParse.model_validate(invalid)
    try:
        document = json.loads(
            output_bytes.decode("utf-8"),
            object_pairs_hook=_object_without_repeated_keys,
        )
    except (ValueError, RecursionError):
        return DescriptorParse.model_validate(invalid)
    if type(document) is not dict:
        return DescriptorParse.model_validate(invalid)
    header = _descriptor_header(document)
    facts["header"] = header
    version = header.bootstrap_schema_version
    if not _is_missing(version) and version != SCHEMA_VERSION:
        return DescriptorParse.model_validate(
            {**facts, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    try:
        envelope = BootstrapDescriptorEnvelope.model_validate_json(output_bytes)
    except (ValidationError, ValueError, RecursionError):
        return DescriptorParse.model_validate(
            {**facts, "failure_code": PROTOCOL_DESCRIBE_OUTPUT_INVALID}
        )
    return DescriptorParse.model_validate({**facts, "envelope": envelope})


# --- The availability observation projection --------------------------------------


def describe_availability_observation(
    *,
    adapter_name: NormalizedIdentifier,
    adapter_version: SemanticVersion,
    verdict: ReconciliationVerdict | MISSING,  # type: ignore[valid-type]
    primary_code: ErrorCode | MISSING,  # type: ignore[valid-type]
    descriptor: AdapterDescriptor | MISSING,  # type: ignore[valid-type]
    observation_id: AvailabilityObservationId,
    executable_path: ExecutablePath,
    executable_hash: Sha256,
    runtime_version: SemanticVersion,
    operating_system: OperatingSystem,
    observed_at_utc: datetime,
    expires_at_utc: datetime,
) -> RuntimeAvailabilityObservation:
    """Plan 5.4: project a terminal describe into the Stage 4 observation.

    ``available`` is true exactly for verdict ``DESCRIBED`` (which requires no
    ``primary_code`` and a descriptor); a ``DESCRIBE_UNAVAILABLE`` verdict or an
    absent verdict (a describe whose deadline won) requires ``primary_code``, a
    Stage 6 code other than ``PROCESS.CANCELLED``, as the ``reason_code``. A
    validate or run verdict is rejected. Network and credential flags come from
    the descriptor when present, whose identity must be the supplied one, and are
    ``False`` otherwise. Every instant and runtime fact is caller-supplied.
    """
    available = False
    if not _is_missing(verdict):
        if not isinstance(verdict, ReconciliationVerdict):
            raise TypeError("verdict must be a ReconciliationVerdict or MISSING")
        if verdict not in _DESCRIBE_VERDICTS:
            raise ValueError(
                f"a validate or run verdict ({verdict.value}) cannot project a "
                "describe observation"
            )
        available = verdict is ReconciliationVerdict.DESCRIBED
    if not _is_missing(descriptor) and not isinstance(descriptor, AdapterDescriptor):
        raise TypeError("descriptor must be an AdapterDescriptor or MISSING")
    if available:
        if not _is_missing(primary_code):
            raise ValueError("a DESCRIBED describe carries no primary code")
        if _is_missing(descriptor):
            raise ValueError("a DESCRIBED describe requires its descriptor")
    else:
        if _is_missing(primary_code):
            raise ValueError("an unavailable describe requires a primary code")
        if type(primary_code) is not str or primary_code not in STAGE6_DIAGNOSTIC_CODES:
            raise ValueError("the primary code is not a Stage 6 code")
        if primary_code == PROCESS_CANCELLED:
            raise ValueError("a cancelled describe mints no observation")
    network_required = False
    credentials_required = False
    if isinstance(descriptor, AdapterDescriptor):
        described_identity = (
            descriptor.adapter_name,
            descriptor.adapter_version,
            descriptor.executable_hash,
        )
        if described_identity != (adapter_name, adapter_version, executable_hash):
            raise ValueError(
                "the descriptor's identity does not equal the supplied adapter identity"
            )
        network_required = descriptor.network_required
        credentials_required = descriptor.credentials_required
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "availability_observation_id": observation_id,
        "adapter_name": adapter_name,
        "adapter_version": adapter_version,
        "executable_path": executable_path,
        "executable_hash": executable_hash,
        "runtime_version": runtime_version,
        "operating_system": operating_system,
        "available": available,
        "observed_at_utc": observed_at_utc,
        "expires_at_utc": expires_at_utc,
        "network_required": network_required,
        "credentials_required": credentials_required,
    }
    if not available:
        payload["reason_code"] = primary_code
    return RuntimeAvailabilityObservation.model_validate(payload)
