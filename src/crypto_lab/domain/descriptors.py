"""Structural engine, adapter, and runtime-availability records.

Relocated here from ``adapters/descriptors.py`` by plan section 5.7, so that
``capabilities`` can consume the contracts specification section 8.2 places in
``CompatibilityResolver.resolve`` without the ``capabilities -> adapters`` edge
specification section 27.1 forbids. Specification section 8.2 authorizes the move
by name -- "names may move between files during implementation planning" -- and
section 11.3 already classifies all three descriptors and
``RuntimeAvailabilityObservation`` as canonical domain records.

Every relocated class, annotation, and helper is moved **verbatim**, including
``StringConstraints`` bounds, validators, and both ``json_schema_extra`` hooks,
because ``schemas/protocol/adapter-descriptor-v1.schema.json`` keys its ``$defs``
by bare class and alias names and never by module path. ``adapters/descriptors.py``
re-exports every name, so its public surface and every existing import site are
unchanged.

``BoundedText`` is defined locally rather than imported from ``adapters``, for the
same dependency-direction reason, and matching the existing repository precedent
in ``configuration/models.py`` and ``datasets/models.py``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

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

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    NormalizedIdentifier,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

MAX_EXECUTABLE_PATH_CHARACTERS = 1024

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]


def _validate_executable_path(value: str) -> str:
    """Reject text that cannot be a well-formed local executable location.

    Specification section 11.3 states that availability paths and hashes "come
    from the explicit catalog", so this record stores an observed location and
    never resolves, opens, or normalizes it -- plan section 5.1 forbids filesystem
    access from resolution entirely, and the resolver compares ``executable_hash``
    rather than this value.

    What is checked is therefore purely textual, and the claim is deliberately
    narrow: a NUL or other control character, or leading or trailing whitespace,
    makes the value useless as a stable identity, because two observations of the
    same executable could then differ on an invisible character. This is **not** a
    quoting or argument-injection control -- interior spaces and shell
    metacharacters validate, and would need their own contract at whatever future
    site actually executes the path. No such site exists in Stage 4, which is what
    makes textual validation sufficient here.
    """
    if value != value.strip():
        raise ValueError("executable path must not carry surrounding whitespace")
    if any(character < " " or character == "\x7f" for character in value):
        raise ValueError("executable path must not contain a control character")
    return value


# `_validate_executable_path`'s two rules restated for the generated schema.
# `StringConstraints` renders only the length bounds, so without this the
# published contract accepted edge whitespace and interior control characters
# that ordinary validated construction rejects -- proven with complete documents
# in `tests/unit/domain/test_domain_descriptors.py`. This is the same
# `WithJsonSchema(exact_string_schema(...))` mechanism `SourceName`,
# `SemanticVersion`, and every identifier already use; `ExecutablePath` was the
# only annotated type in the Stage 4 schema set carrying none.
#
# The **edge** class excludes U+0000-U+0020 plus every non-ASCII member of
# `str.isspace()`, because `value != value.strip()` rejects exactly Python
# whitespace there and the control rule rejects the rest of that range. The
# **interior** class excludes only U+0000-U+001F and U+007F, so an interior
# ASCII space -- or U+00A0, or U+0085 -- still validates, exactly as the runtime
# allows. `\s` is deliberately not used: ECMA `\s` omits U+001C-U+001F and
# U+0085, so it would publish a weaker rule than `str.strip()` enforces. The
# range stops at U+200A rather than U+200B because U+200B is not Python
# whitespace and the runtime accepts it at an edge.
#
# `ExecutablePath` is reached only by `RuntimeAvailabilityObservation`, so the
# annotation lives on the alias without touching any frozen Stage 3 schema;
# `application-config-v1`'s same-named field is a different type with its own
# published Windows-path pattern.
_EXECUTABLE_PATH_SCHEMA_PATTERN = (
    r"^[^\u0000-\u0020\u007f\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028-\u2029\u202f\u205f\u3000]"
    r"(?:[^\u0000-\u001f\u007f]*"
    r"[^\u0000-\u0020\u007f\u0085\u00a0\u1680\u2000-\u200a"
    r"\u2028-\u2029\u202f\u205f\u3000])?$"
)

ExecutablePath = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=MAX_EXECUTABLE_PATH_CHARACTERS,
    ),
    AfterValidator(_validate_executable_path),
    # The trailing `$` is permitted only because `exact_string_schema` replaces
    # it with the project's absolute `(?![\s\S])` ending; the published pattern
    # never relies on `$` as its final assertion.
    WithJsonSchema(
        exact_string_schema(
            _EXECUTABLE_PATH_SCHEMA_PATTERN,
            min_length=1,
            max_length=MAX_EXECUTABLE_PATH_CHARACTERS,
        )
    ),
]


class OperatingSystem(StrEnum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"


def _is_missing(value: object) -> bool:
    return value is MISSING


def _unique_sorted_text(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


def _unique_sorted_versions(
    value: tuple[SemanticVersion, ...],
    label: str,
) -> tuple[SemanticVersion, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value, key=parse_semantic_version)):
        raise ValueError(f"{label} must be numerically sorted")
    return value


def _set_unique_items(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("descriptor schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"descriptor schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _engine_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(schema, ("known_limitations",))


def _observation_schema_extra(schema: JsonSchemaValue) -> None:
    """Publish the ``available`` <-> ``reason_code`` biconditional.

    ``validate_observation`` enforces both directions, and Pydantic emits
    neither: ``reason_code`` is correctly absent from ``required``, but that
    permits its absence *unconditionally* rather than exactly in the state that
    permits it, so the published schema accepted two documents ordinary
    validated construction rejects.

    Plan section 3.1 names ``dependentRequired`` and ``oneOf`` at the same
    authority as the ``uniqueItems`` this module already supplies through
    ``_set_unique_items``, and Stage 3 publishes this exact shape by hand in
    three places: ``_diagnostic_schema_extra`` (``domain/diagnostics.py``) and
    both artifact-owner hooks (``artifacts/ownership.py``).

    Two separable ``if``/``then`` branches rather than one ``oneOf``, so removing
    either direction is caught by its own test. ``dependentRequired`` cannot
    express this pair: it keys on a property's *presence*, and the governing
    state here is a boolean's *value*.

    Deliberately a model hook on this record alone. ``EngineDescriptor`` and
    ``AdapterDescriptor`` share this module and render the already-published
    ``engine-descriptor-v1`` and ``adapter-descriptor-v1``, so routing this
    through ``_set_unique_items``' shared helper would move frozen Stage 3 bytes.
    """
    schema.setdefault("allOf", []).extend(
        (
            {
                "if": {
                    "properties": {"available": {"const": True}},
                    "required": ["available"],
                },
                "then": {"not": {"required": ["reason_code"]}},
            },
            {
                "if": {
                    "properties": {"available": {"const": False}},
                    "required": ["available"],
                },
                "then": {"required": ["reason_code"]},
            },
        )
    )


def _descriptor_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(
        schema,
        (
            "supported_protocol_versions",
            "supported_schema_versions",
            "native_capabilities",
            "approximated_capabilities",
            "unsupported_capabilities",
            "supported_operating_systems",
            "runtime_requirements",
            "known_modeling_limitations",
        ),
    )


class EngineDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_engine_schema_extra
    )

    schema_version: Literal["1.0.0"]
    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion
    engine_family: NormalizedIdentifier
    planned_role: BoundedText
    known_limitations: tuple[BoundedText, ...] = Field(max_length=64)

    @field_validator("known_limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "engine limitations")


class SupportedSchemaVersion(CanonicalModel):
    schema_name: NormalizedIdentifier
    schema_version: SemanticVersion


class AdapterDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_descriptor_schema_extra
    )

    schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine: EngineDescriptor
    supported_protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1, max_length=32
    )
    supported_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1,
        max_length=128,
    )
    capability_vocabulary_version: VocabularyVersion
    native_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    approximated_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    unsupported_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    supported_operating_systems: tuple[OperatingSystem, ...] = Field(
        min_length=1, max_length=8
    )
    runtime_requirements: tuple[BoundedText, ...] = Field(max_length=64)
    network_required: bool
    credentials_required: bool
    known_modeling_limitations: tuple[BoundedText, ...] = Field(max_length=64)
    executable_hash: Sha256

    @field_validator("supported_protocol_versions")
    @classmethod
    def validate_versions(
        cls,
        value: tuple[SemanticVersion, ...],
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "supported versions")

    @field_validator("supported_schema_versions")
    @classmethod
    def validate_schema_versions(
        cls,
        value: tuple[SupportedSchemaVersion, ...],
    ) -> tuple[SupportedSchemaVersion, ...]:
        keys = tuple(
            (item.schema_name, parse_semantic_version(item.schema_version))
            for item in value
        )
        if len(set(keys)) != len(keys):
            raise ValueError("supported schema versions must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("supported schema versions must be sorted")
        return value

    @field_validator(
        "native_capabilities",
        "approximated_capabilities",
        "unsupported_capabilities",
        "runtime_requirements",
        "known_modeling_limitations",
    )
    @classmethod
    def validate_sorted_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "descriptor collection")

    @field_validator("supported_operating_systems")
    @classmethod
    def validate_operating_systems(
        cls,
        value: tuple[OperatingSystem, ...],
    ) -> tuple[OperatingSystem, ...]:
        if len(set(value)) != len(value):
            raise ValueError("operating systems must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("operating systems must be sorted")
        return value

    @model_validator(mode="after")
    def validate_capability_sets(self) -> Self:
        native = set(self.native_capabilities)
        approximated = set(self.approximated_capabilities)
        unsupported = set(self.unsupported_capabilities)
        if native & approximated or native & unsupported or approximated & unsupported:
            raise ValueError("capability declaration sets must be disjoint")
        return self


class RuntimeAvailabilityObservation(CanonicalModel):
    """A time-bounded local observation kept separate from logical capability.

    Exactly the minimum fields of specification section 11.3, in that order.
    Availability is deliberately a *separate* input to
    ``CompatibilityResolver.resolve``: section 11.3 states that "availability
    cannot override semantic incompatibility or safety policy", and section 13.4
    forbids mislabelling an absent runtime as a strategy failure.

    Every material value is an immutable scalar, ``StrEnum``, or timezone-aware
    instant, so the shallow ``frozen=True`` of ``CanonicalModel`` is sufficient
    here and plan section 5.5.1's deep-immutability obligation is satisfied
    without an immutable-mapping representation.

    **``reason_code``'s optionality is a recorded deviation from section 11.5, not
    an oversight.** Section 11.5 requires canonical boundary fields to be required
    "unless this specification makes their absence state-dependent", and its
    closed "Exact state-governed optionality is:" list does **not** enumerate this
    field; the 11.3 row lists ``reason_code`` among the minimum fields and its
    constraint column states no optionality. That distinguishes it from the Stage 3
    ``Diagnostic`` precedent, whose 11.3 row *does* state its optionality ("absent
    when no command caused the fact") and whose ``MISSING`` usage is therefore
    directly spec-backed.

    A strictly required ``reason_code`` is nevertheless unrepresentable: plan
    section 5.9's error-code table is closed and contains no code meaning "the
    runtime is available", so satisfying 11.5 literally would require inventing a
    code the same table forbids. The alternative -- a project-owned availability
    enum -- would permanently fix a vocabulary no normative source authorizes, in a
    record Task 8 schema-generates. ``ErrorCode | MISSING`` under a biconditional
    is therefore the narrowest option that invents nothing, and the biconditional
    makes the state governing absence explicit rather than incidental.

    The biconditional is **published** as well as enforced, through
    ``_observation_schema_extra``: before that hook the generated schema accepted
    an available observation carrying an unavailability code and an unavailable
    one carrying none, both of which this validator rejects.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_observation_schema_extra
    )

    schema_version: Literal["1.0.0"]
    availability_observation_id: AvailabilityObservationId
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    executable_path: ExecutablePath
    executable_hash: Sha256
    runtime_version: SemanticVersion
    operating_system: OperatingSystem
    available: bool
    reason_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    observed_at_utc: UtcDateTime
    expires_at_utc: UtcDateTime
    network_required: bool
    credentials_required: bool

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        """Expiry follows observation, and a reason exists exactly when needed.

        The biconditional is stated in both directions on purpose. Requiring a
        reason only when unavailable would still admit an *available* observation
        carrying an unavailability code, which a consumer could reasonably read as
        the opposite of what ``available`` says.
        """
        if self.expires_at_utc <= self.observed_at_utc:
            raise ValueError("availability expiry must follow the observation instant")
        if self.available and not _is_missing(self.reason_code):
            raise ValueError("an available observation carries no reason code")
        if not self.available and _is_missing(self.reason_code):
            raise ValueError("an unavailable observation requires a reason code")
        return self
