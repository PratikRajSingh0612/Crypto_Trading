"""Strict strategy models: `StrategySpec` and every sub-model.

These shapes are hash material. `EngineExtensionDeclaration`'s first three
fields are the strategy-version payload's `extension_hashes` sort key, so a
rename here would propagate straight into a permanent `content_hash`.

`BoundedText` is declared locally rather than imported from
`crypto_lab.adapters` or `crypto_lab.datasets`: either import would create the
inward dependency edge the architecture exists to prevent, and both of those
packages already carry their own independent local definitions.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal, Self, cast

from pydantic import (
    Field,
    StringConstraints,
    WithJsonSchema,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.capability_names import CapabilityName
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.financial import PositiveDecimal
from crypto_lab.domain.identifiers import (
    NormalizedIdentifier,
    Sha256,
    StrategyId,
    exact_string_schema,
)
from crypto_lab.domain.records import InstrumentId, MarketType
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version
from crypto_lab.strategy.expressions import (
    EXACT_RUNTIME_TYPES,
    Expression,
    LiteralValue,
    LiteralValueType,
)

MAX_UNIVERSE_INSTRUMENTS = 256
MAX_REQUIRED_CAPABILITIES = 128
MAX_PARAMETERS = 128
MAX_FEATURES = 256
MAX_FEATURE_INPUTS = 16
MAX_FEATURE_PARAMETERS = 32
MAX_RULES = 64
MAX_ENGINE_EXTENSIONS = 64
MAX_WARM_UP_BARS = 4_096

_FEATURE_OPERATION_PATTERN = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*/v[1-9][0-9]*$"

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]
BoundedLabel = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=256)
]
Timeframe = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[1-9][0-9]*(?:s|m|h|d|w)$", max_length=16
    ),
    WithJsonSchema(exact_string_schema(r"^[1-9][0-9]*(?:s|m|h|d|w)$", max_length=16)),
]
FeatureOperation = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=4,
        max_length=128,
        pattern=_FEATURE_OPERATION_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _FEATURE_OPERATION_PATTERN,
            min_length=4,
            max_length=128,
        )
    ),
]


def _is_missing(value: object) -> bool:
    return value is MISSING


def _frozen_mapping[KeyT, ValueT](
    validated: Mapping[KeyT, ValueT],
) -> Mapping[KeyT, ValueT]:
    """Detach a validated mapping and return an immutable view of the copy.

    `CanonicalModel` sets `frozen=True`, which stops attribute rebinding and
    nothing else: a `dict` field stayed mutable through ordinary public item
    access, so hash material reachable from a `StrategyVersion` could be changed
    after construction while the recorded `content_hash` stayed stale. Plan
    section 5.5.1 fixes the representation here.

    `dict(validated)` first is **defence in depth, not a currently reachable
    fix**. `MappingProxyType` is a live view, so wrapping an object someone else
    holds would leave the record aliased to a mapping they can still mutate.
    Measured against this Pydantic: no such path exists today, because
    pydantic-core builds a fresh `dict` when it validates a parametrized
    `Mapping`, in JSON mode and in Python mode alike -- so the object reaching
    here is already detached and the copy changes nothing observable. It is kept
    because the invariant should not depend on that internal behaviour, and
    because a future field whose values are not themselves validated would make
    the alias live. Plan section 5.5.1 item 9 forbids wrapping without copying
    for the same reason.

    The values need no copy of their own: every value is either a frozen
    `CanonicalModel` or a `str`.
    """
    return MappingProxyType(dict(validated))


def _extension_key(
    declaration: EngineExtensionDeclaration,
) -> tuple[str, str, tuple[int, int, int]]:
    """The strategy-version payload's `extension_hashes` sort key.

    `version` is compared **numerically** through `parse_semantic_version`, not
    lexicographically: `"1.10.0" < "1.9.0"` as text. The merged
    `_unique_sorted_versions` in `adapters/descriptors.py` sorts the same way, so
    the later task that sorts `extension_hashes` cannot silently disagree here.
    """
    return (
        declaration.adapter_name,
        declaration.extension_id,
        parse_semantic_version(declaration.version),
    )


class Direction(StrEnum):
    """Declared trade direction. Initial policy accepts only `LONG`."""

    LONG = "LONG"
    SHORT = "SHORT"


class ExtensionLifecycleEffect(StrEnum):
    """Specification 12.6's lifecycle-versus-execution alternative."""

    LIFECYCLE_HOOKS_ONLY = "LIFECYCLE_HOOKS_ONLY"
    ALTERS_EXECUTION_BEHAVIOR = "ALTERS_EXECUTION_BEHAVIOR"


class ExtensionEconomicEffect(StrEnum):
    """Specification 12.6's economic-effect classification.

    There is no `PREVENTS_LEVEL_3`: section 12.6 bounds an extension's declared
    economic effect to making a Level 1 or Level 2 comparison ineligible. There
    is no bare `PREVENTS_LEVEL_1` either, because section 25.2 makes Level 2 a
    superset of Level 1, so preventing Level 1 necessarily prevents Level 2.
    Neither omission constrains `ApproximationDeclaration`, which a later task
    owns and which section 13.4 requires to admit Level 3.
    """

    NONE = "NONE"
    PREVENTS_LEVEL_2 = "PREVENTS_LEVEL_2"
    PREVENTS_LEVEL_1_AND_LEVEL_2 = "PREVENTS_LEVEL_1_AND_LEVEL_2"


class EngineExtensionDeclaration(CanonicalModel):
    """One declared engine extension. The core never imports or executes one.

    Exactly the seven fields of specification section 12.6, in that order.
    """

    adapter_name: NormalizedIdentifier
    extension_id: NormalizedIdentifier
    version: SemanticVersion
    content_hash: Sha256
    purpose: BoundedText
    lifecycle_effect: ExtensionLifecycleEffect
    economic_effect: ExtensionEconomicEffect

    @model_validator(mode="after")
    def validate_effects_agree(self) -> Self:
        """A lifecycle-only extension cannot also prevent parity."""
        if (
            self.lifecycle_effect is ExtensionLifecycleEffect.LIFECYCLE_HOOKS_ONLY
            and self.economic_effect is not ExtensionEconomicEffect.NONE
        ):
            raise ValueError(
                "STRATEGY.EXTENSION_DECLARATION: a lifecycle-hooks-only "
                "extension requires economic_effect NONE"
            )
        return self


class MissingValuePolicy(StrEnum):
    """Specification 12.3.2, declared per feature rather than per strategy."""

    REJECT_DATASET = "REJECT_DATASET"
    SKIP_BAR = "SKIP_BAR"
    PROPAGATE_FALSE = "PROPAGATE_FALSE"


class SizingMethod(StrEnum):
    """Economic intent only. Sizing never becomes an order here."""

    FRACTION_OF_AVAILABLE_QUOTE = "FRACTION_OF_AVAILABLE_QUOTE"


class Universe(CanonicalModel):
    """A resolved immutable instrument list. Registry queries are a future kind."""

    kind: Literal["STATIC"]
    instruments: tuple[InstrumentId, ...] = Field(
        min_length=1,
        max_length=MAX_UNIVERSE_INSTRUMENTS,
        # Plan section 3.1 requires `json_schema_extra` to supply the `uniqueItems`
        # Pydantic does not emit for a tuple field; it names callables because that
        # is the form `domain/descriptors.py` uses, and a literal mapping is the same
        # mechanism. Without it the generated schema
        # accepts a repeated instrument that
        # `validate_instruments_are_unique_and_sorted` rejects, and Task 8 publishes
        # this record through the `$defs` of both `strategy-spec-v1` and
        # `strategy-version-v1`. Field-level rather than a model-level hook because
        # it is additive; `StrategySpec.parameters` below sets `maxProperties` the
        # same way.
        #
        # Unlike the comparison-level fields, the validator here **normalizes** an
        # unsorted array rather than rejecting one, so a schema that admits any
        # order agrees with the runtime. The only residue is that Draft 2020-12
        # cannot advertise that a serialized array is sorted.
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("instruments")
    @classmethod
    def validate_instruments_are_unique_and_sorted(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("universe instruments must be unique")
        return tuple(sorted(value))


class ParameterDefinition(CanonicalModel):
    """One typed resolved parameter value with optional bounds and unit.

    `value_type` precedes `value`, `minimum`, and `maximum` because all three
    dispatch on it through the same literal contract, and `ValidationInfo.data`
    carries only the fields validated before them.
    """

    value_type: LiteralValueType
    value: LiteralValue
    minimum: LiteralValue | MISSING = MISSING  # type: ignore[valid-type]
    maximum: LiteralValue | MISSING = MISSING  # type: ignore[valid-type]
    unit: BoundedLabel | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        """Each comparison is guarded, because an absent bound is a sentinel.

        Comparing `MISSING` would raise `TypeError` out of the validation
        contract rather than producing a diagnostic.
        """
        numeric = {LiteralValueType.INTEGER, LiteralValueType.DECIMAL}
        has_minimum = not _is_missing(self.minimum)
        has_maximum = not _is_missing(self.maximum)
        if self.value_type not in numeric and (has_minimum or has_maximum):
            raise ValueError("only INTEGER and DECIMAL parameters accept bounds")

        # The same exact-identity invariant `LiteralExpression` carries: every
        # bound dispatched through the shared literal contract, so a `Decimal`
        # subclass -- which `parse_decimal` admits and which could restate its own
        # text through `__str__` or `as_tuple` -- cannot enter a permanent hash.
        expected = EXACT_RUNTIME_TYPES[self.value_type]
        for declared in (self.value, self.minimum, self.maximum):
            if not _is_missing(declared) and type(declared) is not expected:
                raise ValueError("parameter value type disagrees with value_type")

        # Narrowed by the check above: a bounded parameter is INTEGER or DECIMAL,
        # so `value` and both bounds are `int` or `Decimal`.
        value = cast("int | Decimal", self.value)
        minimum = cast("int | Decimal", self.minimum)
        maximum = cast("int | Decimal", self.maximum)
        # Bound consistency is checked **before** the value comparison. In the
        # other order this branch is unreachable: an inconsistent pair always
        # trips one of the value comparisons first, so the more precise
        # diagnostic would never be the one reported.
        if has_minimum and has_maximum and minimum > maximum:
            raise ValueError("parameter minimum must not exceed its maximum")
        if (has_minimum and minimum > value) or (has_maximum and value > maximum):
            raise ValueError(
                "STRATEGY.PARAMETER_OUT_OF_BOUNDS: parameter value lies "
                "outside its declared bounds"
            )
        return self


class FeatureDefinition(CanonicalModel):
    """One node of the feature graph. Operation semantics belong to a later task.

    Duplicate IDs, reference resolution, cycles, and warm-up sufficiency are
    deliberately **not** validated here: later tasks own those diagnostics.
    """

    id: NormalizedIdentifier
    operation: FeatureOperation
    inputs: tuple[NormalizedIdentifier, ...] = Field(
        min_length=1, max_length=MAX_FEATURE_INPUTS
    )
    parameters: Mapping[NormalizedIdentifier, NormalizedIdentifier] = Field(
        max_length=MAX_FEATURE_PARAMETERS,
        # Restated for serialization mode. A field serializer replaces that
        # mode's schema with its own return type's schema, which carries no
        # `max_length`, so without this the generated schema -- which
        # `schema_registry` renders from `mode="serialization"` -- would publish
        # a weaker bound than the runtime enforces. Identical to the validation
        # -mode value, so the merge is idempotent there.
        json_schema_extra={"maxProperties": MAX_FEATURE_PARAMETERS},
    )
    output_type: LiteralValueType
    warm_up_bars: Annotated[int, Field(strict=True, ge=0, le=MAX_WARM_UP_BARS)]
    missing_value_policy: MissingValuePolicy

    @field_validator("parameters", mode="after")
    @classmethod
    def freeze_parameters(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        """Runs after the `max_length` bound, so the bound still sees a mapping."""
        return _frozen_mapping(value)

    @field_serializer("parameters", when_used="always")
    def serialize_parameters(
        self,
        value: Mapping[str, str],
    ) -> dict[NormalizedIdentifier, NormalizedIdentifier]:
        """Emit an ordinary object in every mode, so `mappingproxy` never leaks.

        The return type restates the exact key and value types rather than plain
        `str`: a field serializer replaces the serialization-mode JSON Schema
        with its own return type's schema, so annotating `dict[str, str]` would
        publish a bare `{"type": "string"}` in place of the exact
        `NormalizedIdentifier` contract.

        `when_used="always"` rather than `"json"`: `canonical_json._normalize`
        dispatches on `type(value) is dict` and reaches a model through
        `model_dump(mode="python")`, so a python-mode `mappingproxy` would raise
        `unsupported canonical JSON type` and break hashing outright.
        """
        return dict(value)


class RuleDefinition(CanonicalModel):
    """One named rule. Declared rule order is preserved: it carries semantics."""

    id: NormalizedIdentifier
    expression: Expression


class SizingIntent(CanonicalModel):
    method: SizingMethod
    fraction: PositiveDecimal

    @model_validator(mode="after")
    def validate_fraction_is_a_fraction(self) -> Self:
        if self.fraction > 1:
            raise ValueError("sizing fraction must not exceed one")
        return self


class RiskAssumptions(CanonicalModel):
    """Declared boundaries only; this implements no risk engine.

    Leverage above one and shorting are repository safety boundaries, so they are
    rejected here rather than merely described.
    """

    leverage: PositiveDecimal
    shorting_allowed: bool

    @model_validator(mode="after")
    def validate_safety_boundaries(self) -> Self:
        if self.leverage != 1:
            raise ValueError("leverage other than one is not permitted")
        if self.shorting_allowed:
            raise ValueError("shorting is not permitted")
        return self


class WarmUpRequirements(CanonicalModel):
    minimum_bars: Annotated[int, Field(strict=True, ge=0, le=MAX_WARM_UP_BARS)]


class ComparisonRequirements(CanonicalModel):
    maximum_level: ComparisonLevel


class SupportedApproximationPolicy(CanonicalModel):
    """The strategy-wide statement for capabilities not individually enumerated.

    Fixed to `REJECT` in `strategy/v1`. A per-requirement `ALLOW_DECLARED` is
    **not** a contradiction: the two govern disjoint sets, and the per-requirement
    value is authoritative for its own capability.
    """

    default: Literal[ApproximationPolicy.REJECT]


class AuthoringMetadata(CanonicalModel):
    author: NormalizedIdentifier
    created_at_utc: UtcDateTime


class StrategySpec(CanonicalModel):
    """Exactly the twenty-one fields of specification section 12.2, in order."""

    schema_version: Literal["1.0.0"]
    strategy_id: StrategyId
    display_name: BoundedLabel
    description: BoundedText
    strategy_family: NormalizedIdentifier
    market_type: MarketType
    direction: Direction
    timeframe: Timeframe
    universe: Universe
    required_capabilities: tuple[CapabilityRequirement, ...] = Field(
        min_length=1, max_length=MAX_REQUIRED_CAPABILITIES
    )
    parameters: Mapping[NormalizedIdentifier, ParameterDefinition] = Field(
        max_length=MAX_PARAMETERS,
        # Restated for serialization mode; see `FeatureDefinition.parameters`.
        json_schema_extra={"maxProperties": MAX_PARAMETERS},
    )
    features: tuple[FeatureDefinition, ...] = Field(max_length=MAX_FEATURES)
    entry_rules: tuple[RuleDefinition, ...] = Field(min_length=1, max_length=MAX_RULES)
    exit_rules: tuple[RuleDefinition, ...] = Field(min_length=1, max_length=MAX_RULES)
    sizing_intent: SizingIntent
    risk_assumptions: RiskAssumptions
    warm_up_requirements: WarmUpRequirements
    comparison_requirements: ComparisonRequirements
    supported_approximation_policy: SupportedApproximationPolicy
    engine_extensions: tuple[EngineExtensionDeclaration, ...] = Field(
        max_length=MAX_ENGINE_EXTENSIONS
    )
    authoring_metadata: AuthoringMetadata

    @field_validator("parameters", mode="after")
    @classmethod
    def freeze_parameters(
        cls,
        value: Mapping[str, ParameterDefinition],
    ) -> Mapping[str, ParameterDefinition]:
        """Runs after the `max_length` bound, so the bound still sees a mapping."""
        return _frozen_mapping(value)

    @field_serializer("parameters", when_used="always")
    def serialize_parameters(
        self,
        value: Mapping[str, ParameterDefinition],
    ) -> dict[NormalizedIdentifier, ParameterDefinition]:
        """Emit an ordinary object in every mode; see `FeatureDefinition`'s note."""
        return dict(value)

    @field_validator("market_type")
    @classmethod
    def validate_market_type_policy(cls, value: MarketType) -> MarketType:
        if value is not MarketType.SPOT:
            raise ValueError(
                "STRATEGY.POLICY_FORBIDDEN_MARKET: initial policy accepts SPOT only"
            )
        return value

    @field_validator("direction")
    @classmethod
    def validate_direction_policy(cls, value: Direction) -> Direction:
        if value is not Direction.LONG:
            raise ValueError(
                "STRATEGY.POLICY_FORBIDDEN_DIRECTION: initial policy accepts LONG only"
            )
        return value

    @field_validator("required_capabilities")
    @classmethod
    def normalize_required_capabilities(
        cls,
        value: tuple[CapabilityRequirement, ...],
    ) -> tuple[CapabilityRequirement, ...]:
        """Capability order carries no economic meaning, so it is canonicalized.

        Normalizing rather than rejecting lets a human author the requirements in
        the vocabulary's reading order.
        """
        names: list[CapabilityName] = [item.capability for item in value]
        if len(set(names)) != len(names):
            raise ValueError("required capabilities must name each capability once")
        return tuple(sorted(value, key=lambda item: item.capability))

    @field_validator("engine_extensions")
    @classmethod
    def normalize_engine_extensions(
        cls,
        value: tuple[EngineExtensionDeclaration, ...],
    ) -> tuple[EngineExtensionDeclaration, ...]:
        """Canonicalized on the same key the strategy-version payload sorts by.

        Normalizing is required rather than optional: the hashed payload embeds
        this sequence, so rejecting an unsorted source would make reordering
        change the hash instead of leaving it alone.
        """
        keys = [_extension_key(item) for item in value]
        if len(set(keys)) != len(keys):
            raise ValueError("engine extensions must be declared once each")
        return tuple(sorted(value, key=_extension_key))
