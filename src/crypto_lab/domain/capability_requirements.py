"""One strategy or comparison capability requirement.

Placed in `domain` rather than in `capabilities` so that `StrategySpec` — whose
`required_capabilities` field is a tuple of these — does not have to import from
`capabilities`. `capabilities/models.py` re-exports it, keeping that package's
public surface intact.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.capability_names import CapabilityName
from crypto_lab.domain.comparison_levels import ComparisonLevel

MAX_REQUIREMENT_COMPARISON_LEVELS = 3


class ApproximationPolicy(StrEnum):
    """The closed approximation vocabulary of `strategy/v1`.

    `ALLOW_DECLARED` means only that a machine-readable `ApproximationDeclaration`
    exists for the same capability and that its comparison-level exclusions are
    honored. There is deliberately no permissive or wildcard member: an
    `ALLOW_ANY`-style value would let an unnamed approximation silently change
    execution meaning, which is what specification section 13.2's "absence is not
    interpreted as native support" rule exists to prevent.
    """

    REJECT = "REJECT"
    ALLOW_DECLARED = "ALLOW_DECLARED"


class CapabilityRequirement(CanonicalModel):
    """Exactly the six minimum fields of specification 11.3, in that order.

    `minimum_semantics` is the exact literal `capabilities/v1` rather than a
    `SemanticVersion` or free text: the capability vocabulary is versioned as a
    whole, and a future value requires a reviewed schema and vocabulary
    migration. The Task 6 resolver compares this value with the descriptor's
    recognized `capability_vocabulary_version` before resolving support.

    `approximation_policy` is required and explicit, with no injected default, so
    a requirement can never be read as permitting an approximation it did not
    declare.
    """

    schema_version: Literal["1.0.0"]
    capability: CapabilityName
    required: bool
    minimum_semantics: Literal["capabilities/v1"]
    approximation_policy: ApproximationPolicy
    comparison_levels: tuple[ComparisonLevel, ...] = Field(
        max_length=MAX_REQUIREMENT_COMPARISON_LEVELS
    )

    @field_validator("comparison_levels")
    @classmethod
    def validate_levels_are_unique_and_sorted(
        cls,
        value: tuple[ComparisonLevel, ...],
    ) -> tuple[ComparisonLevel, ...]:
        """Order carries no meaning here, so it is canonicalized by rejection.

        An explicit empty tuple is accepted and scopes the requirement to no
        particular level, per specification 11.5's explicit-empty-array rule.
        """
        if len(set(value)) != len(value):
            raise ValueError("comparison levels must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("comparison levels must be sorted")
        return value
