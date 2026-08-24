"""Capability declarations, approximation records, and the compatibility result.

Field sets follow specification section 11.3 wherever that table carries a row.
``CompatibilityResult`` has **no** 11.3 row -- nor does
``ComparisonEligibilityResult`` -- so its field set is derived from binding
sentences and each derivation is stated on the class. That derivation is recorded
in the Task 6 ledger and is deliberately not presented as a specification field
list.

Every record here is a scalar-and-ordered-sequence record: no field is a mapping.
That is what plan section 5.5.1's "latent collision" paragraph anticipated, so no
immutable-mapping representation is needed and Task 6 imports nothing from
``types``.

``CapabilityRequirement`` and ``ApproximationPolicy`` are owned by
``crypto_lab.domain.capability_requirements`` per plan section 5.7 item 6 and are
re-exported here. The ``__all__`` entry is mandatory rather than cosmetic: strict
mypy implies ``--no-implicit-reexport``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.capability_names import CapabilityName
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.identifiers import (
    ApproximationId,
    AvailabilityObservationId,
    NormalizedIdentifier,
)
from crypto_lab.domain.versioning import SemanticVersion

__all__ = [
    "APPROXIMATION_DISALLOWED",
    "APPROXIMATION_MISSING",
    "COMPATIBILITY_REASON_CODES",
    "DECLARATION_OVERLAP",
    "LEVEL_PREVENTED",
    "MAX_CAPABILITY_LIMITATIONS",
    "MAX_COMPATIBILITY_APPROXIMATIONS",
    "MAX_COMPATIBILITY_REASONS",
    "MAX_PREVENTED_COMPARISON_LEVELS",
    "REQUIREMENT_UNMET",
    "RUNTIME_UNAVAILABLE",
    "UNKNOWN_NAME",
    "VOCABULARY_VERSION",
    "ApproximationDeclaration",
    "ApproximationPolicy",
    "CapabilityDeclaration",
    "CapabilityRequirement",
    "CapabilitySupportKind",
    "CompatibilityOutcome",
    "CompatibilityReason",
    "CompatibilityResult",
    "reason_sort_key",
]

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]

MAX_CAPABILITY_LIMITATIONS = 64
MAX_PREVENTED_COMPARISON_LEVELS = 3
#: One approximation record per required approximated capability at most, and the
#: vocabulary is closed, so the vocabulary size is the exact bound.
MAX_COMPATIBILITY_APPROXIMATIONS = len(CapabilityVocabulary.names)
#: Deliberately unreachable. Five of the eight reason codes are capability-scoped
#: and every scoped reason names a closed-vocabulary member, while the three
#: unscoped codes survive deduplication at most once each: the worst case is
#: ``26 * 5 + 3 = 133``. Reasons are therefore unconditionally complete and no
#: terminal limit marker is required, which is why plan section 5.4.1's bounded
#: output contract -- a ``STRATEGY.`` marker in any case -- never applies here.
MAX_COMPATIBILITY_REASONS = 256

UNKNOWN_NAME = "CAPABILITY.UNKNOWN_NAME"
VOCABULARY_VERSION = "CAPABILITY.VOCABULARY_VERSION"
DECLARATION_OVERLAP = "CAPABILITY.DECLARATION_OVERLAP"
REQUIREMENT_UNMET = "CAPABILITY.REQUIREMENT_UNMET"
APPROXIMATION_DISALLOWED = "CAPABILITY.APPROXIMATION_DISALLOWED"
APPROXIMATION_MISSING = "CAPABILITY.APPROXIMATION_MISSING"
LEVEL_PREVENTED = "CAPABILITY.LEVEL_PREVENTED"
RUNTIME_UNAVAILABLE = "CAPABILITY.RUNTIME_UNAVAILABLE"

#: Exactly the outcome-reason rows of plan section 5.9's closed error-code table.
#: The remaining two ``CAPABILITY.`` rows are safety-policy diagnostics and live
#: in ``crypto_lab.capabilities.policy``; the two sets are disjoint and their
#: union is the whole table.
COMPATIBILITY_REASON_CODES: frozenset[str] = frozenset(
    {
        UNKNOWN_NAME,
        VOCABULARY_VERSION,
        DECLARATION_OVERLAP,
        REQUIREMENT_UNMET,
        APPROXIMATION_DISALLOWED,
        APPROXIMATION_MISSING,
        LEVEL_PREVENTED,
        RUNTIME_UNAVAILABLE,
    }
)
#: Codes that are not a property of any one vocabulary member. An unrecognized
#: name is deliberately never echoed back into the record: doing so would make the
#: deduplicated reason count a function of arbitrary caller text rather than of the
#: closed vocabulary, which is what makes the bound above provable.
_UNSCOPED_REASON_CODES: frozenset[str] = frozenset(
    {UNKNOWN_NAME, VOCABULARY_VERSION, RUNTIME_UNAVAILABLE}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def _unique_sorted_text(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


def _result_schema_extra(schema: JsonSchemaValue) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("compatibility result schema properties must be an object")
    for field in ("reasons", "approximations"):
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"compatibility result field {field!r} must be an object")
        field_schema["uniqueItems"] = True


class CapabilitySupportKind(StrEnum):
    """Specification section 13.2's three-way partition of every adapter claim.

    Absence is a fourth observable state and is deliberately **not** a member:
    section 13.2 states that "absence is not interpreted as native support", so an
    undeclared capability must remain undeclared rather than acquire a name here.
    """

    NATIVE = "NATIVE"
    APPROXIMATED = "APPROXIMATED"
    UNSUPPORTED = "UNSUPPORTED"


class CapabilityDeclaration(CanonicalModel):
    """One adapter claim for one vocabulary item.

    Exactly the minimum fields of specification section 11.3, in that order. An
    ``APPROXIMATED`` declaration references an ``ApproximationDeclaration`` by
    ``capability``, which is the reference 11.3 requires without adding a field
    that row does not list.
    """

    schema_version: Literal["1.0.0"]
    capability: CapabilityName
    support_kind: CapabilitySupportKind
    evidence_note: BoundedText
    limitations: tuple[BoundedText, ...] = Field(max_length=MAX_CAPABILITY_LIMITATIONS)

    @field_validator("limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Order carries no economic meaning, so it is canonicalized by rejection.

        Specification section 11.1 requires exactly that for a collection whose
        order does not affect semantics.
        """
        return _unique_sorted_text(value, "declaration limitations")


class ApproximationDeclaration(CanonicalModel):
    """A machine-readable account of non-native behaviour.

    Exactly the minimum fields of specification section 11.3, in that order, which
    is also the plan's Task 7 enumeration. Section 13.4 additionally mentions an
    "evidence note"; that field belongs to ``CapabilityDeclaration``, which
    section 11.3 says an approximated declaration references, and adding an
    unenumerated field to a record Task 8 schema-generates is not authorized here.
    """

    schema_version: Literal["1.0.0"]
    approximation_id: ApproximationId
    capability: CapabilityName
    method: BoundedText
    expected_impact: BoundedText
    prevented_comparison_levels: tuple[ComparisonLevel, ...] = Field(
        max_length=MAX_PREVENTED_COMPARISON_LEVELS
    )
    adapter_version: SemanticVersion

    @field_validator("prevented_comparison_levels")
    @classmethod
    def validate_prevented_levels(
        cls,
        value: tuple[ComparisonLevel, ...],
    ) -> tuple[ComparisonLevel, ...]:
        """An ordered unique set, in the words of specification section 11.3.

        An explicit empty tuple is accepted and means the approximation prevents
        no level, following section 11.5's explicit-empty-array rule.
        """
        if len(set(value)) != len(value):
            raise ValueError("prevented comparison levels must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("prevented comparison levels must be sorted")
        return value


class CompatibilityOutcome(StrEnum):
    """The four approved outcomes of specification sections 11.5 and 13.4.

    ``NOT_APPLICABLE`` and ``UNAVAILABLE`` are distinct on purpose and neither may
    absorb the other: section 13.4 requires an unrunnable-but-compatible adapter to
    record "a terminal availability outcome" and forbids mislabelling it as a
    strategy failure.
    """

    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_APPROXIMATION = "SUPPORTED_WITH_APPROXIMATION"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"


class CompatibilityReason(CanonicalModel):
    """One machine-readable reason for a non-``SUPPORTED`` outcome.

    A nested record, so it declares no ``schema_version``: plan section 3.1 fixes
    that field on every canonical **top-level** record, and the enclosing
    ``CompatibilityResult`` carries it.

    ``error_code`` is closed to the eight outcome-reason rows of plan section 5.9.
    ``capability`` is state-governed in both directions: present exactly when the
    code is a property of one vocabulary member.
    """

    error_code: ErrorCode
    capability: CapabilityName | MISSING = MISSING  # type: ignore[valid-type]

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str) -> str:
        if value not in COMPATIBILITY_REASON_CODES:
            raise ValueError("compatibility reason code is outside the closed set")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """A capability is attached exactly when the code is scoped to one.

        Both directions are enforced. Omitting a capability from a scoped reason
        would let one unmet requirement mask another after deduplication, and
        attaching one to an unscoped reason would invent a claim the resolver never
        made -- and, for an unrecognized name, would make the reason count depend
        on caller text.
        """
        scoped = self.error_code not in _UNSCOPED_REASON_CODES
        present = not _is_missing(self.capability)
        if scoped and not present:
            raise ValueError("a capability-scoped reason must name its capability")
        if present and not scoped:
            raise ValueError("an unscoped reason must not name a capability")
        if present and not CapabilityVocabulary.contains(str(self.capability)):
            raise ValueError("a reason capability must be a vocabulary member")
        return self


class CompatibilityResult(CanonicalModel):
    """The deterministic outcome of one requirement-set-to-adapter resolution.

    **Specification section 11.3 carries no row for this record.** The plan's
    section 9 field-list paragraph (Task 2, plan line 2941) names it among the
    models taking "exactly the minimum fields their specification section 11.3 rows
    list", but no such row exists -- nor one for
    ``ComparisonEligibilityResult``. The field set is
    therefore derived, and each derivation is named here so a reviewer can check
    it against a binding sentence rather than against a table that is absent:

    - ``schema_version`` -- section 11.1, and Task 8 generates this record's schema
    - ``outcome`` -- sections 13.3 and 13.4, exactly one of four
    - ``capability_vocabulary_version`` -- section 13.3 step 1, the version the
      decision was made under; pinned to the literal because a new version needs a
      reviewed migration per section 13.1
    - ``requested_comparison_level`` -- the ``comparison_level`` parameter of the
      section 8.2 signature, retained because section 13.4 makes level exclusion a
      material consequence
    - ``adapter_name`` and ``adapter_version`` -- section 17.2.1's requirement that
      an ``UNAVAILABLE`` retry observation "matches the same
      adapter/executable/version identity"
    - ``availability_observation_id`` -- the section 11.3 observation identity,
      which ``EngineRunRecord`` links by the same field name
    - ``reasons`` -- section 13.3's "all reasons in stable capability-name order"
    - ``approximations`` -- section 13.3 step 7's "with all approximation records"

    No ``compatibility_result_id`` and no ``created_at_utc``: plan section 6.2
    authorizes exactly two new identifier types, ``appx_`` and ``avail_``, so the
    plan does not treat this as an independently identified operational record.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_result_schema_extra
    )

    schema_version: Literal["1.0.0"]
    outcome: CompatibilityOutcome
    capability_vocabulary_version: Literal["capabilities/v1"]
    requested_comparison_level: ComparisonLevel
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    availability_observation_id: AvailabilityObservationId
    reasons: tuple[CompatibilityReason, ...] = Field(
        max_length=MAX_COMPATIBILITY_REASONS
    )
    approximations: tuple[ApproximationDeclaration, ...] = Field(
        max_length=MAX_COMPATIBILITY_APPROXIMATIONS
    )

    @field_validator("reasons")
    @classmethod
    def validate_reasons(
        cls,
        value: tuple[CompatibilityReason, ...],
    ) -> tuple[CompatibilityReason, ...]:
        """Deduplicated and totally ordered, enforced at the record boundary.

        Enforcing it here rather than only in the resolver means a hand-built
        result cannot publish an order the resolver would never produce, so the
        byte-identity property is a property of the *type*, not of one code path.
        """
        keys = tuple(reason_sort_key(reason) for reason in value)
        if len(set(keys)) != len(keys):
            raise ValueError("compatibility reasons must be deduplicated")
        if keys != tuple(sorted(keys)):
            raise ValueError("compatibility reasons must be canonically ordered")
        return value

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls,
        value: tuple[ApproximationDeclaration, ...],
    ) -> tuple[ApproximationDeclaration, ...]:
        """At most one record per capability, in capability order."""
        _unique_sorted_text(
            tuple(item.capability for item in value),
            "result approximations",
        )
        return value

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        """The state-governed optionality of this record, as an invariant.

        Specification section 11.5 requires canonical boundary fields to be
        required unless absence is state-dependent, so neither collection is
        optional; what varies is whether it is empty, and that is fixed by the
        outcome:

        - ``SUPPORTED`` -- nothing to explain and nothing approximated
        - ``SUPPORTED_WITH_APPROXIMATION`` -- every applied record is attached, per
          section 13.4, and there is still no defect to report
        - ``NOT_APPLICABLE`` and ``UNAVAILABLE`` -- at least one reason, and no
          approximation record, because no run may proceed on either outcome

        Enforcing this on the type is what prevents the two negative outcomes from
        collapsing into one another silently: a result claiming ``UNAVAILABLE``
        with an approximation record attached would read as a partially successful
        resolution, which section 13.4 forbids.
        """
        negative = {
            CompatibilityOutcome.NOT_APPLICABLE,
            CompatibilityOutcome.UNAVAILABLE,
        }
        if self.outcome in negative:
            if not self.reasons:
                raise ValueError("a negative outcome requires at least one reason")
            if self.approximations:
                raise ValueError("a negative outcome carries no approximation record")
            return self
        if self.reasons:
            raise ValueError("a supported outcome carries no reason")
        if self.outcome is CompatibilityOutcome.SUPPORTED and self.approximations:
            raise ValueError("a natively supported outcome carries no approximation")
        if (
            self.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
            and not self.approximations
        ):
            raise ValueError("an approximated outcome requires every applied record")
        return self


def reason_sort_key(reason: CompatibilityReason) -> tuple[str, str]:
    """Return the total ordering key for one compatibility reason.

    Total over material content: a reason carries exactly ``error_code`` and an
    optional ``capability``, so two reasons equal on this key are byte-identical
    and one was already removed by deduplication. No tie can therefore be resolved
    by generation order, which is what makes a permutation test non-vacuous.

    An unscoped reason takes the empty string, which sorts before every
    ``CapabilityName`` because that pattern requires a leading lowercase letter --
    the same device plan section 5.10 fixes for a spec-level finding.
    """
    capability = reason.capability
    return ("" if _is_missing(capability) else str(capability), reason.error_code)
