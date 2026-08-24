"""The pure deterministic compatibility resolver of specification section 13.3.

The seven-step order below is the specification's, in the specification's
sequence. Nothing here reads a clock, the filesystem, the environment, the
network, process state, machine identity, or a random source; imports an engine or
an adapter; launches a process; evaluates a strategy; or touches market data. The
result is a function of the six explicit immutable arguments alone, and no value
is cached in module state.

Three properties are load-bearing and are stated rather than left to the reader:

1. **Safety policy comes first.** A prohibited request produces a
   ``USER_CONFIGURATION`` diagnostic and **no** ``CompatibilityResult``. The check
   runs before every recognition, comparison, and availability check, so a
   descriptor declaring ``runtime.live`` natively can never obtain it.
2. **Runtime absence and strategy incompatibility never substitute for each
   other.** Section 13.3 places the ``NOT_APPLICABLE`` steps before the
   ``UNAVAILABLE`` step, so a strategy the engine cannot model is reported as
   such even when the runtime is also missing; and section 13.4 forbids recording
   an unrunnable-but-compatible adapter as a strategy failure.
3. **Reasons are complete within the step that returns them.** Section 13.3's
   completeness requirement is that resolution "never stops at the first missing
   capability" -- step 3 -- and steps 3 and 4 are evaluated together so their
   reasons cannot mask each other. Reasons are deduplicated by material content
   and returned in a total order, so no input permutation changes the serialized
   bytes.

   **Stated precisely, because the weaker reading is what the code does.**
   Completeness is per-returning-step, not global. Step 1 returns before steps 2
   to 4 run, so a requirement naming a capability outside the vocabulary is
   reported *instead of*, not alongside, the unmet vocabulary requirements. And
   because an unrecognized name is deliberately reported unscoped -- see
   ``crypto_lab.capabilities.models`` on why the capability is not echoed back --
   a strategy-side and an adapter-side ``UNKNOWN_NAME`` are byte-identical and
   deduplicate to a single reason. Both behaviours are pinned by test so they stay
   deliberate.

**Three specification clauses are not discharged here, and none is silently
skipped.** Step 1 names "protocol, and schema versions"; step 5 names "pinned
version, negotiated protocol". Those have no input at the section 8.2 signature:
``resolve`` receives no ``NegotiationResult``, no requested protocol or schema
version, and no descriptor counterpart for ``availability.runtime_version``, while
``descriptor.runtime_requirements`` is unstructured bounded text. They belong to
the stage that owns ``NegotiationResult``, which remains deferred.
"""

from __future__ import annotations

from crypto_lab.capabilities.models import (
    APPROXIMATION_DISALLOWED,
    APPROXIMATION_MISSING,
    DECLARATION_OVERLAP,
    LEVEL_PREVENTED,
    REQUIREMENT_UNMET,
    RUNTIME_UNAVAILABLE,
    UNKNOWN_NAME,
    VOCABULARY_VERSION,
    ApproximationDeclaration,
    CompatibilityOutcome,
    CompatibilityReason,
    CompatibilityResult,
    reason_sort_key,
)
from crypto_lab.capabilities.policy import (
    CompatibilityPolicy,
    validate_safety_policy,
)
from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.results import Failure, Result, Success


def _reason(code: str, capability: str | None = None) -> CompatibilityReason:
    if capability is None:
        return CompatibilityReason(error_code=code)
    return CompatibilityReason(error_code=code, capability=capability)


def _ordered(reasons: list[CompatibilityReason]) -> tuple[CompatibilityReason, ...]:
    """Deduplicate by material content, then order totally.

    Deduplication precedes ordering, so the sequence is a function of the *set* of
    logical reasons rather than of generation order. The key is total over material
    content -- a reason carries exactly a code and an optional capability -- so no
    tie can survive to be broken by arrival order, which is what makes the
    permutation property non-vacuous.
    """
    unique: dict[tuple[str, str], CompatibilityReason] = {}
    for reason in reasons:
        unique.setdefault(reason_sort_key(reason), reason)
    return tuple(unique[key] for key in sorted(unique))


def _recognition_reasons(
    requirements: tuple[CapabilityRequirement, ...],
    descriptor: AdapterDescriptor,
    policy: CompatibilityPolicy,
    approximations: tuple[ApproximationDeclaration, ...],
) -> tuple[list[CompatibilityReason], list[CompatibilityReason]]:
    """Step 1, partitioned by which side of the pairing is defective.

    The partition decides the outcome. A requirement naming a capability outside
    the declared vocabulary can never be satisfied by *any* conforming descriptor,
    so that incompatibility is unconditional and belongs to the strategy. A
    descriptor defect -- an unrecognized declared name, a vocabulary-version
    mismatch, or a declaration set contradicting the descriptor's own partition --
    is conditional on this adapter: section 13.2 says such a descriptor is
    invalidated and section 11.3 says a failed negotiation "makes the adapter
    unavailable", which section 13.4 records as ``UNAVAILABLE`` rather than as a
    strategy failure. A declaration's *authoring* version is not part of that set;
    see the note at the end of this function.

    Both lists are returned, and the caller emits their union when the
    strategy-side list is non-empty. That is *not* the same as every finding
    surviving: ``UNKNOWN_NAME`` is unscoped on both sides, so a strategy-side and
    an adapter-side occurrence share one material identity and deduplicate to one
    reason. The outcome still distinguishes them -- strategy-side yields
    ``NOT_APPLICABLE``, adapter-side alone yields ``UNAVAILABLE`` -- and the
    unscoped form is what keeps the reason count a function of the closed
    vocabulary rather than of arbitrary caller text.
    """
    strategy_side: list[CompatibilityReason] = []
    adapter_side: list[CompatibilityReason] = []

    # The requirement side of the version check needs no runtime comparison.
    # ``CapabilityRequirement.minimum_semantics`` and
    # ``CompatibilityPolicy.capability_vocabulary_version`` are both
    # ``Literal["capabilities/v1"]``, so agreement holds by construction and a
    # runtime comparison would be unreachable code asserting a type-level fact.
    # ``test_a_requirement_cannot_declare_a_foreign_vocabulary`` pins that.
    for requirement in requirements:
        if not CapabilityVocabulary.contains(requirement.capability):
            strategy_side.append(_reason(UNKNOWN_NAME))

    if descriptor.capability_vocabulary_version != policy.capability_vocabulary_version:
        adapter_side.append(_reason(VOCABULARY_VERSION))

    declared = (
        descriptor.native_capabilities
        + descriptor.approximated_capabilities
        + descriptor.unsupported_capabilities
    )
    for capability in declared:
        if not CapabilityVocabulary.contains(capability):
            adapter_side.append(_reason(UNKNOWN_NAME))

    approximated = frozenset(descriptor.approximated_capabilities)
    seen: set[str] = set()
    for declaration in approximations:
        if not CapabilityVocabulary.contains(declaration.capability):
            adapter_side.append(_reason(UNKNOWN_NAME))
            continue
        if declaration.capability in seen:
            adapter_side.append(_reason(DECLARATION_OVERLAP, declaration.capability))
            continue
        seen.add(declaration.capability)
        if declaration.capability not in approximated:
            adapter_side.append(_reason(DECLARATION_OVERLAP, declaration.capability))

    # `declaration.adapter_version` is deliberately **not** compared with
    # `descriptor.adapter_version`. Specification section 11.3 says only that the
    # "declaration version is included in run provenance" -- it records which
    # adapter version authored the declaration and imposes no equality on the
    # descriptor being resolved -- and section 13.2 closes descriptor invalidity to
    # exactly "unknown capability names or overlapping declarations", which a
    # differing authoring version is not. The specification's one same-identity
    # requirement is section 17.2.1's, and it governs the availability observation;
    # `_is_runnable` enforces it. Treating a version difference as an overlap would
    # invent a provenance-equality constraint no normative source imposes and would
    # make a legitimate declaration unusable the moment an adapter version bumps.
    return strategy_side, adapter_side


def _semantic_reasons(
    requirements: tuple[CapabilityRequirement, ...],
    descriptor: AdapterDescriptor,
    comparison_level: ComparisonLevel,
    declarations: dict[str, ApproximationDeclaration],
) -> tuple[list[CompatibilityReason], dict[str, ApproximationDeclaration]]:
    """Steps 2 through 4, evaluated together because both return the same outcome.

    Steps 3 and 4 both yield ``NOT_APPLICABLE``, so collecting them in one pass and
    returning the union preserves the specification's order while making the reason
    set maximally complete: an unmet requirement never masks a disallowed
    approximation on a different capability, and vice versa.

    Only requirements with ``required=True`` gate the outcome. Steps 2 and 3 speak
    of every *required* capability, so an unsatisfiable optional requirement is not
    an incompatibility. The same scoping governs record attachment, because steps 4
    and 7 both condition on an approximation being *required* -- "if approximations
    are required", "if at least one allowed approximation is required" -- and
    nothing requires an approximation for a capability the strategy declares
    optional. The consequence is recorded rather than hidden: a declaration whose
    ``prevented_comparison_levels`` includes the requested level, for an
    *optional* capability, produces no reason and attaches no record. Whether an
    optional capability can be exercised by a run is not defined by any source
    read here; it is raised for the task that owns comparison eligibility.

    ``CapabilityRequirement.comparison_levels`` is deliberately not consulted.
    Section 13.3 gives the resolver one ``comparison_level`` argument and never
    directs it to filter requirements by their declared level scope; treating a
    level-scoped requirement as inactive would make resolution more permissive
    with no source. The field is consumed by the comparison-eligibility layer.
    """
    native = frozenset(descriptor.native_capabilities)
    approximated = frozenset(descriptor.approximated_capabilities)
    unsupported = frozenset(descriptor.unsupported_capabilities)
    reasons: list[CompatibilityReason] = []
    applied: dict[str, ApproximationDeclaration] = {}

    for requirement in requirements:
        if not requirement.required:
            continue
        capability = requirement.capability
        if capability in native:
            continue
        if capability in unsupported or capability not in approximated:
            # Absence lands here too: section 13.2 states that "absence is not
            # interpreted as native support", so an undeclared capability is unmet
            # rather than silently satisfied.
            reasons.append(_reason(REQUIREMENT_UNMET, capability))
            continue

        # Three independent predicates over one approximated capability. Each is
        # reported when it holds, because a strategy that forbids approximation and
        # an adapter that declared none are separate facts a user must both fix.
        declaration = declarations.get(capability)
        if requirement.approximation_policy is ApproximationPolicy.REJECT:
            reasons.append(_reason(APPROXIMATION_DISALLOWED, capability))
        if declaration is None:
            reasons.append(_reason(APPROXIMATION_MISSING, capability))
            continue
        if comparison_level in declaration.prevented_comparison_levels:
            reasons.append(_reason(LEVEL_PREVENTED, capability))
        applied[capability] = declaration

    # No filtering of `applied` against `reasons` is performed here, and none is
    # needed. The caller consumes `applied` only when `reasons` is empty, and
    # `CompatibilityResult.validate_outcome_shape` independently forbids a negative
    # outcome from carrying any approximation record -- so the invariant is
    # enforced on the type rather than by a pass that could never fire.
    return reasons, applied


def _is_runnable(
    descriptor: AdapterDescriptor,
    availability: RuntimeAvailabilityObservation,
) -> bool:
    """Step 5, as a single predicate over explicit observed facts.

    The granular cause stays on ``RuntimeAvailabilityObservation.reason_code``
    rather than being split across error codes plan section 5.9's closed table does
    not contain, so this returns one boolean and the resolver emits one reason.

    Identity agreement is part of runnability, not a separate concern: an
    observation recorded for a different adapter, version, or executable is not
    evidence about *this* pairing, and specification section 17.2.1 requires an
    ``UNAVAILABLE`` retry observation to match "the same adapter/executable/version
    identity".

    Expiry is deliberately not evaluated. The resolver has no clock and plan
    section 5.1 forbids acquiring one; the observation's own construction already
    guarantees ``expires_at_utc`` follows ``observed_at_utc``, and freshness against
    a current instant belongs to the stage that owns a ``Clock``.
    """
    if not availability.available:
        return False
    if availability.adapter_name != descriptor.adapter_name:
        return False
    if availability.adapter_version != descriptor.adapter_version:
        return False
    if availability.executable_hash != descriptor.executable_hash:
        return False
    if availability.operating_system not in descriptor.supported_operating_systems:
        return False
    # Section 24.4: Project 1 policy rejects any operation that would require
    # network access, while the same section allows such a descriptor to be
    # represented "for future compatibility analysis". Recording it as not runnable
    # honours both, where a safety-policy rejection would produce no result at all.
    return not (descriptor.network_required or availability.network_required)


class CompatibilityResolver:
    """Resolve one immutable requirement set against one adapter descriptor.

    Stateless by construction, following the ``StrategyLoader`` precedent:
    ``__slots__`` is empty and ``resolve`` is a ``staticmethod``, so there is no
    configuration, no cached clock, and no memoized decision an instance could
    carry.
    """

    __slots__ = ()

    @staticmethod
    def resolve(
        requirements: tuple[CapabilityRequirement, ...],
        descriptor: AdapterDescriptor,
        availability: RuntimeAvailabilityObservation,
        comparison_level: ComparisonLevel,
        policy: CompatibilityPolicy,
        approximations: tuple[ApproximationDeclaration, ...],
    ) -> Result[CompatibilityResult]:
        """Return one compatibility decision, or a safety-policy failure.

        The first five parameters are exactly specification section 8.2's, with
        their names, types, and order unchanged. ``approximations`` is appended
        because **no 8.2 parameter can supply the input section 13.3 step 4
        requires**: that step mandates verifying no approximation "prevents the
        requested comparison level", which is readable only from
        ``ApproximationDeclaration.prevented_comparison_levels``.
        ``AdapterDescriptor`` carries capability *names* alone and its generated
        schema is frozen byte-identical, so no field may be added to it;
        ``CapabilityRequirement`` carries a policy, not declarations; and section
        11.3 makes ``CapabilityDeclaration`` the record that "reference[s] an
        ``ApproximationDeclaration``" -- which is itself neither an 8.2 parameter
        nor a descriptor field. Every alternative shape is therefore also a sixth
        parameter, so no parameter-preserving option exists. Section 13.3's own
        input list additionally names "experiment assumptions", so 8.2 is in any
        case not exhaustive on count -- but that observation alone would license
        some sixth parameter rather than this one, and reachability is the
        authorising argument.

        A ``Failure`` is returned only for a safety-policy rejection, and it
        carries no ``CompatibilityResult``, exactly as section 13.3 requires.
        Section 8.2's preamble forbids communicating an expected boundary failure
        through an exception alone, which is why the return type is ``Result``.
        """
        # ---- Step 0: core safety policy, before every other check.
        prohibited = validate_safety_policy(
            requirements, descriptor, availability, policy
        )
        if prohibited:
            return Failure(outcome="FAILURE", diagnostics=prohibited)

        def _decide(
            outcome: CompatibilityOutcome,
            reasons: tuple[CompatibilityReason, ...],
            applied: tuple[ApproximationDeclaration, ...],
        ) -> Result[CompatibilityResult]:
            return Success[CompatibilityResult](
                outcome="SUCCESS",
                value=CompatibilityResult(
                    schema_version="1.0.0",
                    outcome=outcome,
                    capability_vocabulary_version="capabilities/v1",
                    requested_comparison_level=comparison_level,
                    adapter_name=descriptor.adapter_name,
                    adapter_version=descriptor.adapter_version,
                    availability_observation_id=(
                        availability.availability_observation_id
                    ),
                    reasons=reasons,
                    approximations=applied,
                ),
            )

        # ---- Step 1: vocabulary and internal consistency.
        strategy_side, adapter_side = _recognition_reasons(
            requirements, descriptor, policy, approximations
        )
        if strategy_side:
            return _decide(
                CompatibilityOutcome.NOT_APPLICABLE,
                _ordered(strategy_side + adapter_side),
                (),
            )
        if adapter_side:
            return _decide(CompatibilityOutcome.UNAVAILABLE, _ordered(adapter_side), ())

        declarations = {
            declaration.capability: declaration for declaration in approximations
        }

        # ---- Steps 2 to 4: requirement comparison and approximation rules.
        semantic, applied = _semantic_reasons(
            requirements, descriptor, comparison_level, declarations
        )
        if semantic:
            return _decide(CompatibilityOutcome.NOT_APPLICABLE, _ordered(semantic), ())

        # ---- Step 5: runnability, reached only once semantics are established.
        if not _is_runnable(descriptor, availability):
            return _decide(
                CompatibilityOutcome.UNAVAILABLE,
                (_reason(RUNTIME_UNAVAILABLE),),
                (),
            )

        # ---- Steps 6 and 7: every required capability is satisfiable.
        if not applied:
            return _decide(CompatibilityOutcome.SUPPORTED, (), ())
        return _decide(
            CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
            (),
            tuple(applied[capability] for capability in sorted(applied)),
        )
