"""Order-independence and reason stability of the compatibility resolver.

Specification section 13.3 makes resolution "a pure function" of its inputs and
requires "all reasons in stable capability-name order". Section 28.4 lists
"compatibility-result determinism under capability input ordering" as an
acceptance subject. These properties are what make that executable: a
hand-written permutation pair proves one ordering is stable, while a property test
searches for the ordering that is not.

The strategies deliberately reach the step-1 recognition branches as well as the
ordinary path -- an out-of-vocabulary requirement name, a foreign descriptor
vocabulary version, and a duplicated declaration are all drawn -- because a
generator restricted to well-formed input would leave ``_recognition_reasons``
entirely unexercised by this layer.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from crypto_lab.capabilities.models import (
    APPROXIMATION_DISALLOWED,
    APPROXIMATION_MISSING,
    LEVEL_PREVENTED,
    MAX_COMPATIBILITY_REASONS,
    REQUIREMENT_UNMET,
    RUNTIME_UNAVAILABLE,
    ApproximationDeclaration,
    CompatibilityOutcome,
    CompatibilityResult,
)
from crypto_lab.capabilities.policy import (
    PROHIBITED_CAPABILITIES,
    project_1_compatibility_policy,
)
from crypto_lab.capabilities.resolver import CompatibilityResolver
from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    RuntimeAvailabilityObservation,
    SupportedSchemaVersion,
)
from crypto_lab.domain.results import Failure, Result, Success

_OBSERVED = datetime(2026, 8, 24, 12, tzinfo=UTC)
_EXPIRES = datetime(2026, 8, 24, 13, tzinfo=UTC)
_OBSERVATION_ID = "avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e"
_UUID_BODY = "5b1c3d7e-2f4a-4c6b-8d9e-1a2b3c4d5e6"
#: Every vocabulary name the safety policy permits in a request, so the ordinary
#: resolution path is reachable. The prohibited four have their own property.
_PERMITTED = tuple(
    name for name in CapabilityVocabulary.names if name not in PROHIBITED_CAPABILITIES
)
_SUPPORT_KINDS = ("NATIVE", "APPROXIMATED", "UNSUPPORTED")
#: Well-formed ``CapabilityName`` values that are not vocabulary members, so the
#: step-1 recognition branch is reachable from the generated space.
_OUT_OF_VOCABULARY = ("market.crypto", "venue.binance", "orders.live")
#: Drawn so the descriptor-side vocabulary-version branch is reachable too.
_VOCABULARY_VERSIONS = ("capabilities/v1", "capabilities/v1", "capabilities/v2")
#: Authoring versions for the provenance-invariance property. ``1.0.0`` matches the
#: descriptor; the others deliberately do not, because a differing authoring
#: version must not affect the decision.
_AUTHORING_VERSIONS = ("1.0.0", "2.0.0", "0.9.1", "3.1.4")


def _engine() -> EngineDescriptor:
    return EngineDescriptor(
        schema_version="1.0.0",
        engine_name="engine.alpha",
        engine_version="1.2.3",
        engine_family="engine.family",
        planned_role="Research simulation.",
        known_limitations=(),
    )


def _descriptor(
    native: tuple[str, ...],
    approximated: tuple[str, ...],
    unsupported: tuple[str, ...],
    *,
    network_required: bool = False,
    vocabulary_version: str = "capabilities/v1",
) -> AdapterDescriptor:
    return AdapterDescriptor(
        schema_version="1.0.0",
        adapter_name="adapter.alpha",
        adapter_version="1.0.0",
        engine=_engine(),
        supported_protocol_versions=("1.0.0",),
        supported_schema_versions=(
            SupportedSchemaVersion(
                schema_name="domain.instrument-ref",
                schema_version="1.0.0",
            ),
        ),
        capability_vocabulary_version=vocabulary_version,
        native_capabilities=native,
        approximated_capabilities=approximated,
        unsupported_capabilities=unsupported,
        supported_operating_systems=(OperatingSystem.WINDOWS,),
        runtime_requirements=(),
        network_required=network_required,
        credentials_required=False,
        known_modeling_limitations=(),
        executable_hash="a" * 64,
    )


def _observation(*, available: bool = True) -> RuntimeAvailabilityObservation:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "availability_observation_id": _OBSERVATION_ID,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": "C:/adapters/alpha/adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_version": "3.12.13",
        "operating_system": OperatingSystem.WINDOWS,
        "available": available,
        "observed_at_utc": _OBSERVED,
        "expires_at_utc": _EXPIRES,
        "network_required": False,
        "credentials_required": False,
    }
    if not available:
        payload["reason_code"] = RUNTIME_UNAVAILABLE
    return RuntimeAvailabilityObservation.model_validate(payload)


def _approximation_id(index: int) -> str:
    return f"appx_{_UUID_BODY}{index % 10:x}"


@st.composite
def _resolution_inputs(
    draw: st.DrawFn,
) -> tuple[
    tuple[CapabilityRequirement, ...],
    AdapterDescriptor,
    RuntimeAvailabilityObservation,
    ComparisonLevel,
    tuple[ApproximationDeclaration, ...],
]:
    """Draw one coherent resolver input set.

    The descriptor partition is always disjoint, unique, and sorted, because
    ``AdapterDescriptor`` rejects anything else; the interesting variation is which
    capabilities a strategy requires, whether the adapter declares them, and
    whether a matching approximation record exists.
    """
    declared = draw(st.lists(st.sampled_from(_PERMITTED), unique=True, max_size=8))
    kinds = {name: draw(st.sampled_from(_SUPPORT_KINDS)) for name in declared}
    native = tuple(sorted(n for n in declared if kinds[n] == "NATIVE"))
    approximated = tuple(sorted(n for n in declared if kinds[n] == "APPROXIMATED"))
    unsupported = tuple(sorted(n for n in declared if kinds[n] == "UNSUPPORTED"))

    required_names = draw(
        st.lists(
            st.sampled_from((*_PERMITTED, *_OUT_OF_VOCABULARY)),
            unique=True,
            max_size=6,
        )
    )
    requirements = tuple(
        CapabilityRequirement(
            schema_version="1.0.0",
            capability=name,
            required=draw(st.booleans()),
            minimum_semantics="capabilities/v1",
            approximation_policy=draw(st.sampled_from(tuple(ApproximationPolicy))),
            comparison_levels=(),
        )
        for name in required_names
    )

    declarations: list[ApproximationDeclaration] = []
    for index, name in enumerate(approximated):
        if not draw(st.booleans()):
            continue
        prevented = tuple(
            sorted(
                draw(
                    st.lists(
                        st.sampled_from(tuple(ComparisonLevel)),
                        unique=True,
                        max_size=3,
                    )
                ),
                key=str,
            )
        )
        declaration = ApproximationDeclaration(
            schema_version="1.0.0",
            approximation_id=_approximation_id(index),
            capability=name,
            method="Modelled by substitution at the bar boundary.",
            expected_impact="May differ from native execution semantics.",
            prevented_comparison_levels=prevented,
            adapter_version="1.0.0",
        )
        declarations.append(declaration)
        # Occasionally duplicate, so the declaration-overlap branch is reachable.
        if draw(st.booleans()):
            declarations.append(declaration)

    return (
        requirements,
        _descriptor(
            native,
            approximated,
            unsupported,
            network_required=draw(st.booleans()),
            vocabulary_version=draw(st.sampled_from(_VOCABULARY_VERSIONS)),
        ),
        _observation(available=draw(st.booleans())),
        draw(st.sampled_from(tuple(ComparisonLevel))),
        tuple(declarations),
    )


def _resolve(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
) -> Result[CompatibilityResult]:
    requirements, descriptor, availability, level, declarations = inputs
    return CompatibilityResolver.resolve(
        requirements,
        descriptor,
        availability,
        level,
        project_1_compatibility_policy(),
        declarations,
    )


@given(inputs=_resolution_inputs(), data=st.data())
def test_permuting_the_inputs_yields_byte_identical_results(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
    data: st.DataObject,
) -> None:
    """Requirement order and declaration order are semantically immaterial.

    Both collections are unordered sets of facts, so the serialized result must not
    reveal the order they arrived in. ``st.permutations`` is used rather than a
    cyclic rotation: a rotation cannot produce an adjacent swap with everything
    else fixed, which is exactly the shape an unstable secondary sort key would
    expose. Hypothesis replays a drawn permutation exactly, so reproducibility is
    unaffected.
    """
    requirements, descriptor, availability, level, declarations = inputs
    baseline = _resolve(inputs)
    permuted = _resolve(
        (
            tuple(data.draw(st.permutations(requirements))),
            descriptor,
            availability,
            level,
            tuple(data.draw(st.permutations(declarations))),
        )
    )
    assert canonical_json_bytes(baseline) == canonical_json_bytes(permuted)


@given(inputs=_resolution_inputs())
def test_every_result_is_one_approved_outcome_with_canonical_reasons(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
) -> None:
    """``SUPPORTED`` is predicted independently of the resolver's own bookkeeping.

    Sortedness, deduplication, and the outcome-to-collection biconditional are
    deliberately **not** asserted here: ``CompatibilityResult``'s own validators
    enforce all three at construction, so any result the resolver manages to build
    satisfies them by definition and asserting them again would be vacuous. What
    is worth checking is the decision itself, recomputed from the drawn inputs
    without consulting the resolver -- and the reason count against its bound,
    which no validator enforces.
    """
    requirements, descriptor, availability, _level, declarations = inputs
    resolved = _resolve(inputs)
    assert isinstance(resolved, Success), resolved
    result = resolved.value
    assert len(result.reasons) <= MAX_COMPATIBILITY_REASONS

    every_name_recognized = all(
        CapabilityVocabulary.contains(name)
        for name in (
            *(item.capability for item in requirements),
            *descriptor.native_capabilities,
            *descriptor.approximated_capabilities,
            *descriptor.unsupported_capabilities,
            *(item.capability for item in declarations),
        )
    )
    # A declaration's `adapter_version` is provenance, not eligibility, so it is
    # deliberately absent from this predicate: specification section 11.3 requires
    # only that it be "included in run provenance", and section 13.2 closes
    # descriptor invalidity to unknown names and overlapping declarations.
    declared_capabilities = [item.capability for item in declarations]
    declarations_consistent = len(set(declared_capabilities)) == len(
        declared_capabilities
    ) and all(
        name in descriptor.approximated_capabilities for name in declared_capabilities
    )
    version_agrees = descriptor.capability_vocabulary_version == "capabilities/v1"
    all_native = all(
        item.capability in descriptor.native_capabilities
        for item in requirements
        if item.required
    )
    # Adapter identity, hash, and operating system always agree in this generated
    # space, so runnability reduces to availability and the network declaration.
    runnable = availability.available and not descriptor.network_required

    if (
        every_name_recognized
        and declarations_consistent
        and version_agrees
        and all_native
        and runnable
    ):
        assert result.outcome is CompatibilityOutcome.SUPPORTED
        assert result.reasons == ()
        assert result.approximations == ()


@given(inputs=_resolution_inputs())
def test_every_unmet_required_capability_appears_in_the_reasons(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
) -> None:
    """Completeness, computed independently of the resolver's own bookkeeping.

    Skipped when a step-1 finding is present, because step 1 returns before steps
    2 to 4 run -- the documented per-step completeness contract. That case has its
    own dedicated unit test rather than being smuggled in here.
    """
    requirements, descriptor, _availability, _level, declarations = inputs
    resolved = _resolve(inputs)
    assert isinstance(resolved, Success)
    result = resolved.value

    if any(
        not CapabilityVocabulary.contains(name)
        for name in (
            *(item.capability for item in requirements),
            *descriptor.native_capabilities,
            *descriptor.approximated_capabilities,
            *descriptor.unsupported_capabilities,
            *(item.capability for item in declarations),
        )
    ):
        return
    if descriptor.capability_vocabulary_version != "capabilities/v1":
        return
    declared_capabilities = [item.capability for item in declarations]
    if len(set(declared_capabilities)) != len(declared_capabilities):
        return

    satisfiable = frozenset(descriptor.native_capabilities) | frozenset(
        descriptor.approximated_capabilities
    )
    expected = frozenset(
        requirement.capability
        for requirement in requirements
        if requirement.required and requirement.capability not in satisfiable
    )
    if not expected:
        return
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    reported = frozenset(
        str(reason.capability)
        for reason in result.reasons
        if reason.error_code == REQUIREMENT_UNMET
    )
    assert reported == expected


@given(inputs=_resolution_inputs())
def test_runtime_availability_never_changes_a_semantic_verdict(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
) -> None:
    """Section 13.3: runtime absence is never strategy incompatibility.

    Flipping only ``available`` may turn a positive outcome into ``UNAVAILABLE``,
    but it must never turn ``NOT_APPLICABLE`` into anything else, and it must never
    manufacture a semantic reason.
    """
    requirements, descriptor, _availability, level, declarations = inputs
    semantic_codes = {
        REQUIREMENT_UNMET,
        APPROXIMATION_MISSING,
        APPROXIMATION_DISALLOWED,
        LEVEL_PREVENTED,
    }
    outcomes = {}
    for available in (True, False):
        resolved = _resolve(
            (
                requirements,
                descriptor,
                _observation(available=available),
                level,
                declarations,
            )
        )
        assert isinstance(resolved, Success)
        outcomes[available] = resolved.value

    if outcomes[True].outcome is CompatibilityOutcome.NOT_APPLICABLE:
        assert outcomes[False].outcome is CompatibilityOutcome.NOT_APPLICABLE
        assert canonical_json_bytes(outcomes[True]) == canonical_json_bytes(
            outcomes[False]
        )
    unavailable_reasons = {reason.error_code for reason in outcomes[False].reasons}
    if outcomes[False].outcome is CompatibilityOutcome.UNAVAILABLE:
        assert unavailable_reasons.isdisjoint(semantic_codes)


@given(inputs=_resolution_inputs(), authoring=st.sampled_from(_AUTHORING_VERSIONS))
def test_the_declaration_authoring_version_is_provenance_only(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
    authoring: str,
) -> None:
    """Restamping every declaration's authoring version cannot move the decision.

    Specification section 11.3 makes ``adapter_version`` a provenance record, so it
    must be invisible to the outcome and to the reason set. **What this property
    asserts broadly** is exactly that invariance -- outcome, reason set, and the set
    of capabilities whose declarations were applied -- all of which are reachable
    for any drawn input, so a version-equality rule reintroduced anywhere in step 1
    surfaces here.

    The provenance assertion at the end is deliberately *not* claimed to be broadly
    reached: landing on ``SUPPORTED_WITH_APPROXIMATION`` needs a narrow conjunction
    of drawn conditions, so ``approximations`` is often empty and that assertion is
    then trivially true. The deterministic proof that provenance is retained rather
    than rewritten lives in the resolver unit tests; this property covers the
    invariance, not the retention.
    """
    requirements, descriptor, availability, level, declarations = inputs
    restamped = tuple(
        item.model_copy(update={"adapter_version": authoring}) for item in declarations
    )
    baseline = _resolve(inputs)
    changed = _resolve((requirements, descriptor, availability, level, restamped))
    assert isinstance(baseline, Success)
    assert isinstance(changed, Success)
    assert baseline.value.outcome is changed.value.outcome
    assert baseline.value.reasons == changed.value.reasons
    # Which declarations were applied must be identical, not merely how many. This
    # is reachable for every drawn input, including the empty case.
    assert tuple(item.capability for item in baseline.value.approximations) == tuple(
        item.capability for item in changed.value.approximations
    )
    assert all(
        item.adapter_version == authoring for item in changed.value.approximations
    )


@given(
    inputs=_resolution_inputs(),
    prohibited=st.sampled_from(PROHIBITED_CAPABILITIES),
    position=st.integers(min_value=0, max_value=8),
)
def test_a_prohibited_capability_always_prevents_a_result(
    inputs: tuple[
        tuple[CapabilityRequirement, ...],
        AdapterDescriptor,
        RuntimeAvailabilityObservation,
        ComparisonLevel,
        tuple[ApproximationDeclaration, ...],
    ],
    prohibited: str,
    position: int,
) -> None:
    """No arrangement of the other inputs can let a prohibited request through."""
    requirements, descriptor, availability, level, declarations = inputs
    injected = CapabilityRequirement(
        schema_version="1.0.0",
        capability=prohibited,
        required=False,
        minimum_semantics="capabilities/v1",
        approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
        comparison_levels=(),
    )
    index = position % (len(requirements) + 1)
    combined = (*requirements[:index], injected, *requirements[index:])
    resolved = _resolve((combined, descriptor, availability, level, declarations))
    assert isinstance(resolved, Failure)
    assert len(resolved.diagnostics) >= 1
