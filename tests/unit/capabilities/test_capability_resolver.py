"""The deterministic compatibility resolver of specification section 13.3.

The seven-step order is normative and is exercised step by step below. The two
distinctions the specification calls out explicitly get their own tests: runtime
absence never becomes strategy incompatibility (section 13.3), and an unrunnable
adapter is never mislabelled as a strategy failure (section 13.4).
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

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
    CompatibilityResult,
)
from crypto_lab.capabilities.policy import (
    POLICY_FORBIDDEN_REQUEST,
    POLICY_LIVE_RUNTIME,
    project_1_compatibility_policy,
)
from crypto_lab.capabilities.resolver import CompatibilityResolver
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
_APPROXIMATION_ID = "appx_5b1c3d7e-2f4a-4c6b-8d9e-1a2b3c4d5e6f"
_OTHER_APPROXIMATION_ID = "appx_7d3e1f5a-4b6c-4d8e-9a1b-2c3d4e5f6a7b"


def _requirement(capability: str, **updates: object) -> CapabilityRequirement:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "capability": capability,
        "required": True,
        "minimum_semantics": "capabilities/v1",
        "approximation_policy": ApproximationPolicy.REJECT,
        "comparison_levels": (ComparisonLevel.LEVEL_1,),
    }
    payload.update(updates)
    return CapabilityRequirement.model_validate(payload)


def _descriptor(**updates: object) -> AdapterDescriptor:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": EngineDescriptor(
            schema_version="1.0.0",
            engine_name="engine.alpha",
            engine_version="1.2.3",
            engine_family="engine.family",
            planned_role="Research simulation.",
            known_limitations=(),
        ),
        "supported_protocol_versions": ("1.0.0",),
        "supported_schema_versions": (
            SupportedSchemaVersion(
                schema_name="domain.instrument-ref",
                schema_version="1.0.0",
            ),
        ),
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ("data.ohlcv", "market.spot", "runtime.backtest"),
        "approximated_capabilities": ("execution.partial_fills",),
        "unsupported_capabilities": ("execution.event_driven",),
        "supported_operating_systems": (OperatingSystem.WINDOWS,),
        "runtime_requirements": (),
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": (),
        "executable_hash": "a" * 64,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _observation(**updates: object) -> RuntimeAvailabilityObservation:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "availability_observation_id": _OBSERVATION_ID,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": "C:/adapters/alpha/adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_version": "3.12.13",
        "operating_system": OperatingSystem.WINDOWS,
        "available": True,
        "observed_at_utc": _OBSERVED,
        "expires_at_utc": _EXPIRES,
        "network_required": False,
        "credentials_required": False,
    }
    payload.update(updates)
    return RuntimeAvailabilityObservation.model_validate(payload)


def _approximation(**updates: object) -> ApproximationDeclaration:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "approximation_id": _APPROXIMATION_ID,
        "capability": "execution.partial_fills",
        "method": "Fills are modelled as all-or-nothing at the bar close.",
        "expected_impact": "Overstates fill certainty for large orders.",
        "prevented_comparison_levels": (),
        "adapter_version": "1.0.0",
    }
    payload.update(updates)
    return ApproximationDeclaration.model_validate(payload)


def _resolve(
    requirements: tuple[CapabilityRequirement, ...],
    *,
    descriptor: AdapterDescriptor | None = None,
    availability: RuntimeAvailabilityObservation | None = None,
    comparison_level: ComparisonLevel = ComparisonLevel.LEVEL_1,
    approximations: tuple[ApproximationDeclaration, ...] = (),
) -> Result[CompatibilityResult]:
    return CompatibilityResolver.resolve(
        requirements,
        descriptor if descriptor is not None else _descriptor(),
        availability if availability is not None else _observation(),
        comparison_level,
        project_1_compatibility_policy(),
        approximations,
    )


def _succeeded(outcome: Result[CompatibilityResult]) -> CompatibilityResult:
    assert isinstance(outcome, Success), outcome
    return outcome.value


def _codes(result: CompatibilityResult) -> tuple[tuple[str, str], ...]:
    """Return each reason as its ``(capability, code)`` pair, unscoped as ``""``."""
    return tuple(
        (
            reason.capability if isinstance(reason.capability, str) else "",
            reason.error_code,
        )
        for reason in result.reasons
    )


# --------------------------------------------------------------------------
# Signature and purity
# --------------------------------------------------------------------------


def test_the_signature_matches_the_normative_operation_contract() -> None:
    """The five specification 8.2 parameters, in order, plus one.

    The authorising argument is **reachability**, not parameter count. Section 13.3
    step 4 requires the resolver to verify that no approximation "prevents the
    requested comparison level", and that is readable only from
    ``ApproximationDeclaration.prevented_comparison_levels``. No 8.2 parameter can
    supply it: ``AdapterDescriptor`` carries capability names only and its schema is
    frozen byte-identical, ``CapabilityRequirement`` carries a policy rather than
    declarations, and section 11.3 makes ``CapabilityDeclaration`` -- itself neither
    an 8.2 parameter nor a descriptor field -- the record that references an
    ``ApproximationDeclaration``. Every alternative shape is therefore also a sixth
    parameter, so no parameter-preserving option exists.

    Section 13.3's input list additionally names "experiment assumptions", so 8.2
    is not exhaustive on count either -- but that alone would license *some* sixth
    parameter rather than this one, which is why it is the secondary argument.

    The parameter has no default, so a safety-relevant input can never be omitted.
    """
    signature = inspect.signature(CompatibilityResolver.resolve)
    assert tuple(signature.parameters) == (
        "requirements",
        "descriptor",
        "availability",
        "comparison_level",
        "policy",
        "approximations",
    )
    for parameter in signature.parameters.values():
        assert parameter.default is inspect.Parameter.empty, parameter.name


def test_the_resolver_carries_no_state_and_caches_no_result() -> None:
    assert CompatibilityResolver.__slots__ == ()
    with pytest.raises(AttributeError):
        CompatibilityResolver().cached = True  # type: ignore[attr-defined]


def test_identical_inputs_produce_byte_identical_results() -> None:
    first = _succeeded(_resolve((_requirement("market.spot"),)))
    second = _succeeded(_resolve((_requirement("market.spot"),)))
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_no_engine_or_adapter_name_can_grant_support() -> None:
    """Section 11.3: "capabilities are not inferred from the engine name".

    Renaming the engine, its family, and the adapter changes nothing, and a
    descriptor whose engine is famously capable still yields ``NOT_APPLICABLE``
    for a capability it does not declare.
    """
    renamed = _descriptor(
        adapter_name="adapter.omega",
        engine=EngineDescriptor(
            schema_version="1.0.0",
            engine_name="engine.vectorbt",
            engine_version="9.9.9",
            engine_family="engine.famous",
            planned_role="Research simulation.",
            known_limitations=(),
        ),
    )
    availability = _observation(adapter_name="adapter.omega")
    native = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            descriptor=renamed,
            availability=availability,
        )
    )
    assert native.outcome is CompatibilityOutcome.SUPPORTED
    undeclared = _succeeded(
        _resolve(
            (_requirement("research.monte_carlo"),),
            descriptor=renamed,
            availability=availability,
        )
    )
    assert undeclared.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(undeclared) == (("research.monte_carlo", REQUIREMENT_UNMET),)


# --------------------------------------------------------------------------
# Step 0 -- safety policy precedes resolution
# --------------------------------------------------------------------------


def test_a_live_runtime_request_never_reaches_an_outcome() -> None:
    """Section 13.3: no ``CompatibilityResult`` is created at all.

    The descriptor declares ``runtime.live`` nowhere and the runtime is available,
    so ordinary resolution would have produced a result. The failure therefore
    proves precedence rather than coinciding with it.
    """
    outcome = _resolve((_requirement("runtime.live"), _requirement("market.spot")))
    assert isinstance(outcome, Failure)
    assert tuple(item.error_code for item in outcome.diagnostics) == (
        POLICY_LIVE_RUNTIME,
    )
    assert not isinstance(outcome, Success)


def test_a_prohibited_request_fails_even_when_the_descriptor_supports_it() -> None:
    """A declared capability grants no exemption from the safety policy."""
    permissive = _descriptor(
        native_capabilities=(
            "direction.short",
            "market.margin",
            "market.spot",
            "runtime.live",
        )
    )
    outcome = _resolve(
        (_requirement("market.margin"), _requirement("direction.short")),
        descriptor=permissive,
    )
    assert isinstance(outcome, Failure)
    assert {item.error_code for item in outcome.diagnostics} == {
        POLICY_FORBIDDEN_REQUEST
    }
    assert len(outcome.diagnostics) == 2


def test_a_policy_failure_is_never_translated_into_an_outcome() -> None:
    """None of the four outcomes may absorb a safety-policy rejection."""
    outcome = _resolve((_requirement("runtime.live"),))
    assert isinstance(outcome, Failure)
    encoded = canonical_json_bytes(outcome)
    for absorbed in (
        b"SUPPORTED",
        b"SUPPORTED_WITH_APPROXIMATION",
        b"NOT_APPLICABLE",
        b"UNAVAILABLE",
    ):
        assert absorbed not in encoded


def test_the_policy_check_precedes_every_recognition_check() -> None:
    """Precedence holds even against a descriptor that is itself unusable.

    A vocabulary-version mismatch would otherwise produce ``UNAVAILABLE`` at step
    1. The prohibited request must still win, or "before compatibility resolution"
    would mean "before some of it".
    """
    outcome = _resolve(
        (_requirement("runtime.live"),),
        descriptor=_descriptor(capability_vocabulary_version="capabilities/v2"),
    )
    assert isinstance(outcome, Failure)
    assert outcome.diagnostics[0].error_code == POLICY_LIVE_RUNTIME


# --------------------------------------------------------------------------
# Step 1 -- recognition and internal consistency
# --------------------------------------------------------------------------


def test_an_unrecognized_required_capability_is_not_applicable() -> None:
    """A strategy-side defect must not be reported as runtime unavailability.

    No conforming ``capabilities/v1`` descriptor can ever declare the name, so the
    incompatibility is unconditional -- which is exactly ``NOT_APPLICABLE``.
    """
    result = _succeeded(_resolve((_requirement("market.crypto"),)))
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("", UNKNOWN_NAME),)


def test_an_unrecognized_descriptor_name_makes_the_adapter_unavailable() -> None:
    """Section 13.2: an unknown name "invalidates the descriptor".

    An invalid descriptor is not a statement about the strategy, so section 13.4's
    "do not mislabel it as strategy failure" applies and the outcome is
    ``UNAVAILABLE``.
    """
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            descriptor=_descriptor(
                native_capabilities=("market.spot", "market.unlisted")
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", UNKNOWN_NAME),)


def test_a_vocabulary_version_mismatch_makes_the_adapter_unavailable() -> None:
    """Section 11.3: a failed negotiation "makes the adapter unavailable"."""
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            descriptor=_descriptor(capability_vocabulary_version="capabilities/v2"),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", VOCABULARY_VERSION),)
    assert result.capability_vocabulary_version == "capabilities/v1"


def test_a_requirement_cannot_declare_a_foreign_vocabulary() -> None:
    """The requirement side of step 1's version check holds at the type level.

    ``CapabilityRequirement.minimum_semantics`` and
    ``CompatibilityPolicy.capability_vocabulary_version`` are both
    ``Literal["capabilities/v1"]``, so the resolver deliberately performs no
    runtime comparison between them: it would be unreachable code asserting a fact
    the types already guarantee. This test is what makes that reasoning binding --
    if either literal is ever widened, it fails and the check must come back.
    """
    annotation = CapabilityRequirement.model_fields["minimum_semantics"].annotation
    assert get_args(annotation) == ("capabilities/v1",)
    with pytest.raises(ValidationError):
        _requirement("market.spot", minimum_semantics="capabilities/v2")
    policy = project_1_compatibility_policy()
    assert policy.capability_vocabulary_version == "capabilities/v1"
    assert _requirement("market.spot").minimum_semantics == "capabilities/v1"


def test_a_requirement_side_defect_outranks_a_descriptor_side_defect() -> None:
    """Both reason sets are still returned in full, so nothing is lost."""
    result = _succeeded(
        _resolve(
            (_requirement("market.crypto"),),
            descriptor=_descriptor(capability_vocabulary_version="capabilities/v3"),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("", UNKNOWN_NAME), ("", VOCABULARY_VERSION))


def test_two_declarations_for_one_capability_overlap() -> None:
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            approximations=(
                _approximation(),
                _approximation(approximation_id=_OTHER_APPROXIMATION_ID),
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("execution.partial_fills", DECLARATION_OVERLAP),)


def test_a_declaration_outside_the_approximated_set_overlaps() -> None:
    """A declaration contradicting the descriptor's own partition is an overlap.

    ``market.spot`` is declared native, so an approximation record for it claims
    two support kinds at once -- the overlap section 13.2 says invalidates the
    descriptor.
    """
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            approximations=(_approximation(capability="market.spot"),),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("market.spot", DECLARATION_OVERLAP),)


def test_an_unrecognized_declaration_name_is_reported_unscoped() -> None:
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            approximations=(_approximation(capability="market.unlisted"),),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", UNKNOWN_NAME),)


# --------------------------------------------------------------------------
# Steps 2, 3, 6 -- native support
# --------------------------------------------------------------------------


def test_all_native_and_runnable_is_supported() -> None:
    result = _succeeded(
        _resolve(
            (
                _requirement("market.spot"),
                _requirement("data.ohlcv"),
                _requirement("runtime.backtest"),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED
    assert result.reasons == ()
    assert result.approximations == ()
    assert result.adapter_name == "adapter.alpha"
    assert result.adapter_version == "1.0.0"
    assert result.availability_observation_id == _OBSERVATION_ID
    assert result.requested_comparison_level is ComparisonLevel.LEVEL_1


def test_an_empty_requirement_set_is_supported() -> None:
    """Nothing is required, so nothing is unmet. An explicit boundary, not a hole."""
    result = _succeeded(_resolve(()))
    assert result.outcome is CompatibilityOutcome.SUPPORTED


def test_an_unsupported_required_capability_is_not_applicable() -> None:
    result = _succeeded(
        _resolve((_requirement("market.spot"), _requirement("execution.event_driven")))
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.event_driven", REQUIREMENT_UNMET),)


def test_an_absent_capability_is_not_read_as_native_support() -> None:
    """Section 13.2: "Absence is not interpreted as native support"."""
    result = _succeeded(_resolve((_requirement("portfolio.multi_venue"),)))
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("portfolio.multi_venue", REQUIREMENT_UNMET),)


def test_an_optional_requirement_never_gates_the_outcome() -> None:
    """``required=False`` means the strategy runs without it.

    Section 13.3 steps 2 and 3 speak of every *required* capability, so an
    unsatisfiable optional requirement is not an incompatibility.
    """
    result = _succeeded(
        _resolve(
            (
                _requirement("market.spot"),
                _requirement("execution.event_driven", required=False),
                _requirement("portfolio.multi_venue", required=False),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED
    assert result.reasons == ()


def test_the_complete_unmet_set_is_returned_not_the_first() -> None:
    """Section 13.3 step 3, and "never stops at the first missing capability"."""
    result = _succeeded(
        _resolve(
            (
                _requirement("execution.event_driven"),
                _requirement("portfolio.multi_venue"),
                _requirement("research.monte_carlo"),
                _requirement("data.quotes"),
                _requirement("market.spot"),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (
        ("data.quotes", REQUIREMENT_UNMET),
        ("execution.event_driven", REQUIREMENT_UNMET),
        ("portfolio.multi_venue", REQUIREMENT_UNMET),
        ("research.monte_carlo", REQUIREMENT_UNMET),
    )


def test_one_unmet_requirement_does_not_mask_a_different_defect_class() -> None:
    result = _succeeded(
        _resolve(
            (
                _requirement("execution.event_driven"),
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.REJECT,
                ),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (
        ("execution.event_driven", REQUIREMENT_UNMET),
        ("execution.partial_fills", APPROXIMATION_DISALLOWED),
        ("execution.partial_fills", APPROXIMATION_MISSING),
    )


# --------------------------------------------------------------------------
# Steps 4 and 7 -- approximation
# --------------------------------------------------------------------------


def test_an_allowed_declared_approximation_is_supported_with_approximation() -> None:
    declaration = _approximation()
    result = _succeeded(
        _resolve(
            (
                _requirement("market.spot"),
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            approximations=(declaration,),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    assert result.reasons == ()
    assert result.approximations == (declaration,)


def test_every_applied_approximation_record_is_attached() -> None:
    first = _approximation(capability="execution.maker_orders")
    second = _approximation(
        capability="execution.partial_fills",
        approximation_id=_OTHER_APPROXIMATION_ID,
    )
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
                _requirement(
                    "execution.maker_orders",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            descriptor=_descriptor(
                approximated_capabilities=(
                    "execution.maker_orders",
                    "execution.partial_fills",
                )
            ),
            approximations=(second, first),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    assert result.approximations == (first, second)


def test_a_rejected_approximation_policy_is_not_applicable() -> None:
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.REJECT,
                ),
            ),
            approximations=(_approximation(),),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.partial_fills", APPROXIMATION_DISALLOWED),)


def test_a_missing_declaration_is_not_applicable() -> None:
    """Section 13.2: an approximated capability yields a result "only through a
    named approximation declaration"."""
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.partial_fills", APPROXIMATION_MISSING),)


def test_a_declaration_preventing_the_requested_level_is_not_applicable() -> None:
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            comparison_level=ComparisonLevel.LEVEL_1,
            approximations=(
                _approximation(prevented_comparison_levels=(ComparisonLevel.LEVEL_1,)),
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.partial_fills", LEVEL_PREVENTED),)


def test_a_prevented_level_other_than_the_requested_one_is_honoured() -> None:
    """Exclusion is per level, not global."""
    declaration = _approximation(prevented_comparison_levels=(ComparisonLevel.LEVEL_1,))
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            comparison_level=ComparisonLevel.LEVEL_2,
            approximations=(declaration,),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    assert result.approximations == (declaration,)
    assert result.requested_comparison_level is ComparisonLevel.LEVEL_2


def test_a_disallowed_and_level_preventing_approximation_reports_both() -> None:
    """Independently applicable reasons, both collected."""
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.REJECT,
                ),
            ),
            approximations=(
                _approximation(prevented_comparison_levels=(ComparisonLevel.LEVEL_1,)),
            ),
        )
    )
    assert _codes(result) == (
        ("execution.partial_fills", APPROXIMATION_DISALLOWED),
        ("execution.partial_fills", LEVEL_PREVENTED),
    )


def test_conflicting_requirements_for_one_capability_fail_closed() -> None:
    """One requirement permitting and another rejecting yields rejection."""
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.REJECT,
                ),
            ),
            approximations=(_approximation(),),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.partial_fills", APPROXIMATION_DISALLOWED),)


def test_a_declaration_with_a_different_authoring_version_is_applied() -> None:
    """``ApproximationDeclaration.adapter_version`` is provenance, not eligibility.

    Specification section 11.3's constraint column says only that the "declaration
    version is included in run provenance" -- it records which adapter version
    authored the declaration and imposes no equality against the descriptor being
    resolved. Section 13.3 step 1 is explicitly scoped to "vocabulary, protocol,
    and schema versions", and an adapter version is not among the three. Section
    13.2 closes descriptor invalidity to exactly "unknown capability names or
    overlapping declarations", and a differing authoring version is neither. The
    only same-identity requirement in the specification is section 17.2.1's, which
    governs the availability observation on an ``UNAVAILABLE`` retry and is
    enforced separately by ``_is_runnable``.

    So when every semantic and runtime condition passes, the declaration
    participates normally, and its original version survives into the result rather
    than being rewritten to the descriptor's.
    """
    declaration = _approximation(adapter_version="2.0.0")
    result = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            approximations=(declaration,),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    assert result.reasons == ()
    # Provenance is preserved, not normalized: the declaration keeps 2.0.0 while
    # the result records the descriptor's own 1.0.0 separately.
    assert result.approximations == (declaration,)
    assert result.approximations[0].adapter_version == "2.0.0"
    assert result.adapter_version == "1.0.0"


def test_the_authoring_version_never_changes_the_semantic_outcome() -> None:
    """Changing only the provenance version must not move the decision.

    The paired assertion to the test above: the outcome and the reason set are
    identical across authoring versions, while the serialized bytes differ only
    because the retained provenance differs.
    """
    baseline = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            approximations=(_approximation(adapter_version="1.0.0"),),
        )
    )
    restamped = _succeeded(
        _resolve(
            (
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
                ),
            ),
            approximations=(_approximation(adapter_version="3.1.4"),),
        )
    )
    assert baseline.outcome is restamped.outcome
    assert baseline.reasons == restamped.reasons == ()
    assert restamped.approximations[0].adapter_version == "3.1.4"
    assert canonical_json_bytes(baseline) != canonical_json_bytes(restamped)


def test_only_the_observation_version_governs_runtime_identity() -> None:
    """The contrast that proves the correction did not weaken runtime identity.

    Deliberately written as a *side-by-side* comparison rather than a second
    availability case, because the parametrized unrunnable test above already
    covers an observation-version mismatch on its own. What is asserted here is the
    distinction the correction turns on: the very same version string, ``2.0.0``,
    is inert on a declaration and decisive on an observation.

    Section 11.3 makes the declaration's version provenance; section 17.2.1
    requires an ``UNAVAILABLE`` observation to match "the same
    adapter/executable/version identity", so the observation's version is evidence
    about what is actually installed.
    """
    requirement = _requirement(
        "execution.partial_fills",
        approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
    )
    on_the_declaration = _succeeded(
        _resolve(
            (requirement,),
            approximations=(_approximation(adapter_version="2.0.0"),),
        )
    )
    on_the_observation = _succeeded(
        _resolve(
            (requirement,),
            availability=_observation(adapter_version="2.0.0"),
            approximations=(_approximation(),),
        )
    )
    assert on_the_declaration.outcome is (
        CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    )
    assert on_the_declaration.reasons == ()
    assert on_the_observation.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(on_the_observation) == (("", RUNTIME_UNAVAILABLE),)


def test_an_orphan_declaration_for_an_optional_capability_is_ignored() -> None:
    """Approximation handling is scoped to a *required* capability.

    Specification section 13.3 conditions both relevant steps on the approximation
    being needed -- step 4 "if approximations **are required**", step 7 "if at least
    one allowed approximation **is required**" -- and the plan's Task 6 step 5 says
    "a **required** approximation the strategy permits". Nothing requires an
    approximation for a capability the strategy declares optional.

    The consequence is recorded rather than hidden: a declaration whose
    ``prevented_comparison_levels`` includes the requested level, for an *optional*
    capability, produces no reason and attaches no record -- see
    ``test_an_optional_capabilitys_prevented_level_is_not_reported``. Whether an
    optional capability can be exercised by a run is not defined by any source read
    here, so the behaviour follows the "is required" wording and the question is
    raised for the task that owns comparison eligibility.
    """
    result = _succeeded(
        _resolve(
            (
                _requirement("market.spot"),
                _requirement("execution.partial_fills", required=False),
            ),
            approximations=(_approximation(),),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED
    assert result.approximations == ()


# --------------------------------------------------------------------------
# Step 5 -- runtime availability, and the two distinctions
# --------------------------------------------------------------------------


def test_a_compatible_but_unavailable_runtime_is_unavailable() -> None:
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            availability=_observation(
                available=False,
                reason_code=RUNTIME_UNAVAILABLE,
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", RUNTIME_UNAVAILABLE),)


@pytest.mark.parametrize(
    "override",
    [
        {"adapter_name": "adapter.other"},
        {"adapter_version": "2.0.0"},
        {"executable_hash": "b" * 64},
        {"operating_system": OperatingSystem.LINUX},
        {"network_required": True},
    ],
)
def test_every_unrunnable_condition_yields_exactly_one_runtime_reason(
    override: dict[str, object],
) -> None:
    """Section 13.3 step 5's five unrunnable causes, as one reason.

    The granular cause stays on the observation's own ``reason_code`` rather than
    being split across codes the closed table does not contain. One reason also
    keeps the result deduplication-stable when several conditions hold at once.
    """
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            availability=_observation(**override),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", RUNTIME_UNAVAILABLE),)


def test_a_network_requiring_descriptor_is_unavailable_not_supported() -> None:
    """Section 24.4: Project 1 rejects any operation requiring network access.

    Recording it as ``UNAVAILABLE`` keeps the descriptor analysable, which the
    same section explicitly permits, while making it impossible to read as
    ``SUPPORTED``.
    """
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            descriptor=_descriptor(network_required=True),
        )
    )
    assert result.outcome is CompatibilityOutcome.UNAVAILABLE
    assert _codes(result) == (("", RUNTIME_UNAVAILABLE),)


def test_several_unrunnable_conditions_still_yield_one_reason() -> None:
    result = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            availability=_observation(
                available=False,
                reason_code=RUNTIME_UNAVAILABLE,
                adapter_version="3.0.0",
                operating_system=OperatingSystem.MACOS,
                network_required=True,
            ),
        )
    )
    assert _codes(result) == (("", RUNTIME_UNAVAILABLE),)


def test_runtime_absence_never_becomes_strategy_incompatibility() -> None:
    """The same requirement set, differing only in availability."""
    available = _succeeded(_resolve((_requirement("market.spot"),)))
    absent = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            availability=_observation(
                available=False,
                reason_code=RUNTIME_UNAVAILABLE,
            ),
        )
    )
    assert available.outcome is CompatibilityOutcome.SUPPORTED
    assert absent.outcome is CompatibilityOutcome.UNAVAILABLE
    assert REQUIREMENT_UNMET not in {reason.error_code for reason in absent.reasons}


def test_strategy_incompatibility_never_becomes_runtime_unavailability() -> None:
    """The same descriptor and observation, differing only in requirements."""
    incompatible = _succeeded(_resolve((_requirement("execution.event_driven"),)))
    assert incompatible.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert RUNTIME_UNAVAILABLE not in {
        reason.error_code for reason in incompatible.reasons
    }


def test_semantic_incompatibility_outranks_runtime_absence() -> None:
    """Section 13.3 places step 3 before step 5, so the strategy fact wins.

    Reporting ``UNAVAILABLE`` here would tell a user to install a runtime that
    still could not run their strategy.
    """
    result = _succeeded(
        _resolve(
            (_requirement("execution.event_driven"),),
            availability=_observation(
                available=False,
                reason_code=RUNTIME_UNAVAILABLE,
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("execution.event_driven", REQUIREMENT_UNMET),)


# --------------------------------------------------------------------------
# Reason completeness, deduplication, and ordering
# --------------------------------------------------------------------------


def test_repeated_requirements_deduplicate_to_one_logical_reason() -> None:
    result = _succeeded(
        _resolve(
            (
                _requirement("execution.event_driven"),
                _requirement("execution.event_driven"),
                _requirement("execution.event_driven"),
            )
        )
    )
    assert _codes(result) == (("execution.event_driven", REQUIREMENT_UNMET),)


def test_reasons_are_ordered_by_capability_then_by_code() -> None:
    """Stable capability-name order, with a documented secondary key."""
    result = _succeeded(
        _resolve(
            (
                _requirement("research.monte_carlo"),
                _requirement("data.quotes"),
                _requirement(
                    "execution.partial_fills",
                    approximation_policy=ApproximationPolicy.REJECT,
                ),
            )
        )
    )
    observed = _codes(result)
    assert observed == tuple(sorted(observed))
    assert observed == (
        ("data.quotes", REQUIREMENT_UNMET),
        ("execution.partial_fills", APPROXIMATION_DISALLOWED),
        ("execution.partial_fills", APPROXIMATION_MISSING),
        ("research.monte_carlo", REQUIREMENT_UNMET),
    )


def test_an_unscoped_reason_sorts_before_every_scoped_reason() -> None:
    """Both reason kinds co-occur inside step 1, which is where they can meet.

    Steps 2 to 4 are never reached once step 1 has a finding, so the mixed case is
    a strategy-side unrecognized name together with an adapter-side declaration
    overlap -- and both sides are still returned in full.
    """
    result = _succeeded(
        _resolve(
            (_requirement("market.crypto"),),
            approximations=(
                _approximation(),
                _approximation(approximation_id=_OTHER_APPROXIMATION_ID),
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (
        ("", UNKNOWN_NAME),
        ("execution.partial_fills", DECLARATION_OVERLAP),
    )


def test_permuting_requirements_yields_a_byte_identical_result() -> None:
    forward = (
        _requirement("execution.event_driven"),
        _requirement("portfolio.multi_venue"),
        _requirement("research.monte_carlo"),
        _requirement("data.quotes"),
    )
    first = _succeeded(_resolve(forward))
    second = _succeeded(_resolve(tuple(reversed(forward))))
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_permuting_declarations_yields_a_byte_identical_result() -> None:
    declarations = (
        _approximation(capability="execution.maker_orders"),
        _approximation(
            capability="execution.partial_fills",
            approximation_id=_OTHER_APPROXIMATION_ID,
        ),
    )
    requirements = (
        _requirement(
            "execution.maker_orders",
            approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
        ),
        _requirement(
            "execution.partial_fills",
            approximation_policy=ApproximationPolicy.ALLOW_DECLARED,
        ),
    )
    descriptor = _descriptor(
        approximated_capabilities=(
            "execution.maker_orders",
            "execution.partial_fills",
        )
    )
    first = _succeeded(
        _resolve(requirements, descriptor=descriptor, approximations=declarations)
    )
    second = _succeeded(
        _resolve(
            tuple(reversed(requirements)),
            descriptor=descriptor,
            approximations=tuple(reversed(declarations)),
        )
    )
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_an_optional_capabilitys_prevented_level_is_not_reported() -> None:
    """The recorded consequence of scoping approximation handling to ``required``.

    Pinned deliberately rather than left as incidental behaviour: this is the case
    an independent review raised, and the resolution was to keep the "is required"
    reading and make the outcome visible.
    """
    result = _succeeded(
        _resolve(
            (
                _requirement("market.spot"),
                _requirement("execution.partial_fills", required=False),
            ),
            comparison_level=ComparisonLevel.LEVEL_1,
            approximations=(
                _approximation(prevented_comparison_levels=(ComparisonLevel.LEVEL_1,)),
            ),
        )
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED
    assert result.reasons == ()
    assert result.approximations == ()


def test_two_distinct_unrecognized_names_yield_one_unscoped_reason() -> None:
    """The load-bearing premise of the reason bound, pinned.

    ``MAX_COMPATIBILITY_REASONS`` is provably unreachable only because an
    unrecognized name is reported unscoped, so N distinct bad names collapse to one
    reason. Without this test that premise rests on reading the resolver, and the
    existing deduplication test repeats the *same* name rather than two different
    ones.
    """
    result = _succeeded(
        _resolve(
            (
                _requirement("market.crypto"),
                _requirement("venue.binance"),
                _requirement("orders.live"),
            )
        )
    )
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(result) == (("", UNKNOWN_NAME),)


def test_a_step_one_finding_returns_before_the_later_steps_run() -> None:
    """Completeness is per-returning-step, and that is asserted, not assumed.

    Section 13.3's requirement is that resolution "never stops at the first
    *missing capability*" -- step 3 -- and step 3 is complete. Step 1 does return
    before steps 2 to 4, so the two genuinely unmet vocabulary requirements below
    are *not* reported alongside the unrecognized name. The module docstring states
    this; this test stops it from drifting silently either way.
    """
    result = _succeeded(
        _resolve(
            (
                _requirement("market.crypto"),
                _requirement("execution.event_driven"),
                _requirement("portfolio.multi_venue"),
            )
        )
    )
    assert _codes(result) == (("", UNKNOWN_NAME),)
    assert REQUIREMENT_UNMET not in {reason.error_code for reason in result.reasons}


def test_both_sides_of_an_unrecognized_name_deduplicate_to_one_reason() -> None:
    """The other half of the same recorded limitation.

    ``UNKNOWN_NAME`` is unscoped on both sides, so a strategy-side and an
    adapter-side occurrence share one material identity. The outcome still
    distinguishes them: strategy-side present yields ``NOT_APPLICABLE``, whereas the
    adapter-side alone yields ``UNAVAILABLE``.
    """
    both = _succeeded(
        _resolve(
            (_requirement("market.crypto"),),
            descriptor=_descriptor(
                native_capabilities=("market.spot", "market.unlisted")
            ),
        )
    )
    assert both.outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert _codes(both) == (("", UNKNOWN_NAME),)

    adapter_only = _succeeded(
        _resolve(
            (_requirement("market.spot"),),
            descriptor=_descriptor(
                native_capabilities=("market.spot", "market.unlisted")
            ),
        )
    )
    assert adapter_only.outcome is CompatibilityOutcome.UNAVAILABLE


def test_an_expired_observation_is_still_resolved_on_its_stated_availability() -> None:
    """Freshness is deliberately not evaluated, and that is pinned.

    The resolver has no clock and plan section 5.1 forbids acquiring one, so
    ``expires_at_utc`` cannot be compared to "now". The model already guarantees
    expiry follows observation; freshness against a current instant belongs to the
    stage that owns a ``Clock``. Asserted so a future reader can tell deliberate
    deferral from oversight.
    """
    long_past = _observation(
        observed_at_utc=datetime(2020, 1, 1, tzinfo=UTC),
        expires_at_utc=datetime(2020, 1, 1, 1, tzinfo=UTC),
    )
    result = _succeeded(
        _resolve((_requirement("market.spot"),), availability=long_past)
    )
    assert result.outcome is CompatibilityOutcome.SUPPORTED


def test_the_resolver_source_never_reads_the_engine_descriptor() -> None:
    """A source-level guard, because no behavioural test can cover every engine.

    ``test_no_engine_or_adapter_name_can_grant_support`` kills the obvious
    mutation, but a mutation keyed on some *other* hard-coded engine name would
    survive it. Specification section 11.3 requires that capabilities "are not
    inferred from the engine name", so the resolver must not read the engine
    descriptor at all.
    """
    source = Path(inspect.getfile(CompatibilityResolver)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    engine_reads = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in {"engine", "engine_name"}
    ]
    assert engine_reads == []
    for forbidden in ("vectorbt", "backtrader", "nautilus", "engine_family"):
        assert forbidden not in source, forbidden


def test_the_result_is_deeply_immutable_and_round_trips() -> None:
    result = _succeeded(
        _resolve(
            (_requirement("execution.event_driven"),),
        )
    )
    restored = CompatibilityResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert isinstance(restored.reasons, tuple)
    dumped = result.model_dump(mode="python")
    dumped["outcome"] = "SUPPORTED"
    assert result.outcome is CompatibilityOutcome.NOT_APPLICABLE
