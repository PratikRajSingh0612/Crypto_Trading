"""Core safety policy, which runs *before* compatibility resolution.

Specification section 13.3: "Core safety-policy validation runs before
compatibility resolution. A prohibited request, including live runtime,
credentials, shorting, margin, futures, or leverage, produces a
user/configuration diagnostic; no ``CompatibilityResult`` or engine-run attempt
is created."

Specification section 3, "Approved context", names the same scope, and section
24.4 adds that a descriptor may declare credentials "for future compatibility
analysis" while policy "rejects any operation that would require them".
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import get_args

import pytest
from pydantic import ValidationError

from crypto_lab.capabilities.policy import (
    POLICY_CODES,
    POLICY_FORBIDDEN_REQUEST,
    POLICY_LIVE_RUNTIME,
    PROHIBITED_CAPABILITIES,
    SOURCE_COMPONENT,
    CompatibilityPolicy,
    project_1_compatibility_policy,
    validate_safety_policy,
)
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
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory

_OBSERVED = datetime(2026, 8, 24, 12, tzinfo=UTC)
_EXPIRES = datetime(2026, 8, 24, 13, tzinfo=UTC)


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
        "native_capabilities": (
            "direction.short",
            "market.futures",
            "market.margin",
            "market.spot",
            "runtime.live",
        ),
        "approximated_capabilities": (),
        "unsupported_capabilities": (),
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
        "availability_observation_id": "avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e",
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


def _validate(
    requirements: tuple[CapabilityRequirement, ...],
    **updates: object,
) -> tuple[Diagnostic, ...]:
    descriptor = updates.pop("descriptor", _descriptor())
    availability = updates.pop("availability", _observation())
    policy = updates.pop("policy", project_1_compatibility_policy())
    assert updates == {}
    assert isinstance(descriptor, AdapterDescriptor)
    assert isinstance(availability, RuntimeAvailabilityObservation)
    assert isinstance(policy, CompatibilityPolicy)
    return validate_safety_policy(requirements, descriptor, availability, policy)


def test_the_prohibited_set_is_exactly_the_four_representable_prohibitions() -> None:
    """Live runtime, shorting, margin, and futures are vocabulary members.

    Leverage, credentials-as-a-capability, and withdrawal behaviour are **not**
    representable as capability names. No request field is invented to test them:
    a field no production path can set would put an unexercised value into a
    canonical record, and the plan's Task 6 file map authorizes none. Credentials
    are covered instead through the descriptor and observation flags below.
    """
    assert PROHIBITED_CAPABILITIES == (
        "direction.short",
        "market.futures",
        "market.margin",
        "runtime.live",
    )
    for capability in PROHIBITED_CAPABILITIES:
        assert CapabilityVocabulary.contains(capability) is True


def test_the_policy_codes_are_exactly_the_two_closed_table_rows() -> None:
    assert POLICY_CODES == {POLICY_LIVE_RUNTIME, POLICY_FORBIDDEN_REQUEST}
    assert POLICY_LIVE_RUNTIME == "CAPABILITY.POLICY_LIVE_RUNTIME"
    assert POLICY_FORBIDDEN_REQUEST == "CAPABILITY.POLICY_FORBIDDEN_REQUEST"


def test_the_project_1_policy_is_fixed_and_cannot_be_weakened() -> None:
    """The policy is an explicit input, but not a caller-tunable one.

    Section 13.3 makes the capability-policy version an input to resolution, so it
    must be passed explicitly rather than read from a module constant. It must not
    be *weakenable*: a caller supplying an empty prohibited set, or permitting
    credentials, would defeat the prohibition entirely, which is why every
    permission is a ``Literal[False]`` and the prohibited set is pinned.
    """
    policy = project_1_compatibility_policy()
    assert policy.policy_version == "capability-policy/v1"
    assert policy.capability_vocabulary_version == "capabilities/v1"
    assert policy.permit_credential_requirements is False
    assert policy.prohibited_capabilities == PROHIBITED_CAPABILITIES

    baseline = policy.model_dump(mode="python")
    for weakened in (
        {"prohibited_capabilities": ()},
        {"prohibited_capabilities": ("market.margin", "market.spot")},
        # Exactly four names, so the length bound passes and the pinned-set
        # validator is what rejects it. Without this case the validator's own
        # rejection is never exercised.
        {
            "prohibited_capabilities": (
                "market.equities",
                "market.futures",
                "market.margin",
                "runtime.live",
            )
        },
        # The right names in the wrong order, which the pin also rejects.
        {
            "prohibited_capabilities": (
                "runtime.live",
                "market.margin",
                "market.futures",
                "direction.short",
            )
        },
        {"permit_credential_requirements": True},
        {"policy_version": "capability-policy/v2"},
        {"capability_vocabulary_version": "capabilities/v2"},
    ):
        with pytest.raises(ValidationError):
            CompatibilityPolicy.model_validate({**baseline, **weakened})


def test_the_credential_prohibition_is_pinned_at_the_type_level() -> None:
    """The credential check is unconditional, so the field is pinned by type.

    ``validate_safety_policy`` deliberately does not guard on
    ``permit_credential_requirements``: it is ``Literal[False]``, so the guard's
    false arm would be unreachable code asserting a type-level fact -- exactly what
    the resolver declines to do for ``minimum_semantics``. This test is what keeps
    the field load-bearing: if the literal is ever widened to permit credentials,
    it fails here and the runtime guard must be reinstated.
    """
    annotation = CompatibilityPolicy.model_fields[
        "permit_credential_requirements"
    ].annotation
    assert get_args(annotation) == (False,)


def test_a_policy_valid_request_produces_no_diagnostic() -> None:
    assert _validate((_requirement("market.spot"),)) == ()


def test_a_live_runtime_request_is_rejected_with_its_dedicated_code() -> None:
    diagnostics = _validate((_requirement("runtime.live"),))
    assert len(diagnostics) == 1
    only = diagnostics[0]
    assert only.error_code == POLICY_LIVE_RUNTIME
    assert only.category is DiagnosticCategory.USER_CONFIGURATION
    assert only.source_component == SOURCE_COMPONENT
    assert only.retriable is False
    assert only.timestamp_utc == _OBSERVED
    assert only.details == {"capability": "runtime.live"}


@pytest.mark.parametrize(
    "capability",
    ["direction.short", "market.margin", "market.futures"],
)
def test_every_other_prohibited_capability_is_rejected(capability: str) -> None:
    diagnostics = _validate((_requirement(capability),))
    assert len(diagnostics) == 1
    assert diagnostics[0].error_code == POLICY_FORBIDDEN_REQUEST
    assert diagnostics[0].category is DiagnosticCategory.USER_CONFIGURATION
    assert diagnostics[0].details == {"capability": capability}


def test_an_optional_prohibited_requirement_is_still_rejected() -> None:
    """Fail-closed on ``required=False``.

    Specification section 13.3 prohibits the *request*, not merely the hard
    dependency. Declaring ``market.margin`` optionally still asks the resolver to
    consider margin semantics, and reading the prohibition as conditional on
    ``required`` would leave the scope boundary of section 3 satisfiable by a
    single flag.
    """
    diagnostics = _validate((_requirement("market.margin", required=False),))
    assert len(diagnostics) == 1
    assert diagnostics[0].error_code == POLICY_FORBIDDEN_REQUEST


def test_a_descriptor_declaring_support_never_permits_a_prohibited_request() -> None:
    """The fixture descriptor declares all four prohibited names native."""
    descriptor = _descriptor()
    assert "runtime.live" in descriptor.native_capabilities
    diagnostics = _validate((_requirement("runtime.live"),), descriptor=descriptor)
    assert diagnostics[0].error_code == POLICY_LIVE_RUNTIME


def test_a_credential_requirement_is_rejected_from_either_side() -> None:
    from_descriptor = _validate(
        (_requirement("market.spot"),),
        descriptor=_descriptor(credentials_required=True),
    )
    assert len(from_descriptor) == 1
    assert from_descriptor[0].error_code == POLICY_FORBIDDEN_REQUEST
    assert from_descriptor[0].details == {
        "declared_by": "ADAPTER_DESCRIPTOR",
        "prohibited_requirement": "CREDENTIALS",
    }

    from_observation = _validate(
        (_requirement("market.spot"),),
        availability=_observation(credentials_required=True),
    )
    assert len(from_observation) == 1
    assert from_observation[0].details == {
        "declared_by": "RUNTIME_AVAILABILITY_OBSERVATION",
        "prohibited_requirement": "CREDENTIALS",
    }
    assert from_descriptor[0].diagnostic_id != from_observation[0].diagnostic_id


def test_a_network_requirement_is_not_a_policy_rejection() -> None:
    """Network is deliberately resolved as ``UNAVAILABLE``, not rejected here.

    Specification section 13.3 and the plan's Task 6 section both enumerate the
    prohibited-request list and both omit network, while section 24.4 says such a
    descriptor "may be represented for future compatibility analysis" -- which a
    policy rejection, producing no ``CompatibilityResult`` at all, would make
    impossible. The resolver treats it as not runnable instead; see
    ``test_capability_resolver``.

    Section 24.4 applies that sentence to credentials as well, so the asymmetry
    with the credential path below is deliberate: section 13.3 names credentials in
    its prohibited-request list and omits network, and the credential path is the
    stricter of two defensible readings.
    """
    from_descriptor = _validate(
        (_requirement("market.spot"),),
        descriptor=_descriptor(network_required=True),
    )
    from_observation = _validate(
        (_requirement("market.spot"),),
        availability=_observation(network_required=True),
    )
    assert from_descriptor == ()
    assert from_observation == ()


def test_every_independent_prohibition_is_reported_together() -> None:
    """No prohibition masks another, and none is dropped."""
    diagnostics = _validate(
        (
            _requirement("runtime.live"),
            _requirement("direction.short"),
            _requirement("market.margin"),
            _requirement("market.futures"),
            _requirement("market.spot"),
        ),
        descriptor=_descriptor(credentials_required=True),
        availability=_observation(credentials_required=True),
    )
    assert len(diagnostics) == 6
    codes = tuple(item.error_code for item in diagnostics)
    assert codes.count(POLICY_LIVE_RUNTIME) == 1
    assert codes.count(POLICY_FORBIDDEN_REQUEST) == 5


def test_repeated_prohibitions_deduplicate_to_one_logical_diagnostic() -> None:
    diagnostics = _validate(
        (
            _requirement("market.margin"),
            _requirement("market.margin"),
            _requirement("market.margin"),
        )
    )
    assert len(diagnostics) == 1


def test_the_diagnostic_sequence_is_stable_under_requirement_permutation() -> None:
    """Order in, byte-identical order out."""
    forward = (
        _requirement("runtime.live"),
        _requirement("direction.short"),
        _requirement("market.margin"),
        _requirement("market.futures"),
    )
    reversed_order = tuple(reversed(forward))
    assert canonical_json_bytes(_validate(forward)) == canonical_json_bytes(
        _validate(reversed_order)
    )


def test_identity_is_derived_from_content_so_two_runs_agree() -> None:
    """Plan section 5.3.3: identity is derived, never drawn."""
    first = _validate((_requirement("runtime.live"),))
    second = _validate((_requirement("runtime.live"),))
    assert first[0].diagnostic_id == second[0].diagnostic_id
    assert first[0].diagnostic_id.startswith("diag_")


def test_no_diagnostic_carries_a_correlation_id_or_a_cause() -> None:
    """Plan section 5.4.1 item 0's two entry conditions, which keep the key total."""
    for diagnostic in _validate(
        (_requirement("runtime.live"), _requirement("market.margin"))
    ):
        dumped = diagnostic.model_dump(mode="json")
        for absent in ("experiment_id", "run_id", "invocation_id", "engine"):
            assert absent not in dumped
        assert diagnostic.causal_diagnostic_ids == ()
