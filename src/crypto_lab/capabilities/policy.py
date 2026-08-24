"""Core safety policy, applied before any compatibility resolution.

Specification section 13.3 fixes the ordering: "Core safety-policy validation runs
before compatibility resolution. A prohibited request, including live runtime,
credentials, shorting, margin, futures, or leverage, produces a
user/configuration diagnostic; no ``CompatibilityResult`` or engine-run attempt is
created." Specification section 3, "Approved context", states the same approved
application scope, and ``AGENTS.md`` repeats it as a repository safety boundary.

Two prohibitions in that list are **not representable** through the Task 6
contracts and are recorded here rather than invented into a field. Leverage has no
capability name and no resolver parameter, and withdrawal behaviour is an
adapter-protocol operation no Stage 4 record describes. Adding a field solely to
test them would put an unexercised value into a canonical record; the plan's
Task 6 file map authorizes no such field.

Network requirement is deliberately **not** a policy rejection. Section 13.3 and
the plan's Task 6 section both enumerate the prohibited-request list and both omit
it, while section 24.4 states that a network-requiring descriptor "may be
represented for future compatibility analysis" -- which a policy rejection,
producing no ``CompatibilityResult`` at all, would make impossible. The resolver
treats it as not runnable, which is section 13.4's ``UNAVAILABLE`` hook.

**The credentials/network asymmetry is a known, sourced choice, not an oversight.**
Section 24.4 applies its "may be represented" sentence to network *and*
credentials together, so the argument above reads across to credentials. Section
13.3 nevertheless names credentials in its prohibited-request list and omits
network, and section 13.3 is the ordering rule this module implements. The
credential path therefore fails closed -- a credential-declaring descriptor cannot
be resolved at all -- which is the stricter reading of two defensible ones.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, cast

from pydantic import Field, JsonValue, field_validator

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_names import CapabilityName
from crypto_lab.domain.capability_requirements import CapabilityRequirement
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash

SOURCE_COMPONENT = "capabilities.policy"

POLICY_LIVE_RUNTIME = "CAPABILITY.POLICY_LIVE_RUNTIME"
POLICY_FORBIDDEN_REQUEST = "CAPABILITY.POLICY_FORBIDDEN_REQUEST"
#: Exactly the two safety-policy rows of plan section 5.9's closed error-code
#: table. The other eight ``CAPABILITY.`` rows are outcome reasons and live in
#: ``crypto_lab.capabilities.models``.
POLICY_CODES: frozenset[str] = frozenset(
    {
        POLICY_LIVE_RUNTIME,
        POLICY_FORBIDDEN_REQUEST,
    }
)

LIVE_RUNTIME_CAPABILITY = "runtime.live"
#: The four prohibitions of specification section 3 that the closed
#: ``capabilities/v1`` vocabulary can express, in canonical order.
PROHIBITED_CAPABILITIES: tuple[CapabilityName, ...] = (
    "direction.short",
    "market.futures",
    "market.margin",
    "runtime.live",
)

# Each message is a fixed bounded literal interpolating no input, and each is
# paired with its code at the site that decides the code. They are module-level
# strings rather than entries in a lookup mapping on purpose: a diagnostic's
# `message` is part of the section 5.3.3 identity payload, so it is material to
# the derived `diagnostic_id`, and an immutable string cannot be reached and
# rewritten the way a module-level mutable mapping can. `MappingProxyType` is not
# an option here -- plan section 5.5.1 confines the `types` root to
# `strategy/models.py` -- and a lookup with a default arm would fail open on an
# unknown code, so pairing at the decision site is the fail-closed shape.
_LIVE_RUNTIME_MESSAGE = (
    "Live runtime is prohibited in the approved Project 1 scope and is "
    "rejected before compatibility resolution."
)
_FORBIDDEN_REQUEST_MESSAGE = (
    "The request names behaviour prohibited in the approved Project 1 scope "
    "and is rejected before compatibility resolution."
)


class CompatibilityPolicy(CanonicalModel):
    """The versioned capability policy resolution is evaluated under.

    Specification section 13.3 makes "the capability-policy version" an input to
    resolution, so the policy is passed explicitly rather than read from a module
    constant. It must not be *weakenable*, which is why every permission is a
    ``Literal[False]`` and the prohibited set is pinned to
    ``PROHIBITED_CAPABILITIES``: a caller supplying an empty prohibited set would
    otherwise defeat the prohibition the record exists to carry.
    """

    schema_version: Literal["1.0.0"]
    policy_version: Literal["capability-policy/v1"]
    capability_vocabulary_version: Literal["capabilities/v1"]
    prohibited_capabilities: tuple[CapabilityName, ...] = Field(
        min_length=len(PROHIBITED_CAPABILITIES),
        max_length=len(PROHIBITED_CAPABILITIES),
    )
    permit_credential_requirements: Literal[False]

    @field_validator("prohibited_capabilities")
    @classmethod
    def validate_prohibited_capabilities(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != PROHIBITED_CAPABILITIES:
            raise ValueError(
                "the capability policy must carry the exact prohibited set"
            )
        return value


def project_1_compatibility_policy() -> CompatibilityPolicy:
    """Return the single policy the approved Project 1 scope permits.

    A factory rather than a module-level instance, so importing this module
    constructs no validator-backed record and the fresh-import probe of plan
    section 11.1 stays meaningful.
    """
    return CompatibilityPolicy(
        schema_version="1.0.0",
        policy_version="capability-policy/v1",
        capability_vocabulary_version="capabilities/v1",
        prohibited_capabilities=PROHIBITED_CAPABILITIES,
        permit_credential_requirements=False,
    )


def _diagnostic(
    code: str,
    message: str,
    details: dict[str, DiagnosticDetailValue],
    observed_at_utc: datetime,
) -> Diagnostic:
    """Build one diagnostic whose identity is a function of its content alone.

    Plan section 5.3.3: identity is derived, never drawn, because every random and
    wall-clock source is forbidden. Every correlation field is absent and
    ``causal_diagnostic_ids`` is empty, which are plan section 5.4.1 item 0's two
    entry conditions and what makes the ordering key below a total order.
    """
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": DiagnosticCategory.USER_CONFIGURATION.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast("JsonValue", details),
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=f"diag_{identity}",
        severity=DiagnosticSeverity.ERROR,
        error_code=code,
        category=DiagnosticCategory.USER_CONFIGURATION,
        message=message,
        source_component=SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=details,
        causal_diagnostic_ids=(),
    )


def _order_key(diagnostic: Diagnostic) -> tuple[str, bytes]:
    """The documented total ordering key for safety-policy diagnostics.

    Total because, under plan section 5.4.1 item 0, the section 5.3.3 identity
    payload reduces to a function of ``(error_code, source_component, details)``
    and this module emits exactly one ``source_component``: two entries equal on
    this key have equal identities and one was already removed by deduplication,
    so no tie can be resolved by generation order.
    """
    return (diagnostic.error_code, canonical_json_bytes(diagnostic.details))


def validate_safety_policy(
    requirements: tuple[CapabilityRequirement, ...],
    descriptor: AdapterDescriptor,
    availability: RuntimeAvailabilityObservation,
    policy: CompatibilityPolicy,
) -> tuple[Diagnostic, ...]:
    """Return every safety-policy diagnostic for one request, or an empty tuple.

    A non-empty result means no ``CompatibilityResult`` may be produced at all.
    Every independently applicable prohibition is reported: a prohibited
    capability never masks another, and a prohibited capability never masks a
    credential requirement.

    The prohibition is evaluated against the requirement's ``capability``
    regardless of its ``required`` flag. Section 13.3 prohibits the *request*, not
    only the hard dependency, and reading it as conditional on ``required`` would
    make the section 3 scope boundary satisfiable by one flag.

    A declared capability never grants an exemption: the descriptor's own
    ``native_capabilities`` is not consulted here, which is why a descriptor
    claiming ``runtime.live`` natively still yields a rejection.

    The credential check is unconditional rather than guarded on
    ``policy.permit_credential_requirements``. That field is ``Literal[False]``, so
    a guard's false arm would be unreachable code asserting a type-level fact --
    the same reasoning ``resolver.py`` applies when it declines to compare
    ``minimum_semantics`` at runtime. The field is still read, by
    ``test_the_credential_prohibition_is_pinned_at_the_type_level``, which fails if
    the literal is ever widened.

    ``observed_at_utc`` is taken from ``availability.observed_at_utc``, which
    specification section 11.3 already requires, so this entry point needs no
    ambient clock and no parameter beyond the resolver's own inputs.
    """
    observed_at_utc = availability.observed_at_utc
    prohibited = frozenset(policy.prohibited_capabilities)
    findings: list[Diagnostic] = []

    for requirement in requirements:
        if requirement.capability not in prohibited:
            continue
        code, message = (
            (POLICY_LIVE_RUNTIME, _LIVE_RUNTIME_MESSAGE)
            if requirement.capability == LIVE_RUNTIME_CAPABILITY
            else (POLICY_FORBIDDEN_REQUEST, _FORBIDDEN_REQUEST_MESSAGE)
        )
        findings.append(
            _diagnostic(
                code,
                message,
                {"capability": requirement.capability},
                observed_at_utc,
            )
        )

    for declared, source in (
        (descriptor.credentials_required, "ADAPTER_DESCRIPTOR"),
        (availability.credentials_required, "RUNTIME_AVAILABILITY_OBSERVATION"),
    ):
        if not declared:
            continue
        findings.append(
            _diagnostic(
                POLICY_FORBIDDEN_REQUEST,
                _FORBIDDEN_REQUEST_MESSAGE,
                {
                    "declared_by": source,
                    "prohibited_requirement": "CREDENTIALS",
                },
                observed_at_utc,
            )
        )

    unique: dict[tuple[str, bytes], Diagnostic] = {}
    for finding in findings:
        unique.setdefault(_order_key(finding), finding)
    return tuple(unique[key] for key in sorted(unique))
