"""Capability declarations, approximation records, and the compatibility result.

Field sets come from specification section 11.3 where a row exists, per the plan's
section 9 field-list paragraph (plan line 2941). ``CompatibilityResult`` has **no**
11.3 row -- see ``test_the_result_declares_the_plan_derived_field_list`` -- so its
field set is derived from binding sentences and that derivation is stated rather
than implied.

This module also carries the recursive material-graph audit plan section 5.5.1
requires of every canonical record Task 6 introduces, including the domain-owned
``RuntimeAvailabilityObservation``, so there is one authoritative audit rather
than a copy per test module.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.capabilities import models as capability_models
from crypto_lab.capabilities.models import (
    APPROXIMATION_DISALLOWED,
    APPROXIMATION_MISSING,
    COMPATIBILITY_REASON_CODES,
    DECLARATION_OVERLAP,
    LEVEL_PREVENTED,
    MAX_CAPABILITY_LIMITATIONS,
    MAX_COMPATIBILITY_APPROXIMATIONS,
    MAX_COMPATIBILITY_REASONS,
    MAX_PREVENTED_COMPARISON_LEVELS,
    REQUIREMENT_UNMET,
    RUNTIME_UNAVAILABLE,
    UNKNOWN_NAME,
    VOCABULARY_VERSION,
    ApproximationDeclaration,
    CapabilityDeclaration,
    CapabilitySupportKind,
    CompatibilityOutcome,
    CompatibilityReason,
    CompatibilityResult,
    reason_sort_key,
)
from crypto_lab.capabilities.policy import (
    POLICY_CODES,
    project_1_compatibility_policy,
)
from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain import capability_requirements
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import (
    OperatingSystem,
    RuntimeAvailabilityObservation,
)

# Plan section 5.9's closed error-code table, `CAPABILITY.` rows only.
_CLOSED_CAPABILITY_CODES = frozenset(
    {
        "CAPABILITY.UNKNOWN_NAME",
        "CAPABILITY.VOCABULARY_VERSION",
        "CAPABILITY.DECLARATION_OVERLAP",
        "CAPABILITY.REQUIREMENT_UNMET",
        "CAPABILITY.APPROXIMATION_DISALLOWED",
        "CAPABILITY.APPROXIMATION_MISSING",
        "CAPABILITY.LEVEL_PREVENTED",
        "CAPABILITY.RUNTIME_UNAVAILABLE",
        "CAPABILITY.POLICY_LIVE_RUNTIME",
        "CAPABILITY.POLICY_FORBIDDEN_REQUEST",
    }
)
_EXPECTED_DECLARATION_FIELDS = (
    "schema_version",
    "capability",
    "support_kind",
    "evidence_note",
    "limitations",
)
_EXPECTED_APPROXIMATION_FIELDS = (
    "schema_version",
    "approximation_id",
    "capability",
    "method",
    "expected_impact",
    "prevented_comparison_levels",
    "adapter_version",
)
_EXPECTED_RESULT_FIELDS = (
    "schema_version",
    "outcome",
    "capability_vocabulary_version",
    "requested_comparison_level",
    "adapter_name",
    "adapter_version",
    "availability_observation_id",
    "reasons",
    "approximations",
)
_OBSERVATION_ID = "avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e"
_APPROXIMATION_ID = "appx_5b1c3d7e-2f4a-4c6b-8d9e-1a2b3c4d5e6f"


def _declaration(**updates: object) -> CapabilityDeclaration:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "capability": "execution.bar_market",
        "support_kind": CapabilitySupportKind.NATIVE,
        "evidence_note": "Engine models bar market orders natively.",
        "limitations": (),
    }
    payload.update(updates)
    return CapabilityDeclaration.model_validate(payload)


def _approximation(**updates: object) -> ApproximationDeclaration:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "approximation_id": _APPROXIMATION_ID,
        "capability": "execution.partial_fills",
        "method": "Fills are modelled as all-or-nothing at the bar close.",
        "expected_impact": "Overstates fill certainty for large orders.",
        "prevented_comparison_levels": (ComparisonLevel.LEVEL_1,),
        "adapter_version": "1.0.0",
    }
    payload.update(updates)
    return ApproximationDeclaration.model_validate(payload)


def _reason(code: str, capability: str | None = None) -> CompatibilityReason:
    payload: dict[str, object] = {"error_code": code}
    if capability is not None:
        payload["capability"] = capability
    return CompatibilityReason.model_validate(payload)


def _result(**updates: object) -> CompatibilityResult:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "outcome": CompatibilityOutcome.SUPPORTED,
        "capability_vocabulary_version": "capabilities/v1",
        "requested_comparison_level": ComparisonLevel.LEVEL_1,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "availability_observation_id": _OBSERVATION_ID,
        "reasons": (),
        "approximations": (),
    }
    payload.update(updates)
    return CompatibilityResult.model_validate(payload)


def _observation() -> RuntimeAvailabilityObservation:
    return RuntimeAvailabilityObservation(
        schema_version="1.0.0",
        availability_observation_id=_OBSERVATION_ID,
        adapter_name="adapter.alpha",
        adapter_version="1.0.0",
        executable_path="C:/adapters/alpha/adapter.exe",
        executable_hash="a" * 64,
        runtime_version="3.12.13",
        operating_system=OperatingSystem.WINDOWS,
        available=True,
        observed_at_utc=datetime(2026, 8, 24, 12, tzinfo=UTC),
        expires_at_utc=datetime(2026, 8, 24, 13, tzinfo=UTC),
        network_required=False,
        credentials_required=False,
    )


# --------------------------------------------------------------------------
# Re-export surface
# --------------------------------------------------------------------------


def test_the_domain_owned_requirement_types_are_re_exported_by_identity() -> None:
    """Plan section 5.7 item 6 relocated these to ``domain``; Task 2 owns them.

    ``capabilities/models.py`` re-exports them so the package's public surface is
    intact, and the ``__all__`` entry is mandatory because strict mypy implies
    ``--no-implicit-reexport``.
    """
    assert (
        capability_models.CapabilityRequirement
        is capability_requirements.CapabilityRequirement
    )
    assert (
        capability_models.ApproximationPolicy
        is capability_requirements.ApproximationPolicy
    )
    assert "CapabilityRequirement" in capability_models.__all__
    assert "ApproximationPolicy" in capability_models.__all__


def test_the_approximation_policy_has_no_permissive_member() -> None:
    """No ``ALLOW_ANY``: an unnamed approximation could change execution meaning."""
    policy = capability_models.ApproximationPolicy
    assert {member.value for member in policy} == {"REJECT", "ALLOW_DECLARED"}


# --------------------------------------------------------------------------
# Declaration records
# --------------------------------------------------------------------------


def test_the_capability_declaration_declares_the_specification_field_list() -> None:
    assert tuple(CapabilityDeclaration.model_fields) == _EXPECTED_DECLARATION_FIELDS


def test_the_support_kind_vocabulary_is_exactly_the_three_declaration_sets() -> None:
    """Specification section 13.2 partitions every claim into exactly three."""
    assert {member.value for member in CapabilitySupportKind} == {
        "NATIVE",
        "APPROXIMATED",
        "UNSUPPORTED",
    }


def test_the_declaration_rejects_unsorted_duplicate_and_unknown_input() -> None:
    with pytest.raises(ValidationError):
        _declaration(limitations=("b.", "a."))
    with pytest.raises(ValidationError):
        _declaration(limitations=("a.", "a."))
    with pytest.raises(ValidationError):
        _declaration(evidence_note="")
    with pytest.raises(ValidationError):
        _declaration(support_kind="PARTIAL")
    with pytest.raises(ValidationError):
        _declaration(unexpected="value")


def test_the_approximation_declaration_declares_the_plan_field_list() -> None:
    """The plan's Task 7 section enumerates exactly these seven.

    Specification section 13.4 additionally mentions an "evidence note", which
    neither the 11.3 row nor the plan's enumeration lists; ``evidence_note`` is a
    field of ``CapabilityDeclaration``, which section 11.3 says an approximated
    declaration references. The plan's exact seven are used, and the divergence is
    recorded rather than resolved by adding an unenumerated field.
    """
    assert tuple(ApproximationDeclaration.model_fields) == (
        _EXPECTED_APPROXIMATION_FIELDS
    )


def test_prevented_levels_are_an_ordered_unique_set() -> None:
    accepted = _approximation(
        prevented_comparison_levels=(ComparisonLevel.LEVEL_1, ComparisonLevel.LEVEL_2)
    )
    assert accepted.prevented_comparison_levels == (
        ComparisonLevel.LEVEL_1,
        ComparisonLevel.LEVEL_2,
    )
    with pytest.raises(ValidationError):
        _approximation(
            prevented_comparison_levels=(
                ComparisonLevel.LEVEL_2,
                ComparisonLevel.LEVEL_1,
            )
        )
    with pytest.raises(ValidationError):
        _approximation(
            prevented_comparison_levels=(
                ComparisonLevel.LEVEL_1,
                ComparisonLevel.LEVEL_1,
            )
        )
    unrestricted = _approximation(prevented_comparison_levels=())
    assert unrestricted.prevented_comparison_levels == ()


def test_the_approximation_declaration_requires_bounded_non_empty_text() -> None:
    with pytest.raises(ValidationError):
        _approximation(method="")
    with pytest.raises(ValidationError):
        _approximation(expected_impact="")
    with pytest.raises(ValidationError):
        _approximation(approximation_id="appx_not-a-uuid")
    with pytest.raises(ValidationError):
        _approximation(approximation_id=_OBSERVATION_ID)


# --------------------------------------------------------------------------
# Outcomes, reasons, and the closed code table
# --------------------------------------------------------------------------


def test_the_outcome_vocabulary_is_exactly_the_four_approved_values() -> None:
    assert {member.value for member in CompatibilityOutcome} == {
        "SUPPORTED",
        "SUPPORTED_WITH_APPROXIMATION",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
    }


def test_the_reason_and_policy_codes_partition_the_closed_table() -> None:
    """Executable proof that Task 6 invents no error code.

    Plan section 5.9's table is closed and holds exactly ten ``CAPABILITY.`` rows.
    Eight are outcome reasons and two are safety-policy diagnostics; the two sets
    are disjoint and their union is the whole table, so a new code cannot be added
    without failing here.
    """
    assert COMPATIBILITY_REASON_CODES.isdisjoint(POLICY_CODES)
    assert COMPATIBILITY_REASON_CODES | POLICY_CODES == _CLOSED_CAPABILITY_CODES
    assert len(COMPATIBILITY_REASON_CODES) == 8
    assert len(POLICY_CODES) == 2
    assert COMPATIBILITY_REASON_CODES == {
        UNKNOWN_NAME,
        VOCABULARY_VERSION,
        DECLARATION_OVERLAP,
        REQUIREMENT_UNMET,
        APPROXIMATION_DISALLOWED,
        APPROXIMATION_MISSING,
        LEVEL_PREVENTED,
        RUNTIME_UNAVAILABLE,
    }


def test_a_reason_outside_the_closed_reason_set_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _reason("CAPABILITY.POLICY_LIVE_RUNTIME")
    with pytest.raises(ValidationError):
        _reason("CAPABILITY.SOMETHING_NEW")
    with pytest.raises(ValidationError):
        _reason("STRATEGY.SCHEMA_INVALID")


def test_a_reason_is_tied_to_a_capability_only_where_one_applies() -> None:
    """State-governed, in both directions.

    A capability-scoped defect names its capability. A vocabulary-version
    mismatch, an unrecognized name, and runtime unavailability are not properties
    of any one vocabulary member, and an unrecognized name is deliberately never
    echoed back: doing so would make the deduplicated reason count a function of
    arbitrary caller text rather than of the closed vocabulary.
    """
    scoped = _reason(REQUIREMENT_UNMET, "market.spot")
    assert scoped.capability == "market.spot"
    assert scoped.model_dump(mode="json")["capability"] == "market.spot"

    unscoped = _reason(RUNTIME_UNAVAILABLE)
    # Compared by type rather than by ``is MISSING``: the field carries the
    # ``# type: ignore[valid-type]`` sentinel annotation of plan section 3.1, so
    # mypy narrows it to ``str`` and rejects the identity check as non-overlapping.
    assert not isinstance(unscoped.capability, str)
    # Both modes, asserted directly. Plan section 5.5.1 item 10 makes python mode
    # load-bearing in its own right, because `canonical_json._normalize` reaches a
    # model through `model_dump(mode="python")` and raises on an unsupported type --
    # so proving JSON-mode omission alone would leave the hash path unproven.
    assert "capability" not in unscoped.model_dump(mode="json")
    assert "capability" not in unscoped.model_dump(mode="python")

    for code in (UNKNOWN_NAME, VOCABULARY_VERSION, RUNTIME_UNAVAILABLE):
        with pytest.raises(ValidationError):
            _reason(code, "market.spot")
    for code in (
        REQUIREMENT_UNMET,
        APPROXIMATION_MISSING,
        APPROXIMATION_DISALLOWED,
        LEVEL_PREVENTED,
        DECLARATION_OVERLAP,
    ):
        with pytest.raises(ValidationError):
            _reason(code)


def test_a_reason_capability_must_be_a_vocabulary_member() -> None:
    with pytest.raises(ValidationError):
        _reason(REQUIREMENT_UNMET, "market.unknown")


def test_the_reason_sort_key_is_a_total_order_over_material_content() -> None:
    """No tie can reach the sort, so no permutation can change the sequence.

    A reason carries exactly ``error_code`` and an optional ``capability``, so two
    reasons equal on this key are byte-identical and one was already removed by
    deduplication. Unscoped reasons take the empty string, which sorts before
    every ``CapabilityName`` because the pattern requires a leading lowercase
    letter -- the same device plan section 5.10 uses for spec-level findings.
    """
    unscoped = _reason(RUNTIME_UNAVAILABLE)
    scoped = _reason(REQUIREMENT_UNMET, "data.ohlcv")
    assert reason_sort_key(unscoped) == ("", RUNTIME_UNAVAILABLE)
    assert reason_sort_key(scoped) == ("data.ohlcv", REQUIREMENT_UNMET)
    assert reason_sort_key(unscoped) < reason_sort_key(scoped)


# --------------------------------------------------------------------------
# CompatibilityResult
# --------------------------------------------------------------------------


def test_the_result_declares_the_plan_derived_field_list() -> None:
    """Specification section 11.3 carries **no** ``CompatibilityResult`` row.

    The plan's section 9 field-list paragraph (plan line 2941) names this model
    among those taking "exactly the minimum fields their specification section 11.3
    rows list", but no such row exists -- nor one for
    ``ComparisonEligibilityResult``. This assertion therefore checks the
    plan-derived list recorded in the Task 6 ledger, and deliberately does not
    claim to check a specification list. Derivations: ``schema_version`` from 11.1;
    ``outcome`` from 13.3/13.4; ``capability_vocabulary_version`` from 13.3 step 1;
    ``requested_comparison_level`` from the 8.2 parameter; adapter identity from
    specification section 17.2.1's same-identity requirement for ``UNAVAILABLE``;
    ``availability_observation_id`` from the 11.3 observation identity; ``reasons``
    from 13.3's "all reasons in stable capability-name order"; ``approximations``
    from 13.3 step 7's "with all approximation records".
    """
    assert tuple(CompatibilityResult.model_fields) == _EXPECTED_RESULT_FIELDS


def test_a_supported_result_carries_neither_reason_nor_approximation() -> None:
    assert _result().reasons == ()
    with pytest.raises(ValidationError):
        _result(reasons=(_reason(RUNTIME_UNAVAILABLE),))
    with pytest.raises(ValidationError):
        _result(approximations=(_approximation(),))


def test_an_approximated_result_requires_records_and_carries_no_reason() -> None:
    accepted = _result(
        outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
        approximations=(_approximation(),),
    )
    assert accepted.approximations == (_approximation(),)
    with pytest.raises(ValidationError):
        _result(outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION)
    with pytest.raises(ValidationError):
        _result(
            outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
            approximations=(_approximation(),),
            reasons=(_reason(REQUIREMENT_UNMET, "market.spot"),),
        )


@pytest.mark.parametrize(
    "outcome",
    [CompatibilityOutcome.NOT_APPLICABLE, CompatibilityOutcome.UNAVAILABLE],
)
def test_a_negative_result_requires_reasons_and_no_approximation(
    outcome: CompatibilityOutcome,
) -> None:
    accepted = _result(
        outcome=outcome,
        reasons=(_reason(REQUIREMENT_UNMET, "market.spot"),),
    )
    assert len(accepted.reasons) == 1
    with pytest.raises(ValidationError):
        _result(outcome=outcome)
    with pytest.raises(ValidationError):
        _result(
            outcome=outcome,
            reasons=(_reason(REQUIREMENT_UNMET, "market.spot"),),
            approximations=(_approximation(),),
        )


def test_the_result_rejects_unsorted_or_duplicated_reasons() -> None:
    first = _reason(REQUIREMENT_UNMET, "data.ohlcv")
    second = _reason(REQUIREMENT_UNMET, "market.spot")
    assert _result(
        outcome=CompatibilityOutcome.NOT_APPLICABLE, reasons=(first, second)
    ).reasons == (first, second)
    with pytest.raises(ValidationError):
        _result(outcome=CompatibilityOutcome.NOT_APPLICABLE, reasons=(second, first))
    with pytest.raises(ValidationError):
        _result(outcome=CompatibilityOutcome.NOT_APPLICABLE, reasons=(first, first))


def test_the_result_rejects_unsorted_or_capability_duplicated_approximations() -> None:
    first = _approximation(capability="execution.maker_orders")
    second = _approximation(capability="execution.partial_fills")
    approximated = CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
    assert _result(
        outcome=approximated, approximations=(first, second)
    ).approximations == (first, second)
    with pytest.raises(ValidationError):
        _result(outcome=approximated, approximations=(second, first))
    with pytest.raises(ValidationError):
        _result(
            outcome=approximated,
            approximations=(first, _approximation(capability=first.capability)),
        )


def test_the_public_reason_bound_cannot_be_reached() -> None:
    """Reasons are unconditionally complete, so no truncation marker is needed.

    Every capability-scoped code is tied to a vocabulary member, and the three
    unscoped codes appear at most once each after deduplication. The worst case is
    therefore ``26 x 5 + 3 = 133`` unique reasons against a bound of 256, so the
    bounded-output contract of plan section 5.4.1 -- which is a ``STRATEGY.``
    marker in any case -- never fires here.
    """
    scoped_codes = len(COMPATIBILITY_REASON_CODES) - 3
    worst_case = len(CapabilityVocabulary.names) * scoped_codes + 3
    assert worst_case == 133
    assert worst_case < MAX_COMPATIBILITY_REASONS
    assert MAX_COMPATIBILITY_APPROXIMATIONS == len(CapabilityVocabulary.names)


# --------------------------------------------------------------------------
# Deep immutability, detachment, and round trips
# --------------------------------------------------------------------------

_IMMUTABLE_LEAVES = (bool, int, str, Decimal, datetime, StrEnum)
_FORBIDDEN_CONTAINERS = (dict, list, set, bytearray)


def _audit_material_graph(value: object, path: str, failures: list[str]) -> None:
    """Walk only the declared public field graph, never Pydantic internals."""
    if value is None or value is MISSING or isinstance(value, _IMMUTABLE_LEAVES):
        return
    if isinstance(value, _FORBIDDEN_CONTAINERS):
        failures.append(f"{path}: mutable {type(value).__name__}")
        return
    if isinstance(value, frozenset):
        for index, item in enumerate(sorted(value, key=repr)):
            _audit_material_graph(item, f"{path}[{index}]", failures)
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            _audit_material_graph(item, f"{path}[{index}]", failures)
        return
    if isinstance(value, BaseModel):
        if not value.model_config.get("frozen", False):
            failures.append(f"{path}: unfrozen model {type(value).__name__}")
        for name in type(value).model_fields:
            _audit_material_graph(
                getattr(value, name, None), f"{path}.{name}", failures
            )
        return
    failures.append(f"{path}: unaudited {type(value).__name__}")


def _every_task6_record() -> tuple[tuple[str, BaseModel], ...]:
    """All **six** canonical records Task 6 introduces.

    ``CompatibilityPolicy`` belongs here and was initially omitted. Plan section
    5.5.1's forward obligation covers every new canonical record, so leaving one
    out meant a mutable field could have been added to it without any test
    failing -- and the omission would not have been visible from the four
    parametrized tests below, because they only ever see this list.
    """
    return (
        ("CapabilityDeclaration", _declaration(limitations=("Bar granularity.",))),
        ("ApproximationDeclaration", _approximation()),
        ("CompatibilityReason", _reason(REQUIREMENT_UNMET, "market.spot")),
        (
            "CompatibilityResult",
            _result(
                outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
                approximations=(_approximation(),),
            ),
        ),
        ("CompatibilityPolicy", project_1_compatibility_policy()),
        ("RuntimeAvailabilityObservation", _observation()),
    )


class _MutableProbe(BaseModel):
    """A deliberately non-compliant record, used only to prove the audit bites."""

    model_config = ConfigDict(frozen=False)

    mapping: dict[str, str] = Field(default_factory=dict)
    sequence: list[str] = Field(default_factory=list)
    members: set[str] = Field(default_factory=set)


class _NestedProbe(BaseModel):
    """A frozen outer record wrapping an unfrozen inner one."""

    model_config = ConfigDict(frozen=True)

    nested: _MutableProbe


@pytest.mark.parametrize(
    ("record", "expected_fragment"),
    [
        (_MutableProbe(mapping={"a": "b"}), "mutable dict"),
        (_MutableProbe(sequence=["a"]), "mutable list"),
        (_MutableProbe(members={"a"}), "mutable set"),
        (_NestedProbe(nested=_MutableProbe()), "unfrozen model"),
    ],
)
def test_the_material_graph_audit_detects_what_it_claims_to(
    record: BaseModel,
    expected_fragment: str,
) -> None:
    """A guard that cannot fail is not a guard.

    Every real Task 6 record passes the audit, so without a negative control the
    whole of the deep-immutability evidence would survive deleting the audit's
    forbidden-container branch, its recursion, or its frozen check. These probes
    are the only place a failure is expected, and each pins a different branch.
    """
    failures: list[str] = []
    _audit_material_graph(record, "probe", failures)
    assert any(expected_fragment in failure for failure in failures), failures


def test_the_material_graph_audit_rejects_an_unrecognized_leaf() -> None:
    """The fall-through must fail closed rather than silently accept."""
    failures: list[str] = []
    _audit_material_graph(object(), "probe", failures)
    assert failures == ["probe: unaudited object"]


def test_the_material_graph_audit_accepts_the_permitted_value_kinds() -> None:
    """The positive control: the audit must not reject what the plan permits."""
    failures: list[str] = []
    _audit_material_graph(
        (True, 1, "text", Decimal("1.5"), datetime(2026, 8, 24, tzinfo=UTC), None),
        "permitted",
        failures,
    )
    _audit_material_graph(frozenset({"a", "b"}), "frozen", failures)
    assert failures == []


@pytest.mark.parametrize(("label", "record"), _every_task6_record())
def test_every_task6_canonical_record_is_deeply_immutable(
    label: str,
    record: BaseModel,
) -> None:
    failures: list[str] = []
    _audit_material_graph(record, label, failures)
    assert failures == []


@pytest.mark.parametrize(("label", "record"), _every_task6_record())
def test_every_task6_record_rejects_attribute_rebinding(
    label: str,
    record: BaseModel,
) -> None:
    name = next(iter(type(record).model_fields))
    with pytest.raises(ValidationError):
        setattr(record, name, "mutated")
    assert getattr(record, name) != "mutated", label


@pytest.mark.parametrize(("label", "record"), _every_task6_record())
def test_every_task6_record_detaches_both_dump_modes(
    label: str,
    record: BaseModel,
) -> None:
    name = next(iter(type(record).model_fields))
    original = getattr(record, name)
    python_mode = record.model_dump(mode="python")
    json_mode = record.model_dump(mode="json")
    python_mode["injected"] = "mutated"
    json_mode["injected"] = "mutated"
    python_mode[name] = "mutated"
    json_mode[name] = "mutated"
    for dumped in (python_mode, json_mode):
        for nested in dumped.values():
            if isinstance(nested, list):
                nested.append("mutated")
    # Re-assert the record itself, not merely a later dump: a dump is rebuilt on
    # every call, so comparing two dumps would only catch a cached container and
    # would pass even if the record were reachable through the first one.
    assert getattr(record, name) == original, label
    reference = record.model_dump(mode="python")
    assert "injected" not in reference
    assert reference[name] != "mutated"


@pytest.mark.parametrize(("label", "record"), _every_task6_record())
def test_every_task6_record_round_trips_through_both_modes(
    label: str,
    record: BaseModel,
) -> None:
    model = type(record)
    from_python = model.model_validate(record.model_dump(mode="python"))
    from_json = model.model_validate_json(record.model_dump_json())
    assert from_python == record
    assert from_json == record
    assert canonical_json_bytes(from_json) == canonical_json_bytes(record)
    failures: list[str] = []
    _audit_material_graph(from_json, f"{label}:round-trip", failures)
    assert failures == []


def test_a_caller_owned_mutable_sequence_can_never_be_stored() -> None:
    """The sequence analogue of plan section 5.5.1 item 9's aliasing defect.

    ``MappingProxyType`` is a live view, so wrapping a caller's dictionary without
    copying leaves the record aliased to something the caller can still mutate.
    The same hazard exists for a sequence field whose validator returns its input
    object unchanged.

    Here it is closed one step earlier than by copying: ``CanonicalModel`` sets
    ``strict=True``, so a ``list`` is not a valid input for a ``tuple`` field at
    all and the alias is never created. That is stronger than a defensive copy,
    and it is asserted rather than assumed because relaxing strictness on any of
    these fields would silently reintroduce the aliasing path.
    """
    caller_owned = ["Bar granularity."]
    with pytest.raises(ValidationError):
        _declaration(limitations=caller_owned)
    with pytest.raises(ValidationError):
        _result(
            outcome=CompatibilityOutcome.NOT_APPLICABLE,
            reasons=[_reason(REQUIREMENT_UNMET, "market.spot")],
        )

    # The JSON boundary must materialize a fresh immutable tuple rather than keep
    # any reference to the decoded array.
    declaration = CapabilityDeclaration.model_validate_json(
        _declaration(limitations=("Bar granularity.",)).model_dump_json()
    )
    assert declaration.limitations == ("Bar granularity.",)
    assert isinstance(declaration.limitations, tuple)

    # Constructing from a snapshot of a caller-owned list is detached, because
    # ``tuple(...)`` copies. Mutating the caller's list afterwards changes nothing.
    snapshot = _declaration(limitations=tuple(caller_owned))
    caller_owned.append("Injected after construction.")
    assert snapshot.limitations == ("Bar granularity.",)


def test_the_records_reject_a_callable_or_arbitrary_object() -> None:
    """Specification section 11.1: models never accept callables or class paths."""
    with pytest.raises(ValidationError):
        _declaration(evidence_note=len)
    with pytest.raises(ValidationError):
        _result(outcome=object())
    with pytest.raises(ValidationError):
        _approximation(prevented_comparison_levels=(len,))


def test_canonical_bytes_are_deterministic_for_equal_records() -> None:
    first = _result(
        outcome=CompatibilityOutcome.NOT_APPLICABLE,
        reasons=(
            _reason(RUNTIME_UNAVAILABLE),
            _reason(REQUIREMENT_UNMET, "market.spot"),
        ),
    )
    second = _result(
        outcome=CompatibilityOutcome.NOT_APPLICABLE,
        reasons=(
            _reason(RUNTIME_UNAVAILABLE),
            _reason(REQUIREMENT_UNMET, "market.spot"),
        ),
    )
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_the_schema_hook_refuses_a_shape_it_cannot_annotate() -> None:
    """The hook fails loudly rather than silently skipping ``uniqueItems``.

    Pydantic does not emit ``uniqueItems`` for a tuple field, so this hook adds it.
    If a future Pydantic release changed the emitted shape, a hook that shrugged
    would quietly publish a weaker contract than the runtime enforces -- the same
    failure mode plan section 5.5.1 item 16 closes for serializers.
    """
    with pytest.raises(TypeError):
        capability_models._result_schema_extra({"properties": "not-an-object"})
    with pytest.raises(TypeError):
        capability_models._result_schema_extra({"properties": {"reasons": None}})


def test_the_generated_result_schema_keeps_its_shape_and_bounds() -> None:
    """Task 6 registers no schema, but the model's emitted shape is still pinned.

    Task 8 generates ``capabilities/compatibility-result-v1.schema.json`` from
    exactly this model, so a silently widened bound or a lost optionality would
    land in a canonical artifact one task later.
    """
    schema: dict[str, Any] = TypeAdapter(CompatibilityResult).json_schema()
    definitions: dict[str, Any] = schema["$defs"]
    properties: dict[str, Any] = schema["properties"]
    assert properties["reasons"]["type"] == "array"
    assert properties["reasons"]["maxItems"] == MAX_COMPATIBILITY_REASONS
    assert properties["approximations"]["maxItems"] == MAX_COMPATIBILITY_APPROXIMATIONS
    assert set(schema["required"]) == set(_EXPECTED_RESULT_FIELDS)
    assert schema["additionalProperties"] is False
    reason_schema = definitions["CompatibilityReason"]
    assert reason_schema["required"] == ["error_code"]
    assert "capability" in reason_schema["properties"]
    assert reason_schema["additionalProperties"] is False


# --------------------------------------------------------------------------
# Runtime/schema uniqueness agreement -- pre-Task-8 parity correction
# --------------------------------------------------------------------------
#
# Plan section 3.1 requires ``json_schema_extra`` callables to add the
# ``uniqueItems`` constraints Pydantic does not emit, and
# ``domain/descriptors.py`` already does exactly that for every unique-validated
# tuple it owns. Two fields in this module were left without one, so a
# standards-compliant Draft 2020-12 validator accepted arrays that ordinary
# Pydantic validation rejects. Task 8 registers both records for canonical schema
# generation, so the disagreement had to be closed before publication.

_UNIQUE_ITEM_FIELDS: tuple[tuple[str, str], ...] = (
    ("ApproximationDeclaration", "prevented_comparison_levels"),
    ("CapabilityDeclaration", "limitations"),
)
_SCHEMA_MODES: tuple[Literal["validation", "serialization"], ...] = (
    "validation",
    "serialization",
)


def _model_for(name: str) -> type[CanonicalModel]:
    models: dict[str, type[CanonicalModel]] = {
        "ApproximationDeclaration": ApproximationDeclaration,
        "CapabilityDeclaration": CapabilityDeclaration,
    }
    return models[name]


def _payload_for(name: str, *, duplicate: bool) -> dict[str, Any]:
    """Return a **complete** valid JSON document for one model.

    A hand-built property node would not prove that a real document is rejected;
    these payloads go through ``Draft202012Validator`` against the generated model
    schema exactly as an external consumer would validate them.
    """
    if name == "ApproximationDeclaration":
        levels = ["LEVEL_1", "LEVEL_1"] if duplicate else ["LEVEL_1", "LEVEL_2"]
        return {
            "schema_version": "1.0.0",
            "approximation_id": _APPROXIMATION_ID,
            "capability": "execution.partial_fills",
            "method": "Fills are modelled as all-or-nothing at the bar close.",
            "expected_impact": "Overstates fill certainty for large orders.",
            "prevented_comparison_levels": levels,
            "adapter_version": "1.0.0",
        }
    limitations = (
        ["Bar granularity only.", "Bar granularity only."]
        if duplicate
        else ["Bar granularity only.", "No intra-bar ordering."]
    )
    return {
        "schema_version": "1.0.0",
        "capability": "execution.bar_market",
        "support_kind": "NATIVE",
        "evidence_note": "Engine models bar market orders natively.",
        "limitations": limitations,
    }


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_a_unique_validated_tuple_emits_unique_items_in_both_modes(
    model_name: str,
    field: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """The published contract must not be weaker than the runtime one."""
    schema = _model_for(model_name).model_json_schema(mode=mode)

    assert schema["properties"][field]["uniqueItems"] is True


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_schema_rejects_a_duplicate_bearing_document(
    model_name: str,
    field: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """An external Draft 2020-12 consumer must reach the runtime's verdict.

    This is the defect stated as an executable fact: before the correction the
    duplicate document below was **accepted** by the generated schema and
    **rejected** by Pydantic.
    """
    schema = _model_for(model_name).model_json_schema(mode=mode)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(_payload_for(model_name, duplicate=True))
    assert field in schema["properties"]


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_schema_still_accepts_distinct_members(
    model_name: str,
    field: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """The correction must not narrow anything beyond uniqueness."""
    schema = _model_for(model_name).model_json_schema(mode=mode)
    validator = Draft202012Validator(schema)
    document = _payload_for(model_name, duplicate=False)

    validator.validate(document)
    assert len(document[field]) == 2


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_unique_items_addition_preserves_every_other_keyword(
    model_name: str,
    field: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """Exactly one keyword is added; the emitted node is otherwise identical.

    The keyword set below is the one the pre-correction schemas emitted,
    transcribed from captured evidence rather than from the current code, so this
    fails if the fix replaced the node instead of extending it.
    """
    schema = _model_for(model_name).model_json_schema(mode=mode)
    node = schema["properties"][field]

    # `ApproximationDeclaration` gained `enum` in the later runtime/schema parity
    # closure, which published the sortedness half of `validate_prevented_levels`
    # as the eight sorted subsets of the closed three-member level vocabulary.
    # `CapabilityDeclaration.limitations` did **not**: its items are `BoundedText`
    # over an unbounded domain, so no finite enumeration exists there. The
    # asymmetry is asserted rather than smoothed over.
    expected = {"type", "items", "maxItems", "title", "uniqueItems"}
    if model_name == "ApproximationDeclaration":
        expected |= {"enum"}
    assert set(node) == expected
    assert node["type"] == "array"
    if model_name == "ApproximationDeclaration":
        assert node["items"] == {"$ref": "#/$defs/ComparisonLevel"}
        assert node["maxItems"] == MAX_PREVENTED_COMPARISON_LEVELS
        assert node["title"] == "Prevented Comparison Levels"
        assert set(schema["$defs"]["ComparisonLevel"]["enum"]) == {
            level.value for level in ComparisonLevel
        }
    else:
        assert node["items"] == {"type": "string", "minLength": 1, "maxLength": 1024}
        assert node["maxItems"] == MAX_CAPABILITY_LIMITATIONS
        assert node["title"] == "Limitations"


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_no_unrelated_capability_schema_node_gained_unique_items(
    mode: Literal["validation", "serialization"],
) -> None:
    """The constraint must land on the intended fields only.

    ``CompatibilityResult`` keeps exactly the two ``uniqueItems`` its own hook has
    always set, and each corrected model marks exactly its one field.
    """
    result_schema = CompatibilityResult.model_json_schema(mode=mode)
    annotated = {
        name
        for name, node in result_schema["properties"].items()
        if isinstance(node, dict) and node.get("uniqueItems") is True
    }
    assert annotated == {"reasons", "approximations"}

    for model_name, field in _UNIQUE_ITEM_FIELDS:
        schema = _model_for(model_name).model_json_schema(mode=mode)
        marked = {
            name
            for name, node in schema["properties"].items()
            if isinstance(node, dict) and node.get("uniqueItems") is True
        }
        assert marked == {field}


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_constraint_survives_into_the_nested_definition(
    mode: Literal["validation", "serialization"],
) -> None:
    """The `$defs` path is the one Task 8 actually publishes for this record.

    ``CompatibilityResult.approximations`` is a tuple of ``ApproximationDeclaration``,
    so the corrected field reaches
    ``capabilities/compatibility-result-v1.schema.json`` through ``$defs`` rather
    than through a top-level property. An independent review found that no test
    asserted that path: a future refactor moving the constraint to a model-level
    hook that fires only for the outermost schema would keep the standalone tests
    green while the published ``$defs`` silently lost the keyword.

    A duplicate-bearing nested document is validated end to end, so this proves the
    constraint is *enforced* there rather than merely present.
    """
    schema = CompatibilityResult.model_json_schema(mode=mode)
    nested = schema["$defs"]["ApproximationDeclaration"]["properties"]

    assert nested["prevented_comparison_levels"]["uniqueItems"] is True

    Draft202012Validator.check_schema(schema)
    document = {
        "schema_version": "1.0.0",
        "outcome": "SUPPORTED_WITH_APPROXIMATION",
        "capability_vocabulary_version": "capabilities/v1",
        "requested_comparison_level": "LEVEL_1",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "availability_observation_id": _OBSERVATION_ID,
        "reasons": [],
        "approximations": [_payload_for("ApproximationDeclaration", duplicate=True)],
    }
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(document)

    document["approximations"] = [
        _payload_for("ApproximationDeclaration", duplicate=False)
    ]
    Draft202012Validator(schema).validate(document)


# Preventive runtime evidence. These begin GREEN: runtime uniqueness already
# exists and is unchanged by this correction. They are declared so the agreement
# is guarded from both sides rather than only from the schema side.


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
def test_pydantic_still_rejects_duplicate_members(
    model_name: str,
    field: str,
) -> None:
    """Preventive: the runtime half of the agreement.

    Routed through ``model_validate_json`` so it is the **same JSON document** the
    schema tests above validate. Python mode would reject a JSON array outright --
    ``CanonicalModel`` is ``strict=True``, so a ``list`` is not a valid ``tuple``
    input -- and the test would then pass for a reason unrelated to uniqueness.
    """
    with pytest.raises(ValidationError) as caught:
        _model_for(model_name).model_validate_json(
            json.dumps(_payload_for(model_name, duplicate=True))
        )

    assert "unique" in str(caught.value).lower()
    assert field in _model_for(model_name).model_fields


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
def test_pydantic_still_accepts_distinct_members_as_a_tuple(
    model_name: str,
    field: str,
) -> None:
    """Preventive: normalization, ordering, tuple identity, and frozenness."""
    record = _model_for(model_name).model_validate_json(
        json.dumps(_payload_for(model_name, duplicate=False))
    )
    value = getattr(record, field)

    assert isinstance(value, tuple)
    assert len(value) == 2
    # The committed ordering rules are unchanged by this correction.
    assert list(value) == sorted(value, key=str)
    assert record.model_config["frozen"] is True
    with pytest.raises(ValidationError):
        setattr(record, field, ())


def test_the_correction_changes_no_canonical_byte() -> None:
    """Recorded before the edit and compared after: schema shape is not hash material.

    ``uniqueItems`` is a JSON Schema keyword, not a model field, so no valid
    instance's canonical serialization may move. These literals were captured from
    the pre-correction tree.
    """
    assert canonical_json_bytes(_approximation()) == (
        b'{"adapter_version":"1.0.0",'
        b'"approximation_id":"appx_5b1c3d7e-2f4a-4c6b-8d9e-1a2b3c4d5e6f",'
        b'"capability":"execution.partial_fills",'
        b'"expected_impact":"Overstates fill certainty for large orders.",'
        b'"method":"Fills are modelled as all-or-nothing at the bar close.",'
        b'"prevented_comparison_levels":["LEVEL_1"],'
        b'"schema_version":"1.0.0"}'
    )
    assert canonical_json_bytes(
        _declaration(limitations=("Bar granularity only.",))
    ) == (
        b'{"capability":"execution.bar_market",'
        b'"evidence_note":"Engine models bar market orders natively.",'
        b'"limitations":["Bar granularity only."],'
        b'"schema_version":"1.0.0","support_kind":"NATIVE"}'
    )


def test_the_affected_models_keep_their_exact_field_order() -> None:
    """Preventive: the correction adds metadata, never a field."""
    assert (
        tuple(ApproximationDeclaration.model_fields) == _EXPECTED_APPROXIMATION_FIELDS
    )
    assert tuple(CapabilityDeclaration.model_fields) == _EXPECTED_DECLARATION_FIELDS


@pytest.mark.parametrize(("model_name", "field"), _UNIQUE_ITEM_FIELDS)
def test_both_dump_modes_keep_their_shape(model_name: str, field: str) -> None:
    """Preventive: a schema keyword must not alter either serialized form."""
    record = _model_for(model_name).model_validate_json(
        json.dumps(_payload_for(model_name, duplicate=False))
    )
    python_mode = record.model_dump(mode="python")
    json_mode = record.model_dump(mode="json")

    assert set(python_mode) == set(json_mode) == set(type(record).model_fields)
    assert isinstance(python_mode[field], tuple)
    assert isinstance(json_mode[field], list)
    assert [str(item) for item in python_mode[field]] == json_mode[field]


# --------------------------------------------------------------------------
# Stage 4 runtime/schema parity closure -- clauses AD-A1, CR-A1..A4,
# CRSN-A1..A4
#
# Every clause below is a rule ordinary validated construction enforces and the
# generated schema omitted. Plan section 3.1 names `dependentRequired` and
# `oneOf` at the same authority as the `uniqueItems` this module already
# supplies, and Stage 3 publishes this class by hand in three places
# (`domain/diagnostics.py`, both `artifacts/ownership.py` hooks) with committed
# tests asserting the *published* enforcement. These nine schemas are still
# uncommitted, so closing the gap now costs zero released bytes.
# --------------------------------------------------------------------------

# Transcribed from the emitted schema, in the order it publishes: by subset size,
# then lexicographically. The order is part of the published bytes.
_SORTED_LEVEL_SETS: list[list[str]] = [
    [],
    ["LEVEL_1"],
    ["LEVEL_2"],
    ["LEVEL_3"],
    ["LEVEL_1", "LEVEL_2"],
    ["LEVEL_1", "LEVEL_3"],
    ["LEVEL_2", "LEVEL_3"],
    ["LEVEL_1", "LEVEL_2", "LEVEL_3"],
]
_UNSORTED_LEVEL_SETS: list[list[str]] = [
    ["LEVEL_2", "LEVEL_1"],
    ["LEVEL_3", "LEVEL_1"],
    ["LEVEL_3", "LEVEL_2"],
    ["LEVEL_3", "LEVEL_2", "LEVEL_1"],
]
_UNSCOPED_CODES = sorted({UNKNOWN_NAME, VOCABULARY_VERSION, RUNTIME_UNAVAILABLE})
_SCOPED_CODES = sorted(COMPATIBILITY_REASON_CODES - set(_UNSCOPED_CODES))


def _schema_of(model: type[CanonicalModel], mode: str) -> dict[str, Any]:
    schema: dict[str, Any] = model.model_json_schema(mode=mode)  # type: ignore[arg-type]
    return schema


def _nested(parent: dict[str, Any], name: str) -> dict[str, Any]:
    return {"$defs": parent["$defs"], "$ref": f"#/$defs/{name}"}


def _accepts(model: type[CanonicalModel], document: dict[str, Any]) -> bool:
    try:
        model.model_validate_json(json.dumps(document))
    except ValidationError:
        return False
    return True


def _approximation_document(levels: list[str]) -> dict[str, Any]:
    document = _approximation().model_dump(mode="json")
    document["prevented_comparison_levels"] = levels
    return document


def _result_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = _result().model_dump(mode="json")
    document.update(updates)
    return document


def _reason_document(code: str, capability: str | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {"error_code": code}
    if capability is not None:
        document["capability"] = capability
    return document


# --- AD-A1: prevented level sortedness over the closed three-member domain ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("levels", _SORTED_LEVEL_SETS)
def test_ad_a1_every_sorted_prevented_level_set_is_accepted(
    mode: str, levels: list[str]
) -> None:
    document = _approximation_document(list(levels))
    assert _accepts(ApproximationDeclaration, document)
    Draft202012Validator(_schema_of(ApproximationDeclaration, mode)).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("levels", _UNSORTED_LEVEL_SETS)
def test_ad_a1_every_unsorted_prevented_level_set_is_rejected(
    mode: str, levels: list[str]
) -> None:
    """The residue the source comment called inexpressible. For three closed
    members with `maxItems: 3` and `uniqueItems`, an eight-member `enum` is exact."""
    document = _approximation_document(list(levels))
    assert not _accepts(ApproximationDeclaration, document)
    schema = _schema_of(ApproximationDeclaration, mode)
    assert not Draft202012Validator(schema).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_prevented_level_enum_preserves_every_other_keyword(mode: str) -> None:
    node = _schema_of(ApproximationDeclaration, mode)["properties"][
        "prevented_comparison_levels"
    ]
    assert node["type"] == "array"
    assert node["items"] == {"$ref": "#/$defs/ComparisonLevel"}
    assert node["maxItems"] == MAX_PREVENTED_COMPARISON_LEVELS
    assert node["uniqueItems"] is True
    assert node["enum"] == _SORTED_LEVEL_SETS


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_prevented_level_enum_survives_into_the_result_definition(
    mode: str,
) -> None:
    """`CompatibilityResult.approximations` is a tuple of this record, so the
    constraint must reach `compatibility-result-v1` through `$defs` too."""
    parent = _schema_of(CompatibilityResult, mode)
    node = parent["$defs"]["ApproximationDeclaration"]["properties"][
        "prevented_comparison_levels"
    ]
    assert node["enum"] == _SORTED_LEVEL_SETS
    document = _result_document(
        outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION.value,
        approximations=[_approximation_document(["LEVEL_2", "LEVEL_1"])],
    )
    assert not _accepts(CompatibilityResult, document)
    assert not Draft202012Validator(parent).is_valid(document)


def test_the_unbounded_text_sortedness_residue_is_still_inexpressible() -> None:
    """Clause CD-C1. `limitations` items are `BoundedText`, so the element domain
    is unbounded and no finite `enum` exists. Escalation 8 stands here."""
    document = _declaration().model_dump(mode="json")
    document["limitations"] = ["B text.", "A text."]
    assert not _accepts(CapabilityDeclaration, document)
    for mode in ("validation", "serialization"):
        assert Draft202012Validator(_schema_of(CapabilityDeclaration, mode)).is_valid(
            document
        )


# --- CR-A1..A4: the outcome-governed cardinalities ---


def _result_baseline(outcome: str) -> dict[str, Any]:
    document = _result_document(outcome=outcome)
    if outcome == "SUPPORTED_WITH_APPROXIMATION":
        document["approximations"] = [_approximation_document([])]
    elif outcome in ("NOT_APPLICABLE", "UNAVAILABLE"):
        document["reasons"] = [_reason_document(REQUIREMENT_UNMET, "market.spot")]
    return document


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    "outcome",
    ["SUPPORTED", "SUPPORTED_WITH_APPROXIMATION", "NOT_APPLICABLE", "UNAVAILABLE"],
)
def test_every_outcome_baseline_agrees_before_any_mutation(
    mode: str, outcome: str
) -> None:
    """Non-vacuity for the four CR clauses: one complete valid document each."""
    document = _result_baseline(outcome)
    assert _accepts(CompatibilityResult, document)
    schema = _schema_of(CompatibilityResult, mode)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_cr_a1_a_supported_outcome_publishes_no_reason(mode: str) -> None:
    document = _result_baseline("SUPPORTED")
    document["reasons"] = [_reason_document(REQUIREMENT_UNMET, "market.spot")]
    assert not _accepts(CompatibilityResult, document)
    assert not Draft202012Validator(_schema_of(CompatibilityResult, mode)).is_valid(
        document
    )


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_cr_a2_a_natively_supported_outcome_publishes_no_approximation(
    mode: str,
) -> None:
    document = _result_baseline("SUPPORTED")
    document["approximations"] = [_approximation_document([])]
    assert not _accepts(CompatibilityResult, document)
    assert not Draft202012Validator(_schema_of(CompatibilityResult, mode)).is_valid(
        document
    )


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_cr_a3_an_approximated_outcome_requires_at_least_one_record(
    mode: str,
) -> None:
    document = _result_baseline("SUPPORTED_WITH_APPROXIMATION")
    document["approximations"] = []
    assert not _accepts(CompatibilityResult, document)
    assert not Draft202012Validator(_schema_of(CompatibilityResult, mode)).is_valid(
        document
    )


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("outcome", ["NOT_APPLICABLE", "UNAVAILABLE"])
def test_cr_a4_a_negative_outcome_requires_a_reason_and_forbids_approximations(
    mode: str, outcome: str
) -> None:
    """One parametrized test, two independent mutations, both named by outcome."""
    schema = _schema_of(CompatibilityResult, mode)
    without_reason = _result_baseline(outcome)
    without_reason["reasons"] = []
    assert not _accepts(CompatibilityResult, without_reason)
    assert not Draft202012Validator(schema).is_valid(without_reason)

    with_approximation = _result_baseline(outcome)
    with_approximation["approximations"] = [_approximation_document([])]
    assert not _accepts(CompatibilityResult, with_approximation)
    assert not Draft202012Validator(schema).is_valid(with_approximation)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_outcome_conditions_are_three_separable_branches(mode: str) -> None:
    """Structural, so a mutation removing one branch cannot hide behind another."""
    schema = _schema_of(CompatibilityResult, mode)
    branches = schema["allOf"]
    assert len(branches) == 3
    guards = [
        branch["if"]["properties"]["outcome"].get("const")
        or branch["if"]["properties"]["outcome"]["enum"]
        for branch in branches
    ]
    assert guards == [
        "SUPPORTED",
        "SUPPORTED_WITH_APPROXIMATION",
        ["NOT_APPLICABLE", "UNAVAILABLE"],
    ]


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_result_hook_preserves_the_unique_items_it_already_published(
    mode: str,
) -> None:
    """The previous correction's keywords must survive the extension."""
    properties = _schema_of(CompatibilityResult, mode)["properties"]
    assert properties["reasons"]["uniqueItems"] is True
    assert properties["approximations"]["uniqueItems"] is True
    assert properties["reasons"]["maxItems"] == MAX_COMPATIBILITY_REASONS
    assert properties["approximations"]["maxItems"] == MAX_COMPATIBILITY_APPROXIMATIONS
    assert _schema_of(CompatibilityResult, mode)["required"] == list(
        CompatibilityResult.model_fields
    )


# --- CRSN-A1..A4: the reason's closed sets and its scope biconditional ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_reason_baselines_agree_before_any_mutation(mode: str) -> None:
    root = _nested(_schema_of(CompatibilityResult, mode), "CompatibilityReason")
    for document in (
        _reason_document(REQUIREMENT_UNMET, "market.spot"),
        _reason_document(RUNTIME_UNAVAILABLE),
    ):
        assert _accepts(CompatibilityReason, document)
        Draft202012Validator(root).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_crsn_a1_the_error_code_is_published_as_the_closed_eight(mode: str) -> None:
    """Clause CRSN-A1, published **at the field**.

    `ErrorCode` is shared with the frozen `domain/diagnostic-v1.schema.json`, so
    the `enum` must never reach the type. A separate assertion below proves the
    shared `$defs` entry is unchanged.
    """
    parent = _schema_of(CompatibilityResult, mode)
    node = parent["$defs"]["CompatibilityReason"]["properties"]["error_code"]
    assert sorted(node["enum"]) == sorted(COMPATIBILITY_REASON_CODES)
    assert len(node["enum"]) == 8
    document = _reason_document("CONFIG.LAYER_INVALID")
    assert not _accepts(CompatibilityReason, document)
    assert not Draft202012Validator(_nested(parent, "CompatibilityReason")).is_valid(
        document
    )


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_shared_error_code_definition_is_not_narrowed(mode: str) -> None:
    """The scoping trap: `ErrorCode` reaches a released Stage 3 `$id`."""
    parent = _schema_of(CompatibilityResult, mode)
    assert "enum" not in parent["$defs"]["ErrorCode"]
    assert parent["$defs"]["ErrorCode"]["type"] == "string"
    assert "pattern" in parent["$defs"]["ErrorCode"]
    # the field still references the shared type, so the pattern still applies
    node = parent["$defs"]["CompatibilityReason"]["properties"]["error_code"]
    assert node["$ref"] == "#/$defs/ErrorCode"


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_crsn_a2_the_capability_is_published_as_the_closed_vocabulary(
    mode: str,
) -> None:
    """Clause CRSN-A2. The record pins `capability_vocabulary_version` to the
    literal `capabilities/v1`, so the vocabulary is frozen for this schema
    version and publishing it duplicates nothing that can drift underneath."""
    parent = _schema_of(CompatibilityResult, mode)
    node = parent["$defs"]["CompatibilityReason"]["properties"]["capability"]
    assert node["enum"] == list(CapabilityVocabulary.names)
    assert len(node["enum"]) == 26
    document = _reason_document(REQUIREMENT_UNMET, "not.a.member")
    assert not _accepts(CompatibilityReason, document)
    assert not Draft202012Validator(_nested(parent, "CompatibilityReason")).is_valid(
        document
    )


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_every_vocabulary_member_is_still_accepted(mode: str) -> None:
    """26 positive samples: an `enum` with one wrong member silently over-rejects."""
    root = _nested(_schema_of(CompatibilityResult, mode), "CompatibilityReason")
    for name in CapabilityVocabulary.names:
        document = _reason_document(REQUIREMENT_UNMET, name)
        assert _accepts(CompatibilityReason, document), name
        Draft202012Validator(root).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("code", _SCOPED_CODES)
def test_crsn_a3_a_scoped_code_must_name_its_capability(mode: str, code: str) -> None:
    root = _nested(_schema_of(CompatibilityResult, mode), "CompatibilityReason")
    assert _accepts(CompatibilityReason, _reason_document(code, "market.spot"))
    Draft202012Validator(root).validate(_reason_document(code, "market.spot"))
    assert not _accepts(CompatibilityReason, _reason_document(code))
    assert not Draft202012Validator(root).is_valid(_reason_document(code))


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("code", _UNSCOPED_CODES)
def test_crsn_a4_an_unscoped_code_must_not_name_a_capability(
    mode: str, code: str
) -> None:
    root = _nested(_schema_of(CompatibilityResult, mode), "CompatibilityReason")
    assert _accepts(CompatibilityReason, _reason_document(code))
    Draft202012Validator(root).validate(_reason_document(code))
    assert not _accepts(CompatibilityReason, _reason_document(code, "market.spot"))
    scoped_document = _reason_document(code, "market.spot")
    assert not Draft202012Validator(root).is_valid(scoped_document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_reason_scope_conditions_are_two_separable_branches(mode: str) -> None:
    node = _schema_of(CompatibilityResult, mode)["$defs"]["CompatibilityReason"]
    branches = node["allOf"]
    assert len(branches) == 2
    assert branches[0]["if"]["properties"]["error_code"]["enum"] == _UNSCOPED_CODES
    assert branches[0]["then"] == {"not": {"required": ["capability"]}}
    assert branches[1]["if"]["properties"]["error_code"]["enum"] == _SCOPED_CODES
    assert branches[1]["then"] == {"required": ["capability"]}
    assert "capability" not in node["required"]


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_reason_capability_keeps_its_inherited_string_contract(mode: str) -> None:
    """The `enum` is added beside the pattern, not in place of it."""
    node = _schema_of(CompatibilityResult, mode)["$defs"]["CompatibilityReason"][
        "properties"
    ]["capability"]
    assert node["type"] == "string"
    assert node["minLength"] == 3
    assert node["maxLength"] == 128
    assert node["pattern"].startswith("^[a-z]")
    assert isinstance(node["enum"], list)


def test_the_reason_hook_refuses_a_shape_it_cannot_annotate() -> None:
    """The hook fails loudly rather than silently skipping the annotation.

    Task 8 generates a published schema from this model, so a hook that shrugged
    when it could not find its fields would quietly publish a contract weaker
    than the runtime enforces -- which is the whole defect class this correction
    exists to close. Same discipline as `_set_unique_items` and `_mark_unique`.
    """
    with pytest.raises(TypeError, match="properties must be an object"):
        capability_models._reason_schema_extra({})
    with pytest.raises(TypeError, match="scope fields must be objects"):
        capability_models._reason_schema_extra({"properties": {"error_code": {}}})
    with pytest.raises(TypeError, match="scope fields must be objects"):
        capability_models._reason_schema_extra(
            {"properties": {"error_code": "not an object", "capability": {}}}
        )


def test_the_result_hook_still_refuses_a_shape_it_cannot_annotate() -> None:
    """Extending `_result_schema_extra` must not have weakened its own guard."""
    with pytest.raises(TypeError, match="properties must be an object"):
        capability_models._result_schema_extra({})
    with pytest.raises(TypeError, match="must be an object"):
        capability_models._result_schema_extra({"properties": {"reasons": {}}})


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_result_approximation_key_rules_stay_runtime_only(mode: str) -> None:
    """Two residuals an independent review found missing from this record's ledger.

    `CompatibilityResult.validate_approximations` routes through
    `_unique_sorted_text`, which **rejects** both a duplicate capability and an
    unsorted sequence. That is the opposite of `ComparisonInput.approximations`,
    whose validator *normalizes* by returning a sorted tuple -- so the
    "normalizing validators need no published order" argument that correctly
    clears the comparison record does **not** transfer here, and the two rules
    below are genuine runtime-only residuals rather than non-divergences.

    Both are inexpressible for the same reason: the key is `capability`, typed
    `CapabilityName`, and this record applies **no** vocabulary-membership
    validator to a nested `ApproximationDeclaration` -- so the key domain is an
    open pattern, not a closed set, and there is no finite `contains`
    enumeration. The published flat `uniqueItems` is sound but strictly weaker:
    every whole-object duplicate is also a key duplicate, so it never rejects a
    runtime-valid document, but it cannot catch two distinct declarations sharing
    one capability.
    """
    schema = _schema_of(CompatibilityResult, mode)
    base = _result_document(
        outcome=CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION.value
    )

    unsorted_by_capability = dict(base)
    unsorted_by_capability["approximations"] = [
        _approximation(capability="execution.partial_fills").model_dump(mode="json"),
        _approximation(capability="data.ohlcv").model_dump(mode="json"),
    ]
    assert not _accepts(CompatibilityResult, unsorted_by_capability)
    assert Draft202012Validator(schema).is_valid(unsorted_by_capability)

    duplicate_capability = dict(base)
    first = _approximation(capability="data.ohlcv").model_dump(mode="json")
    second = dict(first) | {"method": "A materially different method."}
    duplicate_capability["approximations"] = [first, second]
    assert not _accepts(CompatibilityResult, duplicate_capability)
    assert Draft202012Validator(schema).is_valid(duplicate_capability)

    # the key domain really is open: an off-vocabulary capability is accepted, so
    # no closed enumeration exists to key a `contains` table on.
    off_vocabulary = _approximation(capability="not.a_vocabulary_member")
    assert off_vocabulary.capability == "not.a_vocabulary_member"


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_reason_ordering_rule_stays_runtime_only(mode: str) -> None:
    """Clause CR-C1. `validate_reasons` rejects an uncanonically ordered tuple.

    The key domain here *is* closed and finite -- 26 capabilities x 8 codes -- so
    the discriminating criterion is not "closed versus open" but whether the
    accepted array space is small enough to enumerate. Over a 208-member key
    space it is not, so this stays a residual while the three-member
    `ComparisonLevel` sortedness rules are published as an eight-member `enum`.
    """
    schema = _schema_of(CompatibilityResult, mode)
    document = _result_document(outcome=CompatibilityOutcome.NOT_APPLICABLE.value)
    document["reasons"] = [
        _reason_document(REQUIREMENT_UNMET, "market.spot"),
        _reason_document(REQUIREMENT_UNMET, "data.ohlcv"),
    ]
    assert not _accepts(CompatibilityResult, document)
    assert Draft202012Validator(schema).is_valid(document)


def test_the_capability_parity_correction_changes_no_canonical_byte() -> None:
    """Every pinned canonical value is unchanged by schema metadata."""
    assert canonical_json_bytes(_result()) == canonical_json_bytes(
        CompatibilityResult.model_validate_json(json.dumps(_result_document()))
    )
    assert list(CompatibilityReason.model_fields) == ["error_code", "capability"]
    assert list(ApproximationDeclaration.model_fields) == list(
        _EXPECTED_APPROXIMATION_FIELDS
    )
    assert list(CompatibilityResult.model_fields) == list(_EXPECTED_RESULT_FIELDS)
