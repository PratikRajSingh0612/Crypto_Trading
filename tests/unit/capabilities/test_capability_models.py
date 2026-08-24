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

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.capabilities import models as capability_models
from crypto_lab.capabilities.models import (
    APPROXIMATION_DISALLOWED,
    APPROXIMATION_MISSING,
    COMPATIBILITY_REASON_CODES,
    DECLARATION_OVERLAP,
    LEVEL_PREVENTED,
    MAX_COMPATIBILITY_APPROXIMATIONS,
    MAX_COMPATIBILITY_REASONS,
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
