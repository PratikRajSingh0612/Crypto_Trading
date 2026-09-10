"""Stage 6 Task 1: the closed protocol vocabularies (Stage 6 plan section 3.4)
and the negotiable schema names (plan section 5.2).

Every enum is asserted member by member with its length pinned, so a silently
added, dropped or reordered member fails here rather than in a later parser
test. Values equal names: the uppercase serialization is the plan's declared
reading of specification section 11.1 over the lower-case labels of the 14.4
event table.
"""

from __future__ import annotations

from enum import StrEnum

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    AdapterDiagnosticCategory,
    NegotiationOutcome,
    ProtocolEventType,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.lifecycle import EngineRunState
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

_EXPECTED_MEMBERS: dict[type[StrEnum], tuple[str, ...]] = {
    SemanticStatus: (
        "SUCCEEDED",
        "SUCCEEDED_WITH_WARNINGS",
        "FAILED",
        "CANCELLED",
        "TIMED_OUT",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
    ),
    ValidationOutcome: ("VALID", "NOT_APPLICABLE", "UNAVAILABLE", "INVALID"),
    ProtocolEventType: (
        "HEARTBEAT",
        "PROGRESS",
        "WARNING",
        "DIAGNOSTIC",
        "ARTIFACT_PRODUCED",
        "FINAL_RESULT",
    ),
    NegotiationOutcome: ("NEGOTIATED", "FAILED"),
    ProtocolIntegrityStatus: ("INTACT", "VIOLATED"),
    ReconciliationVerdict: (
        "DESCRIBED",
        "DESCRIBE_UNAVAILABLE",
        "VALIDATED_READY",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
        "FAILED",
        "RESULT_FINALIZATION_ELIGIBLE",
    ),
    AdapterDiagnosticCategory: (
        "ENGINE_RUNTIME",
        "ADAPTER_UNAVAILABILITY",
        "COMPATIBILITY",
    ),
}
_EXPECTED_LENGTHS: dict[type[StrEnum], int] = {
    SemanticStatus: 7,
    ValidationOutcome: 4,
    ProtocolEventType: 6,
    NegotiationOutcome: 2,
    ProtocolIntegrityStatus: 2,
    ReconciliationVerdict: 7,
    AdapterDiagnosticCategory: 3,
}
_ENUMS = list(_EXPECTED_MEMBERS)
_IDS = [enum.__name__ for enum in _ENUMS]
#: Plan section 5.2's five names, in the plan's listed order; the constant is the
#: sorted form of exactly this set.
_NEGOTIABLE_LISTED = (
    "protocol.adapter-descriptor",
    "protocol.adapter-command-request-envelope",
    "protocol.protocol-event-envelope",
    "protocol.adapter-validation-result",
    "protocol.adapter-result-manifest",
)


@pytest.mark.parametrize("enum", _ENUMS, ids=_IDS)
def test_each_vocabulary_has_exactly_the_plan_members_in_order(
    enum: type[StrEnum],
) -> None:
    expected = _EXPECTED_MEMBERS[enum]
    assert issubclass(enum, StrEnum)
    assert tuple(member.name for member in enum) == expected
    assert tuple(member.value for member in enum) == expected
    assert len(enum) == _EXPECTED_LENGTHS[enum] == len(expected)


@pytest.mark.parametrize("enum", _ENUMS, ids=_IDS)
def test_each_vocabulary_serializes_uppercase_identifiers(
    enum: type[StrEnum],
) -> None:
    """Declared reading: specification 11.1 fixes uppercase serialization; the
    14.4 table spellings (`heartbeat`, `artifact_produced`) are labels."""
    for member in enum:
        assert member.value == member.value.upper()
        assert member.value.isidentifier()
        assert member.value == member.name


@pytest.mark.parametrize("enum", _ENUMS, ids=_IDS)
def test_each_vocabulary_rejects_a_foreign_or_lowercase_value(
    enum: type[StrEnum],
) -> None:
    adapter = TypeAdapter(enum)
    first = next(iter(enum))
    assert adapter.validate_python(first.value) is first
    for invalid in (
        first.value.lower(),
        f" {first.value}",
        f"{first.value}\n",
        "",
        "TELEMETRY",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)
    with pytest.raises(ValidationError):
        adapter.validate_python(1)


def test_adapter_diagnostic_categories_are_the_three_claimable_categories() -> None:
    """Plan section 3.9: an adapter may claim exactly these three
    `DiagnosticCategory` members; the nine core-owned categories are the
    complement, so a core namespace can never be spoofed from the wire."""
    claimable = {member.value for member in AdapterDiagnosticCategory}
    domain = {member.value for member in DiagnosticCategory}
    assert claimable <= domain
    assert domain - claimable == {
        "USER_CONFIGURATION",
        "SCHEMA_VALIDATION",
        "PROTOCOL",
        "TIMEOUT",
        "CANCELLATION",
        "ARTIFACT_CORRUPTION",
        "PERSISTENCE",
        "INTERNAL_INVARIANT",
        "SECURITY",
    }
    for member in AdapterDiagnosticCategory:
        assert DiagnosticCategory(member.value).value == member.value
    assert not issubclass(AdapterDiagnosticCategory, DiagnosticCategory)
    assert not issubclass(DiagnosticCategory, AdapterDiagnosticCategory)


def test_the_vocabularies_are_distinct_types_despite_shared_member_names() -> None:
    """`FAILED`, `NOT_APPLICABLE` and `UNAVAILABLE` recur across `SemanticStatus`,
    `ReconciliationVerdict`, `ValidationOutcome` and the Stage 5 `EngineRunState`;
    each vocabulary is its own closed type, never an alias or subclass of another,
    so a value validated for one field cannot stand in for another."""
    types: tuple[type[StrEnum], ...] = (*_ENUMS, EngineRunState)
    for left in types:
        for right in types:
            if left is not right:
                assert not issubclass(left, right), (left, right)
    assert type(SemanticStatus.FAILED) is SemanticStatus
    assert type(ReconciliationVerdict.FAILED) is ReconciliationVerdict
    assert (
        TypeAdapter(SemanticStatus).validate_python("FAILED") is SemanticStatus.FAILED
    )
    assert TypeAdapter(ValidationOutcome).validate_python("INVALID") is (
        ValidationOutcome.INVALID
    )
    with pytest.raises(ValidationError):
        TypeAdapter(ValidationOutcome).validate_python("SUCCEEDED")


def test_negotiable_schema_names_are_the_five_plan_names_sorted() -> None:
    """Declared reading: the constant is sorted because every consuming
    collection is a sorted `SupportedSchemaVersion` tuple (plan 3.1, 3.6, 3.8)
    and the section 5.2 listing order carries no meaning."""
    assert set(NEGOTIABLE_SCHEMA_NAMES) == set(_NEGOTIABLE_LISTED)
    assert NEGOTIABLE_SCHEMA_NAMES == tuple(sorted(_NEGOTIABLE_LISTED))
    assert NEGOTIABLE_SCHEMA_NAMES == (
        "protocol.adapter-command-request-envelope",
        "protocol.adapter-descriptor",
        "protocol.adapter-result-manifest",
        "protocol.adapter-validation-result",
        "protocol.protocol-event-envelope",
    )
    assert type(NEGOTIABLE_SCHEMA_NAMES) is tuple
    assert len(set(NEGOTIABLE_SCHEMA_NAMES)) == 5
    identifier: TypeAdapter[str] = TypeAdapter(NormalizedIdentifier)
    for name in NEGOTIABLE_SCHEMA_NAMES:
        assert identifier.validate_python(name) == name
        assert name.startswith("protocol.")


def test_negotiable_schema_names_map_one_to_one_onto_protocol_identifiers() -> None:
    """Plan section 5.2: `protocol.<name>` maps to the permanent identifier
    `urn:crypto-lab:schema:protocol:<name>:1.0.0`; the descriptor is the
    registered Stage 3 entry, the other four are Stage 6 Task 9 entries."""
    identifiers = {
        name: f"urn:crypto-lab:schema:protocol:{name.removeprefix('protocol.')}:1.0.0"
        for name in NEGOTIABLE_SCHEMA_NAMES
    }
    assert len(set(identifiers.values())) == 5
    registered = {definition.schema_id for definition in SCHEMA_DEFINITIONS}
    assert identifiers["protocol.adapter-descriptor"] in registered
    assert identifiers["protocol.adapter-descriptor"] == (
        "urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0"
    )
    for identifier in identifiers.values():
        assert identifier.startswith("urn:crypto-lab:schema:protocol:")
        assert identifier.endswith(":1.0.0")
