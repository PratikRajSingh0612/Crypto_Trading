"""Test the `StrategyLoader` facade end to end: `Result[StrategyVersion]`.

The facade owns no validation of its own. Its contract is that every boundary it
composes fails closed, that no successful `StrategyVersion` can exist for a
document any stage rejected, and that the record it builds is a function of the
explicit arguments alone.

Failure documents are built by mutating the decoded `sma_cross_long.valid.yaml`
mapping as plain data and re-serializing it with `canonical_json_bytes`. JSON is a
YAML subset, so those bytes load through the same strict boundary as a hand-written
document while keeping each case's defect the whole of its difference from valid.
"""

from __future__ import annotations

import ast
import copy
import importlib
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.results import MAX_RESULT_DIAGNOSTICS, Failure, Success
from crypto_lab.strategy.loader import (
    _MESSAGES,
    _MODEL_DECLARED_CODES,
    SOURCE_COMPONENT,
    StrategyLoader,
    _classify,
    _location,
    _substantive,
)
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategyVersion,
    strategy_version_hash,
    strategy_version_identifier,
)
from crypto_lab.strategy.yaml_source import MAX_SOURCE_BYTES, load_yaml_document

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "strategy"
_SOURCE_ROOT = Path(__file__).resolve().parents[3] / "src" / "crypto_lab" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)
_LATER = datetime(2026, 9, 1, 6, 30, 0, tzinfo=UTC)
_NAME = "sma_cross_long.valid.yaml"
_LIMIT_REACHED = "STRATEGY.DIAGNOSTIC_LIMIT_REACHED"


def _valid_bytes() -> bytes:
    return (_FIXTURES / _NAME).read_bytes()


def _valid_mapping() -> dict[str, Any]:
    outcome = load_yaml_document(_valid_bytes(), _NAME, _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome
    value = outcome.value.value
    assert isinstance(value, dict)
    return copy.deepcopy(value)


def _source(mapping: dict[str, Any]) -> bytes:
    return canonical_json_bytes(mapping)


def _load(
    source: bytes,
    *,
    source_name: str = _NAME,
    observed_at_utc: datetime = _OBSERVED_AT,
) -> Success[StrategyVersion] | Failure:
    return StrategyLoader.load(source, source_name, observed_at_utc)


def _succeed(source: bytes, **kwargs: Any) -> StrategyVersion:
    outcome = _load(source, **kwargs)
    assert isinstance(outcome, Success), outcome
    return outcome.value


def _fail(source: bytes, **kwargs: Any) -> tuple[Diagnostic, ...]:
    outcome = _load(source, **kwargs)
    assert isinstance(outcome, Failure), outcome
    return outcome.diagnostics


def _codes(source: bytes, **kwargs: Any) -> set[str]:
    return {item.error_code for item in _fail(source, **kwargs)}


# --- The success path ------------------------------------------------------


def test_a_complete_valid_strategy_loads_into_a_strategy_version() -> None:
    version = _succeed(_valid_bytes())
    assert isinstance(version, StrategyVersion)
    assert version.schema_version == "1.0.0"
    assert version.hashing_profile_version == STRATEGY_VERSION_PROFILE_VERSION
    assert version.strategy_id == version.strategy_spec.strategy_id
    assert version.content_hash == strategy_version_hash(version.strategy_spec)
    assert version.extension_hashes == ()


def test_the_version_identifier_is_derived_from_the_content_hash() -> None:
    version = _succeed(_valid_bytes())
    assert version.strategy_version_id == strategy_version_identifier(
        version.content_hash
    )


def test_the_created_time_is_the_supplied_observed_time() -> None:
    """No clock is read: `created_at_utc` can only be the explicit argument."""
    version = _succeed(_valid_bytes(), observed_at_utc=_LATER)
    assert version.created_at_utc == _LATER
    assert version.source_provenance.observed_at_utc == _LATER


def test_the_source_provenance_is_constructed_from_the_exact_bytes() -> None:
    source = _valid_bytes()
    provenance = _succeed(source).source_provenance
    assert provenance.source_name == _NAME
    assert provenance.source_bytes_sha256 == sha256_bytes(source)
    assert provenance.source_byte_length == len(source)
    assert provenance.observed_at_utc == _OBSERVED_AT


def test_provenance_records_the_label_and_never_a_path() -> None:
    provenance = _succeed(_valid_bytes(), source_name="alpha.strategy.yaml")
    assert provenance.source_provenance.source_name == "alpha.strategy.yaml"


def test_two_independent_loads_of_equal_inputs_are_byte_identical() -> None:
    first = _succeed(_valid_bytes())
    second = _succeed(_valid_bytes())
    assert first is not second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_a_non_material_argument_change_leaves_the_content_hash_unchanged() -> None:
    baseline = _succeed(_valid_bytes())
    varied = _succeed(_valid_bytes(), source_name="other.yaml", observed_at_utc=_LATER)
    assert baseline.content_hash == varied.content_hash
    assert baseline.strategy_version_id == varied.strategy_version_id
    assert canonical_json_bytes(baseline) != canonical_json_bytes(varied)


@pytest.mark.parametrize(
    "name",
    [
        "sma_cross_long.valid.yaml",
        "sma_cross_long.reordered_keys.yaml",
        "sma_cross_long.commented.yaml",
    ],
)
def test_the_hash_equivalent_triple_loads_to_one_content_hash(name: str) -> None:
    baseline = _succeed(_valid_bytes())
    variant = _succeed((_FIXTURES / name).read_bytes(), source_name=name)
    assert variant.content_hash == baseline.content_hash
    assert variant.strategy_version_id == baseline.strategy_version_id


@pytest.mark.parametrize(
    "name",
    [
        "adjacent_entry_exit.valid.yaml",
        "bar_offsets.valid.yaml",
        "crossover_equality.valid.yaml",
        "decimal_rounding.valid.yaml",
        "missing_input.valid.yaml",
        "warm_up_boundary.valid.yaml",
    ],
)
def test_every_committed_valid_fixture_loads(name: str) -> None:
    version = _succeed((_FIXTURES / name).read_bytes(), source_name=name)
    assert version.content_hash == strategy_version_hash(version.strategy_spec)


def test_distinct_valid_fixtures_have_distinct_content_hashes() -> None:
    names = (
        "adjacent_entry_exit.valid.yaml",
        "bar_offsets.valid.yaml",
        "crossover_equality.valid.yaml",
        "decimal_rounding.valid.yaml",
        "missing_input.valid.yaml",
        "sma_cross_long.valid.yaml",
        "warm_up_boundary.valid.yaml",
    )
    hashes = {
        _succeed((_FIXTURES / name).read_bytes(), source_name=name).content_hash
        for name in names
    }
    assert len(hashes) == len(names)


# --- Stage 1: the safe YAML boundary --------------------------------------


def test_a_path_shaped_source_name_is_rejected_without_echoing_it() -> None:
    offending = "C:/Users/someperson/secret/strategy.yaml"
    diagnostics = _fail(_valid_bytes(), source_name=offending)
    assert {item.error_code for item in diagnostics} == {"STRATEGY.SOURCE_NAME_INVALID"}
    encoded = canonical_json_bytes(diagnostics).decode("utf-8")
    for fragment in ("someperson", "Users", "secret", "C:/"):
        assert fragment not in encoded


def test_a_non_bytes_source_is_rejected_through_result() -> None:
    outcome = StrategyLoader.load(
        "schema_version: '1.0.0'",  # type: ignore[arg-type]
        _NAME,
        _OBSERVED_AT,
    )
    assert isinstance(outcome, Failure)
    assert {item.error_code for item in outcome.diagnostics} == {
        "STRATEGY.SOURCE_NOT_IN_MEMORY"
    }


def test_an_oversized_source_is_rejected() -> None:
    assert _codes(b"#" + b"a" * MAX_SOURCE_BYTES) == {"STRATEGY.SOURCE_TOO_LARGE"}


def test_a_byte_order_mark_is_rejected() -> None:
    assert _codes(b"\xef\xbb\xbf" + _valid_bytes()) == {"STRATEGY.SOURCE_BOM_PRESENT"}


def test_invalid_utf8_is_rejected() -> None:
    assert _codes(b"display_name: \xff\xfe") == {"STRATEGY.SOURCE_NOT_UTF8"}


def test_malformed_yaml_is_rejected() -> None:
    assert _codes(b"schema_version: [unclosed\n") == {"STRATEGY.YAML_SYNTAX"}


def test_an_empty_document_is_rejected() -> None:
    assert _codes(b"# only a comment\n") == {"STRATEGY.YAML_EMPTY_DOCUMENT"}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("python_tag.yaml", "STRATEGY.YAML_FORBIDDEN_TAG"),
        ("unknown_tag.yaml", "STRATEGY.YAML_FORBIDDEN_TAG"),
        ("merge_key.yaml", "STRATEGY.YAML_MERGE_KEY_FORBIDDEN"),
        ("duplicate_key.yaml", "STRATEGY.YAML_DUPLICATE_KEY"),
        ("two_documents.yaml", "STRATEGY.YAML_MULTIPLE_DOCUMENTS"),
        ("billion_laughs.yaml", "STRATEGY.YAML_EXPANSION_EXCEEDED"),
        ("deep_nesting.yaml", "STRATEGY.YAML_DEPTH_EXCEEDED"),
        ("recursive_alias.yaml", "STRATEGY.YAML_RECURSIVE_ALIAS"),
    ],
)
def test_an_adversarial_document_fails_at_the_yaml_boundary(
    name: str,
    expected: str,
) -> None:
    diagnostics = _fail(
        (_FIXTURES / "invalid" / name).read_bytes(),
        source_name=name,
    )
    assert {item.error_code for item in diagnostics} == {expected}


def test_a_yaml_stage_failure_preempts_every_later_stage() -> None:
    """Fail closed at the first stage: no model or graph diagnostic appears."""
    mapping = _valid_mapping()
    mapping["features"][0]["operation"] = "bogus.op/v1"
    corrupted = b"!!python/object:os.system " + _source(mapping)
    assert _codes(corrupted) == {"STRATEGY.YAML_FORBIDDEN_TAG"}


# --- Stage 2: strict model construction -----------------------------------


def test_an_unknown_field_is_rejected_with_the_unknown_field_code() -> None:
    mapping = _valid_mapping()
    mapping["unexpected_field"] = "value"
    assert _codes(_source(mapping)) == {"STRATEGY.UNKNOWN_FIELD"}


def test_a_missing_required_field_is_rejected_as_a_schema_defect() -> None:
    mapping = _valid_mapping()
    del mapping["sizing_intent"]
    assert _codes(_source(mapping)) == {"STRATEGY.SCHEMA_INVALID"}


def test_a_root_document_that_is_not_a_mapping_is_rejected() -> None:
    assert _codes(b"- one\n- two\n") == {"STRATEGY.SCHEMA_INVALID"}


def test_a_scalar_document_is_rejected() -> None:
    assert _codes(b"just_a_scalar\n") == {"STRATEGY.SCHEMA_INVALID"}


@pytest.mark.parametrize(
    ("field_name", "value", "expected"),
    [
        ("market_type", "FUTURES", "STRATEGY.POLICY_FORBIDDEN_MARKET"),
        ("direction", "SHORT", "STRATEGY.POLICY_FORBIDDEN_DIRECTION"),
    ],
)
def test_a_forbidden_policy_value_reports_its_closed_code(
    field_name: str,
    value: str,
    expected: str,
) -> None:
    mapping = _valid_mapping()
    mapping[field_name] = value
    assert _codes(_source(mapping)) == {expected}


def test_a_parameter_outside_its_declared_bounds_reports_its_closed_code() -> None:
    mapping = _valid_mapping()
    mapping["parameters"]["fast_period"]["minimum"] = 40
    assert _codes(_source(mapping)) == {"STRATEGY.PARAMETER_OUT_OF_BOUNDS"}


def test_a_contradictory_extension_declaration_reports_its_closed_code() -> None:
    mapping = _valid_mapping()
    mapping["engine_extensions"] = [
        {
            "adapter_name": "adapter.alpha",
            "extension_id": "ext.one",
            "version": "1.0.0",
            "content_hash": "1" * 64,
            "purpose": "Declares a lifecycle hook yet claims an economic effect.",
            "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
            "economic_effect": "PREVENTS_LEVEL_2",
        }
    ]
    assert _codes(_source(mapping)) == {"STRATEGY.EXTENSION_DECLARATION"}


def test_a_negative_bar_offset_reports_its_closed_code() -> None:
    mapping = _valid_mapping()
    mapping["entry_rules"][0]["expression"]["left"]["bars_ago"] = -1
    assert _codes(_source(mapping)) == {"STRATEGY.REFERENCE_NEGATIVE_OFFSET"}


def test_an_overly_deep_expression_reports_its_closed_code() -> None:
    mapping = _valid_mapping()
    # Twenty-five wrappers give an expression depth of twenty-six, past
    # `MAX_EXPRESSION_DEPTH = 24`, while the deepest YAML container sits at depth
    # twenty-nine, inside `MAX_EVENT_DEPTH = 32`. A deeper document would trip the
    # YAML bound first and prove nothing about the expression bound.
    node: dict[str, Any] = {"op": "ref", "id": "fast_sma", "bars_ago": 0}
    for _ in range(25):
        node = {"op": "not", "operand": node}
    mapping["entry_rules"][0]["expression"] = node
    assert _codes(_source(mapping)) == {"STRATEGY.EXPRESSION_DEPTH_EXCEEDED"}


def test_an_unknown_expression_operator_reports_its_closed_code() -> None:
    mapping = _valid_mapping()
    mapping["entry_rules"][0]["expression"] = {
        "op": "nonexistent_operator",
        "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
        "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
    }
    assert _codes(_source(mapping)) == {"STRATEGY.EXPRESSION_UNKNOWN_OP"}


def test_a_shrunken_collection_is_not_reported_beside_its_own_cause() -> None:
    """A rejected rule is discarded, so the tuple's `too_short` is derived noise."""
    mapping = _valid_mapping()
    mapping["entry_rules"][0]["expression"]["left"]["bars_ago"] = -1
    assert len(mapping["entry_rules"]) == 1
    diagnostics = _fail(_source(mapping))
    assert [item.error_code for item in diagnostics] == [
        "STRATEGY.REFERENCE_NEGATIVE_OFFSET"
    ]


def test_an_independent_length_defect_is_still_reported() -> None:
    """The cascade filter is narrow: a real emptiness defect survives it."""
    mapping = _valid_mapping()
    mapping["entry_rules"] = []
    assert _codes(_source(mapping)) == {"STRATEGY.SCHEMA_INVALID"}


def test_two_independent_defects_are_both_reported() -> None:
    mapping = _valid_mapping()
    mapping["market_type"] = "FUTURES"
    mapping["direction"] = "SHORT"
    assert _codes(_source(mapping)) == {
        "STRATEGY.POLICY_FORBIDDEN_DIRECTION",
        "STRATEGY.POLICY_FORBIDDEN_MARKET",
    }


def test_a_model_stage_failure_preempts_the_graph_stage() -> None:
    mapping = _valid_mapping()
    mapping["unexpected_field"] = "value"
    mapping["features"][0]["operation"] = "bogus.op/v1"
    assert _codes(_source(mapping)) == {"STRATEGY.UNKNOWN_FIELD"}


def test_a_model_diagnostic_names_only_a_closed_constraint_token() -> None:
    """No document byte reaches a model-boundary diagnostic."""
    mapping = _valid_mapping()
    mapping["a_very_distinctive_unknown_key"] = "a_very_distinctive_value"
    diagnostics = _fail(_source(mapping))
    encoded = canonical_json_bytes(diagnostics).decode("utf-8")
    assert "a_very_distinctive_unknown_key" not in encoded
    assert "a_very_distinctive_value" not in encoded
    assert [dict(item.details) for item in diagnostics] == [
        {"constraint": "extra_forbidden"}
    ]


def test_every_model_boundary_diagnostic_names_this_component() -> None:
    mapping = _valid_mapping()
    del mapping["sizing_intent"]
    for diagnostic in _fail(_source(mapping)):
        assert diagnostic.source_component == SOURCE_COMPONENT
        assert diagnostic.category is DiagnosticCategory.SCHEMA_VALIDATION
        assert diagnostic.retriable is False
        assert diagnostic.timestamp_utc == _OBSERVED_AT


def test_an_expression_depth_diagnostic_is_categorized_as_security() -> None:
    mapping = _valid_mapping()
    # Twenty-five wrappers give an expression depth of twenty-six, past
    # `MAX_EXPRESSION_DEPTH = 24`, while the deepest YAML container sits at depth
    # twenty-nine, inside `MAX_EVENT_DEPTH = 32`. A deeper document would trip the
    # YAML bound first and prove nothing about the expression bound.
    node: dict[str, Any] = {"op": "ref", "id": "fast_sma", "bars_ago": 0}
    for _ in range(25):
        node = {"op": "not", "operand": node}
    mapping["entry_rules"][0]["expression"] = node
    diagnostics = _fail(_source(mapping))
    assert [item.category for item in diagnostics] == [DiagnosticCategory.SECURITY]


def test_the_arity_code_is_reserved_and_deliberately_unemitted() -> None:
    """A wrong operand count is reported as a schema defect, not as an arity code.

    `STRATEGY.EXPRESSION_ARITY` is in section 5.9's closed table, but Stage 4 emits
    no diagnostic carrying it, on the same reserved footing as
    `STRATEGY.REFERENCE_FUTURE_BAR` (section 6.5.2). Detecting arity here would mean
    branching on `loc` structure to decide whether a `missing` or `extra_forbidden`
    error sits inside an expression; the plan requires no such mapping, and inventing
    one would put location-derived logic on the redaction boundary.
    """
    mapping = _valid_mapping()
    del mapping["entry_rules"][0]["expression"]["right"]
    assert _codes(_source(mapping)) == {"STRATEGY.SCHEMA_INVALID"}


# --- The model-boundary classification contract ----------------------------


def test_every_classifiable_code_carries_a_fixed_message() -> None:
    """No classification path can raise `KeyError` on the message table."""
    assert _MODEL_DECLARED_CODES <= set(_MESSAGES)
    assert set(_MESSAGES) == _MODEL_DECLARED_CODES | {
        "STRATEGY.SCHEMA_INVALID",
        "STRATEGY.UNKNOWN_FIELD",
        "STRATEGY.EXPRESSION_UNKNOWN_OP",
    }


def test_a_declared_code_is_recovered_from_the_original_exception() -> None:
    error: dict[str, object] = {
        "type": "value_error",
        "loc": ("market_type",),
        "msg": "Value error, STRATEGY.POLICY_FORBIDDEN_MARKET: accepts SPOT only",
        "ctx": {"error": ValueError("STRATEGY.POLICY_FORBIDDEN_MARKET: SPOT only")},
    }
    assert _classify(error) == ("STRATEGY.POLICY_FORBIDDEN_MARKET", {})


def test_a_declared_code_is_recovered_from_the_prefixed_message() -> None:
    """The `msg` fallback, reached whenever an error carries no context at all."""
    error: dict[str, object] = {
        "type": "value_error",
        "loc": ("direction",),
        "msg": "Value error, STRATEGY.POLICY_FORBIDDEN_DIRECTION: LONG only",
    }
    assert _classify(error) == ("STRATEGY.POLICY_FORBIDDEN_DIRECTION", {})


def test_a_context_without_an_exception_falls_back_to_the_message() -> None:
    error: dict[str, object] = {
        "type": "string_too_short",
        "loc": ("display_name",),
        "msg": "String should have at least 1 character",
        "ctx": {"min_length": 1},
    }
    assert _classify(error) == (
        "STRATEGY.SCHEMA_INVALID",
        {"constraint": "string_too_short"},
    )


def test_an_unrecognized_message_head_is_not_mistaken_for_a_closed_code() -> None:
    error: dict[str, object] = {
        "type": "value_error",
        "loc": (),
        "msg": "Value error, SOMETHING.ELSE: not a Stage 4 code",
    }
    assert _classify(error) == (
        "STRATEGY.SCHEMA_INVALID",
        {"constraint": "value_error"},
    )


def test_an_absent_error_type_classifies_as_a_schema_defect() -> None:
    """Defensive narrowing: `errors()` always supplies a type; nothing else may."""
    assert _classify({"loc": ()}) == ("STRATEGY.SCHEMA_INVALID", {"constraint": ""})


def test_an_absent_location_is_read_as_the_document_root() -> None:
    assert _location({"type": "missing"}) == ()
    assert _location({"type": "missing", "loc": ("a", 0)}) == ("a", 0)


def test_only_a_shrink_error_above_a_deeper_error_is_dropped() -> None:
    deeper: dict[str, object] = {"type": "value_error", "loc": ("entry_rules", 0, "id")}
    shrink: dict[str, object] = {"type": "too_short", "loc": ("entry_rules",)}
    assert _substantive([shrink, deeper]) == [deeper]


def test_a_shrink_error_with_nothing_beneath_it_is_kept() -> None:
    shrink: dict[str, object] = {"type": "too_short", "loc": ("entry_rules",)}
    elsewhere: dict[str, object] = {"type": "missing", "loc": ("sizing_intent",)}
    assert _substantive([shrink, elsewhere]) == [shrink, elsewhere]


def test_a_length_overflow_is_never_treated_as_a_shrink_cascade() -> None:
    """A discard can only shrink a collection, so `too_long` is always independent."""
    deeper: dict[str, object] = {"type": "value_error", "loc": ("features", 3, "id")}
    overflow: dict[str, object] = {"type": "too_long", "loc": ("features",)}
    assert _substantive([overflow, deeper]) == [overflow, deeper]


def test_a_sibling_error_does_not_absorb_a_shrink_error() -> None:
    """The test is on the location path, never on depth alone."""
    sibling: dict[str, object] = {"type": "value_error", "loc": ("exit_rules", 0, "id")}
    shrink: dict[str, object] = {"type": "too_short", "loc": ("entry_rules",)}
    assert _substantive([shrink, sibling]) == [shrink, sibling]


# --- Stages 3 and 4: static validation and the feature graph ---------------


def test_a_namespace_collision_never_produces_a_strategy_version() -> None:
    mapping = _valid_mapping()
    mapping["parameters"]["fast_sma"] = {"value_type": "INTEGER", "value": 3}
    diagnostics = _fail(_source(mapping))
    assert "STRATEGY.REFERENCE_NAMESPACE_COLLISION" in {
        item.error_code for item in diagnostics
    }


def test_an_unresolvable_reference_never_produces_a_strategy_version() -> None:
    mapping = _valid_mapping()
    mapping["entry_rules"][0]["expression"]["left"]["id"] = "absent_feature"
    assert "STRATEGY.REFERENCE_UNKNOWN" in _codes(_source(mapping))


def test_a_type_mismatch_never_produces_a_strategy_version() -> None:
    mapping = _valid_mapping()
    mapping["entry_rules"][0]["expression"] = {
        "op": "and",
        "operands": [{"op": "ref", "id": "fast_sma", "bars_ago": 0}],
    }
    assert "STRATEGY.EXPRESSION_TYPE_MISMATCH" in _codes(_source(mapping))


def test_a_cyclic_feature_graph_never_produces_a_strategy_version() -> None:
    diagnostics = _fail(
        (_FIXTURES / "invalid" / "feature_cycle.yaml").read_bytes(),
        source_name="feature_cycle.yaml",
    )
    assert "STRATEGY.FEATURE_CYCLE" in {item.error_code for item in diagnostics}


def test_an_unknown_feature_operation_never_produces_a_strategy_version() -> None:
    mapping = _valid_mapping()
    mapping["features"][0]["operation"] = "bogus.op/v1"
    assert "STRATEGY.FEATURE_UNKNOWN_OPERATION" in _codes(_source(mapping))


def test_a_declared_warm_up_that_is_too_small_never_produces_a_version() -> None:
    mapping = _valid_mapping()
    mapping["features"].append(
        {
            "id": "shifted",
            "operation": "shift/v1",
            "inputs": ["fast_sma"],
            "parameters": {"bars": "fast_period"},
            "output_type": "DECIMAL",
            "warm_up_bars": 0,
            "missing_value_policy": "PROPAGATE_FALSE",
        }
    )
    assert "STRATEGY.FEATURE_WARM_UP_TOO_SMALL" in _codes(_source(mapping))


# --- Determinism, ordering, and bounding ----------------------------------


def test_repeated_failures_over_equal_inputs_are_byte_identical() -> None:
    mapping = _valid_mapping()
    mapping["features"][0]["operation"] = "bogus.op/v1"
    source = _source(mapping)
    assert canonical_json_bytes(_fail(source)) == canonical_json_bytes(_fail(source))


def test_diagnostics_are_returned_in_a_deterministic_total_order() -> None:
    mapping = _valid_mapping()
    mapping["features"][0]["operation"] = "bogus.op/v1"
    mapping["features"][1]["operation"] = "other.op/v1"
    diagnostics = _fail(_source(mapping))
    keys = [
        (item.error_code, item.source_component, canonical_json_bytes(item.details))
        for item in diagnostics
    ]
    assert keys == sorted(keys)


def test_an_overflowing_defect_count_is_bounded_and_marked() -> None:
    mapping = _valid_mapping()
    mapping["features"].extend(
        {
            "id": f"bogus{index:03d}",
            "operation": "bogus.op/v1",
            "inputs": ["absent_input"],
            "parameters": {},
            "output_type": "DECIMAL",
            "warm_up_bars": 0,
            "missing_value_policy": "PROPAGATE_FALSE",
        }
        for index in range(200)
    )
    diagnostics = _fail(_source(mapping))
    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS
    assert diagnostics[-1].error_code == _LIMIT_REACHED
    assert [item.error_code for item in diagnostics[:-1]].count(_LIMIT_REACHED) == 0


def test_no_invalid_document_raises_out_of_the_loader() -> None:
    """Result-only failure signalling across every committed invalid fixture."""
    directory = _FIXTURES / "invalid"
    names = sorted(item.name for item in directory.iterdir())
    assert len(names) == 9
    for name in names:
        outcome = _load((directory / name).read_bytes(), source_name=name)
        assert isinstance(outcome, Failure), name
        assert len(outcome.diagnostics) >= 1


# --- Preventive safety checks (green from the first run) -------------------

_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "importlib",
        "io",
        "os",
        "pathlib",
        "random",
        "secrets",
        "shutil",
        "socket",
        "subprocess",
        "tempfile",
        "time",
        "urllib",
        "uuid",
        "winreg",
    }
)
_FORBIDDEN_CALL_NAMES = frozenset(
    {
        "__dict__",
        "__import__",
        "compile",
        "eval",
        "exec",
        "getattr",
        "import_module",
        "now",
        "open",
        "setattr",
        "today",
        "utcnow",
        "uuid1",
        "uuid4",
        "vars",
    }
)


@pytest.mark.parametrize("module_name", ["loader.py", "versioning.py"])
def test_the_module_imports_no_ambient_or_dynamic_capability(module_name: str) -> None:
    """Preventive, and green from its first run: nothing here to regress yet."""
    tree = ast.parse((_SOURCE_ROOT / module_name).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.split(".")[0])
    assert roots & _FORBIDDEN_IMPORT_ROOTS == set()


@pytest.mark.parametrize("module_name", ["loader.py", "versioning.py"])
def test_the_module_names_no_dynamic_execution_or_clock_helper(
    module_name: str,
) -> None:
    """Preventive. `datetime` is imported for typing only; `now` is never named.

    Defence in depth, and deliberately not claimed as airtight: an independent review
    showed that reflection defeats it — `datetime.__dict__["n" + "ow"](...)` names no
    banned identifier and passes this scan. `__dict__` and `vars` are banned above to
    close that exact spelling, but a determined rewrite could still evade an AST
    check. The primary control is behavioural, not syntactic: `created_at_utc` and
    `observed_at_utc` are proven equal to the caller's explicit argument, and two
    independent loads of equal bytes are proven byte-identical. Those tests killed the
    reflection mutation when this scan did not.
    """
    tree = ast.parse((_SOURCE_ROOT / module_name).read_text(encoding="utf-8"))
    named: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            named.add(node.id)
        if isinstance(node, ast.Attribute):
            named.add(node.attr)
    assert named & _FORBIDDEN_CALL_NAMES == set()


def test_the_loader_imports_no_yaml_surface_of_its_own() -> None:
    """Only `strategy/yaml_source.py` may import `yaml`."""
    tree = ast.parse((_SOURCE_ROOT / "loader.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "yaml" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "yaml"


def test_loading_a_strategy_with_extensions_imports_no_extension_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preventive: declarations are stored and hashed, never resolved or executed."""

    def _refuse(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("the core must never import an extension module")

    monkeypatch.setattr(importlib, "import_module", _refuse)
    mapping = _valid_mapping()
    mapping["engine_extensions"] = [
        {
            "adapter_name": "adapter.alpha",
            "extension_id": "ext.one",
            "version": "1.0.0",
            "content_hash": "1" * 64,
            "purpose": "Adds a declared lifecycle hook only.",
            "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
            "economic_effect": "NONE",
        }
    ]
    before = frozenset(sys.modules)
    version = _succeed(_source(mapping))
    added = frozenset(sys.modules) - before
    assert version.extension_hashes == ("1" * 64,)
    assert not any(
        fragment in name
        for name in added
        for fragment in ("adapter", "alpha", "ext", "extension")
    )


def test_a_declared_extension_changes_the_loaded_content_hash() -> None:
    mapping = _valid_mapping()
    without = _succeed(_source(mapping))
    mapping["engine_extensions"] = [
        {
            "adapter_name": "adapter.alpha",
            "extension_id": "ext.one",
            "version": "1.0.0",
            "content_hash": "1" * 64,
            "purpose": "Adds a declared lifecycle hook only.",
            "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
            "economic_effect": "NONE",
        }
    ]
    with_one = _succeed(_source(mapping))
    assert with_one.content_hash != without.content_hash
    assert with_one.extension_hashes == ("1" * 64,)


def test_the_loader_exposes_no_path_loading_convenience() -> None:
    """Bytes only: a path-accepting entry point would reintroduce filesystem reach."""
    public = {name for name in vars(StrategyLoader) if not name.startswith("_")}
    assert public == {"load"}


# --- Deep immutability of the loader-produced record ------------------------

_FORBIDDEN_MATERIAL_TYPES = (dict, list, set, bytearray)
# Excluded because it is explicitly outside the section 5.5 identity payload.
_NON_MATERIAL_FIELDS = frozenset({"source_provenance"})


def _material_violations(value: object, path: str) -> list[str]:
    """Walk the material graph, reporting a readable path for each mutable find.

    `dict` is tested before `Mapping` because every `dict` *is* a `Mapping`; the
    point of the audit is that only the immutable ones survive. Only public
    values are traversed -- `model_fields` names and attribute access -- never
    Pydantic's private state.
    """
    if isinstance(value, _FORBIDDEN_MATERIAL_TYPES):
        return [f"{path}: {type(value).__name__}"]

    found: list[str] = []
    if isinstance(value, CanonicalModel):
        for name in type(value).model_fields:
            if name in _NON_MATERIAL_FIELDS:
                continue
            found.extend(_material_violations(getattr(value, name), f"{path}.{name}"))
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            found.extend(_material_violations(key, f"{path}<key {key!r}>"))
            found.extend(_material_violations(nested, f"{path}[{key!r}]"))
    elif isinstance(value, tuple | frozenset):
        for index, item in enumerate(value):
            found.extend(_material_violations(item, f"{path}[{index}]"))
    return found


def _reachable_mappings(value: object, path: str) -> list[tuple[str, object]]:
    """Collect every `Mapping` the audit reaches, so the audit is provably alive."""
    found: list[tuple[str, object]] = []
    if isinstance(value, CanonicalModel):
        for name in type(value).model_fields:
            if name in _NON_MATERIAL_FIELDS:
                continue
            found.extend(_reachable_mappings(getattr(value, name), f"{path}.{name}"))
    elif isinstance(value, Mapping):
        found.append((path, value))
        for key, nested in value.items():
            found.extend(_reachable_mappings(nested, f"{path}[{key!r}]"))
    elif isinstance(value, tuple | frozenset):
        for index, item in enumerate(value):
            found.extend(_reachable_mappings(item, f"{path}[{index}]"))
    return found


def test_the_material_graph_holds_no_mutable_container() -> None:
    """One recursive audit over everything the content hash is computed from."""
    version = _succeed(_valid_bytes())

    assert _material_violations(version, "StrategyVersion") == []


def test_the_audit_actually_reaches_both_parameter_mappings() -> None:
    """A vacuous audit would also report zero violations, so prove it is alive."""
    version = _succeed(_valid_bytes())

    reached = _reachable_mappings(version, "StrategyVersion")
    paths = [path for path, _ in reached]

    assert "StrategyVersion.strategy_spec.parameters" in paths
    assert "StrategyVersion.strategy_spec.features[0].parameters" in paths
    assert "StrategyVersion.strategy_spec.features[1].parameters" in paths
    for path, mapping in reached:
        assert not isinstance(mapping, dict), path
        assert isinstance(mapping, Mapping), path


def test_the_loader_produced_record_exposes_both_mappings_immutably() -> None:
    version = _succeed(_valid_bytes())
    spec = version.strategy_spec
    recorded = version.content_hash

    # Deliberately a second, independent implementation of the mutation sweep in
    # `test_strategy_models.py::_assert_mapping_is_immutable`, rather than a
    # shared helper: this module's subject is the *loader-produced* record, and
    # importing a helper across test modules would let one edit silently weaken
    # both. The typing differs for a concrete reason -- `Mapping[str, Any]`
    # rather than the two exact value types, because a union of the two would
    # defeat the targeted suppressions below.
    cases: tuple[tuple[Mapping[str, Any], str], ...] = (
        (spec.parameters, "fast_period"),
        (spec.features[0].parameters, "period"),
    )
    for mapping, present in cases:
        before = dict(mapping)
        # The suppressions are the point rather than a workaround: static typing
        # already forbids these two lines, and the assertions prove the runtime
        # agrees instead of silently permitting them.
        with pytest.raises(TypeError):
            mapping[present] = next(iter(mapping.values()))  # type: ignore[index]
        with pytest.raises(TypeError):
            del mapping[present]  # type: ignore[attr-defined]
        for name, arguments in (
            ("clear", ()),
            ("popitem", ()),
            ("update", ({"injected": "x"},)),
            ("setdefault", ("injected", "x")),
            ("pop", (present,)),
        ):
            with pytest.raises((AttributeError, TypeError)):
                getattr(mapping, name)(*arguments)
        assert dict(mapping) == before

    # The recorded identity is still the identity of the current content after
    # every failed attempt -- the point of the correction.
    assert version.content_hash == recorded
    assert version.content_hash == strategy_version_hash(spec)


def test_the_loader_hands_the_model_canonically_sorted_mapping_keys() -> None:
    """Author-declared mapping order is *not* preserved end to end.

    `StrategyLoader.load` validates from `canonical_json_bytes(...)`, and
    `canonical_json_text` passes `sort_keys=True`, so the model receives keys
    already sorted. `bar_offsets.valid.yaml` declares `shift_zero` first, which
    makes the difference observable.

    Pinned because plan section 5.5.1 requires that the freeze itself introduce
    no reordering, and it would be easy to misread that as a promise that
    authored order survives a load. It does not, and no hash depends on it.
    """
    name = "bar_offsets.valid.yaml"
    declared = tuple(_document_parameters(name))
    version = _succeed((_FIXTURES / name).read_bytes(), source_name=name)

    loaded = tuple(version.strategy_spec.parameters)

    assert declared == ("shift_zero", "shift_one", "shift_two")
    assert loaded == tuple(sorted(declared))
    assert loaded != declared


def _document_parameters(name: str) -> dict[str, Any]:
    outcome = load_yaml_document((_FIXTURES / name).read_bytes(), name, _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome
    document = outcome.value.value
    assert isinstance(document, dict)
    parameters = document["parameters"]
    assert isinstance(parameters, dict)
    return parameters


_GOLDEN_CONTENT_HASHES = {
    "adjacent_entry_exit.valid.yaml": (
        "8b81dbf4494601af4066e81afcca08cd3d368abeba6314c0003ddbb42a06abbb"
    ),
    "bar_offsets.valid.yaml": (
        "e75c3148df232dd5fa29d9737d3bf3d7cc06a36fa9e75db41a26053d49697095"
    ),
    "crossover_equality.valid.yaml": (
        "84544ac5e658c6f63e9b47e9f42c6e5fd091d1666e1e0fb6739f6a9154347100"
    ),
    "decimal_rounding.valid.yaml": (
        "1cb08a6889c1221252cef7626e7cc59e2a413c92f9b190a827e4ba65f259169b"
    ),
    "missing_input.valid.yaml": (
        "a84031fd1cc5e4a96c598e9b23c6a610443ceba54c050d6c00ab284840ac6899"
    ),
    "sma_cross_long.valid.yaml": (
        "14f59d879338f36a91f639e932567dba35cc17b835cfb16d7a4362c05b23c29e"
    ),
    "warm_up_boundary.valid.yaml": (
        "96bb8aafe175f5c99091bc7d0ad5f1f31b0b2cec947bc714e6e6e0ed83cd94a7"
    ),
}


@pytest.mark.parametrize("name", sorted(_GOLDEN_CONTENT_HASHES))
def test_the_committed_fixture_content_hashes_are_unchanged(name: str) -> None:
    """Literal golden identities, so a hash change can never pass unnoticed.

    Every other hash test here is relational — this variant equals that one, this
    field is material — so a change that shifted *every* strategy identity
    together would satisfy all of them. Plan section 5.5.1 item 12 requires the
    deep-immutability correction to leave canonical bytes untouched, and these
    seven values were confirmed identical against the pre-correction `models.py`
    at `c6fdecb` before being pinned here.
    """
    version = _succeed((_FIXTURES / name).read_bytes(), source_name=name)

    assert version.content_hash == _GOLDEN_CONTENT_HASHES[name]
