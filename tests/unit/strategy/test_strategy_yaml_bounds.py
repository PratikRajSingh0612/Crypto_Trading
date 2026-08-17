"""Test every project-owned builder bound of plan sections 5.3, 5.3.1, 5.3.2.

``MAX_EXPRESSION_DEPTH`` is deliberately absent: section 5.3 marks it a
post-parse bound on the validated ``Expression`` tree, not a builder ceiling, so
it is pinned in ``test_strategy_expressions.py`` instead.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from crypto_lab.domain.results import Failure, Success
from crypto_lab.strategy import yaml_source
from crypto_lab.strategy.yaml_source import (
    MAX_ALIAS_REFERENCES,
    MAX_ANCHORS,
    MAX_COLLECTION_ENTRIES,
    MAX_EVENT_COUNT,
    MAX_EVENT_DEPTH,
    MAX_EXPANDED_DEPTH,
    MAX_EXPANDED_NODES,
    MAX_INTEGER_VALUE,
    MAX_SCALAR_CHARACTERS,
    MAX_SOURCE_BYTES,
    MIN_INTEGER_VALUE,
    StrictStrategySafeLoader,
    YamlDocument,
    load_yaml_document,
)

_OBSERVED_AT = datetime(2026, 8, 16, tzinfo=UTC)
_NAME = "bounds.yaml"
_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"

_Loaded = Success[YamlDocument] | Failure


class _Sentinel:
    """A stand-in for an event kind the classifier does not handle.

    Deliberately **not** a ``yaml.Event`` subclass: creating one would enter
    ``yaml.events.Event.__subclasses__()`` for the rest of the session and break
    the leaf-class exhaustiveness assertion in the loader test module.
    """

    start_mark: None = None


def _load(source: bytes, name: str = _NAME) -> _Loaded:
    return load_yaml_document(source, name, _OBSERVED_AT)


def _codes(result: _Loaded) -> tuple[str, ...]:
    assert isinstance(result, Failure)
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def _mapping(result: _Loaded) -> dict[str, Any]:
    assert isinstance(result, Success), _codes(result)
    value = result.value.value
    assert isinstance(value, dict)
    return value


def _fixture(relative: str) -> bytes:
    return (_FIXTURES / relative).read_bytes()


def _event_count(source: bytes) -> int:
    """Count the real event stream, independently of the loader's own pass."""
    text = source.decode("utf-8")
    return sum(1 for _ in yaml.parse(text, Loader=StrictStrategySafeLoader))


# --- MAX_SOURCE_BYTES -------------------------------------------------------


def test_a_source_at_exactly_the_byte_ceiling_is_accepted() -> None:
    # Blank lines produce no event and no scalar, so the padding exercises the
    # byte ceiling alone rather than the scalar or collection ceilings.
    body = b"k: 1\n"
    source = body + b"\n" * (MAX_SOURCE_BYTES - len(body))

    assert len(source) == MAX_SOURCE_BYTES
    assert _mapping(_load(source)) == {"k": 1}


def test_one_byte_over_the_source_ceiling_is_rejected() -> None:
    body = b"k: 1\n"
    source = body + b"\n" * (MAX_SOURCE_BYTES + 1 - len(body))

    assert len(source) == MAX_SOURCE_BYTES + 1
    assert _codes(_load(source)) == ("STRATEGY.SOURCE_TOO_LARGE",)


# --- MAX_SCALAR_CHARACTERS --------------------------------------------------


def test_a_scalar_at_exactly_the_character_ceiling_is_accepted() -> None:
    text = "a" * MAX_SCALAR_CHARACTERS

    assert _mapping(_load(f"k: {text}\n".encode())) == {"k": text}


def test_one_character_over_the_scalar_ceiling_is_rejected() -> None:
    text = "a" * (MAX_SCALAR_CHARACTERS + 1)

    assert _codes(_load(f"k: {text}\n".encode())) == ("STRATEGY.YAML_SCALAR_TOO_LONG",)


# --- MAX_COLLECTION_ENTRIES, at both enforcement sites ----------------------


def test_a_mapping_at_exactly_the_entry_ceiling_is_accepted() -> None:
    source = "".join(f"k{index}: 1\n" for index in range(MAX_COLLECTION_ENTRIES))

    assert len(_mapping(_load(source.encode()))) == MAX_COLLECTION_ENTRIES


def test_one_mapping_entry_over_the_ceiling_is_rejected() -> None:
    source = "".join(f"k{index}: 1\n" for index in range(MAX_COLLECTION_ENTRIES + 1))

    assert _codes(_load(source.encode())) == ("STRATEGY.YAML_COLLECTION_TOO_LARGE",)


def test_one_sequence_entry_over_the_ceiling_is_rejected() -> None:
    items = ", ".join(str(index) for index in range(MAX_COLLECTION_ENTRIES + 1))

    assert _codes(_load(f"k: [{items}]\n".encode())) == (
        "STRATEGY.YAML_COLLECTION_TOO_LARGE",
    )


# --- MAX_EVENT_DEPTH --------------------------------------------------------


def test_nesting_at_exactly_the_event_depth_ceiling_is_accepted() -> None:
    source = f"{'[' * MAX_EVENT_DEPTH}{']' * MAX_EVENT_DEPTH}\n".encode()
    result = _load(source)

    assert isinstance(result, Success), _codes(result)


def test_one_level_over_the_event_depth_ceiling_is_rejected() -> None:
    depth = MAX_EVENT_DEPTH + 1
    source = f"{'[' * depth}{']' * depth}\n".encode()

    assert _codes(_load(source)) == ("STRATEGY.YAML_DEPTH_EXCEEDED",)


def test_the_deep_nesting_fixture_is_rejected() -> None:
    assert _codes(_load(_fixture("invalid/deep_nesting.yaml"))) == (
        "STRATEGY.YAML_DEPTH_EXCEEDED",
    )


def test_a_pathologically_deep_stream_returns_a_failure_without_recursing() -> None:
    """PyYAML's scanner and parser are non-recursive, and so is the builder."""
    depth = 1_000
    source = f"{'[' * depth}{']' * depth}\n".encode()

    assert _codes(_load(source)) == ("STRATEGY.YAML_DEPTH_EXCEEDED",)


# --- MAX_EXPANDED_DEPTH, independently of MAX_EVENT_DEPTH -------------------

_ANCHOR_DEPTH = 20
_REFERENCE_DEPTH = 14


def test_expanded_depth_is_rejected_while_event_depth_stays_inside_its_bound() -> None:
    anchored = "[" * _ANCHOR_DEPTH + "]" * _ANCHOR_DEPTH
    referencing = "[" * _REFERENCE_DEPTH + "*deep" + "]" * _REFERENCE_DEPTH
    source = f"a: &deep {anchored}\nb: {referencing}\n".encode()

    # Raw event depth peaks at 1 + 20 while defining the anchor and 1 + 14 at
    # the alias, both inside MAX_EVENT_DEPTH; splicing the recorded value adds
    # 20 further levels, which only the expanded counter sees.
    assert 1 + _ANCHOR_DEPTH <= MAX_EVENT_DEPTH
    assert 1 + _REFERENCE_DEPTH <= MAX_EVENT_DEPTH
    assert 1 + _REFERENCE_DEPTH + _ANCHOR_DEPTH > MAX_EXPANDED_DEPTH
    assert _codes(_load(source)) == ("STRATEGY.YAML_DEPTH_EXCEEDED",)


# --- MAX_EVENT_COUNT --------------------------------------------------------


def test_a_stream_over_the_event_ceiling_is_rejected() -> None:
    groups = 400
    per_group = 48
    inner = "[" + ", ".join("1" for _ in range(per_group)) + "]"
    source = f"[{', '.join(inner for _ in range(groups))}]\n".encode()

    assert groups <= MAX_COLLECTION_ENTRIES
    assert per_group <= MAX_COLLECTION_ENTRIES
    assert len(source) <= MAX_SOURCE_BYTES
    assert _event_count(source) > MAX_EVENT_COUNT
    assert _codes(_load(source)) == ("STRATEGY.YAML_EVENT_BUDGET_EXCEEDED",)


# --- MAX_ANCHORS ------------------------------------------------------------


def test_anchor_definitions_at_exactly_the_ceiling_are_accepted() -> None:
    source = "".join(f"k{index}: &a{index} {index}\n" for index in range(MAX_ANCHORS))
    result = _load(source.encode())

    assert isinstance(result, Success), _codes(result)


def test_one_anchor_definition_over_the_ceiling_is_rejected() -> None:
    source = "".join(
        f"k{index}: &a{index} {index}\n" for index in range(MAX_ANCHORS + 1)
    )

    assert _codes(_load(source.encode())) == ("STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED",)


# --- MAX_ALIAS_REFERENCES ---------------------------------------------------


def test_alias_references_at_exactly_the_ceiling_are_accepted() -> None:
    references = ", ".join("*x" for _ in range(MAX_ALIAS_REFERENCES))
    source = f"a: &x 1\nb: [{references}]\n".encode()
    result = _load(source)

    assert isinstance(result, Success), _codes(result)


def test_one_alias_reference_over_the_ceiling_is_rejected() -> None:
    references = ", ".join("*x" for _ in range(MAX_ALIAS_REFERENCES + 1))
    source = f"a: &x 1\nb: [{references}]\n".encode()

    assert MAX_ALIAS_REFERENCES + 1 <= MAX_COLLECTION_ENTRIES
    assert _codes(_load(source)) == ("STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED",)


# --- MAX_EXPANDED_NODES and the nested bomb ---------------------------------


def test_the_nested_alias_bomb_is_rejected() -> None:
    assert _codes(_load(_fixture("invalid/billion_laughs.yaml"))) == (
        "STRATEGY.YAML_EXPANSION_EXCEEDED",
    )


def test_the_bomb_stays_inside_every_raw_ceiling_it_is_designed_to_evade() -> None:
    """A flat bomb would pass a non-transitive implementation; this one is nested."""
    source = _fixture("invalid/billion_laughs.yaml")
    events = list(yaml.parse(source.decode("utf-8"), Loader=StrictStrategySafeLoader))
    aliases = [event for event in events if isinstance(event, yaml.AliasEvent)]
    definitions = [
        event
        for event in events
        if not isinstance(event, yaml.AliasEvent)
        and getattr(event, "anchor", None) is not None
    ]

    depth = 0
    peak = 0
    for event in events:
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            peak = max(peak, depth)
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1

    assert len(aliases) == 81
    assert len(definitions) == 10
    assert peak == 2
    assert len(source) <= MAX_SOURCE_BYTES
    assert len(events) <= MAX_EVENT_COUNT
    assert len(aliases) <= MAX_ALIAS_REFERENCES
    assert len(definitions) <= MAX_ANCHORS
    assert peak <= MAX_EVENT_DEPTH


def test_transitive_alias_accounting_is_exact() -> None:
    """The exact hand-computed accounting proof of plan section 5.3.1.

    Describing the accounting is not enough: an off-by-one here stays invisible
    until the bomb fixture silently stops failing.
    """
    text = "a: &x [1, 2]\nb: *x\n"
    budget = yaml_source._Budget()
    events = yaml.parse(text, Loader=StrictStrategySafeLoader)
    with contextlib.closing(events):
        value = yaml_source._build_from_events(iter(events), budget)

    assert value == {"a": [1, 2], "b": [1, 2]}
    assert budget.expanded == 9
    assert budget.expanded_size == {"x": 3}
    assert budget.alias_references == 1
    assert budget.anchor_definitions == 1
    assert budget.open_frames == []
    assert budget.expanded <= MAX_EXPANDED_NODES


def test_the_bomb_is_rejected_before_the_stream_is_consumed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove mid-stream rejection by instrumentation, not by absence.

    Asserting that ``yaml.load`` and friends are never called proves nothing
    here: they are never called for any input, so such an assertion holds
    equally for an implementation that collects every event into a list first.
    """
    source = _fixture("invalid/billion_laughs.yaml")
    total = _event_count(source)
    consumed: list[object] = []
    reached_end: list[bool] = []
    generators: dict[str, Any] = {}
    real_parse: Any = yaml.parse

    def counting_parse(stream: Any, Loader: Any) -> Iterator[Any]:
        inner = real_parse(stream, Loader=Loader)

        def wrapper() -> Iterator[Any]:
            try:
                for event in inner:
                    consumed.append(event)
                    yield event
                reached_end.append(True)
                yield _Sentinel()
            finally:
                # Closing the wrapper must reach PyYAML's own ``finally``, which
                # is where ``Loader.dispose()`` runs.
                inner.close()

        generator = wrapper()
        generators["inner"] = inner
        generators["outer"] = generator
        return generator

    monkeypatch.setattr(yaml, "parse", counting_parse)
    result = _load(source)

    assert _codes(result) == ("STRATEGY.YAML_EXPANSION_EXCEEDED",)
    assert 0 < len(consumed) < total
    assert not reached_end
    assert generators["outer"].gi_frame is None
    assert generators["inner"].gi_frame is None


def test_a_clean_parse_follows_a_failed_bomb_parse() -> None:
    valid = b"k: 1\n"
    alone = _load(valid)
    rejected = _load(_fixture("invalid/billion_laughs.yaml"))
    after_failure = _load(valid)

    assert _codes(rejected) == ("STRATEGY.YAML_EXPANSION_EXCEEDED",)
    assert isinstance(alone, Success)
    assert isinstance(after_failure, Success)
    assert after_failure.value == alone.value


# --- Recursive, unknown, and open aliases -----------------------------------


def test_the_recursive_alias_fixture_is_rejected() -> None:
    assert _codes(_load(_fixture("invalid/recursive_alias.yaml"))) == (
        "STRATEGY.YAML_RECURSIVE_ALIAS",
    )


@pytest.mark.parametrize(
    "source",
    [
        b"a: &loop [*loop]\n",
        b"a: &loop {k: *loop}\n",
        b"a: &outer [[*outer]]\n",
        b"a: *never_defined\n",
    ],
)
def test_recursive_and_unknown_aliases_are_rejected(source: bytes) -> None:
    """Rejecting an open anchor makes a cyclic value structurally impossible."""
    assert _codes(_load(source)) == ("STRATEGY.YAML_RECURSIVE_ALIAS",)


def test_an_accepted_document_is_a_finite_acyclic_tree() -> None:
    result = _load(b"a: &x [1, 2]\nb: *x\n")
    mapping = _mapping(result)

    assert mapping == {"a": [1, 2], "b": [1, 2]}
    assert mapping["a"] is not mapping["b"]


def test_an_anchored_mapping_is_spliced_by_deep_copy() -> None:
    """The expanded-depth measurement must walk mapping values, not lists alone.

    Keys avoid single letters: bare ``y`` and ``n`` are rejected boolean aliases.
    """
    mapping = _mapping(_load(b"a: &m {xx: {zz: 1}}\nb: *m\n"))

    assert mapping == {"a": {"xx": {"zz": 1}}, "b": {"xx": {"zz": 1}}}
    assert mapping["a"] is not mapping["b"]


def test_an_anchored_mapping_key_records_a_unit_cost() -> None:
    """A key scalar may carry an anchor, and an anchored scalar records cost 1."""
    text = "&kk name: 1\nalias: *kk\n"
    budget = yaml_source._Budget()
    events = yaml.parse(text, Loader=StrictStrategySafeLoader)
    with contextlib.closing(events):
        value = yaml_source._build_from_events(iter(events), budget)

    assert value == {"name": 1, "alias": "name"}
    assert budget.expanded_size == {"kk": 1}
    assert budget.anchor_definitions == 1


# --- Anchor redefinition ----------------------------------------------------


def test_a_sequentially_redefined_anchor_is_rejected() -> None:
    """Preventive: a closed anchor is already recorded, so this begins green."""
    assert _codes(_load(b"a: &x 1\nb: &x 2\n")) == ("STRATEGY.YAML_ANCHOR_REDEFINED",)


@pytest.mark.parametrize(
    "source",
    [
        b"a: &x [&x 1]\n",
        b"a: &x {k: &x 1}\n",
        b"a: &x [[&x 1]]\n",
    ],
)
def test_an_anchor_redefined_while_its_own_node_is_open_is_rejected(
    source: bytes,
) -> None:
    """``MAX_ANCHORS`` counts definitions, so a name cannot be redefined at all.

    A name whose node is still open has no recorded expanded size yet, so a
    completed-anchor lookup cannot see the collision.
    """
    assert _codes(_load(source)) == ("STRATEGY.YAML_ANCHOR_REDEFINED",)


# --- Documents --------------------------------------------------------------


@pytest.mark.parametrize("source", [b"", b"# only a comment\n", b"\n\n\n"])
def test_a_stream_without_a_document_is_rejected(source: bytes) -> None:
    assert _codes(_load(source)) == ("STRATEGY.YAML_EMPTY_DOCUMENT",)


def test_every_strategy_fixture_is_utf8_with_lf_endings() -> None:
    """Plan section 6.5, made executable because no other gate observes it.

    Ruff does not lint YAML, ``git diff --check`` inspects trailing whitespace
    rather than line endings, and PyYAML accepts CRLF, so a stray carriage
    return would survive every other check while silently changing the
    ``source_bytes_sha256`` and ``source_byte_length`` Task 5 records.
    """
    fixtures = sorted(_FIXTURES.rglob("*.yaml"))

    assert fixtures
    for path in fixtures:
        assert b"\r" not in path.read_bytes(), path.name
        assert path.read_text(encoding="utf-8")


def test_the_two_documents_fixture_is_rejected() -> None:
    assert _codes(_load(_fixture("invalid/two_documents.yaml"))) == (
        "STRATEGY.YAML_MULTIPLE_DOCUMENTS",
    )


# --- Integer value bounds ---------------------------------------------------


def test_the_minimum_signed_64_bit_integer_is_accepted() -> None:
    assert _mapping(_load(f"k: {MIN_INTEGER_VALUE}\n".encode())) == {
        "k": MIN_INTEGER_VALUE,
    }


@pytest.mark.parametrize(
    "value",
    [MIN_INTEGER_VALUE - 1, MAX_INTEGER_VALUE + 1],
)
def test_an_integer_outside_the_signed_64_bit_range_is_rejected(value: int) -> None:
    assert _codes(_load(f"k: {value}\n".encode())) == (
        "STRATEGY.YAML_INTEGER_OUT_OF_RANGE",
    )


# --- Fail-closed dispatch ---------------------------------------------------


def test_an_unhandled_event_kind_returns_a_failure_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An event kind a future PyYAML release adds must fail closed."""
    real_parse: Any = yaml.parse

    def parse_with_intruder(stream: Any, Loader: Any) -> Iterator[Any]:
        yield from real_parse(stream, Loader=Loader)
        yield _Sentinel()

    monkeypatch.setattr(yaml, "parse", parse_with_intruder)

    assert _codes(_load(b"k: 1\n")) == ("STRATEGY.YAML_SYNTAX",)


def test_a_value_event_after_the_document_ends_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: PyYAML always emits a document start before content.

    The parser returns to ``parse_document_start`` after a document end, so no
    authored source can reach this branch; an injected stream can, and must be
    rejected rather than silently appended to the finished document.
    """
    real_parse: Any = yaml.parse

    def parse_with_trailing_value(stream: Any, Loader: Any) -> Iterator[Any]:
        for event in real_parse(stream, Loader=Loader):
            yield event
            if isinstance(event, yaml.DocumentEndEvent):
                yield yaml.ScalarEvent(None, None, (True, False), "extra")

    monkeypatch.setattr(yaml, "parse", parse_with_trailing_value)

    assert _codes(_load(b"k: 1\n")) == ("STRATEGY.YAML_MULTIPLE_DOCUMENTS",)


# --- Deterministic, bounded, non-leaking diagnostics ------------------------


def test_two_runs_over_equal_input_produce_byte_identical_failures() -> None:
    source = _fixture("invalid/billion_laughs.yaml")
    first = _load(source)
    second = _load(source)

    assert isinstance(first, Failure)
    assert isinstance(second, Failure)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.diagnostics[0].diagnostic_id == second.diagnostics[0].diagnostic_id


def test_a_bound_failure_carries_only_bounded_integer_marks() -> None:
    depth = MAX_EVENT_DEPTH + 1
    result = _load(f"{'[' * depth}{']' * depth}\n".encode())

    assert isinstance(result, Failure)
    diagnostic = result.diagnostics[0]
    assert diagnostic.details == {"line": 1, "column": depth}
    assert diagnostic.category.value in {"SECURITY", "SCHEMA_VALIDATION"}


def test_a_bound_failure_leaks_no_document_token() -> None:
    marker = "distinctive_zz"
    result = _load(f"k: {marker}{'a' * MAX_SCALAR_CHARACTERS}\n".encode())

    assert _codes(result) == ("STRATEGY.YAML_SCALAR_TOO_LONG",)
    assert isinstance(result, Failure)
    assert marker not in result.model_dump_json()
