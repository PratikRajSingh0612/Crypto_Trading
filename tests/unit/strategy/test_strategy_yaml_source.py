"""Test the safe YAML loading contract of plan sections 5.2, 5.2.1 to 5.2.3."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.diagnostics import MAX_DETAIL_STRING
from crypto_lab.domain.results import Failure, Success
from crypto_lab.strategy.yaml_source import (
    _MESSAGES,
    _SECURITY_CODES,
    MAX_SCALAR_CHARACTERS,
    SourceName,
    StrictStrategySafeLoader,
    YamlDocument,
    YamlValue,
    load_yaml_document,
)

_OBSERVED_AT = datetime(2026, 8, 16, tzinfo=UTC)
_NAME = "strategy.yaml"
_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"

_Loaded = Success[YamlDocument] | Failure


def _load(source: object, name: str = _NAME) -> _Loaded:
    return load_yaml_document(source, name, _OBSERVED_AT)  # type: ignore[arg-type]


def _codes(result: _Loaded) -> tuple[str, ...]:
    assert isinstance(result, Failure)
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def _value(source: bytes) -> dict[str, YamlValue]:
    result = _load(source)
    assert isinstance(result, Success), _codes(result)
    value = result.value.value
    assert isinstance(value, dict)
    return value


def _scalar(text: str) -> YamlValue:
    """Return the classified value of one document scalar."""
    return _value(f"k: {text}\n".encode())["k"]


def _scalar_code(text: str) -> tuple[str, ...]:
    return _codes(_load(f"k: {text}\n".encode()))


def _fixture(relative: str) -> bytes:
    return (_FIXTURES / relative).read_bytes()


# --- Section 5.2 entry-point contract -------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "a: 1\n",
        Path("strategy.yaml"),
        io.StringIO("a: 1\n"),
        io.BytesIO(b"a: 1\n"),
    ],
)
def test_entry_point_accepts_bytes_only(source: object) -> None:
    assert _codes(_load(source)) == ("STRATEGY.SOURCE_NOT_IN_MEMORY",)


def test_source_over_the_byte_ceiling_is_rejected() -> None:
    oversized = b"k: " + b"a" * 262_144 + b"\n"

    assert _codes(_load(oversized)) == ("STRATEGY.SOURCE_TOO_LARGE",)


@pytest.mark.parametrize(
    "bom",
    [
        b"\xef\xbb\xbf",
        b"\xff\xfe",
        b"\xfe\xff",
        b"\xff\xfe\x00\x00",
        b"\x00\x00\xfe\xff",
    ],
)
def test_every_byte_order_mark_is_rejected(bom: bytes) -> None:
    assert _codes(_load(bom + b"a: 1\n")) == ("STRATEGY.SOURCE_BOM_PRESENT",)


def test_non_utf8_source_is_rejected() -> None:
    assert _codes(_load(b"k: \xff\xfe_invalid\n")) == ("STRATEGY.SOURCE_NOT_UTF8",)


def test_syntax_error_diagnostic_leaks_no_document_token() -> None:
    result = _load(b"k: [unclosed\nsecret_token_zz: 1\n")

    assert _codes(result) == ("STRATEGY.YAML_SYNTAX",)
    assert isinstance(result, Failure)
    rendered = repr(result.diagnostics)
    assert "secret_token_zz" not in rendered
    assert "unclosed" not in rendered


def test_empty_stream_is_rejected() -> None:
    assert _codes(_load(b"")) == ("STRATEGY.YAML_EMPTY_DOCUMENT",)


def test_two_documents_are_rejected() -> None:
    assert _codes(_load(b"a: 1\n---\nb: 2\n")) == ("STRATEGY.YAML_MULTIPLE_DOCUMENTS",)


@pytest.mark.parametrize("directive", ["%YAML 1.2\n---\n", "%TAG !e! tag:x:\n---\n"])
def test_directives_are_rejected(directive: str) -> None:
    source = f"{directive}a: 1\n".encode()

    assert _codes(_load(source)) == ("STRATEGY.YAML_DIRECTIVE_FORBIDDEN",)


def test_duplicate_keys_are_rejected() -> None:
    assert _codes(_load(b"a: 1\na: 2\n")) == ("STRATEGY.YAML_DUPLICATE_KEY",)


def test_merge_key_is_rejected() -> None:
    source = b"base: &b\n  a: 1\nchild:\n  <<: *b\n"

    assert _codes(_load(source)) == ("STRATEGY.YAML_MERGE_KEY_FORBIDDEN",)


def test_a_document_whose_root_is_a_scalar_is_accepted_by_the_loader() -> None:
    """The loader returns a bounded plain value; ``StrategySpec`` demands a mapping."""
    result = _load(b"a_root_scalar\n")

    assert isinstance(result, Success), _codes(result)
    assert result.value.value == "a_root_scalar"


def test_successful_load_returns_the_bounded_plain_value() -> None:
    # Sequence items avoid single letters: bare ``y`` and ``n`` are rejected
    # boolean aliases, which is itself pinned below.
    assert _value(b"a: 1\nb:\n  - xx\n  - zz\n") == {"a": 1, "b": ["xx", "zz"]}


# --- Section 5.2.1 classifier ---------------------------------------------


def test_an_implicit_scalar_event_carries_no_resolved_tag() -> None:
    """Pin the premise the whole classifier contract rests on."""
    events = [
        event
        for event in yaml.parse("k: 20\n", Loader=StrictStrategySafeLoader)
        if isinstance(event, yaml.ScalarEvent)
    ]

    assert [event.value for event in events] == ["k", "20"]
    assert all(event.tag is None for event in events)


@pytest.mark.parametrize(("text", "expected"), [("20", 20), ("-5", -5), ("0", 0)])
def test_canonical_integers_classify_as_integers(text: str, expected: int) -> None:
    assert _scalar(text) == expected


@pytest.mark.parametrize(("text", "expected"), [("true", True), ("false", False)])
def test_canonical_booleans_classify_as_booleans(text: str, expected: bool) -> None:
    assert _scalar(text) is expected


@pytest.mark.parametrize(("text", "expected"), [('"yes"', "yes"), ('"1"', "1")])
def test_quoted_ambiguous_scalars_classify_as_strings(
    text: str,
    expected: str,
) -> None:
    assert _scalar(text) == expected


@pytest.mark.parametrize(("text", "expected"), [("!!str yes", "yes"), ('!!str ""', "")])
def test_explicit_string_tags_classify_as_strings(text: str, expected: str) -> None:
    assert _scalar(text) == expected


def test_explicit_integer_tag_classifies_as_an_integer() -> None:
    assert _scalar("!!int 20") == 20


def test_invalid_explicit_integer_tag_is_rejected() -> None:
    assert _scalar_code("!!int 0x20") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_explicit_boolean_tag_accepts_only_exact_lowercase_text() -> None:
    assert _scalar("!!bool true") is True
    assert _scalar("!!bool false") is False
    assert _scalar_code("!!bool yes") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)
    assert _scalar_code("!!bool True") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize(
    "text",
    ["yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"],
)
def test_boolean_aliases_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["y", "Y", "n", "N", "True", "TRUE", "False", "FALSE"])
def test_single_letter_and_capitalised_booleans_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["010", "0o17", "+1", "+0", "1_000"])
def test_alternate_integer_notations_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_hexadecimal_is_rejected() -> None:
    assert _scalar_code("0x20") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["12:30", "190:20:30.15"])
def test_sexagesimal_forms_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["1.0", ".5", "1.", "1e3", ".inf", "+.INF", ".nan"])
def test_floats_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["2026-08-15", "2026-08-15T00:00:00Z"])
def test_timestamps_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["~", "null", "Null", "NULL"])
def test_nulls_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_the_empty_plain_scalar_is_rejected() -> None:
    assert _codes(_load(b"k:\n")) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_the_value_token_is_rejected() -> None:
    assert _scalar_code("=") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("text", ["!!binary Zm9v", "!Thing x"])
def test_unknown_explicit_tags_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_FORBIDDEN_TAG",)


@pytest.mark.parametrize("text", ["! abc", '! "yes"', "! {a: 1}"])
def test_the_non_specific_tag_is_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_FORBIDDEN_TAG",)


@pytest.mark.parametrize(
    "source",
    [b"k: !!seq {a: 1}\n", b"k: !!map [1, 2]\n"],
)
def test_mismatched_collection_tags_are_rejected(source: bytes) -> None:
    assert _codes(_load(source)) == ("STRATEGY.YAML_FORBIDDEN_TAG",)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b"k: !!map {a: 1}\n", {"a": 1}),
        (b"k: !!seq [1, 2]\n", [1, 2]),
    ],
)
def test_an_explicit_collection_tag_matching_its_event_kind_is_accepted(
    source: bytes,
    expected: YamlValue,
) -> None:
    assert _value(source)["k"] == expected


@pytest.mark.parametrize(
    "text",
    ["BINANCE:BTC/USDT:SPOT", "bar.close", "indicator.sma/v1", "1h"],
)
def test_identifier_shaped_scalars_survive_as_strings(text: str) -> None:
    assert _scalar(text) == text


def test_maximum_signed_64_bit_integer_is_accepted() -> None:
    assert _scalar("9223372036854775807") == 9223372036854775807


@pytest.mark.parametrize("text", ["9223372036854775808", "1" * 4301])
def test_out_of_range_integers_are_rejected(text: str) -> None:
    assert _scalar_code(text) == ("STRATEGY.YAML_INTEGER_OUT_OF_RANGE",)


def test_negative_zero_is_a_noncanonical_scalar_not_a_bounds_failure() -> None:
    assert _scalar_code("-0") == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_classifier_handles_exactly_the_leaf_event_classes() -> None:
    from crypto_lab.strategy.yaml_source import HANDLED_EVENT_CLASSES

    def _leaves(cls: type) -> set[type]:
        subclasses = cls.__subclasses__()
        if not subclasses:
            return {cls}
        return {leaf for sub in subclasses for leaf in _leaves(sub)}

    assert HANDLED_EVENT_CLASSES == frozenset(_leaves(yaml.events.Event))
    assert len(HANDLED_EVENT_CLASSES) == 10


@pytest.mark.parametrize(
    ("implicit", "style"),
    [
        ((False, False), None),
        ((True, False), '"'),
        ((False, False), "|"),
    ],
)
def test_a_style_and_implicit_disagreement_is_rejected(
    implicit: tuple[bool, bool],
    style: str | None,
) -> None:
    """Unreachable from authored YAML, so the event is constructed directly.

    ``token.plain`` determines both fields for an untagged scalar, so PyYAML
    cannot produce a disagreement. The check exists to fail closed if that
    invariant ever changes, which only a synthetic event can exercise.
    """
    from crypto_lab.strategy.yaml_source import classify_scalar_event

    event = yaml.ScalarEvent(None, None, implicit, "abc", style=style)

    assert classify_scalar_event(event)[1] == "STRATEGY.YAML_NONCANONICAL_SCALAR"


# --- Section 5.2.2 mapping-key contract ------------------------------------


@pytest.mark.parametrize(
    "source",
    [b"a: &x 1\nb:\n  *x : 2\n", b"? [a, b]\n: 1\n", b"? {a: b}\n: 1\n"],
)
def test_non_scalar_keys_are_rejected(source: bytes) -> None:
    assert _codes(_load(source)) == ("STRATEGY.YAML_MAPPING_KEY_INVALID",)


@pytest.mark.parametrize(
    "source",
    [b"1: x\n", b"true: x\n", b"!!int 1: x\n", b"!!bool true: x\n"],
)
def test_keys_that_classify_as_non_strings_are_rejected(source: bytes) -> None:
    """A key classifying successfully but unusable as a key gets the key code."""
    assert _codes(_load(source)) == ("STRATEGY.YAML_MAPPING_KEY_INVALID",)


@pytest.mark.parametrize("source", [b"~: x\n", b"?\n: x\n"])
def test_keys_the_classifier_itself_rejects_keep_the_classifier_code(
    source: bytes,
) -> None:
    """Precedence step 3: 5.2.1's own rejection code wins over the key code.

    ``~`` and the empty plain scalar both match the null row, so neither ever
    classifies successfully and neither can reach the mapping-key rule.
    """
    assert _codes(_load(source)) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


def test_an_explicit_null_key_is_rejected() -> None:
    assert _codes(_load(b"!!null ~: x\n")) == ("STRATEGY.YAML_FORBIDDEN_TAG",)


def test_a_quoted_empty_key_is_a_valid_empty_string() -> None:
    """The plain/quoted asymmetry of 5.2.1 is hash material, so pin both halves."""
    assert _value(b'"": x\n') == {"": "x"}


def test_the_value_token_key_keeps_the_classifier_code() -> None:
    assert _codes(_load(b"=: x\n")) == ("STRATEGY.YAML_NONCANONICAL_SCALAR",)


@pytest.mark.parametrize("source", [b"!Thing k: 1\n", b"! k: 1\n"])
def test_tagged_keys_are_rejected(source: bytes) -> None:
    assert _codes(_load(source)) == ("STRATEGY.YAML_FORBIDDEN_TAG",)


@pytest.mark.parametrize("source", [b"<<: 1\n", b'"<<": 1\n'])
def test_merge_keys_are_rejected_in_both_spellings(source: bytes) -> None:
    assert _codes(_load(source)) == ("STRATEGY.YAML_MERGE_KEY_FORBIDDEN",)


def test_an_over_long_key_is_rejected() -> None:
    """Uses the explicit ``?`` indicator, because PyYAML caps a simple key at 1024.

    Written as a plain ``kkk...: 1`` the over-long text never reaches key
    position at all, so the assertion would be satisfied by the value-position
    length check and precedence step 0 would stay untested.
    """
    long_key = "k" * (MAX_SCALAR_CHARACTERS + 1)
    source = f"? {long_key}\n: 1\n".encode()

    assert _codes(_load(source)) == ("STRATEGY.YAML_SCALAR_TOO_LONG",)


def test_quoted_and_unquoted_keys_with_equal_text_are_duplicates() -> None:
    assert _codes(_load(b'a: 1\n"a": 2\n')) == ("STRATEGY.YAML_DUPLICATE_KEY",)


def test_an_over_long_duplicate_key_stays_inside_the_result_contract() -> None:
    """A duplicated key longer than a diagnostic detail string must not escape.

    ``MAX_SCALAR_CHARACTERS`` is 8192 but ``MAX_DETAIL_STRING`` is 2048, so an
    unclamped echoed key raises ``ValidationError`` out of ``Diagnostic``
    construction rather than returning a ``Result`` failure. The explicit ``?``
    key indicator is required: PyYAML caps a *simple* key at 1024 characters, so
    a plain over-long key never reaches key position at all.
    """
    key = "k" * (MAX_DETAIL_STRING + 1)
    source = "\n".join((f"? {key}", ": 1", f"? {key}", ": 2", "")).encode()

    result = _load(source)

    assert _codes(result) == ("STRATEGY.YAML_DUPLICATE_KEY",)
    assert isinstance(result, Failure)
    detail = result.diagnostics[0].details["key"]
    assert isinstance(detail, str)
    assert len(detail) <= MAX_DETAIL_STRING


def test_the_first_duplicate_in_document_order_is_reported() -> None:
    source = b"a: 1\nb: 2\nb: 3\na: 4\n"
    result = _load(source)

    assert _codes(result) == ("STRATEGY.YAML_DUPLICATE_KEY",)
    assert isinstance(result, Failure)
    details = result.diagnostics[0].details
    assert details["key"] == "b"
    assert details["line"] == 3
    assert details["column"] == 1


# --- Section 5.2.3 SourceName ----------------------------------------------


_REJECTED_SOURCE_NAMES = (
    "strategy..yaml",
    ".hidden",
    "a/b.yaml",
    "a\\b.yaml",
    "c:\\x\\y.yaml",
    "C:\\x\\y.yaml",
    "\\\\host\\share\\x.yaml",
    "//host/share/x.yaml",
    "~x.yaml",
    "~/x.yaml",
    "Strategy.yaml",
    "-leading.yaml",
    "has space.yaml",
    "x" * 129,
)
_ACCEPTED_SOURCE_NAMES = ("strategy.yaml", "sma_cross_long.valid.yaml", "x" * 128)


@pytest.mark.parametrize("name", _REJECTED_SOURCE_NAMES)
def test_source_name_rejects_every_path_shaped_value(name: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SourceName).validate_python(name)


@pytest.mark.parametrize("name", _ACCEPTED_SOURCE_NAMES)
def test_source_name_accepts_every_bounded_label(name: str) -> None:
    assert TypeAdapter(SourceName).validate_python(name) == name


def test_the_generated_source_name_schema_agrees_with_the_runtime_pattern() -> None:
    """The two constraints are separate declarations, so pin them against drift.

    The runtime check is a compiled ``re`` ``fullmatch`` because Pydantic's
    ``rust-regex`` engine rejects the negative look-ahead; the JSON Schema keeps
    the full constraint because look-ahead is valid ECMA-262. Only an executable
    agreement test stops the two from diverging.
    """
    adapter: TypeAdapter[str] = TypeAdapter(SourceName)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )

    for schema in schemas:
        assert schema["pattern"].endswith(r"(?![\s\S])")
        validator = Draft202012Validator(schema)
        for name in _ACCEPTED_SOURCE_NAMES:
            assert adapter.validate_python(name) == name
            validator.validate(name)
        for name in _REJECTED_SOURCE_NAMES:
            with pytest.raises(ValidationError):
                adapter.validate_python(name)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(name)


@pytest.mark.parametrize("name", ["C:\\x\\y.yaml", "strategy..yaml"])
def test_the_entry_point_itself_rejects_a_bad_source_name(name: str) -> None:
    result = _load(b"a: 1\n", name)

    assert _codes(result) == ("STRATEGY.SOURCE_NAME_INVALID",)
    assert isinstance(result, Failure)
    rendered = repr(result.diagnostics)
    for fragment in (name, "x\\y", ".."):
        assert fragment not in rendered


# --- Section 5.2 items 11 and 12: global state and freshness ---------------


def test_loading_an_invalid_document_first_changes_nothing() -> None:
    valid = b"a: 1\n"
    alone = _load(valid)
    _load(b"k: [unclosed\n")
    after_failure = _load(valid)

    assert isinstance(alone, Success)
    assert isinstance(after_failure, Success)
    assert after_failure.value == alone.value


# --- Section 6.5 fixture documents -----------------------------------------


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("invalid/python_tag.yaml", "STRATEGY.YAML_FORBIDDEN_TAG"),
        ("invalid/unknown_tag.yaml", "STRATEGY.YAML_FORBIDDEN_TAG"),
        ("invalid/duplicate_key.yaml", "STRATEGY.YAML_DUPLICATE_KEY"),
        ("invalid/merge_key.yaml", "STRATEGY.YAML_MERGE_KEY_FORBIDDEN"),
        ("invalid/two_documents.yaml", "STRATEGY.YAML_MULTIPLE_DOCUMENTS"),
    ],
)
def test_each_invalid_fixture_is_rejected_with_its_exact_code(
    relative: str,
    expected: str,
) -> None:
    assert _codes(_load(_fixture(relative))) == (expected,)


def test_the_python_object_tag_never_reaches_a_constructor() -> None:
    """The classic PyYAML object-construction vector, rejected before resolution."""
    source = _fixture("invalid/python_tag.yaml")

    assert b"!!python/object/apply:os.system" in source
    result = _load(source)

    assert _codes(result) == ("STRATEGY.YAML_FORBIDDEN_TAG",)
    assert isinstance(result, Failure)
    assert "os.system" not in result.model_dump_json()


def test_loader_state_is_untouched_by_success_and_failure() -> None:
    before = dict(yaml.SafeLoader.yaml_constructors)

    _load(b"a: 1\n")
    _load(b"k: [unclosed\n")
    _load(b"!Thing x\n")

    assert yaml.SafeLoader.yaml_constructors == before
    assert "yaml_constructors" not in StrictStrategySafeLoader.__dict__
    assert yaml.SafeLoader in StrictStrategySafeLoader.__mro__


# Plan section 5.9's closed table, restricted to the codes this stage's loader
# and Task 2 models can emit. Any addition requires a plan amendment, so the set
# is written out rather than derived from the implementation.
_CLOSED_STAGE_FOUR_CODES = frozenset(
    {
        "STRATEGY.SOURCE_TOO_LARGE",
        "STRATEGY.SOURCE_NOT_UTF8",
        "STRATEGY.SOURCE_BOM_PRESENT",
        "STRATEGY.SOURCE_NOT_IN_MEMORY",
        "STRATEGY.SOURCE_NAME_INVALID",
        "STRATEGY.YAML_SYNTAX",
        "STRATEGY.YAML_MULTIPLE_DOCUMENTS",
        "STRATEGY.YAML_EMPTY_DOCUMENT",
        "STRATEGY.YAML_FORBIDDEN_TAG",
        "STRATEGY.YAML_DUPLICATE_KEY",
        "STRATEGY.YAML_MERGE_KEY_FORBIDDEN",
        "STRATEGY.YAML_SCALAR_TOO_LONG",
        "STRATEGY.YAML_COLLECTION_TOO_LARGE",
        "STRATEGY.YAML_DEPTH_EXCEEDED",
        "STRATEGY.YAML_EVENT_BUDGET_EXCEEDED",
        "STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED",
        "STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED",
        "STRATEGY.YAML_EXPANSION_EXCEEDED",
        "STRATEGY.YAML_RECURSIVE_ALIAS",
        "STRATEGY.YAML_NONCANONICAL_SCALAR",
        "STRATEGY.YAML_ANCHOR_REDEFINED",
        "STRATEGY.YAML_MAPPING_KEY_INVALID",
        "STRATEGY.YAML_INTEGER_OUT_OF_RANGE",
        "STRATEGY.YAML_DIRECTIVE_FORBIDDEN",
    }
)


def test_every_emittable_error_code_is_in_the_closed_table() -> None:
    """Section 5.9 closes the error-code vocabulary for the whole stage."""
    assert frozenset(_MESSAGES) <= _CLOSED_STAGE_FOUR_CODES
    assert frozenset(_SECURITY_CODES) <= _CLOSED_STAGE_FOUR_CODES
    # Every closed loader code must also have a fixed project-authored message,
    # or a rejection path could emit a KeyError instead of a diagnostic.
    assert frozenset(_MESSAGES) == _CLOSED_STAGE_FOUR_CODES
