"""Stage 6 Task 1: the textual candidate-path grammar of Stage 6 plan section 3.3.

Every accepted shape is paired with its listed near-miss rejection and the rule
that rejects it, the Windows reserved-stem and trailing-dot rules are proven in
both directions (rejected stems, accepted lookalikes), and the published schema
pattern is proven to accept and reject exactly what the runtime does for every
listed shape. Containment against a real root, links and reparse points remain
Stage 7 and Stage 9 work: only the text is checked here.
"""

from __future__ import annotations

from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError
from pydantic.json_schema import JsonSchemaMode

from crypto_lab.adapters.limits import (
    MAX_PATH_SEGMENTS,
    MAX_RELATIVE_PATH_CHARACTERS,
    MAX_SEGMENT_CHARACTERS,
)
from crypto_lab.adapters.paths import (
    RelativeCandidatePath,
    validate_relative_candidate_path,
)

_ADAPTER: TypeAdapter[str] = TypeAdapter(RelativeCandidatePath)
_LONGEST_SEGMENT = "s" * MAX_SEGMENT_CHARACTERS
#: 255 + 1 + 254 + 1 + 1 = 512 characters.
_LONGEST_PATH = "a" * 255 + "/" + "b" * 254 + "/c"
_MOST_SEGMENTS = "/".join(["a"] * MAX_PATH_SEGMENTS)
_ACCEPTED = [
    "a/b.json",
    "x",
    "0start",
    "results/native/report.bin",
    "a-b_c.d/e",
    "a..b",
    # The three lookalikes plan 3.3 names, plus the same rule at other stems.
    "CONX.json",
    "COM10",
    "a.b/c",
    "LPT0",
    "CON1",
    "console/aux1",
    "anul",
    _LONGEST_SEGMENT,
    _LONGEST_PATH,
    _MOST_SEGMENTS,
]
#: Every plan 3.3 near-miss beside the accepted shape it shadows, with the rule
#: the runtime names; the rule text is what `match` asserts.
_REJECTED = [
    ("a//b.json", "empty"),
    ("./a", "'.' or '..'"),
    ("a/.", "'.' or '..'"),
    ("a\\b", "forbidden character"),
    ("C:/a", "forbidden character"),
    ("a:stream", "forbidden character"),
    ("a/..", "'.' or '..'"),
    ("a/../b", "'.' or '..'"),
    ("/a", "empty"),
    ("a/", "empty"),
    ("a%2e%2e/b", "forbidden character"),
    ("CON.json", "reserved"),
    ("con.json", "reserved"),
    ("LPT9", "reserved"),
    ("a./b", "end in '.'"),
    ("a b", "forbidden character"),
    ("\u00e4", "forbidden character"),
    ("a" * 255 + "/" + "b" * 255 + "/c", "length"),
    ("/".join(["a"] * (MAX_PATH_SEGMENTS + 1)), "more than 32 segments"),
    ("s" * (MAX_SEGMENT_CHARACTERS + 1), "exceeds 255"),
    ("", "length"),
    (".hidden", "forbidden character"),
    ("-lead", "forbidden character"),
    ("_lead", "forbidden character"),
    ("a\x00b", "forbidden character"),
    ("a\n", "forbidden character"),
    ("a.", "end in '.'"),
    ("dir/b.", "end in '.'"),
    ("dir/CON", "reserved"),
    ("nul.a.b", "reserved"),
    ("//server/share", "empty"),
    ("\\\\server\\share", "forbidden character"),
    ("\\\\.\\COM1", "forbidden character"),
]
_RESERVED_STEMS = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
]


def _schema(mode: JsonSchemaMode) -> dict[str, object]:
    return cast("dict[str, object]", _ADAPTER.json_schema(mode=mode))


@pytest.mark.parametrize("value", _ACCEPTED)
def test_each_accepted_shape_validates_through_every_path(value: str) -> None:
    assert validate_relative_candidate_path(value) == value
    assert _ADAPTER.validate_python(value) == value
    assert _ADAPTER.validate_json(f'"{value}"') == value


@pytest.mark.parametrize(("value", "rule"), _REJECTED)
def test_each_near_miss_is_rejected_by_its_named_rule(value: str, rule: str) -> None:
    with pytest.raises(ValueError, match=rule):
        validate_relative_candidate_path(value)
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python(value)


@pytest.mark.parametrize("stem", _RESERVED_STEMS)
def test_each_windows_device_stem_is_rejected_in_every_casing(stem: str) -> None:
    for spelled in (stem, stem.lower(), stem.capitalize()):
        for shape in (spelled, f"{spelled}.json", f"{spelled}.a.b", f"dir/{spelled}"):
            with pytest.raises(ValueError, match="reserved"):
                validate_relative_candidate_path(shape)
        # The rule is on the stem before the first dot, so a longer stem passes.
        assert validate_relative_candidate_path(f"{spelled}x") == f"{spelled}x"
        assert validate_relative_candidate_path(f"{spelled}0") == f"{spelled}0"


def test_non_string_input_is_rejected_by_both_paths() -> None:
    for value in (1, b"a/b", None, ["a"]):
        with pytest.raises(ValidationError):
            _ADAPTER.validate_python(value)
    with pytest.raises(TypeError, match="built-in string"):
        validate_relative_candidate_path(cast("str", 1))


def test_the_grammar_bounds_are_the_limits_constants() -> None:
    assert len(_LONGEST_PATH) == MAX_RELATIVE_PATH_CHARACTERS == 512
    assert len(_LONGEST_SEGMENT) == MAX_SEGMENT_CHARACTERS == 255
    assert _MOST_SEGMENTS.count("/") + 1 == MAX_PATH_SEGMENTS == 32


def test_the_published_schema_is_exact_and_agrees_with_the_runtime() -> None:
    """Plan 12.4: the reserved-stem and trailing-dot rules are published inside
    the pattern and are exact, so the committed bytes accept and reject exactly
    what the runtime does for every listed shape."""
    validation = _schema("validation")
    assert validation == _schema("serialization")
    assert validation["type"] == "string"
    assert validation["minLength"] == 1
    assert validation["maxLength"] == MAX_RELATIVE_PATH_CHARACTERS
    pattern = validation["pattern"]
    assert isinstance(pattern, str)
    assert pattern.startswith("^")
    assert pattern.endswith(r"(?![\s\S])")
    assert not pattern.endswith("$")
    validator = Draft202012Validator(validation)
    for value in _ACCEPTED:
        validator.validate(value)
    for value, _rule in _REJECTED:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(value)
    for terminator in ("\n", "\r", "\r\n"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate("a/b.json" + terminator)
        with pytest.raises(ValidationError):
            _ADAPTER.validate_python("a/b.json" + terminator)
