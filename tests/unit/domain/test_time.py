from __future__ import annotations

import json
import re
from dataclasses import FrozenInstanceError
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

import crypto_lab.domain.time as time_module
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.time import (
    CalendarValidUtcDateTime,
    MonotonicInstant,
    UtcDateTime,
    format_utc,
)
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS, render_schema_files


class UtcProbe(CanonicalModel):
    value: UtcDateTime


def test_utc_python_and_json_round_trip_are_canonical() -> None:
    seconds = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC))
    micros = UtcProbe(value=datetime(2026, 8, 10, 1, 2, 3, 42, tzinfo=UTC))
    assert seconds.model_dump_json() == '{"value":"2026-08-10T01:02:03Z"}'
    assert micros.model_dump_json() == ('{"value":"2026-08-10T01:02:03.000042Z"}')
    assert UtcProbe.model_validate_json(seconds.model_dump_json()) == seconds
    assert format_utc(seconds.value) == "2026-08-10T01:02:03Z"


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - deliberate rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        "2026-08-10T01:02:03Z",
    ],
)
def test_python_validation_rejects_non_typed_or_non_utc_values(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 8, 10, 1, 2, 3),  # noqa: DTZ001 - rejection case
        datetime(
            2026,
            8,
            10,
            1,
            2,
            3,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_format_utc_rejects_naive_and_nonzero_offset_values(value: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        format_utc(value)


@pytest.mark.parametrize(
    "document",
    [
        '{"value":"2026-02-30T01:02:03Z"}',
        '{"value":"2026-08-10T01:02:03+00:00"}',
        '{"value":"2026-08-10T01:02:03.1Z"}',
    ],
)
def test_json_validation_rejects_noncanonical_utc_text(document: str) -> None:
    with pytest.raises(ValidationError):
        UtcProbe.model_validate_json(document)


# --------------------------------------------------------------------------
# Forward-only UTC schema view -- `CalendarValidUtcDateTime`
# --------------------------------------------------------------------------
#
# `parse_utc` routes JSON text through `datetime.fromisoformat`, so it rejects
# an impossible calendar date and an out-of-range clock. The legacy
# `UtcDateTime` projection publishes only `[0-9]{4}-[0-9]{2}-[0-9]{2}` and
# `[0-9]{2}:[0-9]{2}:[0-9]{2}`, so a standards-compliant Draft 2020-12 validator
# accepts documents ordinary Pydantic validation rejects. That projection is
# frozen into three released Stage 3 `$id`s -- `datasets/dataset-descriptor-v1`,
# `datasets/dataset-partition-v1`, and `domain/diagnostic-v1` -- so it cannot be
# tightened in place. `CalendarValidUtcDateTime` is the forward-only schema view:
# the same runtime parser, the same serializer, the same canonical bytes, and a
# strictly narrower published grammar for artifacts not yet released.

_LEGACY: TypeAdapter[datetime] = TypeAdapter(UtcDateTime)
_VIEW: TypeAdapter[datetime] = TypeAdapter(CalendarValidUtcDateTime)

_Mode = Literal["validation", "serialization"]
_MODES: tuple[_Mode, ...] = ("validation", "serialization")

_IMPOSSIBLE_CALENDAR_DATES = (
    "0000-01-01T00:00:00Z",
    "2026-00-01T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-01-00T00:00:00Z",
    "2026-01-32T00:00:00Z",
    "2026-02-29T00:00:00Z",
    "2025-02-29T00:00:00Z",
    "2026-02-30T00:00:00Z",
    "2026-04-31T00:00:00Z",
    "1900-02-29T00:00:00Z",
    "2100-02-29T00:00:00Z",
)

_REAL_CALENDAR_DATES = (
    "0001-01-01T00:00:00Z",
    "0004-02-29T00:00:00Z",
    "0400-02-29T00:00:00Z",
    "2000-02-29T00:00:00Z",
    "2024-02-29T00:00:00Z",
    "2026-02-28T00:00:00Z",
    "2026-04-30T00:00:00Z",
    "9999-12-31T23:59:59Z",
)

_IMPOSSIBLE_CLOCK_VALUES = (
    "2026-01-01T24:00:00Z",
    "2026-01-01T25:00:00Z",
    "2026-01-01T99:00:00Z",
    "2026-01-01T00:60:00Z",
    "2026-01-01T00:99:00Z",
    "2026-01-01T00:00:60Z",
    "2026-01-01T00:00:99Z",
    "2026-01-01T99:99:99Z",
    "2026-01-01T25:61:61Z",
    "2026-01-01T24:00:00.000000Z",
)

_REAL_CLOCK_VALUES = (
    "2026-01-01T00:00:00Z",
    "2026-01-01T09:09:09Z",
    "2026-01-01T10:10:10Z",
    "2026-01-01T19:59:59Z",
    "2026-01-01T20:00:00Z",
    "2026-01-01T23:59:59Z",
    "2026-01-01T23:59:59.000000Z",
    "2026-01-01T23:59:59.999999Z",
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]

_STAGE3_SCHEMA_PATHS = (
    "domain/instrument-ref-v1.schema.json",
    "domain/money-v1.schema.json",
    "domain/price-v1.schema.json",
    "domain/quantity-v1.schema.json",
    "domain/diagnostic-v1.schema.json",
    "configuration/application-config-v1.schema.json",
    "datasets/dataset-partition-v1.schema.json",
    "datasets/dataset-descriptor-v1.schema.json",
    "protocol/engine-descriptor-v1.schema.json",
    "protocol/adapter-descriptor-v1.schema.json",
    "artifacts/artifact-owner-ref-v1.schema.json",
)


def _view_schema(mode: _Mode) -> dict[str, Any]:
    return _VIEW.json_schema(mode=mode)


def _legacy_schema(mode: _Mode) -> dict[str, Any]:
    return _LEGACY.json_schema(mode=mode)


def _runtime_accepts(adapter: TypeAdapter[datetime], text: str) -> bool:
    try:
        adapter.validate_json(json.dumps(text))
    except ValidationError:
        return False
    return True


def test_the_forward_view_reuses_the_legacy_runtime_and_serializer_exactly() -> None:
    """The view is a schema projection, never a second runtime semantic.

    For every value the legacy alias accepts, both aliases must produce the same
    Python `datetime` and the same serialized bytes. That is the whole claim that
    keeps this from being a fork of `parse_utc`.
    """
    for text in _REAL_CALENDAR_DATES + _REAL_CLOCK_VALUES:
        legacy = _LEGACY.validate_json(json.dumps(text))
        view = _VIEW.validate_json(json.dumps(text))
        assert legacy == view, text
        assert type(legacy) is type(view) is datetime, text
        assert legacy.tzinfo == view.tzinfo == UTC, text
        assert _LEGACY.dump_json(view) == _VIEW.dump_json(legacy), text
        assert _VIEW.dump_json(view) == _LEGACY.dump_json(legacy), text

    typed = datetime(2026, 8, 10, 1, 2, 3, 42, tzinfo=UTC)
    assert _VIEW.validate_python(typed) == _LEGACY.validate_python(typed)
    assert _VIEW.dump_json(typed) == b'"2026-08-10T01:02:03.000042Z"'


@pytest.mark.parametrize("text", _IMPOSSIBLE_CALENDAR_DATES)
def test_the_forward_view_schema_rejects_an_impossible_calendar_date(
    text: str,
) -> None:
    assert not _runtime_accepts(_LEGACY, text)
    assert not _runtime_accepts(_VIEW, text)
    for mode in _MODES:
        assert not Draft202012Validator(_view_schema(mode)).is_valid(text), mode


@pytest.mark.parametrize("text", _IMPOSSIBLE_CLOCK_VALUES)
def test_the_forward_view_schema_rejects_an_impossible_clock_value(text: str) -> None:
    assert not _runtime_accepts(_LEGACY, text)
    assert not _runtime_accepts(_VIEW, text)
    for mode in _MODES:
        assert not Draft202012Validator(_view_schema(mode)).is_valid(text), mode


@pytest.mark.parametrize("text", _REAL_CALENDAR_DATES + _REAL_CLOCK_VALUES)
def test_the_forward_view_over_rejects_nothing_the_runtime_accepts(text: str) -> None:
    """The only failure mode a hand-written calendar regex can have."""
    assert _runtime_accepts(_LEGACY, text)
    assert _runtime_accepts(_VIEW, text)
    for mode in _MODES:
        assert Draft202012Validator(_view_schema(mode)).is_valid(text), mode


@pytest.mark.parametrize(
    "text",
    [
        "2026-08-10T01:02:03+00:00",
        "2026-08-10T01:02:03.1Z",
        "2026-08-10T01:02:03.1234567Z",
        "2026-08-10T01:02:03z",
        "2026-08-10T01:02:03",
        "2026-08-10 01:02:03Z",
        "2026-08-10T01:02:03.000000",
    ],
)
def test_the_forward_view_preserves_the_fraction_offset_and_z_grammar(
    text: str,
) -> None:
    """Every rule the legacy branch already carried still rejects."""
    assert not _runtime_accepts(_LEGACY, text)
    assert not _runtime_accepts(_VIEW, text)
    for mode in _MODES:
        assert not Draft202012Validator(_legacy_schema(mode)).is_valid(text), mode
        assert not Draft202012Validator(_view_schema(mode)).is_valid(text), mode


def test_the_forward_view_publishes_the_same_grammar_in_both_render_modes() -> None:
    """A rule carried in one mode only is a mode asymmetry, not a contract."""
    validation = _view_schema("validation")
    serialization = _view_schema("serialization")
    assert validation == serialization
    Draft202012Validator.check_schema(validation)
    Draft202012Validator.check_schema(serialization)


def test_the_forward_view_terminates_on_the_exact_string() -> None:
    """The legacy branch owns termination; this proves the conjunction inherits it
    rather than assuming a `$` anchor would have been exact under a Python-backed
    validator, where `$` also matches before a trailing newline.
    """
    for mode in _MODES:
        validator = Draft202012Validator(_view_schema(mode))
        validator.validate("2026-08-10T01:02:03Z")
        for terminator in ("\n", "\r", "\r\n", " ", "\t"):
            candidate = "2026-08-10T01:02:03Z" + terminator
            assert not validator.is_valid(candidate), (mode, terminator)
            assert not _runtime_accepts(_VIEW, candidate), terminator


def test_the_forward_view_is_additive_over_an_untouched_legacy_branch() -> None:
    """Shape, not just behaviour: three `allOf` branches, the first of which is
    the legacy projection verbatim. A future edit that replaces rather than
    composes has to change this test."""
    legacy = _legacy_schema("validation")
    for mode in _MODES:
        rendered = _view_schema(mode)
        assert set(rendered) == {"allOf"}
        branches = rendered["allOf"]
        assert len(branches) == 3
        assert branches[0] == legacy
        assert branches[1] == {
            "type": "string",
            "pattern": time_module._CALENDAR_DATE_PREFIX_PATTERN,
        }
        assert branches[2] == {
            "type": "string",
            "pattern": time_module._CLOCK_TIME_PREFIX_PATTERN,
        }
        # Rendering must not hand out the module's own objects, or a consumer
        # that post-processes a subschema would mutate the frozen projection.
        assert branches[0] is not time_module._UTC_SCHEMA
        assert rendered is not time_module._CALENDAR_VALID_UTC_SCHEMA
    # And the frozen projection is still exactly what Stage 3 published.
    assert time_module._UTC_SCHEMA == {
        "type": "string",
        "format": "date-time",
        "pattern": time_module._UTC_SCHEMA_PATTERN,
    }
    assert legacy == time_module._UTC_SCHEMA


def test_neither_projection_leans_on_the_date_time_format_keyword() -> None:
    """`format` is an annotation by default in Draft 2020-12: a validator built
    without a `format_checker` ignores it. So the `pattern` keywords carry the
    entire rule, and `format: date-time` is inherited metadata rather than the
    mechanism. Asserted so nobody later reads it as load-bearing."""
    assert Draft202012Validator({"format": "date-time"}).is_valid("not-a-date")
    for mode in _MODES:
        assert _view_schema(mode)["allOf"][0]["format"] == "date-time"
        assert "format" not in _view_schema(mode)["allOf"][1]
        assert "format" not in _view_schema(mode)["allOf"][2]


def test_the_calendar_branch_pattern_is_exact_in_isolation() -> None:
    """Per-branch, so a weakening of this branch alone cannot hide behind the
    conjunction with the other two."""
    pattern = re.compile(time_module._CALENDAR_DATE_PREFIX_PATTERN)
    for text in _IMPOSSIBLE_CALENDAR_DATES:
        assert pattern.match(text) is None, text
    for text in _REAL_CALENDAR_DATES:
        assert pattern.match(text) is not None, text
    # A calendar-valid date carrying an impossible clock still matches this
    # branch: the clock is the other branch's remit, stated rather than implied.
    assert pattern.match("2026-01-01T99:99:99Z") is not None


def test_the_clock_branch_pattern_is_exact_in_isolation() -> None:
    """Per-branch, and the reason the escaped fraction dot is observable at all:
    the legacy branch also requires `\\.`, so weakening it here is invisible in
    the conjunction but visible right here."""
    pattern = re.compile(time_module._CLOCK_TIME_PREFIX_PATTERN)
    for text in _IMPOSSIBLE_CLOCK_VALUES:
        assert pattern.match(text) is None, text
    for text in _REAL_CLOCK_VALUES:
        assert pattern.match(text) is not None, text
    # The fraction separator is a literal dot, never "any character".
    assert pattern.match("2026-01-01T00:00:00.000000Z") is not None
    for wrong in ("2026-01-01T00:00:00X000000Z", "2026-01-01T00:00:00,000000Z"):
        assert pattern.match(wrong) is None, wrong
    # An impossible calendar date still matches this branch: the date is the
    # other branch's remit.
    assert pattern.match("2026-02-30T00:00:00Z") is not None


@pytest.mark.parametrize("component", ["hour", "minute", "second"])
def test_every_two_digit_clock_component_agrees_with_the_runtime(
    component: str,
) -> None:
    """All one hundred spellings of each component, so no in-range value is
    over-rejected and no out-of-range value survives."""
    limit = {"hour": 24, "minute": 60, "second": 60}[component]
    validators = {mode: Draft202012Validator(_view_schema(mode)) for mode in _MODES}
    for value in range(100):
        parts = {"hour": "12", "minute": "34", "second": "56"}
        parts[component] = f"{value:02d}"
        text = f"2026-01-15T{parts['hour']}:{parts['minute']}:{parts['second']}Z"
        expected = value < limit
        assert _runtime_accepts(_LEGACY, text) is expected, text
        assert _runtime_accepts(_VIEW, text) is expected, text
        for mode in _MODES:
            assert validators[mode].is_valid(text) is expected, (mode, text)


@pytest.mark.parametrize(
    "year",
    [
        "0000",  # below the published lower bound
        "0001",  # lower bound
        "0004",  # earliest ordinary leap year
        "0400",  # 400-year leap century
        "1900",  # non-leap century
        "2000",  # 400-year leap century
        "2024",  # ordinary leap year
        "2026",  # ordinary common year
        "2100",  # non-leap century
        "9999",  # upper bound
    ],
)
def test_the_bounded_calendar_matrix_agrees_with_the_gregorian_calendar(
    year: str,
) -> None:
    """Phase 6, committed half: every month `00`..`13` and every candidate day
    `00`..`32` for each material year class, checked four ways -- Python's own
    Gregorian calendar, `parse_utc`, and both render modes of the view."""
    validators = {mode: Draft202012Validator(_view_schema(mode)) for mode in _MODES}
    checked = 0
    for month in range(14):
        for day in range(33):
            text = f"{year}-{month:02d}-{day:02d}T12:34:56Z"
            try:
                date(int(year), month, day)
                gregorian = int(year) >= 1
            except ValueError:
                gregorian = False
            assert _runtime_accepts(_LEGACY, text) is gregorian, text
            assert _runtime_accepts(_VIEW, text) is gregorian, text
            for mode in _MODES:
                assert validators[mode].is_valid(text) is gregorian, (mode, text)
            checked += 1
    assert checked == 14 * 33


def test_the_legacy_projection_stays_a_frozen_stage_three_residual() -> None:
    """The gap this correction does **not** close, kept as an executable fact.

    `CalendarValidUtcDateTime` is a forward-only view precisely because the
    legacy `UtcDateTime` projection is already published in three Stage 3 `$id`s.
    Its permissiveness therefore survives on purpose, and that survival is what
    makes those eleven files byte-identical. The Stage 4 half of this same gap is
    closed -- see the migrated-field tests in `test_domain_descriptors.py`,
    `test_strategy_models.py`, and `test_strategy_versioning.py`.
    """
    for text in _IMPOSSIBLE_CALENDAR_DATES[1:] + _IMPOSSIBLE_CLOCK_VALUES:
        assert not _runtime_accepts(_LEGACY, text), text
        for mode in _MODES:
            assert Draft202012Validator(_legacy_schema(mode)).is_valid(text), (
                mode,
                text,
            )
    # `0000-01-01` is the one member the legacy pattern also rejects, because
    # `[0-9]{4}` admits it but `datetime` has no year zero -- so it is a runtime
    # rejection on both sides and belongs outside the residual list above.
    assert Draft202012Validator(_legacy_schema("validation")).is_valid(
        _IMPOSSIBLE_CALENDAR_DATES[0]
    )
    # The three released files still carry the loose grammar, on disk.
    for name in (
        "datasets/dataset-descriptor-v1.schema.json",
        "datasets/dataset-partition-v1.schema.json",
        "domain/diagnostic-v1.schema.json",
    ):
        published = json.loads((_REPOSITORY_ROOT / "schemas" / name).read_bytes())
        assert published["$defs"]["UtcDateTime"] == {
            "format": "date-time",
            "pattern": time_module._UTC_SCHEMA_PATTERN,
            "type": "string",
        }, name


def _loose_pattern_pointers(node: Any, path: str = "") -> list[str]:
    """Every JSON-Pointer position publishing the permissive legacy grammar,
    except branch 0 of the forward view -- where it is a conjunct narrowed by the
    calendar and clock branches beside it, which is the correction rather than a
    residue of it."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}/{key}"
            if (
                key == "pattern"
                and value == time_module._UTC_SCHEMA_PATTERN
                and not path.endswith("/$defs/CalendarValidUtcDateTime/allOf/0")
            ):
                found.append(here)
            found.extend(_loose_pattern_pointers(value, here))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_loose_pattern_pointers(value, f"{path}/{index}"))
    return found


def test_every_published_stage_four_timestamp_uses_the_forward_view() -> None:
    """The rule the `CalendarValidUtcDateTime` docstring states, made executable.

    A docstring saying "use this everywhere" that nothing enforces is worth
    nothing -- and this one has a deliberate exception (`Bar.timestamp_utc`,
    which no registry entry reaches), so the rule has to be stated at the
    precision it is actually true: **published** Stage 4 schemas only.

    Two halves, because the registry differs between trees. The direct half
    covers the three top-level published Stage 4 models by import, so it is
    non-vacuous in the eleven-entry committed tree as well as the twenty-entry
    working tree. The registry half then generalises: it fails for *any* future
    non-Stage-3 entry that still reaches the permissive grammar, which is the
    protection that matters the day `Bar` or anything like it is registered.
    """
    from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
    from crypto_lab.strategy.models import StrategySpec
    from crypto_lab.strategy.versioning import StrategyVersion

    direct = (RuntimeAvailabilityObservation, StrategySpec, StrategyVersion)
    for model in direct:
        for mode in _MODES:
            schema = model.model_json_schema(mode=mode)
            assert _loose_pattern_pointers(schema) == [], (model.__name__, mode)
            assert "UtcDateTime" not in schema.get("$defs", {}), model.__name__
            assert "CalendarValidUtcDateTime" in schema["$defs"], model.__name__
    assert len(direct) == 3

    stage4_seen = 0
    for definition in SCHEMA_DEFINITIONS:
        if definition.relative_path.as_posix() in _STAGE3_SCHEMA_PATHS:
            continue
        stage4_seen += 1
        for mode in _MODES:
            schema = definition.adapter.json_schema(mode=mode)
            assert _loose_pattern_pointers(schema) == [], (
                definition.schema_id,
                mode,
            )
    # Not asserted to be non-zero: the committed tree registers only the eleven
    # Stage 3 entries, and the direct half above is what carries this test there.
    assert stage4_seen == len(SCHEMA_DEFINITIONS) - len(_STAGE3_SCHEMA_PATHS)


def test_the_frozen_stage_three_schemas_still_publish_the_legacy_grammar() -> None:
    """The exact counterpart, so the guard above cannot be satisfied by silently
    tightening a released Stage 3 `$id` instead of a Stage 4 one."""
    expected = {
        "domain/diagnostic-v1.schema.json": 1,
        "datasets/dataset-partition-v1.schema.json": 1,
        "datasets/dataset-descriptor-v1.schema.json": 1,
    }
    for definition in SCHEMA_DEFINITIONS:
        name = definition.relative_path.as_posix()
        if name not in _STAGE3_SCHEMA_PATHS:
            continue
        for mode in _MODES:
            schema = definition.adapter.json_schema(mode=mode)
            found = _loose_pattern_pointers(schema)
            assert len(found) == expected.get(name, 0), (name, mode, found)
            if name in expected:
                assert found == ["/$defs/UtcDateTime/pattern"], (name, mode)


def test_the_eleven_frozen_stage_three_schemas_stay_byte_identical() -> None:
    """The hard boundary on this correction. Deliberately keyed on the eleven
    known relative paths rather than on `len(rendered)`, because the registry
    holds eleven entries in the committed tree and twenty in the working tree --
    a count assertion would pass in one and fail in the other.
    """
    rendered = render_schema_files()
    root = _REPOSITORY_ROOT / "schemas"
    for name in _STAGE3_SCHEMA_PATHS:
        key = PurePosixPath(name)
        assert key in rendered, name
        assert (root / name).read_bytes() == rendered[key], name


def test_utc_schema_requires_the_exact_z_form() -> None:
    adapter: TypeAdapter[datetime] = TypeAdapter(UtcDateTime)
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["type"] == "string"
        assert schema["format"] == "date-time"
        assert schema["pattern"].endswith(r"Z(?![\s\S])")
        validator = Draft202012Validator(schema)
        validator.validate("2026-08-10T01:02:03Z")
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_json(json.dumps("2026-08-10T01:02:03Z" + terminator))
            with pytest.raises(JsonSchemaValidationError):
                validator.validate("2026-08-10T01:02:03Z" + terminator)


# --------------------------------------------------------------------------
# Stage 7 Task 1: the process-local monotonic instant (plan sections 3.2, 6.1)
# --------------------------------------------------------------------------


def test_monotonic_instant_rejects_negative_nan_and_infinite_values() -> None:
    for bad in (-0.001, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="monotonic instant"):
            MonotonicInstant(bad)
    assert MonotonicInstant(1.5).plus(2.0) == MonotonicInstant(3.5)
    assert MonotonicInstant(1.5).until(MonotonicInstant(4.0)) == 2.5


def test_monotonic_instant_rejects_negative_infinity_and_accepts_zero() -> None:
    with pytest.raises(ValueError, match="monotonic instant"):
        MonotonicInstant(float("-inf"))
    assert MonotonicInstant(0.0).seconds == 0.0
    assert MonotonicInstant(0.0).until(MonotonicInstant(0.0)) == 0.0


@pytest.mark.parametrize("value", [0, 1, True, "1.0", None, 1.5 + 0j])
def test_monotonic_instant_accepts_only_an_exact_float(value: object) -> None:
    """An integer or a bool is not a clock reading; the paired reading is a float."""
    with pytest.raises(ValueError, match="monotonic instant"):
        MonotonicInstant(value)  # type: ignore[arg-type]


def test_monotonic_instant_is_frozen_ordered_hashable_and_slotted() -> None:
    instant = MonotonicInstant(2.0)
    with pytest.raises(FrozenInstanceError):
        instant.seconds = 3.0  # type: ignore[misc]
    assert not hasattr(instant, "__dict__")
    assert MonotonicInstant(1.0) < MonotonicInstant(2.0)
    assert MonotonicInstant(2.0) <= MonotonicInstant(2.0)
    assert MonotonicInstant(3.0) > MonotonicInstant(2.0)
    assert MonotonicInstant(2.0) >= MonotonicInstant(2.0)
    assert MonotonicInstant(2.0) == MonotonicInstant(2.0)
    assert MonotonicInstant(2.0) != MonotonicInstant(2.5)
    assert hash(MonotonicInstant(2.0)) == hash(MonotonicInstant(2.0))
    assert (
        len({MonotonicInstant(2.0), MonotonicInstant(2.0), MonotonicInstant(3.0)}) == 2
    )


def test_until_is_signed_and_plus_accepts_the_record_integer_timeout() -> None:
    swap = MonotonicInstant(10.0)
    assert MonotonicInstant(4.0).until(MonotonicInstant(1.5)) == -2.5
    # Plan 6.1: `monotonic_at_swap.plus(record.timeout_seconds)` passes the record's
    # `int`, so an integer offset is a duration; a bool is not.
    assert swap.plus(4) == MonotonicInstant(14.0)
    assert swap.plus(0) == swap
    assert swap.plus(0.0) == swap
    assert swap.plus(0.5).until(swap) == -0.5
    assert isinstance(swap.plus(4).seconds, float)


@pytest.mark.parametrize(
    "offset",
    [-1.0, -1, float("nan"), float("inf"), float("-inf"), True, "4", None],
)
def test_plus_rejects_negative_non_finite_and_non_numeric_offsets(
    offset: object,
) -> None:
    with pytest.raises(ValueError, match="monotonic instant"):
        MonotonicInstant(1.0).plus(offset)  # type: ignore[arg-type]


def test_plus_fails_closed_when_the_sum_leaves_the_finite_range() -> None:
    largest = 1.7976931348623157e308
    with pytest.raises(ValueError, match="monotonic instant"):
        MonotonicInstant(largest).plus(largest)
    with pytest.raises(ValueError, match="monotonic instant"):
        MonotonicInstant(1.0).plus(10**400)


def test_monotonic_instant_is_not_a_pydantic_field_and_reaches_no_schema() -> None:
    """Plan 2.4: never persisted, serialized or hashed; no model carries it."""
    for path, contents in render_schema_files().items():
        assert b"MonotonicInstant" not in contents, path
    assert not hasattr(MonotonicInstant, "model_validate")
    assert not hasattr(MonotonicInstant, "model_json_schema")
    assert not hasattr(MonotonicInstant, "__pydantic_core_schema__")
