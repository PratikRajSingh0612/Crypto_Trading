"""Property tests for strategy content identity.

Two meaningful properties, per the Task 5 test-first sequence:

**Formatting invariance.** A bounded valid specification is generated as plain data,
**rendered back to YAML source text** under randomised mapping order, inserted
comments, blank lines, block-versus-flow style, and quoting style, and every variant
is loaded through `StrategyLoader`. All variants must share one `content_hash`.
Permuting keys in already canonical JSON would be tautological — `canonical_json_text`
sorts keys and a validated `StrategySpec` has fixed field order — so the variation is
applied to the *source text*, which is the claim plan section 5.5 actually makes.

**Material sensitivity.** Two specifications are generated differing in exactly one
material field. The test first proves that exactly that field differs, by comparing
the two validated dumps field by field, and only then asserts the hashes differ. No
assertion compares an object with itself.

Generators draw **plain data** only — text, integers, booleans, and members of fixed
vocabularies — and every model is constructed in the test body. `st.builds` is never
called inside the draw phase.
"""

from __future__ import annotations

import copy
import string
from datetime import UTC, datetime
from typing import Any, NamedTuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.results import Success
from crypto_lab.strategy.loader import StrategyLoader
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import StrategyVersion

_OBSERVED_AT = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)
_SOURCE_NAME = "generated.strategy.yaml"

_TIMEFRAMES = ("1m", "5m", "15m", "1h", "4h", "1d", "1w")
_FRACTIONS = ("1", "0.75", "0.5", "0.25", "0.125")
_LEVELS = ("LEVEL_1", "LEVEL_2", "LEVEL_3")
_VENUES = ("BINANCE", "COINBASE", "KRAKEN")
_BASES = ("BTC", "ETH", "SOL")
_QUOTES = ("USDT", "USDC", "EUR")
_AUTHORED_AT = ("2026-01-02T03:04:05Z", "2026-07-08T09:10:11Z")
_VERSIONS = ("1.0.0", "1.9.0", "1.10.0", "2.0.0")

# The strategy's declared capability requirements. Fixed plain data: Task 6 owns the
# vocabulary, so varying capability names here would test nothing this task defines.
_CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "schema_version": "1.0.0",
        "capability": "market.spot",
        "required": True,
        "minimum_semantics": "capabilities/v1",
        "approximation_policy": "REJECT",
        "comparison_levels": ["LEVEL_1", "LEVEL_2"],
    },
    {
        "schema_version": "1.0.0",
        "capability": "direction.long",
        "required": True,
        "minimum_semantics": "capabilities/v1",
        "approximation_policy": "REJECT",
        "comparison_levels": ["LEVEL_1", "LEVEL_2"],
    },
    {
        "schema_version": "1.0.0",
        "capability": "data.ohlcv",
        "required": True,
        "minimum_semantics": "capabilities/v1",
        "approximation_policy": "REJECT",
        "comparison_levels": ["LEVEL_1", "LEVEL_2"],
    },
)


# --- Plain-data generators -------------------------------------------------

# Lowercase letters only, and every drawn word is joined to a fixed prefix by an
# underscore. That makes every generated identifier valid against
# `NormalizedIdentifier`, pairwise distinct across namespaces by prefix alone, and
# provably outside the YAML 1.1 plain-scalar rejection table of plan section 5.2:
# no table entry contains an underscore, so no generated name can collide with
# `yes`, `off`, `null`, `true`, or any other ambiguous plain word. Without that,
# a drawn identifier would load only when quoted and formatting invariance would be
# false rather than merely untested.
_WORD = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=6)
_LABEL = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=1,
    max_size=24,
)
_HEX = st.integers(min_value=0, max_value=2**32 - 1)


def _named(prefix: str, word: str) -> str:
    return f"{prefix}_{word}"


def _uuid4_text(seed: int) -> str:
    return f"{seed:08x}-1234-4234-8234-123456789abc"


class _Fields(NamedTuple):
    """Every generated material input, as plain data."""

    identity_seed: int
    family: str
    feature_one: str
    feature_two: str
    parameter_one: str
    parameter_two: str
    author: str
    display_name: str
    description: str
    timeframe: str
    venue: str
    base: str
    quote: str
    fast_period: int
    slow_period: int
    warm_up_one: int
    warm_up_two: int
    minimum_bars: int
    fraction: str
    maximum_level: str
    authored_at: str
    extension_count: int
    extension_version: str


def _mapping(fields: _Fields) -> dict[str, Any]:
    """Build one complete, valid strategy document as plain data.

    Parameterising a known-good shape rather than generating arbitrary feature
    graphs is deliberate: a draw that failed strict-model, static, or graph
    validation would make both properties vacuous, because the loader would return
    `Failure` and there would be no hash to compare.
    """
    return {
        "schema_version": "1.0.0",
        "strategy_id": f"strat_{_uuid4_text(fields.identity_seed)}",
        "display_name": fields.display_name,
        "description": fields.description,
        "strategy_family": fields.family,
        "market_type": "SPOT",
        "direction": "LONG",
        "timeframe": fields.timeframe,
        "universe": {
            "kind": "STATIC",
            "instruments": [f"{fields.venue}:{fields.base}/{fields.quote}:SPOT"],
        },
        "required_capabilities": [copy.deepcopy(item) for item in _CAPABILITIES],
        "parameters": {
            fields.parameter_one: {
                "value_type": "INTEGER",
                "value": fields.fast_period,
                "minimum": 1,
            },
            fields.parameter_two: {
                "value_type": "INTEGER",
                "value": fields.slow_period,
                "minimum": 1,
            },
        },
        "features": [
            {
                "id": fields.feature_one,
                "operation": "indicator.sma/v1",
                "inputs": ["bar.close"],
                "parameters": {"period": fields.parameter_one},
                "output_type": "DECIMAL",
                "warm_up_bars": fields.warm_up_one,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
            {
                "id": fields.feature_two,
                "operation": "indicator.sma/v1",
                "inputs": ["bar.close"],
                "parameters": {"period": fields.parameter_two},
                "output_type": "DECIMAL",
                "warm_up_bars": fields.warm_up_two,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
        ],
        "entry_rules": [
            {
                "id": "enter_rule",
                "expression": {
                    "op": "crosses_above",
                    "left": {"op": "ref", "id": fields.feature_one, "bars_ago": 0},
                    "right": {"op": "ref", "id": fields.feature_two, "bars_ago": 0},
                },
            }
        ],
        "exit_rules": [
            {
                "id": "exit_rule",
                "expression": {
                    "op": "crosses_below",
                    "left": {"op": "ref", "id": fields.feature_one, "bars_ago": 0},
                    "right": {"op": "ref", "id": fields.feature_two, "bars_ago": 0},
                },
            }
        ],
        "sizing_intent": {
            "method": "FRACTION_OF_AVAILABLE_QUOTE",
            "fraction": fields.fraction,
        },
        "risk_assumptions": {"leverage": "1", "shorting_allowed": False},
        "warm_up_requirements": {"minimum_bars": fields.minimum_bars},
        "comparison_requirements": {"maximum_level": fields.maximum_level},
        "supported_approximation_policy": {"default": "REJECT"},
        "engine_extensions": [
            _extension(index, fields.extension_version)
            for index in range(fields.extension_count)
        ],
        "authoring_metadata": {
            "author": fields.author,
            "created_at_utc": fields.authored_at,
        },
    }


def _extension(index: int, version: str) -> dict[str, Any]:
    """Return one declared extension.

    ``adapter_name`` is unique by index, so the model's declared-once rule is
    satisfied for every drawn count.
    """
    return {
        "adapter_name": f"adapter.slot{index}",
        "extension_id": "ext.declared",
        "version": version,
        "content_hash": f"{index + 1:064x}",
        "purpose": "Declares a lifecycle hook only; the core never loads it.",
        "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
        "economic_effect": "NONE",
    }


_FIELD_STRATEGIES: dict[str, st.SearchStrategy[Any]] = {
    "identity_seed": _HEX,
    "family": _WORD,
    "feature_one": _WORD,
    "feature_two": _WORD,
    "parameter_one": _WORD,
    "parameter_two": _WORD,
    "author": _WORD,
    "display_name": _LABEL,
    "description": _LABEL,
    "timeframe": st.sampled_from(_TIMEFRAMES),
    "venue": st.sampled_from(_VENUES),
    "base": st.sampled_from(_BASES),
    "quote": st.sampled_from(_QUOTES),
    "fast_period": st.integers(min_value=1, max_value=512),
    "slow_period": st.integers(min_value=1, max_value=512),
    "warm_up_one": st.integers(min_value=0, max_value=1024),
    "warm_up_two": st.integers(min_value=0, max_value=1024),
    "minimum_bars": st.integers(min_value=0, max_value=4095),
    "fraction": st.sampled_from(_FRACTIONS),
    "maximum_level": st.sampled_from(_LEVELS),
    "authored_at": st.sampled_from(_AUTHORED_AT),
    "extension_count": st.integers(min_value=0, max_value=3),
    "extension_version": st.sampled_from(_VERSIONS),
}
_DRAWN_FIELDS = st.tuples(*(_FIELD_STRATEGIES[name] for name in _Fields._fields))


def _fields(drawn: tuple[Any, ...]) -> _Fields:
    """Assemble the drawn plain values in the test body, never in the draw phase."""
    values = dict(zip(_Fields._fields, drawn, strict=True))
    return _Fields(
        identity_seed=values["identity_seed"],
        family=_named("fam", values["family"]),
        feature_one=_named("fa", values["feature_one"]),
        feature_two=_named("fb", values["feature_two"]),
        parameter_one=_named("pa", values["parameter_one"]),
        parameter_two=_named("pb", values["parameter_two"]),
        author=_named("au", values["author"]),
        display_name=values["display_name"],
        description=values["description"],
        timeframe=values["timeframe"],
        venue=values["venue"],
        base=values["base"],
        quote=values["quote"],
        fast_period=values["fast_period"],
        slow_period=values["slow_period"],
        warm_up_one=values["warm_up_one"],
        warm_up_two=values["warm_up_two"],
        minimum_bars=values["minimum_bars"],
        fraction=values["fraction"],
        maximum_level=values["maximum_level"],
        authored_at=values["authored_at"],
        extension_count=values["extension_count"],
        extension_version=values["extension_version"],
    )


# --- A deterministic YAML source renderer ---------------------------------

_PLAIN_SAFE = frozenset(string.ascii_letters + string.digits + "_./-")
# Every purely alphabetic word the plan's plain-scalar rejection table matches, plus
# the two canonical booleans. A generated identifier can never be one of these
# because each carries an underscore, but a fixed vocabulary value could be, so the
# renderer checks rather than assumes.
_AMBIGUOUS_PLAIN = frozenset(
    {
        "y",
        "Y",
        "yes",
        "Yes",
        "YES",
        "n",
        "N",
        "no",
        "No",
        "NO",
        "on",
        "On",
        "ON",
        "off",
        "Off",
        "OFF",
        "true",
        "True",
        "TRUE",
        "false",
        "False",
        "FALSE",
        "null",
        "Null",
        "NULL",
    }
)


def _is_plain_safe(text: str) -> bool:
    """True when this text can be written as a plain YAML scalar and read back.

    Requires a leading letter, so no numeric, sexagesimal, or date-shaped text is
    ever left unquoted; excludes every flow indicator and the comment character, so
    the same judgement holds inside a flow collection.
    """
    if not text or text[0] not in string.ascii_letters:
        return False
    if text in _AMBIGUOUS_PLAIN:
        return False
    return all(character in _PLAIN_SAFE for character in text)


class _Style(NamedTuple):
    decisions: tuple[int, ...]
    allow_flow: bool
    allow_comments: bool
    quote_mode: int | None


class _Renderer:
    """Render plain data as YAML source text under explicit style choices.

    Decisions are consumed from a fixed cyclic sequence, so one style renders one
    mapping to exactly one text.
    """

    def __init__(self, style: _Style) -> None:
        self._style = style
        self._index = 0

    def _next(self) -> int:
        decisions = self._style.decisions
        value = decisions[self._index % len(decisions)]
        self._index += 1
        return value

    def _scalar(self, value: object) -> str:
        if value is True:
            return "true"
        if value is False:
            return "false"
        if isinstance(value, int):
            return str(value)
        text = str(value)
        mode = self._style.quote_mode
        choice = self._next() % 3 if mode is None else mode
        if choice == 2 and _is_plain_safe(text):
            return text
        if choice == 1 and '"' not in text and "\\" not in text:
            return f'"{text}"'
        # Single quoting is always available: the only escape inside a
        # single-quoted YAML scalar is a doubled quote.
        return "'" + text.replace("'", "''") + "'"

    def _order(self, keys: tuple[str, ...]) -> tuple[str, ...]:
        if not keys:
            return keys
        shift = self._next() % len(keys)
        return keys[shift:] + keys[:shift]

    def _flow(self, value: object) -> str:
        if isinstance(value, dict):
            keys = self._order(tuple(value))
            entries = ", ".join(f"{key}: {self._flow(value[key])}" for key in keys)
            return "{" + entries + "}"
        if isinstance(value, list):
            return "[" + ", ".join(self._flow(item) for item in value) + "]"
        return self._scalar(value)

    def _decorate(self, pad: str, lines: list[str]) -> None:
        if not self._style.allow_comments:
            return
        choice = self._next() % 5
        if choice == 0:
            lines.append(f"{pad}# a harmless comment carrying no meaning")
        elif choice == 1:
            lines.append("")
        elif choice == 2:
            lines.append(f"{pad}#")

    def _trail(self, line: str) -> str:
        if not self._style.allow_comments:
            return line
        return f"{line}  # trailing" if self._next() % 6 == 0 else line

    def _entry(
        self,
        prefix: str,
        child: object,
        indent: int,
        lines: list[str],
    ) -> None:
        if isinstance(child, dict | list):
            if not child:
                lines.append(f"{prefix} {'{}' if isinstance(child, dict) else '[]'}")
                return
            if self._style.allow_flow and self._next() % 3 == 0:
                lines.append(self._trail(f"{prefix} {self._flow(child)}"))
                return
            lines.append(prefix)
            self._block(child, indent + 2, lines)
            return
        lines.append(self._trail(f"{prefix} {self._scalar(child)}"))

    def _block(self, value: object, indent: int, lines: list[str]) -> None:
        pad = " " * indent
        if isinstance(value, dict):
            for key in self._order(tuple(value)):
                self._decorate(pad, lines)
                self._entry(f"{pad}{key}:", value[key], indent, lines)
            return
        if not isinstance(value, list):  # pragma: no cover - callers pass collections
            raise TypeError("block rendering expects a mapping or a sequence")
        for item in value:
            self._decorate(pad, lines)
            self._entry(f"{pad}-", item, indent, lines)

    def render(self, mapping: dict[str, Any]) -> bytes:
        lines: list[str] = []
        self._block(mapping, 0, lines)
        return ("\n".join(lines) + "\n").encode("utf-8")


# Two deliberately contrasting fixed styles, always rendered alongside the drawn
# ones so that no example can consist of byte-identical variants and pass
# vacuously. The first is block-only, comment-free, and plain where plain is legal;
# the second permits flow collections, inserts comments and blank lines, and single
# quotes every string.
_BLOCK_PLAIN = _Style(
    decisions=(0,),
    allow_flow=False,
    allow_comments=False,
    quote_mode=2,
)
_FLOW_QUOTED = _Style(
    decisions=(0, 1, 2, 3, 4),
    allow_flow=True,
    allow_comments=True,
    quote_mode=0,
)

_DRAWN_STYLE = st.tuples(
    st.lists(st.integers(min_value=0, max_value=5), min_size=1, max_size=12),
    st.booleans(),
    st.booleans(),
    st.sampled_from([None, 0, 1, 2]),
)


def _style(drawn: tuple[Any, ...]) -> _Style:
    return _Style(
        decisions=tuple(drawn[0]),
        allow_flow=drawn[1],
        allow_comments=drawn[2],
        quote_mode=drawn[3],
    )


def _load(source: bytes) -> StrategyVersion:
    outcome = StrategyLoader.load(source, _SOURCE_NAME, _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome
    return outcome.value


# The formatting-invariance property performs three complete `StrategyLoader.load`
# calls per example — safe YAML decode, strict model construction, static validation,
# and graph validation, over a real document each time. That is genuine work, and its
# wall-clock time tracks machine load rather than anything about the code.
#
# **Measured evidence for this one test, not a precaution.** With the deadline in
# force and three other `tests\unit\strategy` sessions running concurrently,
# Hypothesis reported:
#
#   FlakyFailure: Unreliable test timings! On an initial run, this test took
#   280.39ms, which exceeded the deadline of 200.00ms, but on a subsequent run it
#   took 41.39 ms, which did not.
#
# The same property passes 3000 examples with the deadline off, so there is no
# falsifying draw: the deadline was measuring contention. Removing it here costs
# nothing that matters — `max_examples` stays at the default, shrinking is untouched,
# no health check is suppressed, and every assertion still runs on every example.
#
# **Deliberately applied to this test alone.** It was briefly applied to the two
# material-sensitivity properties as well. That was wrong twice over: no timing
# measurement covered them, and `deadline=None` does not suppress
# `HealthCheck.too_slow`, which is the mode they actually exhibit under the same
# contention ("Input generation is slow: Hypothesis only generated 2 valid inputs
# after 1.21 seconds"). A suppression that is both unmeasured and ineffective is
# worse than none, so it was removed rather than widened. No `too_slow` suppression
# is added here: that mode appeared only under deliberate four-way oversubscription,
# which no project gate creates, and plan section 11.1 requires measured evidence
# plus fresh independent approval before one is introduced.
#
# Plan section 11.1 forbids a global suppression, a raised global deadline, and a
# project-wide profile. A single per-test decorator is none of those.
_TIMING_INSENSITIVE = settings(deadline=None)


# --- Property A: formatting invariance ------------------------------------


@_TIMING_INSENSITIVE
@given(drawn=_DRAWN_FIELDS, drawn_style=_DRAWN_STYLE)
def test_semantically_equal_yaml_variants_share_one_content_hash(
    drawn: tuple[Any, ...],
    drawn_style: tuple[Any, ...],
) -> None:
    mapping = _mapping(_fields(drawn))
    renderings = [
        _Renderer(style).render(mapping)
        for style in (_BLOCK_PLAIN, _FLOW_QUOTED, _style(drawn_style))
    ]
    # Non-vacuity: the two fixed styles cannot agree, so the loader is genuinely
    # shown different source bytes carrying the same meaning.
    assert len(set(renderings)) >= 2
    versions = [_load(source) for source in renderings]
    assert len({version.content_hash for version in versions}) == 1
    assert len({version.strategy_version_id for version in versions}) == 1
    # Everything except provenance is byte-identical. Provenance is deliberately
    # excluded rather than asserted equal: `source_bytes_sha256` and
    # `source_byte_length` are functions of the source text, so they *must* differ
    # between variants — that they do not reach identity is the whole point.
    identities = {
        canonical_json_bytes(
            version.model_dump(mode="json", exclude={"source_provenance"})
        )
        for version in versions
    }
    assert len(identities) == 1


@given(drawn=_DRAWN_FIELDS)
def test_a_comment_and_key_order_variant_is_never_byte_identical(
    drawn: tuple[Any, ...],
) -> None:
    """Guards the renderer itself: the variation is real, not a no-op."""
    mapping = _mapping(_fields(drawn))
    plain = _Renderer(_BLOCK_PLAIN).render(mapping)
    decorated = _Renderer(_FLOW_QUOTED).render(mapping)
    assert plain != decorated
    assert b"#" not in plain
    assert b"#" in decorated
    assert b"{" in decorated or b"[" in decorated


# --- Property B: material sensitivity -------------------------------------


def _mutate_strategy_id(mapping: dict[str, Any]) -> None:
    identity = mapping["strategy_id"]
    head = "0" if identity[6] != "0" else "1"
    mapping["strategy_id"] = f"strat_{head}{identity[7:]}"


def _mutate_display_name(mapping: dict[str, Any]) -> None:
    mapping["display_name"] = f"{mapping['display_name']}Z"


def _mutate_description(mapping: dict[str, Any]) -> None:
    mapping["description"] = f"{mapping['description']}Z"


def _mutate_strategy_family(mapping: dict[str, Any]) -> None:
    mapping["strategy_family"] = f"{mapping['strategy_family']}z"


def _mutate_timeframe(mapping: dict[str, Any]) -> None:
    mapping["timeframe"] = _rotate(_TIMEFRAMES, mapping["timeframe"])


def _mutate_universe(mapping: dict[str, Any]) -> None:
    instrument = mapping["universe"]["instruments"][0]
    venue, remainder = instrument.split(":", 1)
    mapping["universe"]["instruments"] = [f"{venue}X:{remainder}"]


def _mutate_required_capabilities(mapping: dict[str, Any]) -> None:
    for requirement in mapping["required_capabilities"]:
        if requirement["capability"] == "market.spot":
            requirement["required"] = False
            return
    raise AssertionError("the fixed capability list must contain market.spot")


def _mutate_parameters(mapping: dict[str, Any]) -> None:
    name = next(iter(mapping["parameters"]))
    mapping["parameters"][name]["value"] += 1


def _mutate_features(mapping: dict[str, Any]) -> None:
    mapping["features"][0]["warm_up_bars"] += 1


def _mutate_entry_rules(mapping: dict[str, Any]) -> None:
    mapping["entry_rules"][0]["id"] = "enter_rulez"


def _mutate_exit_rules(mapping: dict[str, Any]) -> None:
    mapping["exit_rules"][0]["expression"]["op"] = "less_than"


def _mutate_sizing_intent(mapping: dict[str, Any]) -> None:
    mapping["sizing_intent"]["fraction"] = _rotate(
        _FRACTIONS,
        mapping["sizing_intent"]["fraction"],
    )


def _mutate_warm_up_requirements(mapping: dict[str, Any]) -> None:
    mapping["warm_up_requirements"]["minimum_bars"] += 1


def _mutate_comparison_requirements(mapping: dict[str, Any]) -> None:
    mapping["comparison_requirements"]["maximum_level"] = _rotate(
        _LEVELS,
        mapping["comparison_requirements"]["maximum_level"],
    )


def _mutate_engine_extensions(mapping: dict[str, Any]) -> None:
    declaration = _extension(9, "3.0.0")
    declaration["adapter_name"] = "adapter.appended"
    mapping["engine_extensions"] = [*mapping["engine_extensions"], declaration]


def _mutate_authoring_metadata(mapping: dict[str, Any]) -> None:
    mapping["authoring_metadata"]["created_at_utc"] = _rotate(
        _AUTHORED_AT,
        mapping["authoring_metadata"]["created_at_utc"],
    )


def _rotate(vocabulary: tuple[str, ...], current: str) -> str:
    return vocabulary[(vocabulary.index(current) + 1) % len(vocabulary)]


_MUTATIONS = {
    "strategy_id": _mutate_strategy_id,
    "display_name": _mutate_display_name,
    "description": _mutate_description,
    "strategy_family": _mutate_strategy_family,
    "timeframe": _mutate_timeframe,
    "universe": _mutate_universe,
    "required_capabilities": _mutate_required_capabilities,
    "parameters": _mutate_parameters,
    "features": _mutate_features,
    "entry_rules": _mutate_entry_rules,
    "exit_rules": _mutate_exit_rules,
    "sizing_intent": _mutate_sizing_intent,
    "warm_up_requirements": _mutate_warm_up_requirements,
    "comparison_requirements": _mutate_comparison_requirements,
    "engine_extensions": _mutate_engine_extensions,
    "authoring_metadata": _mutate_authoring_metadata,
}


def test_the_mutation_table_names_only_specification_fields() -> None:
    assert set(_MUTATIONS) <= set(StrategySpec.model_fields)


@given(drawn=_DRAWN_FIELDS, field_name=st.sampled_from(sorted(_MUTATIONS)))
def test_two_specifications_differing_in_one_material_field_hash_differently(
    drawn: tuple[Any, ...],
    field_name: str,
) -> None:
    baseline_mapping = _mapping(_fields(drawn))
    mutated_mapping = copy.deepcopy(baseline_mapping)
    _MUTATIONS[field_name](mutated_mapping)

    baseline = _load(canonical_json_bytes(baseline_mapping))
    mutated = _load(canonical_json_bytes(mutated_mapping))

    # Prove the intended field actually differs and every other material field is
    # equal, before drawing any conclusion from the hashes.
    dumped_baseline = baseline.strategy_spec.model_dump(mode="json")
    dumped_mutated = mutated.strategy_spec.model_dump(mode="json")
    differing = {
        name
        for name in StrategySpec.model_fields
        if dumped_baseline[name] != dumped_mutated[name]
    }
    assert differing == {field_name}

    assert baseline.content_hash != mutated.content_hash
    assert baseline.strategy_version_id != mutated.strategy_version_id


@given(drawn=_DRAWN_FIELDS)
def test_an_unmutated_reload_is_identical_rather_than_merely_equal_to_itself(
    drawn: tuple[Any, ...],
) -> None:
    """The control case for the property above: two independent loads, one hash."""
    mapping = _mapping(_fields(drawn))
    first = _load(canonical_json_bytes(mapping))
    second = _load(canonical_json_bytes(copy.deepcopy(mapping)))
    assert first is not second
    assert first.content_hash == second.content_hash


# --- Renderer self-checks -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("bar", True),
        ("fa_x", True),
        ("indicator.sma/v1", True),
        ("LEVEL_1", True),
        ("yes", False),
        ("off", False),
        ("null", False),
        ("true", False),
        ("1h", False),
        ("1.0.0", False),
        ("", False),
        ("BINANCE:BTC/USDT:SPOT", False),
        ("has space", False),
    ],
)
def test_the_plain_safety_judgement_is_exact(text: str, expected: bool) -> None:
    assert _is_plain_safe(text) is expected
