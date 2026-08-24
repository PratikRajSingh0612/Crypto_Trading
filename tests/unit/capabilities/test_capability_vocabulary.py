"""The closed ``capabilities/v1`` vocabulary.

Specification section 13.1 fixes exactly twenty-six names across seven
categories. Section 13.2 adds the rule that makes closure matter: "Absence is not
interpreted as native support", and "Unknown capability names or overlapping
declarations invalidate the descriptor". Section 11.3 states that capabilities are
never inferred from an engine name.
"""

from __future__ import annotations

import pytest

from crypto_lab.capabilities.vocabulary import (
    CAPABILITY_VOCABULARY_VERSION,
    CapabilityVocabulary,
)

# Transcribed from specification section 13.1, category by category, so the test
# data is the specification's grouping rather than a copy of the implementation's
# sorted tuple. A transcription error in either place shows up as a failure.
_MARKET = ("market.spot", "market.margin", "market.futures", "market.equities")
_DIRECTION = ("direction.long", "direction.short")
_DATA = ("data.ohlcv", "data.trades", "data.quotes", "data.order_book_l2")
_EXECUTION = (
    "execution.bar_market",
    "execution.bar_limit",
    "execution.event_driven",
    "execution.maker_orders",
    "execution.partial_fills",
    "execution.multiple_open_orders",
)
_PORTFOLIO = (
    "portfolio.single_asset",
    "portfolio.multi_asset",
    "portfolio.multi_venue",
)
_RESEARCH = (
    "research.parameter_sweep",
    "research.optimization",
    "research.monte_carlo",
    "research.walk_forward",
)
_RUNTIME = ("runtime.backtest", "runtime.paper", "runtime.live")
_CATEGORIES = (
    ("market", _MARKET, 4),
    ("direction", _DIRECTION, 2),
    ("data", _DATA, 4),
    ("execution", _EXECUTION, 6),
    ("portfolio", _PORTFOLIO, 3),
    ("research", _RESEARCH, 4),
    ("runtime", _RUNTIME, 3),
)
_EXPECTED = (
    _MARKET + _DIRECTION + _DATA + _EXECUTION + _PORTFOLIO + _RESEARCH + _RUNTIME
)


def test_the_vocabulary_is_exactly_the_twenty_six_specification_names() -> None:
    assert len(CapabilityVocabulary.names) == 26
    assert set(CapabilityVocabulary.names) == set(_EXPECTED)
    assert len(set(_EXPECTED)) == 26


@pytest.mark.parametrize(("prefix", "members", "count"), _CATEGORIES)
def test_each_category_contributes_exactly_its_specification_count(
    prefix: str,
    members: tuple[str, ...],
    count: int,
) -> None:
    """The 4/2/4/6/3/4/3 split the plan's Task 6 section states literally.

    Asserting the total alone would pass if one category lost a name and another
    gained one.
    """
    assert len(members) == count
    observed = tuple(
        name for name in CapabilityVocabulary.names if name.startswith(f"{prefix}.")
    )
    assert len(observed) == count
    assert set(observed) == set(members)


def test_the_canonical_order_is_sorted_and_duplicate_free() -> None:
    """Ordering is deterministic, so a serialized reason list cannot vary."""
    assert CapabilityVocabulary.names == tuple(sorted(CapabilityVocabulary.names))
    assert len(set(CapabilityVocabulary.names)) == len(CapabilityVocabulary.names)


def test_the_vocabulary_version_is_the_exact_literal() -> None:
    assert CAPABILITY_VOCABULARY_VERSION == "capabilities/v1"
    assert CapabilityVocabulary.version == "capabilities/v1"


@pytest.mark.parametrize("name", _EXPECTED)
def test_every_approved_name_is_a_member(name: str) -> None:
    assert CapabilityVocabulary.contains(name) is True


@pytest.mark.parametrize(
    "name",
    [
        # Prefix and suffix matching must not admit anything.
        "market",
        "market.",
        "market.spot.perpetual",
        "market.spo",
        "marketspot",
        # Case folding must not admit anything.
        "MARKET.SPOT",
        "Market.Spot",
        # Surrounding whitespace is not trimmed into a match.
        " market.spot",
        "market.spot ",
        # Aliases and near-synonyms are not admitted.
        "market.cash",
        "spot",
        "data.candles",
        "data.ohlc",
        "runtime.simulation",
        # Engine and adapter names are never capability oracles.
        "vectorbt",
        "backtrader",
        "nautilus_trader",
        "engine.vectorbt",
        "adapter.alpha",
        # Stage 5 and adapter-protocol concepts are absent.
        "protocol.describe",
        "experiment.run",
        "credentials.exchange_key",
        "withdrawal.transfer",
        "leverage.two",
        # Exchange-specific capabilities are absent.
        "market.binance",
        "venue.binance",
        "binance.spot",
    ],
)
def test_no_unapproved_name_is_admitted(name: str) -> None:
    assert CapabilityVocabulary.contains(name) is False


def test_the_vocabulary_names_no_prohibited_project_concept() -> None:
    """Plan section 5.1 and AGENTS.md forbid these as project capabilities.

    ``runtime.live``, ``direction.short``, ``market.margin``, and
    ``market.futures`` are deliberately present: specification section 13.1 makes
    them descriptive vocabulary so a future runtime can be described, and section
    13.3 rejects a request containing them before resolution. Credentials,
    withdrawal, leverage, and exchange names have no such descriptive mandate and
    must not appear at all.
    """
    forbidden = ("credential", "withdraw", "leverage", "binance", "exchange", "broker")
    offenders = tuple(
        name
        for name in CapabilityVocabulary.names
        if any(fragment in name for fragment in forbidden)
    )
    assert offenders == ()


def test_the_vocabulary_exposes_no_mutable_container() -> None:
    """A module-level mutable registry would make the resolver order-dependent."""
    assert isinstance(CapabilityVocabulary.names, tuple)
    assert not isinstance(CapabilityVocabulary.names, list)
    with pytest.raises(TypeError):
        CapabilityVocabulary.names[0] = "market.spot"  # type: ignore[index]


def test_the_vocabulary_carries_no_instance_state() -> None:
    """Stateless by construction, following the ``StrategyLoader`` precedent."""
    assert CapabilityVocabulary.__slots__ == ()
    with pytest.raises(AttributeError):
        CapabilityVocabulary().cached = True  # type: ignore[attr-defined]
