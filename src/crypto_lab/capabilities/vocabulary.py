"""The closed ``capabilities/v1`` capability vocabulary.

Specification section 13.1 fixes the initial vocabulary at exactly the
twenty-six names below: four market, two direction, four data, six execution,
three portfolio, four research, and three runtime. Membership is exact string
equality against a closed set. There is deliberately no alias table, no prefix
match, no case folding, and no engine-name or adapter-name inference: section
13.2 states that "absence is not interpreted as native support" and that
"unknown capability names or overlapping declarations invalidate the descriptor",
and section 11.3 states that capabilities "are not inferred from the engine
name". Any of those conveniences would let an adapter obtain support it never
declared.

``runtime.live``, ``direction.short``, ``market.margin``, and ``market.futures``
are present on purpose. Section 13.1 makes them descriptive vocabulary so a
future runtime can be described without a schema break, and section 13.3 rejects
a *request* containing one of them before resolution. Presence in the vocabulary
is not a feature flag: ``crypto_lab.capabilities.policy`` holds the prohibition.
"""

from __future__ import annotations

from typing import ClassVar

from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion

CAPABILITY_VOCABULARY_VERSION: VocabularyVersion = "capabilities/v1"


class CapabilityVocabulary:
    """The closed name set of one vocabulary version.

    Stateless by construction, following the ``StrategyLoader`` precedent:
    ``__slots__`` is empty and every member is a class-level immutable value, so
    there is no cache, no registry, and no plugin surface an instance could carry.
    Plan section 5.4 forbids a global mutable registry precisely because it would
    make resolution depend on call order.
    """

    __slots__ = ()

    version: ClassVar[VocabularyVersion] = CAPABILITY_VOCABULARY_VERSION
    #: Canonically sorted, so any collection derived from it is deterministically
    #: ordered without a second sort key.
    names: ClassVar[tuple[CapabilityName, ...]] = (
        "data.ohlcv",
        "data.order_book_l2",
        "data.quotes",
        "data.trades",
        "direction.long",
        "direction.short",
        "execution.bar_limit",
        "execution.bar_market",
        "execution.event_driven",
        "execution.maker_orders",
        "execution.multiple_open_orders",
        "execution.partial_fills",
        "market.equities",
        "market.futures",
        "market.margin",
        "market.spot",
        "portfolio.multi_asset",
        "portfolio.multi_venue",
        "portfolio.single_asset",
        "research.monte_carlo",
        "research.optimization",
        "research.parameter_sweep",
        "research.walk_forward",
        "runtime.backtest",
        "runtime.live",
        "runtime.paper",
    )
    _members: ClassVar[frozenset[str]] = frozenset(names)

    @staticmethod
    def contains(name: str) -> bool:
        """Return whether ``name`` is exactly a member of this vocabulary."""
        return name in CapabilityVocabulary._members
