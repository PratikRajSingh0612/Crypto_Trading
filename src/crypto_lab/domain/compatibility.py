"""The four-way compatibility outcome, owned by ``domain``.

Relocated verbatim from ``crypto_lab.capabilities.models`` (Stage 5 plan
sections 2.5 and 3.3): the frozen ``SlotCompatibility`` record and the
aggregation inputs of Stage 5 need a domain-typed outcome, and ``domain`` may
not import ``capabilities``. ``capabilities.models`` re-exports the class, so
every existing import site is unchanged. It renders into the released
``capabilities/compatibility-result-v1`` schema by bare class name with a
``description`` taken from its docstring, so the name, the four members in
order and the docstring below are byte-for-byte those of the merged class.
"""

from __future__ import annotations

from enum import StrEnum


class CompatibilityOutcome(StrEnum):
    """The four approved outcomes of specification sections 11.5 and 13.4.

    ``NOT_APPLICABLE`` and ``UNAVAILABLE`` are distinct on purpose and neither may
    absorb the other: section 13.4 requires an unrunnable-but-compatible adapter to
    record "a terminal availability outcome" and forbids mislabelling it as a
    strategy failure.
    """

    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_APPROXIMATION = "SUPPORTED_WITH_APPROXIMATION"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
