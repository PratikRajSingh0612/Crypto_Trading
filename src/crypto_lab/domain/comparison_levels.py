"""The cross-engine comparison-level vocabulary.

Defined in `domain` rather than in `capabilities`, because `ComparisonLevel` is
also a field of `ExperimentSpec`, `MetricValue`, and `EngineRunRequest`, and
`EngineRunRequest` belongs to `adapters`. Leaving it in `capabilities` would
force an `adapters -> capabilities` edge at a later stage.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import JsonValue


class ComparisonLevel(StrEnum):
    """Specification sections 25.1 to 25.3.

    Level 2 requires Level 1, and Level 3 does not expect numerically identical
    results. Member values sort in numeric order, so a sorted collection is also
    canonically ordered.
    """

    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"


def _sorted_level_sets() -> tuple[tuple[str, ...], ...]:
    """Every sorted unique subset of the closed level vocabulary.

    The vocabulary is closed at three members, so the sorted unique subsets are
    exactly eight. That is what makes an ordering rule over a collection of these
    values *finitely* expressible in JSON Schema, which has no ordering keyword:
    the accepted set can simply be enumerated.

    The declaration order is asserted rather than assumed. Every consumer sorts
    with ``key=str``, so if a later member were declared out of alphabetical order
    this would emit arrays the project's own validators reject, and the published
    contract would silently disagree with the runtime.

    Enumerated by bitmask rather than with ``itertools.combinations``:
    ``tests/safety/test_stage3_boundaries.py`` holds a closed import allowlist for
    ``src/``, and ``itertools`` is not on it. Ordering the result by subset size
    and then by member position reproduces ``combinations`` order exactly, so the
    published sequence is deterministic and does not depend on the enumeration
    method.
    """
    values = tuple(level.value for level in ComparisonLevel)
    if values != tuple(sorted(values, key=str)):
        raise RuntimeError("comparison levels must be declared in sorted order")
    subsets = [
        tuple(value for index, value in enumerate(values) if mask & (1 << index))
        for mask in range(1 << len(values))
    ]
    return tuple(sorted(subsets, key=lambda subset: (len(subset), subset)))


SORTED_COMPARISON_LEVEL_SETS: Final[tuple[tuple[str, ...], ...]] = _sorted_level_sets()


def sorted_comparison_level_enum() -> list[JsonValue]:
    """Return the eight sorted level sets as JSON arrays, for a schema ``enum``.

    A fresh list of fresh lists on every call. Two fields publish this value, and
    handing both the same object would let a generated schema mutated in place
    reach the other field's published node.

    Typed as ``JsonValue`` rather than ``list[list[str]]`` because the result goes
    straight into a ``Field(json_schema_extra=...)`` mapping, whose value type is
    ``JsonValue``; ``list`` is invariant, so the concrete spelling would not be
    assignable there without a cast at every call site.
    """
    sets: list[JsonValue] = []
    for subset in SORTED_COMPARISON_LEVEL_SETS:
        members: list[JsonValue] = list(subset)
        sets.append(members)
    return sets
