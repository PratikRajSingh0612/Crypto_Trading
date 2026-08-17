"""The cross-engine comparison-level vocabulary.

Defined in `domain` rather than in `capabilities`, because `ComparisonLevel` is
also a field of `ExperimentSpec`, `MetricValue`, and `EngineRunRequest`, and
`EngineRunRequest` belongs to `adapters`. Leaving it in `capabilities` would
force an `adapters -> capabilities` edge at a later stage.
"""

from __future__ import annotations

from enum import StrEnum


class ComparisonLevel(StrEnum):
    """Specification sections 25.1 to 25.3.

    Level 2 requires Level 1, and Level 3 does not expect numerically identical
    results. Member values sort in numeric order, so a sorted collection is also
    canonically ordered.
    """

    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"
