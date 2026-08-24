"""Adapter-facing re-export of the relocated structural descriptor contracts.

Plan section 5.7 moved every definition below into ``crypto_lab.domain`` so that
``capabilities`` could consume them without the ``capabilities -> adapters`` edge
specification section 27.1 declares normative and prohibits. This module keeps
specification section 27.1's *Responsibility* column intact -- ``adapters`` still
owns and exposes the descriptor contracts -- while the relocation satisfies its
*Allowed inward dependencies* column. Every existing import site is unchanged.

``__all__`` is mandatory rather than cosmetic: strict mypy implies
``--no-implicit-reexport``, so without it every
``from crypto_lab.adapters.descriptors import ...`` site would fail type checking.
"""

from __future__ import annotations

from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    BoundedText,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)

__all__ = [
    "AdapterDescriptor",
    "BoundedText",
    "CapabilityName",
    "EngineDescriptor",
    "OperatingSystem",
    "SupportedSchemaVersion",
    "VocabularyVersion",
]
