"""Capability naming primitives shared by strategy, capabilities, and adapters.

Relocated here from `adapters/descriptors.py` so `capabilities` and `strategy`
need no inward dependency on `adapters`. Task 6 deletes the definitions there
and re-exports these, and `schema-generate-check` must keep
`adapter-descriptor-v1.schema.json` byte-identical across that swap.

Both aliases are therefore plain `Annotated` assignments rather than PEP 695
`type` statements, matching the form they are relocated from: a `type` alias
emits its own `$def` and `$ref`, which would change the generated descriptor
schema even though the constraints were unchanged.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, WithJsonSchema

from crypto_lab.domain.identifiers import exact_string_schema

CAPABILITY_NAME_PATTERN = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
VOCABULARY_VERSION_PATTERN = r"^capabilities/v[1-9][0-9]*$"

CapabilityName = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=CAPABILITY_NAME_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            CAPABILITY_NAME_PATTERN,
            min_length=3,
            max_length=128,
        )
    ),
]
VocabularyVersion = Annotated[
    str,
    StringConstraints(strict=True, pattern=VOCABULARY_VERSION_PATTERN, max_length=32),
    WithJsonSchema(
        exact_string_schema(
            VOCABULARY_VERSION_PATTERN,
            max_length=32,
        )
    ),
]
