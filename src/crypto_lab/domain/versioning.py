"""Stable semantic-version primitive shared across canonical boundaries."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, StringConstraints, WithJsonSchema

from crypto_lab.domain.identifiers import exact_string_schema

SEMANTIC_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_SEMANTIC_VERSION = re.compile(SEMANTIC_VERSION_PATTERN)


def parse_semantic_version(value: str) -> tuple[int, int, int]:
    """Return numeric stable semantic-version components."""
    matched = _SEMANTIC_VERSION.fullmatch(value)
    if matched is None:
        raise ValueError("version must be stable canonical MAJOR.MINOR.PATCH")
    major, minor, patch = matched.groups()
    return int(major), int(minor), int(patch)


def _validate_semantic_version(value: str) -> str:
    parse_semantic_version(value)
    return value


type SemanticVersion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=64,
        pattern=SEMANTIC_VERSION_PATTERN,
    ),
    AfterValidator(_validate_semantic_version),
    WithJsonSchema(
        exact_string_schema(
            SEMANTIC_VERSION_PATTERN,
            min_length=5,
            max_length=64,
        )
    ),
]
