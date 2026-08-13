"""Strict immutable base classes for canonical Project 1 records."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "1.0.0"


class CanonicalModel(BaseModel):
    """Reject coercion, mutation, unknown fields, and invalid defaults."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        validate_default=True,
    )
