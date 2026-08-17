"""Discriminated success-or-diagnostics result value."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import Diagnostic

MAX_RESULT_DIAGNOSTICS = 256


class Success[T](CanonicalModel):
    """A completed operation carrying its value and no diagnostics."""

    outcome: Literal["SUCCESS"]
    value: T


class Failure(CanonicalModel):
    """A rejected operation carrying at least one diagnostic and no value."""

    outcome: Literal["FAILURE"]
    diagnostics: tuple[Diagnostic, ...] = Field(
        min_length=1,
        max_length=MAX_RESULT_DIAGNOSTICS,
    )


type Result[T] = Annotated[Success[T] | Failure, Field(discriminator="outcome")]
