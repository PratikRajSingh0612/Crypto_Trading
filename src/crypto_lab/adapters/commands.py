"""The adapter command contract (Stage 6 plan section 3.7; specification 8.2, 14.1).

``AdapterCommand`` is the core-owned, configuration-shaped launch contract (trust
class K, unpublished, so it carries no envelope version): the command kind, the
catalog entry that is the sole source of the executable (specification 14.1), the
invocation identity, the core-selected absolute paths the kind requires and the
snapshotted timeout. ``output_path`` is required for ``DESCRIBE`` and ``VALIDATE``
and prohibited for ``RUN``; ``work_dir`` and ``result_path`` are required for
``RUN`` and prohibited otherwise; ``timeout_seconds`` stays within the kind's
bounds. Every path is an absolute local Windows path under the catalog's
``AbsoluteLocalExecutablePath`` rule, checked textually and never resolved or
opened. The command carries no request material by value -- no request, run,
attempt or token field -- so it is never token-bearing, and it never receives a
database handle or an authoritative final path (specification 15.5).

``argument_array`` renders specification 14.1 exactly. The executable itself is
``catalog_entry.executable_path``, prepended by whoever launches; Stage 6 never
launches a process, and no textual relation between ``result_path`` and
``work_dir`` is asserted here, because a lexical check is not a containment proof
(plan 3.3; Stage 7 resolves paths against real roots).
"""

from __future__ import annotations

from typing import Final, Self

from pydantic import Field, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AbsoluteLocalExecutablePath, AdapterCatalogEntry
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    MAX_RUN_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    command_timeout_bounds,
)
from crypto_lab.domain.identifiers import InvocationId
from crypto_lab.domain.lifecycle import CommandKind

#: Specification 14.1: the sub-command verb of each kind, as literals.
_VERBS: Final[dict[CommandKind, str]] = {
    CommandKind.DESCRIBE: "describe",
    CommandKind.VALIDATE: "validate",
    CommandKind.RUN: "run",
}


def _is_missing(value: object) -> bool:
    return value is MISSING


class AdapterCommand(CanonicalModel):
    """One adapter command to launch (plan 3.7); no request material by value."""

    command_kind: CommandKind
    catalog_entry: AdapterCatalogEntry
    invocation_id: InvocationId
    request_path: AbsoluteLocalExecutablePath
    output_path: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
    work_dir: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
    result_path: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
    timeout_seconds: int = Field(ge=MIN_TIMEOUT_SECONDS, le=MAX_RUN_TIMEOUT_SECONDS)

    @model_validator(mode="after")
    def validate_kind_governed_shape(self) -> Self:
        run = self.command_kind is CommandKind.RUN
        if _is_missing(self.output_path) is not run:
            raise ValueError(
                "output_path is required for DESCRIBE and VALIDATE and prohibited "
                "for RUN"
            )
        if _is_missing(self.work_dir) is run:
            raise ValueError("work_dir is required for RUN and prohibited otherwise")
        if _is_missing(self.result_path) is run:
            raise ValueError("result_path is required for RUN and prohibited otherwise")
        bounds = command_timeout_bounds(self.command_kind)
        if not bounds.minimum_seconds <= self.timeout_seconds <= bounds.maximum_seconds:
            raise ValueError(
                f"timeout_seconds must be within {bounds.minimum_seconds}.."
                f"{bounds.maximum_seconds} for {self.command_kind.value}"
            )
        return self


def argument_array(command: AdapterCommand) -> tuple[str, ...]:
    """Specification 14.1 exactly, without the executable (plan 3.7).

    ``("describe", "--request", request_path, "--output", output_path)``,
    ``("validate", "--request", request_path, "--output", output_path)`` or
    ``("run", "--request", request_path, "--work-dir", work_dir, "--result",
    result_path)``. Pure over its argument; nothing is launched.
    """
    if not isinstance(command, AdapterCommand):
        raise TypeError("argument_array takes an AdapterCommand")
    verb = _VERBS[command.command_kind]
    if command.command_kind is CommandKind.RUN:
        return (
            verb,
            "--request",
            command.request_path,
            "--work-dir",
            command.work_dir,
            "--result",
            command.result_path,
        )
    return (verb, "--request", command.request_path, "--output", command.output_path)
