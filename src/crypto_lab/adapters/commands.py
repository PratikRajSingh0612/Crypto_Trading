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

``CommandResult`` (Stage 6 plan section 3.7; specification 14.1 last paragraph) is
the transient projection the Stage 7 supervisor returns for one finished command:
the finalized (terminal) ``CommandInvocationRecord``, the parsed output when the
file was strict-valid, the exact-byte source hash of that file, the
protocol-integrity status, the sequence-ordered accepted ``RunEvent``s, the core
diagnostics minted while supervising, the bounded stderr capture and the
cancellation and timeout facts. Trust class P, unpublished, never persisted: the
manifest branch is trust class W and carries the raw token (hidden from ``repr``),
which is why the whole record is transient. The parsed-output branch is selected by
``invocation.command_kind`` -- ``BootstrapDescriptorEnvelope`` for ``DESCRIBE``
(the declared reading of specification 14.1's ``AdapterDescriptor`` member: the
envelope is the file that contains it together with the negotiation header),
``AdapterValidationResult`` for ``VALIDATE``, ``AdapterResultManifest`` for ``RUN``
-- and may be absent for any kind, because a ``CommandResult`` carries no verdict:
the native exit value, the exit category and a present output are process facts
and adapter declarations that ``adapters.reconciliation`` reconciles; nothing here
implies semantic success, transitions a record, persists, launches or finalizes.

Task-local readings, declared rather than inferred silently: ``cancelled`` is true
exactly for a ``CANCELLED`` invocation and ``timed_out`` exactly for a
``TIMED_OUT`` one (biconditionals; the plan's implications hold a fortiori, so a
cancellation or timeout can never masquerade as an ordinary exited result); a
``PROTOCOL_FAILED`` invocation requires ``protocol_integrity`` ``VIOLATED``, while
``EXITED`` beside ``VIOLATED`` stays representable for the reconcilers' precedence
check; a present ``parsed_output`` requires ``parsed_output_source_hash``;
``accepted_events`` is empty for ``DESCRIBE``, contiguous from sequence ``1`` and
names the invocation and its run; ``diagnostics`` are unique on identity and
bounded by ``MAX_DIAGNOSTIC_IDS``. A stale or foreign parsed output is
representable here: identity is the reconciler's check, not the carrier's.
"""

from __future__ import annotations

from typing import Final, Self

from pydantic import Field, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AbsoluteLocalExecutablePath, AdapterCatalogEntry
from crypto_lab.adapters.events import RunEvent
from crypto_lab.adapters.limits import MAX_SEQUENCE
from crypto_lab.adapters.manifests import AdapterResultManifest, AdapterValidationResult
from crypto_lab.adapters.negotiation import BootstrapDescriptorEnvelope
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    MAX_DIAGNOSTIC_IDS,
    MAX_RUN_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    CommandInvocationRecord,
    command_timeout_bounds,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.identifiers import InvocationId, Sha256
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
    CommandKind,
)

#: Specification 14.1: the sub-command verb of each kind, as literals.
_VERBS: Final[dict[CommandKind, str]] = {
    CommandKind.DESCRIBE: "describe",
    CommandKind.VALIDATE: "validate",
    CommandKind.RUN: "run",
}
#: Plan 3.7: the parsed-output branch each command kind selects.
_OUTPUT_OF_KIND: Final[dict[CommandKind, type[CanonicalModel]]] = {
    CommandKind.DESCRIBE: BootstrapDescriptorEnvelope,
    CommandKind.VALIDATE: AdapterValidationResult,
    CommandKind.RUN: AdapterResultManifest,
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


class CommandResult(CanonicalModel):
    """The supervisor's projection of one finished command (plan 3.7; trust class P).

    Transient and unpublished; see the module docstring for the branch rule and the
    declared readings. It carries no verdict and creates no semantic success.
    """

    invocation: CommandInvocationRecord
    parsed_output: (  # type: ignore[valid-type]
        BootstrapDescriptorEnvelope
        | AdapterValidationResult
        | AdapterResultManifest
        | MISSING
    ) = MISSING
    parsed_output_source_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    protocol_integrity: ProtocolIntegrityStatus
    accepted_events: tuple[RunEvent, ...] = Field(max_length=MAX_SEQUENCE)
    diagnostics: tuple[Diagnostic, ...] = Field(max_length=MAX_DIAGNOSTIC_IDS)
    stderr: StderrCapture | MISSING = MISSING  # type: ignore[valid-type]
    cancelled: bool
    timed_out: bool

    @model_validator(mode="after")
    def validate_terminal_projection(self) -> Self:
        invocation = self.invocation
        state = invocation.state
        if state not in TERMINAL_COMMAND_INVOCATION_STATES:
            raise ValueError(
                "CommandResult requires a terminal (finalized) invocation, not "
                f"{state.value}"
            )
        if not _is_missing(self.parsed_output):
            expected = _OUTPUT_OF_KIND[invocation.command_kind]
            if type(self.parsed_output) is not expected:
                raise ValueError(
                    f"parsed_output must be a {expected.__name__} for command_kind "
                    f"{invocation.command_kind.value}"
                )
            if _is_missing(self.parsed_output_source_hash):
                raise ValueError("parsed_output requires parsed_output_source_hash")
        if self.cancelled is not (state is CommandInvocationState.CANCELLED):
            raise ValueError("cancelled is true exactly for a CANCELLED invocation")
        if self.timed_out is not (state is CommandInvocationState.TIMED_OUT):
            raise ValueError("timed_out is true exactly for a TIMED_OUT invocation")
        if (
            state is CommandInvocationState.PROTOCOL_FAILED
            and self.protocol_integrity is not ProtocolIntegrityStatus.VIOLATED
        ):
            raise ValueError(
                "a PROTOCOL_FAILED invocation requires protocol_integrity VIOLATED"
            )
        events = self.accepted_events
        if invocation.command_kind is CommandKind.DESCRIBE and events:
            raise ValueError("accepted_events is empty for DESCRIBE")
        if tuple(event.sequence for event in events) != tuple(
            range(1, len(events) + 1)
        ):
            raise ValueError("accepted_events must be contiguous from sequence 1")
        for event in events:
            if event.invocation_id != invocation.invocation_id:
                raise ValueError("accepted_events must name the invocation")
            if event.run_id != invocation.run_id:
                raise ValueError("accepted_events must name the invocation's run")
        identities = [item.diagnostic_id for item in self.diagnostics]
        if len(set(identities)) != len(identities):
            raise ValueError("diagnostics must be unique on diagnostic_id")
        return self
