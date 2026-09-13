"""The six structural ports of the process-supervision boundary.

Stage 7 plan sections 2.3 and 3.4, under specification sections 8, 8.1 and 8.2.
All six are ``typing.Protocol`` classes, ``runtime_checkable``, structural, with no
implementation and no I/O. ``ProcessSupervisor`` is the application-facing port
specification 8.1 places in this package; the other five are placed with the package
that consumes them, the supervisor and the reconciler. Every parameter and return
type reachable from ``InvocationLifecycle`` is a ``domain`` or ``adapters`` type,
never a record of this package, so the ``experiments`` layer implements it
structurally without importing ``process_supervision`` and the dependency direction
of specification section 8 holds in both packages. Nothing here reads a clock,
starts a thread, opens a pipe or launches a process.
"""

from __future__ import annotations

from typing import IO, Protocol, runtime_checkable

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.adapters.envelopes import AdapterCommandRequestEnvelope
from crypto_lab.adapters.events import RunEvent
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    NativeExitValue,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.descriptors import ExecutablePath
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.identifiers import InvocationId, RunId
from crypto_lab.domain.lifecycle import CommandInvocationState
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Result
from crypto_lab.process_supervision.models import (
    CleanupReport,
    InterruptOutcome,
    LaunchFailure,
    LaunchSpecification,
    ProcessInspection,
    RunReconciliationFacts,
    SupervisionOutcome,
    SupervisionTraceEntry,
    TerminationReport,
)

__all__ = [
    "InvocationLifecycle",
    "LaunchedProcess",
    "ProcessController",
    "ProcessSupervisor",
    "ReconciliationSource",
    "SupervisionObserver",
]


@runtime_checkable
class ProcessSupervisor(Protocol):
    """Specification 8.1: run one adapter command under deadlines, protocol limits
    and cancellation.

    Plan 2.5 reading 1: the result is ``Result[SupervisionOutcome]``, a ``Failure``
    only when no record changed (a structural preflight refusal, a lost swap against
    a record another actor moved, an own-request defect, the long-path probe) and
    otherwise a ``Success`` carrying the specification's ``CommandResult`` verbatim
    beside the parse outcome and protocol summary.
    """

    async def invoke(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[SupervisionOutcome]:
        """Supervise one command to its terminal record and single enrichment."""


@runtime_checkable
class InvocationLifecycle(Protocol):
    """The structural port the supervisor drives over the Stage 5 operations.

    Plan 3.4 and 5.1: nine members, each one merged operation behind the unit of
    work the ``experiments`` implementation owns. Only domain and adapters types
    cross this port.
    """

    def load(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]:
        """Read the invocation record."""

    def linked_run(
        self, invocation_id: InvocationId
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        """Return the linked run's own record, or ``Success(MISSING)`` for a
        ``DESCRIBE`` (plan 3.4: the supervisor reads its ids, state and revision)."""

    def begin_start(
        self, invocation_id: InvocationId, *, expected_revision: int
    ) -> Result[CommandInvocationRecord]:
        """The paired-clock ``PENDING`` to ``STARTING`` swap after the pre-swap
        revalidation of plan 4.4 (the linked launch for a ``RUN``)."""

    def request_envelope(
        self, invocation_id: InvocationId
    ) -> Result[AdapterCommandRequestEnvelope]:
        """Build the request envelope of the ``STARTING`` record from the
        registered material."""

    def record_process_start(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        process_start: ProcessStartFacts,
    ) -> Result[CommandInvocationRecord]:
        """The launch handoff: ``STARTING`` to ``RUNNING`` with the process facts
        (the linked start for a ``RUN``)."""

    def record_terminal(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        target_state: CommandInvocationState,
        primary: Diagnostic | MISSING,  # type: ignore[valid-type]
        additional: tuple[Diagnostic, ...],
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
    ) -> Result[CommandInvocationRecord]:
        """The terminal transition with its primary, additionals and, for
        ``EXITED``, the native exit pair; coupled to the run per plan 5.2."""

    def enrich(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
        cleanup_complete: bool,
        additional: tuple[Diagnostic, ...],
    ) -> Result[CommandInvocationRecord]:
        """The single write-once enrichment after cleanup (plan 6.6)."""

    def append_event(self, event: RunEvent) -> Result[RunEvent]:
        """Append one accepted event; idempotent on identical content."""

    def resolve_external_winner(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        primary: Diagnostic,
    ) -> Result[CommandInvocationRecord | MISSING]:  # type: ignore[valid-type]
        """Plan 2.5 reading 22: write ``CANCELLED`` with the supplied primary only
        when the linked run is terminal (alone) or the experiment is ``CANCELLED``
        (coupled); otherwise ``Success(MISSING)`` and no write."""


@runtime_checkable
class LaunchedProcess(Protocol):
    """One launched child as the supervisor sees it (plan 3.4, 6.5, 6.7, 8.2-8.4).

    ``wait(0.0)`` is the poll; ``interrupt``, ``terminate_tree``, ``cancel_read``
    and ``close`` never raise, they report. ``job_available``, ``job_error_code`` and
    ``image_path`` are the launch facts from which the supervisor mints
    ``PROCESS.JOB_OBJECT_UNAVAILABLE`` and the ``LAUNCHED`` trace fact.
    """

    @property
    def pid(self) -> int:
        """The child's process identifier."""

    @property
    def creation_identity(self) -> str:
        """The durable ``windows:<pid>:<creation>`` text."""

    @property
    def stdout(self) -> IO[bytes]:
        """The read end of the protocol pipe."""

    @property
    def stderr(self) -> IO[bytes]:
        """The read end of the evidence pipe."""

    def wait(self, timeout_seconds: float) -> int | None:
        """Return the exit value once the handle is signaled, else ``None``."""

    def interrupt(self) -> InterruptOutcome:
        """Deliver the graceful interrupt to the child's process group."""

    def terminate_tree(self, exit_code: int) -> TerminationReport:
        """Terminate the verified process tree with ``exit_code``."""

    def cancel_read(self, native_thread_id: int) -> bool:
        """Cancel the synchronous pipe read a reader thread is blocked in."""

    def close(self, *, close_stdout: bool, close_stderr: bool) -> CleanupReport:
        """Close the pipes whose readers ended, verify the tree, close the handles."""

    @property
    def job_available(self) -> bool:
        """Whether the child was assigned to the supervisor's Job Object."""

    @property
    def job_error_code(self) -> int | MISSING:  # type: ignore[valid-type]
        """The error of the job assignment when it was unavailable."""

    @property
    def image_path(self) -> ExecutablePath | MISSING:  # type: ignore[valid-type]
        """The image path observed from the owning handle, when readable."""


@runtime_checkable
class ProcessController(Protocol):
    """Process creation, identity, Job Objects and tree termination (plan 3.4, 8).

    ``launch`` returns a process or a ``LaunchFailure``, never an exception and
    never a ``Diagnostic``; ``inspect`` returns an instant-free inspection.
    """

    def launch(
        self, specification: LaunchSpecification
    ) -> LaunchedProcess | LaunchFailure:
        """Create the child suspended, own it, assign the job, resume it."""

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        """Re-inspect a recorded identity: matching, reused, absent or undetermined."""

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        """Terminate the verified tree behind a recorded identity."""


@runtime_checkable
class SupervisionObserver(Protocol):
    """Receives every supervision trace entry on the supervision thread (plan 3.4).

    An exception the observer raises is caught and otherwise ignored, so an observer
    can never alter a terminal decision.
    """

    def observe(self, entry: SupervisionTraceEntry) -> None:
        """Observe one entry."""


@runtime_checkable
class ReconciliationSource(Protocol):
    """The durable records a reconciliation pass reads (plan 3.4, 8.5).

    Implemented in Stage 7 only by a test-resident double; Stage 8 implements it in
    ``persistence``.
    """

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        """Every nonterminal invocation and every terminal one with
        ``cleanup_complete=false``, ordered ``(created_at_utc, invocation_id)``."""

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        """The run and its experiment, as facts."""
