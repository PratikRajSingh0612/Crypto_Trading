"""Restart reconciliation of command invocations (Stage 7 plan section 8.5).

Stage 7 plan sections 3.5, 8.5 and 8.6, under specification sections 15.2, 15.6, 15.7
and 29.2. ``reconcile_invocations`` walks every nonterminal invocation and every
terminal one with ``cleanup_complete=false`` that the ``ReconciliationSource`` lists,
applies exactly one row of the plan 8.5 table per record, and returns a
``ReconciliationReport`` whose entries are in ``(created_at_utc, invocation_id)`` order.
Every durable write goes through the ``InvocationLifecycle`` port (``record_terminal``,
``enrich``; ``load`` only to classify a refused swap), so the coupled run mappings and
the alone path of plan section 5 hold unchanged; every process action goes through
``ProcessController`` (``inspect``, ``terminate_tree``), never a pid alone; every
decision is one ``RECONCILIATION_DECISION`` trace entry handed to the observer.

After a restart nothing of the live supervision survives -- no process, Job Object or
thread handle, no reader, queue or monotonic deadline, no envelope or request material
-- so the reconciler uses durable facts plus one fresh inspection per inspecting row and
never reattaches a pipe, never reconstructs a native exit (an invocation never becomes
``EXITED`` here), never writes a run success state, never removes a root of an
invocation that reached ``RUNNING``, never reads a request file and never
re-materializes a raw attempt token: the run facts carry the token hash only.

Predicate order (plan 8.5 preamble and the ``INVARIANT_REPORTED`` row). For a ``RUN``
at ``STARTING`` or ``RUNNING`` the half-applied-pair predicate is evaluated before every
other row, because the merged coupled operation refuses a mixed running pair whatever
the target. For a ``VALIDATE`` at ``STARTING`` or ``RUNNING`` beside a run that is
neither ``VALIDATING`` nor terminal, cancellation is evaluated first (``READY ->
CANCELLED`` is an edge) and the pair is otherwise reported, because ``READY`` has no
edge to ``TIMED_OUT`` or ``FAILED``. A live matching process found beside a reported
pair is terminated so no unverifiable child survives the pass (specification 29.2 step
7).

Task-local readings, declared here and in the Task 7 ledger rather than inferred
silently:

- The listed targets are stable-sorted on the port's own key and an ``invocation_id``
  appears at most once; a conforming source is walked in source order unchanged.
- A ``run_facts`` failure for a linked record is ``INVARIANT_REPORTED`` for that record
  (the pass continues), with the source's diagnostics reported beside the minted one.
- A tree still ``ALIVE_MATCHING`` after ``terminate_tree`` is a
  ``PROCESS.CLEANUP_FAILED`` of action ``TREE_VERIFIED_DEAD`` with
  ``error_class = tree_alive`` and no error number.
- ``PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION.supervisor_instance_id`` names the
  recorded owner of the process (the supervision that was lost); the report names the
  reconciling instance.
- Every terminalizing row completes its own cleanup and enrichment in the same pass;
  the terminal cleanup rows serve records a crashed supervisor or a failed cleanup left
  behind.
- ``manifest_present`` is ``lstat`` existence of the planned result path (not found is
  false, any other error is true); the file is never opened.
- Instants inside diagnostic details are rendered as ISO 8601 text.
- A refused enrichment after a committed terminal write keeps the terminalizing action
  (the record did move) and reports the failure; a refused enrichment that is a cleanup
  row's only write is ``SKIPPED_EXTERNAL_WINNER``.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from pydantic import TypeAdapter
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_START_TIMED_OUT,
    PROCESS_VALIDATE_TIMED_OUT,
    stage6_diagnostic,
)
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.descriptors import BoundedText
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.process_supervision.diagnostics import (
    CORE_INVARIANT_VIOLATION,
    PROCESS_CLEANUP_FAILED,
    PROCESS_FORCED_TERMINATION,
    PROCESS_LAUNCH_NOT_COMMITTED,
    PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
    PROCESS_PID_REUSE_DETECTED,
    stage7_diagnostic,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    CleanupFailure,
    InvocationReconciliation,
    ProcessInspection,
    ProcessPresence,
    ReconciliationAction,
    ReconciliationReport,
    RunReconciliationFacts,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    TerminationReport,
)
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    ProcessController,
    ReconciliationSource,
    SupervisionObserver,
)
from crypto_lab.process_supervision.roots import (
    CommandPaths,
    PathPreflight,
    plan_command_paths,
    remove_command_root,
)

__all__ = ["reconcile_invocations"]

#: Plan 3.5: the ``source_component`` of every diagnostic this module mints.
SOURCE_COMPONENT: Final = "process_supervision.reconciliation"
#: Plan 3.5: the ``reason`` word of a forced termination the reconciler performs.
_FORCE_REASON: Final = "reconciliation"
#: The closed ``error_class`` word of a tree that is still alive after its termination.
_TREE_ALIVE: Final = "tree_alive"
_MIXED_CHECK: Final = "mixed_running_pair"
_FACTS_CHECK: Final = "run_facts_unavailable"
_K: Final = CommandKind
_S: Final = CommandInvocationState
_R: Final = EngineRunState
_A: Final = ReconciliationAction
_P: Final = ProcessPresence
#: Plan 3.5: the kind primaries of a ``RUNNING``-origin ``TIMED_OUT``.
_TIMEOUT_CODE_FROM_RUNNING: Final[dict[CommandKind, str]] = {
    _K.DESCRIBE: PROCESS_DESCRIBE_TIMED_OUT,
    _K.VALIDATE: PROCESS_VALIDATE_TIMED_OUT,
    _K.RUN: PROCESS_RUN_TIMED_OUT,
}
#: Plan 3.5: ``START_TIMED_OUT`` only for a ``STARTING``-origin ``RUN``.
_TIMEOUT_CODE_FROM_STARTING: Final[dict[CommandKind, str]] = {
    _K.DESCRIBE: PROCESS_DESCRIBE_TIMED_OUT,
    _K.VALIDATE: PROCESS_VALIDATE_TIMED_OUT,
    _K.RUN: PROCESS_START_TIMED_OUT,
}
#: Plan 8.5: the run state a live linked pair carries beside each open invocation state.
_LIVE_RUN_STATE: Final[
    dict[CommandKind, dict[CommandInvocationState, EngineRunState]]
] = {
    _K.RUN: {_S.STARTING: _R.STARTING, _S.RUNNING: _R.RUNNING},
    _K.VALIDATE: {_S.STARTING: _R.VALIDATING, _S.RUNNING: _R.VALIDATING},
}
#: ``ReconciliationReport.supervisor_instance_id`` is ``BoundedText``; the same grammar
#: is applied before any read so an over-long id cannot fail after a write.
_BOUNDED_TEXT: TypeAdapter[str] = TypeAdapter(BoundedText)

type _Facts = dict[str, DiagnosticDetailValue]


class _Write(StrEnum):
    """What one enrichment attempt did."""

    WRITTEN = "WRITTEN"
    NOTHING_NEW = "NOTHING_NEW"
    REFUSED = "REFUSED"


def _is_missing(value: object) -> bool:
    return value is MISSING


def _reason_parts(failure: CleanupFailure) -> tuple[str, int | None]:
    """A ``CleanupFailure.reason`` of the form ``<word>:<number>``."""
    word, separator, number = failure.reason.partition(":")
    if separator and number.isdigit():
        return word, int(number)
    return failure.reason, None


def _iso(instant: datetime) -> str:
    return instant.isoformat()


def _path_exists(path: str) -> bool:
    """Existence only: ``lstat`` of the path itself, never following a reparse point."""
    try:
        Path(path).lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:  # pragma: no cover - an existing path that cannot be inspected
        return True
    return True


def _ordered(
    records: tuple[CommandInvocationRecord, ...],
) -> tuple[CommandInvocationRecord, ...]:
    """The port's order, imposed, and each invocation once (first occurrence)."""
    seen: set[str] = set()
    unique: list[CommandInvocationRecord] = []
    for record in sorted(
        records, key=lambda item: (item.created_at_utc, item.invocation_id)
    ):
        if record.invocation_id in seen:
            continue
        seen.add(record.invocation_id)
        unique.append(record)
    return tuple(unique)


@dataclass(slots=True)
class _Target:
    """One record under reconciliation and everything this pass learned about it."""

    record: CommandInvocationRecord
    current: CommandInvocationRecord
    now: datetime
    paths: CommandPaths
    facts: RunReconciliationFacts | None = None
    facts_failure: Failure | None = None
    inspection: ProcessInspection | None = None
    termination: TerminationReport | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    manifest_present: bool | None = None
    action: ReconciliationAction | None = None

    @property
    def kind(self) -> CommandKind:
        return self.record.command_kind

    @property
    def presence(self) -> ProcessPresence | None:
        return None if self.inspection is None else self.inspection.presence

    @property
    def identity(self) -> ProcessIdentity | None:
        identity = self.record.pid_identity
        return identity if isinstance(identity, ProcessIdentity) else None

    @property
    def cancelled(self) -> bool:
        """Plan 2.5 reading 17: the experiment or the run is ``CANCELLED``."""
        return self.facts is not None and self.facts.cancelled

    @property
    def past_deadline(self) -> bool:
        deadline = self.record.deadline_utc
        return isinstance(deadline, datetime) and self.now >= deadline

    def remember(self, diagnostic: Diagnostic) -> Diagnostic:
        """First-occurrence unique on identity (the entry's own rule, plan 3.3)."""
        if all(
            item.diagnostic_id != diagnostic.diagnostic_id for item in self.diagnostics
        ):
            self.diagnostics.append(diagnostic)
        return diagnostic

    def remember_all(self, diagnostics: tuple[Diagnostic, ...]) -> None:
        for diagnostic in diagnostics:
            self.remember(diagnostic)


@dataclass(slots=True)
class _Pass:
    """One reconciliation pass over the source's targets."""

    source: ReconciliationSource
    lifecycle: InvocationLifecycle
    controller: ProcessController
    preflight: PathPreflight
    clock: Clock
    supervisor_instance_id: str
    observer: Any
    sequence: int = 0

    # -- the pass ---------------------------------------------------------------------

    def run(self) -> Result[ReconciliationReport]:
        started_at_utc = self.clock.now_utc()
        listed = self.source.list_reconciliation_targets()
        if isinstance(listed, Failure):
            return listed
        entries = tuple(self._reconcile(record) for record in _ordered(listed.value))
        return Success[ReconciliationReport](
            outcome="SUCCESS",
            value=ReconciliationReport(
                supervisor_instance_id=self.supervisor_instance_id,
                started_at_utc=started_at_utc,
                entries=entries,
            ),
        )

    def _reconcile(self, record: CommandInvocationRecord) -> InvocationReconciliation:
        """Exactly one plan 8.5 row per record; ``now`` and the facts read once."""
        now = self.clock.now_utc()
        paths = plan_command_paths(
            self.preflight.supervision_root,
            command_kind=record.command_kind,
            invocation_id=record.invocation_id,
            run_id=record.run_id,
        )
        target = _Target(record=record, current=record, now=now, paths=paths)
        if record.state is _S.PENDING:
            target.action = _A.LEFT_PENDING
        else:
            self._read_facts(target)
            if target.facts_failure is not None:
                self._invariant(target, _FACTS_CHECK)
            elif record.state in TERMINAL_COMMAND_INVOCATION_STATES:
                self._cleanup_row(target)
            elif record.state is _S.STARTING:
                self._starting_row(target)
            else:
                self._running_row(target)
        self._emit(target)
        return self._entry(target)

    def _read_facts(self, target: _Target) -> None:
        run_id = target.record.run_id
        if target.kind is _K.DESCRIBE or not isinstance(run_id, str):
            return
        facts = self.source.run_facts(run_id)
        if isinstance(facts, Failure):
            target.facts_failure = facts
        else:
            target.facts = facts.value

    # -- the rows ---------------------------------------------------------------------

    def _mixed(self, target: _Target) -> bool:
        """The plan 8.5 half-applied-pair predicate, narrower than the merged one: a
        terminal run is routed to the alone path, not reported."""
        facts = target.facts
        if facts is None or target.kind is _K.DESCRIBE:
            return False
        if facts.run_state in TERMINAL_ENGINE_RUN_STATES:
            return False
        return facts.run_state is not _LIVE_RUN_STATE[target.kind][target.record.state]

    def _starting_row(self, target: _Target) -> None:
        mixed = self._mixed(target)
        if mixed and target.kind is _K.RUN:
            self._invariant(target, _MIXED_CHECK)
            return
        if target.cancelled:
            self._terminalize(
                target,
                _S.CANCELLED,
                self._mint6(
                    target, PROCESS_CANCELLED, "cancellation won before the launch"
                ),
                action=_A.TERMINALIZED_CANCELLED,
            )
            return
        if mixed:
            self._invariant(target, _MIXED_CHECK)
            return
        if target.past_deadline:
            self._terminalize(
                target,
                _S.TIMED_OUT,
                self._mint6(
                    target,
                    _TIMEOUT_CODE_FROM_STARTING[target.kind],
                    "the deadline passed before the launch handoff committed",
                ),
                action=_A.TERMINALIZED_TIMED_OUT,
            )
            return
        record = target.record
        details: _Facts = {"stored_revision": record.revision}
        if isinstance(record.launch_attempted_at_utc, datetime):
            details["launch_attempted_at_utc"] = _iso(record.launch_attempted_at_utc)
        if isinstance(record.deadline_utc, datetime):
            details["deadline_utc"] = _iso(record.deadline_utc)
        self._terminalize(
            target,
            _S.FAILED_TO_START,
            self._mint7(
                target,
                PROCESS_LAUNCH_NOT_COMMITTED,
                "a persisted STARTING record has no committed process identity",
                details=details,
            ),
            action=_A.TERMINALIZED_FAILED_TO_START,
        )

    def _running_row(self, target: _Target) -> None:
        self._inspect(target)
        mixed = self._mixed(target)
        if mixed and target.kind is _K.RUN:
            self._invariant(target, _MIXED_CHECK)
            return
        if not mixed and target.presence is _P.ALIVE_MATCHING:
            self._lost_supervision(target)
            return
        if target.cancelled:
            self._terminalize(
                target,
                _S.CANCELLED,
                self._mint6(
                    target, PROCESS_CANCELLED, "cancellation won after restart"
                ),
                action=_A.TERMINALIZED_CANCELLED,
            )
            return
        if mixed:
            self._invariant(target, _MIXED_CHECK)
            return
        if target.past_deadline:
            self._terminalize(
                target,
                _S.TIMED_OUT,
                self._mint6(
                    target,
                    _TIMEOUT_CODE_FROM_RUNNING[target.kind],
                    "the deadline passed with no exit facts to reconstruct",
                ),
                action=_A.TERMINALIZED_TIMED_OUT,
            )
            return
        target.action = _A.LEFT_RUNNING_AWAITING_DEADLINE
        if target.kind is _K.RUN and isinstance(target.paths.result_path, str):
            target.manifest_present = _path_exists(target.paths.result_path)

    def _lost_supervision(self, target: _Target) -> None:
        """Plan 8.5 and reading 16: a live matching child is unsupervisable."""
        self._terminate(target)
        identity = target.identity
        report = target.termination
        details: _Facts = {
            "tree_terminated": report is not None and not report.failures,
        }
        if identity is not None:
            details = {
                "pid": identity.pid,
                "creation_identity": identity.creation_identity,
                "supervisor_instance_id": identity.supervisor_instance_id,
                **details,
            }
        self._terminalize(
            target,
            _S.PROTOCOL_FAILED,
            self._mint7(
                target,
                PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
                "the supervising instance was lost and the pipes cannot be reattached",
                details=details,
            ),
            action=_A.TERMINALIZED_PROTOCOL_FAILED,
        )

    def _invariant(self, target: _Target, check: str) -> None:
        """Plan 8.5 ``INVARIANT_REPORTED``: reported, never written; a live matching
        process is still terminated so no unverifiable child survives the pass."""
        details: _Facts = {
            "check": check,
            "command_kind": target.kind.value,
            "invocation_state": target.record.state.value,
        }
        if target.facts is not None:
            details["run_state"] = target.facts.run_state.value
        self._mint7(
            target,
            CORE_INVARIANT_VIOLATION,
            "the durable pair cannot be reconciled without reconstructing facts",
            details=details,
        )
        if target.facts_failure is not None:
            target.remember_all(target.facts_failure.diagnostics)
        if target.record.process_created and target.inspection is None:
            self._inspect(target)
        if target.presence is _P.ALIVE_MATCHING:
            self._terminate(target)
        target.action = _A.INVARIANT_REPORTED

    def _cleanup_row(self, target: _Target) -> None:
        """Plan 8.5: a terminal record whose cleanup a crash left incomplete."""
        record = target.record
        if record.state is _S.EXITED or not record.process_created:
            complete = True
            if not record.process_created:
                complete = self._remove_root(target)
        else:
            self._inspect(target)
            complete = True
            if target.presence is _P.ALIVE_MATCHING:
                self._terminate(target)
                complete = self._tree_cleanup(target)
        written = self._enrich(target, cleanup_complete=complete)
        if written is _Write.WRITTEN:
            target.action = _A.CLEANUP_COMPLETED if complete else _A.CLEANUP_FAILED
        elif written is _Write.NOTHING_NEW:
            target.action = _A.CLEANUP_STILL_FAILING
        else:
            target.action = _A.SKIPPED_EXTERNAL_WINNER

    # -- process actions --------------------------------------------------------------

    def _inspect(self, target: _Target) -> None:
        identity = target.identity
        if identity is None or target.inspection is not None:
            return
        inspection = self.controller.inspect(identity)
        target.inspection = inspection
        if inspection.presence is _P.ALIVE_DIFFERENT_IDENTITY:
            details: _Facts = {
                "pid": identity.pid,
                "expected_creation_identity": identity.creation_identity,
            }
            if isinstance(inspection.observed_creation_identity, str):
                details["observed_creation_identity"] = (
                    inspection.observed_creation_identity
                )
            self._mint7(
                target,
                PROCESS_PID_REUSE_DETECTED,
                "the recorded pid now names a process with another creation identity",
                details=details,
            )

    def _terminate(self, target: _Target) -> None:
        """At most once per record per pass, and only after this pass's own
        ``ALIVE_MATCHING`` inspection (identity first, never a pid alone)."""
        identity = target.identity
        if identity is None or target.termination is not None:
            return
        report = self.controller.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
        target.termination = report
        self._mint7(
            target,
            PROCESS_FORCED_TERMINATION,
            "the process tree was terminated",
            details={
                "reason": _FORCE_REASON,
                "exit_code": FORCED_TERMINATION_EXIT_CODE,
                "descendants_terminated": len(report.descendants),
                "job_object": report.job_terminated,
            },
        )

    def _tree_cleanup(self, target: _Target) -> bool:
        """After a termination: every reported failure and a re-inspection decide
        whether the tree cleanup is complete."""
        report = target.termination
        if report is None:  # pragma: no cover - called only after _terminate
            return True
        complete = True
        for failure in report.failures:
            self._cleanup_failed(target, failure)
            complete = False
        identity = target.identity
        if identity is not None:
            again = self.controller.inspect(identity)
            if again.presence is _P.ALIVE_MATCHING:
                self._cleanup_failed(
                    target,
                    CleanupFailure(
                        action=CleanupAction.TREE_VERIFIED_DEAD, reason=_TREE_ALIVE
                    ),
                )
                complete = False
        return complete

    def _remove_root(self, target: _Target) -> bool:
        """Plan 7.5: a pre-``RUNNING`` root only; never raises."""
        removal = remove_command_root(target.paths.command_root)
        for failure in removal.failures:
            self._cleanup_failed(target, failure)
        return removal.complete

    def _cleanup_failed(self, target: _Target, failure: CleanupFailure) -> None:
        word, number = _reason_parts(failure)
        details: _Facts = {
            "cleanup_action": failure.action.value,
            "error_class": word,
        }
        if number is not None:
            details["os_error_code"] = number
        self._mint7(
            target, PROCESS_CLEANUP_FAILED, "a cleanup action failed", details=details
        )

    # -- durable writes ---------------------------------------------------------------

    def _terminalize(
        self,
        target: _Target,
        state: CommandInvocationState,
        primary: Diagnostic,
        *,
        action: ReconciliationAction,
    ) -> None:
        """One terminal write through the port, then the row's own cleanup."""
        if target.presence is _P.ALIVE_MATCHING:
            self._terminate(target)  # a live matching child never survives the pass
        additional = tuple(
            diagnostic
            for diagnostic in target.diagnostics
            if diagnostic.diagnostic_id != primary.diagnostic_id
        )
        written = self.lifecycle.record_terminal(
            target.record.invocation_id,
            expected_revision=target.record.revision,
            target_state=state,
            primary=primary,
            additional=additional,
            native_exit_value=MISSING,
        )
        if isinstance(written, Failure):
            self._skip(target, written)
            return
        target.current = written.value
        target.action = action
        if target.current.process_created:
            complete = (
                self._tree_cleanup(target) if target.termination is not None else True
            )
        else:
            complete = self._remove_root(target)
        self._enrich(target, cleanup_complete=complete)

    def _skip(self, target: _Target, failure: Failure) -> None:
        """Plan 8.5 last row: the stored record is the winner; nothing else happens."""
        target.remember_all(failure.diagnostics)
        reload = self.lifecycle.load(target.record.invocation_id)
        if isinstance(reload, Failure):
            target.remember_all(reload.diagnostics)
        else:
            target.current = reload.value
        target.action = _A.SKIPPED_EXTERNAL_WINNER

    def _enrich(self, target: _Target, *, cleanup_complete: bool) -> _Write:
        """Plan 6.6: one enrichment carrying only what the record does not yet hold; an
        enrichment that would add nothing is not attempted (plan 8.5
        ``CLEANUP_STILL_FAILING``)."""
        record = target.current
        stored = set(record.diagnostic_ids)
        additional = tuple(
            diagnostic
            for diagnostic in target.diagnostics
            if diagnostic.diagnostic_id not in stored
        )
        adds_cleanup = cleanup_complete and not record.cleanup_complete
        if not adds_cleanup and not additional:
            return _Write.NOTHING_NEW
        enriched = self.lifecycle.enrich(
            record.invocation_id,
            expected_revision=record.revision,
            native_exit_value=MISSING,
            cleanup_complete=cleanup_complete,
            additional=additional,
        )
        if isinstance(enriched, Success):
            target.current = enriched.value
            return _Write.WRITTEN
        target.remember_all(enriched.diagnostics)
        reload = self.lifecycle.load(record.invocation_id)
        if isinstance(reload, Failure):
            target.remember_all(reload.diagnostics)
        else:
            target.current = reload.value
        return _Write.REFUSED

    # -- diagnostics and the trace --------------------------------------------------

    def _correlation(self, target: _Target) -> tuple[Any, Any]:
        facts = target.facts
        if facts is None:
            return MISSING, MISSING
        return facts.experiment_id, facts.run_id

    def _mint6(
        self,
        target: _Target,
        code: str,
        message: str,
        *,
        details: _Facts | None = None,
    ) -> Diagnostic:
        experiment_id, run_id = self._correlation(target)
        return target.remember(
            stage6_diagnostic(
                code,
                message,
                source_component=SOURCE_COMPONENT,
                timestamp_utc=target.now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=target.record.invocation_id,
                details=details,
            )
        )

    def _mint7(
        self,
        target: _Target,
        code: str,
        message: str,
        *,
        details: _Facts | None = None,
    ) -> Diagnostic:
        experiment_id, run_id = self._correlation(target)
        return target.remember(
            stage7_diagnostic(
                code,
                message,
                source_component=SOURCE_COMPONENT,
                timestamp_utc=target.now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=target.record.invocation_id,
                details=details,
            )
        )

    def _emit(self, target: _Target) -> None:
        """Plan 8.5: every decision is one ``RECONCILIATION_DECISION`` entry; an
        observer never alters a decision (plan 3.4)."""
        action = target.action
        if action is None:  # pragma: no cover - every row assigns an action
            raise ValueError("a reconciliation row must assign an action")
        self.sequence += 1
        codes: list[DiagnosticDetailValue] = [
            diagnostic.error_code for diagnostic in target.diagnostics
        ]
        facts: _Facts = {
            "action": action.value,
            "command_kind": target.kind.value,
            "state_before": target.record.state.value,
            "state_after": target.current.state.value,
            "revision_after": target.current.revision,
            "codes": codes,
            "terminated": target.termination is not None,
        }
        presence = target.presence
        if presence is not None:
            facts["presence"] = presence.value
        if target.manifest_present is not None:
            facts["manifest_present"] = target.manifest_present
        entry = SupervisionTraceEntry(
            kind=SupervisionTraceKind.RECONCILIATION_DECISION,
            invocation_id=target.record.invocation_id,
            sequence=self.sequence,
            at_utc=target.now,
            monotonic_100ns=round(self.clock.monotonic().seconds * 1e7),
            facts=facts,
        )
        if _is_missing(self.observer):
            return
        with suppress(Exception):  # plan 3.4: an observer never alters a decision
            self.observer.observe(entry)

    def _entry(self, target: _Target) -> InvocationReconciliation:
        action = target.action
        if action is None:  # pragma: no cover - every row assigns an action
            raise ValueError("a reconciliation row must assign an action")
        presence: Any = MISSING if target.presence is None else target.presence
        manifest: Any = (
            MISSING if target.manifest_present is None else target.manifest_present
        )
        return InvocationReconciliation(
            invocation_id=target.record.invocation_id,
            command_kind=target.kind,
            state_before=target.record.state,
            action=action,
            record_after=target.current,
            presence=presence,
            manifest_present=manifest,
            diagnostics=tuple(target.diagnostics),
        )


def reconcile_invocations(
    *,
    source: ReconciliationSource,
    lifecycle: InvocationLifecycle,
    controller: ProcessController,
    preflight: PathPreflight,
    clock: Clock,
    supervisor_instance_id: str,
    observer: SupervisionObserver | MISSING,  # type: ignore[valid-type]
) -> Result[ReconciliationReport]:
    """Plan 8.5: one reconciliation pass over every target the source lists.

    Walks ``list_reconciliation_targets()`` in ``(created_at_utc, invocation_id)`` order
    and applies exactly one row per record through the lifecycle and controller ports;
    ``now`` is read once per record and the run facts once per linked record. A
    ``Failure`` from the listing is returned unchanged with nothing done. The report
    names the reconciling instance and carries one entry per invocation.
    """
    if not isinstance(preflight, PathPreflight):
        raise TypeError("preflight must be a PathPreflight")
    instance = _BOUNDED_TEXT.validate_python(supervisor_instance_id)
    return _Pass(
        source=source,
        lifecycle=lifecycle,
        controller=controller,
        preflight=preflight,
        clock=clock,
        supervisor_instance_id=instance,
        observer=observer,
    ).run()
