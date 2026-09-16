"""Deterministic test doubles for the Stage 7 supervision ports (plan section 9.2).

Test-resident on purpose: the two ports implemented here, ``DiagnosticRecorder``
(``crypto_lab.experiments.supervision_lifecycle``) and ``ReconciliationSource``
(``crypto_lab.process_supervision.ports``), are implemented in production only by
Stage 8's ``persistence`` package over its tables. Both doubles read and seed the
shared ``InMemoryBackingStore`` of the Stage 5 doubles directly: the recorder seeds a
diagnostic so the merged operations can read it back through the unit of work's
reader, and the source lists the reconciliation targets and the run facts a
reconciliation pass needs. Nothing here reads a wall clock, draws a random value,
sleeps, starts a thread or launches a process.

Stage 7 Task 5 adds ``SeedingDiagnosticRecorder`` and ``InMemoryReconciliationSource``;
Tasks 6 and 8 extend this module with the scripted controller, the recording
lifecycle and observer, the supervision clocks and the production catalog helpers.

Task-local readings, declared in the class docstrings below: a re-record of an
already-seeded identity is accepted with the first instance kept, whatever its
instant (identity is content-derived and excludes ``timestamp_utc``); a missing run
or experiment is the repository's ``CORE.INVARIANT_VIOLATION`` stamped with the
fixed doubles instant, because the source holds no clock.
"""

from __future__ import annotations

from typing import Final

from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.identifiers import RunId
from crypto_lab.domain.lifecycle import TERMINAL_COMMAND_INVOCATION_STATES
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION, stage5_failure
from crypto_lab.process_supervision.models import RunReconciliationFacts
from doubles.experiments import INSTANT, InMemoryBackingStore

SOURCE_COMPONENT: Final = "doubles.supervision"


def _invariant(message: str) -> Failure:
    return stage5_failure(
        INVARIANT_VIOLATION,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=INSTANT,
    )


class SeedingDiagnosticRecorder:
    """The ``DiagnosticRecorder`` double: seed the store, remember every call.

    ``record`` seeds the diagnostic into the backing store when its identity is
    absent and accepts an identical re-record with the first instance kept
    (idempotent on ``diagnostic_id``); ``calls`` lists every recorded identity in
    call order, repeats included. It implements ``record`` only, so the Stage 5
    reader-implementation census is untouched.
    """

    def __init__(self, store: InMemoryBackingStore) -> None:
        self._store = store
        self.calls: list[str] = []

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        self.calls.append(diagnostic.diagnostic_id)
        if diagnostic.diagnostic_id not in self._store.diagnostics.live:
            self._store.seed_diagnostic(diagnostic)
        return Success[None](outcome="SUCCESS", value=None)


class InMemoryReconciliationSource:
    """The ``ReconciliationSource`` double over the committed rows (plan 3.4, 8.5).

    ``list_reconciliation_targets`` returns every nonterminal invocation and every
    terminal one with ``cleanup_complete=false``, ordered ``(created_at_utc,
    invocation_id)``; ``run_facts`` reads the run and its experiment.
    """

    def __init__(self, store: InMemoryBackingStore) -> None:
        self._store = store

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        targets = sorted(
            (
                record
                for record in self._store.committed_command_invocations()
                if record.state not in TERMINAL_COMMAND_INVOCATION_STATES
                or not record.cleanup_complete
            ),
            key=lambda record: (record.created_at_utc, record.invocation_id),
        )
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=tuple(targets)
        )

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        run = self._store.engine_runs.live.get(run_id)
        if run is None:
            return _invariant(f"run {run_id} does not exist")
        experiment = self._store.experiments.live.get(run.experiment_id)
        if experiment is None:
            return _invariant(f"experiment {run.experiment_id} does not exist")
        return Success[RunReconciliationFacts](
            outcome="SUCCESS",
            value=RunReconciliationFacts(
                run_id=run.run_id,
                experiment_id=run.experiment_id,
                run_state=run.state,
                run_revision=run.revision,
                attempt_token_hash=run.attempt_token_hash,
                request_hash=run.request_hash,
                experiment_state=experiment.state,
            ),
        )
