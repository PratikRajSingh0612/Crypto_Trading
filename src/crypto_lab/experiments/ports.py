"""The application-owned repository, reader and unit-of-work ports of Stage 5.

Specification section 8 places repository protocols in the application package
that consumes them and requires that the application never import a concrete
implementation; ``persistence`` (Stage 8) implements these protocols. Stage 5 plan
section 10 fixes the inventory below: five ``experiments`` protocols plus
``CommandInvocationRepository`` in ``crypto_lab.adapters.ports`` (plan 2.4). All
methods are synchronous and return ``Result[...]`` because these are short local
transactions (specification 8.2); a repository never commits on its own -- the
application service owns the unit of work.

Declared extensions beyond specification section 8.2's operation list, each
because a named Stage 5 rule reads it: ``count_attempts``, ``latest_attempt`` and
``get_by_attempt_number`` (plan 8.1, 5, 9.2); ``RetryDecisionRepository`` (plan
8.4); ``RuntimeAvailabilityObservationReader.list_for_adapter`` (plan 8.2 gate 6);
``DiagnosticReader.get`` and ``get_many`` (plan 6 unrecognized exit, plan 8.2
closure). ``EngineRunRepository.append_event`` is deliberately absent: its
``RunEvent`` parameter is a Stage 6 adapter-protocol contract (plan 1.4).

Task-local readings, declared here rather than inferred silently:

- ``UnitOfWork`` exposes the six repositories and readers as read-only members.
  Plan section 9.1 gives an operation exactly ``unit_of_work`` and ``clock``, so
  the repositories an atomic operation reads and writes must be reachable through
  the unit of work that bounds them. ``begin()`` returns the active transaction
  (specification 8.2); ``commit()`` is all-or-nothing and may return a
  ``PERSISTENCE.CONCURRENCY_CONFLICT`` when a row the transaction changed moved
  underneath it; ``rollback()`` is idempotent so a ``finally`` clause is always
  safe. Nesting, a second commit and repository access after close are programmer
  defects and may raise (specification 8.2).
- A missing identity on ``get`` is a ``Failure`` carrying
  ``CORE.INVARIANT_VIOLATION``: plan 8.6's six-code vocabulary has no not-found
  code, and an operation that names a nonexistent record has reached an
  impossible aggregate state. A duplicate identity or unique-index collision on an
  insert, and a zero-row compare-and-swap (revision mismatch or missing row), are
  ``PERSISTENCE.CONCURRENCY_CONFLICT``: the existing row is the durable state the
  caller must reread (specification 23.2). Whether a duplicate is an identical
  replay or a divergent conflict is decided by the service after a read, never by
  the repository.
- ``DiagnosticReader`` offers primitive reads only. Traversal, cycle detection,
  the depth and node bounds and canonical ordering belong to Task 7's
  ``resolve_causal_closure`` (plan 8.2); neither this port nor any implementation
  may contain a second traversal.
- Every multi-valued query has one canonical order: ``list_for_adapter`` returns
  every matching observation sorted by ``availability_observation_id`` (the
  order ``RetryEvaluationSnapshot`` requires) and is deliberately unbounded --
  the snapshot's 256-candidate bound is applied by Task 7 after gate 6's
  qualifying filter, so no qualifying observation is ever dropped by the read;
  ``get_many`` is sorted by ``diagnostic_id``, requires unique identifiers,
  admits at most 256 and fails on any missing one (the traversal's node bound);
  ``list_for_run`` is ordered by ``(created_at_utc, invocation_id)``.
- ``latest_attempt`` and ``get_by_attempt_number`` both return ``MISSING`` for an
  absent attempt, an ordinary answer rather than a failure (plan 10; plan 8.5
  step 2 probes a reserved number whose absence is the normal first-creation
  path). Whether an absence is an invariant violation is the service's call.
- A commit re-validates, against the live store, the primary identity and every
  unique index of each row the transaction inserted or replaced, so two
  transactions inserting distinct identities that collide on an index cannot
  both publish (specification 23.3).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    DiagnosticId,
    ExperimentId,
    LogicalSlotId,
    NormalizedIdentifier,
    RunId,
    Sha256,
)
from crypto_lab.domain.results import Result
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.domain.versioning import SemanticVersion


@runtime_checkable
class ExperimentRepository(Protocol):
    """Persist and compare-and-swap experiment records (specification 8.1)."""

    def get(self, experiment_id: ExperimentId) -> Result[ExperimentRecord]:
        """Return the stored record; a missing identity is a ``Failure``."""

    def add(self, record: ExperimentRecord) -> Result[None]:
        """Insert one new record; an existing identity is a conflict."""

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: ExperimentRecord,
    ) -> Result[ExperimentRecord]:
        """Replace the stored record when its revision equals ``expected_revision``;
        a mismatch or a missing row is ``PERSISTENCE.CONCURRENCY_CONFLICT``."""


@runtime_checkable
class EngineRunRepository(Protocol):
    """Persist attempt identity, transitions and terminal outcomes (spec 8.1)."""

    def get(self, run_id: RunId) -> Result[EngineRunRecord]:
        """Return the stored attempt; a missing identity is a ``Failure``."""

    def add_attempt(self, record: EngineRunRecord) -> Result[None]:
        """Insert one attempt; an existing ``run_id`` or an existing
        ``(experiment_id, logical_slot_id, attempt_number)`` is a conflict."""

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: EngineRunRecord,
    ) -> Result[EngineRunRecord]:
        """Replace the stored attempt when its revision equals ``expected_revision``."""

    def count_attempts(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
    ) -> Result[int]:
        """The number of persisted attempts of the slot, the initial one included
        (plan 8.1 gate 1); a reservation is not an attempt."""

    def latest_attempt(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        """The slot's highest-numbered attempt, or ``MISSING`` when it has none."""

    def get_by_attempt_number(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
        attempt_number: int,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        """The slot's attempt with that number, or ``MISSING`` when it has none."""


class RetryDecisionInsertOutcome(CanonicalModel):
    """Plan section 10: whether the insert won, and the stored winner either way.

    A nested value object without an envelope ``schema_version`` (plan 3.1).
    ``record`` is always the row that is durable after the call: the candidate
    when ``inserted`` is true, the pre-existing row otherwise.
    """

    inserted: bool
    record: RetryDecisionRecord


@runtime_checkable
class RetryDecisionRepository(Protocol):
    """The immutable retry decisions, keyed by predecessor (plan 3.9, 8.4)."""

    def get_by_predecessor(
        self,
        logical_slot_id: LogicalSlotId,
        predecessor_run_id: RunId,
    ) -> Result[RetryDecisionRecord]:
        """The decision recorded for the predecessor; absent is a ``Failure``."""

    def insert_if_absent(
        self,
        record: RetryDecisionRecord,
    ) -> Result[RetryDecisionInsertOutcome]:
        """Insert atomically when no row exists for the key; otherwise return the
        existing winner unchanged. Neither row is ever modified."""


@runtime_checkable
class RuntimeAvailabilityObservationReader(Protocol):
    """Primitive reads over the Stage 4 availability observations (plan 8.2)."""

    def get(
        self,
        observation_id: AvailabilityObservationId,
    ) -> Result[RuntimeAvailabilityObservation]:
        """The observation with that identity; absent is a ``Failure``."""

    def list_for_adapter(
        self,
        adapter_name: NormalizedIdentifier,
        adapter_version: SemanticVersion,
        executable_hash: Sha256,
    ) -> Result[tuple[RuntimeAvailabilityObservation, ...]]:
        """Every observation of that adapter identity, sorted by identifier;
        unbounded, so a qualifying observation is never dropped by the read."""


@runtime_checkable
class DiagnosticReader(Protocol):
    """Primitive diagnostic reads only -- no traversal (plan 8.2)."""

    def get(self, diagnostic_id: DiagnosticId) -> Result[Diagnostic]:
        """The diagnostic with that identity; absent is a ``Failure``."""

    def get_many(
        self,
        diagnostic_ids: tuple[DiagnosticId, ...],
    ) -> Result[tuple[Diagnostic, ...]]:
        """The named diagnostics, sorted by identifier; the identifiers must be
        unique and at most 256, and any missing one is a ``Failure``."""


@runtime_checkable
class UnitOfWork(Protocol):
    """One short atomic transaction over the Stage 5 repositories (spec 8.1, 23.2).

    ``begin()`` returns the active transaction; the repository members below are
    valid on it; ``commit()`` publishes every staged write or none; ``rollback()``
    discards them and is idempotent.
    """

    @property
    def experiments(self) -> ExperimentRepository:
        """The experiment repository bound to this transaction."""

    @property
    def engine_runs(self) -> EngineRunRepository:
        """The engine-run repository bound to this transaction."""

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        """The command-invocation repository bound to this transaction."""

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        """The retry-decision repository bound to this transaction."""

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        """The availability-observation reader bound to this transaction."""

    @property
    def diagnostics(self) -> DiagnosticReader:
        """The diagnostic reader bound to this transaction."""

    def begin(self) -> UnitOfWork:
        """Open one transaction and return it."""

    def commit(self) -> Result[None]:
        """Publish every write atomically, or nothing."""

    def rollback(self) -> None:
        """Discard every write; safe to call more than once."""
