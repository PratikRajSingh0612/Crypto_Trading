"""The SQLite unit of work and its transaction (plan 4.2, Task 4).

``SqliteUnitOfWork(database, clock)`` is the root; ``begin()`` checks out one
pooled connection, issues the one explicit deferred ``BEGIN`` through the
engine's begin hook, binds the six port repositories and the five
persistence-owned extras to it, and returns a ``SqliteTransaction``. Both satisfy
the Stage 5 ``UnitOfWork`` protocol structurally; the transaction's extra members
are attributes the protocol never sees (reading 11), so the port's member set is
unchanged. One DBAPI connection belongs to one open transaction and returns to
the pool at ``commit()`` or ``rollback()``; nothing holds a connection outside a
transaction.

The programmer defects of reading 2 raise ``RuntimeError``: ``begin()`` on a
transaction, a member on the root, and a member or ``commit()`` after the
transaction was released. ``rollback()`` is idempotent -- a no-op on the root,
after a commit and on a second call -- so an operation's ``finally`` clause is
always safe, and it consults the connection's ``in_transaction`` first because an
I/O error may already have ended the SQLite transaction.

Two closures are distinguished. A transaction that was *released* is finished:
every member access and ``commit()`` are defects. A transaction the I/O-class
rule *closed* still holds its connection: every member call and ``commit()``
return the stored ``Failure`` and only ``rollback()`` releases it. The same
applies from the start to a transaction whose connection could never be checked
out -- a DBAPI error, or the pool's own checkout timeout, which is not a DBAPI
error and has its own branch here -- which ``begin()`` returns closed with
``PERSISTENCE.STORAGE_UNAVAILABLE`` rather than raising.

Every member routes its statements through ``TransactionScope.open_statement``,
so a closed transaction can issue none: the six guarded members below wrap the
Task 3 classes, which were built over a bare ``Connection``, and the four
lifecycle repositories carry the same gate inside each method. One member is not
re-guarded: ``diagnostics``. A guarded wrapper for it would define both ``get``
and ``get_many`` and so become a sixth Stage 5 reader implementation, which plan
section 2.6 and acceptance criterion 12 pin at five; it is read-only, it can
publish nothing, and on a transaction that never acquired a connection accessing
it raises ``RuntimeError`` instead of answering with the stored ``Failure``. That
is the one documented departure from the section 4.2 member rule.

``commit()`` publishes every staged write or none. Over SQLite it never reports a
revision or unique-key loss -- those surface at the write (reading 3) -- so its
only failures are a checkpoint race, which is
``PERSISTENCE.CONCURRENCY_CONFLICT`` after a rollback, and the I/O class, which
is ``PERSISTENCE.WRITE_FAILED`` after a rollback.

The root keeps its open transactions so the test harness can roll back one a test
abandoned (plan 7.1). The set is strong rather than weak because ``weakref`` is
not one of the twenty-nine allowed import roots and plan section 2.6 adds no
root in this task; a transaction deregisters itself the moment it is released, so
only genuinely abandoned ones accumulate, and the plan 2.8 reclaim probe drops
the root with the transaction before collecting.
"""

from __future__ import annotations

from contextlib import ExitStack, suppress

from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.artifacts.ownership import ArtifactOwnerRef
from crypto_lab.configuration.snapshot import ConfigSnapshot
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.datasets.ports import DatasetRepository
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    DatasetId,
    ExperimentId,
    NormalizedIdentifier,
    Sha256,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.versioning import SemanticVersion
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from crypto_lab.persistence.registries import (
    SqliteArtifactOwnerRegistry,
    SqliteAvailabilityObservationReader,
    SqliteAvailabilityObservationWriter,
    SqliteConfigurationSnapshotWriter,
    SqliteDatasetRepository,
    SqliteDiagnosticReader,
    SqliteStrategyVersionRepository,
)
from crypto_lab.persistence.repositories import (
    SqliteCommandInvocationRepository,
    SqliteEngineRunRepository,
    SqliteExperimentRepository,
    SqliteRetryDecisionRepository,
    TransactionScope,
)
from crypto_lab.strategy.ports import StrategyVersionRepository
from crypto_lab.strategy.versioning import StrategyVersion

__all__ = ["SqliteTransaction", "SqliteUnitOfWork"]

_NO_TRANSACTION = "no active transaction: call begin() first"
_CLOSED = "the transaction is closed"
_NESTED = (
    "nested transactions are not supported: begin() is valid on the root "
    "unit of work only"
)


def _error_details(
    error: DBAPIError | PoolTimeoutError,
) -> dict[str, DiagnosticDetailValue]:
    """The SQLite result code of a DBAPI error; the pool's own error carries none."""
    details: dict[str, DiagnosticDetailValue] = {}
    origin = getattr(error, "orig", None)
    for name in ("sqlite_errorcode", "sqlite_errorname"):
        value = getattr(origin, name, None)
        if isinstance(value, int | str) and not isinstance(value, bool):
            details[name] = value
    return details


class _GuardedObservationWriter:
    """``SqliteAvailabilityObservationWriter`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def add(self, observation: RuntimeAvailabilityObservation) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        writer = SqliteAvailabilityObservationWriter(opened, clock=self._scope.clock)
        return writer.add(observation)


class _GuardedObservationReader:
    """``SqliteAvailabilityObservationReader`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(
        self, observation_id: AvailabilityObservationId
    ) -> Result[RuntimeAvailabilityObservation]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        reader = SqliteAvailabilityObservationReader(opened, clock=self._scope.clock)
        return reader.get(observation_id)

    def list_for_adapter(
        self,
        adapter_name: NormalizedIdentifier,
        adapter_version: SemanticVersion,
        executable_hash: Sha256,
    ) -> Result[tuple[RuntimeAvailabilityObservation, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        reader = SqliteAvailabilityObservationReader(opened, clock=self._scope.clock)
        return reader.list_for_adapter(adapter_name, adapter_version, executable_hash)


class _GuardedConfigurationSnapshots:
    """``SqliteConfigurationSnapshotWriter`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def freeze(
        self, experiment_id: ExperimentId, snapshot: ConfigSnapshot
    ) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        writer = SqliteConfigurationSnapshotWriter(opened, clock=self._scope.clock)
        return writer.freeze(experiment_id, snapshot)

    def get(self, experiment_id: ExperimentId) -> Result[ConfigSnapshot | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        writer = SqliteConfigurationSnapshotWriter(opened, clock=self._scope.clock)
        return writer.get(experiment_id)


class _GuardedArtifactOwners:
    """``SqliteArtifactOwnerRegistry`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def register(self, owner: ArtifactOwnerRef) -> Result[Sha256]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        return SqliteArtifactOwnerRegistry(opened, clock=self._scope.clock).register(
            owner
        )

    def get(self, owner_hash: Sha256) -> Result[ArtifactOwnerRef]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        return SqliteArtifactOwnerRegistry(opened, clock=self._scope.clock).get(
            owner_hash
        )


class _GuardedStrategyVersions:
    """``SqliteStrategyVersionRepository`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get_by_hash(self, content_hash: Sha256) -> Result[StrategyVersion]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        repository = SqliteStrategyVersionRepository(opened, clock=self._scope.clock)
        return repository.get_by_hash(content_hash)

    def register(self, version: StrategyVersion) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        repository = SqliteStrategyVersionRepository(opened, clock=self._scope.clock)
        return repository.register(version)


class _GuardedDatasets:
    """``SqliteDatasetRepository`` behind the transaction's gate."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get_by_hash(self, content_hash: Sha256) -> Result[DatasetDescriptor]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        return SqliteDatasetRepository(opened, clock=self._scope.clock).get_by_hash(
            content_hash
        )

    def list_partitions(
        self, dataset_id: DatasetId
    ) -> Result[tuple[DatasetPartition, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        repository = SqliteDatasetRepository(opened, clock=self._scope.clock)
        return repository.list_partitions(dataset_id)

    def register(
        self,
        descriptor: DatasetDescriptor,
        partitions: tuple[DatasetPartition, ...],
    ) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        repository = SqliteDatasetRepository(opened, clock=self._scope.clock)
        return repository.register(descriptor, partitions)


class SqliteTransaction:
    """One open transaction on one exclusively owned connection (plan 4.2)."""

    __slots__ = (
        "_artifact_owners",
        "_command_invocations",
        "_configuration_snapshots",
        "_connection",
        "_datasets",
        "_engine_runs",
        "_experiments",
        "_observation_reader",
        "_observation_writer",
        "_retry_decisions",
        "_root",
        "_scope",
        "_stack",
        "_strategy_versions",
    )

    def __init__(
        self,
        *,
        root: SqliteUnitOfWork,
        stack: ExitStack,
        connection: Connection | None,
        clock: Clock,
        failure: Failure | None,
    ) -> None:
        self._root = root
        self._stack = stack
        self._connection = connection
        self._scope = TransactionScope(
            connection=connection, clock=clock, failure=failure
        )
        self._experiments = SqliteExperimentRepository(self._scope)
        self._engine_runs = SqliteEngineRunRepository(self._scope)
        self._command_invocations = SqliteCommandInvocationRepository(self._scope)
        self._retry_decisions = SqliteRetryDecisionRepository(self._scope)
        self._observation_reader = _GuardedObservationReader(self._scope)
        self._observation_writer = _GuardedObservationWriter(self._scope)
        self._configuration_snapshots = _GuardedConfigurationSnapshots(self._scope)
        self._artifact_owners = _GuardedArtifactOwners(self._scope)
        self._strategy_versions = _GuardedStrategyVersions(self._scope)
        self._datasets = _GuardedDatasets(self._scope)

    # -- Lifecycle ---------------------------------------------------------

    def begin(self) -> SqliteTransaction:
        """A programmer defect: a transaction never nests (reading 2)."""
        raise RuntimeError(_NESTED)

    def commit(self) -> Result[None]:
        """Publish every staged write, or none (plan 4.2)."""
        self._require_live()
        stored = self._scope.failure
        if stored is not None:
            self._release()
            return stored
        connection = self._connection
        if connection is None:  # pragma: no cover - set with ``failure``
            raise RuntimeError(_CLOSED)
        try:
            connection.commit()
        except DBAPIError as error:
            return self._commit_failure(error)
        except BaseException:
            # Anything else escaping a commit is a defect, but the connection is
            # still ours: release it before the exception leaves, so no pooled
            # connection is stranded by a path that returns no ``Result``.
            self.rollback()
            raise
        self._release()
        return Success[None](outcome="SUCCESS", value=None)

    def rollback(self) -> None:
        """Discard every staged write and release the connection; idempotent."""
        if self._scope.finished:
            return
        connection = self._connection
        try:
            if connection is not None and connection.in_transaction():
                # An I/O error may already have ended the SQLite transaction.
                with suppress(DBAPIError):
                    connection.rollback()
        finally:
            self._release()

    def _commit_failure(self, error: DBAPIError) -> Failure:
        """Plan 4.2: a checkpoint race is the conflict, the I/O class the write
        failure; both roll back first and release the connection."""
        code = SqliteDatabase.classify(error)
        if code != CONCURRENCY_CONFLICT:
            code = WRITE_FAILED
        details: dict[str, DiagnosticDetailValue] = {
            "operation": "commit",
            **_error_details(error),
        }
        failure = persistence_failure(
            code,
            message="the transaction could not be committed",
            clock=self._scope.clock,
            details=details,
        )
        self.rollback()
        return failure

    def open_failure(self) -> Failure | None:
        """The stored ``Failure`` of a transaction the I/O-class rule closed.

        ``None`` while the transaction is usable. Exposed so a test can tell a
        closed transaction from a released one without reaching into the scope.
        """
        return self._scope.failure

    def _require_live(self) -> None:
        if self._scope.finished:
            raise RuntimeError(_CLOSED)

    def _release(self) -> None:
        self._scope.finish()
        self._connection = None
        try:
            self._stack.close()
        finally:
            self._root.forget(self)

    def _reading_connection(self) -> Connection:
        """The connection the unguarded diagnostic reader binds to.

        A finished transaction and one closed by a storage failure are both
        programmer defects here; see the module docstring for why this member
        alone cannot answer a closed transaction with its stored ``Failure``.
        """
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            raise RuntimeError(_CLOSED)
        return opened

    # -- The six port members ----------------------------------------------

    @property
    def experiments(self) -> ExperimentRepository:
        """The experiment repository bound to this transaction."""
        self._require_live()
        return self._experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        """The engine-run repository bound to this transaction."""
        self._require_live()
        return self._engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        """The command-invocation repository bound to this transaction."""
        self._require_live()
        return self._command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        """The retry-decision repository bound to this transaction."""
        self._require_live()
        return self._retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        """The availability-observation reader bound to this transaction."""
        self._require_live()
        return self._observation_reader

    @property
    def diagnostics(self) -> DiagnosticReader:
        """The diagnostic reader bound to this transaction (reads only)."""
        self._require_live()
        return SqliteDiagnosticReader(
            self._reading_connection(), clock=self._scope.clock
        )

    # -- The five persistence-owned extras (reading 11) ---------------------

    @property
    def availability_observation_writer(self) -> _GuardedObservationWriter:
        """The insert-once observation writer; not a port member."""
        self._require_live()
        return self._observation_writer

    @property
    def configuration_snapshots(self) -> _GuardedConfigurationSnapshots:
        """The sole writer of the four frozen-snapshot columns (reading 22)."""
        self._require_live()
        return self._configuration_snapshots

    @property
    def artifact_owners(self) -> _GuardedArtifactOwners:
        """The artifact-owner registry keyed by ``artifact_owner_hash``."""
        self._require_live()
        return self._artifact_owners

    @property
    def strategy_versions(self) -> StrategyVersionRepository:
        """The strategy-version registry port (reading 12)."""
        self._require_live()
        return self._strategy_versions

    @property
    def datasets(self) -> DatasetRepository:
        """The dataset registry port (reading 12)."""
        self._require_live()
        return self._datasets


class SqliteUnitOfWork:
    """The root: ``begin()`` opens one transaction over the database (plan 4.2)."""

    __slots__ = ("_clock", "_database", "_open")

    def __init__(self, database: SqliteDatabase, clock: Clock) -> None:
        self._database = database
        self._clock = clock
        self._open: list[SqliteTransaction] = []

    def begin(self) -> SqliteTransaction:
        """Check out one connection, issue the deferred ``BEGIN``, bind the members.

        A checkout or ``BEGIN`` that cannot succeed returns a closed transaction
        carrying ``PERSISTENCE.STORAGE_UNAVAILABLE`` rather than raising, so the
        caller's ``Result`` discipline is never broken by a storage outage.
        """
        stack = ExitStack()
        connection: Connection | None = None
        failure: Failure | None = None
        try:
            connection = stack.enter_context(self._database.connection())
            connection.begin()
        except (DBAPIError, PoolTimeoutError) as error:
            failure = persistence_failure(
                STORAGE_UNAVAILABLE,
                message="the transaction could not be opened",
                clock=self._clock,
                details={"operation": "begin", **_error_details(error)},
            )
        transaction = SqliteTransaction(
            root=self,
            stack=stack,
            connection=connection,
            clock=self._clock,
            failure=failure,
        )
        self._open.append(transaction)
        return transaction

    def commit(self) -> Result[None]:
        """A programmer defect: the root holds no transaction (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    def rollback(self) -> None:
        """A no-op: the root holds nothing to discard."""

    def open_transactions(self) -> tuple[SqliteTransaction, ...]:
        """Every transaction this root opened and neither committed nor rolled back."""
        return tuple(self._open)

    def forget(self, transaction: SqliteTransaction) -> None:
        """Deregister a released transaction so only abandoned ones survive."""
        self._open = [item for item in self._open if item is not transaction]

    @property
    def experiments(self) -> ExperimentRepository:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    @property
    def engine_runs(self) -> EngineRunRepository:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)

    @property
    def diagnostics(self) -> DiagnosticReader:
        """A programmer defect on the root (reading 2)."""
        raise RuntimeError(_NO_TRANSACTION)
