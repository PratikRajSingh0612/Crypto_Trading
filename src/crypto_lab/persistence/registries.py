"""The insert-only registries, readers and the diagnostic recorder (plan 4.4, Task 3).

Eight persistence-owned classes over the Task 2 tables and the Task 3 codecs:

- ``SqliteDiagnosticReader`` implements the Stage 5 ``DiagnosticReader`` port with
  primitive reads only (no traversal, plan 8.2): ``get`` and ``get_many`` (sorted
  by identifier, unique, at most 256, any missing one a ``Failure``), each row
  rebuilt through ``decode_diagnostic`` and never through the causal relation.
- ``SqliteDiagnosticRecorder`` implements ``DiagnosticRecorder`` over the
  ``SqliteDatabase`` itself: every ``record`` call is its own short write
  transaction -- ``INSERT ... ON CONFLICT (diagnostic_id) DO NOTHING``, a
  read-back of the stored row, then the two set-based edge statements of plan
  3.3.9 that derive ``diagnostic_causes`` from the **stored** JSON column through
  ``json_each`` (forward edges to recorded causes, back edges from recorded
  referrers), then ``COMMIT`` -- so the relation converges under every recording
  order (reading 23) and is committed before the caller's next ``begin()`` (plan
  1.5 note 3). A stored row whose content differs from the argument in any field
  other than ``timestamp_utc`` is ``CORE.INVARIANT_VIOLATION`` and the transaction
  is rolled back before the edge statements run; a refused edge statement rolls
  the diagnostic row back with it. This method is the only writer of
  ``diagnostic_causes``.
- ``SqliteAvailabilityObservationReader`` implements the Stage 5
  ``RuntimeAvailabilityObservationReader`` port (``list_for_adapter`` sorted by
  identifier, unbounded); ``SqliteAvailabilityObservationWriter.add`` is the
  insert-once writer (an identical row -- same identity, same ``content_sha256``
  -- is an idempotent ``Success``; the same identity with another fingerprint is
  the invariant).
- ``SqliteConfigurationSnapshotWriter`` is the Stage 8-owned typed ingress of the
  frozen configuration snapshot (reading 22): ``freeze`` pre-reads the experiment
  row (missing -> INV ``does not exist``), refuses a stored snapshot at or after
  ``QUEUED`` unless the argument equals it field for field (idempotent), and
  otherwise writes the four snapshot columns with one ``UPDATE`` that never
  touches ``revision``; ``get`` rebuilds ``ConfigSnapshot`` from the four columns
  through the record's own validator (a tampered byte is the invariant) or
  returns ``MISSING`` while no snapshot is frozen. This method is the only writer
  of the four snapshot columns.
- ``SqliteStrategyVersionRepository`` and ``SqliteDatasetRepository`` implement
  the two Task 3 ports (reading 12): identical content is an idempotent
  ``Success``; a different record under the same hash, a second version of one
  strategy at one ``created_at_utc``, or an identity-inconsistent dataset pair is
  the invariant, decided by a pre-insert read inside the transaction; a colliding
  row committed by another connection after this transaction's snapshot surfaces
  at the insert as reading 3's ``PERSISTENCE.CONCURRENCY_CONFLICT``.
  ``register(descriptor, partitions)`` runs its inserts inside one ``SAVEPOINT``
  so a refused partition insert leaves no descriptor row staged (reading 21).
- ``SqliteArtifactOwnerRegistry`` registers the six owner variants idempotently
  on ``owner_hash``; a foreign-key refusal (an unpersisted experiment, run,
  invocation, dataset or strategy version) is the invariant.

Except for the recorder, every class is constructed over the caller's
``Connection`` and issues Core statements inside the enclosing transaction: it
never commits, never rolls the transaction back and never opens a session of its
own. A refused statement is mapped through ``SqliteDatabase.classify`` (plan 6.5)
into one persistence diagnostic stamped from the injected clock, carrying the
table, the operation, the identity and the SQLite result code; SQLite aborts the
statement alone, so the caller's transaction stays usable (reading 3). No
persistence module reads ``causal_diagnostic_ids`` by attribute: the codec
serializes it through ``model_dump`` and the recorder's edge statements read the
stored JSON column.
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import select, text, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from crypto_lab.artifacts.ownership import ArtifactOwnerRef, artifact_owner_hash
from crypto_lab.configuration.snapshot import ConfigSnapshot
from crypto_lab.datasets.hashing import validate_dataset_identity
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    DatasetId,
    DiagnosticId,
    ExperimentId,
    NormalizedIdentifier,
    Sha256,
)
from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.versioning import SemanticVersion
from crypto_lab.persistence.codecs import (
    decode_artifact_owner,
    decode_dataset,
    decode_dataset_partition,
    decode_diagnostic,
    decode_observation,
    decode_strategy_version,
    encode_artifact_owner,
    encode_dataset,
    encode_dataset_partition,
    encode_diagnostic,
    encode_observation,
    encode_strategy_version,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    persistence_failure,
)
from crypto_lab.persistence.schema import (
    ArtifactOwnerRow,
    DatasetPartitionRow,
    DatasetRow,
    DiagnosticRow,
    ExperimentRow,
    RuntimeAvailabilityObservationRow,
    StrategyVersionRow,
)
from crypto_lab.strategy.versioning import StrategyVersion

__all__ = [
    "MAX_DIAGNOSTICS_PER_READ",
    "SqliteArtifactOwnerRegistry",
    "SqliteAvailabilityObservationReader",
    "SqliteAvailabilityObservationWriter",
    "SqliteConfigurationSnapshotWriter",
    "SqliteDatasetRepository",
    "SqliteDiagnosticReader",
    "SqliteDiagnosticRecorder",
    "SqliteStrategyVersionRepository",
]

#: Stage 5 plan 8.2: the traversal's node bound is the ``get_many`` bound.
MAX_DIAGNOSTICS_PER_READ: Final = 256
#: Plan 3.3.9, reading 23: the two set-based edge statements. Both read the stored
#: JSON column through ``json_each`` and select only existing endpoints; the
#: ``WHERE`` clauses are required by SQLite's upsert grammar over a ``SELECT``.
_FORWARD_EDGES: Final = (
    "INSERT INTO diagnostic_causes (diagnostic_id, causal_diagnostic_id) "
    "SELECT d.diagnostic_id, j.value "
    "FROM diagnostics d, json_each(d.causal_diagnostic_ids) j "
    "WHERE d.diagnostic_id = :diagnostic_id "
    "AND j.value IN (SELECT diagnostic_id FROM diagnostics) "
    "ON CONFLICT DO NOTHING"
)
_BACK_EDGES: Final = (
    "INSERT INTO diagnostic_causes (diagnostic_id, causal_diagnostic_id) "
    "SELECT d.diagnostic_id, :diagnostic_id "
    "FROM diagnostics d, json_each(d.causal_diagnostic_ids) j "
    "WHERE j.value = :diagnostic_id "
    "ON CONFLICT DO NOTHING"
)
#: Plan 4.4: a snapshot may be replaced only while the experiment is pre-QUEUED.
_PRE_QUEUE_STATES: Final = frozenset(
    {ExperimentState.DRAFT.value, ExperimentState.VALIDATED.value}
)
_SNAPSHOT_COLUMNS: Final = (
    ExperimentRow.configuration_snapshot_schema_version,
    ExperimentRow.configuration_snapshot_json,
    ExperimentRow.configuration_audit_hash,
    ExperimentRow.material_base_configuration_hash,
)


# --------------------------------------------------------------------------
# Failure construction (plan 6.5)
# --------------------------------------------------------------------------


def _sqlite_details(
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


def _refused(
    error: DBAPIError | PoolTimeoutError,
    *,
    table: str,
    operation: str,
    identity: str,
    clock: Clock,
) -> Failure:
    """A refused statement or checkout mapped through the single failure authority."""
    details: dict[str, DiagnosticDetailValue] = {
        "table": table,
        "operation": operation,
        "identity": identity,
        **_sqlite_details(error),
    }
    return persistence_failure(
        SqliteDatabase.classify(error),
        message=f"{operation} on {table} was refused by the database",
        clock=clock,
        details=details,
    )


def _invariant(
    message: str, *, table: str, operation: str, identity: str, clock: Clock
) -> Failure:
    return persistence_failure(
        INVARIANT_VIOLATION,
        message=message,
        clock=clock,
        details={"table": table, "operation": operation, "identity": identity},
    )


def _missing(
    kind: str,
    identity: str,
    *,
    table: str,
    clock: Clock,
    operation: str = "get",
) -> Failure:
    """Reading 4: a missing identity is the invariant and says ``does not exist``."""
    return _invariant(
        f"{kind} {identity} does not exist",
        table=table,
        operation=operation,
        identity=identity,
        clock=clock,
    )


def _none() -> Success[None]:
    return Success[None](outcome="SUCCESS", value=None)


def _values(row: RowMapping) -> dict[str, object]:
    """One stored row as the codecs' ``Mapping[str, object]``.

    A ``RowMapping`` is keyed by column name here (every read selects a ``*Row``
    class), but SQLAlchemy types its keys wider than ``str``; the copy narrows
    the type without changing a value.
    """
    return {str(key): value for key, value in row.items()}


# --------------------------------------------------------------------------
# Diagnostics: the reader and the recorder (plan 4.4, 3.3.8, 3.3.9)
# --------------------------------------------------------------------------


class SqliteDiagnosticReader:
    """Primitive diagnostic reads over one transaction's connection (plan 8.2)."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def get(self, diagnostic_id: DiagnosticId) -> Result[Diagnostic]:
        row = (
            self._connection.execute(
                select(DiagnosticRow).where(
                    DiagnosticRow.diagnostic_id == diagnostic_id
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return _missing(
                "diagnostic", diagnostic_id, table="diagnostics", clock=self._clock
            )
        return decode_diagnostic(_values(row), clock=self._clock)

    def get_many(
        self, diagnostic_ids: tuple[DiagnosticId, ...]
    ) -> Result[tuple[Diagnostic, ...]]:
        if len(set(diagnostic_ids)) != len(diagnostic_ids):
            return _invariant(
                "diagnostic identifiers must be unique",
                table="diagnostics",
                operation="get_many",
                identity="",
                clock=self._clock,
            )
        if len(diagnostic_ids) > MAX_DIAGNOSTICS_PER_READ:
            return _invariant(
                f"at most {MAX_DIAGNOSTICS_PER_READ} diagnostics per read",
                table="diagnostics",
                operation="get_many",
                identity="",
                clock=self._clock,
            )
        if not diagnostic_ids:
            return Success[tuple[Diagnostic, ...]](outcome="SUCCESS", value=())
        rows = (
            self._connection.execute(
                select(DiagnosticRow)
                .where(DiagnosticRow.diagnostic_id.in_(diagnostic_ids))
                .order_by(DiagnosticRow.diagnostic_id)
            )
            .mappings()
            .all()
        )
        found = {str(row["diagnostic_id"]) for row in rows}
        missing = sorted(set(diagnostic_ids) - found)
        if missing:
            return _missing(
                "diagnostic",
                missing[0],
                table="diagnostics",
                clock=self._clock,
                operation="get_many",
            )
        decoded = [decode_diagnostic(_values(row), clock=self._clock) for row in rows]
        failures = [item for item in decoded if isinstance(item, Failure)]
        if failures:
            return failures[0]
        return Success[tuple[Diagnostic, ...]](
            outcome="SUCCESS",
            value=tuple(item.value for item in decoded if isinstance(item, Success)),
        )


def _content_without_timestamp(diagnostic: Diagnostic) -> bytes:
    """Plan 4.4: every field but ``timestamp_utc`` decides identity reuse."""
    payload = diagnostic.model_dump(mode="json")
    del payload["timestamp_utc"]
    return canonical_json_bytes(payload)


class SqliteDiagnosticRecorder:
    """``DiagnosticRecorder`` over the database: one autonomous transaction per call."""

    __slots__ = ("_clock", "_database")

    def __init__(self, database: SqliteDatabase, *, clock: Clock) -> None:
        self._database = database
        self._clock = clock

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        values = encode_diagnostic(diagnostic)
        identity = diagnostic.diagnostic_id
        # The checkout sits inside the ``try`` so an exhausted pool or a DBAPI
        # error at connect is the classified ``Failure`` too; leaving the ``with``
        # block without ``commit()`` rolls the transaction back.
        try:
            with self._database.connection() as connection:
                connection.execute(
                    insert(DiagnosticRow)
                    .values(**values)
                    .on_conflict_do_nothing(index_elements=["diagnostic_id"])
                )
                row = (
                    connection.execute(
                        select(DiagnosticRow).where(
                            DiagnosticRow.diagnostic_id == identity
                        )
                    )
                    .mappings()
                    .one()
                )
                stored = decode_diagnostic(_values(row), clock=self._clock)
                if isinstance(stored, Failure):
                    connection.rollback()
                    return stored
                if _content_without_timestamp(
                    stored.value
                ) != _content_without_timestamp(diagnostic):
                    connection.rollback()
                    return _invariant(
                        f"diagnostic {identity} is already recorded with different "
                        "content",
                        table="diagnostics",
                        operation="record",
                        identity=identity,
                        clock=self._clock,
                    )
                connection.execute(text(_FORWARD_EDGES), {"diagnostic_id": identity})
                connection.execute(text(_BACK_EDGES), {"diagnostic_id": identity})
                connection.commit()
        except (DBAPIError, PoolTimeoutError) as error:
            return _refused(
                error,
                table="diagnostics",
                operation="record",
                identity=identity,
                clock=self._clock,
            )
        return _none()


# --------------------------------------------------------------------------
# Availability observations: the reader and the writer (plan 4.4, 3.3.7)
# --------------------------------------------------------------------------


class SqliteAvailabilityObservationReader:
    """``RuntimeAvailabilityObservationReader`` over one transaction's connection."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def get(
        self, observation_id: AvailabilityObservationId
    ) -> Result[RuntimeAvailabilityObservation]:
        row = (
            self._connection.execute(
                select(RuntimeAvailabilityObservationRow).where(
                    RuntimeAvailabilityObservationRow.availability_observation_id
                    == observation_id
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return _missing(
                "availability observation",
                observation_id,
                table="runtime_availability_observations",
                clock=self._clock,
            )
        return decode_observation(_values(row), clock=self._clock)

    def list_for_adapter(
        self,
        adapter_name: NormalizedIdentifier,
        adapter_version: SemanticVersion,
        executable_hash: Sha256,
    ) -> Result[tuple[RuntimeAvailabilityObservation, ...]]:
        table = RuntimeAvailabilityObservationRow
        rows = (
            self._connection.execute(
                select(table)
                .where(
                    table.adapter_name == adapter_name,
                    table.adapter_version == adapter_version,
                    table.executable_hash == executable_hash,
                )
                .order_by(table.availability_observation_id)
            )
            .mappings()
            .all()
        )
        decoded = [decode_observation(_values(row), clock=self._clock) for row in rows]
        failures = [item for item in decoded if isinstance(item, Failure)]
        if failures:
            return failures[0]
        return Success[tuple[RuntimeAvailabilityObservation, ...]](
            outcome="SUCCESS",
            value=tuple(item.value for item in decoded if isinstance(item, Success)),
        )


class SqliteAvailabilityObservationWriter:
    """Insert-once observations inside the enclosing transaction (reading 11)."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def add(self, observation: RuntimeAvailabilityObservation) -> Result[None]:
        values = encode_observation(observation)
        identity = observation.availability_observation_id
        table = "runtime_availability_observations"
        try:
            stored = self._connection.execute(
                select(RuntimeAvailabilityObservationRow.content_sha256).where(
                    RuntimeAvailabilityObservationRow.availability_observation_id
                    == identity
                )
            ).scalar_one_or_none()
            if stored is not None:
                if stored == values["content_sha256"]:
                    return _none()
                return _invariant(
                    f"availability observation {identity} is already stored with "
                    "different content",
                    table=table,
                    operation="add",
                    identity=identity,
                    clock=self._clock,
                )
            self._connection.execute(
                insert(RuntimeAvailabilityObservationRow).values(**values)
            )
        except DBAPIError as error:
            return _refused(
                error,
                table=table,
                operation="add",
                identity=identity,
                clock=self._clock,
            )
        return _none()


# --------------------------------------------------------------------------
# The frozen configuration snapshot (plan 4.4, reading 22)
# --------------------------------------------------------------------------


class SqliteConfigurationSnapshotWriter:
    """The typed ingress and self-checking egress of the frozen snapshot."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def _row(self, experiment_id: ExperimentId) -> Any:
        return (
            self._connection.execute(
                select(ExperimentRow.state, *_SNAPSHOT_COLUMNS).where(
                    ExperimentRow.experiment_id == experiment_id
                )
            )
            .mappings()
            .first()
        )

    def freeze(
        self, experiment_id: ExperimentId, snapshot: ConfigSnapshot
    ) -> Result[None]:
        row = self._row(experiment_id)
        if row is None:
            return _missing(
                "experiment",
                experiment_id,
                table="experiments",
                clock=self._clock,
                operation="freeze",
            )
        argument = (
            snapshot.schema_version,
            snapshot.configuration_json,
            snapshot.configuration_audit_hash,
            snapshot.material_base_configuration_hash,
        )
        stored = tuple(row[column.key] for column in _SNAPSHOT_COLUMNS)
        if row["configuration_snapshot_json"] is not None and (
            row["state"] not in _PRE_QUEUE_STATES
        ):
            if stored == argument:
                return _none()
            return _invariant(
                f"configuration snapshot of experiment {experiment_id} is frozen at "
                "QUEUED",
                table="experiments",
                operation="freeze",
                identity=experiment_id,
                clock=self._clock,
            )
        try:
            self._connection.execute(
                update(ExperimentRow)
                .where(ExperimentRow.experiment_id == experiment_id)
                .values(
                    configuration_snapshot_schema_version=snapshot.schema_version,
                    configuration_snapshot_json=snapshot.configuration_json,
                    configuration_audit_hash=snapshot.configuration_audit_hash,
                    material_base_configuration_hash=(
                        snapshot.material_base_configuration_hash
                    ),
                )
            )
        except DBAPIError as error:
            return _refused(
                error,
                table="experiments",
                operation="freeze",
                identity=experiment_id,
                clock=self._clock,
            )
        return _none()

    def get(self, experiment_id: ExperimentId) -> Result[ConfigSnapshot | MISSING]:  # type: ignore[valid-type]
        row = self._row(experiment_id)
        if row is None:
            return _missing(
                "experiment", experiment_id, table="experiments", clock=self._clock
            )
        if row["configuration_snapshot_json"] is None:
            absent: Any = MISSING
            return Success(outcome="SUCCESS", value=absent)
        try:
            snapshot = ConfigSnapshot.model_validate(
                {
                    "schema_version": row["configuration_snapshot_schema_version"],
                    "configuration_json": row["configuration_snapshot_json"],
                    "configuration_audit_hash": row["configuration_audit_hash"],
                    "material_base_configuration_hash": row[
                        "material_base_configuration_hash"
                    ],
                }
            )
        except ValidationError as error:
            errors = error.errors()
            location = (
                ".".join(str(part) for part in errors[0]["loc"]) if errors else "record"
            )
            return persistence_failure(
                INVARIANT_VIOLATION,
                message="stored configuration snapshot failed egress validation",
                clock=self._clock,
                details={
                    "table": "experiments",
                    "identity": experiment_id,
                    "location": location or "record",
                    "operation": "get",
                },
            )
        return Success[ConfigSnapshot](outcome="SUCCESS", value=snapshot)


# --------------------------------------------------------------------------
# The two registry ports (plan 4.4, reading 12)
# --------------------------------------------------------------------------


class SqliteStrategyVersionRepository:
    """``StrategyVersionRepository`` over one transaction's connection."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def get_by_hash(self, content_hash: Sha256) -> Result[StrategyVersion]:
        row = (
            self._connection.execute(
                select(StrategyVersionRow).where(
                    StrategyVersionRow.content_hash == content_hash
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return _missing(
                "strategy version",
                content_hash,
                table="strategy_versions",
                clock=self._clock,
            )
        return decode_strategy_version(_values(row), clock=self._clock)

    def register(self, version: StrategyVersion) -> Result[None]:
        values = encode_strategy_version(version)
        identity = version.content_hash
        try:
            existing = self._connection.execute(
                select(StrategyVersionRow.record).where(
                    StrategyVersionRow.content_hash == identity
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing == values["record"]:
                    return _none()
                return _invariant(
                    f"strategy version {identity} is already registered with a "
                    "different record",
                    table="strategy_versions",
                    operation="register",
                    identity=identity,
                    clock=self._clock,
                )
            colliding = self._connection.execute(
                select(StrategyVersionRow.content_hash).where(
                    StrategyVersionRow.strategy_id == values["strategy_id"],
                    StrategyVersionRow.created_at_utc == values["created_at_utc"],
                )
            ).scalar_one_or_none()
            if colliding is not None:
                return _invariant(
                    f"strategy {version.strategy_id} already has a version at "
                    "the same created_at_utc",
                    table="strategy_versions",
                    operation="register",
                    identity=identity,
                    clock=self._clock,
                )
            self._connection.execute(insert(StrategyVersionRow).values(**values))
        except DBAPIError as error:
            return _refused(
                error,
                table="strategy_versions",
                operation="register",
                identity=identity,
                clock=self._clock,
            )
        return _none()


class SqliteDatasetRepository:
    """``DatasetRepository`` over one transaction's connection."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def get_by_hash(self, content_hash: Sha256) -> Result[DatasetDescriptor]:
        row = (
            self._connection.execute(
                select(DatasetRow).where(DatasetRow.content_hash == content_hash)
            )
            .mappings()
            .first()
        )
        if row is None:
            return _missing(
                "dataset", content_hash, table="datasets", clock=self._clock
            )
        return decode_dataset(_values(row), clock=self._clock)

    def list_partitions(
        self, dataset_id: DatasetId
    ) -> Result[tuple[DatasetPartition, ...]]:
        known = self._connection.execute(
            select(DatasetRow.dataset_id).where(DatasetRow.dataset_id == dataset_id)
        ).scalar_one_or_none()
        if known is None:
            return _missing(
                "dataset",
                dataset_id,
                table="datasets",
                clock=self._clock,
                operation="list_partitions",
            )
        rows = (
            self._connection.execute(
                select(DatasetPartitionRow)
                .where(DatasetPartitionRow.dataset_id == dataset_id)
                .order_by(DatasetPartitionRow.ordinal)
            )
            .mappings()
            .all()
        )
        decoded = [
            decode_dataset_partition(_values(row), clock=self._clock) for row in rows
        ]
        failures = [item for item in decoded if isinstance(item, Failure)]
        if failures:
            return failures[0]
        return Success[tuple[DatasetPartition, ...]](
            outcome="SUCCESS",
            value=tuple(item.value for item in decoded if isinstance(item, Success)),
        )

    def register(
        self,
        descriptor: DatasetDescriptor,
        partitions: tuple[DatasetPartition, ...],
    ) -> Result[None]:
        identity = descriptor.content_hash
        try:
            validate_dataset_identity(descriptor, partitions)
        except ValueError as error:
            return _invariant(
                f"dataset registration refused: {error}",
                table="datasets",
                operation="register",
                identity=identity,
                clock=self._clock,
            )
        values = encode_dataset(descriptor)
        partition_values = [encode_dataset_partition(item) for item in partitions]
        table = "datasets"
        try:
            existing = self._connection.execute(
                select(DatasetRow.record).where(DatasetRow.content_hash == identity)
            ).scalar_one_or_none()
            if existing is not None:
                if existing == values["record"]:
                    return _none()
                return _invariant(
                    f"dataset content hash {identity} is already registered under a "
                    "different descriptor",
                    table=table,
                    operation="register",
                    identity=identity,
                    clock=self._clock,
                )
            # Reading 21: one savepoint around the descriptor and its partitions,
            # so a refused partition insert leaves no descriptor row staged.
            with self._connection.begin_nested():
                self._connection.execute(insert(DatasetRow).values(**values))
                table = "dataset_partitions"
                for partition in partition_values:
                    self._connection.execute(
                        insert(DatasetPartitionRow).values(**partition)
                    )
        except DBAPIError as error:
            return _refused(
                error,
                table=table,
                operation="register",
                identity=identity,
                clock=self._clock,
            )
        return _none()


# --------------------------------------------------------------------------
# The artifact-owner registry (plan 4.4, 3.3.12, reading 8)
# --------------------------------------------------------------------------


class SqliteArtifactOwnerRegistry:
    """The six ``ArtifactOwnerRef`` variants keyed by ``owner_hash``."""

    __slots__ = ("_clock", "_connection")

    def __init__(self, connection: Connection, *, clock: Clock) -> None:
        self._connection = connection
        self._clock = clock

    def register(self, owner: ArtifactOwnerRef) -> Result[Sha256]:
        owner_hash = artifact_owner_hash(owner)
        try:
            existing = self._connection.execute(
                select(ArtifactOwnerRow.owner_hash).where(
                    ArtifactOwnerRow.owner_hash == owner_hash
                )
            ).scalar_one_or_none()
            if existing is None:
                self._connection.execute(
                    insert(ArtifactOwnerRow).values(**encode_artifact_owner(owner))
                )
        except DBAPIError as error:
            return _refused(
                error,
                table="artifact_owners",
                operation="register",
                identity=owner_hash,
                clock=self._clock,
            )
        return Success[Sha256](outcome="SUCCESS", value=owner_hash)

    def get(self, owner_hash: Sha256) -> Result[ArtifactOwnerRef]:
        row = (
            self._connection.execute(
                select(ArtifactOwnerRow).where(
                    ArtifactOwnerRow.owner_hash == owner_hash
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return _missing(
                "artifact owner", owner_hash, table="artifact_owners", clock=self._clock
            )
        return decode_artifact_owner(_values(row), clock=self._clock)
