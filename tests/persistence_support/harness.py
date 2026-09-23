"""SQLite test support helpers for the Stage 8 persistence suites (plan 7.1).

Task 1 creates this module with exactly five helpers -- ``raw_connection``,
``file_sha256``, ``accept_any_revision``, ``ok`` and ``code`` -- and later tasks
extend it as plan section 7.1 tabulates, each helper in the task that first needs
it. ``raw_connection`` is the independent stdlib connection the concurrency cases
use for lock holders and raw statements; it is never bound to the engine under
test. ``file_sha256`` serves the no-mutation assertions of the refused opens.
``accept_any_revision`` is the accepting ``revision_policy`` the Task 1 database
probes pass to ``SqliteDatabase.open`` (written ``_accept`` in the plan's
sketches) so an unmigrated file opens. ``ok`` and ``code`` are the two ``Result``
narrowers every later task's tests use, with the same shapes as the shared
contract module's private ``_ok`` and ``_code`` helpers, which stay private and
are not imported here. Task 2 adds ``open_test_database``: ``open_for_migration``
on ``tmp_path / "registry.sqlite3"`` followed by ``apply_migrations`` only when
the revision report is not yet ``CURRENT``, so one helper serves the first open
and every reopen of a migrated file.

Task 3 adds five helpers (plan 7.1): ``causal_edges`` reads the restricted
``diagnostic_causes`` relation through a raw connection, ordered by both columns;
``install_refusing_edge_trigger`` and ``install_refusing_partition_trigger``
install the two test-only ``BEFORE INSERT`` triggers of cases C-31 and C-29 (c)
from fixed DDL text -- the partition trigger's ``WHEN`` clause carries an integer
literal rendered from ``int(ordinal)``, never an identity or a bound parameter,
because SQLite admits no variable inside ``CREATE TRIGGER``; ``sample_strategy_version``
builds one valid ``StrategyVersion`` over a fixed ``StrategySpec`` (the committed
``sma_cross_long.valid.yaml`` document as plain data) with ``content_hash`` computed
by the versioning module's own hash function, so the record's
``validate_identity_is_recomputed`` accepts it and a second call returns an equal
record; ``sample_dataset_with_partitions`` builds one ``DatasetDescriptor`` and
exactly two ``DatasetPartition`` values at ordinals 0 and 1, identity-consistent
through ``validate_dataset_identity``, the second partition being the one C-29 (c)'s
trigger refuses. The two builders import only the committed ``strategy`` and
``datasets`` modules and the doubles' constants; nothing here imports a lifecycle
repository, ``fixtures.py`` or ``SqliteHarness`` (Task 4). The module never
imports ``subprocess`` and never launches a child.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from sqlalchemy.engine import Connection

from crypto_lab.datasets.hashing import dataset_metadata_hash, validate_dataset_identity
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.records import InstrumentRef, MarketType
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    apply_migrations,
    check_revision,
    open_for_migration,
)
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategySourceProvenance,
    StrategyVersion,
    sorted_extension_hashes,
    strategy_version_hash,
    strategy_version_identifier,
)
from doubles.experiments import INSTANT, UUID_A, UUID_B

__all__ = [
    "accept_any_revision",
    "causal_edges",
    "code",
    "file_sha256",
    "install_refusing_edge_trigger",
    "install_refusing_partition_trigger",
    "ok",
    "open_test_database",
    "raw_connection",
    "sample_dataset_with_partitions",
    "sample_strategy_version",
]

#: Plan 7.1: the two test-only triggers, fixed DDL text (C-31, C-29 (c)).
_REFUSING_EDGE_TRIGGER: Final = (
    "CREATE TRIGGER test_refuse_edge BEFORE INSERT ON diagnostic_causes "
    "BEGIN SELECT RAISE(ABORT, 'test: edge refused'); END"
)
_REFUSING_PARTITION_TRIGGER_HEAD: Final = (
    "CREATE TRIGGER test_refuse_partition BEFORE INSERT ON dataset_partitions "
    "WHEN NEW.ordinal = "
)
_REFUSING_PARTITION_TRIGGER_TAIL: Final = (
    " BEGIN SELECT RAISE(ABORT, 'test: partition refused'); END"
)
_CAUSAL_EDGES_SQL: Final = (
    "SELECT diagnostic_id, causal_diagnostic_id FROM diagnostic_causes ORDER BY 1, 2"
)

#: The committed ``sma_cross_long.valid.yaml`` document as plain data, so the
#: fixed ``StrategySpec`` needs no file read; validated in JSON mode below.
_STRATEGY_SPEC_DOCUMENT: Final[dict[str, Any]] = {
    "schema_version": "1.0.0",
    "strategy_id": "strat_3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "display_name": "SMA Cross Long",
    "description": (
        "Enters long when a fast average crosses above a slow average and exits "
        "on the reverse cross."
    ),
    "strategy_family": "trend_following",
    "market_type": "SPOT",
    "direction": "LONG",
    "timeframe": "1h",
    "universe": {"kind": "STATIC", "instruments": ["BINANCE:BTC/USDT:SPOT"]},
    "required_capabilities": [
        {
            "schema_version": "1.0.0",
            "capability": capability,
            "required": True,
            "minimum_semantics": "capabilities/v1",
            "approximation_policy": "REJECT",
            "comparison_levels": levels,
        }
        for capability, levels in (
            ("market.spot", ["LEVEL_1", "LEVEL_2"]),
            ("direction.long", ["LEVEL_1", "LEVEL_2"]),
            ("data.ohlcv", ["LEVEL_1", "LEVEL_2"]),
            ("execution.bar_market", ["LEVEL_2"]),
            ("runtime.backtest", []),
        )
    ],
    "parameters": {
        "fast_period": {"value_type": "INTEGER", "value": 20, "minimum": 2},
        "slow_period": {"value_type": "INTEGER", "value": 50, "minimum": 3},
    },
    "features": [
        {
            "id": "fast_sma",
            "operation": "indicator.sma/v1",
            "inputs": ["bar.close"],
            "parameters": {"period": "fast_period"},
            "output_type": "DECIMAL",
            "warm_up_bars": 20,
            "missing_value_policy": "PROPAGATE_FALSE",
        },
        {
            "id": "slow_sma",
            "operation": "indicator.sma/v1",
            "inputs": ["bar.close"],
            "parameters": {"period": "slow_period"},
            "output_type": "DECIMAL",
            "warm_up_bars": 50,
            "missing_value_policy": "PROPAGATE_FALSE",
        },
    ],
    "entry_rules": [
        {
            "id": "enter_cross",
            "expression": {
                "op": "crosses_above",
                "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
                "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
            },
        }
    ],
    "exit_rules": [
        {
            "id": "exit_cross",
            "expression": {
                "op": "crosses_below",
                "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
                "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
            },
        }
    ],
    "sizing_intent": {"method": "FRACTION_OF_AVAILABLE_QUOTE", "fraction": "1"},
    "risk_assumptions": {"leverage": "1", "shorting_allowed": False},
    "warm_up_requirements": {"minimum_bars": 50},
    "comparison_requirements": {"maximum_level": "LEVEL_2"},
    "supported_approximation_policy": {"default": "REJECT"},
    "engine_extensions": [],
    "authoring_metadata": {
        "author": "local_user",
        "created_at_utc": "2026-08-10T00:00:00Z",
    },
}
_STRATEGY_SOURCE_BYTES: Final = b"schema_version: placeholder"
_STRATEGY_SOURCE_NAME: Final = "sma_cross_long.valid.yaml"

#: The dataset fixture identities and interval (the shape of
#: ``tests/unit/datasets/test_dataset_metadata_hashing.py::_models``).
DATASET_ID: Final = f"ds_{UUID_A}"
PARTITION_IDS: Final = (f"part_{UUID_A}", f"part_{UUID_B}")
_DATASET_START: Final = INSTANT - timedelta(days=2)
_DATASET_MIDDLE: Final = INSTANT - timedelta(days=1)
_DATASET_END: Final = INSTANT


def raw_connection(path: Path) -> sqlite3.Connection:
    """A stdlib connection with explicit transaction control.

    ``isolation_level=None`` disables the DBAPI's implicit ``BEGIN``, so a lock
    holder issues ``BEGIN IMMEDIATE`` itself and a raw statement autocommits.
    The caller closes it in ``finally:`` (plan 7.5).
    """
    return sqlite3.connect(path, isolation_level=None)


def file_sha256(path: Path) -> str:
    """The SHA-256 hex digest of the main database file, for C-20 and C-21."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def accept_any_revision(connection: Connection) -> Result[None]:
    """The accepting revision policy: ``Success(None)`` without reading anything."""
    del connection
    return Success[None](outcome="SUCCESS", value=None)


def ok[T](result: Success[T] | Failure) -> T:
    """Narrow a ``Result`` to its ``Success`` value, failing on a ``Failure``."""
    assert isinstance(result, Success), result
    return result.value


def code(result: object) -> str:
    """Narrow a ``Result`` to the error code of its single ``Failure`` diagnostic."""
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def open_test_database(
    tmp_path: Path, *, busy_timeout_ms: int = 100, clock: Clock
) -> SqliteDatabase:
    """The migrated test database at ``tmp_path / "registry.sqlite3"`` (plan 7.1).

    ``open_for_migration`` admits ``EMPTY``, ``BEHIND`` and ``CURRENT``;
    ``apply_migrations`` runs only when the report is not yet ``CURRENT``, so a
    current file reopens unchanged. The caller closes the database in
    ``finally:`` or through the ``sqlite_database`` fixture.
    """
    database = ok(
        open_for_migration(
            tmp_path / "registry.sqlite3", busy_timeout_ms=busy_timeout_ms, clock=clock
        )
    )
    try:
        with database.read_only() as connection:
            report = check_revision(connection)
        if report.state is not RevisionState.CURRENT:
            ok(apply_migrations(database))
    except BaseException:
        database.close()
        raise
    return database


# --------------------------------------------------------------------------
# Task 3 (plan 7.1): the causal-edge reader and the two test-only triggers
# --------------------------------------------------------------------------


def _execute_raw(database: SqliteDatabase, statement: str) -> list[tuple[Any, ...]]:
    connection = raw_connection(database.path)
    try:
        return list(connection.execute(statement).fetchall())
    finally:
        connection.close()


def causal_edges(database: SqliteDatabase) -> tuple[tuple[str, str], ...]:
    """Every ``(diagnostic_id, causal_diagnostic_id)`` row, ordered by both columns.

    Read through an independent stdlib connection, so no engine-side state can
    stand in for the durable relation (C-31, Task 7).
    """
    return tuple(
        (str(referrer), str(cause))
        for referrer, cause in _execute_raw(database, _CAUSAL_EDGES_SQL)
    )


def install_refusing_edge_trigger(database: SqliteDatabase) -> None:
    """C-31: refuse every insert into ``diagnostic_causes`` (fixed DDL text)."""
    _execute_raw(database, _REFUSING_EDGE_TRIGGER)


def install_refusing_partition_trigger(database: SqliteDatabase, ordinal: int) -> None:
    """C-29 (c): refuse the ``dataset_partitions`` insert at exactly ``ordinal``.

    The ``WHEN`` clause carries ``str(int(ordinal))`` -- an integer literal, no
    identity and no bound parameter, because SQLite admits no variable inside
    ``CREATE TRIGGER``; every data statement of the tests keeps bound parameters.
    """
    if isinstance(ordinal, bool) or not isinstance(ordinal, int):
        raise TypeError("ordinal must be a built-in integer")
    _execute_raw(
        database,
        _REFUSING_PARTITION_TRIGGER_HEAD
        + str(int(ordinal))
        + _REFUSING_PARTITION_TRIGGER_TAIL,
    )


# --------------------------------------------------------------------------
# Task 3 (plan 7.1): the two registry fixture builders
# --------------------------------------------------------------------------


def sample_strategy_version() -> StrategyVersion:
    """One valid ``StrategyVersion`` over the fixed spec at ``INSTANT`` (plan 7.1).

    ``content_hash`` is the versioning module's own ``strategy_version_hash`` and
    ``strategy_version_id`` its deterministic derivation, so the record's
    ``validate_identity_is_recomputed`` accepts it; a second call returns an
    equal record.
    """
    spec = StrategySpec.model_validate_json(
        canonical_json_bytes(_STRATEGY_SPEC_DOCUMENT)
    )
    content_hash = strategy_version_hash(spec)
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_identifier(content_hash),
        strategy_id=spec.strategy_id,
        content_hash=content_hash,
        strategy_spec=spec,
        extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=INSTANT,
        source_provenance=StrategySourceProvenance(
            source_name=_STRATEGY_SOURCE_NAME,
            source_bytes_sha256=sha256_bytes(_STRATEGY_SOURCE_BYTES),
            source_byte_length=len(_STRATEGY_SOURCE_BYTES),
            observed_at_utc=INSTANT,
        ),
    )


def _dataset_provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _dataset_partition(
    *,
    partition_id: str,
    ordinal: int,
    start: object,
    end: object,
    raw: str,
    normalized: str,
) -> DatasetPartition:
    return DatasetPartition.model_validate(
        {
            "schema_version": "1.0.0",
            "partition_id": partition_id,
            "dataset_id": DATASET_ID,
            "ordinal": ordinal,
            "relative_path": f"ohlcv/{ordinal}.parquet",
            "content_hash": str(ordinal + 3) * 64,
            "row_count": 10 + ordinal,
            "start_utc": start,
            "end_utc": end,
            "raw_checksum": raw,
            "normalized_checksum": normalized,
            "column_schema_version": "1.0.0",
            "raw_source_provenance": (_dataset_provenance(),),
            "quality_observations": (),
        }
    )


def sample_dataset_with_partitions() -> tuple[
    DatasetDescriptor, tuple[DatasetPartition, ...]
]:
    """One ``DatasetDescriptor`` and exactly two partitions at ordinals 0 and 1.

    Identity-consistent through ``validate_dataset_identity``: the descriptor's
    ``content_hash`` is ``dataset_metadata_hash`` over the descriptor's material
    fields and the ordered partitions. The second partition (ordinal 1) is the
    one C-29 (c)'s trigger refuses.
    """
    partitions = (
        _dataset_partition(
            partition_id=PARTITION_IDS[0],
            ordinal=0,
            start=_DATASET_START,
            end=_DATASET_MIDDLE,
            raw="1" * 64,
            normalized="2" * 64,
        ),
        _dataset_partition(
            partition_id=PARTITION_IDS[1],
            ordinal=1,
            start=_DATASET_MIDDLE,
            end=_DATASET_END,
            raw="2" * 64,
            normalized="1" * 64,
        ),
    )
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "dataset_id": DATASET_ID,
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        "data_type": DatasetDataType.OHLCV,
        "timeframe": "1m",
        "start_utc": _DATASET_START,
        "end_utc": _DATASET_END,
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": (_dataset_provenance(),),
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": DatasetValidationStatus.VALID,
        "partition_ids": PARTITION_IDS,
        "missing_intervals": (),
        "duplicate_intervals": (),
        "diagnostic_ids": (),
        "raw_checksums": tuple(item.raw_checksum for item in partitions),
        "normalized_checksums": tuple(item.normalized_checksum for item in partitions),
        "column_schema_version": "1.0.0",
        "known_limitations": (),
        "created_at_utc": INSTANT,
    }
    unhashed = DatasetDescriptor.model_validate(payload)
    payload["content_hash"] = dataset_metadata_hash(unhashed, partitions)
    descriptor = DatasetDescriptor.model_validate(payload)
    validate_dataset_identity(descriptor, partitions)
    return descriptor, partitions
