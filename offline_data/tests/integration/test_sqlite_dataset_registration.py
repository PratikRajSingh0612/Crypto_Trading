"""The temporary SQLite dataset-registration contract (registration plan section 3).

The committed goldens under ``tests/fixtures/candles/golden`` and
``tests/fixtures/binance/golden`` are the emitted metadata of the five fixture
families. This module is their consumer on the registration side: it parses
each pair strictly through the core models, recomputes the identity with the
core's ``dataset_metadata_hash``, registers the pair through the real
``SqliteDatasetRepository`` into a fresh temporary SQLite database created and
migrated by the core's own ``open_for_migration`` and ``apply_migrations``,
commits, closes, reopens through ``open_database`` and reads the records back
by content hash and by ordinal. Read-back is held to complete typed equality
and byte-identical canonical JSON, the ordinal and partition-id contract is
pinned, re-registration of the identical pair is idempotent, and two negative
controls show the refusals are structured: a descriptor whose content hash does
not match its material metadata is refused before any row exists, and a
different descriptor under an already registered hash is refused with the
original records unchanged.

Every case uses its own ``tmp_path / "registry.sqlite3"``: the five families
reuse one dataset and one partition identifier, so two families never share a
database. The core enters through the existing non-editable path dependency
only; no production module of this sub-project is added, no persistent or
application registry is opened, and no partition path is read.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from crypto_lab.datasets.hashing import (
    dataset_metadata_hash,
    validate_dataset_identity,
)
from crypto_lab.datasets.models import (
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import MonotonicInstant, format_utc
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.migration_runner import (
    apply_migrations,
    open_database,
    open_for_migration,
)
from crypto_lab.persistence.registries import SqliteDatasetRepository
from pydantic import TypeAdapter

from crypto_lab_offline_data.metadata import P2_B1_LIMITATION, P2_B3_LIMITATION

BUSY_TIMEOUT_MS = 100
DATABASE_FILE_NAME = "registry.sqlite3"
REGISTRY_FILE_NAMES = frozenset(
    {DATABASE_FILE_NAME, f"{DATABASE_FILE_NAME}-wal", f"{DATABASE_FILE_NAME}-shm"}
)
INVARIANT_VIOLATION = "CORE.INVARIANT_VIOLATION"
FIXED_INSTANT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
PARTITIONS_ADAPTER: TypeAdapter[tuple[DatasetPartition, ...]] = TypeAdapter(
    tuple[DatasetPartition, ...]
)
FOREIGN_HASH = hashlib.sha256(b"no committed golden carries this metadata").hexdigest()


@dataclass(frozen=True, slots=True)
class Family:
    """One committed golden family and the facts its read-back must preserve."""

    stem: str
    directory: str
    source_name: str
    source: str
    warnings: bool
    binance: bool

    @property
    def limitations(self) -> tuple[str, ...]:
        if self.binance:
            return (P2_B3_LIMITATION, P2_B1_LIMITATION)
        return (P2_B1_LIMITATION,)

    @property
    def status(self) -> DatasetValidationStatus:
        if self.warnings:
            return DatasetValidationStatus.VALID_WITH_WARNINGS
        return DatasetValidationStatus.VALID


FAMILIES = (
    Family(
        stem="btcusdt-1m-clean",
        directory="candles",
        source_name="ohlcv-csv",
        source="local-fixture",
        warnings=False,
        binance=False,
    ),
    Family(
        stem="btcusdt-1m-gaps-duplicates",
        directory="candles",
        source_name="ohlcv-csv",
        source="local-fixture",
        warnings=True,
        binance=False,
    ),
    Family(
        stem="SYNTHETIC-BTCUSDT-1m-2024-12-31-ms",
        directory="binance",
        source_name="binance-spot-kline-csv",
        source="synthetic-binance-fixture",
        warnings=False,
        binance=True,
    ),
    Family(
        stem="SYNTHETIC-BTCUSDT-1m-2025-01-01-us",
        directory="binance",
        source_name="binance-spot-kline-csv",
        source="synthetic-binance-fixture",
        warnings=False,
        binance=True,
    ),
    Family(
        stem="SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us",
        directory="binance",
        source_name="binance-spot-kline-csv",
        source="synthetic-binance-fixture",
        warnings=True,
        binance=True,
    ),
)
FAMILY_IDS = [family.stem for family in FAMILIES]


@dataclass(frozen=True, slots=True)
class Golden:
    """One family's three committed documents, strictly parsed and identity-checked."""

    descriptor_bytes: bytes
    partitions_bytes: bytes
    content_hash: str
    descriptor: DatasetDescriptor
    partitions: tuple[DatasetPartition, ...]
    fixture: Path


@dataclass(frozen=True, slots=True)
class ReadBack:
    """What a fresh repository returns after reopen, with the row counts seen there."""

    descriptor: DatasetDescriptor
    partitions: tuple[DatasetPartition, ...]
    dataset_rows: int
    partition_rows: int


@dataclass(frozen=True, slots=True)
class RegistrationClock:
    """A deterministic core ``Clock``: one fixed UTC instant, monotonic reading zero.

    The shared ``fixed_clock`` double of ``conftest.py`` satisfies only the
    sub-project's own clock protocol; the core ``Clock`` also requires the paired
    ``monotonic`` reading, so this module carries its own double.
    """

    instant: datetime = FIXED_INSTANT

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic(self) -> MonotonicInstant:
        return MonotonicInstant(0.0)


def _golden_hash(path: Path) -> str:
    """The sixty-four hex digits of the golden hash file, one line, LF-terminated."""
    data = path.read_bytes()
    assert data.endswith(b"\n")
    assert b"\r" not in data
    text = data[:-1].decode("ascii")
    assert len(text) == 64
    assert set(text) <= set("0123456789abcdef")
    return text


def _parse(
    descriptor_bytes: bytes, partitions_bytes: bytes
) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    """Strict JSON-mode parsing through the core models, the consumer's view."""
    descriptor = DatasetDescriptor.model_validate_json(descriptor_bytes, strict=True)
    partitions = PARTITIONS_ADAPTER.validate_json(partitions_bytes, strict=True)
    return descriptor, partitions


def _document(descriptor_bytes: bytes) -> dict[str, object]:
    """The descriptor's JSON object, for one in-memory key change before re-parsing."""
    document = json.loads(descriptor_bytes)
    assert isinstance(document, dict)
    return document


def _load_golden(sub_project_root: Path, family: Family) -> Golden:
    """Load, strictly parse and identity-check one family's committed documents."""
    fixtures = sub_project_root / "tests" / "fixtures" / family.directory
    golden = fixtures / "golden"
    descriptor_bytes = (golden / f"{family.stem}.descriptor.json").read_bytes()
    partitions_bytes = (golden / f"{family.stem}.partitions.json").read_bytes()
    content_hash = _golden_hash(golden / f"{family.stem}.content_hash.txt")
    descriptor, partitions = _parse(descriptor_bytes, partitions_bytes)
    recomputed = dataset_metadata_hash(descriptor, partitions)
    assert recomputed == descriptor.content_hash
    assert recomputed == content_hash
    validate_dataset_identity(descriptor, partitions)
    return Golden(
        descriptor_bytes=descriptor_bytes,
        partitions_bytes=partitions_bytes,
        content_hash=content_hash,
        descriptor=descriptor,
        partitions=partitions,
        fixture=fixtures / f"{family.stem}.valid.csv",
    )


def _create_database(path: Path, clock: Clock) -> SqliteDatabase:
    """Create and migrate the temporary database; it is closed again on a refusal."""
    opened = open_for_migration(path, busy_timeout_ms=BUSY_TIMEOUT_MS, clock=clock)
    assert isinstance(opened, Success), opened
    database = opened.value
    try:
        applied = apply_migrations(database)
        assert isinstance(applied, Success), applied
    except BaseException:
        database.close()
        raise
    return database


def _reopen_database(path: Path, clock: Clock) -> SqliteDatabase:
    """Reopen an existing, migrated database for normal use."""
    opened = open_database(path, busy_timeout_ms=BUSY_TIMEOUT_MS, clock=clock)
    assert isinstance(opened, Success), opened
    return opened.value


def _register_golden(path: Path, clock: Clock, golden: Golden) -> None:
    """Step 1: create, migrate, register with ``Success[None]``, commit and close."""
    database = _create_database(path, clock)
    try:
        with database.connection() as connection:
            repository = SqliteDatasetRepository(connection, clock=clock)
            registered = repository.register(golden.descriptor, golden.partitions)
            assert isinstance(registered, Success), registered
            assert registered.value is None
            connection.commit()
    finally:
        database.close()


def _read_back(database: SqliteDatabase, clock: Clock, golden: Golden) -> ReadBack:
    """A fresh repository's ``get_by_hash`` and ``list_partitions``, both successes.

    The committed row counts are read with literal SQL on that repository's own
    connection, inside the same checkout.
    """
    with database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=clock)
        read = repository.get_by_hash(golden.content_hash)
        assert isinstance(read, Success), read
        listed = repository.list_partitions(golden.descriptor.dataset_id)
        assert isinstance(listed, Success), listed
        datasets = connection.exec_driver_sql(
            "SELECT count(*) FROM datasets"
        ).scalar_one()
        partitions = connection.exec_driver_sql(
            "SELECT count(*) FROM dataset_partitions"
        ).scalar_one()
    assert isinstance(datasets, int)
    assert isinstance(partitions, int)
    return ReadBack(read.value, listed.value, datasets, partitions)


def _reopen_and_read(path: Path, clock: Clock, golden: Golden) -> ReadBack:
    """Step 2: reopen through ``open_database`` and read back on a fresh repository."""
    database = _reopen_database(path, clock)
    try:
        return _read_back(database, clock, golden)
    finally:
        database.close()


def _reregister_identical(path: Path, clock: Clock, golden: Golden) -> tuple[int, int]:
    """Step 6: register the identical pair again on a write connection and commit.

    The row counts are read on the repository's own connection after the commit.
    """
    database = _reopen_database(path, clock)
    try:
        with database.connection() as connection:
            repository = SqliteDatasetRepository(connection, clock=clock)
            repeated = repository.register(golden.descriptor, golden.partitions)
            assert isinstance(repeated, Success), repeated
            assert repeated.value is None
            connection.commit()
            datasets = connection.exec_driver_sql(
                "SELECT count(*) FROM datasets"
            ).scalar_one()
            partitions = connection.exec_driver_sql(
                "SELECT count(*) FROM dataset_partitions"
            ).scalar_one()
    finally:
        database.close()
    assert isinstance(datasets, int)
    assert isinstance(partitions, int)
    return datasets, partitions


def _assert_invariant_refusal(result: object, *, identity: str) -> None:
    """Exactly one ``CORE.INVARIANT_VIOLATION`` diagnostic with the register details."""
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert dict(diagnostic.details) == {
        "table": "datasets",
        "operation": "register",
        "identity": identity,
    }


def _assert_only_registry_files(directory: Path) -> None:
    """The database and its WAL/SHM siblings are the only entries, all under tmp."""
    names = {entry.name for entry in directory.iterdir()}
    assert DATABASE_FILE_NAME in names
    assert names <= REGISTRY_FILE_NAMES


def _assert_unchanged(read: ReadBack, golden: Golden) -> None:
    """Typed and byte-identical equality with the goldens, one row in each table."""
    assert read.descriptor == golden.descriptor
    assert read.partitions == golden.partitions
    assert canonical_json_bytes(read.descriptor) == golden.descriptor_bytes
    assert canonical_json_bytes(list(read.partitions)) == golden.partitions_bytes
    assert (read.dataset_rows, read.partition_rows) == (1, 1)


# --- the test-local doubles and the reason every case owns its database --------


def test_the_local_clock_is_a_core_clock_and_the_shared_double_is_not(
    fixed_clock: object,
) -> None:
    clock = RegistrationClock()

    assert isinstance(clock, Clock)
    assert clock.now_utc() == FIXED_INSTANT
    assert clock.now_utc().tzinfo is UTC
    assert clock.monotonic() == MonotonicInstant(0.0)
    assert not isinstance(fixed_clock, Clock)


def test_the_five_families_share_one_dataset_and_one_partition_identifier(
    sub_project_root: Path,
) -> None:
    """Five distinct identities over one fixed dataset and partition identifier."""
    goldens = [_load_golden(sub_project_root, family) for family in FAMILIES]

    assert len({golden.content_hash for golden in goldens}) == len(FAMILIES)
    assert len({golden.descriptor.dataset_id for golden in goldens}) == 1
    assert len({golden.descriptor.partition_ids for golden in goldens}) == 1
    assert FOREIGN_HASH not in {golden.content_hash for golden in goldens}


# --- the positive matrix, one fresh temporary database per family and case ------


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_the_golden_pair_registers_and_reads_back_identically_after_reopen(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Steps 1 to 3: register, commit, reopen, typed and byte-identical read-back."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME

    _register_golden(path, clock, golden)
    read = _reopen_and_read(path, clock, golden)

    _assert_unchanged(read, golden)
    recomputed = dataset_metadata_hash(read.descriptor, read.partitions)
    assert recomputed == golden.content_hash
    assert recomputed == read.descriptor.content_hash
    validate_dataset_identity(read.descriptor, read.partitions)
    _assert_only_registry_files(tmp_path)


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_the_read_back_preserves_every_identity_and_material_field(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Step 3, field by field: the values the registry must hand back unchanged."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME
    expected = golden.descriptor
    (expected_partition,) = golden.partitions

    _register_golden(path, clock, golden)
    read = _reopen_and_read(path, clock, golden)
    descriptor = read.descriptor
    (partition,) = read.partitions

    assert descriptor.dataset_id == expected.dataset_id
    assert partition.dataset_id == descriptor.dataset_id
    assert partition.partition_id == expected_partition.partition_id
    assert descriptor.partition_ids == expected.partition_ids
    assert descriptor.partition_ids == (partition.partition_id,)
    assert partition.ordinal == expected_partition.ordinal
    assert partition.relative_path == expected_partition.relative_path
    assert partition.row_count == expected_partition.row_count
    assert (descriptor.start_utc, descriptor.end_utc) == (
        expected.start_utc,
        expected.end_utc,
    )
    assert (partition.start_utc, partition.end_utc) == (
        expected_partition.start_utc,
        expected_partition.end_utc,
    )
    assert partition.content_hash == expected_partition.content_hash
    assert partition.raw_checksum == expected_partition.raw_checksum
    assert partition.normalized_checksum == expected_partition.normalized_checksum
    assert descriptor.raw_checksums == expected.raw_checksums
    assert descriptor.normalized_checksums == expected.normalized_checksums
    assert descriptor.schema_version == expected.schema_version == "1.0.0"
    assert partition.schema_version == expected_partition.schema_version == "1.0.0"
    assert descriptor.column_schema_version == expected.column_schema_version
    assert partition.column_schema_version == descriptor.column_schema_version
    assert descriptor.column_schema_version == "0.1.0"
    assert (
        descriptor.normalization_implementation == expected.normalization_implementation
    )
    assert descriptor.normalization_version == expected.normalization_version
    assert descriptor.source == expected.source == family.source
    assert descriptor.created_at_utc == expected.created_at_utc
    assert descriptor.imported_at_utc == expected.imported_at_utc
    assert descriptor.validation_status is expected.validation_status
    assert descriptor.validation_status is family.status
    assert descriptor.missing_intervals == expected.missing_intervals
    assert descriptor.duplicate_intervals == expected.duplicate_intervals
    assert descriptor.diagnostic_ids == expected.diagnostic_ids == ()
    assert descriptor.known_limitations == expected.known_limitations
    assert descriptor.known_limitations == family.limitations
    assert partition.quality_observations == expected_partition.quality_observations
    assert set(family.limitations) <= set(partition.quality_observations)


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_the_read_back_provenance_and_checksums_name_the_committed_fixture(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Step 4: provenance, checksum linkage, limitation texts and warning facts."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME
    fixture_hash = hashlib.sha256(golden.fixture.read_bytes()).hexdigest()

    _register_golden(path, clock, golden)
    read = _reopen_and_read(path, clock, golden)
    descriptor = read.descriptor
    (partition,) = read.partitions
    (provenance,) = descriptor.raw_source_provenance

    assert provenance.source_name == family.source_name
    assert provenance.source_version == "1.0.0"
    assert provenance.source_record == golden.fixture.name
    assert provenance.source_record == f"{family.stem}.valid.csv"
    assert provenance.source_hash == fixture_hash
    assert partition.raw_source_provenance == descriptor.raw_source_provenance
    assert partition.raw_checksum == fixture_hash
    assert descriptor.raw_checksums == tuple(
        item.raw_checksum for item in read.partitions
    )
    assert descriptor.normalized_checksums == tuple(
        item.normalized_checksum for item in read.partitions
    )
    assert partition.normalized_checksum == partition.content_hash
    assert P2_B1_LIMITATION in descriptor.known_limitations
    assert P2_B1_LIMITATION in partition.quality_observations
    assert (P2_B3_LIMITATION in descriptor.known_limitations) is family.binance
    assert (P2_B3_LIMITATION in partition.quality_observations) is family.binance
    assert descriptor.validation_status is family.status
    if family.warnings:
        assert descriptor.missing_intervals != ()
        assert descriptor.duplicate_intervals != ()
    else:
        assert descriptor.missing_intervals == ()
        assert descriptor.duplicate_intervals == ()


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_the_read_back_ordinals_and_partition_ids_follow_the_contract(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Step 5: ordinals are ``range(len)`` and the IDs are the descriptor's, in order.

    Every committed golden holds one partition at ordinal 0, so this proves that
    contract instance, not multi-partition sorting coverage.
    """
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME

    _register_golden(path, clock, golden)
    read = _reopen_and_read(path, clock, golden)
    ordinals = tuple(item.ordinal for item in read.partitions)
    partition_ids = tuple(item.partition_id for item in read.partitions)

    assert ordinals == tuple(range(len(read.partitions)))
    assert partition_ids == read.descriptor.partition_ids
    assert partition_ids == golden.descriptor.partition_ids
    assert len(read.partitions) == 1
    assert ordinals == (0,)
    assert all(
        item.dataset_id == read.descriptor.dataset_id for item in read.partitions
    )


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_re_registering_the_identical_pair_is_idempotent(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Step 6: the identical pair registers again as ``Success[None]``; one row each."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME

    _register_golden(path, clock, golden)
    counts = _reregister_identical(path, clock, golden)
    read = _reopen_and_read(path, clock, golden)

    assert counts == (1, 1)
    _assert_unchanged(read, golden)
    _assert_only_registry_files(tmp_path)


# --- the negative controls, each in its own fresh temporary database -------------


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_a_descriptor_whose_hash_is_not_its_metadata_is_refused_before_any_row(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """A foreign ``content_hash`` is the invariant refusal; nothing is staged."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME
    document = _document(golden.descriptor_bytes)
    assert document["content_hash"] == golden.content_hash
    assert FOREIGN_HASH != golden.content_hash
    document["content_hash"] = FOREIGN_HASH
    tampered, partitions = _parse(
        json.dumps(document).encode("utf-8"), golden.partitions_bytes
    )
    assert tampered.content_hash == FOREIGN_HASH
    assert partitions == golden.partitions
    assert dataset_metadata_hash(tampered, partitions) == golden.content_hash

    database = _create_database(path, clock)
    try:
        with database.connection() as connection:
            repository = SqliteDatasetRepository(connection, clock=clock)
            refused = repository.register(tampered, partitions)
            _assert_invariant_refusal(refused, identity=FOREIGN_HASH)
            staged_datasets = connection.exec_driver_sql(
                "SELECT count(*) FROM datasets"
            ).scalar_one()
            staged_partitions = connection.exec_driver_sql(
                "SELECT count(*) FROM dataset_partitions"
            ).scalar_one()
            assert (staged_datasets, staged_partitions) == (0, 0)
            connection.commit()
    finally:
        database.close()

    database = _reopen_database(path, clock)
    try:
        with database.connection() as connection:
            repository = SqliteDatasetRepository(connection, clock=clock)
            committed_datasets = connection.exec_driver_sql(
                "SELECT count(*) FROM datasets"
            ).scalar_one()
            committed_partitions = connection.exec_driver_sql(
                "SELECT count(*) FROM dataset_partitions"
            ).scalar_one()
            assert (committed_datasets, committed_partitions) == (0, 0)
            absent = repository.get_by_hash(FOREIGN_HASH)
            assert isinstance(absent, Failure), absent
            (diagnostic,) = absent.diagnostics
            assert diagnostic.error_code == INVARIANT_VIOLATION
            registered = repository.register(golden.descriptor, golden.partitions)
            assert isinstance(registered, Success), registered
            assert registered.value is None
            connection.commit()
    finally:
        database.close()

    read = _reopen_and_read(path, clock, golden)
    _assert_unchanged(read, golden)
    _assert_only_registry_files(tmp_path)


@pytest.mark.parametrize("family", FAMILIES, ids=FAMILY_IDS)
def test_a_different_descriptor_under_a_registered_hash_is_refused(
    family: Family, tmp_path: Path, sub_project_root: Path
) -> None:
    """Creation time is excluded from the hash, so the shifted descriptor keeps the
    registered identity and differs in content: the registry refuses it and the
    original records and counts are unchanged after commit and reopen."""
    golden = _load_golden(sub_project_root, family)
    clock = RegistrationClock()
    path = tmp_path / DATABASE_FILE_NAME
    _register_golden(path, clock, golden)
    document = _document(golden.descriptor_bytes)
    created_at = document["created_at_utc"]
    assert isinstance(created_at, str)
    assert document["imported_at_utc"] == created_at
    one_second_later = golden.descriptor.created_at_utc + timedelta(seconds=1)
    document["created_at_utc"] = format_utc(one_second_later)
    assert document["created_at_utc"] != created_at
    assert document["imported_at_utc"] == created_at
    shifted, partitions = _parse(
        json.dumps(document).encode("utf-8"), golden.partitions_bytes
    )
    assert shifted.created_at_utc == one_second_later
    assert shifted.imported_at_utc == golden.descriptor.imported_at_utc
    assert shifted != golden.descriptor
    assert shifted.content_hash == golden.content_hash
    assert dataset_metadata_hash(shifted, partitions) == golden.content_hash
    validate_dataset_identity(shifted, partitions)

    database = _reopen_database(path, clock)
    try:
        with database.connection() as connection:
            repository = SqliteDatasetRepository(connection, clock=clock)
            refused = repository.register(shifted, partitions)
            _assert_invariant_refusal(refused, identity=golden.content_hash)
            connection.commit()
    finally:
        database.close()

    read = _reopen_and_read(path, clock, golden)
    _assert_unchanged(read, golden)
    assert read.descriptor.created_at_utc == golden.descriptor.created_at_utc
    assert read.descriptor.created_at_utc != one_second_later
    _assert_only_registry_files(tmp_path)
