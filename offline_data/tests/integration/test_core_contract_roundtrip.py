"""The consumer round trip of plan section 9.1 (Task 3).

The command writes ``descriptor.json``, ``partitions.json`` and the interim
container into a fresh directory; this module then acts as an independent
consumer: it re-parses the two JSON files through the core models in strict
JSON mode (``model_validate_json(strict=True)`` and a ``TypeAdapter`` over the
partition tuple), recomputes the identity with the core's own
``dataset_metadata_hash``, checks it with ``validate_dataset_identity``, ties
the partition's ``content_hash`` and ``row_count`` to the container's bytes and
the ``raw_checksum`` to the fixture's bytes, and proves the canonical bytes
round-trip exactly. Negative controls show the consumer check is load-bearing:
a material byte changed in the emitted JSON is caught by the identity check and
a non-canonical value by strict parsing. The six golden files under
``tests/fixtures/candles/golden`` are compared byte for byte, and each golden
hash is recomputed from the golden JSON through the core rather than trusted.
"""

from __future__ import annotations

import hashlib
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
from pydantic import TypeAdapter, ValidationError

from crypto_lab_offline_data.cli import (
    DESCRIPTOR_FILE_NAME,
    PARTITIONS_FILE_NAME,
    normalize_command,
)
from crypto_lab_offline_data.metadata import CONTAINER_FILE_NAME, P2_B1_LIMITATION
from crypto_lab_offline_data.providers import Clock, IdProvider

INSTRUMENT_ID = "BINANCE:BTC/USDT:SPOT"
FIXTURE_ROW_COUNT = 60
EXPECTED_STATUS = {
    "btcusdt-1m-clean": DatasetValidationStatus.VALID,
    "btcusdt-1m-gaps-duplicates": DatasetValidationStatus.VALID_WITH_WARNINGS,
}
FIXTURE_STEMS = tuple(EXPECTED_STATUS)
PARTITIONS_ADAPTER: TypeAdapter[tuple[DatasetPartition, ...]] = TypeAdapter(
    tuple[DatasetPartition, ...]
)


def _fixture(candles_root: Path, stem: str) -> Path:
    return candles_root / f"{stem}.valid.csv"


def _run(fixture: Path, output: Path, ids: IdProvider, clock: Clock) -> int:
    argv = [
        "normalize",
        "--input",
        str(fixture),
        "--output",
        str(output),
        "--instrument",
        INSTRUMENT_ID,
        "--timeframe",
        "1m",
    ]
    return normalize_command(argv, ids=ids, clock=clock)


def _emit(fixture: Path, output: Path, ids: IdProvider, clock: Clock) -> Path:
    assert _run(fixture, output, ids, clock) == 0
    assert sorted(entry.name for entry in output.iterdir()) == sorted(
        (CONTAINER_FILE_NAME, DESCRIPTOR_FILE_NAME, PARTITIONS_FILE_NAME)
    )
    return output


def _reparse(
    descriptor_bytes: bytes, partitions_bytes: bytes
) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    """Strict JSON-mode parsing through the core models, the consumer's view."""
    descriptor = DatasetDescriptor.model_validate_json(descriptor_bytes, strict=True)
    partitions = PARTITIONS_ADAPTER.validate_json(partitions_bytes, strict=True)
    return descriptor, partitions


def _reparse_directory(
    output: Path,
) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    return _reparse(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(),
        (output / PARTITIONS_FILE_NAME).read_bytes(),
    )


@pytest.mark.parametrize("stem", FIXTURE_STEMS)
def test_the_emitted_json_reparses_strictly_and_the_core_recomputes_the_hash(
    stem: str,
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fixture = _fixture(candles_root, stem)
    output = _emit(fixture, tmp_path / "output", fixed_ids, fixed_clock)
    container_bytes = (output / CONTAINER_FILE_NAME).read_bytes()

    descriptor, partitions = _reparse_directory(output)

    assert descriptor.validation_status is EXPECTED_STATUS[stem]
    assert len(partitions) == 1
    (partition,) = partitions
    validate_dataset_identity(descriptor, partitions)
    assert dataset_metadata_hash(descriptor, partitions) == descriptor.content_hash
    assert partition.content_hash == hashlib.sha256(container_bytes).hexdigest()
    assert partition.normalized_checksum == partition.content_hash
    assert partition.row_count == container_bytes.count(b"\n") == FIXTURE_ROW_COUNT
    assert partition.raw_checksum == hashlib.sha256(fixture.read_bytes()).hexdigest()
    assert descriptor.raw_checksums == (partition.raw_checksum,)
    assert descriptor.normalized_checksums == (partition.normalized_checksum,)
    assert descriptor.partition_ids == (partition.partition_id,)
    assert partition.dataset_id == descriptor.dataset_id
    assert descriptor.raw_source_provenance[0].source_record == fixture.name
    assert descriptor.known_limitations == (P2_B1_LIMITATION,)
    assert P2_B1_LIMITATION in partition.quality_observations
    assert partition.relative_path == (
        f"datasets/{descriptor.dataset_id}/{CONTAINER_FILE_NAME}"
    )


@pytest.mark.parametrize("stem", FIXTURE_STEMS)
def test_the_emitted_files_are_exactly_the_canonical_bytes_of_the_models(
    stem: str,
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = _emit(
        _fixture(candles_root, stem), tmp_path / "output", fixed_ids, fixed_clock
    )
    descriptor_bytes = (output / DESCRIPTOR_FILE_NAME).read_bytes()
    partitions_bytes = (output / PARTITIONS_FILE_NAME).read_bytes()

    descriptor, partitions = _reparse(descriptor_bytes, partitions_bytes)

    assert canonical_json_bytes(descriptor) == descriptor_bytes
    assert canonical_json_bytes(list(partitions)) == partitions_bytes
    assert descriptor_bytes.startswith(b"{")
    assert descriptor_bytes.endswith(b"}")
    assert partitions_bytes.startswith(b"[{")
    assert partitions_bytes.endswith(b"}]")
    assert b"\n" not in descriptor_bytes
    assert b"\n" not in partitions_bytes
    assert b"\xef\xbb\xbf" not in descriptor_bytes[:3]
    assert b" " not in descriptor_bytes.replace(P2_B1_LIMITATION.encode(), b"")


def test_two_runs_into_fresh_directories_emit_identical_bytes(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    first = _emit(clean_fixture, tmp_path / "first", fixed_ids, fixed_clock)
    second = _emit(clean_fixture, tmp_path / "second", fixed_ids, fixed_clock)

    for name in (CONTAINER_FILE_NAME, DESCRIPTOR_FILE_NAME, PARTITIONS_FILE_NAME):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    descriptor, partitions = _reparse_directory(first)
    validate_dataset_identity(descriptor, partitions)


def test_a_changed_material_byte_is_caught_by_the_identity_check(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The consumer check is load-bearing: the hash is recomputed, not trusted."""
    output = _emit(clean_fixture, tmp_path / "output", fixed_ids, fixed_clock)
    partitions_bytes = (output / PARTITIONS_FILE_NAME).read_bytes()
    assert partitions_bytes.count(b'"row_count":60') == 1
    tampered = partitions_bytes.replace(b'"row_count":60', b'"row_count":61')

    descriptor, partitions = _reparse(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(), tampered
    )

    assert partitions[0].row_count == 61
    assert dataset_metadata_hash(descriptor, partitions) != descriptor.content_hash
    with pytest.raises(ValueError, match="content_hash"):
        validate_dataset_identity(descriptor, partitions)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (b'"validation_status":"VALID"', b'"validation_status":"valid"'),
        (b'"normalized_to_utc":true', b'"normalized_to_utc":false'),
        (b'"normalized_to_utc":true', b'"normalized_to_utc":"true"'),
        (b'"data_type":"OHLCV"', b'"data_type":"OHLCV","extra":1'),
        (b'"created_at_utc":"2026-01-02T03:04:05Z"', b'"created_at_utc":"2026-01-02"'),
    ],
)
def test_strict_json_mode_refuses_a_non_canonical_descriptor(
    original: bytes,
    replacement: bytes,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = _emit(clean_fixture, tmp_path / "output", fixed_ids, fixed_clock)
    descriptor_bytes = (output / DESCRIPTOR_FILE_NAME).read_bytes()
    assert descriptor_bytes.count(original) == 1
    tampered = descriptor_bytes.replace(original, replacement)

    with pytest.raises(ValidationError):
        DatasetDescriptor.model_validate_json(tampered, strict=True)


# --- the committed goldens (captured once from the first GREEN run) ----------


def _golden(candles_root: Path, stem: str, suffix: str) -> Path:
    return candles_root / "golden" / f"{stem}.{suffix}"


def _golden_hash(candles_root: Path, stem: str) -> str:
    """The sixty-four hex digits of the golden hash file, one line, LF-terminated."""
    data = _golden(candles_root, stem, "content_hash.txt").read_bytes()
    assert data.endswith(b"\n")
    assert b"\r" not in data
    text = data[:-1].decode("ascii")
    assert len(text) == 64
    assert set(text) <= set("0123456789abcdef")
    return text


def test_the_six_golden_files_exist_and_nothing_else_is_committed_beside_them(
    candles_root: Path,
) -> None:
    golden = candles_root / "golden"
    expected = sorted(
        f"{stem}.{suffix}"
        for stem in FIXTURE_STEMS
        for suffix in ("descriptor.json", "partitions.json", "content_hash.txt")
    )

    assert sorted(entry.name for entry in golden.iterdir()) == expected
    assert len(expected) == 6


@pytest.mark.parametrize("stem", FIXTURE_STEMS)
def test_the_command_output_equals_the_committed_goldens_byte_for_byte(
    stem: str,
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = _emit(
        _fixture(candles_root, stem), tmp_path / "output", fixed_ids, fixed_clock
    )
    descriptor_golden = _golden(candles_root, stem, "descriptor.json").read_bytes()
    partitions_golden = _golden(candles_root, stem, "partitions.json").read_bytes()

    descriptor_bytes = (output / DESCRIPTOR_FILE_NAME).read_bytes()
    partitions_bytes = (output / PARTITIONS_FILE_NAME).read_bytes()

    assert descriptor_bytes == descriptor_golden
    assert partitions_bytes == partitions_golden
    descriptor, _ = _reparse(descriptor_bytes, partitions_bytes)
    assert descriptor.content_hash == _golden_hash(candles_root, stem)


@pytest.mark.parametrize("stem", FIXTURE_STEMS)
def test_the_golden_hash_is_recomputed_by_the_core_from_the_golden_json(
    stem: str,
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The consumer trusts the core, not the golden hash: parse, recompute, compare."""
    descriptor_golden = _golden(candles_root, stem, "descriptor.json").read_bytes()
    partitions_golden = _golden(candles_root, stem, "partitions.json").read_bytes()
    golden_hash = _golden_hash(candles_root, stem)
    fixture = _fixture(candles_root, stem)

    descriptor, partitions = _reparse(descriptor_golden, partitions_golden)

    recomputed = dataset_metadata_hash(descriptor, partitions)
    assert recomputed == golden_hash == descriptor.content_hash
    validate_dataset_identity(descriptor, partitions)
    assert descriptor.validation_status is EXPECTED_STATUS[stem]
    assert canonical_json_bytes(descriptor) == descriptor_golden
    assert canonical_json_bytes(list(partitions)) == partitions_golden
    output = _emit(fixture, tmp_path / "output", fixed_ids, fixed_clock)
    container_bytes = (output / CONTAINER_FILE_NAME).read_bytes()
    assert partitions[0].content_hash == hashlib.sha256(container_bytes).hexdigest()
    assert (
        partitions[0].raw_checksum == hashlib.sha256(fixture.read_bytes()).hexdigest()
    )


def test_the_golden_hashes_differ_between_fixtures(candles_root: Path) -> None:
    hashes = {_golden_hash(candles_root, stem) for stem in FIXTURE_STEMS}

    assert len(hashes) == 2
