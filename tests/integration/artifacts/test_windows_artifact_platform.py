"""Stage 9 Task 4, plan 7.5 (specification 28.5; R15.5-03, R19.3-10, R22.5-03,
T28.3-02, T28.5-01): the Windows platform cases of the artifact store and the
confinement, on the real filesystem under ``tmp_path`` -- junction, symbolic-link
and hard-link rejection, mutation during hashing, a candidate held open by
another handle, the long-path rejection that always runs beside the success that
is conditional on detected support (whose fixture geometry -- legal components,
a planned path over 259 and within 1024 characters -- is checked on every host),
and roots with spaces and Unicode components.

The symbolic-link case needs a privilege this principal may lack; when it does,
the case is a second junction planted at the leaf's parent -- never a skip and
never the Stage 7 skip reason. The module is self-contained (``tests/integration``
is collected before ``tests/unit``), so its candidate builders are local.
"""

from __future__ import annotations

import _winapi
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.hashing import ContentHasher, StreamingContentHasher
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    finalized_relative_path_for,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner, artifact_owner_hash
from crypto_lab.artifacts.paths import ConfinedPath, confine_candidate_path
from crypto_lab.artifacts.store import (
    PROCESS_PATH_PREFLIGHT_REJECTED,
    ArtifactStore,
    MoveOutcome,
)
from crypto_lab.artifacts.validation import (
    DEFAULT_CEILINGS,
    CandidateValidation,
    ValidatedCandidate,
    validate_candidate,
)
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import (
    candidate_artifact_id_for,
    core_candidate_artifact_id_for,
    sha256_bytes,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.process_supervision.models import (
    FILE_CEILING_WITHOUT_LONG_PATHS,
    LONG_PATH_CEILING,
)
from crypto_lab.process_supervision.roots import probe_long_path_support
from doubles.experiments import (
    ATTEMPT_TOKEN,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
)

_NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
_OWNER_HASH = "b" * 64
_RELATIVE = f"INVOCATION/{INVOCATION_ID}/stderr.txt"
_NATIVE_PATH = "results/native.bin"
_RUN_OWNER = RunArtifactOwner(
    owner_kind="RUN",
    experiment_id=EXPERIMENT_ID,
    run_id=RUN_ID,
    invocation_id=INVOCATION_ID,
)
_TOKEN = AttemptTokenMaterial(run_id=RUN_ID, attempt_token=ATTEMPT_TOKEN)
#: NTFS and the Win32 namespace bound one path component at 255 characters; the
#: long-path root is built from components under that bound, never from one
#: over-long name.
_MAX_COMPONENT_CHARACTERS = 255
_LONG_COMPONENT = "longroot" * 31  # 248 characters: a legal component
_ORIGINAL_LONG_COMPONENT = "longroot" * 32  # 256 characters: the refused geometry
_LONG_DATA = b"long path bytes"


def _long_artifacts_root(tmp_path: Path) -> Path:
    """The artifacts root of the long-path case: two legal components, so the
    root itself exceeds the 259-character ceiling while no component exceeds 255
    and the planned finalized path below it stays within 1024."""
    return tmp_path / _LONG_COMPONENT / _LONG_COMPONENT


def _planned_finalized_path(artifacts_root: Path, data: bytes) -> Path:
    """The finalized path ``atomic_move`` would target under ``artifacts_root``,
    computed lexically so the geometry is checkable before any store exists."""
    return artifacts_root.joinpath(
        *finalized_relative_path_for(sha256_bytes(data)).split("/")
    )


def _long_path_geometry_refusal(planned: Path) -> str | None:
    """Why a planned long-path fixture is illegal, or ``None`` when it is legal:
    every component is at most 255 characters and the whole path lies over the
    file ceiling without long-path support and within the ceiling with it."""
    if any(len(part) > _MAX_COMPONENT_CHARACTERS for part in planned.parts):
        return "component_too_long"
    length = len(str(planned))
    if length <= FILE_CEILING_WITHOUT_LONG_PATHS:
        return "path_not_long"
    if length > LONG_PATH_CEILING:
        return "path_over_ceiling"
    return None


def _failure(result: object) -> Failure:
    assert isinstance(result, Failure)
    return result


def _codes(result: object) -> tuple[str, ...]:
    return tuple(diagnostic.error_code for diagnostic in _failure(result).diagnostics)


def _hold_open_without_sharing(path: Path) -> int:
    """Open ``path`` with share mode 0, so any other open is a sharing violation
    (the Stage 7 share-lock fixture)."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _open_store(staging: Path, artifacts: Path, quarantine: Path) -> ArtifactStore:
    staging.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    quarantine.parent.mkdir(parents=True, exist_ok=True)
    opened = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert isinstance(opened, Success), opened
    store = opened.value
    assert isinstance(store, ArtifactStore)
    return store


def _staged(
    store: ArtifactStore, data: bytes, relative: str = _RELATIVE
) -> ConfinedPath:
    written = store.write_staged(_OWNER_HASH, relative, data, now_utc=_NOW)
    assert isinstance(written, Success), written
    value = written.value
    assert isinstance(value, ConfinedPath)
    return value


def _adapter_candidate(data: bytes) -> CandidateArtifact:
    return CandidateArtifact(
        schema_version="1.0.0",
        candidate_artifact_id=candidate_artifact_id_for(
            RUN_ID, INVOCATION_ID, _NATIVE_PATH
        ),
        owner=_RUN_OWNER,
        finalization_purpose=ArtifactFinalizationPurpose.RESULT,
        source_role=ArtifactSourceRole.ENGINE_NATIVE_RESULT,
        producer_kind=CandidateArtifactProducerKind.ADAPTER,
        artifact_kind="engine.native",
        staging_relative_path=_NATIVE_PATH,
        state=CandidateArtifactState.VALIDATING,
        adapter_declared_size=len(data),
        adapter_declared_hash=hashlib.sha256(data).hexdigest(),
        adapter_declared_media_type="application/octet-stream",
        validation_observations=(),
        created_at_utc=INSTANT,
        updated_at_utc=INSTANT,
        revision=2,
    )


def _core_candidate() -> CandidateArtifact:
    return CandidateArtifact(
        schema_version="1.0.0",
        candidate_artifact_id=core_candidate_artifact_id_for(
            artifact_owner_hash(_RUN_OWNER), "INVOCATION", INVOCATION_ID, "stderr.txt"
        ),
        owner=_RUN_OWNER,
        finalization_purpose=ArtifactFinalizationPurpose.EVIDENCE,
        source_role=ArtifactSourceRole.CORE_EVIDENCE,
        producer_kind=CandidateArtifactProducerKind.CORE,
        artifact_kind="stderr.capture",
        staging_relative_path=_RELATIVE,
        state=CandidateArtifactState.VALIDATING,
        validation_observations=(),
        created_at_utc=INSTANT,
        updated_at_utc=INSTANT,
        revision=2,
    )


def _stage(root: Path, candidate: CandidateArtifact, data: bytes) -> ConfinedPath:
    leaf = root.joinpath(*candidate.staging_relative_path.split("/"))
    leaf.parent.mkdir(parents=True, exist_ok=True)
    leaf.write_bytes(data)
    confined = confine_candidate_path(
        root, candidate.staging_relative_path, now_utc=_NOW
    )
    assert isinstance(confined, Success), confined
    return confined.value


def _validate(
    candidate: CandidateArtifact,
    confined: ConfinedPath,
    *,
    hasher: ContentHasher | None = None,
) -> CandidateValidation:
    adapter = candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    return validate_candidate(
        candidate,
        confined,
        hasher=StreamingContentHasher() if hasher is None else hasher,
        token=_TOKEN if adapter else MISSING,
        ceilings=DEFAULT_CEILINGS,
        now_utc=_NOW,
        media_type=MISSING if adapter else "text/plain",
    )


def _succeeded(validation: CandidateValidation) -> ValidatedCandidate:
    assert isinstance(validation.result, Success), validation.result
    value = validation.result.value
    assert isinstance(value, ValidatedCandidate)
    return value


def test_junction_symlink_hardlink_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "results").mkdir(parents=True)
    leaf = root / "results" / "native.bin"
    leaf.write_bytes(b"native")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "inner").mkdir(parents=True)
    (elsewhere / "inner" / "native.bin").write_bytes(b"outside")

    # A junction as an ancestor of the leaf.
    _winapi.CreateJunction(str(elsewhere), str(root / "jx"))
    try:
        junction = confine_candidate_path(root, "jx/inner/native.bin", now_utc=_NOW)
    finally:
        os.rmdir(root / "jx")
    assert _codes(junction) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)

    # A symbolic link at the leaf when the principal may create one; otherwise a
    # second junction planted at the leaf's parent.
    link = root / "results" / "linked.bin"
    try:
        os.symlink(elsewhere / "inner" / "native.bin", link)
    except OSError:
        _winapi.CreateJunction(str(elsewhere / "inner"), str(root / "results" / "lnk"))
        try:
            symlinked = confine_candidate_path(
                root, "results/lnk/native.bin", now_utc=_NOW
            )
        finally:
            os.rmdir(root / "results" / "lnk")
    else:
        try:
            symlinked = confine_candidate_path(root, "results/linked.bin", now_utc=_NOW)
        finally:
            link.unlink()
    assert _codes(symlinked) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)

    # A hard link to the leaf.
    alias = tmp_path / "alias.bin"
    os.link(leaf, alias)
    try:
        hard = confine_candidate_path(root, "results/native.bin", now_utc=_NOW)
    finally:
        alias.unlink()
    assert _codes(hard) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert (elsewhere / "inner" / "native.bin").read_bytes() == b"outside"
    # Positive control: the plain leaf is confined once the aliases are gone.
    assert isinstance(
        confine_candidate_path(root, "results/native.bin", now_utc=_NOW), Success
    )


def test_mutation_during_hashing_rejected(tmp_path: Path) -> None:
    """19.3: a file that changes while hashing is rejected; the writer appends
    between chunks through the probe-free ``on_chunk`` hook of the hasher."""
    data = b"0123456789abcdef"
    candidate = _adapter_candidate(data)
    confined = _stage(tmp_path, candidate, data)
    appended: list[int] = []

    def append_between_chunks(length: int) -> None:
        if not appended:
            with confined.path.open("ab") as handle:
                handle.write(b"late bytes")
        appended.append(length)

    mutating = StreamingContentHasher(chunk_size=4, on_chunk=append_between_chunks)
    validation = _validate(candidate, confined, hasher=mutating)
    assert isinstance(validation.result, Failure)
    diagnostic = validation.result.diagnostics[0]
    assert diagnostic.error_code == ARTIFACT_VALIDATION_FAILED
    assert "changed while hashing" in diagnostic.message
    last = validation.observations[-1]
    assert (last.stage, last.outcome, last.error_code) == (
        "HASH",
        "FAILED",
        ARTIFACT_VALIDATION_FAILED,
    )
    assert last.diagnostic_id == diagnostic.diagnostic_id
    assert appended[0] == 4
    assert confined.path.read_bytes() == data + b"late bytes"
    # The same bytes hashed quietly validate with the declared facts of the
    # settled file, proving the refusal was the mutation and not the content.
    settled_data = data + b"late bytes"
    settled = _adapter_candidate(settled_data)
    _succeeded(_validate(settled, _stage(tmp_path / "settled", settled, settled_data)))


def test_open_handle_move_failure(tmp_path: Path) -> None:
    """28.5:2133: a candidate held open by another handle cannot be moved; the
    failure is ``ARTIFACT.MOVE_FAILED`` and the move succeeds once released."""
    store = _open_store(
        tmp_path / "runtime" / "staging",
        tmp_path / "artifacts",
        tmp_path / "runtime" / "quarantine",
    )
    data = b"held open"
    staged = _staged(store, data)
    target = store.finalized_path_for(sha256_bytes(data))
    handle = _hold_open_without_sharing(staged.path)
    try:
        exclusive = store.atomic_move(staged, target, now_utc=_NOW)
    finally:
        _winapi.CloseHandle(handle)
    assert _codes(exclusive) == (ARTIFACT_MOVE_FAILED,)
    assert staged.path.read_bytes() == data
    assert not target.exists()
    with staged.path.open("rb") as shared_reader:
        shared = store.atomic_move(staged, target, now_utc=_NOW)
        assert shared_reader.read() == data
    assert _codes(shared) == (ARTIFACT_MOVE_FAILED,)
    assert not target.exists()
    released = store.atomic_move(staged, target, now_utc=_NOW)
    assert isinstance(released, Success)
    assert released.value == MoveOutcome(
        source=staged.path, target=target, deduplicated=False
    )
    assert target.read_bytes() == data


def test_long_path_fixture_geometry_is_legal_on_every_host(tmp_path: Path) -> None:
    """The long-path fixture is checked without any long-path support: the
    original single 256-character component is refused (NTFS bounds a component
    at 255, so that root could never be created), and the corrected root yields
    a planned finalized path over 259 and within 1024 characters whose every
    component is legal. The checker's other two refusals are exercised so that
    ``None`` is a verdict, not a default."""
    assert (FILE_CEILING_WITHOUT_LONG_PATHS, LONG_PATH_CEILING) == (259, 1024)
    original = tmp_path / _ORIGINAL_LONG_COMPONENT
    assert len(original.name) == 256
    refused = _planned_finalized_path(original, _LONG_DATA)
    assert _long_path_geometry_refusal(refused) == "component_too_long"
    assert _long_path_geometry_refusal(tmp_path / "short" / "blob") == "path_not_long"
    over = tmp_path.joinpath(*[_LONG_COMPONENT] * 5)
    assert _long_path_geometry_refusal(over) == "path_over_ceiling"
    long_artifacts = _long_artifacts_root(tmp_path)
    assert all(len(part) <= _MAX_COMPONENT_CHARACTERS for part in long_artifacts.parts)
    assert len(str(long_artifacts)) > FILE_CEILING_WITHOUT_LONG_PATHS
    planned = _planned_finalized_path(long_artifacts, _LONG_DATA)
    assert planned.parent.parent == long_artifacts / "objects"
    assert _long_path_geometry_refusal(planned) is None
    assert FILE_CEILING_WITHOUT_LONG_PATHS < len(str(planned)) <= LONG_PATH_CEILING


def test_long_path_rejection_always_success_conditional(tmp_path: Path) -> None:
    """22.5:1655: the rejection over the handed-in ceiling always runs; the
    long-path success runs only when the host's probe detects support."""
    probe = probe_long_path_support(str(tmp_path), now=_NOW)
    assert isinstance(probe, Success)
    preflight = probe.value
    store = _open_store(
        tmp_path / "runtime" / "staging",
        tmp_path / "artifacts",
        tmp_path / "runtime" / "quarantine",
    )
    long_planned = store.artifacts_root / ("segment" * 40) / "blob"
    assert len(str(long_planned)) > 259
    rejected = store.preflight_planned_path(
        long_planned, file_ceiling=259, now_utc=_NOW
    )
    assert _codes(rejected) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    assert _failure(rejected).diagnostics[0].details["reason"] == "ceiling_exceeded"
    if preflight.long_paths_supported:
        assert preflight.file_ceiling == LONG_PATH_CEILING
        long_artifacts = _long_artifacts_root(tmp_path)
        assert len(str(long_artifacts)) > FILE_CEILING_WITHOUT_LONG_PATHS
        long_store = _open_store(
            tmp_path / "runtime" / "staging", long_artifacts, tmp_path / "runtime" / "q"
        )
        data = _LONG_DATA
        staged = _staged(long_store, data)
        target = long_store.finalized_path_for(sha256_bytes(data))
        assert target == _planned_finalized_path(long_artifacts, data)
        assert _long_path_geometry_refusal(target) is None
        admitted = long_store.preflight_planned_path(
            target, file_ceiling=preflight.file_ceiling, now_utc=_NOW
        )
        assert isinstance(admitted, Success)
        moved = long_store.atomic_move(staged, target, now_utc=_NOW)
        assert isinstance(moved, Success)
        assert target.read_bytes() == data
    else:
        assert preflight.file_ceiling == FILE_CEILING_WITHOUT_LONG_PATHS
        again = store.preflight_planned_path(
            long_planned, file_ceiling=preflight.file_ceiling, now_utc=_NOW
        )
        assert _codes(again) == (PROCESS_PATH_PREFLIGHT_REJECTED,)


def test_space_and_unicode_roots(tmp_path: Path) -> None:
    """28.5: staging, store and quarantine roots with spaces and Unicode
    components carry the whole stage-validate-move-quarantine flow."""
    staging = tmp_path / "lab space" / "stägîng ✓"
    artifacts = tmp_path / "art ifacts ü"
    quarantine = tmp_path / "lab space" / "quar antine ñ"
    store = _open_store(staging, artifacts, quarantine)
    data = b"stderr with unicode roots\n"
    staged = _staged(store, data)
    assert staged.root == staging / _OWNER_HASH
    candidate = _core_candidate()
    confined = confine_candidate_path(
        staging / _OWNER_HASH, candidate.staging_relative_path, now_utc=_NOW
    )
    assert isinstance(confined, Success)
    validated = _succeeded(_validate(candidate, confined.value))
    target = store.finalized_path_for(validated.content_hash)
    moved = store.atomic_move(confined.value, target, now_utc=_NOW)
    assert isinstance(moved, Success)
    assert target.read_bytes() == data
    duplicate = _staged(store, data, relative=f"INVOCATION/{INVOCATION_ID}/again.txt")
    deduplicated = store.atomic_move(duplicate, target, now_utc=_NOW)
    assert isinstance(deduplicated, Success)
    assert deduplicated.value.deduplicated is True
    suspect = _staged(store, b"suspect", relative=f"INVOCATION/{INVOCATION_ID}/s.txt")
    quarantined = store.quarantine_move(
        suspect, "entry one", ARTIFACT_VALIDATION_FAILED, now_utc=_NOW
    )
    assert isinstance(quarantined, Success)
    assert quarantined.value.target.read_bytes() == b"suspect"
    entries = store.quarantine_entries()
    assert [entry.entry_id for entry in entries] == ["entry one"]
    assert entries[0].files == (f"INVOCATION/{INVOCATION_ID}/s.txt",)
