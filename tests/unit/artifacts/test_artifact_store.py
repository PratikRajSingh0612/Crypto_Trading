"""Stage 9 Task 4: the content-addressed artifact store (plan 6.1, 6.2, 6.5;
specification 19.2:1405, 22.5, 28.5:2132-2133; readings 20, 21 and 26).

``ArtifactStore.open`` runs the 22.5 preflight (drive-lettered absolute roots, no
UNC, no reparse point on or above, one volume) and creates the layout;
``atomic_move`` reopens the source, compares the handle identity, ``fsync``s and
renames with the one move primitive, deduplicating an existing equal blob and
refusing a differing one; ``quarantine_move`` writes its metadata exclusively;
``write_staged`` is the only core-staging writer. The two guard tests at the end
pin the ``os`` root to this module and its attribute use to ``fstat`` and ``fsync``.
"""

from __future__ import annotations

import _winapi
import ast
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts import store as store_module
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
    artifact_failure,
)
from crypto_lab.artifacts.hashing import HashScan, StreamingContentHasher
from crypto_lab.artifacts.paths import ConfinedPath
from crypto_lab.artifacts.store import (
    CORE_INVARIANT_VIOLATION,
    PROCESS_PATH_PREFLIGHT_REJECTED,
    STORE_DIAGNOSTIC_POSTURES,
    ArtifactStore,
    MoveOutcome,
    QuarantineEntry,
    QuarantineOutcome,
    RemovalReport,
    read_confined,
    same_volume,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import (
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    CausalClosureEntry,
    hard_block_error_code,
)
from crypto_lab.process_supervision import diagnostics as stage7_diagnostics
from doubles.experiments import INVOCATION_ID

_NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
_OWNER_HASH = "a" * 64
_RELATIVE = f"INVOCATION/{INVOCATION_ID}/stderr.txt"
_ENTRY = "fin_12345678-1234-4234-8234-123456789abc"
_REPOSITORY = Path(__file__).resolve().parents[3]
_SOURCE = _REPOSITORY / "src/crypto_lab"
_STORE = _SOURCE / "artifacts/store.py"
_STAGE3_GUARD = _REPOSITORY / "tests/safety/test_stage3_boundaries.py"
_PACKAGE_LAYOUT = _REPOSITORY / "tests/unit/test_package_layout.py"


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


def _open(tmp_path: Path, **overrides: Any) -> ArtifactStore:
    arguments: dict[str, Any] = {
        "staging_root": tmp_path / "runtime" / "staging",
        "artifacts_root": tmp_path / "artifacts",
        "quarantine_root": tmp_path / "runtime" / "quarantine",
        "now_utc": _NOW,
    }
    arguments.update(overrides)
    for key in ("staging_root", "artifacts_root"):
        arguments[key].mkdir(parents=True, exist_ok=True)
    arguments["quarantine_root"].parent.mkdir(parents=True, exist_ok=True)
    opened = ArtifactStore.open(**arguments)
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


def _moved(result: object) -> MoveOutcome:
    assert isinstance(result, Success), result
    value = result.value
    assert isinstance(value, MoveOutcome)
    return value


def _literal(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None or not any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            continue
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            value = value.args[0]
        return ast.literal_eval(value)
    raise AssertionError(f"{name} not found in {path}")


def _parse_store() -> ast.Module:
    return ast.parse(_STORE.read_text(encoding="utf-8"), filename=str(_STORE))


# --- Plan Task 4 Step 1 ---------------------------------------------------------------


def test_same_volume_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading 20: the probe measures that two files under one ``tmp_path`` share
    ``st_dev`` and that the handle identity equals the ``lstat`` identity; the
    rejections cover a relative root, a UNC root, a missing root, a file root, a
    reparse root and a volume mismatch."""
    first = tmp_path / "first.bin"
    second = tmp_path / "nested" / "second.bin"
    second.parent.mkdir()
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    assert same_volume(first, second)
    assert first.stat().st_dev == second.stat().st_dev
    with first.open("rb") as handle:
        by_handle = os.fstat(handle.fileno())
    by_path = first.lstat()
    identity_pairs = (
        (by_handle.st_dev, by_path.st_dev),
        (by_handle.st_ino, by_path.st_ino),
        (by_handle.st_size, by_path.st_size),
        (by_handle.st_mtime_ns, by_path.st_mtime_ns),
    )
    (tmp_path / "st_dev_probe.txt").write_text(
        json.dumps(
            {
                "first_st_dev": first.stat().st_dev,
                "second_st_dev": second.stat().st_dev,
                "fstat_identity": identity_pairs,
            }
        ),
        encoding="utf-8",
    )
    assert all(left == right for left, right in identity_pairs), identity_pairs

    store = _open(tmp_path)
    assert store.staging_root == tmp_path / "runtime" / "staging"
    assert store.artifacts_root == tmp_path / "artifacts"
    assert store.quarantine_root == tmp_path / "runtime" / "quarantine"
    assert store.objects_root == tmp_path / "artifacts" / "objects"
    assert store.manifests_root == tmp_path / "artifacts" / "manifests"
    for created in (store.objects_root, store.manifests_root, store.quarantine_root):
        assert created.is_dir()
    assert isinstance(
        ArtifactStore.open(
            store.staging_root,
            store.artifacts_root,
            store.quarantine_root,
            now_utc=_NOW,
        ),
        Success,
    )  # idempotent reopen

    def refuse(staging: Path, artifacts: Path, quarantine: Path) -> str:
        result = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
        assert _codes(result) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
        diagnostic = _failure(result).diagnostics[0]
        assert diagnostic.category is DiagnosticCategory.USER_CONFIGURATION
        assert diagnostic.retriable is False
        assert not isinstance(diagnostic.invocation_id, str)
        reason = diagnostic.details["reason"]
        assert isinstance(reason, str)
        return reason

    staging, artifacts, quarantine = (
        store.staging_root,
        store.artifacts_root,
        store.quarantine_root,
    )
    assert refuse(Path("staging"), artifacts, quarantine) == "root_not_absolute"
    assert refuse(staging, tmp_path / "absent", quarantine) == "root_missing"
    assert refuse(staging, first, quarantine) == "root_not_directory"
    assert refuse(staging, artifacts, tmp_path / "absent" / "q") == "root_missing"

    def refuse_stat(*args: object, **kwargs: object) -> None:
        raise AssertionError("a UNC root reached the filesystem")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "stat", refuse_stat)
        patched.setattr(Path, "lstat", refuse_stat)
        assert refuse(staging, Path("//server/share/art"), quarantine) == "root_unc"
        assert (
            refuse(staging, Path(r"\\?\UNC\server\share\art"), quarantine) == "root_unc"
        )

    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        junction_root = refuse(staging, tmp_path / "link", quarantine)
    finally:
        os.rmdir(tmp_path / "link")
    assert junction_root == "ancestor_reparse_point"

    with monkeypatch.context() as patched:
        patched.setattr(store_module, "same_volume", lambda left, right: False)
        assert refuse(staging, artifacts, quarantine) == "volume_mismatch"

    blocked_artifacts = tmp_path / "blocked"
    blocked_artifacts.mkdir()
    (blocked_artifacts / "objects").write_bytes(b"a file where the layout belongs")
    assert refuse(staging, blocked_artifacts, quarantine) == "layout_not_creatable"
    with pytest.raises(TypeError, match="root must be a Path"):
        ArtifactStore.open(str(staging), artifacts, quarantine, now_utc=_NOW)  # type: ignore[arg-type]


def _snapshot(root: Path) -> tuple[tuple[str, int, int], ...]:
    """Every object below ``root`` with its ``lstat`` size and mtime: a parent
    directory's mtime changes when a child is created, so a new directory
    anywhere below ``root`` changes the snapshot."""
    entries: list[tuple[str, int, int]] = []
    for path in root.rglob("*"):
        observed = path.lstat()
        entries.append(
            (path.relative_to(root).as_posix(), observed.st_size, observed.st_mtime_ns)
        )
    return tuple(sorted(entries))


def _fresh_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Staging and artifacts roots that exist, a quarantine root whose parent
    exists and which the store may create -- the shape of every fixture."""
    staging = tmp_path / "runtime" / "staging"
    artifacts = tmp_path / "artifacts"
    quarantine = tmp_path / "runtime" / "quarantine"
    staging.mkdir(parents=True)
    artifacts.mkdir()
    return staging, artifacts, quarantine


def test_volume_mismatch_refusal_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 6.1 and reading 20: the root, reparse and same-volume preflight all
    complete before the layout is created, so a refused volume leaves the
    filesystem exactly as it was found -- no ``objects/``, no ``manifests/``, no
    quarantine root."""
    staging, artifacts, quarantine = _fresh_roots(tmp_path)
    before = _snapshot(tmp_path)
    with monkeypatch.context() as patched:
        patched.setattr(store_module, "same_volume", lambda left, right: False)
        refused = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert _codes(refused) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    diagnostic = _failure(refused).diagnostics[0]
    assert diagnostic.details["reason"] == "volume_mismatch"
    assert diagnostic.category is DiagnosticCategory.USER_CONFIGURATION
    assert diagnostic.retriable is False
    assert str(tmp_path) not in diagnostic.message
    assert _snapshot(tmp_path) == before
    assert not (artifacts / "objects").exists()
    assert not (artifacts / "manifests").exists()
    assert not quarantine.exists()
    assert list(artifacts.iterdir()) == []
    assert [path.name for path in (tmp_path / "runtime").iterdir()] == ["staging"]
    # Positive control: the same roots on one volume open and create the layout.
    opened = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert isinstance(opened, Success)
    assert (artifacts / "objects").is_dir()
    assert (artifacts / "manifests").is_dir()
    assert quarantine.is_dir()


def test_volume_probe_precedes_layout_and_stands_in_for_an_absent_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same-volume probe runs while no layout directory exists; a quarantine
    root the store may still create is probed through its parent, and through
    itself once it exists."""
    staging, artifacts, quarantine = _fresh_roots(tmp_path)
    probes: list[tuple[Path, Path, bool, bool]] = []
    original = store_module.same_volume

    def spying_same_volume(left: Path, right: Path) -> bool:
        probes.append(
            (left, right, (artifacts / "objects").exists(), quarantine.exists())
        )
        return original(left, right)

    monkeypatch.setattr(store_module, "same_volume", spying_same_volume)
    first = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert isinstance(first, Success)
    assert probes == [
        (staging, artifacts, False, False),
        (staging, quarantine.parent, False, False),
    ]
    probes.clear()
    reopened = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert isinstance(reopened, Success)
    assert probes == [
        (staging, artifacts, True, True),
        (staging, quarantine, True, True),
    ]


def test_file_shaped_quarantine_root_is_refused_before_any_layout(
    tmp_path: Path,
) -> None:
    """22.5: a quarantine root that exists as a regular file is
    ``root_not_directory`` -- the root itself is inspected when it exists, its
    parent only while it is absent -- and the refusal precedes the layout, so the
    file's bytes and the filesystem snapshot are exactly as they were found."""
    staging, artifacts, quarantine = _fresh_roots(tmp_path)
    planted = b"a file where the quarantine root belongs"
    quarantine.write_bytes(planted)
    before = _snapshot(tmp_path)
    refused = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert _codes(refused) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    diagnostic = _failure(refused).diagnostics[0]
    assert diagnostic.details["reason"] == "root_not_directory"
    assert diagnostic.category is DiagnosticCategory.USER_CONFIGURATION
    assert diagnostic.retriable is False
    assert str(tmp_path) not in diagnostic.message
    assert quarantine.read_bytes() == planted
    assert _snapshot(tmp_path) == before
    assert not (artifacts / "objects").exists()
    assert not (artifacts / "manifests").exists()
    assert list(artifacts.iterdir()) == []
    # Positive control: with the file gone the same roots open and create the layout.
    quarantine.unlink()
    opened = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert isinstance(opened, Success)
    assert quarantine.is_dir()
    assert (artifacts / "objects").is_dir()


def test_quarantine_root_inspection_error_refuses_rather_than_implying_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``lstat`` of the quarantine root that fails for a reason other than
    absence is refused as ``root_not_directory`` (the Stage 7 ``roots.py``
    posture) instead of being probed through its parent; nothing is created."""
    staging, artifacts, quarantine = _fresh_roots(tmp_path)
    before = _snapshot(tmp_path)
    original_lstat = Path.lstat

    def refuse_quarantine_lstat(self: Path) -> os.stat_result:
        if self == quarantine:
            raise PermissionError(13, "Permission denied")
        return original_lstat(self)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "lstat", refuse_quarantine_lstat)
        refused = ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW)
    assert _codes(refused) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    assert _failure(refused).diagnostics[0].details["reason"] == "root_not_directory"
    assert _snapshot(tmp_path) == before
    assert not quarantine.exists()
    assert not (artifacts / "objects").exists()
    assert not (artifacts / "manifests").exists()
    # Positive control: the same roots open once the root can be inspected.
    assert isinstance(
        ArtifactStore.open(staging, artifacts, quarantine, now_utc=_NOW), Success
    )


def test_the_two_mirrored_postures_equal_the_stage_seven_table() -> None:
    """``artifacts`` may not import ``process_supervision``; the two non-artifact
    codes the store mints are restated and pinned equal, literal and posture."""
    assert (
        PROCESS_PATH_PREFLIGHT_REJECTED
        == stage7_diagnostics.PROCESS_PATH_PREFLIGHT_REJECTED
    )
    assert CORE_INVARIANT_VIOLATION == stage7_diagnostics.CORE_INVARIANT_VIOLATION
    assert set(STORE_DIAGNOSTIC_POSTURES) == {
        PROCESS_PATH_PREFLIGHT_REJECTED,
        CORE_INVARIANT_VIOLATION,
    }
    for code, posture in STORE_DIAGNOSTIC_POSTURES.items():
        theirs = stage7_diagnostics.STAGE7_DIAGNOSTIC_CODES[code]
        assert (posture.category, posture.retriable, posture.severity) == (
            theirs.category,
            theirs.retriable,
            theirs.severity,
        )
    assert STORE_DIAGNOSTIC_POSTURES[CORE_INVARIANT_VIOLATION].severity is (
        DiagnosticSeverity.ERROR
    )


def test_content_addressed_dedup_never_overwrites(tmp_path: Path) -> None:
    """R19.2-05, R19.2-08, reading 21: an existing equal blob deduplicates; a
    differing one is an invariant violation; finalized content is never
    overwritten."""
    store = _open(tmp_path)
    data = b"finalized bytes"
    digest = sha256_bytes(data)
    target = store.finalized_path_for(digest)
    assert target == store.objects_root / digest[:2] / digest
    assert store.manifest_path_for("art_12345678-1234-4234-8234-123456789abc") == (
        store.manifests_root / "art_12345678-1234-4234-8234-123456789abc.json"
    )
    with pytest.raises(ValueError, match="64 lowercase hex"):
        store.finalized_path_for("A" * 64)
    with pytest.raises(ValueError, match="art_"):
        store.manifest_path_for("cand_12345678-1234-4234-8234-123456789abc")
    with pytest.raises(TypeError, match="artifact id must be a built-in string"):
        store.manifest_path_for(7)  # type: ignore[arg-type]

    first = _staged(store, data)
    with pytest.raises(TypeError, match="target must be a Path"):
        store.atomic_move(first, str(target), now_utc=_NOW)  # type: ignore[arg-type]
    moved = _moved(store.atomic_move(first, target, now_utc=_NOW))
    assert moved == MoveOutcome(source=first.path, target=target, deduplicated=False)
    assert not first.path.exists()
    assert target.read_bytes() == data
    blob_identity = target.lstat()

    second = _staged(store, data, relative=f"INVOCATION/{INVOCATION_ID}/again.txt")
    deduplicated = _moved(store.atomic_move(second, target, now_utc=_NOW))
    assert deduplicated == MoveOutcome(
        source=second.path, target=target, deduplicated=True
    )
    assert not second.path.exists()
    assert target.read_bytes() == data
    assert (target.lstat().st_ino, target.lstat().st_mtime_ns) == (
        blob_identity.st_ino,
        blob_identity.st_mtime_ns,
    )

    colliding = _staged(
        store, b"different bytes", relative=f"INVOCATION/{INVOCATION_ID}/other.txt"
    )
    refused = store.atomic_move(colliding, target, now_utc=_NOW)
    assert _codes(refused) == (CORE_INVARIANT_VIOLATION,)
    collision = _failure(refused).diagnostics[0]
    assert collision.category is DiagnosticCategory.INTERNAL_INVARIANT
    assert target.read_bytes() == data
    assert colliding.path.read_bytes() == b"different bytes"
    with pytest.raises(ValueError, match="content-addressed"):
        store.atomic_move(colliding, store.objects_root / "aa" / "blob", now_utc=_NOW)
    with pytest.raises(ValueError, match="content-addressed"):
        store.atomic_move(colliding, tmp_path / digest, now_utc=_NOW)


def test_dedup_storage_failures_are_move_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dedup branch's own storage refusals: an unreadable existing blob, a
    candidate that cannot be removed, a shard blocked by a file."""
    store = _open(tmp_path)
    data = b"finalized bytes"
    target = store.finalized_path_for(sha256_bytes(data))
    _moved(store.atomic_move(_staged(store, data), target, now_utc=_NOW))
    second = _staged(store, data, relative=f"INVOCATION/{INVOCATION_ID}/again.txt")
    original_open = Path.open

    def refuse_target_read(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == target:
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_target_read)
        unreadable = store.atomic_move(second, target, now_utc=_NOW)
    assert _codes(unreadable) == (ARTIFACT_MOVE_FAILED,)
    assert second.path.read_bytes() == data

    def refuse_unlink(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Permission denied")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "unlink", refuse_unlink)
        unremovable = store.atomic_move(second, target, now_utc=_NOW)
    assert _codes(unremovable) == (ARTIFACT_MOVE_FAILED,)
    assert second.path.read_bytes() == data
    assert target.read_bytes() == data

    other = b"other content"
    other_digest = sha256_bytes(other)
    assert other_digest[:2] != sha256_bytes(data)[:2]
    (store.objects_root / other_digest[:2]).write_bytes(b"a file, not a shard")
    third = _staged(store, other, relative=f"INVOCATION/{INVOCATION_ID}/third.txt")
    blocked = store.atomic_move(
        third, store.finalized_path_for(other_digest), now_utc=_NOW
    )
    assert _codes(blocked) == (ARTIFACT_MOVE_FAILED,)
    assert third.path.read_bytes() == other


def test_rename_only_same_volume(tmp_path: Path) -> None:
    """R29.1-01: ``Path.rename`` is the one move primitive; the blob keeps its
    file identity across the move, so nothing was copied; no ``shutil`` and no
    ``replace`` appear in the module."""
    store = _open(tmp_path)
    data = b"renamed, not copied"
    staged = _staged(store, data)
    target = store.finalized_path_for(sha256_bytes(data))
    _moved(store.atomic_move(staged, target, now_utc=_NOW))
    assert target.lstat().st_ino == staged.identity.st_ino
    assert target.lstat().st_dev == staged.identity.st_dev
    tree = _parse_store()
    roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "shutil" not in roots
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "replace" not in attributes
    assert "rename" in attributes


def test_os_errors_become_stable_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F8.2-9, R21.3-01: an ``OSError`` from the move is ``ARTIFACT.MOVE_FAILED``
    with a content-derived identity and no path in the message."""
    store = _open(tmp_path)
    data = b"will not move"
    staged = _staged(store, data)
    target = store.finalized_path_for(sha256_bytes(data))

    def refuse_rename(self: Path, target: Path) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "rename", refuse_rename)
    first = store.atomic_move(staged, target, now_utc=_NOW)
    second = store.atomic_move(staged, target, now_utc=_NOW)
    assert _codes(first) == (ARTIFACT_MOVE_FAILED,)
    assert _codes(second) == (ARTIFACT_MOVE_FAILED,)
    diagnostic = _failure(first).diagnostics[0]
    assert diagnostic.diagnostic_id == _failure(second).diagnostics[0].diagnostic_id
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.retriable is False
    assert diagnostic.details == {}
    assert str(tmp_path) not in diagnostic.message
    assert "stderr.txt" not in diagnostic.message
    assert staged.path.read_bytes() == data
    assert not target.exists()


def test_disk_full_permission_lock_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R29.5-01, reading 26: a move failure is a storage failure in the
    ``PERSISTENCE`` category, outside the hard-blocking partition."""
    store = _open(tmp_path)
    data = b"held or full"
    staged = _staged(store, data)
    target = store.finalized_path_for(sha256_bytes(data))
    original_open = Path.open

    def permission_refused(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == staged.path:
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", permission_refused)
        locked = store.atomic_move(staged, target, now_utc=_NOW)
    assert _codes(locked) == (ARTIFACT_MOVE_FAILED,)

    def disk_full(self: Path, target: Path) -> Path:
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "rename", disk_full)
        full = store.atomic_move(staged, target, now_utc=_NOW)
    assert _codes(full) == (ARTIFACT_MOVE_FAILED,)
    for result in (locked, full):
        diagnostic = _failure(result).diagnostics[0]
        assert diagnostic.category is DiagnosticCategory.PERSISTENCE
        assert diagnostic.category not in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES
        closure = (
            CausalClosureEntry(
                category=diagnostic.category, error_code=diagnostic.error_code
            ),
        )
        assert not isinstance(hard_block_error_code(closure), str)
    assert staged.path.read_bytes() == data


def test_quarantine_entry_written_exclusive(tmp_path: Path) -> None:
    store = _open(tmp_path)
    data = b"quarantined bytes"
    staged = _staged(store, data)
    outcome = store.quarantine_move(
        staged,
        _ENTRY,
        ARTIFACT_VALIDATION_FAILED,
        now_utc=_NOW,
        sha256=sha256_bytes(data),
    )
    assert isinstance(outcome, Success)
    value = outcome.value
    assert isinstance(value, QuarantineOutcome)
    entry_root = store.quarantine_root / _ENTRY
    assert value == QuarantineOutcome(
        entry_id=_ENTRY,
        target=entry_root.joinpath(*_RELATIVE.split("/")),
        metadata_path=entry_root / "quarantine.json",
        metadata_written=True,
    )
    assert value.target.read_bytes() == data
    assert not staged.path.exists()
    metadata = json.loads(value.metadata_path.read_text(encoding="utf-8"))
    assert metadata == {
        "schema_version": "1.0.0",
        "entry_id": _ENTRY,
        "reason_code": ARTIFACT_VALIDATION_FAILED,
        "quarantined_at_utc": "2026-08-10T01:02:03Z",
        "source_root": str(staged.root),
        "relative_path": _RELATIVE,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
    }
    metadata_bytes = value.metadata_path.read_bytes()

    # A second blob of the same entry: moved, metadata left exactly as written.
    second = _staged(store, b"second", relative=f"INVOCATION/{INVOCATION_ID}/two.txt")
    again = store.quarantine_move(
        second, _ENTRY, ARTIFACT_VALIDATION_FAILED, now_utc=_NOW
    )
    assert isinstance(again, Success)
    assert again.value.metadata_written is False
    assert value.metadata_path.read_bytes() == metadata_bytes
    assert again.value.target.read_bytes() == b"second"

    # A planted metadata file is never overwritten; the blob still moves.
    planted_entry = store.quarantine_root / "planted"
    planted_entry.mkdir()
    (planted_entry / "quarantine.json").write_bytes(b"{}")
    third = _staged(store, b"third", relative=f"INVOCATION/{INVOCATION_ID}/three.txt")
    planted = store.quarantine_move(
        third, "planted", ARTIFACT_MOVE_FAILED, now_utc=_NOW
    )
    assert isinstance(planted, Success)
    assert planted.value.metadata_written is False
    assert (planted_entry / "quarantine.json").read_bytes() == b"{}"

    # A target that already exists is never overwritten: invariant violation.
    colliding = _staged(store, b"collide")
    refused = store.quarantine_move(
        colliding, _ENTRY, ARTIFACT_VALIDATION_FAILED, now_utc=_NOW
    )
    assert _codes(refused) == (CORE_INVARIANT_VIOLATION,)
    assert value.target.read_bytes() == data
    assert colliding.path.read_bytes() == b"collide"

    entries = store.quarantine_entries()
    assert entries == (
        QuarantineEntry(
            entry_id=_ENTRY,
            reason_code=ARTIFACT_VALIDATION_FAILED,
            quarantined_at_utc=_NOW,
            files=(_RELATIVE, f"INVOCATION/{INVOCATION_ID}/two.txt"),
        ),
        QuarantineEntry(
            entry_id="planted",
            reason_code=None,
            quarantined_at_utc=None,
            files=(f"INVOCATION/{INVOCATION_ID}/three.txt",),
        ),
    )
    with pytest.raises(ValueError, match="entry id"):
        store.quarantine_move(
            colliding, "../escape", ARTIFACT_MOVE_FAILED, now_utc=_NOW
        )
    with pytest.raises(ValueError, match="reason"):
        store.quarantine_move(colliding, "other", "not a code", now_utc=_NOW)
    with pytest.raises(TypeError, match="entry id must be a built-in string"):
        store.quarantine_move(colliding, 7, ARTIFACT_MOVE_FAILED, now_utc=_NOW)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="reason must be a built-in string"):
        store.quarantine_move(colliding, "other", 7, now_utc=_NOW)  # type: ignore[arg-type]


def test_quarantine_storage_refusals_and_listing_tolerance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _open(tmp_path)
    swapped = _staged(store, b"before")
    swapped.path.unlink()
    swapped.path.write_bytes(b"after the swap, another size")
    refused = store.quarantine_move(
        swapped, _ENTRY, ARTIFACT_VALIDATION_FAILED, now_utc=_NOW
    )
    assert _codes(refused) == (ARTIFACT_VALIDATION_FAILED,)
    assert not (store.quarantine_root / _ENTRY).exists()

    staged = _staged(store, b"meta", relative=f"INVOCATION/{INVOCATION_ID}/m.txt")
    original_open = Path.open

    def refuse_exclusive(self: Path, *args: Any, **kwargs: Any) -> Any:
        if args and args[0] == "xb":
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_exclusive)
        unwritable = store.quarantine_move(
            staged, "meta-entry", ARTIFACT_MOVE_FAILED, now_utc=_NOW
        )
    assert _codes(unwritable) == (ARTIFACT_MOVE_FAILED,)
    moved_anyway = store.quarantine_root / "meta-entry" / "INVOCATION" / INVOCATION_ID
    assert (moved_anyway / "m.txt").read_bytes() == b"meta"

    (store.quarantine_root / "blocked").write_bytes(b"a file where an entry belongs")
    blocked = store.quarantine_move(
        _staged(store, b"b", relative=f"INVOCATION/{INVOCATION_ID}/b.txt"),
        "blocked",
        ARTIFACT_MOVE_FAILED,
        now_utc=_NOW,
    )
    assert _codes(blocked) == (ARTIFACT_MOVE_FAILED,)

    (store.quarantine_root / "bare").mkdir()
    (store.quarantine_root / "bare" / "x.bin").write_bytes(b"x")
    (store.quarantine_root / "malformed").mkdir()
    (store.quarantine_root / "malformed" / "quarantine.json").write_bytes(b"not json")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "secret.bin").write_bytes(b"s")
    _winapi.CreateJunction(str(elsewhere), str(store.quarantine_root / "jx"))
    inner_junction = store.quarantine_root / "bare" / "inner"
    _winapi.CreateJunction(str(elsewhere), str(inner_junction))
    try:
        entries = store.quarantine_entries()
    finally:
        os.rmdir(store.quarantine_root / "jx")
        os.rmdir(inner_junction)
    assert [(entry.entry_id, entry.reason_code, entry.files) for entry in entries] == [
        ("bare", None, ("x.bin",)),
        ("malformed", None, ()),
        ("meta-entry", None, (f"INVOCATION/{INVOCATION_ID}/m.txt",)),
    ]
    assert all(entry.quarantined_at_utc is None for entry in entries)
    with pytest.raises(TypeError, match="ConfinedPath"):
        store.quarantine_move(staged.path, "x", ARTIFACT_MOVE_FAILED, now_utc=_NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        store.quarantine_move(
            staged, "x", ARTIFACT_MOVE_FAILED, now_utc=_NOW, sha256="not-hex"
        )

    # A rename refused by the volume itself is the storage posture of reading 26.
    def disk_full(self: Path, target: Path) -> Path:
        raise OSError(28, "No space left on device")

    unmovable_source = _staged(
        store, b"unmovable", relative=f"INVOCATION/{INVOCATION_ID}/u.txt"
    )
    with monkeypatch.context() as patched:
        patched.setattr(Path, "rename", disk_full)
        unmovable = store.quarantine_move(
            unmovable_source, "unmovable", ARTIFACT_MOVE_FAILED, now_utc=_NOW
        )
    assert _codes(unmovable) == (ARTIFACT_MOVE_FAILED,)
    assert "quarantined" in _failure(unmovable).diagnostics[0].message
    assert unmovable_source.path.read_bytes() == b"unmovable"


def test_write_staged_storage_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A junction below the owner root is refused before any byte is written; a
    file where a directory belongs, an unreadable existing file and a refused
    confinement after the write are each returned as stable diagnostics."""
    store = _open(tmp_path)
    data = b"stderr\n"
    owner_root = store.staging_root / _OWNER_HASH
    owner_root.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _winapi.CreateJunction(str(elsewhere), str(owner_root / "INVOCATION"))
    try:
        through = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    finally:
        os.rmdir(owner_root / "INVOCATION")
    assert _codes(through) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert list(elsewhere.iterdir()) == []

    (owner_root / "INVOCATION").write_bytes(b"a file where a directory belongs")
    blocked = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert _codes(blocked) == (ARTIFACT_MOVE_FAILED,)
    (owner_root / "INVOCATION").unlink()

    written = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert isinstance(written, Success)
    original_open = Path.open

    def refuse_reads(self: Path, *args: Any, **kwargs: Any) -> Any:
        if args and args[0] == "rb":
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_reads)
        unreadable = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert _codes(unreadable) == (ARTIFACT_MOVE_FAILED,)

    planted = artifact_failure(
        ARTIFACT_PATH_BOUNDARY_VIOLATION, message="planted refusal", now_utc=_NOW
    )
    with monkeypatch.context() as patched:
        patched.setattr(
            store_module, "confine_candidate_path", lambda *args, **kwargs: planted
        )
        refused = store.write_staged(
            _OWNER_HASH, f"INVOCATION/{INVOCATION_ID}/fresh.txt", data, now_utc=_NOW
        )
    assert refused is planted


def test_write_staged_is_exclusive_and_fsynced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R15.5-02, plan 6.5: exclusive create below ``<staging_root>/<owner_hash>/``,
    ``fsync`` observed through the ``os`` spy, equal bytes replayed, differing bytes
    an invariant violation, an escaping path refused."""
    store = _open(tmp_path)
    fsyncs: list[int] = []
    original_fsync = os.fsync

    def spying_fsync(fd: int) -> None:
        fsyncs.append(fd)
        original_fsync(fd)

    monkeypatch.setattr(os, "fsync", spying_fsync)
    data = b"stderr line\n"
    written = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert isinstance(written, Success)
    confined = written.value
    assert isinstance(confined, ConfinedPath)
    owner_root = store.staging_root / _OWNER_HASH
    assert confined.root == owner_root
    assert confined.relative == _RELATIVE
    assert confined.path == owner_root.joinpath(*_RELATIVE.split("/"))
    assert confined.path.read_bytes() == data
    assert len(fsyncs) == 1

    replayed = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert isinstance(replayed, Success)
    assert replayed.value == confined
    assert len(fsyncs) == 1  # a replay writes nothing

    differing = store.write_staged(_OWNER_HASH, _RELATIVE, b"other", now_utc=_NOW)
    assert _codes(differing) == (CORE_INVARIANT_VIOLATION,)
    assert confined.path.read_bytes() == data

    escaping = store.write_staged(_OWNER_HASH, "../escape.txt", data, now_utc=_NOW)
    assert _codes(escaping) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert not (store.staging_root / "escape.txt").exists()
    with pytest.raises(ValueError, match="owner hash"):
        store.write_staged("not-a-hash", _RELATIVE, data, now_utc=_NOW)
    with pytest.raises(TypeError, match="owner hash must be a built-in string"):
        store.write_staged(b"a" * 64, _RELATIVE, data, now_utc=_NOW)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bytes"):
        store.write_staged(_OWNER_HASH, _RELATIVE, "text", now_utc=_NOW)  # type: ignore[arg-type]

    def refuse_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_open)
        refused = store.write_staged(
            _OWNER_HASH, f"INVOCATION/{INVOCATION_ID}/held.txt", data, now_utc=_NOW
        )
    assert _codes(refused) == (ARTIFACT_MOVE_FAILED,)


def test_atomic_move_fsyncs_and_rechecks_the_handle_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 6.5 and reading 18: the source is reopened, its ``fstat`` identity is
    compared with the confined identity and it is ``fsync``ed before the rename."""
    store = _open(tmp_path)
    data = b"move me"
    staged = _staged(store, data)
    target = store.finalized_path_for(sha256_bytes(data))
    fstats: list[int] = []
    fsyncs: list[int] = []
    original_fstat = os.fstat
    original_fsync = os.fsync

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    def spying_fsync(fd: int) -> None:
        fsyncs.append(fd)
        original_fsync(fd)

    monkeypatch.setattr(os, "fstat", spying_fstat)
    monkeypatch.setattr(os, "fsync", spying_fsync)
    _moved(store.atomic_move(staged, target, now_utc=_NOW))
    assert len(fstats) == 1
    assert len(fsyncs) == 1
    assert fstats == fsyncs  # the same handle

    swapped = _staged(
        store, b"before swap", relative=f"INVOCATION/{INVOCATION_ID}/s.txt"
    )
    swapped.path.unlink()
    swapped.path.write_bytes(b"after the swap, another size")
    refused = store.atomic_move(
        swapped, store.finalized_path_for(sha256_bytes(b"before swap")), now_utc=_NOW
    )
    assert _codes(refused) == (ARTIFACT_VALIDATION_FAILED,)
    assert "changed while finalizing" in _failure(refused).diagnostics[0].message
    assert swapped.path.read_bytes() == b"after the swap, another size"
    with pytest.raises(TypeError, match="ConfinedPath"):
        store.atomic_move(swapped.path, target, now_utc=_NOW)  # type: ignore[arg-type]


def test_preflight_planned_path_uses_the_caller_ceiling(tmp_path: Path) -> None:
    """22.5:1655: a planned path over the handed-in file ceiling is refused before
    anything is written; the rejection always runs."""
    store = _open(tmp_path)
    planned = store.finalized_path_for("b" * 64)
    long_planned = store.artifacts_root / ("deep" * 70) / "blob"
    assert len(str(long_planned)) > 259
    admitted = store.preflight_planned_path(planned, file_ceiling=259, now_utc=_NOW)
    assert isinstance(admitted, Success)
    rejected = store.preflight_planned_path(
        long_planned, file_ceiling=259, now_utc=_NOW
    )
    assert _codes(rejected) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    details = _failure(rejected).diagnostics[0].details
    assert details["reason"] == "ceiling_exceeded"
    assert details["path_length"] == len(str(long_planned))
    assert details["ceiling"] == 259
    assert str(long_planned) not in _failure(rejected).diagnostics[0].message
    assert isinstance(
        store.preflight_planned_path(long_planned, file_ceiling=1024, now_utc=_NOW),
        Success,
    )
    with pytest.raises(ValueError, match="ceiling"):
        store.preflight_planned_path(planned, file_ceiling=0, now_utc=_NOW)


def test_remove_raw_bytes_reports_each_outcome(tmp_path: Path) -> None:
    store = _open(tmp_path)
    removable = tmp_path / "root" / "request.json"
    removable.parent.mkdir()
    removable.write_bytes(b"{}")
    missing = tmp_path / "root" / "output.json"
    directory = tmp_path / "root" / "runs"
    directory.mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.bin").write_bytes(b"keep")
    junction = tmp_path / "root" / "jx"
    _winapi.CreateJunction(str(target), str(junction))
    held = tmp_path / "root" / "held.json"
    held.write_bytes(b"held")
    handle = _hold_open_without_sharing(held)
    try:
        report = store.remove_raw_bytes((removable, missing, directory, junction, held))
    finally:
        _winapi.CloseHandle(handle)
        os.rmdir(junction)
    assert report == RemovalReport(
        removed=(removable,),
        missing=(missing,),
        failed=(directory, junction, held),
    )
    assert held.read_bytes() == b"held"
    assert not removable.exists()
    assert (target / "keep.bin").read_bytes() == b"keep"
    with pytest.raises(ValueError, match="absolute"):
        store.remove_raw_bytes((Path("request.json"),))
    assert store.remove_raw_bytes(()) == RemovalReport(
        removed=(), missing=(), failed=()
    )


def test_remove_raw_bytes_distinguishes_absence_from_inspection_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.3 phase 6: only a ``FileNotFoundError`` from the inspection means
    missing; a ``PermissionError`` or any other ``OSError`` is a failed removal
    whose source is retained -- no unlink is attempted and the bytes stay."""
    store = _open(tmp_path)
    root = tmp_path / "root"
    root.mkdir()
    removable = root / "request.json"
    removable.write_bytes(b"{}")
    absent = root / "output.json"
    denied = root / "denied.json"
    denied.write_bytes(b"denied bytes")
    faulted = root / "faulted.json"
    faulted.write_bytes(b"faulted bytes")
    original_lstat = Path.lstat
    original_unlink = Path.unlink
    unlinked: list[Path] = []

    def selective_lstat(self: Path) -> os.stat_result:
        if self == denied:
            raise PermissionError(13, "Permission denied")
        if self == faulted:
            raise OSError(5, "Input/output error")
        return original_lstat(self)

    def spying_unlink(self: Path, missing_ok: bool = False) -> None:
        unlinked.append(self)
        original_unlink(self, missing_ok=missing_ok)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "lstat", selective_lstat)
        patched.setattr(Path, "unlink", spying_unlink)
        report = store.remove_raw_bytes((removable, absent, denied, faulted))
    assert report == RemovalReport(
        removed=(removable,), missing=(absent,), failed=(denied, faulted)
    )
    assert unlinked == [removable]
    assert not removable.exists()
    assert denied.read_bytes() == b"denied bytes"
    assert faulted.read_bytes() == b"faulted bytes"
    # Positive control: once inspectable, the same two sources are removed.
    assert store.remove_raw_bytes((denied, faulted)) == RemovalReport(
        removed=(denied, faulted), missing=(), failed=()
    )


class _RecordingHasher:
    """A ``ContentHasher`` that records the descriptor of every handle it reads
    and delegates to the streaming hasher (plan 4.1 stream entry points)."""

    def __init__(self, chunk_size: int = 4) -> None:
        self._inner = StreamingContentHasher(chunk_size=chunk_size)
        self.descriptors: list[int] = []

    def sha256_stream(self, source: BinaryIO) -> str:
        self.descriptors.append(source.fileno())
        return self._inner.sha256_stream(source)

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        self.descriptors.append(source.fileno())
        return self._inner.sha256_and_scan(
            source, token, detect_token_shape=detect_token_shape
        )


class _UnreadableHasher:
    """A ``ContentHasher`` whose stream fails with a plain storage error."""

    def sha256_stream(self, source: BinaryIO) -> str:
        raise OSError(5, "Input/output error")

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        raise OSError(5, "Input/output error")


def test_hash_confined_streams_through_the_identity_checked_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.1 and reading 18: the store opens the confined candidate once, checks
    the ``fstat`` identity of that handle against the confined identity, streams
    the digest through the same handle and checks the identity again; a swap or a
    mutation while hashing is ``ARTIFACT.VALIDATION_FAILED``, a refused open or
    read ``ARTIFACT.MOVE_FAILED``, and no path is reopened for the hash. The
    dedup branch hashes the candidate through the same bridge."""
    recording = _RecordingHasher()
    store = _open(tmp_path, hasher=recording)
    data = b"hash me through the handle"
    staged = _staged(store, data)
    fstats: list[int] = []
    original_fstat = os.fstat

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    opens: list[tuple[Path, tuple[Any, ...]]] = []
    original_open = Path.open

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(os, "fstat", spying_fstat)
    monkeypatch.setattr(Path, "open", spying_open)
    hashed = store.hash_confined(staged, now_utc=_NOW)
    assert isinstance(hashed, Success), hashed
    assert hashed.value == sha256_bytes(data)
    assert len(recording.descriptors) == 1
    assert fstats == [recording.descriptors[0], recording.descriptors[0]]
    assert opens == [(staged.path, ("rb",))]
    assert staged.path.read_bytes() == data

    # A swap between confinement and hashing: refused before any byte is hashed.
    swapped = _staged(store, b"before", relative=f"INVOCATION/{INVOCATION_ID}/s.txt")
    swapped.path.unlink()
    swapped.path.write_bytes(b"after the swap, another size")
    recording.descriptors.clear()
    refused = store.hash_confined(swapped, now_utc=_NOW)
    assert _codes(refused) == (ARTIFACT_VALIDATION_FAILED,)
    assert "changed while finalizing" in _failure(refused).diagnostics[0].message
    assert recording.descriptors == []

    # A mutation while hashing: the identity after the stream differs.
    appended: list[int] = []

    def append_between_chunks(length: int) -> None:
        if not appended:
            with original_open(staged.path, "ab") as handle:
                handle.write(b"late bytes")
        appended.append(length)

    mutating = StreamingContentHasher(chunk_size=4, on_chunk=append_between_chunks)
    mutated = _open(tmp_path, hasher=mutating).hash_confined(staged, now_utc=_NOW)
    assert _codes(mutated) == (ARTIFACT_VALIDATION_FAILED,)
    assert "changed while finalizing" in _failure(mutated).diagnostics[0].message
    assert appended[0] == 4
    assert staged.path.read_bytes() == data + b"late bytes"

    # Storage refusals: a refused open and a read that fails mid-stream.
    settled = _staged(store, b"settled", relative=f"INVOCATION/{INVOCATION_ID}/t.txt")

    def refuse_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == settled.path:
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_open)
        unopenable = store.hash_confined(settled, now_utc=_NOW)
    assert _codes(unopenable) == (ARTIFACT_MOVE_FAILED,)
    unreadable = _open(tmp_path, hasher=_UnreadableHasher()).hash_confined(
        settled, now_utc=_NOW
    )
    assert _codes(unreadable) == (ARTIFACT_MOVE_FAILED,)
    for result in (unopenable, unreadable):
        diagnostic = _failure(result).diagnostics[0]
        assert diagnostic.category is DiagnosticCategory.PERSISTENCE
        assert str(tmp_path) not in diagnostic.message
    assert settled.path.read_bytes() == b"settled"
    with pytest.raises(TypeError, match="ConfinedPath"):
        store.hash_confined(settled.path, now_utc=_NOW)  # type: ignore[arg-type]

    # The dedup branch: the existing blob is streamed by path, the candidate
    # through the identity-checked handle -- fstat before and after its stream.
    target = store.finalized_path_for(sha256_bytes(b"settled"))
    _moved(store.atomic_move(settled, target, now_utc=_NOW))
    duplicate = _staged(store, b"settled", relative=f"INVOCATION/{INVOCATION_ID}/d.txt")
    recording.descriptors.clear()
    fstats.clear()
    opens.clear()
    deduplicated = _moved(store.atomic_move(duplicate, target, now_utc=_NOW))
    assert deduplicated.deduplicated is True
    assert [(path, args) for path, args in opens] == [
        (duplicate.path, ("r+b",)),
        (target, ("rb",)),
        (duplicate.path, ("rb",)),
    ]
    assert len(recording.descriptors) == 2
    assert len(fstats) == 3
    assert fstats[-2:] == [recording.descriptors[1]] * 2
    assert not duplicate.path.exists()
    assert target.read_bytes() == b"settled"


def test_read_confined_reads_through_the_identity_checked_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bounded-read bridge of the phase-1 ``SCHEMA`` step: one ``rb`` open of
    the confined candidate, the ``fstat`` identity of that handle compared with
    the confined identity before and after at most ``limit`` bytes are read from
    it in one read, and no path reopened. A swap between confinement and the read
    is ``ARTIFACT.VALIDATION_FAILED`` before a byte is read, a refused open the
    storage posture ``ARTIFACT.MOVE_FAILED``; the arguments are checked."""
    store = _open(tmp_path)
    data = b"read me through the handle"
    staged = _staged(store, data)
    fstats: list[int] = []
    original_fstat = os.fstat

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    opens: list[tuple[Path, tuple[Any, ...]]] = []
    reads: list[tuple[int, int]] = []  # (fstats so far, size asked for)
    descriptors: list[int] = []
    original_open = Path.open

    class _ReadSpy:
        def __init__(self, inner: BinaryIO) -> None:
            self._inner = inner
            descriptors.append(inner.fileno())

        def __enter__(self) -> _ReadSpy:
            return self

        def __exit__(self, *exc: object) -> None:
            self._inner.close()

        def read(self, size: int = -1) -> bytes:
            reads.append((len(fstats), size))
            return self._inner.read(size)

        def fileno(self) -> int:
            return self._inner.fileno()

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        handle = original_open(self, *args, **kwargs)
        if self == staged.path and args == ("rb",):
            return _ReadSpy(handle)
        return handle

    monkeypatch.setattr(os, "fstat", spying_fstat)
    monkeypatch.setattr(Path, "open", spying_open)
    read = read_confined(staged, limit=len(data), now_utc=_NOW)
    assert isinstance(read, Success), read
    assert read.value == data
    assert opens == [(staged.path, ("rb",))]
    assert descriptors == [fstats[0]]
    assert fstats == [descriptors[0]] * 2
    assert reads == [(1, len(data))]  # one fstat before the read, so one after
    # Bounded: at most ``limit`` bytes in one read; nothing beyond is asked for.
    bounded = read_confined(staged, limit=7, now_utc=_NOW)
    assert isinstance(bounded, Success), bounded
    assert bounded.value == data[:7]
    assert reads[-1] == (3, 7)
    empty = read_confined(staged, limit=0, now_utc=_NOW)
    assert isinstance(empty, Success), empty
    assert empty.value == b""
    assert len(reads) == 3
    assert staged.path.read_bytes() == data

    # A swap between confinement and the read: refused before any byte is read.
    swapped = _staged(store, b"before", relative=f"INVOCATION/{INVOCATION_ID}/s.txt")
    swapped.path.unlink()
    swapped.path.write_bytes(b"after the swap, another size")
    reads.clear()
    refused = read_confined(swapped, limit=64, now_utc=_NOW)
    assert _codes(refused) == (ARTIFACT_VALIDATION_FAILED,)
    assert "changed while finalizing" in _failure(refused).diagnostics[0].message
    assert reads == []

    # Storage refusal: a refused open is the reading 26 posture, path unnamed.
    def refuse_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == staged.path:
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_open)
        unopenable = read_confined(staged, limit=len(data), now_utc=_NOW)
    assert _codes(unopenable) == (ARTIFACT_MOVE_FAILED,)
    diagnostic = _failure(unopenable).diagnostics[0]
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.retriable is False
    assert str(tmp_path) not in diagnostic.message
    assert staged.path.read_bytes() == data

    with pytest.raises(TypeError, match="ConfinedPath"):
        read_confined(staged.path, limit=1, now_utc=_NOW)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="built-in integer"):
        read_confined(staged, limit=1.0, now_utc=_NOW)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="built-in integer"):
        read_confined(staged, limit=True, now_utc=_NOW)
    with pytest.raises(ValueError, match="negative"):
        read_confined(staged, limit=-1, now_utc=_NOW)


def test_replay_refuses_a_reparse_point_leaf_before_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing staged leaf that is a reparse point is confined -- and refused
    -- before a byte of it is read: no ``rb`` open of the leaf, nothing streamed
    through the hasher, the bytes beyond the reparse point untouched. A symbolic
    link at the leaf when the principal may create one; otherwise a junction
    planted at the leaf path itself, whose exclusive create is made to report the
    collision a file reparse point reports (a directory junction's own ``xb``
    refusal is a storage failure, likewise unread -- the control first)."""
    recording = _RecordingHasher()
    store = _open(tmp_path, hasher=recording)
    owner_root = store.staging_root / _OWNER_HASH
    leaf = owner_root.joinpath(*_RELATIVE.split("/"))
    leaf.parent.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    outside = elsewhere / "outside.txt"
    outside.write_bytes(b"bytes beyond the reparse point")
    payload = b"stderr\n"
    opens: list[tuple[Path, tuple[Any, ...]]] = []
    original_open = Path.open

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        return original_open(self, *args, **kwargs)

    def colliding_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        if self == leaf and args == ("xb",):
            raise FileExistsError(17, "File exists")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spying_open)
    try:
        os.symlink(outside, leaf)
    except OSError:
        _winapi.CreateJunction(str(elsewhere), str(leaf))
        try:
            control = store.write_staged(_OWNER_HASH, _RELATIVE, payload, now_utc=_NOW)
            assert _codes(control) == (ARTIFACT_MOVE_FAILED,)
            assert "written" in _failure(control).diagnostics[0].message
            with monkeypatch.context() as patched:
                patched.setattr(Path, "open", colliding_open)
                refused = store.write_staged(
                    _OWNER_HASH, _RELATIVE, payload, now_utc=_NOW
                )
        finally:
            os.rmdir(leaf)
    else:
        try:
            refused = store.write_staged(_OWNER_HASH, _RELATIVE, payload, now_utc=_NOW)
        finally:
            leaf.unlink()
    assert _codes(refused) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert "reparse" in _failure(refused).diagnostics[0].message
    assert [args for path, args in opens if path == leaf and args == ("rb",)] == []
    assert recording.descriptors == []
    assert outside.read_bytes() == b"bytes beyond the reparse point"
    # Positive control: with the reparse point gone the same path is written.
    written = store.write_staged(_OWNER_HASH, _RELATIVE, payload, now_utc=_NOW)
    assert isinstance(written, Success)
    assert leaf.read_bytes() == payload


def test_replay_refuses_a_hard_linked_leaf_before_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing staged leaf with a second hard link is confined -- and refused
    -- before a byte of it is read, for an equal and for a differing payload
    alike; once the alias is gone the replay confines the leaf and streams it
    through the identity-checked handle (``fstat`` before and after, on the one
    descriptor the hasher read)."""
    recording = _RecordingHasher()
    store = _open(tmp_path, hasher=recording)
    data = b"stderr line\n"
    confined = _staged(store, data)
    alias = tmp_path / "alias.txt"
    os.link(confined.path, alias)
    opens: list[tuple[Path, tuple[Any, ...]]] = []
    fstats: list[int] = []
    original_open = Path.open
    original_fstat = os.fstat

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        return original_open(self, *args, **kwargs)

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    monkeypatch.setattr(Path, "open", spying_open)
    monkeypatch.setattr(os, "fstat", spying_fstat)
    try:
        assert confined.path.lstat().st_nlink == 2
        equal = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
        differing = store.write_staged(_OWNER_HASH, _RELATIVE, b"other", now_utc=_NOW)
    finally:
        alias.unlink()
    for refused in (equal, differing):
        assert _codes(refused) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
        assert "hard link" in _failure(refused).diagnostics[0].message
    assert [path for path, args in opens if args == ("rb",)] == []
    assert recording.descriptors == []
    assert fstats == []
    assert confined.path.read_bytes() == data
    # Positive control: the plain leaf replays through the identity-checked handle.
    replayed = store.write_staged(_OWNER_HASH, _RELATIVE, data, now_utc=_NOW)
    assert isinstance(replayed, Success)
    assert replayed.value == confined
    assert [path for path, args in opens if args == ("rb",)] == [confined.path]
    assert len(recording.descriptors) == 1
    assert fstats == [recording.descriptors[0]] * 2
    assert confined.path.read_bytes() == data


# --- Plan 2.6: the ``os`` root, confined to this module and two attributes ------------


def test_os_usage_is_fstat_and_fsync_only() -> None:
    """Plan 2.6 (import-root table): ``import os`` once, never aliased or
    ``from``-imported, and every ``os.<attr>`` read is ``fstat`` or ``fsync``."""
    tree = _parse_store()
    imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        and any(alias.name.partition(".")[0] == "os" for alias in node.names)
    ]
    assert len(imports) == 1
    assert [(alias.name, alias.asname) for alias in imports[0].names] == [("os", None)]
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.partition(".")[0] == "os"
        for node in ast.walk(tree)
    )
    attributes = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    assert attributes == {"fstat", "fsync"}
    rebound = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "os"
        and isinstance(node.ctx, ast.Store)
    ]
    assert rebound == []
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "os"
        for node in ast.walk(tree)
    )


def test_os_is_imported_only_by_the_artifact_store() -> None:
    """Plan 2.6: a tree-wide AST walk over ``src/crypto_lab``; exactly one importer."""
    importers: list[str] = []
    for path in sorted(_SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        roots = {
            alias.name.partition(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.partition(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        if "os" in roots:
            importers.append(path.relative_to(_SOURCE).as_posix())
    assert importers == ["artifacts/store.py"]


def test_the_guard_literals_moved_to_the_task_four_sizes() -> None:
    """Plan 2.6 for Task 4 on the Task-3-excluded branch: paths 121 -> 125, roots
    29 -> 30 with ``os``, deferred names 19 -> 18 without ``ContentHasher``.

    Task 5 (the same branch table, "Tasks 4-7 running sizes" 125, 129, 132, 135)
    moved the two census sizes 125 -> 129 with its four persistence modules; the
    roots, the deferred names and the Task 4 module slice are Task-5-independent
    and stay pinned exactly.
    """
    allowed = _literal(_STAGE3_GUARD, "_ALLOWED_SOURCE_FILES")
    assert {
        "artifacts/paths.py",
        "artifacts/hashing.py",
        "artifacts/validation.py",
        "artifacts/store.py",
    } <= allowed
    assert len(allowed) == 129
    roots = _literal(_STAGE3_GUARD, "_ALLOWED_IMPORT_ROOTS")
    assert "os" in roots
    assert len(roots) == 30
    deferred = _literal(_STAGE3_GUARD, "_DEFERRED_DEFINITIONS")
    assert "ContentHasher" not in deferred
    assert len(deferred) == 18
    modules = _literal(_PACKAGE_LAYOUT, "PACKAGE_MODULES")
    anchor = modules.index("crypto_lab.artifacts.diagnostics") + 1
    assert tuple(modules[anchor : anchor + 4]) == (
        "crypto_lab.artifacts.paths",
        "crypto_lab.artifacts.hashing",
        "crypto_lab.artifacts.validation",
        "crypto_lab.artifacts.store",
    )
    assert len(modules) == 129
