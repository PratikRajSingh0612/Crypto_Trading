"""Stage 9 Task 4: physical path confinement (plan 6.3; specification 15.5, 19.3,
24.3:1772; readings 18 and 19).

``confine_candidate_path`` applies the lexical grammar first and only then
``lstat``-walks the chain from the root to the leaf, so a hostile path is refused
before anything is opened; the leaf must be a regular file with one link and no
reparse bit, and its strict resolution must lie inside the root's. The returned
``ConfinedPath`` carries the ``lstat`` identity the recheck compares.
"""

from __future__ import annotations

import _winapi
import builtins
import dataclasses
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crypto_lab.adapters.paths import validate_relative_candidate_path
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.paths import (
    ConfinedPath,
    FileIdentity,
    confine_candidate_path,
    is_within_root,
    lexical_candidate_path,
    recheck_confined_path,
)
from crypto_lab.domain.results import Failure, Success

_NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
_RELATIVE = "results/native.bin"


def _failure(result: object) -> Failure:
    assert isinstance(result, Failure)
    return result


def _codes(result: object) -> tuple[str, ...]:
    return tuple(diagnostic.error_code for diagnostic in _failure(result).diagnostics)


def _confined(result: object) -> ConfinedPath:
    assert isinstance(result, Success)
    value = result.value
    assert isinstance(value, ConfinedPath)
    return value


def _staged(tmp_path: Path, data: bytes = b"native") -> tuple[Path, Path]:
    root = tmp_path / "root"
    leaf = root / "results" / "native.bin"
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(data)
    return root, leaf


def _identity_of(path: Path) -> FileIdentity:
    observed = path.lstat()
    return FileIdentity(
        st_dev=observed.st_dev,
        st_ino=observed.st_ino,
        st_size=observed.st_size,
        st_mtime_ns=observed.st_mtime_ns,
    )


# --- Plan Task 4 Step 1 ---------------------------------------------------------------


def test_untrusted_path_confined_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Specification 15.5: containment is verified before the file is opened; the
    whole confinement opens nothing, and every hostile shape is refused first."""
    root, leaf = _staged(tmp_path)

    def refuse_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("confinement opened a file")

    monkeypatch.setattr(Path, "open", refuse_open)
    monkeypatch.setattr(builtins, "open", refuse_open)
    for relative in (
        "../escape.bin",
        "results/../../escape.bin",
        "results\\native.bin",
        "/results/native.bin",
        "results//native.bin",
        "",
        ".",
        "results/.",
        "results/missing.bin",
    ):
        result = confine_candidate_path(root, relative, now_utc=_NOW)
        assert _codes(result) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,), relative
        message = _failure(result).diagnostics[0].message
        assert str(root) not in message
        assert "native.bin" not in message
    confined = _confined(confine_candidate_path(root, _RELATIVE, now_utc=_NOW))
    assert confined.root == root
    assert confined.relative == _RELATIVE
    assert confined.path == leaf
    assert confined.identity == _identity_of(leaf)


@pytest.mark.parametrize(
    "relative",
    [
        "results/native.bin:stream",
        "results:zone/native.bin",
        "C:/results/native.bin",
        "C:results",
        "//server/share/native.bin",
        "\\\\server\\share\\native.bin",
        "\\\\?\\C:\\results\\native.bin",
    ],
)
def test_ads_and_drive_and_unc_rejected(tmp_path: Path, relative: str) -> None:
    root, _ = _staged(tmp_path)
    result = confine_candidate_path(root, relative, now_utc=_NOW)
    assert _codes(result) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    with pytest.raises(ValueError, match=r"candidate path|alternate data stream"):
        lexical_candidate_path(relative)
    with pytest.raises(ValueError, match="candidate path"):
        validate_relative_candidate_path(relative)


def test_the_ads_rule_fires_before_the_restated_grammar() -> None:
    with pytest.raises(ValueError, match="alternate data stream"):
        lexical_candidate_path("results/native.bin:stream")
    with pytest.raises(TypeError, match="built-in string"):
        lexical_candidate_path(b"results/native.bin")  # type: ignore[arg-type]
    assert lexical_candidate_path(_RELATIVE) == _RELATIVE


def test_reparse_ancestor_rejected(tmp_path: Path) -> None:
    root, _ = _staged(tmp_path)
    target = tmp_path / "elsewhere"
    (target / "deep").mkdir(parents=True)
    (target / "deep" / "native.bin").write_bytes(b"through the junction")
    _winapi.CreateJunction(str(target), str(root / "link"))
    try:
        through = confine_candidate_path(root, "link/deep/native.bin", now_utc=_NOW)
        assert _codes(through) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
        assert "reparse" in _failure(through).diagnostics[0].message
        # The root itself a junction: refused the same way.
        as_root = confine_candidate_path(root / "link", "deep/native.bin", now_utc=_NOW)
        assert _codes(as_root) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
        # Positive control beside the junction: the plain chain is confined.
        plain = confine_candidate_path(root, _RELATIVE, now_utc=_NOW)
        assert isinstance(plain, Success)
    finally:
        os.rmdir(root / "link")
    assert (target / "deep" / "native.bin").read_bytes() == b"through the junction"


def test_hard_link_rejected(tmp_path: Path) -> None:
    """Reading 19: ``st_nlink > 1`` on the leaf is a boundary violation."""
    root, leaf = _staged(tmp_path)
    alias = tmp_path / "alias.bin"
    os.link(leaf, alias)
    try:
        assert leaf.lstat().st_nlink == 2
        linked = confine_candidate_path(root, _RELATIVE, now_utc=_NOW)
        assert _codes(linked) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
        assert "link" in _failure(linked).diagnostics[0].message
    finally:
        alias.unlink()
    assert leaf.lstat().st_nlink == 1
    assert isinstance(confine_candidate_path(root, _RELATIVE, now_utc=_NOW), Success)


def test_identity_recheck_detects_swap(tmp_path: Path) -> None:
    """Reading 18: the recheck calls the same confinement and compares the
    ``lstat`` identity; a change is ``ARTIFACT.VALIDATION_FAILED``."""
    root, leaf = _staged(tmp_path)
    confined = _confined(confine_candidate_path(root, _RELATIVE, now_utc=_NOW))
    unchanged = recheck_confined_path(confined, now_utc=_NOW)
    assert isinstance(unchanged, Success)
    assert unchanged.value == confined
    leaf.unlink()
    leaf.write_bytes(b"swapped bytes of another size")
    swapped = recheck_confined_path(confined, now_utc=_NOW)
    assert _codes(swapped) == (ARTIFACT_VALIDATION_FAILED,)
    assert "changed while finalizing" in _failure(swapped).diagnostics[0].message
    leaf.unlink()
    missing = recheck_confined_path(confined, now_utc=_NOW)
    assert _codes(missing) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    with pytest.raises(TypeError, match="ConfinedPath"):
        recheck_confined_path(leaf, now_utc=_NOW)  # type: ignore[arg-type]


def test_resolve_prefix_is_separator_aware() -> None:
    """A sibling whose name extends the root's is outside it; the compare is
    case-folded as Windows is and strips the extended-length prefix."""
    root = Path(r"C:\lab\root")
    assert is_within_root(Path(r"C:\lab\root\objects\aa\blob"), root)
    assert is_within_root(Path(r"C:\LAB\ROOT\Objects\blob"), root)
    assert is_within_root(Path(r"\\?\C:\lab\root\blob"), root)
    assert is_within_root(Path(r"C:\lab\root\blob"), Path(r"\\?\C:\lab\root"))
    assert not is_within_root(Path(r"C:\lab\root2\blob"), root)
    assert not is_within_root(Path(r"C:\lab\rootling"), root)
    assert not is_within_root(root, root)
    assert not is_within_root(Path(r"C:\lab"), root)
    assert not is_within_root(Path(r"D:\lab\root\blob"), root)


# --- Further shape and contract cases -------------------------------------------------


def test_every_physical_refusal_arm_names_its_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The remaining physical arms of plan 6.3: a missing ancestor, an ancestor that
    is a file, a reparse point at the leaf position (a junction, which needs no
    privilege), a leaf that cannot be resolved and a leaf whose strict resolution
    lies outside the root's."""
    root, leaf = _staged(tmp_path)
    (root / "file.bin").write_bytes(b"a file where a directory belongs")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    missing = confine_candidate_path(root, "absent/native.bin", now_utc=_NOW)
    assert _codes(missing) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    message = _failure(missing).diagnostics[0].message
    assert message == "an ancestor of the candidate does not exist"

    through_file = confine_candidate_path(root, "file.bin/native.bin", now_utc=_NOW)
    assert _codes(through_file) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    message = _failure(through_file).diagnostics[0].message
    assert message == "an ancestor of the candidate is not a directory"

    _winapi.CreateJunction(str(elsewhere), str(root / "results" / "jx"))
    try:
        leaf_reparse = confine_candidate_path(root, "results/jx", now_utc=_NOW)
    finally:
        os.rmdir(root / "results" / "jx")
    assert _codes(leaf_reparse) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    message = _failure(leaf_reparse).diagnostics[0].message
    assert message == "the candidate is a reparse point"

    original_resolve = Path.resolve

    def unresolvable(self: Path, strict: bool = False) -> Path:
        raise OSError(1, "cannot resolve")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "resolve", unresolvable)
        unresolved = confine_candidate_path(root, _RELATIVE, now_utc=_NOW)
    assert _codes(unresolved) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    message = _failure(unresolved).diagnostics[0].message
    assert message == "the candidate could not be resolved"

    def resolve_elsewhere(self: Path, strict: bool = False) -> Path:
        if self == leaf:
            return elsewhere / "native.bin"
        return original_resolve(self, strict=strict)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "resolve", resolve_elsewhere)
        escaped = confine_candidate_path(root, _RELATIVE, now_utc=_NOW)
    assert _codes(escaped) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    message = _failure(escaped).diagnostics[0].message
    assert message == "the candidate resolves outside the root"
    for refusal in (missing, through_file, leaf_reparse, unresolved, escaped):
        assert str(tmp_path) not in _failure(refusal).diagnostics[0].message
    # Positive control once every fixture and patch is gone.
    assert isinstance(confine_candidate_path(root, _RELATIVE, now_utc=_NOW), Success)


def test_the_leaf_must_be_a_regular_file_under_an_existing_absolute_root(
    tmp_path: Path,
) -> None:
    root, leaf = _staged(tmp_path)
    (root / "results" / "folder").mkdir()
    directory = confine_candidate_path(root, "results/folder", now_utc=_NOW)
    assert _codes(directory) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert "regular file" in _failure(directory).diagnostics[0].message
    missing_root = confine_candidate_path(tmp_path / "absent", _RELATIVE, now_utc=_NOW)
    assert _codes(missing_root) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    relative_root = confine_candidate_path(Path("root"), _RELATIVE, now_utc=_NOW)
    assert _codes(relative_root) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    assert "absolute" in _failure(relative_root).diagnostics[0].message
    file_root = confine_candidate_path(leaf, "native.bin", now_utc=_NOW)
    assert _codes(file_root) == (ARTIFACT_PATH_BOUNDARY_VIOLATION,)
    with pytest.raises(TypeError, match="root must be a Path"):
        confine_candidate_path(str(root), _RELATIVE, now_utc=_NOW)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "relative",
    [
        "results/native.bin",
        "a",
        "a/b/c.d",
        "con/native.bin",
        "results/aux.bin",
        "results/com1",
        "results/native.",
        "results/.hidden",
        "résumé/native.bin",
        "results/native bin",
        "results/%41.bin",
        "a" * 255,
        "a" * 256,
        "/".join(["s"] * 32),
        "/".join(["s"] * 33),
    ],
)
def test_the_confinement_grammar_agrees_with_the_adapter_grammar(relative: str) -> None:
    """``artifacts`` may not import ``adapters``; the restated lexical half is
    pinned to accept exactly what ``validate_relative_candidate_path`` accepts."""
    ours = _accepts(lexical_candidate_path, relative)
    theirs = _accepts(validate_relative_candidate_path, relative)
    assert ours == theirs, relative


def _accepts(validator: object, value: str) -> bool:
    assert callable(validator)
    try:
        validator(value)
    except ValueError:
        return False
    return True


def test_file_identity_is_the_lstat_quadruple_and_frozen(tmp_path: Path) -> None:
    root, _ = _staged(tmp_path)
    confined = _confined(confine_candidate_path(root, _RELATIVE, now_utc=_NOW))
    assert [field.name for field in dataclasses.fields(FileIdentity)] == [
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
    ]
    assert [field.name for field in dataclasses.fields(ConfinedPath)] == [
        "root",
        "relative",
        "path",
        "identity",
    ]
    assert confined.identity.st_size == len(b"native")
    with pytest.raises(dataclasses.FrozenInstanceError):
        confined.identity.st_size = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        confined.relative = "other"  # type: ignore[misc]
