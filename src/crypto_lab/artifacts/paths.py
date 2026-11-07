"""Physical path confinement for staged candidate artifacts.

Stage 9 plan 6.3 under specification 15.5, 19.3:1417 and 24.3:1772 (readings 18
and 19). ``confine_candidate_path`` applies the lexical grammar first -- the
``adapters/paths.py`` rules as restated by ``artifacts/models.py``, plus the
explicit alternate-data-stream rule -- and only then walks the chain from the
root to the leaf with ``lstat``, so a hostile string is refused before the
filesystem is consulted and nothing is ever opened here. Every ancestor from the
root down must exist and be a directory whose attributes carry no reparse bit
(junction, symbolic link and mount point alike); the leaf must exist, be a
regular file, carry no reparse bit and have exactly one hard link; the strict
resolution of the leaf must lie inside the strict resolution of the root, compared
case-folded as Windows does, separator-aware and with the extended-length prefix
stripped. The returned ``ConfinedPath`` carries the ``lstat`` identity
``(st_dev, st_ino, st_size, st_mtime_ns)``; ``recheck_confined_path`` repeats the
same confinement and compares that identity, reporting a change as
``ARTIFACT.VALIDATION_FAILED``.

``artifacts`` imports ``domain`` and itself only (plan 2.6), so the Win32
attribute and ``st_mode`` masks are spelled locally rather than imported from
``stat`` or ``process_supervision/roots.py``; the root must be an absolute,
drive-lettered local path, so a UNC root never reaches a filesystem call. The
refusal messages never carry a path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Final, Protocol

from pydantic import InstanceOf

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
    artifact_failure,
)
from crypto_lab.artifacts.models import validate_relative_staging_path
from crypto_lab.domain.results import Failure, Result, Success

#: Win32 file attributes and ``st_mode`` masks, spelled locally (plan 2.6: no
#: ``stat`` import; the attribute test mirrors ``roots.py`` without importing it).
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400
_S_IFMT: Final = 0o170000
_S_IFREG: Final = 0o100000
_EXTENDED_LENGTH_PREFIX: Final = "\\\\?\\"
#: Reading 18: the one message of an identity change, shared with the store.
CHANGED_WHILE_FINALIZING: Final = "candidate changed while finalizing"


class StatLike(Protocol):
    """The four identity members read from an ``lstat`` or ``fstat`` result."""

    @property
    def st_dev(self) -> int: ...

    @property
    def st_ino(self) -> int: ...

    @property
    def st_size(self) -> int: ...

    @property
    def st_mtime_ns(self) -> int: ...


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """The ``(st_dev, st_ino, st_size, st_mtime_ns)`` identity of one file."""

    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int


@dataclass(frozen=True, slots=True)
class ConfinedPath:
    """A candidate leaf proven inside its root, with the identity observed then."""

    root: Path
    relative: str
    path: Path
    identity: FileIdentity


def file_identity_of(observed: StatLike) -> FileIdentity:
    """Project a stat result onto the identity quadruple."""
    return FileIdentity(
        st_dev=int(observed.st_dev),
        st_ino=int(observed.st_ino),
        st_size=int(observed.st_size),
        st_mtime_ns=int(observed.st_mtime_ns),
    )


def lexical_candidate_path(relative: str) -> str:
    """The lexical half of 15.5: the restated grammar plus the explicit ADS rule.

    Purely textual. A ``:`` anywhere is refused first by name (alternate data
    stream or drive syntax); every other rule is the ``adapters/paths.py`` grammar
    as ``artifacts/models.py`` restates it, with its messages renamed to the
    candidate-path wording.
    """
    if type(relative) is not str:
        raise TypeError("candidate path must be a built-in string")
    if ":" in relative:
        raise ValueError("candidate path carries alternate data stream or drive syntax")
    try:
        return validate_relative_staging_path(relative)
    except ValueError as error:
        raise ValueError(
            str(error).replace("staging path", "candidate path")
        ) from error


def _comparable(path: Path) -> str:
    text = str(path)
    if text.startswith(_EXTENDED_LENGTH_PREFIX):
        text = text[len(_EXTENDED_LENGTH_PREFIX) :]
    return text.casefold()


def is_within_root(candidate: Path, root: Path) -> bool:
    """Whether ``candidate`` lies strictly below ``root``: a case-folded,
    separator-aware string prefix with the extended-length prefix stripped."""
    root_text = _comparable(root).rstrip("\\") + "\\"
    candidate_text = _comparable(candidate)
    return candidate_text.startswith(root_text) and len(candidate_text) > len(root_text)


def _attributes(observed: object) -> int:
    return int(getattr(observed, "st_file_attributes", 0))


def _is_reparse_point(observed: object) -> bool:
    return bool(_attributes(observed) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_directory(observed: object) -> bool:
    return bool(_attributes(observed) & _FILE_ATTRIBUTE_DIRECTORY)


def _root_refusal(root: Path) -> str | None:
    if not root.is_absolute():
        return "the confinement root must be absolute"
    drive = PureWindowsPath(root).drive
    if len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":":
        return "the confinement root must be a drive-lettered local path"
    return None


def confine_candidate_path(
    root: Path, relative: str, *, now_utc: datetime
) -> Result[ConfinedPath]:
    """Plan 6.3: confine ``relative`` under ``root`` lexically, then physically.

    Every refusal is ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` stamped with ``now_utc``
    and names its rule, never the path. Nothing is opened.
    """
    if not isinstance(root, Path):
        raise TypeError("root must be a Path")

    def refuse(message: str) -> Failure:
        return artifact_failure(
            ARTIFACT_PATH_BOUNDARY_VIOLATION, message=message, now_utc=now_utc
        )

    try:
        validated = lexical_candidate_path(relative)
    except ValueError as error:
        return refuse(f"candidate path refused: {error}")
    root_refusal = _root_refusal(root)
    if root_refusal is not None:
        return refuse(root_refusal)
    try:
        root_observed = root.lstat()
    except OSError:
        return refuse("the confinement root does not exist")
    if _is_reparse_point(root_observed):
        return refuse("the confinement root is a reparse point")
    if not _is_directory(root_observed):
        return refuse("the confinement root is not a directory")
    segments = validated.split("/")
    current = root
    for segment in segments[:-1]:
        current = current / segment
        try:
            ancestor = current.lstat()
        except OSError:
            return refuse("an ancestor of the candidate does not exist")
        if _is_reparse_point(ancestor):
            return refuse("an ancestor of the candidate is a reparse point")
        if not _is_directory(ancestor):
            return refuse("an ancestor of the candidate is not a directory")
    leaf = current / segments[-1]
    try:
        observed = leaf.lstat()
    except OSError:
        return refuse("the candidate does not exist under the root")
    if _is_reparse_point(observed):
        return refuse("the candidate is a reparse point")
    if (observed.st_mode & _S_IFMT) != _S_IFREG:
        return refuse("the candidate is not a regular file")
    if observed.st_nlink != 1:
        return refuse("the candidate has more than one hard link")
    try:
        resolved_leaf = leaf.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except OSError:
        return refuse("the candidate could not be resolved")
    if not is_within_root(resolved_leaf, resolved_root):
        return refuse("the candidate resolves outside the root")
    return Success[InstanceOf[ConfinedPath]](
        outcome="SUCCESS",
        value=ConfinedPath(
            root=root,
            relative=validated,
            path=leaf,
            identity=file_identity_of(observed),
        ),
    )


def recheck_confined_path(
    confined: ConfinedPath, *, now_utc: datetime
) -> Result[ConfinedPath]:
    """Reading 18: the same confinement again, then the identity compare; a
    changed identity is ``ARTIFACT.VALIDATION_FAILED``."""
    if not isinstance(confined, ConfinedPath):
        raise TypeError("confined must be a ConfinedPath")
    result = confine_candidate_path(confined.root, confined.relative, now_utc=now_utc)
    if isinstance(result, Failure):
        return result
    if result.value.identity != confined.identity:
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=CHANGED_WHILE_FINALIZING,
            now_utc=now_utc,
        )
    return result


__all__ = (
    "CHANGED_WHILE_FINALIZING",
    "ConfinedPath",
    "FileIdentity",
    "StatLike",
    "confine_candidate_path",
    "file_identity_of",
    "is_within_root",
    "lexical_candidate_path",
    "recheck_confined_path",
)
