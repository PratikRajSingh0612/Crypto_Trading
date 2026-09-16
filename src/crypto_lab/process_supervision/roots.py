"""Command roots, path preflight, exclusive creates and bounded output reads.

Stage 7 plan section 7 (and 4.1 row 1, 4.4), under specification sections 14.1, 15.1,
15.5 and 22.5. ``plan_command_paths`` is the one layout authority: the command root
is ``<supervision_root>\\<invocation_id>`` for every kind and the work directory is
``<command_root>\\runs\\<run_id>\\work`` (plan 2.5 reading 11), rendered as pure
Windows path text. ``probe_long_path_support`` fixes the directory and file ceilings
of one supervisor instance with a single create-and-remove probe (reading 20) and
``preflight_command_paths`` refuses a command path before anything is written; both
mint ``PROCESS.PATH_PREFLIGHT_REJECTED`` as a ``Failure`` with the instant and ids
their caller passes and never a path in the message. ``create_command_root`` and
``write_request_file`` are exclusive creates; ``snapshot_written_paths`` is the
write-boundary walk; ``read_output_file`` reads at most ceiling + 1 bytes and returns
the plan 7.4 ``OutputReadFailure`` for a file that exists but cannot be read;
``remove_command_root`` never raises and never descends through a reparse point;
``observe_executable`` is the pre-swap observation of the registered executable.

Nothing here reads a clock, the environment or an ambient path (no ``Path.cwd``,
``Path.home`` or ``expanduser``); every file is opened under a caller-supplied path,
every walk is depth-bounded, and a reparse point is never followed. Task-local
readings, declared rather than inferred silently:

- ``CommandPaths`` carries no kind: the kind-governed presence rule of
  ``AdapterCommand`` is applied as its two shapes (an output file exactly when there
  is no work directory, and the work directory and result path together).
- ``run_id`` is required exactly for ``VALIDATE`` and ``RUN`` and refused for
  ``DESCRIBE``; the root and both ids are validated through the merged grammars, so
  every rendered path is lexically under the root.
- A supervision root that is itself a reparse point shares the reason word
  ``ancestor_reparse_point``; any ``OSError`` from the probe's long directory reads as
  "unsupported" (the conservative ceilings).
- ``create_command_root`` and ``write_request_file`` fail by ``OSError``
  (``FileExistsError`` for an existing root or request file); a reparse point found in
  the chain after creation raises a plain ``OSError`` with no error number.
- ``snapshot_written_paths`` records files and reparse-point entries, not bare
  directories, and records a directory at the depth bound as one entry.
- ``read_output_file`` refuses a reparse point with ``error_class="ReparsePoint"`` and
  no error number, because no operating-system call failed; for a failed open or
  read, ``os_error_code`` is the exception's own Win32 number when it carries one
  (``winerror``) and otherwise its ``errno`` (the interpreter's ``open`` reports the
  CRT errno for a sharing violation), never a number derived from text.
- ``observe_executable`` raises the ``OSError`` of a regular file whose bytes cannot be
  read: the observation record cannot state that case and this module may not
  change it.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Final, Self

from pydantic import TypeAdapter, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AbsoluteLocalExecutablePath, AdapterCatalogEntry
from crypto_lab.adapters.limits import RESULT_MANIFEST_RELATIVE_PATH
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.identifiers import ExperimentId, InvocationId, RunId
from crypto_lab.domain.lifecycle import CommandKind
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_PATH_PREFLIGHT_REJECTED,
    stage7_failure,
)
from crypto_lab.process_supervision.models import (
    COMMAND_ROOT_CEILING,
    DIRECTORY_CEILING_WITHOUT_LONG_PATHS,
    FILE_CEILING_WITHOUT_LONG_PATHS,
    LONG_PATH_CEILING,
    READ_CHUNK_BYTES,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    ExecutableObservation,
    OutputReadFailure,
)

__all__ = [
    "CommandPaths",
    "PathPreflight",
    "create_command_root",
    "observe_executable",
    "plan_command_paths",
    "preflight_command_paths",
    "probe_long_path_support",
    "read_output_file",
    "remove_command_root",
    "snapshot_written_paths",
    "write_request_file",
]

#: Plan 7.1: the fixed file and directory names of the layout.
_REQUEST_FILE_NAME: Final = "request.json"
_OUTPUT_FILE_NAME: Final = "output.json"
_RUNS_SEGMENT: Final = "runs"
_WORK_SEGMENT: Final = "work"
#: Plan 7.2: the probe directory under the supervision root.
_PROBE_SEGMENT: Final = ".probe"
#: Plan 3.5: the roots module mints on behalf of the supervisor.
_SOURCE_COMPONENT: Final = "process_supervision.supervisor"
#: Win32 file attributes and ``st_mode`` masks, spelled locally (plan 2.6: no ``stat``).
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400
_S_IFMT: Final = 0o170000
_S_IFREG: Final = 0o100000
#: The bound of every depth-first walk in this module.
_MAX_WALK_DEPTH: Final = 64
#: Plan 7.5: the closed reason words of a removal failure, keyed on ``winerror``.
_ERROR_SHARING_VIOLATION: Final = 32
_ERROR_ACCESS_DENIED: Final = 5
_ERROR_DIR_NOT_EMPTY: Final = 145
_CLEANUP_REASON_WORDS: Final[dict[int, str]] = {
    _ERROR_SHARING_VIOLATION: "sharing_violation",
    _ERROR_ACCESS_DENIED: "access_denied",
    _ERROR_DIR_NOT_EMPTY: "directory_not_empty",
}
_REPARSE_POINT_ERROR_CLASS: Final = "ReparsePoint"

_PATH_ADAPTER: TypeAdapter[str] = TypeAdapter(AbsoluteLocalExecutablePath)
_INVOCATION_ADAPTER: TypeAdapter[str] = TypeAdapter(InvocationId)
_RUN_ADAPTER: TypeAdapter[str] = TypeAdapter(RunId)


# --- Records (plan 3.3) ---------------------------------------------------------------


def _lexically_under(candidate: str, root: PureWindowsPath) -> bool:
    return root in PureWindowsPath(candidate).parents


class CommandPaths(CanonicalModel):
    """The core-selected absolute paths of one command (K; plan 3.3, 7.1).

    Every path is lexically under ``command_root``; ``result_path`` is the work
    directory joined with ``RESULT_MANIFEST_RELATIVE_PATH``; the two shapes are the
    kind-governed shapes of ``AdapterCommand``.
    """

    command_root: AbsoluteLocalExecutablePath
    request_path: AbsoluteLocalExecutablePath
    output_path: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
    work_dir: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
    result_path: AbsoluteLocalExecutablePath | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_shape_and_containment(self) -> Self:
        work_present = isinstance(self.work_dir, str)
        if work_present is not isinstance(self.result_path, str):
            raise ValueError("work_dir and result_path are present together or absent")
        if isinstance(self.output_path, str) is work_present:
            raise ValueError("output_path is present exactly when work_dir is absent")
        root = PureWindowsPath(self.command_root)
        for label, value in (
            ("request_path", self.request_path),
            ("output_path", self.output_path),
            ("work_dir", self.work_dir),
            ("result_path", self.result_path),
        ):
            if isinstance(value, str) and not _lexically_under(value, root):
                raise ValueError(f"{label} must be lexically under command_root")
        if isinstance(self.work_dir, str) and isinstance(self.result_path, str):
            expected = PureWindowsPath(self.work_dir) / RESULT_MANIFEST_RELATIVE_PATH
            if PureWindowsPath(self.result_path) != expected:
                raise ValueError(
                    "result_path must be work_dir joined with "
                    "RESULT_MANIFEST_RELATIVE_PATH"
                )
        return self

    @property
    def directories(self) -> tuple[str, ...]:
        """The command root and, for a ``RUN``, the work directory (the ceilings)."""
        if isinstance(self.work_dir, str):
            return (self.command_root, self.work_dir)
        return (self.command_root,)

    @property
    def files(self) -> tuple[str, ...]:
        """The request file and the output or result file (the file ceiling)."""
        if isinstance(self.result_path, str):
            return (self.request_path, self.result_path)
        if isinstance(self.output_path, str):
            return (self.request_path, self.output_path)
        return (self.request_path,)  # pragma: no cover - excluded by the validator


class PathPreflight(CanonicalModel):
    """The ceilings one supervisor instance applies (K; plan 3.3, 7.2).

    Exactly the pair keyed on ``long_paths_supported``: 247/259 without long-path
    support, ``MAX_EXECUTABLE_PATH_CHARACTERS`` (1024) for both with it.
    """

    supervision_root: AbsoluteLocalExecutablePath
    long_paths_supported: bool
    directory_ceiling: int
    file_ceiling: int
    probed_at_utc: CalendarValidUtcDateTime

    @model_validator(mode="after")
    def validate_ceilings(self) -> Self:
        expected = (
            (LONG_PATH_CEILING, LONG_PATH_CEILING)
            if self.long_paths_supported
            else (DIRECTORY_CEILING_WITHOUT_LONG_PATHS, FILE_CEILING_WITHOUT_LONG_PATHS)
        )
        if (self.directory_ceiling, self.file_ceiling) != expected:
            raise ValueError(
                "directory_ceiling and file_ceiling must be exactly the pair keyed on "
                f"long_paths_supported ({expected[0]}, {expected[1]})"
            )
        return self


# --- The layout (plan 7.1) -----------------------------------------------------------


def plan_command_paths(
    supervision_root: str,
    *,
    command_kind: CommandKind,
    invocation_id: InvocationId,
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
) -> CommandPaths:
    """Plan 7.1: the harness layout the Stage 6 envelope and fake adapter fix.

    Pure over its arguments; ``run_id`` is required exactly for ``VALIDATE`` and
    ``RUN`` (a ``VALIDATE`` uses it in no path). The root and both ids pass the merged
    grammars, so every rendered path is lexically under the root.
    """
    if not isinstance(command_kind, CommandKind):
        raise TypeError("command_kind must be a CommandKind")
    root_text = _PATH_ADAPTER.validate_python(supervision_root)
    invocation = _INVOCATION_ADAPTER.validate_python(invocation_id)
    linked = command_kind is not CommandKind.DESCRIBE
    if linked and not isinstance(run_id, str):
        raise ValueError(f"run_id is required for {command_kind.value}")
    if not linked and isinstance(run_id, str):
        raise ValueError("run_id is prohibited for DESCRIBE")
    command_root = PureWindowsPath(root_text) / invocation
    request_path = command_root / _REQUEST_FILE_NAME
    if command_kind is CommandKind.RUN and isinstance(run_id, str):
        run = _RUN_ADAPTER.validate_python(run_id)
        work_dir = command_root / _RUNS_SEGMENT / run / _WORK_SEGMENT
        return CommandPaths(
            command_root=str(command_root),
            request_path=str(request_path),
            work_dir=str(work_dir),
            result_path=str(work_dir / RESULT_MANIFEST_RELATIVE_PATH),
        )
    if isinstance(run_id, str):
        _RUN_ADAPTER.validate_python(run_id)
    return CommandPaths(
        command_root=str(command_root),
        request_path=str(request_path),
        output_path=str(command_root / _OUTPUT_FILE_NAME),
    )


# --- Filesystem primitives (reparse-point aware, never following one) ---------------


def _attributes(path: Path) -> int:
    """The Win32 file attributes of ``path`` itself; a reparse point is not followed."""
    return int(getattr(path.lstat(), "st_file_attributes", 0))


def _is_reparse_point(attributes: int) -> bool:
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_directory(attributes: int) -> bool:
    return bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)


def _reparse_point_on_or_above(path: Path) -> bool:
    """Whether ``path`` or any existing ancestor up to the drive is a reparse point."""
    for candidate in (path, *path.parents):
        try:
            attributes = _attributes(candidate)
        except OSError:
            continue
        if _is_reparse_point(attributes):
            return True
    return False


def _error_number(error: OSError) -> int | None:
    winerror = getattr(error, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    return error.errno if isinstance(error.errno, int) else None


# --- Preflight (plan 7.2) ------------------------------------------------------------


def probe_long_path_support(
    supervision_root: str, *, now: datetime
) -> Result[PathPreflight]:
    """Plan 7.2 and reading 20: probe long-path support under the supervision root.

    The root must be an absolute local path, an existing directory, and neither it
    nor any ancestor may be a reparse point; the probe then creates and removes one
    directory longer than 247 characters under ``<root>\\.probe`` and fixes the
    ceilings for the instance. A ``Failure`` carries
    ``PROCESS.PATH_PREFLIGHT_REJECTED`` with no invocation: this is the one minting
    site without one.
    """

    def refuse(reason: str, message: str) -> Failure:
        return stage7_failure(
            PROCESS_PATH_PREFLIGHT_REJECTED,
            message,
            source_component=_SOURCE_COMPONENT,
            timestamp_utc=now,
            details={"reason": reason, "path_length": len(supervision_root)},
        )

    try:
        root_text = _PATH_ADAPTER.validate_python(supervision_root)
    except ValueError:
        return refuse(
            "root_not_local", "the supervision root is not an absolute local path"
        )
    root = Path(root_text)
    try:
        attributes = _attributes(root)
    except (FileNotFoundError, NotADirectoryError):
        return refuse("root_missing", "the supervision root does not exist")
    except OSError:
        return refuse(
            "root_not_directory",
            "the supervision root cannot be established as a directory",
        )
    if _reparse_point_on_or_above(root):
        return refuse(
            "ancestor_reparse_point",
            "the supervision root or one of its ancestors is a reparse point",
        )
    if not _is_directory(attributes):
        return refuse("root_not_directory", "the supervision root is not a directory")
    supported = _probe_long_directory(root)
    directory_ceiling, file_ceiling = (
        (LONG_PATH_CEILING, LONG_PATH_CEILING)
        if supported
        else (DIRECTORY_CEILING_WITHOUT_LONG_PATHS, FILE_CEILING_WITHOUT_LONG_PATHS)
    )
    return Success[PathPreflight](
        outcome="SUCCESS",
        value=PathPreflight(
            supervision_root=root_text,
            long_paths_supported=supported,
            directory_ceiling=directory_ceiling,
            file_ceiling=file_ceiling,
            probed_at_utc=now,
        ),
    )


def _probe_long_directory(root: Path) -> bool:
    """Create and remove one directory whose absolute length exceeds 247 characters."""
    probe_parent = root / _PROBE_SEGMENT
    prefix_length = len(str(probe_parent)) + 1
    probe = probe_parent / ("p" * max(1, COMMAND_ROOT_CEILING + 1 - prefix_length))
    try:
        probe.mkdir(parents=True, exist_ok=False)
    except OSError:
        supported = False
    else:
        supported = True
    finally:
        with suppress(OSError):
            probe.rmdir()
        with suppress(OSError):
            probe_parent.rmdir()
    return supported


def preflight_command_paths(
    paths: CommandPaths,
    preflight: PathPreflight,
    *,
    now: datetime,
    invocation_id: InvocationId | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
    experiment_id: ExperimentId | MISSING = MISSING,  # type: ignore[valid-type]
) -> Result[None]:
    """Plan 7.2 and 4.4: refuse a command path before anything is written.

    In order: a command root longer than ``COMMAND_ROOT_CEILING`` (247, always: it is
    the child's working directory), a work directory longer than the directory
    ceiling, a request, output or result path longer than the file ceiling, then any
    existing component of a command path that is a reparse point. The rejection
    carries the caller's instant and correlation ids and never a path.
    """
    if not isinstance(paths, CommandPaths):
        raise TypeError("paths must be a CommandPaths")
    if not isinstance(preflight, PathPreflight):
        raise TypeError("preflight must be a PathPreflight")

    def refuse(reason: str, message: str, path_length: int, ceiling: int) -> Failure:
        return stage7_failure(
            PROCESS_PATH_PREFLIGHT_REJECTED,
            message,
            source_component=_SOURCE_COMPONENT,
            timestamp_utc=now,
            experiment_id=experiment_id,
            run_id=run_id,
            invocation_id=invocation_id,
            details={
                "reason": reason,
                "path_length": path_length,
                "ceiling": ceiling,
                "long_path_support": preflight.long_paths_supported,
            },
        )

    bounded: list[tuple[str, str, int]] = [
        ("command root", paths.command_root, COMMAND_ROOT_CEILING)
    ]
    if isinstance(paths.work_dir, str):
        bounded.append(("work directory", paths.work_dir, preflight.directory_ceiling))
    bounded.append(("request path", paths.request_path, preflight.file_ceiling))
    if isinstance(paths.output_path, str):
        bounded.append(("output path", paths.output_path, preflight.file_ceiling))
    if isinstance(paths.result_path, str):
        bounded.append(("result path", paths.result_path, preflight.file_ceiling))
    for label, path_text, ceiling in bounded:
        if len(path_text) > ceiling:
            return refuse(
                "ceiling_exceeded",
                f"the {label} exceeds its path ceiling",
                len(path_text),
                ceiling,
            )
    for label, path_text, ceiling in bounded:
        if _reparse_point_on_or_above(Path(path_text)):
            return refuse(
                "ancestor_reparse_point",
                f"an existing component of the {label} is a reparse point",
                len(path_text),
                ceiling,
            )
    return Success[None](outcome="SUCCESS", value=None)


# --- Creation and the write boundary (plan 7.3) -------------------------------------


def create_command_root(paths: CommandPaths) -> None:
    """Plan 7.3: create the command root (and the work directory) exclusively.

    ``parents=True, exist_ok=False``: an existing root raises ``FileExistsError``
    (the supervisor's ``CORE.INVARIANT_VIOLATION``); any other ``OSError`` propagates
    (the supervisor's ``PROCESS.LAUNCH_FAILED`` at stage ``create_root``). After the
    creation the chain up to the drive is walked once, and a reparse point found on
    it raises a plain ``OSError``.
    """
    if not isinstance(paths, CommandPaths):
        raise TypeError("paths must be a CommandPaths")
    Path(paths.command_root).mkdir(parents=True, exist_ok=False)
    deepest = Path(paths.command_root)
    if isinstance(paths.work_dir, str):
        deepest = Path(paths.work_dir)
        deepest.mkdir(parents=True, exist_ok=False)
    if _reparse_point_on_or_above(deepest):
        raise OSError("a component of the command root chain is a reparse point")


def write_request_file(request_path: str, data: bytes) -> None:
    """Plan 7.3: write the request envelope bytes with an exclusive create (``xb``)."""
    if type(data) is not bytes:
        raise TypeError("the request file takes bytes")
    target = Path(_PATH_ADAPTER.validate_python(request_path))
    with target.open("xb") as handle:
        handle.write(data)


def snapshot_written_paths(command_root: str) -> frozenset[str]:
    """Plan 7.3: every file under the root as a relative POSIX path.

    An ``lstat`` walk: a reparse-point entry is recorded as a single path and never
    entered, a bare directory is not a write, and a directory at the depth bound is
    recorded as one entry. A missing root is the empty set, and so is a root that has
    itself become a reparse point, which is never entered either.
    """
    root = Path(command_root)
    try:
        root_attributes = _attributes(root)
    except (FileNotFoundError, NotADirectoryError):
        return frozenset()
    if _is_reparse_point(root_attributes):
        return frozenset()  # a root turned into a reparse point is never entered
    recorded: set[str] = set()
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        for child in directory.iterdir():
            try:
                attributes = _attributes(child)
            except FileNotFoundError:
                continue
            relative = child.relative_to(root).as_posix()
            if _is_reparse_point(attributes):
                recorded.add(relative)
            elif _is_directory(attributes):
                if depth + 1 >= _MAX_WALK_DEPTH:
                    recorded.add(relative)
                else:
                    pending.append((child, depth + 1))
            else:
                recorded.add(relative)
    return frozenset(recorded)


# --- Reading the output file (plan 7.4) -----------------------------------------------


def _output_read_failure(error: OSError) -> OutputReadFailure:
    number = _error_number(error)
    if number is None:
        return OutputReadFailure(error_class=type(error).__name__)
    return OutputReadFailure(os_error_code=number, error_class=type(error).__name__)


def read_output_file(path: str, *, ceiling: int) -> bytes | OutputReadFailure | MISSING:  # type: ignore[valid-type]
    """Plan 7.4: read at most ``ceiling + 1`` bytes of the declared output file.

    ``lstat`` first: an absent file is ``MISSING``; a reparse point is refused as an
    ``OutputReadFailure``; a file that exists but cannot be opened or read (a sharing
    violation, access denied, a directory) is an ``OutputReadFailure`` carrying the
    error number and class name only. The extra byte is what lets the caller's parser
    reject an oversized file by length without the file being read whole.
    """
    if type(ceiling) is not int:
        raise TypeError("ceiling must be a built-in integer")
    if ceiling < 1:
        raise ValueError("ceiling must be positive")
    target = Path(path)
    try:
        attributes = _attributes(target)
    except (FileNotFoundError, NotADirectoryError):
        return MISSING
    except OSError as error:
        return _output_read_failure(error)
    if _is_reparse_point(attributes):
        return OutputReadFailure(error_class=_REPARSE_POINT_ERROR_CLASS)
    remaining = ceiling + 1
    chunks: list[bytes] = []
    try:
        with target.open("rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(remaining, READ_CHUNK_BYTES))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
    except FileNotFoundError:
        return MISSING
    except OSError as error:
        return _output_read_failure(error)
    return b"".join(chunks)


# --- Removal (plan 7.5) -------------------------------------------------------------


def _cleanup_failure(error: OSError) -> CleanupFailure:
    number = _error_number(error)
    word = _CLEANUP_REASON_WORDS.get(number if number is not None else -1, "os_error")
    return CleanupFailure(
        action=CleanupAction.COMMAND_ROOT_REMOVED,
        reason=f"{word}:{0 if number is None else number}",
    )


def _remove_entry(path: Path, attributes: int) -> None:
    if _is_directory(attributes):
        path.rmdir()
    else:
        path.unlink()


def _remove_tree(root: Path) -> CleanupFailure | None:
    """Iterative post-order removal; ``None`` on success, else the first failure."""
    pending: list[tuple[Path, int, bool]] = [(root, 0, False)]
    while pending:
        path, depth, expanded = pending.pop()
        try:
            attributes = _attributes(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as error:
            return _cleanup_failure(error)
        try:
            if _is_reparse_point(attributes) or not _is_directory(attributes):
                _remove_entry(path, attributes)
            elif expanded:
                path.rmdir()
            elif depth >= _MAX_WALK_DEPTH:
                return CleanupFailure(
                    action=CleanupAction.COMMAND_ROOT_REMOVED, reason="depth_exceeded:0"
                )
            else:
                pending.append((path, depth, True))
                pending.extend((child, depth + 1, False) for child in path.iterdir())
        except FileNotFoundError:
            continue
        except OSError as error:
            return _cleanup_failure(error)
    return None


def remove_command_root(command_root: str) -> CleanupReport:
    """Plan 7.5: bounded depth-first removal that never raises and is idempotent.

    Files go before their directory; a reparse-point entry is removed as an entry and
    never entered; a missing root or entry is success; the first ``OSError`` is one
    ``CleanupFailure(COMMAND_ROOT_REMOVED, "<reason>:<winerror>")`` such as
    ``sharing_violation:32``.
    """
    failure = _remove_tree(Path(command_root))
    if failure is None:
        return CleanupReport(
            completed=(CleanupAction.COMMAND_ROOT_REMOVED,), failures=()
        )
    return CleanupReport(completed=(), failures=(failure,))


# --- The executable observation (plan 4.1 row 1, reading 3) -------------------------


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def observe_executable(
    entry: AdapterCatalogEntry, *, now: datetime
) -> ExecutableObservation:
    """Plan 4.1 row 1: observe the registered executable before the swap.

    ``lstat`` of the path itself (never following a reparse point) and the ancestor
    walk of plan 7.2; the SHA-256 is streamed only when the file is a present regular
    file with no reparse point on it or any ancestor, and ``verified`` is whether it
    equals the catalog hash.
    """
    if not isinstance(entry, AdapterCatalogEntry):
        raise TypeError("entry must be an AdapterCatalogEntry")
    path = Path(entry.executable_path)
    try:
        result = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        present = regular_file = reparse_point = False
    else:
        present = True
        reparse_point = _is_reparse_point(int(getattr(result, "st_file_attributes", 0)))
        regular_file = (result.st_mode & _S_IFMT) == _S_IFREG and not reparse_point
    ancestor_reparse_point = _reparse_point_on_or_above(path.parent)
    facts: dict[str, object] = {
        "executable_path": entry.executable_path,
        "expected_hash": entry.executable_hash,
        "present": present,
        "regular_file": regular_file,
        "reparse_point": reparse_point,
        "ancestor_reparse_point": ancestor_reparse_point,
        "observed_at_utc": now,
    }
    if present and regular_file and not ancestor_reparse_point:
        facts["observed_hash"] = _sha256_of_file(path)
    return ExecutableObservation.model_validate(facts)
