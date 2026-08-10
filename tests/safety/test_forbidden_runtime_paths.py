"""Keep generated runtime roots and secret filenames out of version control."""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

_FORBIDDEN_ROOT_DIRECTORIES = frozenset(
    {
        "runtime",
        "data",
        "artifacts",
        "logs",
        "runtimes",
        ".gitnexus",
        ".venv",
    }
)
_FORBIDDEN_FILE_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
)
_IGNORE_PROBES: tuple[str, ...] = (
    "runtime/.stage1-ignore-probe",
    "data/.stage1-ignore-probe",
    "artifacts/.stage1-ignore-probe",
    "logs/.stage1-ignore-probe",
    "runtimes/.stage1-ignore-probe",
    ".gitnexus/.stage1-ignore-probe",
    ".venv/.stage1-ignore-probe",
    ".env",
    ".env.local",
    "stage1.pem",
    "stage1.key",
    "stage1.p12",
    "stage1.pfx",
    "stage1.sqlite",
    "stage1.sqlite3",
    "stage1.db",
)
_MUST_REMAIN_VISIBLE_PROBES: tuple[str, ...] = (
    ".codex/config.toml",
    "docs/stage1-visible-probe.md",
    "schemas/stage1-visible-probe.json",
    "tests/stage1_visible_probe.py",
    "scripts/stage1-visible-probe.ps1",
    "uv.lock",
    ".python-version",
    "src/crypto_lab/artifacts/stage1_visible_probe.py",
)


def is_forbidden_runtime_path(relative_path: str) -> bool:
    """Return whether a repository-relative path is forbidden in source control."""
    normalized = PurePosixPath(relative_path.replace("\\", "/"))
    parts = normalized.parts
    if parts and parts[0].lower() in _FORBIDDEN_ROOT_DIRECTORIES:
        return True
    filename = normalized.name.lower()
    return any(
        fnmatch.fnmatchcase(filename, pattern) for pattern in _FORBIDDEN_FILE_PATTERNS
    )


def _run_git(
    repository_root: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    git_executable = shutil.which("git")
    assert git_executable is not None, (
        "Git is required by the repository verification workflow"
    )
    return subprocess.run(  # noqa: S603 - shutil.which returns the local Git path.
        [git_executable, *arguments],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("relative_path", _IGNORE_PROBES)
def test_classifier_covers_each_required_path(relative_path: str) -> None:
    assert is_forbidden_runtime_path(relative_path)


@pytest.mark.parametrize("relative_path", _IGNORE_PROBES)
def test_each_required_path_is_git_ignored(
    repository_root: Path,
    relative_path: str,
) -> None:
    completed = _run_git(
        repository_root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative_path,
    )

    assert completed.returncode == 0, (
        f"Expected {relative_path!r} to be ignored; git stderr: {completed.stderr!r}"
    )


@pytest.mark.parametrize("relative_path", _MUST_REMAIN_VISIBLE_PROBES)
def test_source_and_control_paths_are_not_git_ignored(
    repository_root: Path,
    relative_path: str,
) -> None:
    completed = _run_git(
        repository_root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative_path,
    )

    assert completed.returncode == 1, (
        f"Expected {relative_path!r} to remain visible; git stderr: "
        f"{completed.stderr!r}"
    )


def test_repository_has_no_tracked_or_unignored_forbidden_path(
    repository_root: Path,
) -> None:
    completed = _run_git(
        repository_root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    )
    assert completed.returncode == 0, completed.stderr

    visible_paths = tuple(path for path in completed.stdout.split("\0") if path)
    forbidden_paths = tuple(
        sorted(path for path in visible_paths if is_forbidden_runtime_path(path))
    )
    assert forbidden_paths == ()
