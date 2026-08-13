"""Write or check the closed Stage 3 schema registry."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from crypto_lab.schema_registry import render_schema_files


def _schema_files(root: Path) -> set[PurePosixPath]:
    if root.is_symlink():
        raise ValueError(f"schema output root must not be a symlink: {root}")
    if not root.exists():
        return set()
    files: set[PurePosixPath] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"schema output entry must not be a symlink: {path}")
        if path.is_file():
            files.add(PurePosixPath(path.relative_to(root).as_posix()))
    return files


def _write(output: Path, expected: dict[PurePosixPath, bytes]) -> int:
    output.mkdir(parents=True, exist_ok=True)
    unexpected = _schema_files(output) - set(expected)
    if unexpected:
        for relative_path in sorted(unexpected):
            print(
                f"unexpected schema output file: {relative_path.as_posix()}",
                file=sys.stderr,
            )
        return 1
    for relative_path in sorted(expected):
        contents = expected[relative_path]
        target = output.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
    return 0


def _check(output: Path, expected: dict[PurePosixPath, bytes]) -> int:
    actual_paths = _schema_files(output)
    expected_paths = set(expected)
    failures: list[str] = []
    for relative_path in sorted(expected_paths - actual_paths):
        failures.append(f"missing schema: {relative_path.as_posix()}")
    for relative_path in sorted(actual_paths - expected_paths):
        failures.append(f"unexpected schema: {relative_path.as_posix()}")
    for relative_path in sorted(expected_paths & actual_paths):
        target = output.joinpath(*relative_path.parts)
        if target.read_bytes() != expected[relative_path]:
            failures.append(f"changed schema: {relative_path.as_posix()}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = render_schema_files()
    try:
        if args.write:
            return _write(args.output, expected)
        return _check(args.output, expected)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
