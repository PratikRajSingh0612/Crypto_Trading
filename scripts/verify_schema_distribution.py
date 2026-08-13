"""Verify exact schema bytes and locations in the wheel and sdist."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from crypto_lab.schema_registry import render_schema_files


def _single(paths: list[Path], label: str) -> Path:
    if len(paths) != 1:
        raise ValueError(f"expected exactly one {label}; found {len(paths)}")
    return paths[0]


def _verify_source(source: Path, expected: dict[PurePosixPath, bytes]) -> None:
    if source.is_symlink():
        raise ValueError(f"source schema root must not be a symlink: {source}")
    actual: dict[PurePosixPath, bytes] = {}
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"source schema entry must not be a symlink: {path}")
        if path.is_file():
            relative = PurePosixPath(path.relative_to(source).as_posix())
            actual[relative] = path.read_bytes()
    if actual != expected:
        raise ValueError("source schema tree does not match the closed registry")


def _verify_wheel(wheel: Path, expected: dict[PurePosixPath, bytes]) -> None:
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        if any("\\" in entry.filename for entry in entries):
            raise ValueError("wheel entries must use POSIX separators")
        expected_names = {
            f"crypto_lab/schemas/{relative_path.as_posix()}"
            for relative_path in expected
        }
        expected_directories = {"crypto_lab", "crypto_lab/schemas"}
        for name in expected_names:
            parts = name.split("/")[:-1]
            expected_directories.update(
                "/".join(parts[:index]) for index in range(1, len(parts) + 1)
            )
        relevant = [
            entry
            for entry in entries
            if entry.filename.rstrip("/") in {"crypto_lab", "crypto_lab/schemas"}
            or entry.filename.startswith("crypto_lab/schemas/")
            or entry.filename.endswith(".schema.json")
        ]
        names: list[str] = []
        by_name: dict[str, zipfile.ZipInfo] = {}
        for entry in relevant:
            normalized = entry.filename.rstrip("/")
            mode = (entry.external_attr >> 16) & 0o170000
            if normalized in expected_directories:
                if not entry.is_dir() or mode not in {0, 0o040000}:
                    raise ValueError("wheel schema root entries must be directories")
                continue
            if normalized not in expected_names:
                raise ValueError(f"unexpected wheel schema entry: {entry.filename}")
            if entry.is_dir() or mode not in {0, 0o100000}:
                raise ValueError("wheel schema payloads must be regular files")
            names.append(normalized)
            by_name[normalized] = entry
        if len(names) != len(expected_names) or set(names) != expected_names:
            raise ValueError(
                "wheel schema entries are missing, duplicated, or unexpected"
            )
        for relative_path, contents in expected.items():
            name = f"crypto_lab/schemas/{relative_path.as_posix()}"
            if by_name[name].file_size != len(contents):
                raise ValueError(f"wheel schema size differs: {name}")
            if archive.read(name) != contents:
                raise ValueError(f"wheel schema bytes differ: {name}")


def _verify_sdist(sdist: Path, expected: dict[PurePosixPath, bytes]) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        archive_root = sdist.name.removesuffix(".tar.gz")
        schema_prefix = f"{archive_root}/schemas/"
        all_members = archive.getmembers()
        if any("\\" in member.name for member in all_members):
            raise ValueError("sdist entries must use POSIX separators")
        expected_names = {
            f"{archive_root}/schemas/{relative_path.as_posix()}"
            for relative_path in expected
        }
        expected_directories = {archive_root, f"{archive_root}/schemas"}
        for name in expected_names:
            parts = name.split("/")[:-1]
            expected_directories.update(
                "/".join(parts[:index]) for index in range(1, len(parts) + 1)
            )
        relevant = [
            member
            for member in all_members
            if member.name.rstrip("/") in {archive_root, f"{archive_root}/schemas"}
            or member.name.startswith(schema_prefix)
            or member.name.endswith(".schema.json")
        ]
        names: list[str] = []
        members_by_name: dict[str, tarfile.TarInfo] = {}
        for member in relevant:
            normalized = member.name.rstrip("/")
            if normalized in expected_directories:
                if not member.isdir():
                    raise ValueError("sdist schema root entries must be directories")
                continue
            if normalized not in expected_names:
                raise ValueError(f"unexpected sdist schema entry: {member.name}")
            if not member.isfile():
                raise ValueError("sdist schema payloads must be regular files")
            names.append(normalized)
            members_by_name[normalized] = member
        if len(names) != len(expected_names) or set(names) != expected_names:
            raise ValueError(
                "sdist schema entries are missing, duplicated, or unexpected"
            )
        for relative_path, contents in expected.items():
            name = f"{archive_root}/schemas/{relative_path.as_posix()}"
            member = members_by_name[name]
            if member.size != len(contents):
                raise ValueError(f"sdist schema size differs: {name}")
            extracted = archive.extractfile(member)
            if extracted is None or extracted.read() != contents:
                raise ValueError(f"sdist schema bytes differ: {name}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--dist", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = render_schema_files()
    try:
        _verify_source(args.source, expected)
        wheel = _single(sorted(args.dist.glob("*.whl")), "wheel")
        sdist = _single(sorted(args.dist.glob("*.tar.gz")), "sdist")
        _verify_wheel(wheel, expected)
        _verify_sdist(sdist, expected)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
