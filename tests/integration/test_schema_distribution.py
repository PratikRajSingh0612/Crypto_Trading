from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

import pytest

from crypto_lab.schema_registry import render_schema_files
from verify_schema_distribution import (
    _single,
    _verify_sdist,
    _verify_source,
    _verify_wheel,
    main,
)

type Variant = Literal[
    "exact",
    "missing",
    "changed",
    "duplicate",
    "unexpected",
    "unexpected_payload",
    "backslash",
    "special",
    "schema_root_symlink",
    "schema_root_file",
]


def _write_source(
    root: Path,
    expected: dict[PurePosixPath, bytes],
) -> None:
    for relative_path, contents in expected.items():
        target = root.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)


def _write_wheel(
    path: Path,
    expected: dict[PurePosixPath, bytes],
    *,
    variant: Variant = "exact",
    prefix: str = "crypto_lab/schemas",
) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        if variant in {"schema_root_symlink", "schema_root_file"}:
            root = zipfile.ZipInfo("crypto_lab/schemas/")
            root.create_system = 3
            root.external_attr = (
                0o120777 if variant == "schema_root_symlink" else 0o100644
            ) << 16
            archive.writestr(
                root, b"target" if variant == "schema_root_symlink" else b""
            )
        for index, (relative_path, contents) in enumerate(expected.items()):
            if index == 0 and variant == "missing":
                continue
            name = f"{prefix}/{relative_path.as_posix()}"
            written = b"changed\n" if index == 0 and variant == "changed" else contents
            archive.writestr(name, written)
            if index == 0 and variant == "duplicate":
                archive.writestr(name, written)
        if variant == "unexpected":
            archive.writestr(f"{prefix}/foreign.schema.json", b"{}\n")
        if variant == "unexpected_payload":
            archive.writestr(f"{prefix}/README.txt", b"foreign\n")
        if variant == "backslash":
            archive.writestr(f"{prefix}\\README.txt", b"foreign\n")


def _add_tar_member(
    archive: tarfile.TarFile,
    name: str,
    contents: bytes,
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(contents)
    archive.addfile(info, io.BytesIO(contents))


def _add_tar_special(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.FIFOTYPE
    archive.addfile(info)


def _write_sdist(
    path: Path,
    expected: dict[PurePosixPath, bytes],
    *,
    variant: Variant = "exact",
    archive_root: str | None = None,
) -> None:
    root = path.name.removesuffix(".tar.gz") if archive_root is None else archive_root
    with tarfile.open(path, mode="w:gz") as archive:
        root_info = tarfile.TarInfo(f"{root}/schemas")
        if variant == "schema_root_symlink":
            root_info.type = tarfile.SYMTYPE
            root_info.linkname = "elsewhere"
        elif variant == "schema_root_file":
            root_info.type = tarfile.REGTYPE
        else:
            root_info.type = tarfile.DIRTYPE
        archive.addfile(root_info)
        for index, (relative_path, contents) in enumerate(expected.items()):
            if index == 0 and variant == "missing":
                continue
            name = f"{root}/schemas/{relative_path.as_posix()}"
            written = b"changed\n" if index == 0 and variant == "changed" else contents
            _add_tar_member(archive, name, written)
            if index == 0 and variant == "duplicate":
                _add_tar_member(archive, name, written)
        if variant == "unexpected":
            _add_tar_member(
                archive,
                f"{root}/schemas/foreign.schema.json",
                b"{}\n",
            )
        if variant == "unexpected_payload":
            _add_tar_member(
                archive,
                f"{root}/schemas/README.txt",
                b"foreign\n",
            )
        if variant == "backslash":
            _add_tar_member(archive, f"{root}\\schemas\\README.txt", b"foreign\n")
        if variant == "special":
            _add_tar_special(archive, f"{root}/schemas/pipe")


def test_source_wheel_and_sdist_helpers_accept_exact_bytes(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    wheel = tmp_path / "package.whl"
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_source(source, expected)
    _write_wheel(wheel, expected)
    _write_sdist(sdist, expected)
    _verify_source(source, expected)
    _verify_wheel(wheel, expected)
    _verify_sdist(sdist, expected)


@pytest.mark.parametrize(
    "variant",
    [
        "missing",
        "changed",
        "unexpected",
        "unexpected_payload",
        "backslash",
        "schema_root_symlink",
        "schema_root_file",
    ],
)
def test_wheel_rejects_missing_changed_and_unexpected_entries(
    tmp_path: Path,
    variant: Variant,
) -> None:
    expected = render_schema_files()
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel, expected, variant=variant)
    with pytest.raises(ValueError, match="wheel"):
        _verify_wheel(wheel, expected)


def test_wheel_rejects_duplicate_and_root_level_entries(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    duplicate = tmp_path / "duplicate.whl"
    with pytest.warns(UserWarning, match=r"Duplicate name:"):
        _write_wheel(duplicate, expected, variant="duplicate")
    with pytest.raises(ValueError, match="duplicated"):
        _verify_wheel(duplicate, expected)
    root_level = tmp_path / "root.whl"
    _write_wheel(root_level, expected, prefix="schemas")
    with pytest.raises(ValueError, match="wheel schema"):
        _verify_wheel(root_level, expected)


@pytest.mark.parametrize(
    "variant",
    [
        "missing",
        "changed",
        "duplicate",
        "unexpected",
        "unexpected_payload",
        "backslash",
        "special",
        "schema_root_symlink",
        "schema_root_file",
    ],
)
def test_sdist_rejects_missing_changed_duplicate_and_unexpected_entries(
    tmp_path: Path,
    variant: Variant,
) -> None:
    expected = render_schema_files()
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_sdist(sdist, expected, variant=variant)
    with pytest.raises(ValueError, match="sdist"):
        _verify_sdist(sdist, expected)


def test_sdist_root_is_derived_exactly_from_the_archive_filename(
    tmp_path: Path,
) -> None:
    expected = render_schema_files()
    sdist = tmp_path / "crypto_trading_lab-0.1.0.tar.gz"
    _write_sdist(sdist, expected, archive_root="wrong-root")
    with pytest.raises(ValueError, match="sdist schema"):
        _verify_sdist(sdist, expected)


def test_source_and_single_helpers_reject_mismatches(tmp_path: Path) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    _write_source(source, expected)
    first = next(iter(expected))
    source.joinpath(*first.parts).write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="source schema tree"):
        _verify_source(source, expected)
    _write_source(source, expected)
    (source / "README.txt").write_text("foreign\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source schema tree"):
        _verify_source(source, expected)
    wheel = tmp_path / "one.whl"
    assert _single([wheel], "wheel") == wheel
    with pytest.raises(ValueError, match="exactly one wheel"):
        _single([], "wheel")
    with pytest.raises(ValueError, match="exactly one wheel"):
        _single([wheel, tmp_path / "two.whl"], "wheel")


def test_distribution_main_accepts_one_exact_pair(tmp_path: Path) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_source(source, expected)
    _write_wheel(dist / "package.whl", expected)
    _write_sdist(dist / "crypto_trading_lab-0.1.0.tar.gz", expected)
    assert main(("--source", str(source), "--dist", str(dist))) == 0


def test_distribution_main_rejects_multiple_archives(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = render_schema_files()
    source = tmp_path / "schemas"
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_source(source, expected)
    _write_wheel(dist / "one.whl", expected)
    _write_wheel(dist / "two.whl", expected)
    _write_sdist(dist / "crypto_trading_lab-0.1.0.tar.gz", expected)
    assert main(("--source", str(source), "--dist", str(dist))) == 1
    assert "expected exactly one wheel" in capsys.readouterr().err
