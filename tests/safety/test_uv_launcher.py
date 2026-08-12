from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import subprocess
from base64 import b64decode
from pathlib import Path

import pytest

_EXPECTED_NORMALIZED_SHA256 = (
    "1aee7c257068e9fd68ba741f24dd1e6a02fca7592a609185cd1afffab7cd8041"
)
_ALLOWED_COMMANDS = {
    "<dynamic>",
    "Get-Command",
    "Get-Item",
    "Join-Path",
    "Pop-Location",
    "Push-Location",
    "Remove-Item",
    "Resolve-Path",
    "Resolve-ClosedRepositoryPath",
    "Resolve-ClosedSchemaWriteDirectory",
    "Set-StrictMode",
}
_PURGED_ENVIRONMENT_NAMES = (
    "UV_PROJECT",
    "UV_PROJECT_ENVIRONMENT",
    "UV_WORKING_DIR",
    "UV_CONFIG_FILE",
    "UV_NO_CONFIG",
    "UV_PYTHON",
    "UV_PYTHON_INSTALL_DIR",
    "UV_PYTHON_BIN_DIR",
    "UV_PYTHON_DOWNLOADS",
    "UV_MANAGED_PYTHON",
    "UV_NO_MANAGED_PYTHON",
    "UV_NO_PROJECT",
    "UV_ACTIVE",
    "UV_ENV_FILE",
    "UV_NO_ENV_FILE",
    "UV_OFFLINE",
    "UV_NO_SYNC",
    "UV_FROZEN",
    "UV_LOCKED",
    "UV_ISOLATED",
    "UV_NO_DEV",
    "UV_NO_DEFAULT_GROUPS",
    "UV_NO_GROUP",
    "UV_NO_INSTALL_LOCAL",
    "UV_NO_INSTALL_PROJECT",
    "UV_NO_INSTALL_WORKSPACE",
    "UV_NO_EDITABLE",
    "UV_BUILD_CONSTRAINT",
    "UV_NO_VERIFY_HASHES",
    "UV_REQUIRE_HASHES",
    "UV_CACHE_DIR",
    "UV_COMPILE_BYTECODE",
    "UV_EXCLUDE_NEWER",
    "UV_FORK_STRATEGY",
    "UV_INDEX_STRATEGY",
    "UV_INSECURE_HOST",
    "UV_LINK_MODE",
    "UV_NO_BINARY",
    "UV_NO_BINARY_PACKAGE",
    "UV_NO_BUILD",
    "UV_NO_BUILD_ISOLATION",
    "UV_NO_BUILD_PACKAGE",
    "UV_NO_CACHE",
    "UV_NO_PROGRESS",
    "UV_NO_SOURCES",
    "UV_NO_SOURCES_PACKAGE",
    "UV_PRERELEASE",
    "UV_RESOLUTION",
    "UV_SYSTEM_CERTS",
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_KEYRING_PROVIDER",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PYTHONPLATLIBDIR",
    "PYTHONEXECUTABLE",
    "__PYVENV_LAUNCHER__",
    "PYTHONUSERBASE",
    "PYTHONSAFEPATH",
    "PYTHONHASHSEED",
    "PYTHONPYCACHEPREFIX",
    "PYTHONNOUSERSITE",
    "PYTHONCASEOK",
    "PYTHONOPTIMIZE",
    "PYTHONDEBUG",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "PYTHONVERBOSE",
    "PYTHONMALLOC",
    "PYTHONMALLOCSTATS",
    "PYTHONTRACEMALLOC",
    "PYTHONPROFILEIMPORTTIME",
    "PYTHONFAULTHANDLER",
    "PYTHONASYNCIODEBUG",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONLEGACYWINDOWSSTDIO",
    "PYTHONLEGACYWINDOWSFSENCODING",
    "PYTHONCOERCECLOCALE",
    "PYTHONDEVMODE",
    "PYTHONWARNDEFAULTENCODING",
    "PYTHONNODEBUGRANGES",
    "PYTHONINTMAXSTRDIGITS",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "COVERAGE_PROCESS_START",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_RCFILE",
    "COVERAGE_FILE",
    "COVERAGE_FORCE_CONFIG",
    "COVERAGE_CORE",
    "COVERAGE_DEBUG",
    "COVERAGE_DEBUG_CALLS",
    "COVERAGE_DEBUG_FILE",
    "COVERAGE_COVERAGE",
    "COVERAGE_TESTING",
    "COVERAGE_AST_DUMP",
    "COVERAGE_TRACK_ARCS",
    "COVERAGE_SYSMON_LOG",
    "COVERAGE_SYSMON_STATS",
    "COV_CORE_SOURCE",
    "COV_CORE_CONFIG",
    "COV_CORE_DATAFILE",
    "COV_CORE_BRANCH",
    "COV_CORE_CONTEXT",
    "MYPYPATH",
)
_PYDANTIC_PROOF = (
    "from pydantic.plugin import _loader;"
    "_loader.importlib_metadata.distributions="
    "lambda:(_ for _ in ()).throw(RuntimeError('plugin discovery ran'));"
    "assert tuple(_loader.get_plugins())==()"
)
_PYTHON = "<PYTHON>"
_RUFF = "<RUFF>"
_CLI = "<CLI>"
_ROOT = "<ROOT>"


def _normalized_source(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line.rstrip() for line in lines) + "\n"


def _powershell() -> str:
    executable = shutil.which("powershell")
    assert executable is not None
    return executable


def _run_launcher(
    repository_root: Path,
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - reviewed fixed PowerShell boundary
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repository_root / "scripts" / "invoke-uv.ps1"),
            *arguments,
        ],
        cwd=repository_root if cwd is None else cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )


def _create_junction(path: Path, target: Path) -> None:
    script = (
        "$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        "New-Item -ItemType Junction -Path ([string]$payload.path) "
        "-Target ([string]$payload.target)|Out-Null"
    )
    created = subprocess.run(  # noqa: S603 - reviewed fixed PowerShell boundary
        [_powershell(), "-NoProfile", "-Command", script],
        input=json.dumps({"path": str(path), "target": str(target)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert created.returncode == 0, created.stderr


def _powershell_command_records(
    path: Path,
    repository_root: Path,
) -> tuple[tuple[str, str], ...]:
    parser = (
        "$path=[Console]::In.ReadLine();$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$path,[ref]$tokens,[ref]$errors);"
        "if($errors.Count-ne 0){exit 91};"
        "$records=@($ast.FindAll({param($node) $node -is "
        "[System.Management.Automation.Language.CommandAst]},$true)|"
        "ForEach-Object{$name=$_.GetCommandName();"
        "if($null-eq$name){$name='<dynamic>'};"
        "[pscustomobject]@{name=$name;extent=$_.Extent.Text}});"
        "$records|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed parser boundary
        [_powershell(), "-NoProfile", "-Command", parser],
        cwd=repository_root,
        input=f"{path}\n",
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    records = [parsed] if isinstance(parsed, dict) else parsed
    return tuple((record["name"], record["extent"]) for record in records)


def _fake_uv_environment(tmp_path: Path) -> dict[str, str]:
    source = tmp_path / "FakeUv.cs"
    source.write_text(
        """
using System;
using System.Text;

public static class FakeUv
{
    private static string Encode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("cwd=" + Encode(Environment.CurrentDirectory));
        foreach (string argument in args)
        {
            Console.WriteLine("arg=" + Encode(argument));
        }
        string[] names = Environment.GetEnvironmentVariable("FAKE_UV_ENV_NAMES")
            .Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string name in names)
        {
            string value = Environment.GetEnvironmentVariable(name);
            Console.WriteLine(
                "env=" + name + ":" + (value == null ? "<missing>" : Encode(value))
            );
        }
        foreach (string argument in args)
        {
            if (argument.Contains("__exit37__"))
            {
                return 37;
            }
        }
        return 0;
    }
}
""".lstrip(),
        encoding="utf-8",
    )
    fake_uv = tmp_path / "uv.exe"
    compiler = (
        "$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
        "$source=[IO.File]::ReadAllText([string]$payload.source);"
        "Add-Type -TypeDefinition $source "
        "-OutputAssembly ([string]$payload.output) -OutputType ConsoleApplication"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed compiler boundary
        [_powershell(), "-NoProfile", "-Command", compiler],
        cwd=tmp_path,
        input=json.dumps({"source": str(source), "output": str(fake_uv)}),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    environment = {
        "PATH": str(tmp_path),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": str(tmp_path),
        "TMP": str(tmp_path),
        "FAKE_UV_ENV_NAMES": ";".join(
            (*_PURGED_ENVIRONMENT_NAMES, "PYDANTIC_DISABLE_PLUGINS")
        ),
    }
    for index, name in enumerate(_PURGED_ENVIRONMENT_NAMES):
        environment[name] = f"hostile-{index}"
    environment["PYDANTIC_DISABLE_PLUGINS"] = "ambient-test-value"
    return environment


def _parse_fake_uv(stdout: str) -> dict[str, object]:
    result: dict[str, object] = {"argv": [], "environment": {}}
    for line in stdout.splitlines():
        kind, payload = line.split("=", 1)
        if kind == "cwd":
            result["cwd"] = b64decode(payload).decode()
        elif kind == "arg":
            argv = result["argv"]
            assert isinstance(argv, list)
            argv.append(b64decode(payload).decode())
        else:
            name, encoded = payload.split(":", 1)
            environment = result["environment"]
            assert isinstance(environment, dict)
            environment[name] = (
                None if encoded == "<missing>" else b64decode(encoded).decode()
            )
    return result


def test_launcher_has_exact_reviewed_normalized_source(repository_root: Path) -> None:
    launcher = repository_root / "scripts" / "invoke-uv.ps1"
    source = _normalized_source(launcher)
    digest = hashlib.sha256(source.encode()).hexdigest()
    assert digest == _EXPECTED_NORMALIZED_SHA256
    assert source.count('$env:PYDANTIC_DISABLE_PLUGINS = "__all__"') == 1
    assert "Get-ChildItem Env:" not in source
    assert "Get-Item Env:" not in source
    assert "GetEnvironmentVariable" not in source
    assert source.count("[System.Environment]::SetEnvironmentVariable(") == 1
    assert "Get-Command uv.exe -CommandType Application -All" in source
    assert "$uvCommands.Count -ne 1" in source
    assert "[System.IO.Path]::GetFullPath($uvCommands[0].Source)" in source
    assert "& $uvExecutable @uvArguments" in source
    assert source.count('"--disable-plugin-autoload"') == 1
    assert source.count('"--cov-config=$coverageConfig"') == 1
    assert source.count('"pytest-launcher-bootstrap"') == 1
    assert "function Resolve-ClosedRepositoryPath" in source
    assert "function Resolve-ClosedSchemaWriteDirectory" in source
    assert source.count("[System.IO.FileAttributes]::ReparsePoint") == 4
    assert 'Join-Path $repositoryRoot ".venv\\Scripts\\python.exe"' in source
    block_start = source.index("$environmentNamesToRemove = @(")
    block_end = source.index("\n)\n\nPush-Location", block_start)
    declared_names = tuple(
        line.strip().removesuffix(",").strip('"')
        for line in source[block_start:block_end].splitlines()[1:]
    )
    assert declared_names == _PURGED_ENVIRONMENT_NAMES
    for name in declared_names:
        assert f"$env:{name}" not in source


def test_launcher_ast_has_only_closed_commands(repository_root: Path) -> None:
    launcher = repository_root / "scripts" / "invoke-uv.ps1"
    records = _powershell_command_records(launcher, repository_root)
    assert {name for name, _ in records} == _ALLOWED_COMMANDS
    assert tuple(extent for name, extent in records if name == "<dynamic>") == (
        "& $uvExecutable @uvArguments",
    )


@pytest.fixture(scope="module")
def fake_uv_environment(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return _fake_uv_environment(tmp_path_factory.mktemp("fake-uv"))


@pytest.fixture
def launcher_repository(
    tmp_path: Path,
    repository_root: Path,
) -> Path:
    root = tmp_path / "launcher-repository"
    for directory in (
        root / ".venv" / "Scripts",
        root / "dist",
        root / "schemas",
        root / "scripts",
        root / "tests" / "safety",
        root / "tests" / "unit" / "domain",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        repository_root / "scripts" / "invoke-uv.ps1",
        root / "scripts" / "invoke-uv.ps1",
    )
    for path in (
        root / ".venv" / "Scripts" / "python.exe",
        root / ".venv" / "Scripts" / "ruff.exe",
        root / ".venv" / "Scripts" / "crypto-lab.exe",
        root / "scripts" / "generate_schemas.py",
        root / "scripts" / "verify_schema_distribution.py",
        root / "tests" / "__exit37__.py",
        root / "tests" / "safety" / "test_uv_launcher.py",
        root / "tests" / "unit" / "domain" / "test_records.py",
        root / "pyproject.toml",
    ):
        path.touch()
    return root


def _base_arguments(repository_root: Path) -> list[str]:
    root = str(repository_root)
    return [
        "--directory",
        root,
        "--project",
        root,
        "--no-config",
        "--managed-python",
        "--no-python-downloads",
    ]


def _run_arguments(repository_root: Path, *arguments: str) -> list[str]:
    python = str(repository_root / ".venv" / "Scripts" / "python.exe")
    return [
        *_base_arguments(repository_root),
        "--offline",
        "run",
        "--no-sync",
        "--no-env-file",
        "--python",
        python,
        "--",
        *arguments,
    ]


@pytest.mark.parametrize(
    ("arguments", "command"),
    [
        (["lock-check"], ["--offline", "lock", "--check", "--python", _PYTHON]),
        (
            ["lock-resolve-offline"],
            ["--offline", "lock", "--python", _PYTHON],
        ),
        (
            ["sync"],
            [
                "--offline",
                "sync",
                "--frozen",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
        (["lock-acquire"], ["lock", "--python", _PYTHON]),
        (
            ["sync-acquire"],
            [
                "sync",
                "--frozen",
                "--no-install-project",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
        (["ruff-format-all"], ["RUN", _RUFF, "format", "--check", "."]),
        (["ruff-check-all"], ["RUN", _RUFF, "check", "."]),
        (
            ["mypy-all"],
            ["RUN", _PYTHON, "-I", "-B", "-m", "mypy"],
        ),
        (
            ["pytest-all"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
            ],
        ),
        (
            ["pytest-launcher-bootstrap"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                "-o",
                "addopts=",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-k",
                "launcher and not validation_libraries and not pydantic",
                "-q",
            ],
        ),
        (
            ["pytest-focused", "tests/safety/test_uv_launcher.py", "-q"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-q",
            ],
        ),
        (
            [
                "pytest-focused",
                "-o",
                "addopts=",
                "tests/unit/domain/test_records.py::test_valid",
                "tests/safety/test_uv_launcher.py",
                "-q",
            ],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "pytest",
                "--disable-plugin-autoload",
                "-p",
                "pytest_cov.plugin",
                f"--cov-config={_ROOT}\\pyproject.toml",
                "-o",
                "addopts=",
                f"{_ROOT}\\tests\\unit\\domain\\test_records.py::test_valid",
                f"{_ROOT}\\tests\\safety\\test_uv_launcher.py",
                "-q",
            ],
        ),
        (
            ["schema-generate-write"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\generate_schemas.py",
                "--output",
                f"{_ROOT}\\schemas",
                "--write",
            ],
        ),
        (
            ["schema-generate-check"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\generate_schemas.py",
                "--output",
                f"{_ROOT}\\schemas",
                "--check",
            ],
        ),
        (
            ["schema-distribution"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                f"{_ROOT}\\scripts\\verify_schema_distribution.py",
                "--source",
                f"{_ROOT}\\schemas",
                "--dist",
                f"{_ROOT}\\dist",
            ],
        ),
        (["cli-version"], ["RUN", _CLI, "--version"]),
        (
            ["cli-module-version"],
            [
                "RUN",
                _PYTHON,
                "-I",
                "-B",
                "-m",
                "crypto_lab.cli",
                "--version",
            ],
        ),
        (["cli-help"], ["RUN", _CLI]),
        (["cli-unknown"], ["RUN", _CLI, "--unknown"]),
        (
            ["pydantic-proof"],
            ["RUN", _PYTHON, "-I", "-B", "-c", _PYDANTIC_PROOF],
        ),
        (
            ["build"],
            [
                "--offline",
                "build",
                "--no-build-isolation",
                "--python",
                _PYTHON,
            ],
        ),
    ],
)
def test_launcher_synthesizes_only_exact_offline_uv_forms_and_pins_root(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
    arguments: list[str],
    command: list[str],
) -> None:
    environment = fake_uv_environment.copy()
    completed = _run_launcher(
        launcher_repository,
        arguments,
        environment=environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    replacements = {
        _PYTHON: str(launcher_repository / ".venv" / "Scripts" / "python.exe"),
        _RUFF: str(launcher_repository / ".venv" / "Scripts" / "ruff.exe"),
        _CLI: str(launcher_repository / ".venv" / "Scripts" / "crypto-lab.exe"),
        _ROOT: str(launcher_repository),
    }
    rendered = [
        next(
            (
                argument.replace(marker, value)
                for marker, value in replacements.items()
                if marker in argument
            ),
            argument,
        )
        for argument in command
    ]
    expected = (
        _run_arguments(launcher_repository, *rendered[1:])
        if command[0] == "RUN"
        else [*_base_arguments(launcher_repository), *rendered]
    )
    assert _parse_fake_uv(completed.stdout) == {
        "argv": expected,
        "cwd": str(launcher_repository),
        "environment": {
            **dict.fromkeys(_PURGED_ENVIRONMENT_NAMES),
            "PYDANTIC_DISABLE_PLUGINS": "__all__",
        },
    }
    for index, name in enumerate(_PURGED_ENVIRONMENT_NAMES):
        assert environment[name] == f"hostile-{index}"
    assert environment["PYDANTIC_DISABLE_PLUGINS"] == "ambient-test-value"


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["lock-check", "extra"],
        ["lock-resolve-offline", "extra"],
        ["sync", "extra"],
        ["lock-acquire", "extra"],
        ["sync-acquire", "extra"],
        ["build", "extra"],
        ["ruff-format-all", "extra"],
        ["ruff-check-all", "extra"],
        ["mypy-all", "extra"],
        ["pytest-all", "extra"],
        ["pytest-launcher-bootstrap", "extra"],
        ["run", "python", "-m", "pip"],
        ["pytest-focused"],
        ["pytest-focused", r"C:\outside\test.py"],
        ["pytest-focused", r"\\server\share\test.py"],
        ["pytest-focused", "/outside/test.py"],
        ["pytest-focused", "tests/../outside.py"],
        ["pytest-focused", "tests//test_bad.py"],
        ["pytest-focused", "tests/*.py"],
        ["pytest-focused", "tests/missing.py"],
        ["pytest-focused", "tests/path with spaces/test_bad.py"],
        ["pytest-focused", "tests/test_bad.py::test_name::nested"],
        ["pytest-focused", "-p", "plugin"],
        ["pytest-focused", "--pyargs", "package"],
        ["pytest-focused", "--rootdir", "outside"],
        ["pytest-focused", "--import-mode=prepend", "tests/test_bad.py"],
        ["pytest-focused", "-c", "outside.ini"],
        ["pytest-focused", "-o", "not-addopts", "tests/test_bad.py"],
        ["pytest-focused", "tests/test_bad.py", "-q", "tests/test_more.py"],
        ["schema-generate-write", "extra"],
        ["schema-generate-check", "extra"],
        ["schema-distribution", "extra"],
        ["cli-version", "extra"],
        ["cli-module-version", "extra"],
        ["cli-help", "extra"],
        ["cli-unknown", "extra"],
        ["pydantic-proof", "extra"],
        ["unknown"],
    ],
)
def test_launcher_rejects_every_unapproved_form(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
    arguments: list[str],
) -> None:
    completed = _run_launcher(
        launcher_repository,
        arguments,
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""


def test_launcher_rejects_ambiguous_uv_application_resolution(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    first_directory = Path(fake_uv_environment["PATH"])
    second_directory = tmp_path / "second-uv"
    second_directory.mkdir()
    shutil.copy2(first_directory / "uv.exe", second_directory / "uv.exe")
    environment = fake_uv_environment.copy()
    environment["PATH"] = f"{first_directory}{os.pathsep}{second_directory}"
    completed = _run_launcher(
        launcher_repository,
        ["lock-check"],
        environment=environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "Exactly one uv.exe application" in completed.stderr


def test_launcher_rejects_reparse_point_test_target(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    outside = tmp_path / "outside-tests"
    outside.mkdir()
    (outside / "test_escape.py").touch()
    link = launcher_repository / "tests" / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Windows test principal cannot create a symbolic link")
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/linked/test_escape.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_launcher_rejects_junction_target_without_optional_privilege(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    outside = tmp_path / "junction-target"
    outside.mkdir()
    (outside / "test_escape.py").touch()
    junction = launcher_repository / "tests" / "junction"
    _create_junction(junction, outside)
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/junction/test_escape.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_schema_write_accepts_only_the_absent_exact_schema_leaf(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    schema_directory = launcher_repository / "schemas"
    shutil.rmtree(schema_directory)
    completed = _run_launcher(
        launcher_repository,
        ["schema-generate-write"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = _parse_fake_uv(completed.stdout)
    argv = parsed["argv"]
    assert isinstance(argv, list)
    assert str(schema_directory) in argv
    assert not schema_directory.exists()


def test_schema_write_rejects_an_existing_reparse_point_leaf(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    schema_directory = launcher_repository / "schemas"
    shutil.rmtree(schema_directory)
    outside = tmp_path / "outside-schemas"
    outside.mkdir()
    _create_junction(schema_directory, outside)
    completed = _run_launcher(
        launcher_repository,
        ["schema-generate-write"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "reparse point" in completed.stderr


def test_launcher_propagates_native_exit_code(
    launcher_repository: Path,
    tmp_path: Path,
    fake_uv_environment: dict[str, str],
) -> None:
    completed = _run_launcher(
        launcher_repository,
        ["pytest-focused", "tests/__exit37__.py"],
        environment=fake_uv_environment,
        cwd=tmp_path,
    )
    assert completed.returncode == 37


def test_validation_libraries_are_available() -> None:
    for module_name in ("hypothesis", "jsonschema", "pydantic"):
        assert importlib.import_module(module_name) is not None


def test_launcher_disables_real_pydantic_plugin_discovery_and_leaves_parent_unchanged(
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("pydantic")
    monkeypatch.setenv("PYDANTIC_DISABLE_PLUGINS", "ambient-test-value")
    completed = _run_launcher(repository_root, ["pydantic-proof"])
    assert completed.returncode == 0, completed.stderr
    assert os.environ["PYDANTIC_DISABLE_PLUGINS"] == "ambient-test-value"


@pytest.mark.parametrize(
    "mutation",
    [
        "bitsadmin /transfer forbidden https://example.invalid/a out",
        "certutil -urlcache -split -f https://example.invalid/a out",
        "[System.Net.Http.HttpClient]::new()",
        "$executable = 'uv'; & $executable --version",
    ],
)
def test_mutations_fail_exact_source_and_closed_command_guards(
    repository_root: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    source = _normalized_source(repository_root / "scripts" / "invoke-uv.ps1")
    mutated = tmp_path / "mutated-launcher.ps1"
    mutated.write_text(f"{source}{mutation}\n", encoding="utf-8")
    digest = hashlib.sha256(_normalized_source(mutated).encode()).hexdigest()
    assert digest != _EXPECTED_NORMALIZED_SHA256
    if mutation.startswith("$executable") or mutation.startswith(
        ("bitsadmin", "certutil")
    ):
        records = _powershell_command_records(mutated, repository_root)
        assert {name for name, _ in records} != _ALLOWED_COMMANDS or tuple(
            extent for name, extent in records if name == "<dynamic>"
        ) != ("& $uvExecutable @uvArguments",)
