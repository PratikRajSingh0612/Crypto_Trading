param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Dispatch order: resolve and validate the repository root and the project
# metadata file, resolve the unique absolute uv executable, validate the
# requested operation and its arguments, apply the fixed child-environment
# policy, then invoke uv. The five uv bootstrap profiles reach uv without
# resolving the project interpreter, because a fresh worktree has no .venv
# until sync creates it and uv rejects a --python path that does not exist.
# Every other profile shares one dispatch branch that resolves and validates
# .venv\Scripts\python.exe exactly once: that path is an argument-synthesis
# input, and resolving it reads no environment value, so it cannot depend on
# the child-environment policy applied immediately before invocation.
# Operation validation stays in one closed table, partitioned by nesting, so
# no second table can drift away from it.
#
# Root confinement is validated unconditionally below, for every operation.
# Before this file dispatched bootstrap profiles separately, the unconditional
# top-level interpreter resolution enforced that incidentally, and sync and
# sync-acquire are exactly the profiles that make uv create and populate .venv.
# The walk covers exactly the pre-correction surface -- the root, .venv,
# .venv\Scripts, and .venv\Scripts\python.exe -- and claims no more; it is not
# a check of every path uv may write. Get-Item -Force is the existence probe
# rather than Directory::Exists or File::Exists, because it reaches a reparse
# point's own attributes without depending on how those helpers treat a link
# whose target is missing.
#
# uv is located with Get-Command against PATH. Application discovery resolves a
# relative PATH element against the process working directory, which
# Push-Location does not change, so no location change can anchor it. The
# rejection of a non-rooted resolved source below is therefore the control that
# prevents validating one file and executing another. The purge list must never
# gain a name that affects application discovery, such as PATH or PATHEXT.
#
# uv's platform directory roots -- its managed-Python directory and its cache
# directory -- are trusted at the same level as PATH. The uv-specific overrides
# UV_PYTHON_INSTALL_DIR and UV_CACHE_DIR are purged, but the APPDATA and
# LOCALAPPDATA roots they fall back to are not, and specification section 9
# authorizes purging neither. Specification section 24.2 places a deliberately
# malicious executable running with the user's operating-system permissions
# outside the containment guarantee.

if ($args.Count -eq 0) {
    throw "An invoke-uv operation is required"
}

$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path
$operation = [string]$args[0]
[object[]]$tail = @(
    if ($args.Count -gt 1) {
        $args[1..($args.Count - 1)]
    }
)

function Resolve-ClosedRepositoryPath {
    param(
        [string]$Candidate,
        [bool]$AllowDirectory
    )

    $fullPath = [System.IO.Path]::GetFullPath($Candidate)
    $normalizedRoot = $repositoryRoot.TrimEnd("\")
    $rootPrefix = "$normalizedRoot\"
    if (
        -not $fullPath.StartsWith(
            $rootPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Path must remain below the repository root: $Candidate"
    }
    $relativePath = $fullPath.Substring($rootPrefix.Length)
    $segments = $relativePath.Split("\")
    if ($segments.Count -eq 0 -or $segments -contains "") {
        throw "Path must identify a normalized repository entry: $Candidate"
    }
    $currentPath = $normalizedRoot
    $rootItem = Get-Item -LiteralPath $currentPath -Force
    if (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
        -ne 0
    ) {
        throw "Repository root must not be a reparse point"
    }
    foreach ($segment in $segments) {
        $currentPath = Join-Path -Path $currentPath -ChildPath $segment
        $item = Get-Item -LiteralPath $currentPath -Force
        if (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
            -ne 0
        ) {
            throw "Repository path must not traverse a reparse point: $Candidate"
        }
    }
    if (-not $AllowDirectory -and $item.PSIsContainer) {
        throw "Expected a regular file: $Candidate"
    }
    return $fullPath
}

function Resolve-ClosedSchemaWriteDirectory {
    $normalizedRoot = $repositoryRoot.TrimEnd("\")
    $candidate = [System.IO.Path]::GetFullPath(
        (Join-Path $normalizedRoot "schemas")
    )
    $parent = [System.IO.Path]::GetDirectoryName($candidate)
    if (
        $parent -cne $normalizedRoot `
        -or [System.IO.Path]::GetFileName($candidate) -cne "schemas"
    ) {
        throw "Schema write path must be the exact repository schemas directory"
    }
    $rootItem = Get-Item -LiteralPath $normalizedRoot -Force
    if (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
        -ne 0
    ) {
        throw "Repository root must not be a reparse point"
    }
    if ([System.IO.File]::Exists($candidate)) {
        throw "Schema write path must not be a file"
    }
    if ([System.IO.Directory]::Exists($candidate)) {
        $schemaItem = Get-Item -LiteralPath $candidate -Force
        if (
            ($schemaItem.Attributes -band `
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "Schema write path must not be a reparse point"
        }
    }
    return $candidate
}

$repositoryRootItem = Get-Item -LiteralPath $repositoryRoot -Force
if (
    ($repositoryRootItem.Attributes -band `
        [System.IO.FileAttributes]::ReparsePoint) -ne 0
) {
    throw "Repository root must not be a reparse point"
}
$projectEnvironmentPath = $repositoryRoot.TrimEnd("\")
foreach ($projectEnvironmentSegment in @(".venv", "Scripts", "python.exe")) {
    $projectEnvironmentPath = Join-Path `
        -Path $projectEnvironmentPath -ChildPath $projectEnvironmentSegment
    $projectEnvironmentItem = Get-Item `
        -LiteralPath $projectEnvironmentPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $projectEnvironmentItem) {
        break
    }
    if (
        ($projectEnvironmentItem.Attributes -band `
            [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Project environment must not traverse a reparse point"
    }
}
$coverageConfig = Resolve-ClosedRepositoryPath `
    (Join-Path $repositoryRoot "pyproject.toml") $false

$uvCommands = @(
    Get-Command uv.exe -CommandType Application -All -ErrorAction Stop
)
if ($uvCommands.Count -ne 1) {
    throw "Exactly one uv.exe application must be resolvable"
}
if (-not [System.IO.Path]::IsPathRooted($uvCommands[0].Source)) {
    throw "uv.exe must resolve to an absolute application path"
}
$uvExecutable = [System.IO.Path]::GetFullPath($uvCommands[0].Source)
if ([string]::IsNullOrWhiteSpace($uvExecutable)) {
    throw "Unable to resolve uv.exe to an absolute application path"
}
$uvBaseArguments = @(
    "--directory",
    $repositoryRoot,
    "--project",
    $repositoryRoot,
    "--no-config",
    "--managed-python",
    "--no-python-downloads"
)

switch -CaseSensitive ($operation) {
    "lock-check" {
        if ($tail.Count -ne 0) {
            throw "lock-check accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "lock",
            "--check"
        )
    }
    "lock-resolve-offline" {
        if ($tail.Count -ne 0) {
            throw "lock-resolve-offline accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "lock"
        )
    }
    "sync" {
        if ($tail.Count -ne 0) {
            throw "sync accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "--offline",
            "sync",
            "--frozen",
            "--no-build-isolation"
        )
    }
    "lock-acquire" {
        if ($tail.Count -ne 0) {
            throw "lock-acquire accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "lock"
        )
    }
    "sync-acquire" {
        if ($tail.Count -ne 0) {
            throw "sync-acquire accepts no arguments"
        }
        $uvArguments = $uvBaseArguments + @(
            "sync",
            "--frozen",
            "--no-install-project",
            "--no-build-isolation"
        )
    }
    default {
        $pythonExecutable = Resolve-ClosedRepositoryPath `
            (Join-Path $repositoryRoot ".venv\Scripts\python.exe") $false
        $runPrefix = $uvBaseArguments + @(
            "--offline",
            "run",
            "--no-sync",
            "--no-env-file",
            "--python",
            $pythonExecutable,
            "--"
        )
        $pytestPrefix = @(
            $pythonExecutable,
            "-I",
            "-B",
            "-m",
            "pytest",
            "--disable-plugin-autoload",
            "-p",
            "pytest_cov.plugin",
            "--cov-config=$coverageConfig"
        )
        switch -CaseSensitive ($operation) {
            "ruff-format-all" {
                if ($tail.Count -ne 0) {
                    throw "ruff-format-all accepts no arguments"
                }
                $ruffExecutable = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot ".venv\Scripts\ruff.exe") $false
                $uvArguments = $runPrefix + @(
                    $ruffExecutable,
                    "format",
                    "--check",
                    "."
                )
            }
            "ruff-check-all" {
                if ($tail.Count -ne 0) {
                    throw "ruff-check-all accepts no arguments"
                }
                $ruffExecutable = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot ".venv\Scripts\ruff.exe") $false
                $uvArguments = $runPrefix + @($ruffExecutable, "check", ".")
            }
            "mypy-all" {
                if ($tail.Count -ne 0) {
                    throw "mypy-all accepts no arguments"
                }
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    "-m",
                    "mypy"
                )
            }
            "pytest-all" {
                if ($tail.Count -ne 0) {
                    throw "pytest-all accepts no arguments"
                }
                $uvArguments = $runPrefix + $pytestPrefix
            }
            "pytest-launcher-bootstrap" {
                if ($tail.Count -ne 0) {
                    throw "pytest-launcher-bootstrap accepts no arguments"
                }
                $launcherTest = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "tests\safety\test_uv_launcher.py") `
                    $false
                $uvArguments = $runPrefix + $pytestPrefix + @(
                    "-o",
                    "addopts=",
                    $launcherTest,
                    "-k",
                    "launcher and not validation_libraries and not pydantic",
                    "-q"
                )
            }
            "pytest-focused" {
                if ($tail.Count -eq 0) {
                    throw "pytest-focused requires at least one test target"
                }
                $pytestArguments = [System.Collections.Generic.List[object]]::new()
                $index = 0
                if (
                    $tail.Count -ge 2 `
                    -and [string]$tail[0] -ceq "-o" `
                    -and [string]$tail[1] -ceq "addopts="
                ) {
                    [void]$pytestArguments.Add("-o")
                    [void]$pytestArguments.Add("addopts=")
                    $index = 2
                }
                $targetCount = 0
                while ($index -lt $tail.Count) {
                    $argument = [string]$tail[$index]
                    if ($argument -ceq "-q" -and $index -eq $tail.Count - 1) {
                        [void]$pytestArguments.Add($argument)
                        $index += 1
                        continue
                    }
                    if ($argument.StartsWith("-", [System.StringComparison]::Ordinal)) {
                        throw "pytest-focused accepts only test targets and final -q"
                    }
                    $normalized = $argument.Replace("\", "/")
                    if (
                        $normalized -cnotmatch `
                            '^tests/[A-Za-z0-9_./-]+(?:::[A-Za-z0-9_]+)?$'
                    ) {
                        throw "pytest-focused target contains unsupported characters"
                    }
                    $targetParts = $normalized -split "::", 2
                    $targetPath = $targetParts[0]
                    if (
                        [System.IO.Path]::IsPathRooted($targetPath) `
                        -or -not $targetPath.StartsWith(
                            "tests/",
                            [System.StringComparison]::Ordinal
                        ) `
                        -or $targetPath.Contains(":")
                    ) {
                        throw "pytest-focused target must be repository-relative under tests/"
                    }
                    $segments = $targetPath.Split("/")
                    if (
                        $segments -contains "" `
                        -or $segments -contains "." `
                        -or $segments -contains ".."
                    ) {
                        throw "pytest-focused target is not normalized"
                    }
                    $resolvedTarget = Resolve-ClosedRepositoryPath `
                        (Join-Path $repositoryRoot $targetPath.Replace("/", "\")) `
                        $true
                    $nodeSuffix = if ($targetParts.Count -eq 2) {
                        "::$($targetParts[1])"
                    }
                    else {
                        ""
                    }
                    [void]$pytestArguments.Add("$resolvedTarget$nodeSuffix")
                    $targetCount += 1
                    $index += 1
                }
                if ($targetCount -eq 0) {
                    throw "pytest-focused requires at least one test target"
                }
                $uvArguments = $runPrefix + $pytestPrefix + @($pytestArguments)
            }
            "schema-generate-write" {
                if ($tail.Count -ne 0) {
                    throw "schema-generate-write accepts no arguments"
                }
                $schemaGenerator = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "scripts\generate_schemas.py") $false
                $schemaDirectory = Resolve-ClosedSchemaWriteDirectory
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    $schemaGenerator,
                    "--output",
                    $schemaDirectory,
                    "--write"
                )
            }
            "schema-generate-check" {
                if ($tail.Count -ne 0) {
                    throw "schema-generate-check accepts no arguments"
                }
                $schemaGenerator = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "scripts\generate_schemas.py") $false
                $schemaDirectory = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "schemas") $true
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    $schemaGenerator,
                    "--output",
                    $schemaDirectory,
                    "--check"
                )
            }
            "migration-check" {
                if ($tail.Count -ne 0) {
                    throw "migration-check accepts no arguments"
                }
                $migrationVerifier = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "scripts\verify_migrations.py") $false
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    $migrationVerifier
                )
            }
            "schema-distribution" {
                if ($tail.Count -ne 0) {
                    throw "schema-distribution accepts no arguments"
                }
                $schemaVerifier = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot `
                        "scripts\verify_schema_distribution.py") $false
                $schemaDirectory = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "schemas") $true
                $distDirectory = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot "dist") $true
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    $schemaVerifier,
                    "--source",
                    $schemaDirectory,
                    "--dist",
                    $distDirectory
                )
            }
            "cli-version" {
                if ($tail.Count -ne 0) {
                    throw "cli-version accepts no arguments"
                }
                $cliExecutable = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
                $uvArguments = $runPrefix + @($cliExecutable, "--version")
            }
            "cli-module-version" {
                if ($tail.Count -ne 0) {
                    throw "cli-module-version accepts no arguments"
                }
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    "-m",
                    "crypto_lab.cli",
                    "--version"
                )
            }
            "cli-help" {
                if ($tail.Count -ne 0) {
                    throw "cli-help accepts no arguments"
                }
                $cliExecutable = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
                $uvArguments = $runPrefix + @($cliExecutable)
            }
            "cli-unknown" {
                if ($tail.Count -ne 0) {
                    throw "cli-unknown accepts no arguments"
                }
                $cliExecutable = Resolve-ClosedRepositoryPath `
                    (Join-Path $repositoryRoot ".venv\Scripts\crypto-lab.exe") $false
                $uvArguments = $runPrefix + @($cliExecutable, "--unknown")
            }
            "pydantic-proof" {
                if ($tail.Count -ne 0) {
                    throw "pydantic-proof accepts no arguments"
                }
                $pydanticProof = (
                    "from pydantic.plugin import _loader;" +
                    "_loader.importlib_metadata.distributions=" +
                    "lambda:(_ for _ in ()).throw(RuntimeError('plugin discovery ran'));" +
                    "assert tuple(_loader.get_plugins())==()"
                )
                $uvArguments = $runPrefix + @(
                    $pythonExecutable,
                    "-I",
                    "-B",
                    "-c",
                    $pydanticProof
                )
            }
            "build" {
                if ($tail.Count -ne 0) {
                    throw "build accepts no arguments"
                }
                $uvArguments = $uvBaseArguments + @(
                    "--offline",
                    "build",
                    "--no-build-isolation",
                    "--python",
                    $pythonExecutable
                )
            }
            default {
                throw "Unknown invoke-uv operation: $operation"
            }
        }
    }
}

$nativeExitCode = 1
$environmentNamesToRemove = @(
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
    "MYPYPATH"
)

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($environmentName in $environmentNamesToRemove) {
        [System.Environment]::SetEnvironmentVariable(
            $environmentName,
            $null,
            [System.EnvironmentVariableTarget]::Process
        )
    }
    $env:PYDANTIC_DISABLE_PLUGINS = "__all__"
    & $uvExecutable @uvArguments
    $nativeExitCode = $LASTEXITCODE
}
finally {
    Remove-Item -LiteralPath Env:\PYDANTIC_DISABLE_PLUGINS -ErrorAction SilentlyContinue
    Pop-Location
}

exit $nativeExitCode
