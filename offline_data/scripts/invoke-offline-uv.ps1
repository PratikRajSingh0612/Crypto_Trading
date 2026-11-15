param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Closed uv launcher of the offline_data sub-project. It mirrors the core
# launcher scripts/invoke-uv.ps1 at the repository root: the same dispatch
# order, the same fixed uv controls, the same path confinement and the same
# child-environment policy, rooted at the sub-project directory (the parent of
# this scripts directory, offline_data/) and pinned to the sub-project
# environment offline_data\.venv. The caller's current directory is
# irrelevant: the root is derived from this file's location, uv receives it
# through --directory and --project, and every test target is resolved against
# it, so the launcher behaves identically whether it is invoked from the
# repository root as .\offline_data\scripts\invoke-offline-uv.ps1 or from the
# sub-project root as .\scripts\invoke-offline-uv.ps1.
#
# Dispatch order: resolve and validate the sub-project root and the project
# metadata file, resolve the unique absolute uv executable, validate the
# requested operation and its arguments, apply the fixed child-environment
# policy, then invoke uv. The three uv bootstrap profiles (lock-check,
# lock-resolve-offline, sync) reach uv without resolving the project
# interpreter, because a fresh checkout has no .venv until sync creates it and
# uv rejects a --python path that does not exist. Every other profile shares
# one dispatch branch that resolves and validates .venv\Scripts\python.exe
# exactly once: that path is an argument-synthesis input, and resolving it
# reads no environment value, so it cannot depend on the child-environment
# policy applied immediately before invocation. Operation validation stays in
# one closed table, partitioned by nesting, so no second table can drift away
# from it. The profile set is closed and offline: lock-check,
# lock-resolve-offline, sync, pytest-focused, pytest-all, ruff-format-all,
# ruff-check-all and mypy-all. There is no acquiring, building, schema,
# migration or command-line profile; every profile passes --offline.
#
# Root confinement is validated unconditionally below, for every operation.
# The walk covers exactly the root, .venv, .venv\Scripts and
# .venv\Scripts\python.exe and claims no more; it is not a check of every path
# uv may write. Get-Item -Force is the existence probe rather than
# Directory::Exists or File::Exists, because it reaches a reparse point's own
# attributes without depending on how those helpers treat a link whose target
# is missing.
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
    throw "An invoke-offline-uv operation is required"
}

$projectRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path
$operation = [string]$args[0]
[object[]]$tail = @(
    if ($args.Count -gt 1) {
        $args[1..($args.Count - 1)]
    }
)

function Resolve-ClosedProjectPath {
    param(
        [string]$Candidate,
        [bool]$AllowDirectory
    )

    $fullPath = [System.IO.Path]::GetFullPath($Candidate)
    $normalizedRoot = $projectRoot.TrimEnd("\")
    $rootPrefix = "$normalizedRoot\"
    if (
        -not $fullPath.StartsWith(
            $rootPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Path must remain below the sub-project root: $Candidate"
    }
    $relativePath = $fullPath.Substring($rootPrefix.Length)
    $segments = $relativePath.Split("\")
    if ($segments.Count -eq 0 -or $segments -contains "") {
        throw "Path must identify a normalized sub-project entry: $Candidate"
    }
    $currentPath = $normalizedRoot
    $rootItem = Get-Item -LiteralPath $currentPath -Force
    if (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
        -ne 0
    ) {
        throw "Sub-project root must not be a reparse point"
    }
    foreach ($segment in $segments) {
        $currentPath = Join-Path -Path $currentPath -ChildPath $segment
        $item = Get-Item -LiteralPath $currentPath -Force
        if (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) `
            -ne 0
        ) {
            throw "Sub-project path must not traverse a reparse point: $Candidate"
        }
    }
    if (-not $AllowDirectory -and $item.PSIsContainer) {
        throw "Expected a regular file: $Candidate"
    }
    return $fullPath
}

$projectRootItem = Get-Item -LiteralPath $projectRoot -Force
if (
    ($projectRootItem.Attributes -band `
        [System.IO.FileAttributes]::ReparsePoint) -ne 0
) {
    throw "Sub-project root must not be a reparse point"
}
$projectEnvironmentPath = $projectRoot.TrimEnd("\")
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
$coverageConfig = Resolve-ClosedProjectPath `
    (Join-Path $projectRoot "pyproject.toml") $false

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
    $projectRoot,
    "--project",
    $projectRoot,
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
    default {
        $pythonExecutable = Resolve-ClosedProjectPath `
            (Join-Path $projectRoot ".venv\Scripts\python.exe") $false
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
                $ruffExecutable = Resolve-ClosedProjectPath `
                    (Join-Path $projectRoot ".venv\Scripts\ruff.exe") $false
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
                $ruffExecutable = Resolve-ClosedProjectPath `
                    (Join-Path $projectRoot ".venv\Scripts\ruff.exe") $false
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
                        throw "pytest-focused target must be sub-project-relative under tests/"
                    }
                    $segments = $targetPath.Split("/")
                    if (
                        $segments -contains "" `
                        -or $segments -contains "." `
                        -or $segments -contains ".."
                    ) {
                        throw "pytest-focused target is not normalized"
                    }
                    $resolvedTarget = Resolve-ClosedProjectPath `
                        (Join-Path $projectRoot $targetPath.Replace("/", "\")) `
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
            default {
                throw "Unknown invoke-offline-uv operation: $operation"
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

Push-Location -LiteralPath $projectRoot
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
