[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$subProjectRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path
$launcher = Join-Path -Path $subProjectRoot -ChildPath "scripts\invoke-offline-uv.ps1"

function Assert-NativeSuccess {
    param([string]$CommandLabel)

    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "$CommandLabel failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $subProjectRoot
try {
    Write-Host "`n==> Check lockfile consistency"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher lock-check
    Assert-NativeSuccess "Lockfile check"

    Write-Host "`n==> Sync locked environment"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher sync
    Assert-NativeSuccess "Locked synchronization"

    Write-Host "`n==> Check formatting"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher ruff-format-all
    Assert-NativeSuccess "Format check"

    Write-Host "`n==> Run lint checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher ruff-check-all
    Assert-NativeSuccess "Lint check"

    Write-Host "`n==> Run strict type checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher mypy-all
    Assert-NativeSuccess "Type check"

    Write-Host "`n==> Run test suite"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher pytest-all
    Assert-NativeSuccess "Test suite"

    Write-Host "`n==> Check Git whitespace"
    & git diff --check -- .
    Assert-NativeSuccess "Git whitespace check"
}
catch {
    if ($verificationExitCode -eq 0) {
        $verificationExitCode = 1
    }
    [Console]::Error.WriteLine($_.Exception.Message)
}
finally {
    Pop-Location
}

exit $verificationExitCode
