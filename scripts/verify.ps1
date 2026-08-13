[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path

function Assert-NativeSuccess {
    param([string]$CommandLabel)

    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "$CommandLabel failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "`n==> Check lockfile consistency"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 lock-check
    Assert-NativeSuccess "Lockfile check"

    Write-Host "`n==> Sync locked environment"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 sync
    Assert-NativeSuccess "Locked synchronization"

    Write-Host "`n==> Check formatting"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 ruff-format-all
    Assert-NativeSuccess "Format check"

    Write-Host "`n==> Run lint checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 ruff-check-all
    Assert-NativeSuccess "Lint check"

    Write-Host "`n==> Run strict type checks"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 mypy-all
    Assert-NativeSuccess "Type check"

    Write-Host "`n==> Check generated schemas"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 schema-generate-check
    Assert-NativeSuccess "Generated-schema check"

    Write-Host "`n==> Run test suite"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 pytest-all
    Assert-NativeSuccess "Test suite"

    Write-Host "`n==> Build package"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 build
    Assert-NativeSuccess "Package build"

    Write-Host "`n==> Check schema distribution"
    & powershell -NoProfile -ExecutionPolicy Bypass -File `
        .\scripts\invoke-uv.ps1 schema-distribution
    Assert-NativeSuccess "Schema distribution check"

    Write-Host "`n==> Check Git whitespace"
    & git diff --check
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
