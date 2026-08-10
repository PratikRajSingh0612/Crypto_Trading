[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path

function Invoke-VerificationStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Heading,

        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    Write-Host ""
    Write-Host "==> $Heading"
    & $Executable @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "Command failed with exit code $LASTEXITCODE`: $Executable $($ArgumentList -join ' ')"
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    Invoke-VerificationStep `
        "Check lockfile consistency" `
        "uv" `
        @("lock", "--check", "--offline")
    Invoke-VerificationStep "Sync locked environment" "uv" @("sync", "--frozen", "--offline")
    Invoke-VerificationStep "Check formatting" "uv" @("run", "--no-sync", "ruff", "format", "--check", ".")
    Invoke-VerificationStep "Run lint checks" "uv" @("run", "--no-sync", "ruff", "check", ".")
    Invoke-VerificationStep "Run strict type checks" "uv" @("run", "--no-sync", "mypy", "src", "tests")
    Invoke-VerificationStep "Run test suite" "uv" @("run", "--no-sync", "pytest")
    Invoke-VerificationStep "Build package" "uv" @("build", "--offline")
    Invoke-VerificationStep "Check Git whitespace" "git" @("diff", "--check")
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
