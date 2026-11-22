#Requires -RunAsAdministrator
# Disposable CI host ONLY. Never run on an RDS production server.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This destructive installation smoke test is limited to GitHub Actions.' }
$Root = Join-Path $env:ProgramFiles 'RDPGuard'
try {
    & "$PSScriptRoot\Install.ps1" -SkipAdminSetup
    python "$PSScriptRoot\test_installed.py"
    if ($LASTEXITCODE -ne 0) { throw 'Installed service smoke tests failed.' }
} finally {
    if (Test-Path "$env:ProgramData\RDPGuard\logs") {
        New-Item -ItemType Directory 'test-results\service-logs' -Force | Out-Null
        Copy-Item "$env:ProgramData\RDPGuard\logs\*" 'test-results\service-logs' -Force -ErrorAction SilentlyContinue
        Copy-Item "$env:ProgramData\RDPGuard\web-logs\*" 'test-results\service-logs' -Force -ErrorAction SilentlyContinue
    }
    & "$PSScriptRoot\Uninstall.ps1" -PurgeData
}
