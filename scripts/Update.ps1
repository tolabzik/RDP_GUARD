#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:ProgramFiles 'RDPGuard'
$DataRoot = Join-Path $env:ProgramData 'RDPGuard'
$Payload = Join-Path $PSScriptRoot 'RDPGuard'
if (-not (Test-Path (Join-Path $Payload 'rdpguard.exe'))) { throw 'Release payload is missing.' }
if (-not (Get-Service RDPGuardService -ErrorAction SilentlyContinue)) { throw 'Use Install.ps1 for a new installation.' }
. (Join-Path $PSScriptRoot 'WatchdogTask.ps1')
& (Join-Path $InstallRoot 'rdpguard.exe') emergency-disable
if ($LASTEXITCODE -ne 0) { throw 'Could not remove managed firewall rules. Update stopped.' }
Stop-Service RDPGuardWeb -ErrorAction SilentlyContinue
Stop-Service RDPGuardService
$Backup = Join-Path $DataRoot ('backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $Backup | Out-Null
Copy-Item (Join-Path $DataRoot 'guard.db*') $Backup -Force
$BinaryBackup = Join-Path $Backup 'binaries'
Copy-Item $InstallRoot $BinaryBackup -Recurse
try {
    # Replace the shared dependency tree so obsolete modules do not shadow the new version.
    Remove-Item (Join-Path $InstallRoot '_internal') -Recurse -Force
    Copy-Item (Join-Path $Payload '*') $InstallRoot -Recurse -Force
    Register-RdpGuardWatchdog -InstallRoot $InstallRoot
    Start-Service RDPGuardService
    Start-Service RDPGuardWeb
    Write-Host "Updated. Protected backup: $Backup. Protection stays disabled until explicit reactivation."
} catch {
    Stop-Service RDPGuardWeb -ErrorAction SilentlyContinue
    Stop-Service RDPGuardService -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $BinaryBackup '*') $InstallRoot -Recurse -Force
    Write-Error "Update failed; previous binaries restored. Data retained at $Backup. Services remain stopped: $_"
    throw
}
