#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()] param([switch]$PurgeData)
$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:ProgramFiles 'RDPGuard'
$DataRoot = Join-Path $env:ProgramData 'RDPGuard'
$Cli = Join-Path $InstallRoot 'rdpguard.exe'
if (Test-Path $Cli) {
    & $Cli emergency-disable
    if ($LASTEXITCODE -ne 0) { throw 'Emergency cleanup failed; refusing to remove the recovery tools.' }
}
foreach ($Name in @('RDPGuardWeb','RDPGuardService')) {
    if (Get-Service $Name -ErrorAction SilentlyContinue) {
        Stop-Service $Name -ErrorAction SilentlyContinue
        & sc.exe delete $Name | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Unable to delete $Name" }
    }
}
Unregister-ScheduledTask -TaskName 'RDPGuardRollback' -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path $InstallRoot) { Remove-Item $InstallRoot -Recurse -Force }
if ($PurgeData -and (Test-Path $DataRoot)) { Remove-Item $DataRoot -Recurse -Force }
Write-Host 'RDP Guard removed. Existing firewall rules, Kaspersky and Windows RDP configuration were not changed.'
if (-not $PurgeData) { Write-Host "Logs and configuration retained: $DataRoot" }
