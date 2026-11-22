#Requires -RunAsAdministrator
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
Get-Service RDPGuardService,RDPGuardWeb,MpsSvc | Format-Table Name,Status,StartType
Get-ScheduledTaskInfo -TaskName RDPGuardRollback | Format-List
& (Join-Path $env:ProgramFiles 'RDPGuard\rdpguard.exe') health
if ($LASTEXITCODE -ne 0) { throw 'Guard health request failed.' }
