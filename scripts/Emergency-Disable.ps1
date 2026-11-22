#Requires -RunAsAdministrator
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$Cli = Join-Path $env:ProgramFiles 'RDPGuard\rdpguard.exe'
& $Cli emergency-disable
if ($LASTEXITCODE -ne 0) { throw 'Emergency cleanup failed. Inspect the protected logs and managed firewall group.' }
