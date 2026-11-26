#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$SkipAdminSetup)
$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:ProgramFiles 'RDPGuard'
$DataRoot = Join-Path $env:ProgramData 'RDPGuard'
$Payload = Join-Path $PSScriptRoot 'RDPGuard'
if (-not (Test-Path (Join-Path $Payload 'rdpguard.exe'))) { throw 'Run Install.ps1 from the extracted release archive.' }
if (Get-Service RDPGuardService -ErrorAction SilentlyContinue) { throw 'RDP Guard is already installed. Use Update.ps1.' }
. (Join-Path $PSScriptRoot 'WatchdogTask.ps1')

function Invoke-Sc([string[]]$Arguments) {
    & sc.exe @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failed: $($Arguments -join ' ')" }
}
function Set-PrivateDirectory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $Acl = New-Object System.Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($Sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $Identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $Acl.AddAccessRule($Rule)
    }
    Set-Acl -Path $Path -AclObject $Acl
}

Set-PrivateDirectory $DataRoot
Set-PrivateDirectory (Join-Path $DataRoot 'logs')
Set-RdpGuardMaintenance -DataRoot $DataRoot
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Copy-Item (Join-Path $Payload '*') $InstallRoot -Recurse -Force
# Program files inherit read/execute access; only Administrators and SYSTEM may modify binaries.
$BinaryAcl = Get-Acl $InstallRoot
$BinaryAcl.SetAccessRuleProtection($true, $false)
foreach ($Pair in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','ReadAndExecute'))) {
    $Identity = New-Object System.Security.Principal.SecurityIdentifier($Pair[0])
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Pair[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $BinaryAcl.AddAccessRule($Rule)
}
Set-Acl $InstallRoot $BinaryAcl

try {
    Invoke-Sc -Arguments @('create','RDPGuardService','binPath=',('"' + (Join-Path $InstallRoot 'guardservice.exe') + '"'),'start=','delayed-auto','obj=','LocalSystem','DisplayName=','RDP Guard Protection Service')
    Invoke-Sc -Arguments @('create','RDPGuardWeb','binPath=',('"' + (Join-Path $InstallRoot 'webservice.exe') + '"'),'start=','delayed-auto','obj=','NT AUTHORITY\LocalService','depend=','RDPGuardService','DisplayName=','RDP Guard Local Web Panel')
    foreach ($Service in @('RDPGuardService','RDPGuardWeb')) {
        Invoke-Sc -Arguments @('sidtype',$Service,'unrestricted')
        Invoke-Sc -Arguments @('failure',$Service,'reset=','86400','actions=','restart/10000/restart/60000/restart/300000')
        Invoke-Sc -Arguments @('failureflag',$Service,'1')
    }
    $WebSid = (New-Object System.Security.Principal.NTAccount('NT SERVICE\RDPGuardWeb')).Translate([System.Security.Principal.SecurityIdentifier])
    # A non-inheriting traverse permission lets the web identity reach only its own log directory.
    $Acl = Get-Acl $DataRoot
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($WebSid,'Traverse','None','None','Allow')))
    Set-Acl $DataRoot $Acl
    $WebLogs = Join-Path $DataRoot 'web-logs'
    Set-PrivateDirectory $WebLogs
    $Acl = Get-Acl $WebLogs
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($WebSid,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl $WebLogs $Acl

    Set-RdpGuardServiceRecovery -DataRoot $DataRoot
    Register-RdpGuardWatchdog -InstallRoot $InstallRoot

    if (-not $SkipAdminSetup) {
        $AdminName = Read-Host 'New panel administrator username (3-64 ASCII characters)'
        & (Join-Path $InstallRoot 'rdpguard.exe') init-admin --username $AdminName
        if ($LASTEXITCODE -ne 0) { throw 'Panel administrator setup failed. Services remain stopped.' }
    }
    Start-Service RDPGuardService
    Start-Service RDPGuardWeb
    Remove-Item -LiteralPath (Join-Path $DataRoot 'maintenance.json') -ErrorAction SilentlyContinue
    Write-Host 'Installed in MONITOR ONLY. Panel: http://127.0.0.1:8787'
    Write-Host 'Existing Windows/Kaspersky firewall rules and RDP/audit settings were not changed.'
    if ($SkipAdminSetup) { Write-Warning 'No default password exists. Run rdpguard.exe init-admin --username YOUR_NAME before using the panel.' }
} catch {
    Write-Error "Installation incomplete: $_. Run Uninstall.ps1 to remove registered services, or repair before starting them."
    throw
}
