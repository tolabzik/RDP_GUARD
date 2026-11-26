#Requires -Version 5.1
# Shared by installation and update. Defining these functions changes no system state.
function Set-RdpGuardMaintenance {
    param([Parameter(Mandatory)][string]$DataRoot)
    $Until = [math]::Floor(([DateTime]::UtcNow - [DateTime]'1970-01-01Z').TotalSeconds) + 1800
    @{ until = $Until } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataRoot 'maintenance.json') -Encoding ASCII
}

function Set-RdpGuardServiceRecovery {
    param([Parameter(Mandatory)][string]$DataRoot)
    foreach ($Service in @('RDPGuardService','RDPGuardWeb')) {
        & sc.exe config $Service start= delayed-auto | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Cannot configure startup: $Service" }
        & sc.exe failure $Service reset= 86400 actions= restart/10000/restart/60000/restart/300000 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Cannot configure recovery: $Service" }
        & sc.exe failureflag $Service 1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Cannot configure failure flag: $Service" }
    }
    # Keep the diagnostic web process available while the protection service recovers.
    & sc.exe config RDPGuardWeb depend= / | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot separate web service recovery.' }
    $Public = Join-Path $DataRoot 'service-status'
    New-Item -ItemType Directory -Path $Public -Force | Out-Null
    $Acl = New-Object System.Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($Sid in @('S-1-5-18','S-1-5-32-544')) {
        $Identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $WebSid = (New-Object System.Security.Principal.NTAccount('NT SERVICE\RDPGuardWeb')).Translate([System.Security.Principal.SecurityIdentifier])
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($WebSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl $Public $Acl
}

function New-RdpGuardWatchdogXml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Executable, [Parameter(Mandatory)][datetime]$StartAt)
    $Command = [System.Security.SecurityElement]::Escape($Executable)
    $Boundary = $StartAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    # Server 2012 R2's New-ScheduledTaskTrigger rejects an interval without a duration.
    # Task Scheduler XML explicitly supports indefinite repetition by omitting Duration.
    # Do not use a finite duration on a one-time trigger: recovery must never expire.
    return @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>RDP Guard independent rollback watchdog</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>$Boundary</StartBoundary><Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals><Principal id="System">
    <UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>
  </Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled>
    <RunOnlyIfIdle>false</RunOnlyIfIdle><ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="System"><Exec><Command>$Command</Command><Arguments>watchdog</Arguments></Exec></Actions>
</Task>
"@
}

function Register-RdpGuardWatchdog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InstallRoot)
    $Executable = Join-Path $InstallRoot 'rdpguard.exe'
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Installed watchdog executable is missing.' }
    $TaskXml = New-RdpGuardWatchdogXml -Executable $Executable -StartAt (Get-Date).AddMinutes(1)
    Register-ScheduledTask -TaskName 'RDPGuardRollback' -Xml $TaskXml -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName 'RDPGuardRollback' -ErrorAction Stop
}
