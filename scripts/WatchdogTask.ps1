#Requires -Version 5.1
# Shared by installation and update. Defining these functions changes no system state.
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
