#Requires -Version 5.1
# Portable regression: capture registration without touching Windows Task Scheduler.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WatchdogTask.ps1')
function Assert-Task([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Definition([xml]$Definition, [string]$Executable) {
    $Task = $Definition.Task
    Assert-Task ($Task.version -eq '1.2') 'Use the downlevel Task Scheduler schema.'
    Assert-Task ($Task.Triggers.TimeTrigger.Repetition.Interval -eq 'PT1M') 'Missing minute interval.'
    Assert-Task ($null -eq $Task.Triggers.TimeTrigger.Repetition.Duration) 'Repetition must have no expiry.'
    Assert-Task ($null -eq $Task.Triggers.TimeTrigger.EndBoundary) 'Time trigger must have no end boundary.'
    Assert-Task ($Task.Triggers.TimeTrigger.Enabled -eq 'true') 'Time trigger disabled.'
    Assert-Task ($Task.Triggers.BootTrigger.Enabled -eq 'true') 'Boot trigger disabled.'
    Assert-Task ($Task.Principals.Principal.UserId -eq 'S-1-5-18') 'LocalSystem SID required.'
    Assert-Task ($null -eq $Task.Principals.Principal.LogonType) 'LocalSystem must not use a user-logon XML value.'
    Assert-Task ($Task.Principals.Principal.RunLevel -eq 'HighestAvailable') 'Elevated watchdog required.'
    Assert-Task ($Task.Settings.MultipleInstancesPolicy -eq 'IgnoreNew') 'Concurrent watchdogs must not overlap.'
    Assert-Task ($Task.Settings.ExecutionTimeLimit -eq 'PT1M') 'Watchdog execution must be bounded.'
    Assert-Task ($Task.Settings.StartWhenAvailable -eq 'true') 'Missed runs must be recovered.'
    Assert-Task ($Task.Actions.Exec.Command -eq $Executable) 'Executable XML escaping changed the path.'
    Assert-Task ($Task.Actions.Exec.Arguments -eq 'watchdog') 'Unexpected watchdog arguments.'
}

$SamplePath = 'C:\Program Files\R&D <sample>\rdpguard.exe'
$StartAt = [datetime]::new(2026, 1, 1, 12, 0, 0, [DateTimeKind]::Utc)
$Definition = [xml](New-RdpGuardWatchdogXml -Executable $SamplePath -StartAt $StartAt)
Assert-Definition $Definition $SamplePath
Assert-Task ($Definition.Task.Triggers.TimeTrigger.StartBoundary -eq '2026-01-01T12:00:00Z') 'Start must be UTC.'

function New-ScheduledTaskTrigger { throw 'Server 2012 R2 rejects RepetitionInterval without RepetitionDuration.' }
$script:Calls = [System.Collections.Generic.List[string]]::new()
$script:RejectRegistration = $false
function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$Xml, [switch]$Force)
    Assert-Task ($TaskName -eq 'RDPGuardRollback' -and $Force) 'Wrong registration target.'
    Assert-Definition ([xml]$Xml) (Join-Path $script:TestRoot 'rdpguard.exe')
    $script:Calls.Add('register')
    if ($script:RejectRegistration) { throw 'Injected registration failure' }
}
function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    Assert-Task ($TaskName -eq 'RDPGuardRollback') 'Wrong start target.'
    $script:Calls.Add('start')
}
$script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rdpguard-task-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $script:TestRoot | Out-Null
try {
    New-Item -ItemType File -Path (Join-Path $script:TestRoot 'rdpguard.exe') | Out-Null
    Register-RdpGuardWatchdog -InstallRoot $script:TestRoot
    Assert-Task (($script:Calls -join ',') -eq 'register,start') 'Register before starting the task.'
    $script:Calls.Clear()
    $script:RejectRegistration = $true
    $Rejected = $false
    try { Register-RdpGuardWatchdog -InstallRoot $script:TestRoot } catch {
        if ($_.Exception.Message -ne 'Injected registration failure') { throw }
        $Rejected = $true
    }
    Assert-Task ($Rejected -and ($script:Calls -join ',') -eq 'register') 'Registration failure must abort startup.'
} finally {
    Remove-Item -LiteralPath $script:TestRoot -Recurse -Force
}
Write-Host 'Watchdog XML, indefinite repetition, downlevel cmdlet avoidance and error propagation passed.'
