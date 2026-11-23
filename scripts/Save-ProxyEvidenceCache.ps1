#Requires -Version 5.1
<#
.SYNOPSIS
Keeps a finite local cache of recent proxy evidence before a busy event log wraps.
.DESCRIPTION
Only invokes the read-only exporter and writes local evidence/status files.
No services, auditing, firewall rules, or RDP settings are changed.
Keep the hosting PowerShell/job alive until status.json reports completed/failed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExporterPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateRange(30, 600)][int]$DurationSeconds = 480,
    [ValidateRange(1, 10)][int]$PollSeconds = 10,
    [ValidateRange(20, 60)][int]$WindowSeconds = 30
)

$ErrorActionPreference = 'Stop'

function Write-ProxyCacheStatus {
    param([string]$Directory, [object]$Status)
    $path = Join-Path $Directory 'status.json'
    $temporary = Join-Path $Directory ('.status.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $temporary + '.previous'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText($temporary, ($Status | ConvertTo-Json -Depth 10), $encoding)
        if ([IO.File]::Exists($path)) {
            [IO.File]::Replace($temporary, $path, $backup)
        } else {
            [IO.File]::Move($temporary, $path)
        }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
    }
}

function ConvertTo-ProxyCacheArgument {
    param([string]$Value)
    if ($Value -match '["\x00\r\n]') { throw 'Unsupported character in child-process argument.' }
    return '"' + $Value + '"'
}

function Invoke-ProxyCacheExporter {
    param([string]$Executable, [string]$Exporter, [string]$Output,
          [string]$StartUtc, [string]$EndUtc, [int]$TimeoutMilliseconds)
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-ProxyCacheArgument $Exporter),
        '-OutputPath', (ConvertTo-ProxyCacheArgument $Output),
        '-StartUtc', (ConvertTo-ProxyCacheArgument $StartUtc),
        '-EndUtc', (ConvertTo-ProxyCacheArgument $EndUtc),
        '-LookbackSeconds', '5', '-MaxEvents', '5000')
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = $arguments -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $started = $false
    try {
        if (-not $process.Start()) { throw 'Exporter process did not start.' }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutMilliseconds)
        if (-not $finished) {
            $process.Kill()
            if (-not $process.WaitForExit(2000)) { throw 'Timed-out exporter did not terminate.' }
        }
        if (-not $stdoutTask.Wait(2000) -or -not $stderrTask.Wait(2000)) {
            throw 'Exporter output streams did not close.'
        }
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            timed_out = -not $finished
            stdout = $stdoutTask.Result
            stderr = $stderrTask.Result
        }
    } finally {
        if ($started) {
            try { if (-not $process.HasExited) { $process.Kill() } } catch { }
        }
        $process.Dispose()
    }
}

function ConvertTo-ProxyCacheUtc {
    param([object]$Value)
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Test-ProxyCacheExport {
    param([string]$Path, [string]$StartUtc, [string]$EndUtc)
    if (-not [IO.File]::Exists($Path)) { throw 'Exporter did not create an evidence file.' }
    $file = Get-Item -LiteralPath $Path
    if ($file.Length -gt 33554432) { throw 'Evidence file exceeds the 32 MiB validation limit.' }
    $document = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
    if ($document.schema -ne 'rdpguard.windows-proxy-evidence.v1' -or
        $document.complete -isnot [bool] -or -not $document.complete -or
        $document.truncated -isnot [bool] -or $document.truncated -or
        @($document.errors).Count -ne 0 -or
        $document.log_coverage.status -ne 'retained') {
        throw 'Exporter evidence is invalid, incomplete, or outside retained log coverage.'
    }
    if ((ConvertTo-ProxyCacheUtc $document.requested_start_utc) -ne
        (ConvertTo-ProxyCacheUtc $StartUtc) -or
        (ConvertTo-ProxyCacheUtc $document.requested_end_utc) -ne
        (ConvertTo-ProxyCacheUtc $EndUtc) -or
        $document.lookback_seconds -ne 5 -or $document.max_events -ne 5000 -or
        $document.event_count -ne @($document.events).Count) {
        throw 'Exporter evidence does not match the requested window or bounds.'
    }
    return [int]$document.event_count
}

function New-ProxyCacheTimer {
    return [Diagnostics.Stopwatch]::StartNew()
}

function Start-ProxyEvidenceCache {
    param([string]$Exporter, [string]$Directory, [int]$Duration,
          [int]$Poll, [int]$Window, [string]$Executable)
    $exporterFull = [IO.Path]::GetFullPath($Exporter)
    $directoryFull = [IO.Path]::GetFullPath($Directory)
    if (-not (Test-Path -LiteralPath $exporterFull -PathType Leaf)) { throw 'ExporterPath does not exist.' }
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Windows PowerShell executable not found.' }
    if (Test-Path -LiteralPath $directoryFull) { throw 'OutputDirectory already exists; choose a new directory.' }
    $null = New-Item -ItemType Directory -Path $directoryFull -ErrorAction Stop
    $snapshots = New-Object 'System.Collections.Generic.List[object]'
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $status = [ordered]@{
        schema = 'rdpguard.proxy-evidence-cache.v1'
        state = 'starting'
        ready = $false
        computer = [Environment]::MachineName
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        deadline_utc = [DateTime]::UtcNow.AddSeconds($Duration).ToString('o')
        updated_at_utc = [DateTime]::UtcNow.ToString('o')
        duration_seconds = $Duration
        poll_seconds = $Poll
        window_seconds = $Window
        exporter_path = $exporterFull
        output_directory = $directoryFull
        valid_snapshot_count = 0
        failed_snapshot_count = 0
        snapshots = @()
        errors = @()
    }
    Write-ProxyCacheStatus $directoryFull $status
    $timer = New-ProxyCacheTimer
    $nextPoll = 0
    $counter = 0
    $totalBytes = [long]0
    try {
        while ($timer.ElapsedMilliseconds -lt ($Duration * 1000)) {
            $remaining = ($Duration * 1000) - $timer.ElapsedMilliseconds
            if ($remaining -lt 1000) { break }
            $delay = $nextPoll - $timer.ElapsedMilliseconds
            if ($delay -gt 0) {
                Start-Sleep -Milliseconds ([int][Math]::Min(250, [Math]::Min($delay, $remaining)))
                continue
            }
            $counter++
            $end = [DateTime]::UtcNow.AddSeconds(-2)
            $start = $end.AddSeconds(-$Window)
            $startText, $endText = $start.ToString('o'), $end.ToString('o')
            $filename = 'evidence-{0}-{1:D4}.json' -f $end.ToString('yyyyMMddTHHmmssfffffffZ'), $counter
            $output = Join-Path $directoryFull $filename
            $snapshot = [ordered]@{
                file = $filename
                requested_start_utc = $startText
                requested_end_utc = $endText
                valid = $false
                event_count = $null
                exit_code = $null
                timed_out = $false
                error = $null
            }
            $becameReady = $false
            try {
                $invokeArguments = @{
                    Executable = $Executable; Exporter = $exporterFull; Output = $output
                    StartUtc = $startText; EndUtc = $endText
                    TimeoutMilliseconds = [int][Math]::Min(15000, $remaining)
                }
                $result = Invoke-ProxyCacheExporter @invokeArguments
                $snapshot.exit_code = $result.exit_code
                $snapshot.timed_out = $result.timed_out
                [IO.File]::WriteAllText($output + '.stdout.txt', $result.stdout)
                [IO.File]::WriteAllText($output + '.stderr.txt', $result.stderr)
                if ($result.timed_out) { throw 'Exporter exceeded its bounded execution time.' }
                if ($result.exit_code -ne 0) { throw ('Exporter exited with code {0}.' -f $result.exit_code) }
                $snapshot.event_count = Test-ProxyCacheExport $output $startText $endText
                $snapshot.valid = $true
                $status.valid_snapshot_count++
                if (-not $status.ready) { $status.ready = $true; $becameReady = $true }
            } catch {
                $snapshot.error = $_.Exception.Message
                $status.failed_snapshot_count++
                $errors.Add(('Snapshot {0}: {1}' -f $filename, $_.Exception.Message))
            }
            if ([IO.File]::Exists($output)) { $totalBytes += (Get-Item -LiteralPath $output).Length }
            $snapshots.Add([pscustomobject]$snapshot)
            $status.state = if ($becameReady) { 'READY' } else { 'running' }
            $status.updated_at_utc = [DateTime]::UtcNow.ToString('o')
            $status.snapshots = @($snapshots.ToArray())
            $status.errors = @($errors.ToArray())
            Write-ProxyCacheStatus $directoryFull $status
            if ($becameReady) { Write-Output ('READY {0}' -f (Join-Path $directoryFull 'status.json')) }
            if ($totalBytes -gt 268435456) { throw 'Evidence cache exceeded the 256 MiB limit.' }
            $nextPoll += ($Poll * 1000)
            if ($nextPoll -lt $timer.ElapsedMilliseconds) { $nextPoll = $timer.ElapsedMilliseconds }
        }
    } catch {
        $errors.Add($_.Exception.Message)
    } finally {
        $timer.Stop()
        if ($status.valid_snapshot_count -eq 0) { $errors.Add('No valid evidence snapshot was saved.') }
        $status.state = if ($errors.Count -gt 0) { 'failed' } else { 'completed' }
        $status.updated_at_utc = [DateTime]::UtcNow.ToString('o')
        $status.ended_at_utc = $status.updated_at_utc
        $status.elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
        $status.snapshots = @($snapshots.ToArray())
        $status.errors = @($errors.ToArray())
        Write-ProxyCacheStatus $directoryFull $status
    }
    Write-Output ([pscustomobject]$status)
}

$rdpCacheExecutable = Join-Path $PSHOME 'powershell.exe'
$rdpCacheArguments = @{
    Exporter = $ExporterPath; Directory = $OutputDirectory; Duration = $DurationSeconds
    Poll = $PollSeconds; Window = $WindowSeconds; Executable = $rdpCacheExecutable
}
$rdpCacheLast = $null
Start-ProxyEvidenceCache @rdpCacheArguments | ForEach-Object {
    $rdpCacheLast = $_
    Write-Output $_
}
if ($null -ne $rdpCacheLast -and $rdpCacheLast.state -eq 'failed') { exit 2 }
