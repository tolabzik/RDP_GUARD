#Requires -Version 5.1
<#
.SYNOPSIS
Exports read-only RdpCoreTS connection/failure evidence for an offline proxy probe.
.DESCRIPTION
The requested interval is [StartUtc, EndUtc). Event 131 records from the lookback
interval are also retained so an event 140 can be associated with its connection.
This script does not change services, auditing, firewall rules, or RDP settings.
An incomplete export is retained, marked complete=false, and exits with code 2.
.EXAMPLE
powershell.exe -NoProfile -File .\Export-ProxyEvidence.ps1 -StartUtc '2026-11-23T16:50:00Z' -EndUtc '2026-11-23T16:55:00Z' -OutputPath .\proxy-evidence.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$StartUtc,
    [Parameter(Mandatory = $true)][string]$EndUtc,
    [ValidateRange(1, 100000)][int]$MaxEvents = 50000,
    [ValidateRange(0, 3600)][int]$LookbackSeconds = 300
)

$ErrorActionPreference = 'Stop'
$rdpGuardChannel = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
$rdpGuardProvider = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'

function ConvertTo-ExplicitUtc {
    param([string]$Value, [string]$ParameterName)
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') {
        throw "$ParameterName must be an ISO 8601 timestamp with Z or an explicit offset."
    }
    try {
        return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
    } catch {
        throw "$ParameterName is not a valid timestamp."
    }
}

function ConvertFrom-ProxyEvidenceXml {
    param([string]$RawXml, [DateTimeOffset]$RequestedStart, [DateTimeOffset]$RequestedEnd)

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $textReader = New-Object System.IO.StringReader($RawXml)
    $reader = [System.Xml.XmlReader]::Create($textReader, $settings)
    try {
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
    } finally {
        $reader.Dispose()
        $textReader.Dispose()
    }
    $namespaces = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $namespaces.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $system = $document.SelectSingleNode('/e:Event/e:System', $namespaces)
    if ($null -eq $system) { throw 'Event XML is missing System.' }

    $provider = $system.SelectSingleNode('e:Provider', $namespaces)
    $channel = $system.SelectSingleNode('e:Channel', $namespaces)
    $timeCreated = $system.SelectSingleNode('e:TimeCreated', $namespaces)
    $eventIdNode = $system.SelectSingleNode('e:EventID', $namespaces)
    $recordIdNode = $system.SelectSingleNode('e:EventRecordID', $namespaces)
    $versionNode = $system.SelectSingleNode('e:Version', $namespaces)
    $computerNode = $system.SelectSingleNode('e:Computer', $namespaces)
    if ($null -eq $provider -or $null -eq $channel -or $null -eq $timeCreated -or
        $null -eq $eventIdNode -or $null -eq $recordIdNode -or $null -eq $versionNode -or
        $null -eq $computerNode) { throw 'Event XML is missing required provenance fields.' }
    if ($provider.GetAttribute('Name') -ne $rdpGuardProvider -or $channel.InnerText -ne $rdpGuardChannel) {
        throw 'Unexpected event provider or channel.'
    }
    $eventId = [int]$eventIdNode.InnerText
    $recordId = [long]$recordIdNode.InnerText
    $version = [int]$versionNode.InnerText
    if ($eventId -notin @(131, 140) -or $recordId -lt 0 -or $version -lt 0) {
        throw 'Unexpected event identifier, record identifier, or version.'
    }
    $timestamp = ConvertTo-ExplicitUtc $timeCreated.GetAttribute('SystemTime') 'Event SystemTime'
    $requested = $timestamp -ge $RequestedStart -and $timestamp -lt $RequestedEnd
    $correlation = $system.SelectSingleNode('e:Correlation', $namespaces)
    $activityId = ''
    $relatedActivityId = ''
    if ($null -ne $correlation) {
        $activityId = $correlation.GetAttribute('ActivityID')
        $relatedActivityId = $correlation.GetAttribute('RelatedActivityID')
    }
    $eventData = @($document.SelectNodes('/e:Event/e:EventData/e:Data', $namespaces) | ForEach-Object {
        [ordered]@{ name = $_.GetAttribute('Name'); value = $_.InnerText }
    })
    return [pscustomobject][ordered]@{
        channel = $channel.InnerText
        provider_name = $provider.GetAttribute('Name')
        provider_guid = $provider.GetAttribute('Guid')
        event_id = $eventId
        version = $version
        record_id = $recordId
        computer = $computerNode.InnerText
        timestamp_utc = $timestamp.UtcDateTime.ToString('o')
        activity_id = $activityId
        related_activity_id = $relatedActivityId
        in_requested_window = [bool]$requested
        data = $eventData
        raw_xml = $RawXml
    }
}

$rdpGuardStart = ConvertTo-ExplicitUtc $StartUtc 'StartUtc'
$rdpGuardEnd = ConvertTo-ExplicitUtc $EndUtc 'EndUtc'
if ($rdpGuardEnd -le $rdpGuardStart -or ($rdpGuardEnd - $rdpGuardStart).TotalHours -gt 24) {
    throw 'The requested interval must be positive and no longer than 24 hours.'
}
if ($rdpGuardEnd -gt [DateTimeOffset]::UtcNow) {
    throw 'EndUtc is in the future; wait until the entire requested interval has elapsed before exporting.'
}
$rdpGuardQueryStart = $rdpGuardStart.AddSeconds(-$LookbackSeconds)
$rdpGuardOutput = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $rdpGuardOutput) { throw 'OutputPath already exists; choose a new evidence file.' }
$rdpGuardOutputDirectory = [System.IO.Path]::GetDirectoryName($rdpGuardOutput)
if (-not (Test-Path -LiteralPath $rdpGuardOutputDirectory -PathType Container)) {
    throw 'The OutputPath parent directory does not exist.'
}

$rdpGuardErrors = New-Object 'System.Collections.Generic.List[string]'
$rdpGuardEvents = New-Object 'System.Collections.Generic.List[object]'
$rdpGuardRecords = @()
try {
    # Native query end is inclusive; the XML filter below enforces [start, end).
    $rdpGuardRecords = @(Get-WinEvent -FilterHashtable @{
        LogName = $rdpGuardChannel
        Id = @(131, 140)
        StartTime = $rdpGuardQueryStart.LocalDateTime
        EndTime = $rdpGuardEnd.LocalDateTime
    } -MaxEvents ($MaxEvents + 1) -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
        $rdpGuardErrors.Add(('Event query failed: {0}: {1}' -f $_.FullyQualifiedErrorId, $_.Exception.Message))
    }
}
$rdpGuardTruncated = $rdpGuardRecords.Count -gt $MaxEvents
if ($rdpGuardTruncated) {
    $rdpGuardErrors.Add("Native query exceeded MaxEvents=$MaxEvents; earlier records may be missing.")
}
$rdpGuardFiltered = 0
foreach ($rdpGuardRecord in ($rdpGuardRecords | Select-Object -First $MaxEvents)) {
    try {
        $rdpGuardEvidence = ConvertFrom-ProxyEvidenceXml $rdpGuardRecord.ToXml() $rdpGuardStart $rdpGuardEnd
        $rdpGuardEventTime = ConvertTo-ExplicitUtc $rdpGuardEvidence.timestamp_utc 'Export timestamp'
        if ($rdpGuardEventTime -lt $rdpGuardQueryStart -or $rdpGuardEventTime -ge $rdpGuardEnd -or
            ($rdpGuardEvidence.event_id -eq 140 -and -not $rdpGuardEvidence.in_requested_window)) {
            $rdpGuardFiltered++
            continue
        }
        $rdpGuardEvents.Add($rdpGuardEvidence)
    } catch {
        $rdpGuardErrors.Add(('Event conversion failed: {0}' -f $_.Exception.Message))
    } finally {
        if ($rdpGuardRecord -is [System.IDisposable]) { $rdpGuardRecord.Dispose() }
    }
}
# Dispose the extra record used to detect truncation, if one was returned.
foreach ($rdpGuardRecord in ($rdpGuardRecords | Select-Object -Skip $MaxEvents)) {
    if ($rdpGuardRecord -is [System.IDisposable]) { $rdpGuardRecord.Dispose() }
}
$rdpGuardComplete = -not $rdpGuardTruncated -and $rdpGuardErrors.Count -eq 0
$rdpGuardDocument = [ordered]@{
    schema = 'rdpguard.windows-proxy-evidence.v1'
    requested_start_utc = $rdpGuardStart.UtcDateTime.ToString('o')
    requested_end_utc = $rdpGuardEnd.UtcDateTime.ToString('o')
    query_start_utc = $rdpGuardQueryStart.UtcDateTime.ToString('o')
    exported_at_utc = [DateTime]::UtcNow.ToString('o')
    window_end_exclusive = $true
    lookback_seconds = $LookbackSeconds
    max_events = $MaxEvents
    complete = [bool]$rdpGuardComplete
    truncated = [bool]$rdpGuardTruncated
    queried_event_count = $rdpGuardRecords.Count
    event_count = $rdpGuardEvents.Count
    filtered_out_count = $rdpGuardFiltered
    errors = @($rdpGuardErrors.ToArray())
    events = @($rdpGuardEvents.ToArray() | Sort-Object timestamp_utc, record_id)
}
$rdpGuardJson = $rdpGuardDocument | ConvertTo-Json -Depth 12
$rdpGuardEncoding = New-Object System.Text.UTF8Encoding($false)
$rdpGuardBytes = $rdpGuardEncoding.GetBytes($rdpGuardJson + [Environment]::NewLine)
$rdpGuardFile = [System.IO.File]::Open($rdpGuardOutput, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $rdpGuardFile.Write($rdpGuardBytes, 0, $rdpGuardBytes.Length) }
finally { $rdpGuardFile.Dispose() }
Write-Host ('Saved {0} events to {1}; complete={2}; truncated={3}' -f
    $rdpGuardEvents.Count, $rdpGuardOutput, $rdpGuardComplete, $rdpGuardTruncated)
if (-not $rdpGuardComplete) {
    Write-Warning 'Evidence is incomplete. Review errors in the JSON; do not infer absence of connections.'
    exit 2
}
