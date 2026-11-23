"""Exercise the exporter with a mocked native event source, including incomplete reads."""

import json
from pathlib import Path
import shutil
import subprocess
from xml.sax.saxutils import escape

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Export-ProxyEvidence.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell.exe")
pytestmark = pytest.mark.skipif(not POWERSHELL, reason="PowerShell is required for exporter checks")
CHANNEL = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
PROVIDER = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
ACTIVITY = "{f4203b90-2593-4730-bb47-6b743c610000}"


def event(event_id, record, timestamp, *, computer="СЕРВЕР", provider=PROVIDER):
    data = '<Data Name="ClientIP">45.144.220.53:59034</Data>' if event_id == 131 else (
        '<Data Name="IPString">45.144.220.53</Data>'
    )
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}" Guid="{{1139c61b-b549-4251-8ed3-27250a1edec8}}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version>"
        f'<TimeCreated SystemTime="{timestamp}"/><EventRecordID>{record}</EventRecordID>'
        f'<Correlation ActivityID="{ACTIVITY}" RelatedActivityID="{{00000000-0000-0000-0000-000000000001}}"/>'
        f"<Channel>{CHANNEL}</Channel><Computer>{escape(computer)}</Computer></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def run_export(tmp_path, events=(), *, error=None, max_events=50, start="2026-11-23T16:54:28Z",
               end="2026-11-23T16:54:30Z", existing=False):
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({"events": list(events), "error": error}), encoding="utf-8")
    output = tmp_path / "evidence.json"
    if existing:
        output.write_text("existing evidence", encoding="utf-8")
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$fixture = ConvertFrom-Json ([IO.File]::ReadAllText({ps_quote(fixture)}))\n"
        "function Get-WinEvent {\n"
        "  [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents)\n"
        "  if ($fixture.error -eq 'empty') { Write-Error 'No matching events' -ErrorId NoMatchingEventsFound }\n"
        "  if ($fixture.error -eq 'denied') { throw 'Access denied' }\n"
        "  foreach ($xml in ($fixture.events | Select-Object -First $MaxEvents)) {\n"
        "    $record = [pscustomobject]@{ Xml = $xml }\n"
        "    $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml }\n"
        "    $record\n"
        "  }\n"
        "}\n"
        f"& {ps_quote(SCRIPT)} -OutputPath {ps_quote(output)} -StartUtc {ps_quote(start)} "
        f"-EndUtc {ps_quote(end)} -MaxEvents {max_events} -LookbackSeconds 5\n"
        "if ($LASTEXITCODE) { exit $LASTEXITCODE }\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        text=True, capture_output=True, timeout=30,
    )
    return result, output


def test_export_preserves_native_evidence_and_distinguishes_lookback(tmp_path):
    antecedent = event(131, 10, "2026-11-23T16:54:27.9912345Z")
    failure = event(140, 11, "2026-11-23T16:54:28.1234567Z")
    result, output = run_export(tmp_path, [failure, antecedent])
    assert result.returncode == 0, result.stdout + result.stderr
    assert not output.read_bytes().startswith(b"\xef\xbb\xbf")
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["complete"] is True and evidence["truncated"] is False
    assert evidence["query_start_utc"] == "2026-11-23T16:54:23.0000000Z"
    assert evidence["event_count"] == 2
    first, second = evidence["events"]
    assert first["in_requested_window"] is False and second["in_requested_window"] is True
    assert first["activity_id"] == second["activity_id"] == ACTIVITY
    assert first["raw_xml"] == antecedent and second["raw_xml"] == failure
    assert first["computer"] == "СЕРВЕР"
    assert first["data"] == [{"name": "ClientIP", "value": "45.144.220.53:59034"}]
    assert first["provider_guid"] == "{1139c61b-b549-4251-8ed3-27250a1edec8}"


def test_export_window_is_half_open_and_only_connections_use_lookback(tmp_path):
    records = [event(140, 1, "2026-11-23T16:54:27Z"),
               event(131, 2, "2026-11-23T16:54:22Z"),
               event(140, 3, "2026-11-23T16:54:28Z"),
               event(131, 4, "2026-11-23T16:54:30Z")]
    result, output = run_export(tmp_path, records)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert [e["record_id"] for e in evidence["events"]] == [3]
    assert evidence["filtered_out_count"] == 3


def test_cap_is_explicit_and_incomplete_artifact_is_retained(tmp_path):
    records = [event(140, number, "2026-11-23T16:54:29Z") for number in range(3)]
    result, output = run_export(tmp_path, records, max_events=2)
    assert result.returncode == 2, result.stdout + result.stderr
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["complete"] is False and evidence["truncated"] is True
    assert evidence["queried_event_count"] == 3 and evidence["event_count"] == 2
    assert evidence["errors"]


@pytest.mark.parametrize("error,code,complete", [("empty", 0, True), ("denied", 2, False)])
def test_empty_log_differs_from_unreadable_log(tmp_path, error, code, complete):
    result, output = run_export(tmp_path, error=error)
    assert result.returncode == code, result.stdout + result.stderr
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["complete"] is complete
    assert evidence["events"] == []
    assert bool(evidence["errors"]) is not complete


def test_invalid_record_marks_export_incomplete(tmp_path):
    result, output = run_export(tmp_path, [event(140, 1, "2026-11-23T16:54:29Z", provider="Other")])
    assert result.returncode == 2, result.stdout + result.stderr
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert not evidence["complete"] and evidence["events"] == []
    assert "provider" in evidence["errors"][0]


@pytest.mark.parametrize("start,end", [
    ("2026-11-23T16:54:28", "2026-11-23T16:54:30Z"),
    ("2026-11-23T16:54:30Z", "2026-11-23T16:54:28Z"),
    ("2026-11-21T16:54:28Z", "2026-11-23T16:54:30Z"),
])
def test_invalid_or_unbounded_window_creates_no_artifact(tmp_path, start, end):
    result, output = run_export(tmp_path, start=start, end=end)
    assert result.returncode != 0
    assert not output.exists()


def test_existing_evidence_is_not_overwritten(tmp_path):
    result, output = run_export(tmp_path, existing=True)
    assert result.returncode != 0
    assert output.read_text(encoding="utf-8") == "existing evidence"


def test_explicit_offset_is_normalized_to_utc(tmp_path):
    result, output = run_export(tmp_path, start="2026-11-23T17:54:28+01:00", end="2026-11-23T17:54:30+01:00")
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["requested_start_utc"] == "2026-11-23T16:54:28.0000000Z"
