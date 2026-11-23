import json
from pathlib import Path
import shutil
import subprocess
import textwrap

import pytest


PWSH = shutil.which("pwsh")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Save-ProxyEvidenceCache.ps1"
pytestmark = pytest.mark.skipif(not PWSH, reason="PowerShell is unavailable")


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def run_ps(tmp_path, code):
    loader = f"""
    $ErrorActionPreference = 'Stop'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile({quote(SCRIPT)},[ref]$tokens,[ref]$errors)
    if ($errors.Count) {{ throw ($errors | Out-String) }}
    foreach($statement in $ast.EndBlock.Statements) {{
        if($statement -is [Management.Automation.Language.FunctionDefinitionAst]) {{
            . ([scriptblock]::Create($statement.Extent.Text))
        }}
    }}
    """
    path = tmp_path / "test.ps1"
    path.write_text(textwrap.dedent(loader + code))
    return subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-File", str(path)],
                          capture_output=True, text=True, timeout=20)


def evidence(start, end, **changes):
    return {
        "schema": "rdpguard.windows-proxy-evidence.v1",
        "requested_start_utc": start, "requested_end_utc": end,
        "complete": True, "truncated": False, "errors": [], "events": [],
        "event_count": 0, "lookback_seconds": 5, "max_events": 5000,
        "log_coverage": {"status": "retained"}, **changes,
    }


@pytest.mark.parametrize("changes", [
    {"complete": False}, {"log_coverage": {"status": "insufficient"}},
    {"log_coverage": {"status": "unknown"}}, {"max_events": 50000},
    {"event_count": 1}, {"requested_end_utc": "2026-01-01T00:00:31Z"},
])
def test_invalid_cache_snapshot_never_becomes_ready(tmp_path, changes):
    start, end = "2026-01-01T00:00:00Z", "2026-01-01T00:00:30Z"
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence(start, end, **changes)))
    result = run_ps(tmp_path, f"""
    try {{ Test-ProxyCacheExport {quote(path)} {quote(start)} {quote(end)}; exit 9 }}
    catch {{ Write-Output 'rejected' }}
    """)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rejected"


def test_valid_empty_snapshot_with_retained_coverage_is_accepted(tmp_path):
    start, end = "2026-01-01T00:00:00Z", "2026-01-01T00:00:30Z"
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence(start, end)))
    result = run_ps(tmp_path, f"Test-ProxyCacheExport {quote(path)} {quote(start)} {quote(end)}")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0"


def test_child_timeout_is_bounded_and_preserves_partial_artifact(tmp_path):
    exporter = tmp_path / "slow exporter.ps1"
    output = tmp_path / "partial evidence.json"
    exporter.write_text(
        "param($OutputPath,$StartUtc,$EndUtc,$LookbackSeconds,$MaxEvents)\n"
        "[IO.File]::WriteAllText($OutputPath, 'partial')\nStart-Sleep -Seconds 10\n"
    )
    code = (
        f"$result=Invoke-ProxyCacheExporter -Executable {quote(PWSH)} -Exporter {quote(exporter)} "
        f"-Output {quote(output)} -StartUtc '2026-01-01T00:00:00Z' "
        "-EndUtc '2026-01-01T00:00:30Z' -TimeoutMilliseconds 1000\n"
        "$result | ConvertTo-Json -Compress"
    )
    result = run_ps(tmp_path, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["timed_out"] is True
    assert output.read_text() == "partial"


def test_atomic_status_replacement_leaves_valid_json(tmp_path):
    result = run_ps(tmp_path, f"""
    Write-ProxyCacheStatus {quote(tmp_path)} @{{state='starting';ready=$false}}
    Write-ProxyCacheStatus {quote(tmp_path)} @{{state='READY';ready=$true}}
    """)
    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / "status.json").read_text()) == {"state": "READY", "ready": True}
    assert not list(tmp_path.glob(".status.*.tmp"))


def test_existing_output_directory_is_not_reused(tmp_path):
    exporter = tmp_path / "exporter.ps1"
    exporter.write_text("")
    command = (
        f"Start-ProxyEvidenceCache -Exporter {quote(exporter)} -Directory {quote(tmp_path)} "
        f"-Duration 30 -Poll 10 -Window 30 -Executable {quote(PWSH)}"
    )
    result = run_ps(tmp_path, "try { " + command + "; exit 9 } catch { Write-Output 'rejected' }")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rejected"
    assert not (tmp_path / "status.json").exists()


@pytest.mark.parametrize("fail_child", [False, True])
def test_cache_loop_is_finite_and_ready_requires_valid_snapshot(tmp_path, fail_child):
    exporter = tmp_path / "exporter.ps1"
    exporter.write_text("")
    cache_dir = tmp_path / "new cache"
    code = """
    $global:cacheTicks=0
    function New-ProxyCacheTimer {
        $timer=New-Object PSObject
        $timer | Add-Member ScriptProperty ElapsedMilliseconds {
            $global:cacheTicks+=1000; return $global:cacheTicks
        }
        $timer | Add-Member NoteProperty Elapsed ([TimeSpan]::FromSeconds(30))
        $timer | Add-Member ScriptMethod Stop {}
        return $timer
    }
    function Start-Sleep { param($Milliseconds) $global:cacheTicks+=$Milliseconds }
    function Invoke-ProxyCacheExporter {
        param($Executable,$Exporter,$Output,$StartUtc,$EndUtc,$TimeoutMilliseconds)
        if([DateTimeOffset]::Parse($EndUtc) -ge [DateTimeOffset]::UtcNow) { throw 'future window' }
        if($TimeoutMilliseconds -gt 15000) { throw 'unbounded child timeout' }
        $doc=@{
            schema='rdpguard.windows-proxy-evidence.v1'
            requested_start_utc=$StartUtc;requested_end_utc=$EndUtc
            complete=$true;truncated=$false;errors=@();events=@();event_count=0
            lookback_seconds=5;max_events=5000;log_coverage=@{status='retained'}
        }
        [IO.File]::WriteAllText($Output,($doc | ConvertTo-Json -Depth 5))
        return [pscustomobject]@{exit_code=EXITCODE;timed_out=$false;stdout='';stderr=''}
    }
    """.replace("EXITCODE", "9" if fail_child else "0")
    code += (
        f"$messages=@(Start-ProxyEvidenceCache -Exporter {quote(exporter)} "
        f"-Directory {quote(cache_dir)} -Duration 30 -Poll 10 -Window 30 "
        f"-Executable {quote(PWSH)})\n"
        "$messages | ConvertTo-Json -Depth 10"
    )
    result = run_ps(tmp_path, code)
    assert result.returncode == 0, result.stderr
    status = json.loads((cache_dir / "status.json").read_text())
    assert status["state"] == ("failed" if fail_child else "completed")
    assert status["ready"] is not fail_child
    assert 1 <= len(status["snapshots"]) <= 5
    assert list(cache_dir.glob("evidence-*.json"))
    assert ("READY " in result.stdout) is not fail_child
