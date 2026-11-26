import json
from dataclasses import replace
import sys
import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from conftest import activate
from rdp_guard import recovery
from rdp_guard.events import SECURITY
from rdp_guard.guard import Guard
from rdp_guard.web.app import create_app
from rdp_guard.windows.platform import remote_network_allowed
from rdp_guard.windows.recovery import TimeSynchronizer, supervise_services


def confirmed(guard):
    activate(guard)
    guard.clock.now += 1
    guard.safety.admin_sessions[0].update(ip_source="LSM/25", connected_at=guard.clock(),
                                         source_timestamp=guard.clock(), source_record_id=10)
    guard.dispatch("confirm-active", {}, "admin")
    guard.safety.recovery_health = lambda *args: guard.safety.checks | {"time_sync": True, "errors": []}


def restart(guard):
    result = Guard(guard.store, guard.firewall.backend, guard.safety, guard.data_dir, guard.clock)
    result.collectors[SECURITY] = {"healthy": True}
    return result


def test_overnight_restart_recovers_without_an_interactive_admin(guard):
    confirmed(guard)
    guard.clock.now += 12 * 3600
    guard.safety.admin_sessions = []
    restored = restart(guard)
    assert restored.mode == "MONITOR ONLY"
    restored.tick(force=True)
    assert restored.mode == "ACTIVE"
    lease = json.loads(restored.lease_path.read_text())
    assert lease["confirmed"] is True and lease["deadline"] is None and lease["recovered"] is True


def test_fast_restart_also_requires_fresh_clock_and_health(guard):
    confirmed(guard)
    guard.safety.recovery_health = lambda *args: guard.safety.checks | {"time_sync": False, "errors": []}
    restored = restart(guard)
    restored.tick(force=True)
    assert restored.mode == "MONITOR ONLY"
    assert "time_sync" in restored.recovery_status["reason"]


def test_transient_failure_recovers_when_checks_return(guard):
    confirmed(guard)
    guard.safety.ok = False
    with pytest.raises(RuntimeError):
        guard.tick(force=True)
    assert recovery.approval(guard.data_dir)
    guard.tick(force=True)
    assert guard.mode == "MONITOR ONLY"
    guard.safety.ok = True
    guard.tick(force=True)
    assert guard.mode == "ACTIVE"
    events = guard.service_journal.recent()
    assert any(e["event"] == "waiting" for e in events)
    assert any(e["event"] == "active" for e in events)


@pytest.mark.parametrize("command", ["monitor-only", "emergency-disable"])
def test_manual_disable_never_rearms_after_restart(guard, command):
    confirmed(guard)
    guard.dispatch(command, {}, "admin")
    assert recovery.approval(guard.data_dir) is None
    guard.clock.now += 36000
    restored = restart(guard)
    restored.tick(force=True)
    assert restored.mode == "MONITOR ONLY"


@pytest.mark.parametrize("change", ["port", "whitelist", "subscription", "firewall", "maintenance"])
def test_resume_requires_unchanged_admin_access_and_dependencies(guard, change):
    confirmed(guard)
    restored = restart(guard)
    if change == "port":
        restored.settings = replace(restored.settings, rdp_port=restored.settings.rdp_port + 1)
    elif change == "whitelist":
        restored.store.db.execute("DELETE FROM whitelist")
    elif change == "subscription":
        restored.collectors[SECURITY]["healthy"] = False
    elif change == "firewall":
        restored.safety.checks["firewall"] = False
    else:
        recovery.atomic_document(restored.data_dir / "maintenance.json", {"until": restored.clock() + 100})
    restored.tick(force=True)
    assert restored.mode == "MONITOR ONLY"


def test_unconfirmed_activation_cannot_grant_recovery(guard):
    activate(guard)
    guard.clock.now += 36000
    restored = restart(guard)
    restored.tick(force=True)
    assert restored.mode == "MONITOR ONLY"
    assert recovery.approval(guard.data_dir) is None


def test_journal_survives_reopening_and_deduplicates_polling(tmp_path):
    journal = recovery.ServiceJournal(tmp_path)
    journal.transition("protection", "waiting", "clock", now=1)
    journal.transition("protection", "waiting", "clock", now=2)
    journal.transition("protection", "active", "ready", now=3)
    journal.transition("protection", "waiting", "clock", now=4)
    assert [r["timestamp"] for r in recovery.ServiceJournal(tmp_path).recent()] == [4, 3, 1]


def test_service_supervisor_restarts_stopped_service_and_respects_installer(tmp_path, monkeypatch):
    starts = []
    api = SimpleNamespace(QueryServiceStatus=lambda _: (16, 1, 0, 1067, 0, 0, 0),
                          StartService=starts.append)
    monkeypatch.setitem(sys.modules, "win32serviceutil", api)
    supervise_services(tmp_path)
    assert starts == ["RDPGuardService", "RDPGuardWeb"]
    recovery.atomic_document(tmp_path / "maintenance.json", {"until": __import__("time").time() + 300})
    starts.clear()
    supervise_services(tmp_path)
    assert starts == []


def test_time_recovery_uses_existing_source_and_rejects_local_oscillator(tmp_path):
    calls = []
    def runner(args):
        calls.append(args)
        return "time.windows.com,0x8" if args == ["/query", "/source"] else "OK"
    sync = TimeSynchronizer(tmp_path, threading.Event(), runner=runner)
    assert not sync.snapshot()["ready"]
    sync.synchronize()
    assert sync.snapshot()["ready"]
    assert calls == [["/resync", "/rediscover"], ["/query", "/source"]]
    sync.runner = lambda args: "Local CMOS Clock"
    with pytest.raises(RuntimeError):
        sync.synchronize()


def test_allow_rule_must_cover_whole_recovery_network():
    assert remote_network_allowed("203.0.113.0/24", "203.0.113.10/32")
    assert not remote_network_allowed("203.0.113.10/32", "203.0.113.0/24")
    assert not remote_network_allowed("LocalSubnet", "203.0.113.10/32")


def test_offline_web_stays_available_without_leaking_private_details(tmp_path):
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"checked_at": 100, "secret": "credential",
        "services": {"RDPGuardService": {"state": 1, "exit_code": 1067, "detail": "private"}}}))
    class Offline:
        def call(self, request):
            raise OSError("private IPC path")
    with TestClient(create_app(Offline(), status_path=path), base_url="http://127.0.0.1:8787",
                    client=("127.0.0.1", 1), raise_server_exceptions=False) as client:
        response = client.get("/")
        assert response.status_code == 503 and "Служба защиты недоступна" in response.text
        public = client.get("/api/service-status")
        assert public.status_code == 200
        assert "private" not in public.text and "credential" not in public.text
        assert public.json()["services"]["RDPGuardService"]["exit_code"] == 1067


def test_watchdog_withdraws_stale_authority_before_restarting(guard, monkeypatch):
    from rdp_guard import runtime
    from rdp_guard.windows import platform, firewall, recovery as native_recovery
    confirmed(guard)
    guard.clock.now += 36000
    monkeypatch.setattr(runtime.time, "time", guard.clock)
    monkeypatch.setattr(platform, "DATA_DIR", guard.data_dir)
    monkeypatch.setattr(platform, "require_admin", lambda: None)
    monkeypatch.setattr(platform, "firewall_mutex", nullcontext)
    monkeypatch.setattr(firewall, "WindowsFirewall", lambda: guard.firewall.backend)
    calls = []
    def supervise(data_dir):
        assert not guard.lease_path.exists()
        calls.append(data_dir)
    monkeypatch.setattr(native_recovery, "supervise_services", supervise)
    assert runtime.watchdog()["recovery_pending"]
    assert calls == [guard.data_dir]
    assert recovery.approval(guard.data_dir)
    assert not guard.emergency_path.exists()


def test_health_query_cannot_renew_lease_withdrawn_by_watchdog(guard):
    confirmed(guard)
    old = json.loads(guard.lease_path.read_text())
    guard.lease_path.unlink()
    with pytest.raises(OSError):
        guard._renew_lease(old, dict(old, heartbeat=guard.clock() + 1))
    assert not guard.lease_path.exists()


def test_ntp_backward_step_does_not_stall_heartbeats(guard):
    confirmed(guard)
    guard.tick(force=True)
    guard.clock.now -= 3600
    guard.tick()
    assert json.loads(guard.lease_path.read_text())["heartbeat"] == guard.clock()
    guard.clock.now += 11
    guard.tick()
    assert json.loads(guard.lease_path.read_text())["heartbeat"] == guard.clock()


def test_diagnostic_disk_failure_does_not_stop_recovery(tmp_path, monkeypatch):
    def fail(self):
        raise OSError("disk full")
    monkeypatch.setattr(recovery.ServiceJournal, "_open", fail)
    starts = []
    monkeypatch.setitem(sys.modules, "win32serviceutil", SimpleNamespace(
        QueryServiceStatus=lambda _: (16, 1, 0, 1067, 0, 0, 0), StartService=starts.append))
    supervise_services(tmp_path)
    assert starts == ["RDPGuardService", "RDPGuardWeb"]


@pytest.mark.parametrize("document", [[], None, "bad", {"until": True}])
def test_invalid_recovery_documents_are_not_authority(tmp_path, document):
    for name in ("recovery-approval.json", "maintenance.json"):
        (tmp_path / name).write_text(json.dumps(document))
    assert recovery.approval(tmp_path) is None
    assert not recovery.maintenance(tmp_path)
