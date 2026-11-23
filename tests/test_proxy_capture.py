"""The diagnostic capture must preserve NAT identity and report evidence gaps."""

import json
import os
from pathlib import Path, PureWindowsPath
import socket
import struct
import threading
import time
import subprocess
import sys

import pytest

from rdp_guard import proxy_capture as capture

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Capture-ProxyEvidence.py"


def nla(kind, data):
    size = len(data) + 4
    return struct.pack("=HH", size, kind) + data + bytes((-size) % 4)


def conn_tuple(src, sport, dst, dport):
    family = socket.AF_INET6 if ":" in src else socket.AF_INET
    source_key, destination_key = (3, 4) if family == socket.AF_INET6 else (1, 2)
    addresses = nla(source_key, socket.inet_pton(family, src)) + nla(destination_key, socket.inet_pton(family, dst))
    protocol = nla(1, b"\x06") + nla(2, struct.pack("!H", sport)) + nla(3, struct.pack("!H", dport))
    return nla(1 | 0x8000, addresses) + nla(2 | 0x8000, protocol)


def conn_event(ipv6=False):
    internal, target, external = (
        ("fd00::2", "2001:db8::10", "2001:db8::20") if ipv6
        else ("172.18.0.2", "79.140.26.181", "45.144.220.53"))
    body = struct.pack("=BBH", socket.AF_INET6 if ipv6 else socket.AF_INET, 0, 0)
    body += nla(1 | 0x8000, conn_tuple(internal, 50000, target, 45451))
    body += nla(2 | 0x8000, conn_tuple(target, 45451, external, 60000))
    body += nla(12, struct.pack("!I", 1234)) + nla(18, struct.pack("!H", 7))
    return body, {"ip": target, "port": 45451}


@pytest.mark.parametrize("ipv6", [False, True])
def test_preserves_changed_nat_port_and_zone(ipv6):
    body, backend = conn_event(ipv6)
    result = capture.decode_conntrack(0x100, 0x400, body, backend)
    assert result["original"]["sport"] == 50000
    assert result["reply"]["dport"] == 60000
    assert result["conntrack_id"] == 1234
    assert result["zone"] == 7
    assert result["operation"] == "new"


@pytest.mark.parametrize("kind,flags,snapshot,operation", [
    (0x100, 0, True, "snapshot"), (0x100, 0, False, "update"), (0x102, 0, False, "destroy"),
])
def test_distinguishes_snapshot_and_lifecycle(kind, flags, snapshot, operation):
    body, backend = conn_event()
    assert capture.decode_conntrack(kind, flags, body, backend, snapshot)["operation"] == operation


def test_unrelated_targets_are_not_exported():
    body, _ = conn_event()
    assert capture.decode_conntrack(0x100, 0, body, {"ip": "192.0.2.1", "port": 45451}) is None


@pytest.mark.parametrize("data", [b"\x01", struct.pack("=HH", 2, 1), struct.pack("=HH", 100, 1)])
def test_malformed_attributes_are_gaps(data):
    with pytest.raises(capture.CaptureError):
        capture.attributes(data)


def test_duplicate_attribute_is_not_silently_overwritten():
    with pytest.raises(capture.CaptureError, match="duplicate"):
        capture.attributes(nla(1, b"one") + nla(1, b"two"))


def test_truncated_netlink_datagram_is_not_accepted():
    payload = struct.pack("=IHHII", 24, 0x100, 0, 5, 0) + b"short"
    with pytest.raises(capture.CaptureError):
        list(capture.netlink_messages(payload))


@pytest.mark.parametrize("body", [b"x", b"xxx", struct.pack("=i", -5)])
def test_invalid_or_failed_dump_done_is_not_success(body):
    with pytest.raises(capture.CaptureError):
        capture.check_dump_done(body)


@pytest.mark.parametrize("body", [b"", struct.pack("=i", 0)])
def test_successful_dump_done(body):
    capture.check_dump_done(body)


def process(host_pid, namespace_pid, start_ticks, namespace="pid:[1234]"):
    return {"host_pid": host_pid, "namespace_pids": [host_pid, namespace_pid],
            "start_ticks": start_ticks, "pid_namespace": namespace}


def test_draining_worker_exit_and_new_worker_do_not_create_gap():
    master, old, new = process(1000, 1, 10), process(1001, 2, 20), process(1002, 3, 30)
    tracker = capture.ProcessTracker([master, old])
    change = tracker.observe([master, old, new])
    assert change == {"added": [new], "removed": []}
    change = tracker.observe([master, new])
    assert change == {"added": [], "removed": [old]}
    assert tracker.observe([new, master]) is None


def test_reused_namespace_pid_is_gap_even_after_original_process_exits():
    master, old = process(1000, 1, 10), process(1001, 2, 20)
    tracker = capture.ProcessTracker([master, old])
    tracker.observe([master])
    with pytest.raises(capture.CaptureError, match="pid_reused"):
        tracker.observe([master, process(1010, 2, 40)])


def test_same_host_pid_with_changed_start_ticks_is_gap():
    master = process(1000, 1, 10)
    tracker = capture.ProcessTracker([master])
    with pytest.raises(capture.CaptureError, match="pid_reused"):
        tracker.observe([process(1000, 1, 99)])


def test_multiple_namespaces_require_explicit_scope():
    first, other = process(1000, 1, 10), process(2000, 1, 10, "pid:[5678]")
    with pytest.raises(capture.CaptureError, match="namespace_missing_or_ambiguous"):
        capture.ProcessTracker([first, other])
    tracker = capture.ProcessTracker([first, other], "pid:[1234]")
    assert tracker.snapshot() == [first]
    assert tracker.observe([first, other, process(2001, 2, 30, "pid:[5678]")]) is None


def test_scoped_namespace_disappearance_is_not_silently_ignored():
    first, other = process(1000, 1, 10), process(2000, 1, 10, "pid:[5678]")
    tracker = capture.ProcessTracker([first, other], "pid:[1234]")
    with pytest.raises(capture.CaptureError, match="scoped_namespace_not_observed"):
        tracker.observe([other])


class MemoryWriter:
    def __init__(self):
        self.records = []

    def emit(self, kind, **values):
        self.records.append({"kind": kind, **values})


def test_tail_starts_at_eof_and_preserves_new_line_offsets(tmp_path):
    path = tmp_path / "nginx.log"
    path.write_bytes(b"old line\n")
    writer = MemoryWriter()
    tail = capture.LogTail(path, 100000)
    try:
        with path.open("ab") as log:
            log.write(b"new line\n")
        tail.poll(writer)
        assert writer.records == [{
            "kind": "nginx_line", "line": "new line",
            "source_inode": path.stat().st_ino, "offset": 9,
        }]
    finally:
        tail.close()


def test_partial_initial_line_cannot_become_false_connection(tmp_path):
    path = tmp_path / "nginx.log"
    path.write_bytes(b"old partial")
    writer = MemoryWriter()
    tail = capture.LogTail(path, 100000)
    try:
        with path.open("ab") as log:
            log.write(b" completion\nnew record\n")
        tail.poll(writer)
        assert [item["line"] for item in writer.records] == ["new record"]
    finally:
        tail.close()


@pytest.mark.parametrize("operation,reason", [("rotate", "rotated"), ("truncate", "truncated")])
def test_log_generation_change_reports_gap(tmp_path, operation, reason):
    if os.name == "nt" and operation == "rotate":
        pytest.skip("Linux log rotation relies on renaming an open inode")
    path = tmp_path / "nginx.log"
    path.write_bytes(b"old line\n")
    tail = capture.LogTail(path, 100000)
    try:
        if operation == "rotate":
            path.rename(tmp_path / "nginx.log.1")
        path.write_bytes(b"")
        with pytest.raises(capture.CaptureError, match=reason):
            tail.poll(MemoryWriter())
    finally:
        tail.close()


def test_record_limit_still_allows_gap_and_capture_end(tmp_path):
    path = tmp_path / "evidence.jsonl"
    writer = capture.Writer(path, 1)
    try:
        writer.emit("capture_start")
        with pytest.raises(capture.CaptureError, match="record_limit"):
            writer.emit("nginx_line", line="x")
        writer.gap("record_limit_reached")
        writer.emit("capture_end", force=True, complete=False)
    finally:
        writer.file.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["kind"] for row in rows] == ["capture_start", "gap", "capture_end"]
    assert len({row["capture_id"] for row in rows}) == 1
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        capture.Writer(path, 10)


def test_oversized_line_is_not_exported(tmp_path):
    path = tmp_path / "nginx.log"
    path.write_bytes(b"")
    tail = capture.LogTail(path, 2 * capture.MAX_LINE)
    try:
        path.write_bytes(b"x" * (capture.MAX_LINE + 1) + b"\n")
        writer = MemoryWriter()
        with pytest.raises(capture.CaptureError, match="oversized"):
            tail.poll(writer)
        assert not writer.records
    finally:
        tail.close()


def continuous_config(tmp_path, **extra):
    return {"nginx_log": str(tmp_path / "nginx.log"), "backend_ip": "79.140.26.181",
            "backend_port": 45451, "listener_ip": None, "listener_port": 45451,
            "nginx_utc_offset_minutes": 0, **extra}


def wait_for(predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.005)
    raise AssertionError("capture did not reach expected state")


class FakeSession:
    def __init__(self, config, writer):
        self.writer, self.closed = writer, False
        self.ready, self.fail = threading.Event(), None
        self.emitted_dump = False
        writer.emit("capture_start", previous_epoch_error=writer.previous_error)

    def poll(self, wait=0.1, checkpoint=True):
        self.ready.wait(min(wait, 0.01))
        if self.fail:
            raise self.fail
        if not self.ready.is_set() or not checkpoint:
            return False
        if not self.emitted_dump:
            self.writer.emit("snapshot_end", lifecycle_complete=False)
            self.writer.emit("nginx_line", line="an actually observed line")
            self.emitted_dump = True
        return True

    def close(self):
        self.closed = True


def start_fake_capture(monkeypatch, tmp_path, **config):
    sessions = []

    def factory(config, writer):
        session = FakeSession(config, writer)
        sessions.append(session)
        return session

    monkeypatch.setattr(capture, "CaptureSession", factory)
    stop = threading.Event()
    observer = capture.ContinuousCapture(continuous_config(tmp_path, **config), stop).start()
    wait_for(lambda: sessions)
    return observer, stop, sessions


def stop_capture(observer, stop):
    stop.set()
    observer.join(2)
    assert not observer._thread.is_alive()


def test_continuous_waits_for_real_drain_and_snapshot_is_immutable(monkeypatch, tmp_path):
    observer, stop, sessions = start_fake_capture(monkeypatch, tmp_path)
    try:
        assert observer.snapshot()["healthy"] is False
        assert observer.snapshot()["checkpoint_utc"] is None
        assert observer.snapshot()["records"] == []
        sessions[0].ready.set()
        snapshot = wait_for(lambda: observer.snapshot() if observer.snapshot()["healthy"] else None)
        assert [r["kind"] for r in snapshot["records"]] == [
            "capture_start", "snapshot_end", "nginx_line", "capture_end"]
        assert snapshot["records"][-1]["complete"] is True
        assert snapshot["records"][-1]["checkpoint"] is True
        assert snapshot["records"][-1]["snapshot_of_open_epoch"] is True
        assert snapshot["checkpoint_utc"] == snapshot["records"][-1]["observed_utc"]
        checkpoint = snapshot["checkpoint_utc"]
        snapshot["records"][2]["line"] = "caller mutated its copy"
        # Reading the snapshot must not forge a fresh end timestamp.
        assert observer.snapshot()["checkpoint_utc"] == checkpoint
        assert observer.snapshot()["records"][2]["line"] == "an actually observed line"
        assert len(sessions) == 1
        observer.start()  # Idempotent; no second subscription thread.
        assert len(sessions) == 1
    finally:
        stop_capture(observer, stop)
    assert sessions[0].closed
    assert observer.snapshot()["healthy"] is False
    assert observer.snapshot()["error"] == "capture_stopped"


def test_stale_checkpoint_is_unavailable_without_forging_new_boundary(monkeypatch, tmp_path):
    observer, stop, sessions = start_fake_capture(monkeypatch, tmp_path)
    try:
        sessions[0].ready.set()
        wait_for(lambda: observer.snapshot()["healthy"])
        checkpoint = observer.snapshot()["checkpoint_utc"]
        sessions[0].ready.clear()  # Inputs no longer drain.
        observer._clock = lambda: time.monotonic() + 11
        snapshot = observer.snapshot()
        assert not snapshot["healthy"]
        assert snapshot["error"] == "capture_checkpoint_stale"
        assert snapshot["checkpoint_utc"] == checkpoint
        assert snapshot["records"] == []
    finally:
        stop_capture(observer, stop)


@pytest.mark.parametrize("error,reason", [
    (capture.CaptureError("nginx_log_rotated"), "nginx_log_rotated"),
    (capture.CaptureError("nginx_log_truncated"), "nginx_log_truncated"),
    (OSError(capture.errno.ENOBUFS, "lost events"), "netlink_enobufs"),
    (capture.CaptureError("nginx_scoped_namespace_not_observed"), "nginx_scoped_namespace_not_observed"),
    (capture.CaptureError("record_limit_reached"), "record_limit_reached"),
])
def test_detected_gap_withdraws_old_checkpoint_and_restarts_epoch(monkeypatch, tmp_path, error, reason):
    observer, stop, sessions = start_fake_capture(monkeypatch, tmp_path)
    try:
        sessions[0].ready.set()
        wait_for(lambda: observer.snapshot()["healthy"])
        old_epoch = observer.snapshot()["epoch"]
        sessions[0].fail = error
        wait_for(lambda: observer.snapshot()["error"] == reason)
        assert not observer.snapshot()["healthy"]
        assert observer.snapshot()["records"] == []
        wait_for(lambda: len(sessions) == 2)
        assert sessions[0].closed
        assert observer.snapshot()["epoch"] != old_epoch
        assert not observer.snapshot()["healthy"]
        sessions[1].ready.set()
        snapshot = wait_for(lambda: observer.snapshot() if observer.snapshot()["healthy"] else None)
        assert snapshot["records"][0]["previous_epoch_error"] == reason
        assert all(row["capture_id"] == snapshot["epoch"] for row in snapshot["records"])
    finally:
        stop_capture(observer, stop)


def test_epoch_duration_is_bounded_and_old_history_not_reused(monkeypatch, tmp_path):
    observer, stop, sessions = start_fake_capture(monkeypatch, tmp_path, epoch_seconds=10)
    try:
        sessions[0].ready.set()
        wait_for(lambda: observer.snapshot()["healthy"])
        old_epoch = observer.snapshot()["epoch"]
        observer._clock = lambda: time.monotonic() + 11
        wait_for(lambda: observer.snapshot()["error"] == "epoch_time_limit_reached")
        assert observer.snapshot()["records"] == []
        wait_for(lambda: len(sessions) == 2)
        assert sessions[0].closed
        assert observer.snapshot()["epoch"] != old_epoch
    finally:
        stop_capture(observer, stop)


def test_memory_record_and_byte_bounds_and_input_immutability():
    writer = capture.MemoryWriter(2, 100000)
    value = {"nested": [1]}
    writer.emit("capture_start", value=value)
    value["nested"].append(2)
    assert writer.records[0]["value"] == {"nested": [1]}
    writer.emit("snapshot_end")
    with pytest.raises(capture.CaptureError, match="record_limit_reached"):
        writer.emit("anything")
    assert len(writer.records) == 2
    bounded = capture.MemoryWriter(100, 300)
    with pytest.raises(capture.CaptureError, match="memory_byte_limit_reached"):
        bounded.emit("nginx_line", line="x" * 301)
    assert bounded.records == [] and bounded.bytes == 0


def test_config_defaults_and_invalid_limits(tmp_path):
    config = capture.capture_config(continuous_config(tmp_path))
    assert config["max_records"] == 100000
    assert config["max_log_bytes"] == 64 * 1024 * 1024
    assert config["epoch_seconds"] == 900
    for bad in ({"nginx_log": "relative"}, {"max_records": 99}, {"backend_port": True},
                {"epoch_seconds": 0}, {"max_log_bytes": 129 * 1024 * 1024}):
        with pytest.raises(ValueError):
            capture.capture_config(continuous_config(tmp_path, **bad))


def test_linux_config_keeps_posix_path_when_validated_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(capture, "Path", PureWindowsPath)
    cfg = capture.capture_config(continuous_config(tmp_path, nginx_log="/srv/npm/data/logs/stream.log"))
    assert cfg["nginx_log"] == "/srv/npm/data/logs/stream.log"
    native = capture.capture_config(continuous_config(tmp_path, nginx_log=r"C:\capture\stream.log"))
    assert native["nginx_log"] == r"C:\capture\stream.log"
    with pytest.raises(ValueError, match="absolute"):
        capture.capture_config(continuous_config(tmp_path, nginx_log=r"capture\stream.log"))


class FakeSocket:
    def __init__(self):
        self.queue, self.closed = [], False

    def recvmsg(self, limit):
        return self.queue.pop(0), [], 0, (0, 0)

    def close(self):
        self.closed = True


def native_session(monkeypatch, tmp_path):
    path = tmp_path / "nginx.log"
    path.write_text("")
    session = capture.CaptureSession.__new__(capture.CaptureSession)
    session.writer = capture.MemoryWriter(100, 100000)
    session.tail = capture.LogTail(path, 100000)
    session.events, session.dump = FakeSocket(), FakeSocket()
    session.sockets = [session.events, session.dump]
    session.dump_done, session.seq = False, 7
    session.backend = {"ip": "79.140.26.181", "port": 45451}
    session.began, session.began_wall = time.monotonic(), time.time()
    session.next_process_check, session.dump_deadline = time.monotonic() + 1, time.monotonic() + 10
    processes = [process(1000, 1, 1)]
    session.process_tracker = capture.ProcessTracker(processes)
    monkeypatch.setattr(capture, "nginx_processes", lambda: processes.copy())
    monkeypatch.setattr(capture.select, "select", lambda inputs, *args: ([s for s in inputs if s.queue], [], []))
    return session, path, processes


def message(kind, body=b"", seq=7):
    return struct.pack("=IHHII", 16 + len(body), kind, 0, seq, 0) + body


def test_native_drain_requires_dump_done_empty_queues_and_complete_log(monkeypatch, tmp_path):
    session, path, _ = native_session(monkeypatch, tmp_path)
    try:
        assert not session.poll(wait=0)
        assert session.writer.records == []
        session.dump.queue.append(message(3))
        path.write_text("unfinished")
        assert not session.poll(wait=0)
        assert session.dump_done and session.dump.closed
        with path.open("a") as log:
            log.write(" line\n")
        body, _ = conn_event()
        session.events.queue.extend([message(0x100, body), message(0x102, body)])
        assert not session.poll(wait=0)  # One queued datagram remains.
        assert session.poll(wait=0)
        assert [row["kind"] for row in session.writer.records] == [
            "snapshot_end", "nginx_line", "conntrack", "conntrack"]
        assert not session.events.queue
    finally:
        session.close()


def test_native_worker_turnover_preserves_epoch_but_reuse_invalidates(monkeypatch, tmp_path):
    session, _, processes = native_session(monkeypatch, tmp_path)
    try:
        session.dump.queue.append(message(3))
        assert session.poll(wait=0)
        worker = process(1001, 2, 2)
        processes.append(worker)
        assert session.poll(wait=0)
        processes.remove(worker)
        assert session.poll(wait=0)
        assert len([r for r in session.writer.records if r["kind"] == "nginx_process_change"]) == 2
        processes.append(process(1005, 2, 99))
        with pytest.raises(capture.CaptureError, match="pid_reused"):
            session.poll(wait=0)
    finally:
        session.close()


def test_native_clock_step_prevents_checkpoint(monkeypatch, tmp_path):
    session, _, _ = native_session(monkeypatch, tmp_path)
    try:
        session.dump.queue.append(message(3))
        session.began_wall -= 10
        with pytest.raises(capture.CaptureError, match="host_clock_stepped"):
            session.poll(wait=0)
    finally:
        session.close()


def test_standalone_compatibility_entry_point_help():
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], text=True, capture_output=True)
    assert result.returncode == 0
    assert "--nginx-log" in result.stdout
    assert "--backend-ip" in result.stdout


def test_gap_detected_while_copying_cannot_return_old_healthy_snapshot(monkeypatch, tmp_path):
    observer, stop, sessions = start_fake_capture(monkeypatch, tmp_path)
    try:
        sessions[0].ready.set()
        wait_for(lambda: observer.snapshot()["healthy"])
        sessions[0].ready.clear()
        original_copy = capture.deepcopy

        def copy_during_gap(value):
            result = original_copy(value)
            observer._unavailable("netlink_enobufs")
            return result

        monkeypatch.setattr(capture, "deepcopy", copy_during_gap)
        result = observer.snapshot()
        assert result["healthy"] is False
        assert result["error"] == "netlink_enobufs"
        assert result["records"] == []
    finally:
        stop_capture(observer, stop)
