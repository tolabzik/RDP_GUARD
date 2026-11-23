"""The diagnostic capture must preserve NAT identity and report evidence gaps."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import struct

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Capture-ProxyEvidence.py"
SPEC = importlib.util.spec_from_file_location("proxy_capture", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


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
