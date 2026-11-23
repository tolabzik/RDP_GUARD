#!/usr/bin/env python3
"""Bounded, read-only Linux evidence capture. Never changes firewall or services.

JSONL is diagnostic evidence, not authorization to ban an address. A successful
capture means no loss was detected, not that the kernel/log transport is lossless.
Requires Linux conntrack read privileges and access to the selected nginx log.
"""

import argparse
from datetime import datetime, timezone
import errno
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import time
import uuid


NETLINK_NETFILTER = 12
CT_GET = 0x101
CT_DELETE = 0x102
NLM_F_REQUEST_DUMP = 0x301
NLM_F_DUMP_INTR = 0x10
NLM_F_CREATE = 0x400
MAX_LINE = 65536


class CaptureError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def attributes(data):
    """Decode netlink attributes strictly; malformed input is a capture gap."""
    result, pos = {}, 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise CaptureError("truncated_netlink_attribute")
        size, kind = struct.unpack_from("=HH", data, pos)
        if size < 4 or pos + size > len(data):
            raise CaptureError("invalid_netlink_attribute")
        kind &= 0x3fff
        if kind in result:
            raise CaptureError("duplicate_netlink_attribute")
        result[kind] = data[pos + 4:pos + size]
        pos += (size + 3) & ~3
    return result


def tuple_from(data):
    top = attributes(data)
    ips, proto = attributes(top.get(1, b"")), attributes(top.get(2, b""))
    family = socket.AF_INET if 1 in ips else socket.AF_INET6
    src_key, dst_key = (1, 2) if family == socket.AF_INET else (3, 4)
    try:
        return {
            "src": socket.inet_ntop(family, ips[src_key]),
            "dst": socket.inet_ntop(family, ips[dst_key]),
            "protocol": proto[1][0],
            "sport": struct.unpack("!H", proto[2])[0],
            "dport": struct.unpack("!H", proto[3])[0],
        }
    except (KeyError, IndexError, ValueError, OSError, struct.error):
        return None  # Non-TCP entries need not have transport ports.


def netlink_messages(data):
    pos = 0
    while pos < len(data):
        if len(data) - pos < 16:
            raise CaptureError("truncated_netlink_message")
        size, kind, flags, seq, pid = struct.unpack_from("=IHHII", data, pos)
        if size < 16 or pos + size > len(data):
            raise CaptureError("invalid_netlink_message")
        yield kind, flags, seq, pid, data[pos + 16:pos + size]
        pos += (size + 3) & ~3


def check_dump_done(body):
    # Some kernels send an empty legacy DONE; modern replies contain an errno.
    if body and len(body) < 4:
        raise CaptureError("malformed_conntrack_dump_done")
    if len(body) >= 4 and struct.unpack_from("=i", body)[0]:
        raise CaptureError("conntrack_dump_failed")


def decode_conntrack(kind, flags, body, backend, snapshot=False):
    if kind not in (0x100, CT_DELETE) or len(body) < 4:
        return None
    top = attributes(body[4:])
    original = tuple_from(top[1]) if 1 in top else None
    reply = tuple_from(top[2]) if 2 in top else None
    if not original or original["protocol"] != 6:
        return None
    if (original["dst"], original["dport"]) != (backend["ip"], backend["port"]):
        return None
    if not reply or reply["protocol"] != 6:
        raise CaptureError("target_conntrack_reply_missing")
    operation = "snapshot" if snapshot else (
        "destroy" if kind == CT_DELETE else "new" if flags & NLM_F_CREATE else "update")
    return {
        "operation": operation, "original": original, "reply": reply,
        "conntrack_id": struct.unpack("!I", top[12])[0] if len(top.get(12, b"")) == 4 else None,
        "zone": struct.unpack("!H", top[18])[0] if len(top.get(18, b"")) == 2 else 0,
    }


def nginx_processes(proc_root=Path("/proc")):
    """Metadata only. Never reads process command lines or environment secrets."""
    result = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() not in ("nginx", "openresty"):
                continue
            stat = (entry / "stat").read_text()
            # Fields after the final ')' begin at proc(5) field 3.
            start_ticks = int(stat[stat.rfind(")") + 2:].split()[19])
            status = (entry / "status").read_text().splitlines()
            ns_pids = next((list(map(int, x.split()[1:])) for x in status if x.startswith("NSpid:")), [])
            result.append({"host_pid": int(entry.name), "namespace_pids": ns_pids,
                           "start_ticks": start_ticks, "pid_namespace": os.readlink(entry / "ns/pid")})
        except (OSError, ValueError, IndexError):
            continue  # Process may exit while /proc is being read.
    return sorted(result, key=lambda item: item["host_pid"])


class Writer:
    def __init__(self, path, limit):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.file = os.fdopen(fd, "w", encoding="utf-8")
        self.capture_id, self.count, self.limit = str(uuid.uuid4()), 0, limit
        self.gaps = []

    def emit(self, kind, force=False, **values):
        if self.count >= self.limit and not force:
            raise CaptureError("record_limit_reached")
        item = {"kind": kind, "capture_id": self.capture_id, "observed_utc": utc_now(),
                "monotonic_ns": time.monotonic_ns(), **values}
        self.file.write(json.dumps(item, ensure_ascii=True, separators=(",", ":")) + "\n")
        self.file.flush()
        self.count += 1

    def gap(self, reason):
        self.gaps.append(reason)
        self.emit("gap", force=True, reason=reason)


class LogTail:
    def __init__(self, path, byte_limit):
        self.path, self.file = Path(path), open(path, "rb")
        info = os.fstat(self.file.fileno())
        self.identity = (info.st_dev, info.st_ino)
        self.file.seek(0, os.SEEK_END)
        self.offset = self.file.tell()
        self.discard_partial = False
        if self.offset:
            self.file.seek(self.offset - 1)
            self.discard_partial = self.file.read(1) != b"\n"
        self.buffer, self.read_bytes, self.byte_limit = b"", 0, byte_limit

    def poll(self, writer):
        info = self.path.stat()
        if (info.st_dev, info.st_ino) != self.identity:
            raise CaptureError("nginx_log_rotated")
        if info.st_size < self.file.tell():
            raise CaptureError("nginx_log_truncated")
        data = self.file.read(1024 * 1024)
        self.read_bytes += len(data)
        if self.read_bytes > self.byte_limit:
            raise CaptureError("log_byte_limit_reached")
        self.buffer += data
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            offset, self.offset = self.offset, self.offset + len(line) + 1
            if self.discard_partial:
                self.discard_partial = False
                continue
            if len(line) > MAX_LINE:
                raise CaptureError("oversized_nginx_line")
            try:
                text = line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CaptureError("invalid_nginx_utf8") from exc
            writer.emit("nginx_line", line=text, source_inode=self.identity[1], offset=offset)
        if len(self.buffer) > MAX_LINE:
            raise CaptureError("oversized_partial_nginx_line")

    def close(self):
        self.file.close()


def open_netlink(groups):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        # Do not enable NETLINK_NO_ENOBUFS: dropped events must remain visible.
        sock.bind((0, groups))
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


def run(args):
    backend = {"ip": str(ipaddress.ip_address(args.backend_ip)), "port": args.backend_port}
    writer = Writer(args.output, args.max_records)
    sockets, tail, complete = [], None, False
    began = time.monotonic()
    began_wall = time.time()
    first_processes = []
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        first_processes = nginx_processes()
        writer.emit(
            "capture_start", backend=backend,
            listener={"ip": args.listener_ip, "port": args.listener_port},
            nginx_utc_offset_minutes=args.nginx_utc_offset_minutes, boot_id=boot_id,
            nginx_processes=first_processes, nginx_log=str(Path(args.nginx_log).absolute()),
            duration_seconds=args.duration, initial_snapshot_lifecycle_complete=False,
            nginx_start_at_eof=True,
            limitations=["Diagnostic only; no blocking.", "No detected gap does not prove lossless capture.",
                         "Container PID and host PID namespaces differ; process metadata is informational."],
        )
        event_setting = Path("/proc/sys/net/netfilter/nf_conntrack_events")
        if event_setting.exists() and event_setting.read_text().strip() == "0":
            raise CaptureError("kernel_conntrack_events_disabled")
        tail = LogTail(args.nginx_log, args.max_log_bytes)
        # Subscribe first. The snapshot can overlap queued events; downstream must deduplicate.
        events = open_netlink(7)  # NFNLGRP_CONNTRACK_{NEW,UPDATE,DESTROY}.
        sockets.append(events)
        dump = open_netlink(0)
        sockets.append(dump)
        seq = int(time.time_ns() & 0xffffffff) or 1
        family = socket.AF_INET if ipaddress.ip_address(args.backend_ip).version == 4 else socket.AF_INET6
        payload = struct.pack("=BBH", family, 0, 0)
        request = struct.pack("=IHHII", 16 + len(payload), CT_GET, NLM_F_REQUEST_DUMP, seq, 0) + payload
        dump.sendto(request, (0, 0))
        dump_deadline, dump_done = time.monotonic() + 10, False
        end = began + args.duration
        next_process_check = time.monotonic() + 1
        while True:
            cutoff = time.monotonic() >= end
            if cutoff and time.monotonic() > end + 0.5:
                raise CaptureError("cutoff_backlog_not_drained")
            tail.poll(writer)
            if not dump_done and time.monotonic() > dump_deadline:
                raise CaptureError("initial_conntrack_dump_timeout")
            ready, _, _ = select.select(
                sockets, [], [], 0 if cutoff else min(0.1, max(0, end - time.monotonic())))
            for sock in ready:
                chunk, _, message_flags, sender = sock.recvmsg(1024 * 1024)
                if sender[0] != 0:
                    raise CaptureError("unexpected_netlink_sender")
                if message_flags & socket.MSG_TRUNC:
                    raise CaptureError("truncated_netlink_datagram")
                for kind, flags, msg_seq, _, body in netlink_messages(chunk):
                    if flags & NLM_F_DUMP_INTR:
                        raise CaptureError("interrupted_conntrack_dump")
                    is_dump = sock is dump
                    if is_dump and msg_seq != seq:
                        raise CaptureError("unexpected_dump_sequence")
                    if kind == 2:  # NLMSG_ERROR
                        code = struct.unpack_from("=i", body)[0]
                        if code:
                            raise OSError(-code, "conntrack query")
                        continue
                    if kind == 3:  # NLMSG_DONE
                        if is_dump:
                            check_dump_done(body)
                            dump_done = True
                            writer.emit("snapshot_end", lifecycle_complete=False)
                            sockets.remove(dump)
                            dump.close()
                        continue
                    if kind == 4:  # NLMSG_OVERRUN
                        raise CaptureError("netlink_overrun")
                    item = decode_conntrack(kind, flags, body, backend, is_dump)
                    if item:
                        writer.emit("conntrack", **item)
            if time.monotonic() >= next_process_check:
                if abs((time.time() - began_wall) - (time.monotonic() - began)) > 1:
                    raise CaptureError("host_clock_stepped")
                if nginx_processes() != first_processes:
                    raise CaptureError("nginx_process_set_changed")
                next_process_check = time.monotonic() + 1
            if cutoff and not ready and os.fstat(tail.file.fileno()).st_size == tail.file.tell():
                if tail.buffer:
                    raise CaptureError("partial_nginx_line_at_cutoff")
                break
        if not dump_done:
            raise CaptureError("initial_dump_incomplete")
        if abs((time.time() - began_wall) - (time.monotonic() - began)) > 1:
            raise CaptureError("host_clock_stepped")
        if nginx_processes() != first_processes:
            raise CaptureError("nginx_process_set_changed")
        complete = True
    except KeyboardInterrupt:
        writer.gap("interrupted_by_operator")
    except (CaptureError, OSError, ValueError, struct.error) as exc:
        reason = "netlink_enobufs" if isinstance(exc, OSError) and exc.errno == errno.ENOBUFS else str(exc)
        writer.gap(reason)
    finally:
        for sock in sockets:
            sock.close()
        if tail:
            tail.close()
        writer.emit("capture_end", force=True, complete=complete and not writer.gaps,
                    elapsed_seconds=round(time.monotonic() - began, 3), gaps=writer.gaps,
                    records_before_end=writer.count, trailing_partial_log_line=bool(tail and tail.buffer),
                    completeness_scope="No detected capture loss; not a security guarantee.")
        writer.file.close()
    print(json.dumps({"output": str(Path(args.output).absolute()), "capture_id": writer.capture_id,
                      "complete": complete and not writer.gaps, "gaps": writer.gaps}))
    return 0 if complete and not writer.gaps else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-log", required=True)
    parser.add_argument("--backend-ip", required=True, type=lambda value: str(ipaddress.ip_address(value)))
    parser.add_argument("--backend-port", required=True, type=int)
    parser.add_argument("--listener-ip", default=None)
    parser.add_argument("--listener-port", required=True, type=int)
    parser.add_argument("--nginx-utc-offset-minutes", required=True, type=int)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--output", required=True, help="New JSONL file; existing files are never overwritten.")
    parser.add_argument("--max-records", type=int, default=100000)
    parser.add_argument("--max-log-bytes", type=int, default=32 * 1024 * 1024)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This capture must run on Linux.")
    if not 1 <= args.duration <= 300:
        parser.error("duration must be between 1 and 300 seconds")
    if any(not 1 <= port <= 65535 for port in (args.backend_port, args.listener_port)):
        parser.error("ports must be between 1 and 65535")
    if not -840 <= args.nginx_utc_offset_minutes <= 840:
        parser.error("nginx UTC offset must be between -840 and 840 minutes")
    if not 100 <= args.max_records <= 1000000 or not MAX_LINE <= args.max_log_bytes <= 128 * 1024 * 1024:
        parser.error("record or byte limit is outside supported bounds")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
