#!/usr/bin/env python3
"""Bounded, read-only Linux evidence capture. Never changes firewall or services.

JSONL is diagnostic evidence, not authorization to ban an address. A successful
capture means no loss was detected, not that the kernel/log transport is lossless.
Requires Linux conntrack read privileges and access to the selected nginx log.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import errno
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import select
import socket
import struct
import sys
import threading
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


class ProcessTracker:
    """Allow graceful worker turnover while refusing a reused log PID identity."""
    def __init__(self, processes, namespace=None):
        namespaces = {item["pid_namespace"] for item in processes}
        if namespace is None:
            if len(namespaces) != 1:
                raise CaptureError("nginx_pid_namespace_missing_or_ambiguous")
            namespace = next(iter(namespaces))
        self.namespace, self.seen, self.current = namespace, {}, {}
        self.observe(processes)

    def observe(self, processes):
        selected = [item for item in processes if item["pid_namespace"] == self.namespace]
        if not selected:
            raise CaptureError("nginx_scoped_namespace_not_observed")
        current = {}
        for item in selected:
            if not item["namespace_pids"]:
                raise CaptureError("nginx_namespace_pid_missing")
            key = (self.namespace, item["namespace_pids"][-1])
            identity = (item["start_ticks"], item["host_pid"])
            if key in current:
                raise CaptureError("duplicate_nginx_namespace_pid")
            if key in self.seen and self.seen[key] != identity:
                raise CaptureError("nginx_namespace_pid_reused")
            self.seen[key] = identity  # Retain exited PIDs for the entire capture.
            current[key] = item
        added = [current[key] for key in current.keys() - self.current.keys()]
        removed = [self.current[key] for key in self.current.keys() - current.keys()]
        self.current = current
        return {"added": sorted(added, key=lambda item: item["host_pid"]),
                "removed": sorted(removed, key=lambda item: item["host_pid"])} if added or removed else None

    def snapshot(self):
        return sorted(self.current.values(), key=lambda item: item["host_pid"])


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


class MemoryWriter:
    """One bounded epoch; records are immutable after emission."""
    def __init__(self, limit, byte_limit, previous_error=""):
        self.capture_id = str(uuid.uuid4())
        self.limit, self.byte_limit = limit, byte_limit
        self.previous_error = previous_error
        self.records, self.gaps = [], []
        self.bytes = 0

    def emit(self, kind, force=False, **values):
        item = {"kind": kind, "capture_id": self.capture_id, "observed_utc": utc_now(),
                "monotonic_ns": time.monotonic_ns(), **deepcopy(values)}
        size = len(json.dumps(item, ensure_ascii=True).encode("utf-8"))
        if not force and len(self.records) >= self.limit:
            raise CaptureError("record_limit_reached")
        if not force and self.bytes + size > self.byte_limit:
            raise CaptureError("memory_byte_limit_reached")
        # Forced records are reserved for a single gap and final boundary.
        if force and len(self.records) >= self.limit + 2:
            raise CaptureError("forced_record_limit_reached")
        self.records.append(item)
        self.bytes += size

    def gap(self, reason):
        self.gaps.append(reason)
        self.emit("gap", force=True, reason=reason)

    def checkpoint(self):
        """Caller must have drained actual inputs before constructing this boundary."""
        end = {"kind": "capture_end", "capture_id": self.capture_id, "observed_utc": utc_now(),
               "monotonic_ns": time.monotonic_ns(), "complete": not self.gaps,
               "checkpoint": True, "snapshot_of_open_epoch": True, "gaps": list(self.gaps),
               "records_before_end": len(self.records),
               "completeness_scope": "Drained observed inputs; not a security guarantee."}
        return self.records.copy() + [end]


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


class CaptureSession:
    """One native observation epoch. A checkpoint requires both inputs drained.

    The event socket remains open throughout the epoch; repeated snapshots do
    not reopen subscriptions or discard lifecycle history. Polling does not
    establish a lossless transport guarantee or validate connection lifecycles.
    """
    def __init__(self, config, writer):
        self.config, self.writer = config, writer
        self.sockets, self.tail = [], None
        self.began, self.began_wall = time.monotonic(), time.time()
        self.dump_done = False
        self.backend = {"ip": config["backend_ip"], "port": config["backend_port"]}
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _open(self):
        if not sys.platform.startswith("linux"):
            raise CaptureError("linux_capture_required")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.process_tracker = ProcessTracker(nginx_processes(), self.config.get("nginx_pid_namespace"))
        self.writer.emit(
            "capture_start", backend=self.backend,
            listener={"ip": self.config.get("listener_ip"), "port": self.config["listener_port"]},
            nginx_utc_offset_minutes=self.config["nginx_utc_offset_minutes"], boot_id=boot_id,
            nginx_processes=self.process_tracker.snapshot(),
            nginx_pid_namespace=self.process_tracker.namespace,
            nginx_log=self.config["nginx_log"], epoch_seconds=self.config.get("epoch_seconds"),
            previous_epoch_error=getattr(self.writer, "previous_error", ""),
            initial_snapshot_lifecycle_complete=False, nginx_start_at_eof=True,
            limitations=["Diagnostic only; no blocking.", "No detected gap does not prove lossless capture.",
                         "Process snapshots are sampled; short-lived processes may be missed.",
                         "The caller must scope the PID namespace to the nginx instance writing this log."],
        )
        event_setting = Path("/proc/sys/net/netfilter/nf_conntrack_events")
        if event_setting.exists() and event_setting.read_text().strip() == "0":
            raise CaptureError("kernel_conntrack_events_disabled")
        self.tail = LogTail(self.config["nginx_log"], self.config["max_log_bytes"])
        # Subscribe before dumping. Consumers must deduplicate overlapping observations.
        self.events = open_netlink(7)
        self.sockets.append(self.events)
        self.dump = open_netlink(0)
        self.sockets.append(self.dump)
        self.seq = int(time.time_ns() & 0xffffffff) or 1
        family = socket.AF_INET if ipaddress.ip_address(self.backend["ip"]).version == 4 else socket.AF_INET6
        payload = struct.pack("=BBH", family, 0, 0)
        request = struct.pack("=IHHII", 16 + len(payload), CT_GET, NLM_F_REQUEST_DUMP, self.seq, 0) + payload
        self.dump.sendto(request, (0, 0))
        self.dump_deadline, self.next_process_check = time.monotonic() + 10, time.monotonic() + 1

    def _read(self, sock):
        try:
            chunk, _, message_flags, sender = sock.recvmsg(1024 * 1024)
        except BlockingIOError:
            return
        if sender[0] != 0:
            raise CaptureError("unexpected_netlink_sender")
        if message_flags & socket.MSG_TRUNC:
            raise CaptureError("truncated_netlink_datagram")
        for kind, flags, msg_seq, _, body in netlink_messages(chunk):
            if flags & NLM_F_DUMP_INTR:
                raise CaptureError("interrupted_conntrack_dump")
            is_dump = sock is self.dump
            if is_dump and msg_seq != self.seq:
                raise CaptureError("unexpected_dump_sequence")
            if kind == 2:
                if len(body) < 4:
                    raise CaptureError("malformed_netlink_error")
                code = struct.unpack_from("=i", body)[0]
                if code:
                    raise OSError(-code, "conntrack query")
                continue
            if kind == 3:
                if is_dump:
                    if self.dump_done:
                        raise CaptureError("duplicate_conntrack_dump_done")
                    check_dump_done(body)
                    self.dump_done = True
                    self.writer.emit("snapshot_end", lifecycle_complete=False)
                    self.sockets.remove(self.dump)
                    self.dump.close()
                continue
            if kind == 4:
                raise CaptureError("netlink_overrun")
            item = decode_conntrack(kind, flags, body, self.backend, is_dump)
            if item:
                self.writer.emit("conntrack", **item)

    def _validate_host(self, force=False):
        now = time.monotonic()
        if abs((time.time() - self.began_wall) - (now - self.began)) > 1:
            raise CaptureError("host_clock_stepped")
        if force or now >= self.next_process_check:
            changes = self.process_tracker.observe(nginx_processes())
            if changes:
                self.writer.emit("nginx_process_change", pid_namespace=self.process_tracker.namespace, **changes)
                self.writer.emit("nginx_process_snapshot", pid_namespace=self.process_tracker.namespace,
                                 nginx_processes=self.process_tracker.snapshot())
            self.next_process_check = now + 1

    def _drained(self):
        if not self.dump_done or self.tail.buffer or self.tail.discard_partial:
            return False
        info = self.tail.path.stat()
        if (info.st_dev, info.st_ino) != self.tail.identity:
            raise CaptureError("nginx_log_rotated")
        if info.st_size < self.tail.file.tell():
            raise CaptureError("nginx_log_truncated")
        return (info.st_size == self.tail.file.tell()
                and not select.select(self.sockets, [], [], 0)[0])

    def poll(self, wait=0.1, checkpoint=True):
        """Read available evidence; return true only at an observed drained boundary."""
        self.tail.poll(self.writer)
        if not self.dump_done and time.monotonic() > self.dump_deadline:
            raise CaptureError("initial_conntrack_dump_timeout")
        ready, _, _ = select.select(self.sockets, [], [], wait)
        for sock in ready:
            self._read(sock)
        self._validate_host()
        if not checkpoint or not self._drained():
            return False
        # Revalidate processes and drain the log again after the /proc scan. A
        # publisher may only stamp a boundary after this second readiness check.
        self._validate_host(force=True)
        self.tail.poll(self.writer)
        return self._drained()

    def close(self):
        for sock in self.sockets:
            sock.close()
        self.sockets = []
        if self.tail is not None:
            self.tail.close()
            self.tail = None


def capture_config(config):
    """Validate the small shared contract without performing any host operations."""
    result = dict(config)
    path = Path(result["nginx_log"])
    posix_path = PurePosixPath(result["nginx_log"])
    if not (posix_path.is_absolute() or path.is_absolute()):
        raise ValueError("nginx_log must be an absolute path")
    # Linux configs are also inspected on Windows build/bootstrap hosts. Do not
    # turn a valid /srv/... host path into a Windows rooted-relative \\srv\\... path.
    result["nginx_log"] = str(posix_path if posix_path.is_absolute() else path)
    result["backend_ip"] = str(ipaddress.ip_address(result["backend_ip"]))
    if result.get("listener_ip") is not None:
        result["listener_ip"] = str(ipaddress.ip_address(result["listener_ip"]))
    for name in ("backend_port", "listener_port"):
        if type(result[name]) is not int or not 1 <= result[name] <= 65535:
            raise ValueError(f"{name} must be an integer between 1 and 65535")
    offset = result["nginx_utc_offset_minutes"]
    if type(offset) is not int or not -840 <= offset <= 840:
        raise ValueError("nginx_utc_offset_minutes must be an integer between -840 and 840")
    for name, default, minimum, maximum in (
        ("max_records", 100000, 100, 1000000),
        ("max_log_bytes", 64 * 1024 * 1024, MAX_LINE, 128 * 1024 * 1024),
        ("epoch_seconds", 900, 1, 86400),
    ):
        result.setdefault(name, default)
        if type(result[name]) is not int or not minimum <= result[name] <= maximum:
            raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    namespace = result.get("nginx_pid_namespace")
    if namespace is not None and (not isinstance(namespace, str) or not namespace):
        raise ValueError("nginx_pid_namespace must be a nonempty string or null")
    return result


class ContinuousCapture:
    """Persistent, bounded native capture with immutable diagnostic checkpoints.

    A detected gap immediately withdraws the published checkpoint. Recovery
    starts a fresh UUID and starts the log at EOF; history is never joined across
    epochs. A configured namespace stays unavailable if that namespace vanishes.
    With auto selection, a subsequent unambiguous namespace may start a new epoch.
    """
    def __init__(self, config, stop):
        self.config, self.stop = capture_config(config), stop
        self._lock, self._thread = threading.Lock(), None
        self._clock = time.monotonic
        self._state = {"healthy": False, "error": "capture_not_started", "epoch": "",
                       "records": [], "checkpoint_utc": None}
        self._checkpoint_time = None

    def start(self):
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="rdpguard-proxy-capture", daemon=True)
                self._thread.start()
        return self

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)

    def _unavailable(self, error, epoch=None):
        with self._lock:
            self._state = {"healthy": False, "error": error,
                           "epoch": epoch if epoch is not None else self._state["epoch"],
                           "records": [], "checkpoint_utc": None}
            self._checkpoint_time = None

    def _publish(self, writer):
        if writer.gaps:
            raise CaptureError("cannot_checkpoint_epoch_with_gap")
        records = writer.checkpoint()
        with self._lock:
            self._state = {"healthy": True, "error": "", "epoch": writer.capture_id,
                           "records": records, "checkpoint_utc": records[-1]["observed_utc"]}
            self._checkpoint_time = self._clock()

    def snapshot(self):
        # Published records never change. Copy outside the lock so a large
        # diagnostic response cannot prevent the reader from draining netlink.
        with self._lock:
            state, checkpoint_time = self._state, self._checkpoint_time
        result = deepcopy(state)
        with self._lock:
            if (self._state["epoch"] != state["epoch"]
                    or (state["healthy"] and not self._state["healthy"])):
                return {"healthy": False, "error": self._state["error"] or "capture_epoch_changed",
                        "epoch": self._state["epoch"], "records": [], "checkpoint_utc": None}
            if (state["healthy"] and (checkpoint_time is None
                    or self._clock() - checkpoint_time > 10)):
                return {"healthy": False, "error": "capture_checkpoint_stale",
                        "epoch": state["epoch"], "records": [],
                        "checkpoint_utc": state["checkpoint_utc"]}
            return result

    def _run(self):
        previous_error = ""
        try:
            while not self.stop.is_set():
                # Bound serialized state as well as record count and raw log input.
                writer = MemoryWriter(self.config["max_records"],
                                      self.config["max_log_bytes"] + self.config["max_records"] * 1024,
                                      previous_error)
                self._unavailable(previous_error or "capture_initializing", writer.capture_id)
                session = None
                began, next_checkpoint = self._clock(), self._clock()
                try:
                    session = CaptureSession(self.config, writer)
                    while not self.stop.is_set():
                        if self._clock() - began >= self.config["epoch_seconds"]:
                            raise CaptureError("epoch_time_limit_reached")
                        checkpoint = self._clock() >= next_checkpoint
                        if session.poll(wait=0.1, checkpoint=checkpoint):
                            self._publish(writer)
                            next_checkpoint = self._clock() + 1
                except Exception as exc:
                    previous_error = ("netlink_enobufs" if isinstance(exc, OSError) and exc.errno == errno.ENOBUFS
                                      else str(exc) or type(exc).__name__)
                    self._unavailable(previous_error)
                finally:
                    if session is not None:
                        session.close()
                # Explicit unhealthy interval between generations. No old prefix
                # is eligible while initial dump and log subscription are rebuilt.
                if not self.stop.is_set():
                    self.stop.wait(1)
        finally:
            self._unavailable("capture_stopped")


def run(args):
    writer = Writer(args.output, args.max_records)
    config = vars(args).copy()
    config["nginx_log"] = str(Path(args.nginx_log).absolute())
    config["epoch_seconds"] = args.duration
    began, complete, session, trailing_partial = time.monotonic(), False, None, False
    try:
        session = CaptureSession(config, writer)
        end = began + args.duration
        while True:
            cutoff = time.monotonic() >= end
            if cutoff and time.monotonic() > end + 0.5:
                raise CaptureError("cutoff_backlog_not_drained")
            if session.poll(wait=0 if cutoff else min(0.1, max(0, end - time.monotonic())),
                            checkpoint=cutoff):
                complete = True
                break
    except KeyboardInterrupt:
        writer.gap("interrupted_by_operator")
    except (CaptureError, OSError, ValueError, struct.error) as exc:
        reason = "netlink_enobufs" if isinstance(exc, OSError) and exc.errno == errno.ENOBUFS else str(exc)
        writer.gap(reason)
    finally:
        if session is not None:
            trailing_partial = bool(session.tail and session.tail.buffer)
            session.close()
        writer.emit("capture_end", force=True, complete=complete and not writer.gaps,
                    elapsed_seconds=round(time.monotonic() - began, 3), gaps=writer.gaps,
                    records_before_end=writer.count, trailing_partial_log_line=trailing_partial,
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
    parser.add_argument("--nginx-pid-namespace",
                        help="Exact /proc/PID/ns/pid link, e.g. pid:[4026532278]. "
                             "Required when multiple nginx PID namespaces exist.")
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
