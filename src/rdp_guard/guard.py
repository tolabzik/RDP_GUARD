from contextlib import nullcontext
from dataclasses import asdict
import json
import platform
from pathlib import Path
import threading
import time

from . import __version__
from .events import FAILURE_SOURCES, SECURITY, parse_event
from .firewall import FirewallEngine, owned
from .models import Settings, address, contains, network, overlaps
from . import recovery


def atomic_json(path: Path, value):
    recovery.atomic_document(path, value)


class Guard:
    def __init__(self, store, backend, safety, data_dir: Path, clock=time.time, firewall_lock=nullcontext):
        self.store, self.firewall, self.safety = store, FirewallEngine(backend), safety
        self.data_dir, self.clock, self.firewall_lock = data_dir, clock, firewall_lock
        self.lock = threading.RLock()
        self.settings = Settings.load(store.get("settings", {}))
        self.started = clock()
        self.last_sync = 0
        self.last_cleanup = 0
        self.last_heartbeat = 0
        self.last_health = 0
        self.last_tick = self.started
        self.platform_status = {}
        self.last_error = ""
        self.collectors = {}
        self.service_journal = recovery.ServiceJournal(data_dir)
        self.recovery_status = {"state": "disabled", "reason": "Автовосстановление ещё не подтверждено"}
        self.last_recovery = float("-inf")
        self.emergency_path = data_dir / "emergency.disabled"
        self.lease_path = data_dir / "active-lease.json"
        # Do not renew a stale lease on startup before the independent watchdog can inspect it.
        if self.mode == "ACTIVE":
            try:
                lease = json.loads(self.lease_path.read_text(encoding="utf-8"))
                stale = clock() - lease["heartbeat"] > 45 or lease["heartbeat"] > clock() + 10
            except (OSError, ValueError, KeyError, TypeError):
                stale = True
            if stale:
                self.store.set("mode", "MONITOR ONLY")
                self.store.set("cleanup_requested", True)
                self.store.audit("guard", "stale-startup-lease", {}, clock())
        if recovery.approval(data_dir) and not self.emergency_path.exists():
            # Even a fast reboot/service restart must obtain fresh health and time evidence.
            self.store.set("mode", "MONITOR ONLY")
            self.store.set("cleanup_requested", True)
            self._recovery_state("waiting", "Проверка после запуска службы")

    def _recovery_state(self, state, reason):
        self.recovery_status = {"state": state, "reason": reason, "updated_at": self.clock()}
        self.service_journal.transition("protection", state, reason, now=self.clock())

    def _try_resume(self, force=False):
        consent = recovery.approval(self.data_dir)
        if not consent or self.emergency_path.exists():
            return
        now = self.clock()
        if not force and 0 <= now - self.last_recovery < 15:
            return
        self.last_recovery = now
        try:
            if recovery.maintenance(self.data_dir, now):
                raise RuntimeError("Установка обновления: восстановление временно приостановлено")
            if consent["rdp_port"] != self.settings.rdp_port or not self.trusted(consent["admin_ip"]):
                raise RuntimeError("Изменились RDP-порт или доверенный адрес подтверждения; нужна новая активация")
            health = self.safety.recovery_health(self.settings.rdp_port, [network(consent["admin_ip"])])
            required = ("firewall", "listening", "port_matches", "allow_rules", "watchdog", "audit_logon", "time_sync")
            failed = [key for key in required if health.get(key) is not True]
            if failed:
                raise RuntimeError("Ожидание проверок: " + ", ".join(failed) + "; " + "; ".join(health.get("errors", [])))
            self.protected()  # An empty inventory is valid; an unverifiable one is not.
            if not self.collectors.get(SECURITY, {}).get("healthy"):
                raise RuntimeError("Ожидание подписки на журнал Security")
            from .firewall import GROUP, PREFIX
            if any((r.group == GROUP or r.name.startswith(PREFIX)) and not owned(r)
                   for r in self.firewall.backend.list_rules()):
                raise RuntimeError("Не подтверждена принадлежность правил firewall")
            white = self.store.rows("SELECT network FROM whitelist")
            blocks = self.store.rows("SELECT network FROM blocks WHERE ended IS NULL")
            if any(overlaps(b["network"], w["network"]) for b in blocks for w in white):
                raise RuntimeError("Пересечение белого списка и блокировок")
            recent = self.store.rows("SELECT COUNT(*) n FROM blocks WHERE kind='dynamic' AND created>?", (now - 60,))[0]["n"]
            if recent >= self.settings.max_blocks_per_minute or len(blocks) >= self.settings.max_block_entries:
                raise RuntimeError("Ожидание освобождения лимита блокировок")
            with self.firewall_lock():
                if self.emergency_path.exists() or recovery.approval(self.data_dir) != consent:
                    raise RuntimeError("Разрешение на восстановление отозвано")
                atomic_json(self.lease_path, {"started": now, "deadline": None, "heartbeat": now,
                                              "confirmed": True, "recovered": True})
                with self.store.transaction() as db:
                    # Monitoring decisions must not be promoted into active bans.
                    db.execute("UPDATE blocks SET ended=?,status='discarded' WHERE ended IS NULL AND status='proposed'", (now,))
                    self.store.set("mode", "ACTIVE")
                    self.store.audit("recovery", "activation-restored", {"admin_ip": consent["admin_ip"]}, now)
            self.platform_status = health
            self.last_error = ""
            self._recovery_state("active", "Защита восстановлена после успешных проверок")
        except Exception as exc:
            self._recovery_state("waiting", str(exc))

    @property
    def mode(self):
        return self.store.get("mode", "MONITOR ONLY")

    def trusted(self, ip):
        return any(contains(r["network"], ip) for r in self.store.rows("SELECT network FROM whitelist"))

    def relay_ips(self):
        # Infrastructure exclusions survive disabling the agent. Its clients
        # remain subject to the separately scoped proxy policy.
        return self.store.get("proxy_relay_ips", [])

    def protected(self):
        snapshot = self.safety.sessions()
        if not snapshot["healthy"]:
            detail = snapshot.get("error", "Session inventory is unavailable")
            raise RuntimeError(f"Cannot verify current administrative RDP sessions: {detail}")
        return snapshot["sessions"]

    def ingest(self, xml: str, channel: str, bookmark: str):
        now = self.clock()
        with self.lock, self.store.transaction() as db:
            try:
                event = parse_event(xml)
                if event.channel != channel:
                    raise ValueError("Event channel differs from subscription")
            except Exception as exc:
                self.store.audit("collector", "parse-rejected", {"channel": channel, "error": str(exc)}, now)
                db.execute("INSERT OR REPLACE INTO bookmarks VALUES (?,?)", (channel, bookmark))
                return False
            values = asdict(event)
            inserted = db.execute(
                f"INSERT OR IGNORE INTO events ({','.join(values)}) VALUES ({','.join('?' for _ in values)})",
                tuple(values.values()),
            ).rowcount
            if inserted:
                self._detect(event, db, now)
            # The event, decision, audit, and bookmark commit together, before acknowledging delivery.
            db.execute("INSERT OR REPLACE INTO bookmarks VALUES (?,?)", (channel, bookmark))
            return bool(inserted)

    def _detect(self, event, db, now):
        def disposition(value):
            db.execute("UPDATE events SET disposition=? WHERE key=?", (value, event.key))

        if FAILURE_SOURCES.get(event.channel) != event.event_id:
            return
        if event.ip is None:
            disposition("no-source-ip")
            return
        if event.ip in self.relay_ips():
            disposition("proxy-relay")
            return
        # A newly subscribed channel can replay years of records. Do not query live
        # WTS sessions for each old failure or turn historical evidence into bans.
        if not now - self.settings.window_seconds <= event.timestamp <= now + 5:
            disposition("historical")
            return
        if self.trusted(event.ip):
            disposition("whitelisted")
            return
        try:
            sessions = self.protected()
        except RuntimeError:
            disposition("safety-unavailable")
            return
        if any(s["ip"] == event.ip for s in sessions):
            disposition("admin-protected")
            # Avoid flooding audit for every attack behind a shared administrative NAT.
            if not self.store.rows("SELECT id FROM audit WHERE action='admin-ip-attempt' AND timestamp>? LIMIT 1",
                                   (now - 60,)):
                self.store.audit("detector", "admin-ip-attempt", {"ip": event.ip}, now)
            return
        eligible = event.category == "RDP-confirmed" or (
            event.category == "Network-auth" and self.settings.include_network_auth)
        if not eligible:
            disposition("unconfirmed" if event.category == "Network-auth" else "ineligible")
            return
        if self.store.rows("SELECT id FROM blocks WHERE network=? AND ended IS NULL", (network(event.ip),)):
            disposition("existing-decision")
            return
        last_end = db.execute("SELECT MAX(ended) FROM blocks WHERE network=?", (network(event.ip),)).fetchone()[0]
        since = max(now - self.settings.window_seconds, last_end or 0)
        categories = ("RDP-confirmed", "Network-auth") if self.settings.include_network_auth else ("RDP-confirmed",)
        # Security/4625 and RdpCoreTS/140 may describe the same failed connection.
        # There is no reliable common ID: count each source independently rather
        # than merge by timestamp or sum both toward a premature threshold.
        counts = db.execute(
            "SELECT COUNT(*),MIN(timestamp),MAX(timestamp) FROM events WHERE ip=? AND event_id=? "
            "AND channel=? AND timestamp>? AND timestamp<=? "
            f"AND category IN ({','.join('?' for _ in categories)}) "
            "AND disposition NOT IN ('whitelisted','admin-protected','safety-unavailable','historical')",
            (event.ip, event.event_id, event.channel, since, now + 5, *categories),
        ).fetchone()
        if counts[0] < self.settings.threshold:
            return
        recent = db.execute("SELECT COUNT(*) FROM blocks WHERE kind='dynamic' AND created>?", (now - 60,)).fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM blocks WHERE ended IS NULL").fetchone()[0]
        if recent >= self.settings.max_blocks_per_minute or total >= self.settings.max_block_entries:
            disposition("circuit-breaker")
            if self.mode == "ACTIVE":
                self.store.set("mode", "MONITOR ONLY")
                self.store.set("cleanup_requested", True)
                self.store.audit("detector", "circuit-breaker", {"recent": recent, "total": total}, now)
            return
        row = db.execute("SELECT count FROM strikes WHERE ip=?", (event.ip,)).fetchone()
        strikes = (row[0] if row else 0) + 1
        active = self.mode == "ACTIVE" and not self.emergency_path.exists()
        if active:
            db.execute("INSERT OR REPLACE INTO strikes VALUES (?,?)", (event.ip, strikes))
        duration = self.settings.ban_seconds[min(strikes - 1, len(self.settings.ban_seconds) - 1)]
        db.execute(
            "INSERT INTO blocks(network,kind,reason,attempts,first_seen,last_seen,created,expires,status,strikes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (network(event.ip), "dynamic", f"{event.category} / {event.channel} / {event.event_id}: {counts[0]} failures",
             counts[0], counts[1], counts[2],
             now, now + duration, "pending" if active else "proposed", strikes),
        )
        disposition("pending" if active else "proposed")
        self.store.audit("detector", "block-decision" if active else "block-proposed",
                         {"ip": event.ip, "attempts": counts[0], "seconds": duration,
                          "channel": event.channel, "event_id": event.event_id}, now)

    def _set_monitor(self, actor, action):
        # Persist inhibition before touching the firewall. Failed removal remains visible and retryable.
        self.store.set("mode", "MONITOR ONLY")
        recovery.revoke(self.data_dir)
        self._recovery_state("disabled", action)
        self.store.set("cleanup_requested", True)
        self.store.audit(actor, action, {}, self.clock())
        self._cleanup()

    def _cleanup(self):
        with self.firewall_lock():
            self.firewall.clear()
            self.lease_path.unlink(missing_ok=True)
        self.store.db.execute("UPDATE blocks SET status='suspended',error='' WHERE ended IS NULL AND status!='proposed'")
        self.store.set("cleanup_requested", False)
        self.last_error = ""

    def _renew_lease(self, previous, updated):
        # The independent watchdog can withdraw a lease while a native health
        # query is running. Never resurrect that stale authority afterwards.
        with self.firewall_lock():
            current = json.loads(self.lease_path.read_text(encoding="utf-8"))
            if current != previous or self.emergency_path.exists():
                raise RuntimeError("Active lease was withdrawn during health checks")
            atomic_json(self.lease_path, updated)

    def tick(self, force=False):
        with self.lock:
            now = self.clock()
            if now < self.last_tick:
                # An NTP correction must not postpone heartbeat and retries
                # until the old wall clock catches up.
                self.last_sync = self.last_health = self.last_heartbeat = self.last_cleanup = 0
                self.last_recovery = float("-inf")
            self.last_tick = now
            try:
                if self.emergency_path.exists() and self.mode == "ACTIVE":
                    self._set_monitor("watchdog", "emergency-latch-observed")
                if self.store.get("cleanup_requested", False):
                    self._cleanup()
                with self.store.transaction() as db:
                    db.execute("UPDATE blocks SET ended=?,status='expired' WHERE ended IS NULL AND expires IS NOT NULL AND expires<=?",
                               (now, now))
                if force or not self.platform_status or now - self.last_health >= 10:
                    self.platform_status = self.safety.health(self.settings.rdp_port)
                    self.last_health = now
                if self.mode != "ACTIVE":
                    self._try_resume(force=force)
                if self.mode == "ACTIVE":
                    if not self.lease_path.exists():
                        raise RuntimeError("Active lease is missing")
                    lease = json.loads(self.lease_path.read_text(encoding="utf-8"))
                    if lease.get("deadline") and now >= lease["deadline"]:
                        self.emergency_path.write_text("Reconnect confirmation expired", encoding="utf-8")
                        self._set_monitor("watchdog", "activation-timeout")
                        return
                    sessions = self.protected()
                    if not self.platform_status["firewall"]:
                        raise RuntimeError("Windows Firewall is unavailable or disabled on an active profile")
                    if not self.platform_status.get("watchdog"):
                        raise RuntimeError("Independent rollback watchdog is unavailable")
                    if force or now - self.last_sync >= self.settings.firewall_interval_seconds:
                        self._sync(sessions)
                        self.last_sync = now
                    if now - self.last_heartbeat >= 10:
                        self._renew_lease(lease, dict(lease, heartbeat=now))
                        self.last_heartbeat = now
                if now - self.last_cleanup >= 3600:
                    with self.store.transaction() as db:
                        db.execute("DELETE FROM events WHERE timestamp<?", (now - self.settings.retention_days * 86400,))
                        db.execute("DELETE FROM sessions WHERE expires<? OR last_seen<?", (now, now - 1800))
                        db.execute("DELETE FROM login_attempts WHERE timestamp<?", (now - 86400,))
                    self.last_cleanup = now
            except Exception as exc:
                self.last_error = str(exc)
                self.store.db.execute("UPDATE blocks SET status='error',error=? WHERE ended IS NULL AND status!='proposed'",
                                      (self.last_error,))
                self.store.audit("guard", "reconcile-error", {"error": self.last_error}, now)
                if self.mode == "ACTIVE":
                    self.store.set("mode", "MONITOR ONLY")
                    self.store.set("cleanup_requested", True)
                    self._recovery_state("waiting" if recovery.approval(self.data_dir) else "disabled", self.last_error)
                raise

    def _sync(self, sessions):
        white = self.store.rows("SELECT network FROM whitelist")
        blocks = self.store.rows("SELECT * FROM blocks WHERE ended IS NULL AND status!='proposed'")
        desired, suppressed = [], []
        for row in blocks:
            if (any(overlaps(row["network"], w["network"]) for w in white)
                    or any(contains(row["network"], s["ip"]) for s in sessions)
                    or any(contains(row["network"], relay) for relay in self.relay_ips())):
                suppressed.append(row["id"])
            else:
                desired.append(row["network"])
        with self.firewall_lock():
            if self.emergency_path.exists() or self.mode != "ACTIVE":
                raise RuntimeError("Firewall writes inhibited by emergency/monitor mode")
            lease = json.loads(self.lease_path.read_text(encoding="utf-8"))
            now = self.clock()
            if lease.get("deadline") is not None and now >= lease["deadline"]:
                raise RuntimeError("Firewall writes inhibited by an expired lease")
            self.firewall.reconcile(desired, self.settings.rdp_port, self.settings.batch_size)
        with self.store.transaction() as db:
            for row in blocks:
                db.execute("UPDATE blocks SET status=?,error='' WHERE id=?",
                           ("protected" if row["id"] in suppressed else "applied", row["id"]))
        self.last_error = ""

    def preflight(self):
        health = self.safety.health(self.settings.rdp_port)
        session_error = ""
        try:
            sessions = self.protected()
            session_ok = True
        except RuntimeError as exc:
            sessions, session_ok = [], False
            session_error = str(exc)
        white = self.store.rows("SELECT * FROM whitelist")
        blocks = self.store.rows("SELECT * FROM blocks WHERE ended IS NULL")
        sessions = [s | {"whitelisted": self.trusted(s["ip"])} for s in sessions]
        admin_white = any(s["whitelisted"] for s in sessions)
        collisions = any(overlaps(b["network"], w["network"]) for b in blocks for w in white)
        rules = self.firewall.backend.list_rules()
        from .firewall import GROUP, PREFIX
        foreign = any((r.group == GROUP or r.name.startswith(PREFIX)) and not owned(r) for r in rules)
        checks = {
            "firewall": health["firewall"], "rdp_listening": health["listening"],
            "rdp_port_matches_windows": health["port_matches"], "rdp_allow_rules": health["allow_rules"],
            "independent_watchdog": health["watchdog"], "session_inventory": session_ok,
            "administrative_whitelist": admin_white, "no_list_overlap": not collisions,
            "managed_rule_ownership": not foreign,
            "security_subscription": self.collectors.get(SECURITY, {}).get("healthy", False),
            "audit_logon_success_failure": health.get("audit_logon", False),
        }
        return {"checks": checks, "ready": all(checks.values()), "sessions": sessions, "session_error": session_error,
                "dry_run": [{"network": b["network"], "status": b["status"]} for b in blocks],
                "warning": "ACTIVE can interrupt RDP. Verify backup access, reconnect and confirm within the rollback period."}

    def activate(self, args, actor):
        if args.get("confirmation") != "ENABLE RDP GUARD" or args.get("backup_access") is not True:
            raise ValueError("Explicit confirmation and verified backup access are required")
        preflight = self.preflight()
        if not preflight["ready"]:
            raise ValueError("Preflight failed: " + ", ".join(k for k, v in preflight["checks"].items() if not v))
        if self.mode == "ACTIVE":
            raise ValueError("Protection is already active")
        recovery.revoke(self.data_dir)
        now = self.clock()
        # Lease exists BEFORE active state. The independent task survives guard/web failure and reboots.
        with self.firewall_lock():
            atomic_json(self.lease_path, {"started": now, "deadline": now + self.settings.rollback_seconds,
                                          "heartbeat": now, "confirmed": False})
            self.emergency_path.unlink(missing_ok=True)
        with self.store.transaction() as db:
            db.execute("UPDATE blocks SET ended=?,status='discarded' WHERE ended IS NULL AND status='proposed'", (now,))
            self.store.set("mode", "ACTIVE")
            self.store.audit(actor, "activate-pending-reconnect", preflight["checks"], now)
        self.tick(force=True)
        return {"deadline": now + self.settings.rollback_seconds}

    def confirm_active(self, actor):
        if self.mode != "ACTIVE" or not self.lease_path.exists():
            raise ValueError("No pending activation")
        lease = json.loads(self.lease_path.read_text(encoding="utf-8"))
        if not lease.get("deadline") or self.clock() >= lease["deadline"]:
            raise ValueError("Activation confirmation is absent or expired")
        proof = None
        for session in self.protected():
            if not self.trusted(session["ip"]):
                continue
            # WindowsSafety binds LSM 21/25 to an active RDP administrative token,
            # session ID, user/domain and the current WTS connection time. Reuse that
            # verified proof: reconnects may produce 4624/7 without 4624/10 or 4778.
            # A late event for a connection established before activation is insufficient.
            if (session.get("ip_source") in ("LSM/21", "LSM/25") and
                    lease["started"] < session.get("connected_at", 0) <=
                    session.get("source_timestamp", 0) <= self.clock()):
                proof = session
                break
        now = self.clock()
        # A native session/event lookup may finish after the rollback deadline.
        if now >= lease["deadline"]:
            raise ValueError("Activation confirmation is absent or expired")
        if proof is None:
            raise ValueError("Не найдено новое административное RDP-подключение после включения защиты "
                             "с адреса из белого списка. Закройте окно RDP, подключитесь снова и повторите подтверждение.")
        with self.firewall_lock():
            self._renew_lease(lease, dict(lease, deadline=None, confirmed=True, heartbeat=now))
            recovery.approve(self.data_dir, self.settings.rdp_port, proof["ip"], now)
        self._recovery_state("active", "Активация подтверждена; автоматическое восстановление разрешено")
        self.store.audit(actor, "activation-confirmed", {key: proof[key] for key in
            ("id", "username", "domain", "ip", "ip_source", "source_record_id", "source_timestamp", "connected_at")}, now)
        return {"confirmed": True}

    def add_whitelist(self, value, comment, actor):
        net = network(value)
        with self.store.transaction() as db:
            db.execute("INSERT INTO whitelist VALUES (?,?,?,?) ON CONFLICT(network) DO UPDATE SET comment=excluded.comment",
                       (net, comment[:500], actor, self.clock()))
            for row in self.store.rows("SELECT id,network FROM blocks WHERE ended IS NULL"):
                if overlaps(net, row["network"]):
                    db.execute("UPDATE blocks SET ended=?,status='whitelisted' WHERE id=?", (self.clock(), row["id"]))
            self.store.audit(actor, "whitelist-add", {"network": net, "comment": comment[:500]}, self.clock())

    def add_block(self, value, comment, actor, seconds=None):
        net = network(value, blocking=True)
        if any(contains(net, relay) for relay in self.relay_ips()):
            raise ValueError("Block includes a registered shared proxy address")
        if any(overlaps(net, w["network"]) for w in self.store.rows("SELECT network FROM whitelist")):
            raise ValueError("Block overlaps the whitelist")
        if any(contains(net, session["ip"]) for session in self.protected()):
            raise ValueError("Block includes an active administrative RDP session")
        if seconds is not None and (type(seconds) is not int or not 60 <= seconds <= 2592000):
            raise ValueError("Duration must be 60 seconds to 30 days")
        total = self.store.rows("SELECT COUNT(*) AS n FROM blocks WHERE ended IS NULL")[0]["n"]
        if total >= self.settings.max_block_entries:
            raise ValueError("Block capacity exceeded")
        now = self.clock()
        with self.store.transaction() as db:
            db.execute("INSERT INTO blocks(network,kind,reason,attempts,first_seen,last_seen,created,expires,status,strikes) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?)", (net, "static" if seconds is None else "manual", comment[:500],
                       0, now, now, now, None if seconds is None else now + seconds,
                       "pending" if self.mode == "ACTIVE" else "suspended", 0))
            self.store.audit(actor, "block-add", {"network": net, "seconds": seconds, "comment": comment[:500]}, now)

    def snapshot(self):
        now = self.clock()
        failures = "(" + " OR ".join("(channel=? AND event_id=?)" for _ in FAILURE_SOURCES) + ")"
        source_args = tuple(value for pair in FAILURE_SOURCES.items() for value in pair)
        counters = {}
        for label, seconds in (("hour", 3600), ("day", 86400), ("week", 604800), ("minute", 60)):
            counters[label] = self.store.rows(
                "SELECT COUNT(*) n,COUNT(DISTINCT ip) unique_ips,COUNT(ip) with_ip FROM events WHERE "
                + failures + " AND timestamp>=? AND timestamp<=?", (*source_args, now - seconds, now))[0]
        blocks = self.store.rows("SELECT status,COUNT(*) n FROM blocks WHERE ended IS NULL GROUP BY status")
        histogram = self.store.rows(
            "SELECT CAST(timestamp/300 AS INTEGER)*300 time,COUNT(*) count FROM events WHERE "
            + failures + " AND timestamp>=? AND timestamp<=? GROUP BY 1 ORDER BY 1", (*source_args, now - 3600, now))
        failure_sources = self.store.rows(
            "SELECT channel,event_id,COUNT(*) n,COUNT(ip) with_ip FROM events WHERE "
            + failures + " AND timestamp>=? AND timestamp<=? GROUP BY channel,event_id", (*source_args, now - 86400, now))
        return {"version": __version__, "mode": self.mode, "uptime": int(now - self.started), "now": now,
                "os": platform.platform(), "platform": self.platform_status,
                "counters": counters, "failure_sources": failure_sources, "blocks": blocks, "histogram": histogram,
                "whitelist_count": self.store.rows("SELECT COUNT(*) n FROM whitelist")[0]["n"],
                "last_error": self.last_error, "collectors": self.collectors,
                "emergency_disabled": self.emergency_path.exists(),
                "recovery": self.recovery_status | {"approved": bool(recovery.approval(self.data_dir))},
                "lease": json.loads(self.lease_path.read_text(encoding="utf-8")) if self.lease_path.exists() else None}

    def _commit_proxy_binding(self, binding, actor, *, trusted_relay=None):
        """Caller holds Guard.lock; credentials have already been validated."""
        relays = sorted(set(self.relay_ips()) | set(binding.get("relay_ips", [])))
        if trusted_relay is not None:
            if trusted_relay not in binding.get("relay_ips", []):
                raise ValueError("Trusted relay is not declared in this binding")
            if any(contains(row["network"], trusted_relay) for row in self.store.rows(
                    "SELECT network FROM blocks WHERE ended IS NULL")):
                raise ValueError("Trusted relay overlaps an existing block")
        with self.store.transaction() as db:
            self.store.set("proxy_binding", binding)
            self.store.set("proxy_relay_ips", relays)
            self.store.set("proxy_status", {})
            self.store.set("proxy_outbox", None)
            if trusted_relay is not None:
                db.execute("INSERT OR IGNORE INTO whitelist VALUES (?,?,?,?)",
                           (network(trusted_relay), "Trusted proxy relay (pairing)", actor, self.clock()))
            for row in self.store.rows("SELECT id,network FROM blocks WHERE ended IS NULL"):
                if any(contains(row["network"], relay) for relay in relays):
                    db.execute("UPDATE blocks SET ended=?,status='proxy-relay' WHERE id=?",
                               (self.clock(), row["id"]))
            self.store.audit(actor, "proxy-pair" if trusted_relay is not None else "proxy-configure",
                             {"enabled": binding["enabled"], "mode": binding.get("mode", "monitor"),
                              "relay_ips": relays, "trusted_relay": trusted_relay}, self.clock())
        # The normal runtime tick reconciles local rules. Pairing itself performs
        # no firewall operation and never changes the protection/activation mode.
        return {"ok": True, "relay_ips": relays}

    def _enrollment(self):
        if getattr(self, "stopping", False):
            raise ValueError("Enrollment service is stopping")
        if not hasattr(self, "proxy_enrollment"):
            from .proxy_enrollment import EnrollmentManager
            self.proxy_enrollment = EnrollmentManager(self)
        return self.proxy_enrollment

    def proxy_results(self, args):
        from .proxy_client import ProxyTransport, validate_binding, sanitize_status
        with self.lock:
            binding = validate_binding(self.data_dir, self.store.get("proxy_binding", {}))
        if not binding["enabled"]:
            raise ValueError("Proxy is not connected")
        request = {key: args.get(key, default) for key, default in
                   (("query", ""), ("status", ""), ("offset", 0), ("sort", "recent"))}
        receipt = ProxyTransport(binding).post("/v1/results", dict(request,
            stream_id=binding["stream_id"], backend_id=binding["backend_id"]))
        status = sanitize_status(receipt)
        if any(status.get(key) != binding[key] for key in ("stream_id", "backend_id", "computer")):
            raise ValueError("Results belong to another proxy binding")
        with self.lock:
            if self.store.get("proxy_binding") != binding:
                raise ValueError("Proxy binding changed while fetching results")
        return {"results": status["results"], "total": int(receipt["total"]),
                "offset": int(receipt["offset"]), "limit": 50,
                "whitelist": [network(item) for item in receipt.get("whitelist", [])][:1000],
                "threshold": int(receipt["threshold"]), "window_seconds": int(receipt["window_seconds"])}

    def dispatch(self, operation, args, actor):
        if not isinstance(args, dict):
            raise ValueError("Arguments must be an object")
        if operation == "proxy-results":
            return self.proxy_results(args)
        with self.lock:
            if operation == "proxy-pair-preview":
                return self._enrollment().preview(args.get("document"))
            if operation == "proxy-pair-status":
                return self._enrollment().status()
            if operation == "proxy-pair":
                return self._enrollment().start(args.get("document"), args.get("trusted_relay"), actor)
            if operation == "proxy-status":
                status = dict(self.store.get("proxy_status", {}))
                from .proxy_evidence import instant
                from .proxy_client import binding_id
                binding = self.store.get("proxy_binding", {"enabled": False})
                try:
                    stale = (status.get("binding_id") != binding_id(binding)
                             or not 0 <= self.clock() - instant(status["updated_at_utc"]) <= 20)
                except (ValueError, KeyError, TypeError):
                    stale = True
                return {"binding": binding,
                        "relay_ips": self.relay_ips(), "status": status, "stale": stale,
                        "enrollment": self.proxy_enrollment.status() if hasattr(self, "proxy_enrollment") else {"state": "idle"}}
            if operation == "proxy-configure":
                from .proxy_client import binding_id, validate_binding
                binding = validate_binding(self.data_dir, args.get("binding"))
                if binding.get("mode") == "enforce":
                    if args.get("confirmation") != "ENABLE PROXY BLOCKS":
                        raise ValueError("Explicit proxy enforcement confirmation is required")
                    previous = self.store.get("proxy_binding", {})
                    status = self.store.get("proxy_status", {})
                    from .proxy_evidence import instant
                    try:
                        fresh = all(0 <= self.clock() - instant(status[field]) <= 20
                                    for field in ("updated_at_utc", "last_sent_utc"))
                    except (ValueError, KeyError, TypeError):
                        fresh = False
                    if (previous.get("enabled") is not True
                            or dict(previous, mode="monitor") != dict(binding, mode="monitor")
                            or status.get("binding_id") != binding_id(previous)
                            or not fresh or status.get("error") or any(status.get(field) is not True for field in
                                                ("enforcement_allowed", "transport_healthy", "healthy", "capture_healthy"))):
                        raise ValueError("Fresh validated status for the unchanged proxy binding is required")
                if hasattr(self, "proxy_enrollment"):
                    self.proxy_enrollment.cancel()
                result = self._commit_proxy_binding(binding, actor)
                self.tick(force=True)
                return result
            if operation == "proxy-unblock":
                if not self.store.get("proxy_binding", {}).get("enabled"):
                    raise ValueError("Proxy agent is not configured")
                ip = address(args["client_ip"])
                queue = self.store.get("proxy_unblock_queue", [])
                if len(queue) >= 100:
                    raise ValueError("Proxy command queue is full")
                import uuid
                from .proxy_client import binding_id
                queue.append({"id": str(uuid.uuid4()), "client_ip": ip, "created": self.clock(),
                              "binding_id": binding_id(self.store.get("proxy_binding"))})
                self.store.set("proxy_unblock_queue", queue)
                self.store.audit(actor, operation, {"client_ip": ip}, self.clock())
                return {"ok": True, "queued": True}
            if operation == "status":
                return self.snapshot()
            if operation == "service-events":
                records = self.service_journal.recent()
                if platform.system() == "Windows":
                    try:
                        from .windows.recovery import scm_events
                        records += scm_events()
                    except Exception as exc:
                        records.append({"timestamp": self.clock(), "component": "Windows SCM", "event": "read-error", "detail": str(exc)})
                return sorted(records, key=lambda row: row["timestamp"], reverse=True)[:200]
            if operation == "health":
                return self.snapshot() | {"platform": self.safety.health(self.settings.rdp_port),
                                          "integrity": self.store.rows("PRAGMA quick_check")}
            if operation == "preflight":
                return self.preflight()
            if operation == "events":
                filters, values = [], []
                for field in ("ip", "username", "category", "disposition"):
                    if args.get(field):
                        filters.append(f"{field}=?")
                        values.append(str(args[field])[:512])
                for key, operator in (("since", ">="), ("until", "<=")):
                    if args.get(key) is not None:
                        filters.append(f"timestamp{operator}?")
                        values.append(float(args[key]))
                offset = max(0, min(int(args.get("offset", 0)), 1000000))
                where = " WHERE " + " AND ".join(filters) if filters else ""
                return self.store.rows("SELECT * FROM events" + where + " ORDER BY timestamp DESC LIMIT 100 OFFSET ?", (*values, offset))
            if operation in ("list-blocks", "list-whitelist", "audit"):
                if operation == "list-blocks":
                    return self.store.rows("SELECT * FROM blocks " + ("" if args.get("history") else "WHERE ended IS NULL ")
                                           + "ORDER BY created DESC LIMIT 4000")
                if operation == "list-whitelist":
                    return self.store.rows("SELECT * FROM whitelist ORDER BY created DESC LIMIT 4000")
                return self.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 200")
            if operation == "settings":
                return asdict(self.settings)
            if operation in ("export-config", "diagnostics"):
                result = {"version": __version__, "settings": asdict(self.settings),
                          "whitelist": self.store.rows("SELECT * FROM whitelist"),
                          "blacklist": self.store.rows("SELECT network,reason FROM blocks WHERE ended IS NULL AND kind='static'")}
                if operation == "diagnostics":
                    result |= {"status": self.snapshot(), "audit": self.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 100")}
                return result
            if operation == "activate":
                return self.activate(args, actor)
            if operation == "confirm-active":
                return self.confirm_active(actor)
            if operation == "monitor-only":
                self._set_monitor(actor, operation)
            elif operation == "emergency-disable":
                self.emergency_path.write_text("Disabled by authenticated administrator", encoding="utf-8")
                self._set_monitor(actor, operation)
            elif operation == "whitelist-add":
                self.add_whitelist(args["network"], str(args.get("comment", "")), actor)
            elif operation == "whitelist-remove":
                net = network(args["network"])
                if self.mode == "ACTIVE" and any(contains(net, s["ip"]) for s in self.protected()):
                    raise ValueError("Switch to Monitor Only before removing an administrative session whitelist")
                with self.store.transaction() as db:
                    db.execute("DELETE FROM whitelist WHERE network=?", (net,))
                    self.store.audit(actor, operation, {"network": net}, self.clock())
            elif operation == "block":
                self.add_block(args["network"], str(args.get("comment", "Manual block")), actor, args.get("seconds"))
            elif operation in ("unblock", "extend", "make-permanent"):
                net = network(args["network"], blocking=True)
                with self.store.transaction() as db:
                    if operation == "unblock":
                        db.execute("UPDATE blocks SET ended=?,status='removed' WHERE network=? AND ended IS NULL", (self.clock(), net))
                    elif operation == "extend":
                        seconds = args.get("seconds")
                        if type(seconds) is not int or not 60 <= seconds <= 2592000:
                            raise ValueError("Duration must be 60 seconds to 30 days")
                        db.execute("UPDATE blocks SET expires=? WHERE network=? AND ended IS NULL AND kind!='static'",
                                   (self.clock() + seconds, net))
                    else:
                        db.execute("UPDATE blocks SET kind='static',expires=NULL,status=? WHERE network=? AND ended IS NULL",
                                   ("pending" if self.mode == "ACTIVE" else "suspended", net))
                    self.store.audit(actor, operation, {"network": net}, self.clock())
            elif operation == "update-settings":
                updated = Settings.load(args.get("settings", {}))
                if updated.rdp_port != self.settings.rdp_port:
                    if self.mode == "ACTIVE" or args.get("confirm_port") != updated.rdp_port:
                        raise ValueError("Port changes require Monitor Only and explicit confirm_port")
                    if not self.safety.health(updated.rdp_port)["port_matches"]:
                        raise ValueError("Port does not match the Windows RDP listener configuration")
                with self.store.transaction():
                    self.store.set("settings", asdict(updated))
                    self.store.audit(actor, operation, asdict(updated), self.clock())
                self.settings = updated
            elif operation == "import-lists":
                # Validate the complete import before changing anything. Apply as additions, never replace.
                entries = args.get("entries")
                kind = args.get("kind")
                if kind not in ("whitelist", "blacklist") or not isinstance(entries, list) or len(entries) > 1000:
                    raise ValueError("Choose whitelist/blacklist and at most 1000 entries")
                normalized = [(network(e["network"], blocking=kind == "blacklist"), str(e.get("comment", ""))[:500]) for e in entries]
                if len({n for n, _ in normalized}) != len(normalized):
                    raise ValueError("Duplicate import networks")
                if kind == "blacklist":
                    protected = [w["network"] for w in self.store.rows("SELECT network FROM whitelist")]
                    protected += [network(s["ip"]) for s in self.protected()]
                    protected += [network(relay) for relay in self.relay_ips()]
                    existing = {b["network"] for b in self.store.rows("SELECT network FROM blocks WHERE ended IS NULL")}
                    if len(existing) + len(normalized) > self.settings.max_block_entries:
                        raise ValueError("Block capacity exceeded")
                    if any(n in existing or any(overlaps(n, p) for p in protected) for n, _ in normalized):
                        raise ValueError("Import overlaps protected or existing entries")
                # One transaction, no nested helper transaction.
                with self.store.transaction() as db:
                    for net, comment in normalized:
                        now = self.clock()
                        if kind == "whitelist":
                            db.execute("INSERT OR REPLACE INTO whitelist VALUES (?,?,?,?)", (net, comment, actor, now))
                            for b in self.store.rows("SELECT id,network FROM blocks WHERE ended IS NULL"):
                                if overlaps(net, b["network"]):
                                    db.execute("UPDATE blocks SET ended=?,status='whitelisted' WHERE id=?", (now, b["id"]))
                        else:
                            db.execute("INSERT INTO blocks(network,kind,reason,attempts,first_seen,last_seen,created,status,strikes) "
                                       "VALUES (?,'static',?,0,?,?,?, ?,0)",
                                       (net, comment, now, now, now, "pending" if self.mode == "ACTIVE" else "suspended"))
                    self.store.audit(actor, operation, {"kind": kind, "count": len(entries)}, self.clock())
            elif operation == "firewall-reconcile":
                if self.mode != "ACTIVE":
                    self.store.set("cleanup_requested", True)
            else:
                raise ValueError("Unknown operation")
            self.tick(force=True)
            return {"ok": True, "mode": self.mode}
