"""Durable activation consent and a bounded, process-independent service journal.

These files live in the Administrators/SYSTEM-only data directory. An expired
heartbeat withdraws current firewall authority; it does not revoke explicit
consent to recover. Manual disable and unconfirmed activation still do.
"""
import json
import logging
import os
from pathlib import Path
import sqlite3
import tempfile
import time


def atomic_document(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(document, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def approval(data_dir):
    try:
        value = json.loads((Path(data_dir) / "recovery-approval.json").read_text(encoding="utf-8"))
        from .models import address
        if (not isinstance(value, dict) or value.get("schema") != 1 or type(value.get("rdp_port")) is not int
                or not 1 <= value["rdp_port"] <= 65535):
            return None
        value["admin_ip"] = address(value["admin_ip"])
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def approve(data_dir, port, admin_ip, now):
    from .models import address
    atomic_document(Path(data_dir) / "recovery-approval.json",
                    dict(schema=1, rdp_port=port, admin_ip=address(admin_ip), confirmed_at=now))


def revoke(data_dir):
    (Path(data_dir) / "recovery-approval.json").unlink(missing_ok=True)


def maintenance(data_dir, now=None):
    """A bounded installer pause cannot leave recovery disabled indefinitely."""
    now = time.time() if now is None else now
    try:
        value = json.loads((Path(data_dir) / "maintenance.json").read_text(encoding="utf-8"))
        return isinstance(value, dict) and type(value.get("until")) in (int, float) and now <= value["until"] <= now + 1800
    except (OSError, ValueError, TypeError):
        return False


class ServiceJournal:
    def __init__(self, data_dir):
        self.path = Path(data_dir) / "service-events.sqlite3"

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, component TEXT NOT NULL,
                event TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS states (component TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        return db

    def record(self, component, event, detail="", *, now=None):
        try:
            self._record(component, event, detail, now=now)
        except (OSError, sqlite3.Error):
            logging.exception("Service journal unavailable: %s / %s", component, event)

    def _record(self, component, event, detail="", *, now=None):
        db = self._open()
        try:
            with db:
                db.execute("INSERT INTO events(timestamp,component,event,detail) VALUES (?,?,?,?)",
                           (time.time() if now is None else now, component[:80], event[:80], str(detail)[:2000]))
                db.execute("DELETE FROM events WHERE id <= (SELECT MAX(id)-2000 FROM events)")
        finally:
            db.close()

    def transition(self, component, event, detail="", *, now=None):
        """Deduplicate polling failures without losing a later occurrence."""
        try:
            self._transition(component, event, detail, now=now)
        except (OSError, sqlite3.Error):
            logging.exception("Service journal unavailable: %s / %s", component, event)

    def _transition(self, component, event, detail="", *, now=None):
        value = json.dumps([event, str(detail)[:2000]])
        db = self._open()
        try:
            with db:
                previous = db.execute("SELECT value FROM states WHERE component=?", (component,)).fetchone()
                if previous and previous[0] == value:
                    return
                db.execute("INSERT OR REPLACE INTO states VALUES (?,?)", (component, value))
                db.execute("INSERT INTO events(timestamp,component,event,detail) VALUES (?,?,?,?)",
                           (time.time() if now is None else now, component, event, str(detail)[:2000]))
                db.execute("DELETE FROM events WHERE id <= (SELECT MAX(id)-2000 FROM events)")
        finally:
            db.close()

    def recent(self, limit=200):
        if not self.path.exists():
            return []
        db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",
                                                  (max(1, min(limit, 200)),))]
        finally:
            db.close()
