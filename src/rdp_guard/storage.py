from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import threading
import time

from .models import Settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 key TEXT PRIMARY KEY, channel TEXT, record_id INTEGER, timestamp REAL, event_id INTEGER,
 ip TEXT, username TEXT, domain TEXT, logon_type INTEGER, auth_package TEXT, logon_process TEXT,
 status TEXT, substatus TEXT, source_port INTEGER, category TEXT, confidence TEXT, reason TEXT,
 disposition TEXT NOT NULL DEFAULT 'observed');
CREATE INDEX IF NOT EXISTS events_ip_time ON events(ip,timestamp);
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
CREATE TABLE IF NOT EXISTS bookmarks(channel TEXT PRIMARY KEY, xml TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS whitelist(network TEXT PRIMARY KEY, comment TEXT, author TEXT, created REAL);
CREATE TABLE IF NOT EXISTS blocks(
 id INTEGER PRIMARY KEY, network TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, attempts INTEGER,
 first_seen REAL, last_seen REAL, created REAL, expires REAL, status TEXT NOT NULL,
 strikes INTEGER NOT NULL, ended REAL, error TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS blocks_active ON blocks(network) WHERE ended IS NULL;
CREATE INDEX IF NOT EXISTS blocks_time ON blocks(created);
CREATE TABLE IF NOT EXISTS strikes(ip TEXT PRIMARY KEY, count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp REAL, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS admins(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, username TEXT, csrf TEXT, created REAL,
 expires REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS login_attempts(timestamp REAL, username TEXT, success INTEGER);
PRAGMA user_version=1;
"""


class Store:
    def __init__(self, path: Path | str):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=10000")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > 1:
            raise ValueError("Database was created by a newer RDP Guard version")
        if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Database integrity check failed")
        self.db.executescript(SCHEMA)
        if self.get("settings") is None:
            self.set("settings", asdict(Settings()))
        if self.get("mode") is None:
            self.set("mode", "MONITOR ONLY")

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def rows(self, query, args=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(query, args)]

    def get(self, key, default=None):
        rows = self.rows("SELECT value FROM meta WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set(self, key, value):
        with self.lock:
            self.db.execute("INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (key, json.dumps(value)))

    def audit(self, actor, action, detail, now=None):
        with self.lock:
            self.db.execute("INSERT INTO audit(timestamp,actor,action,detail) VALUES (?,?,?,?)",
                            (now or time.time(), actor, action, json.dumps(detail, ensure_ascii=False)))

    def close(self):
        with self.lock:
            self.db.close()
