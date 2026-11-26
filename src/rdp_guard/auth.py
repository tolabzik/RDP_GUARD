import hashlib
import re
import secrets
import time

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

READ_OPERATIONS = {"status", "health", "preflight", "events", "list-blocks", "list-whitelist", "audit",
                   "settings", "export-config", "diagnostics", "proxy-status", "proxy-pair-preview", "proxy-pair-status",
                   "service-events", "proxy-results"}


class AuthenticationError(ValueError):
    pass


class RateLimitError(AuthenticationError):
    pass


class Auth:
    def __init__(self, store, clock=time.time):
        self.store, self.clock = store, clock
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)
        self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))

    def create_admin(self, username, password):
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise ValueError("Username must be 3-64 ASCII letters, digits, dot, dash or underscore")
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise ValueError("Password must be 12-256 characters")
        with self.store.transaction() as db:
            db.execute("INSERT INTO admins VALUES (?,?)", (username, self.hasher.hash(password)))
            self.store.audit("local-administrator", "create-panel-admin", {"username": username}, self.clock())

    def login(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 256:
            raise AuthenticationError("Invalid credentials")
        now = self.clock()
        failures = self.store.rows("SELECT COUNT(*) n FROM login_attempts WHERE timestamp>? AND success=0", (now - 300,))[0]["n"]
        if failures >= 10:
            raise RateLimitError("Too many failed logins; wait five minutes")
        rows = self.store.rows("SELECT password_hash FROM admins WHERE username=?", (username,))
        valid = False
        try:
            valid = self.hasher.verify(rows[0]["password_hash"] if rows else self.dummy_hash, password) and bool(rows)
        except (VerificationError, InvalidHashError):
            pass
        with self.store.transaction() as db:
            db.execute("INSERT INTO login_attempts VALUES (?,?,?)", (now, username, int(valid)))
            self.store.audit("panel", "login-success" if valid else "login-failed", {"username": username}, now)
        if not valid:
            raise AuthenticationError("Invalid credentials")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.transaction() as db:
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)",
                       (hashlib.sha256(token.encode()).hexdigest(), username, csrf, now, now + 28800, now))
            if self.hasher.check_needs_rehash(rows[0]["password_hash"]):
                db.execute("UPDATE admins SET password_hash=? WHERE username=?", (self.hasher.hash(password), username))
        return {"token": token, "csrf": csrf, "username": username}

    def session(self, token, csrf=None, mutate=False):
        if not isinstance(token, str) or len(token) > 256:
            raise AuthenticationError("Authentication required")
        digest = hashlib.sha256(token.encode()).hexdigest()
        rows = self.store.rows("SELECT * FROM sessions WHERE token_hash=?", (digest,))
        now = self.clock()
        if not rows or rows[0]["expires"] <= now or rows[0]["last_seen"] < now - 1800:
            raise AuthenticationError("Session expired")
        session = rows[0]
        if mutate and (not isinstance(csrf, str) or not secrets.compare_digest(csrf, session["csrf"])):
            raise AuthenticationError("CSRF validation failed")
        self.store.db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, digest))
        return session

    def logout(self, token):
        self.store.db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))


class Dispatcher:
    def __init__(self, guard):
        self.guard, self.auth = guard, Auth(guard.store, guard.clock)

    def __call__(self, request, identity):
        with self.guard.lock:
            if not isinstance(request, dict) or set(request) - {"op", "args", "token", "csrf"}:
                raise ValueError("Invalid RPC envelope")
            operation, args = request.get("op"), request.get("args", {})
            if not isinstance(operation, str) or not isinstance(args, dict):
                raise ValueError("Invalid RPC command")
            if identity["role"] == "web":
                if operation == "login":
                    return self.auth.login(args.get("username"), args.get("password"))
                session = self.auth.session(request.get("token"), request.get("csrf"),
                                            operation not in READ_OPERATIONS | {"session"})
                actor = f"panel:{session['username']}"
                if operation == "session":
                    return {"username": session["username"], "csrf": session["csrf"]}
                if operation == "logout":
                    self.auth.logout(request["token"])
                    return {"ok": True}
            elif identity["role"] == "admin":
                actor = f"windows:{identity['sid']}"
            else:
                raise AuthenticationError("IPC identity denied")
        try:
            return self.guard.dispatch(operation, args, actor)
        except Exception as exc:
            if operation not in READ_OPERATIONS:
                # Never serialize request credentials or arbitrary payloads to audit.
                with self.guard.lock:
                    self.guard.store.audit(actor, "command-rejected", {"op": operation, "error": str(exc)})
            raise
