import argparse
import getpass
import json
import sys

from . import __version__


def parser():
    root = argparse.ArgumentParser(description="RDP Guard local administration (elevated Windows terminal)")
    root.add_argument("--version", action="version", version=f"RDP Guard {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("status", "health", "preflight", "list-blocks", "list-whitelist", "monitor-only", "emergency-disable",
                 "firewall-reconcile", "export-config", "watchdog", "has-admin"):
        commands.add_parser(name)
    for name in ("block", "unblock", "whitelist-add", "whitelist-remove"):
        command = commands.add_parser(name)
        command.add_argument("network", help="IP address or CIDR network")
        if name in ("block", "whitelist-add"):
            command.add_argument("--comment", default="")
        if name == "block":
            command.add_argument("--seconds", type=int, help="Optional temporary duration; omission means permanent")
    for name in ("init-admin", "reset-admin"):
        command = commands.add_parser(name)
        command.add_argument("--username", required=True)
        command.add_argument("--password-stdin", action="store_true", help="Read a password from stdin (automation only)")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        from .windows.platform import DATA_DIR, require_admin
        require_admin()
        if args.command == "emergency-disable":
            from .runtime import emergency_disable
            result = emergency_disable()
        elif args.command == "watchdog":
            from .runtime import watchdog
            result = watchdog()
        elif args.command in ("init-admin", "reset-admin", "has-admin"):
            from .auth import Auth
            from .storage import Store
            if not DATA_DIR.is_dir():
                raise ValueError("Run Install.ps1 first to provision protected data directories")
            store = Store(DATA_DIR / "guard.db")
            try:
                if args.command == "has-admin":
                    return 0 if store.rows("SELECT username FROM admins LIMIT 1") else 1
                password = sys.stdin.readline().rstrip("\r\n") if args.password_stdin else getpass.getpass("New panel password (12+ characters): ")
                if not args.password_stdin and password != getpass.getpass("Repeat password: "):
                    raise ValueError("Passwords do not match")
                auth = Auth(store)
                if args.command == "init-admin":
                    auth.create_admin(args.username, password)
                else:
                    if not 12 <= len(password) <= 256:
                        raise ValueError("Password must be 12-256 characters")
                    with store.transaction() as db:
                        if not db.execute("UPDATE admins SET password_hash=? WHERE username=?",
                                          (auth.hasher.hash(password), args.username)).rowcount:
                            raise ValueError("Unknown panel administrator")
                        db.execute("DELETE FROM sessions WHERE username=?", (args.username,))
                        store.audit("local-administrator", "reset-panel-password", {"username": args.username})
                result = {"ok": True, "username": args.username}
            finally:
                store.close()
        else:
            from .windows.ipc import PipeClient
            values = vars(args).copy()
            operation = values.pop("command")
            result = PipeClient().call({"op": operation, "args": values})
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"RDP Guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
