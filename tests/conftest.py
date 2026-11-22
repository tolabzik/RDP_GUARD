from datetime import datetime, timezone
from xml.sax.saxutils import escape

import pytest

from rdp_guard.events import SECURITY
from rdp_guard.firewall import MemoryFirewall
from rdp_guard.guard import Guard
from rdp_guard.storage import Store


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class Safety:
    def __init__(self):
        self.ok = True
        self.admin_sessions = [{"id": 2, "ip": "203.0.113.10", "username": "administrator", "domain": "SERVER"}]
        self.checks = dict.fromkeys(("firewall", "listening", "port_matches", "allow_rules", "watchdog", "audit_logon"), True)

    def sessions(self):
        return {"healthy": self.ok, "sessions": self.admin_sessions}

    def health(self, port):
        return self.checks | {"errors": []}


def event_xml(record=1, timestamp=1_800_000_000, ip="198.51.100.7", logon_type=10, event_id=4625,
              username="missing-user", substatus="0xC0000064", channel=SECURITY, provider="Microsoft-Windows-Security-Auditing"):
    date = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    values = {"IpAddress": ip, "TargetUserName": username, "TargetDomainName": "SERVER", "LogonType": str(logon_type),
              "AuthenticationPackageName": "NTLM", "LogonProcessName": "NtLmSsp", "Status": "0xC000006D",
              "SubStatus": substatus, "IpPort": "50000"}
    data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in values.items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="{provider}"/><EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>
    <TimeCreated SystemTime="{date}"/><Channel>{channel}</Channel></System><EventData>{data}</EventData></Event>'''


@pytest.fixture
def guard(tmp_path):
    store = Store(tmp_path / "guard.db")
    controller = Guard(store, MemoryFirewall(), Safety(), tmp_path, clock=Clock())
    controller.collectors[SECURITY] = {"healthy": True}
    yield controller
    store.close()


def activate(guard):
    guard.dispatch("whitelist-add", {"network": "203.0.113.10"}, "test")
    guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")


def failures(guard, count=10, start=1, **kwargs):
    for index in range(start, start + count):
        guard.ingest(event_xml(record=index, timestamp=guard.clock(), **kwargs), SECURITY, f"bookmark-{index}")
    guard.tick(force=True)
