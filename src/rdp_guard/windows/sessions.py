"""Bind an active WTS session to its server-recorded RDP source, including NAT."""
import ctypes
import threading
import time

from defusedxml import ElementTree as ET

from ..events import LSM, NS, parse_event

FILETIME_EPOCH = 116444736000000000


class _Level1(ctypes.Structure):
    # Fixed Windows ABI widths also let the layout be checked on non-Windows hosts.
    _fields_ = [("SessionId", ctypes.c_uint32), ("SessionState", ctypes.c_int32),
                ("SessionFlags", ctypes.c_int32), ("WinStationName", ctypes.c_uint16 * 33),
                ("UserName", ctypes.c_uint16 * 21), ("DomainName", ctypes.c_uint16 * 18),
                ("LogonTime", ctypes.c_int64), ("ConnectTime", ctypes.c_int64),
                ("DisconnectTime", ctypes.c_int64), ("LastInputTime", ctypes.c_int64),
                ("CurrentTime", ctypes.c_int64), ("IncomingBytes", ctypes.c_uint32),
                ("OutgoingBytes", ctypes.c_uint32), ("IncomingFrames", ctypes.c_uint32),
                ("OutgoingFrames", ctypes.c_uint32), ("IncomingCompressedBytes", ctypes.c_uint32),
                ("OutgoingCompressedBytes", ctypes.c_uint32)]


class _InfoEx(ctypes.Structure):
    # The documented union currently has just its level-1 member.
    _fields_ = [("Level", ctypes.c_uint32), ("Data", _Level1)]


def session_clock(session_id):
    """WTSSessionInfoEx provides the latest connection time, not just the logon time."""
    dll = ctypes.WinDLL("wtsapi32", use_last_error=True)
    dll.WTSQuerySessionInformationW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    dll.WTSQuerySessionInformationW.restype = ctypes.c_int
    dll.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    dll.WTSFreeMemory.restype = None
    buffer, size = ctypes.c_void_p(), ctypes.c_uint32()
    if not dll.WTSQuerySessionInformationW(None, session_id, 25, ctypes.byref(buffer), ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if size.value < ctypes.sizeof(_InfoEx):
            raise RuntimeError("Incomplete WTS session information")
        info = ctypes.cast(buffer, ctypes.POINTER(_InfoEx)).contents
        if info.Level != 1 or info.Data.SessionId != session_id:
            raise RuntimeError("Unexpected WTS session information")
        data = info.Data
        return {"id": int(data.SessionId), "state": int(data.SessionState),
                "logon_ticks": int(data.LogonTime), "connect_ticks": int(data.ConnectTime),
                "current_ticks": int(data.CurrentTime)}
    finally:
        dll.WTSFreeMemory(buffer)


def latest_connection_event(session_id):
    import win32evtlog
    if type(session_id) is not int or not 0 <= session_id <= 0xFFFFFFFF:
        raise ValueError("Invalid WTS session ID")
    # Numeric session IDs only; account names never become XPath syntax. Read the newest
    # record only: an invalid/currently missing record must not fall back to an older login.
    query = ("*[System[(EventID=21 or EventID=25)] and "
             f"UserData[EventXML[SessionID={session_id}]]]")
    result = win32evtlog.EvtQuery(LSM, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
    events = []
    try:
        events = win32evtlog.EvtNext(result, 1, 1000, 0)
        if not events:
            raise RuntimeError(f"No server RDP connection event for session {session_id}")
        return win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    finally:
        for event in events:
            event.Close()
        result.Close()


def connection_source(xml, session_id, username, domain, connected_at, now):
    event = parse_event(xml)  # Validates channel, provider, timestamp and IP syntax.
    if event.channel != LSM or event.event_id not in (21, 25) or event.ip is None:
        raise RuntimeError("Expected an LSM logon/reconnection with a valid source IP")
    data = ET.fromstring(xml).find("e:UserData", NS)
    fields = {}
    if data is not None:
        for node in data.iter():
            if not list(node) and node.text:
                name = node.tag.split("}")[-1]
                if name in fields:
                    raise RuntimeError("Ambiguous RDP connection event")
                fields[name] = node.text
    expected_user = f"{domain}\\{username}" if domain else username
    if fields.get("SessionID") != str(session_id) or fields.get("User", "").casefold() != expected_user.casefold():
        raise RuntimeError("RDP connection event does not match the active session and user")
    if not connected_at <= event.timestamp <= now:
        raise RuntimeError("RDP connection event does not belong to the current connection")
    return {"ip": event.ip, "ip_source": f"LSM/{event.event_id}", "source_record_id": event.record_id,
            "source_timestamp": event.timestamp, "connected_at": connected_at}


class SessionSourceResolver:
    def __init__(self, read_clock=session_clock, read_event=latest_connection_event, clock=time.time):
        self.read_clock, self.read_event, self.clock = read_clock, read_event, clock
        self.cache = {}
        self.lock = threading.RLock()

    @staticmethod
    def identity(info, session_id, user_sid, username, domain):
        if (info["id"] != session_id or info["state"] != 0 or
                min(info["logon_ticks"], info["connect_ticks"]) <= FILETIME_EPOCH or
                max(info["logon_ticks"], info["connect_ticks"]) > info["current_ticks"]):
            raise RuntimeError("Active RDP connection timestamps are unavailable")
        return session_id, user_sid, username.casefold(), domain.casefold(), info["logon_ticks"], info["connect_ticks"]

    def resolve(self, session_id, user_sid, username, domain, expected_clock=None):
        with self.lock:
            before = self.read_clock(session_id)
            key = self.identity(before, session_id, user_sid, username, domain)
            if expected_clock is not None and self.identity(expected_clock, session_id, user_sid, username, domain) != key:
                raise RuntimeError("RDP session changed while reading its identity")
            cached = self.cache.get(session_id)
            if cached and cached[0] == key:
                return dict(cached[1])
            self.cache.pop(session_id, None)
            connected_at = (max(before["logon_ticks"], before["connect_ticks"]) - FILETIME_EPOCH) / 10_000_000
            xml = self.read_event(session_id)
            proof = connection_source(xml, session_id, username, domain, connected_at, self.clock())
            after = self.read_clock(session_id)
            if self.identity(after, session_id, user_sid, username, domain) != key:
                raise RuntimeError("RDP session changed while verifying its source")
            # Only cache verified bindings. Every lookup checks WTS again, invalidating the
            # binding immediately on reconnection, a different user, or reuse of a session ID.
            if len(self.cache) >= 256:
                self.cache.clear()
            self.cache[session_id] = key, dict(proof)
            return proof
