from datetime import datetime
import hashlib
from defusedxml import ElementTree as ET

from .models import AuthEvent, address

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SECURITY = "Security"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_CORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
FAILURE_SOURCES = {SECURITY: 4625, RDP_CORE: 140}
REASONS = {
    "0XC0000064": "Unknown user", "0XC000006A": "Incorrect password",
    "0XC000006D": "Logon failure", "0XC0000234": "Account locked",
    "0XC0000072": "Account disabled", "0XC0000071": "Password expired",
    "0XC000015B": "Logon type not granted",
}


def parse_event(xml: str) -> AuthEvent:
    if len(xml) > 131072:
        raise ValueError("Oversized event")
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Missing System element")
    channel = system.findtext("e:Channel", namespaces=NS)
    provider = system.find("e:Provider", NS)
    expected = {SECURITY: "Microsoft-Windows-Security-Auditing",
                RCM: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                LSM: "Microsoft-Windows-TerminalServices-LocalSessionManager",
                RDP_CORE: "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"}
    if channel not in expected or provider is None or provider.get("Name") != expected[channel]:
        raise ValueError("Unexpected event provider or channel")
    event_id = int(system.findtext("e:EventID", namespaces=NS))
    if channel == RDP_CORE and event_id != 140:
        raise ValueError("Unsupported RdpCoreTS event; only credential failure 140 is collected")
    record = int(system.findtext("e:EventRecordID", namespaces=NS))
    raw_time = system.find("e:TimeCreated", NS).get("SystemTime")
    dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    if dt.tzinfo is None or record < 0:
        raise ValueError("Invalid event time or record")
    data = {node.get("Name"): (node.text or "")[:512]
            for node in root.findall("e:EventData/e:Data", NS)}
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        for node in user_data.iter():
            if node.text and not list(node):
                data[node.tag.split("}")[-1]] = node.text[:512]
    raw_ip = data.get("IpAddress") or data.get("ClientAddress") or data.get("Address") or data.get("Param3")
    if channel == RDP_CORE:
        # Native event 140 supplies IPString, but no account or source-port identity.
        # Never fill missing fields by matching a nearby Security event.
        raw_ip = data.get("IPString")
    try:
        ip = address(raw_ip or "")
    except ValueError:
        ip = None
    logon = int(data["LogonType"]) if data.get("LogonType", "").isdigit() else None
    port = int(data["IpPort"]) if data.get("IpPort", "").isdigit() else None
    if port is not None and not 0 <= port <= 65535:
        port = None
    category, confidence = "Other", "none"
    if channel == SECURITY and event_id in (4624, 4625):
        if logon == 10:
            category, confidence = "RDP-confirmed", "high"
        elif logon == 3:
            category, confidence = "Network-auth", "unconfirmed"
    elif channel == RDP_CORE:
        category, confidence = "RDP-confirmed", "high"
    elif channel in (RCM, LSM) or (channel == SECURITY and event_id == 4778):
        category, confidence = "RDP-context", "context-only"
    status, substatus = data.get("Status", "").upper(), data.get("SubStatus", "").upper()
    reason = REASONS.get(substatus) or REASONS.get(status) or (
        "Successful authentication" if event_id == 4624 else "Context" if category == "RDP-context"
        else "Authentication failure" if event_id == 4625 else "Other")
    if channel == RDP_CORE:
        reason = "RDP authentication failure (incorrect username or password)"
    # Timestamp distinguishes reused record IDs after a channel clear. Identical records deduplicate.
    identity = f"{channel}|{record}|{raw_time}|{event_id}"
    return AuthEvent(
        hashlib.sha256(identity.encode()).hexdigest(), channel, record, dt.timestamp(), event_id, ip,
        data.get("TargetUserName") or data.get("AccountName") or data.get("User") or data.get("Param1", ""),
        data.get("TargetDomainName") or data.get("AccountDomain") or data.get("Param2", ""), logon,
        data.get("AuthenticationPackageName", ""), data.get("LogonProcessName", ""), status, substatus,
        port, category, confidence, reason,
    )
