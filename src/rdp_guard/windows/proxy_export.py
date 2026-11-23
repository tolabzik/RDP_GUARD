"""Bounded native event-log exports, separate from the authentication collector."""
from datetime import datetime, timezone
import json
import platform
import time
import uuid

from defusedxml import ElementTree as ET

from ..proxy_evidence import CHANNEL, PROVIDER, PROVIDER_GUID, WINDOWS_SCHEMA, instant, windows_log_coverage


MAX_BYTES = 32 * 1024 * 1024
MAX_XML_BYTES = 131072
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _system(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_XML_BYTES:
        raise ValueError("Native event exceeds XML size limit")
    root = ET.fromstring(raw)
    system = root.find("e:System", NS)
    if system is None or system.findtext("e:Channel", namespaces=NS) != CHANNEL:
        raise ValueError("Unexpected native event channel")
    computer = system.findtext("e:Computer", namespaces=NS)
    record_id = int(system.findtext("e:EventRecordID", namespaces=NS))
    timestamp = system.find("e:TimeCreated", NS).attrib["SystemTime"]
    instant(timestamp)
    if not computer or not computer.strip() or record_id < 1:
        raise ValueError("Missing native event identity")
    return root, system, {"record_id": record_id, "timestamp_utc": timestamp, "computer": computer}


def native_event(raw, start, end):
    root, system, record = _system(raw)
    provider = system.find("e:Provider", NS)
    event_id = int(system.findtext("e:EventID", namespaces=NS))
    version = int(system.findtext("e:Version", namespaces=NS))
    if (provider is None or provider.attrib.get("Name") != PROVIDER
            or str(uuid.UUID(provider.attrib.get("Guid", "").strip("{}"))) != PROVIDER_GUID
            or event_id not in (131, 140) or version != 0):
        raise ValueError("Unsupported native proxy event schema")
    correlation = system.find("e:Correlation", NS)
    attributes = correlation.attrib if correlation is not None else {}
    return dict(record, channel=CHANNEL, provider_name=PROVIDER, provider_guid=provider.attrib["Guid"],
                event_id=event_id, version=version, activity_id=attributes.get("ActivityID", ""),
                related_activity_id=attributes.get("RelatedActivityID", ""),
                in_requested_window=start <= instant(record["timestamp_utc"]) < end,
                data=[{"name": item.attrib.get("Name", ""), "value": item.text or ""}
                      for item in root.findall("e:EventData/e:Data", NS)], raw_xml=raw)


class NativeProxyExporter:
    def __init__(self, api=None, clock=time.time):
        self._api, self.clock = api, clock

    @property
    def api(self):
        if self._api is None:
            import win32evtlog
            self._api = win32evtlog
        return self._api

    def _query(self, query, limit, *, oldest=False):
        api = self.api
        flags = api.EvtQueryChannelPath | (api.EvtQueryForwardDirection if oldest else api.EvtQueryReverseDirection)
        handle = api.EvtQuery(CHANNEL, flags, query)
        result, size = [], 0
        try:
            while len(result) < limit:
                try:
                    batch = api.EvtNext(handle, min(128, limit - len(result)), 1000, 0)
                except Exception as exc:
                    if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                        break
                    raise
                if not batch:
                    break
                try:
                    for event in batch:
                        raw = api.EvtRender(event, api.EvtRenderEventXml)
                        length = len(raw.encode("utf-8"))
                        size += length
                        if length > MAX_XML_BYTES or size > MAX_BYTES:
                            raise ValueError("Native event export exceeds size limit")
                        result.append(raw)
                finally:
                    for event in batch:
                        event.Close()
        finally:
            handle.Close()
        return result

    def _snapshot(self):
        api = self.api
        snapshot = dict(observed_at_utc=utc(self.clock()), computer=platform.node(), channel=CHANNEL,
                        is_enabled=None, log_mode=None, maximum_size_bytes=None, record_count=None,
                        oldest_record_number=None, oldest=None, newest=None, errors=[])
        config = log = None
        try:
            config = api.EvtOpenChannelConfig(CHANNEL)
            def prop(key):
                return api.EvtGetChannelConfigProperty(config, getattr(api, key), 0)[0]
            snapshot["is_enabled"] = bool(prop("EvtChannelConfigEnabled"))
            retention, backup = prop("EvtChannelLoggingConfigRetention"), prop("EvtChannelLoggingConfigAutoBackup")
            snapshot["log_mode"] = "AutoBackup" if backup else "Retain" if retention else "Circular"
            snapshot["maximum_size_bytes"] = prop("EvtChannelLoggingConfigMaxSize")
            log = api.EvtOpenLog(CHANNEL, api.EvtOpenChannelPath)
            snapshot["record_count"] = api.EvtGetLogInfo(log, api.EvtLogNumberOfLogRecords)[0]
            snapshot["oldest_record_number"] = api.EvtGetLogInfo(log, api.EvtLogOldestRecordNumber)[0]
        except Exception:
            snapshot["errors"].append("Native channel metadata could not be read")
        finally:
            for handle in (config, log):
                if handle is not None:
                    handle.Close()
        for name in ("oldest", "newest"):
            try:
                records = self._query("*", 1, oldest=name == "oldest")
                if not records:
                    raise ValueError("Empty channel")
                snapshot[name] = _system(records[0])[2]
            except Exception:
                snapshot["errors"].append(f"Native {name} record is unavailable")
        return snapshot

    def export(self, start_utc, end_utc, *, lookback_seconds=5, max_events=5000):
        start, end = instant(start_utc), instant(end_utc)
        if not 0 < end - start <= 86400 or end > self.clock():
            raise ValueError("Export window must be elapsed and bounded")
        if type(max_events) is not int or not 1 <= max_events <= 5000:
            raise ValueError("Invalid export event limit")
        if type(lookback_seconds) is not int or not 0 <= lookback_seconds <= 3600:
            raise ValueError("Invalid export lookback")
        query_start = start - lookback_seconds
        before, records, errors = self._snapshot(), [], []
        query = ("*[System[(EventID=131 or EventID=140) and TimeCreated["
                 f"@SystemTime >= '{utc(query_start)}' and @SystemTime < '{utc(end)}']]]")
        try:
            records = self._query(query, max_events + 1)
        except Exception:
            errors.append("Native event query failed or exceeded its size limit")
        after = self._snapshot()
        truncated = len(records) > max_events
        if truncated:
            errors.append("Native event query exceeded max_events")
        events, filtered = [], 0
        for raw in records[:max_events]:
            try:
                event = native_event(raw, start, end)
                timestamp = instant(event["timestamp_utc"])
                if not query_start <= timestamp < end or (event["event_id"] == 140 and timestamp < start):
                    filtered += 1
                else:
                    events.append(event)
            except Exception:
                errors.append("Native event conversion failed")
        coverage = dict(status="retained", reasons=[], before=before, after=after)
        computer = (before.get("oldest") or {}).get("computer", platform.node())
        document = dict(schema=WINDOWS_SCHEMA, computer=computer, log_coverage=coverage,
                        requested_start_utc=utc(start), requested_end_utc=utc(end),
                        query_start_utc=utc(query_start), exported_at_utc=utc(self.clock()),
                        window_end_exclusive=True, lookback_seconds=lookback_seconds, max_events=max_events,
                        complete=not errors, truncated=truncated, queried_event_count=len(records),
                        event_count=len(events), filtered_out_count=filtered, errors=errors,
                        events=sorted(events, key=lambda e: (instant(e["timestamp_utc"]), e["record_id"])))
        coverage.update(windows_log_coverage(document, events))
        if len(json.dumps(document, ensure_ascii=False).encode("utf-8")) > MAX_BYTES:
            raise ValueError("Serialized evidence exceeds size limit")
        return document
