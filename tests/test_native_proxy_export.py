import copy
import json

import pytest

from rdp_guard.proxy_evidence import CHANNEL, PROVIDER
from rdp_guard.windows.proxy_export import NativeProxyExporter, utc


NOW = 2000000000


def xml(event_id, record, timestamp, computer="WIN-TEST"):
    data = ('<Data Name="ConnType">TCP</Data><Data Name="ClientIP">45.144.220.53:59034</Data>'
            if event_id == 131 else '<Data Name="IPString">45.144.220.53</Data>')
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{PROVIDER}" Guid="{{1139c61b-b549-4251-8ed3-27250a1edec8}}"/>'
            f'<EventID>{event_id}</EventID><Version>0</Version><EventRecordID>{record}</EventRecordID>'
            f'<TimeCreated SystemTime="{utc(timestamp)}"/><Channel>{CHANNEL}</Channel>'
            f'<Computer>{computer}</Computer><Correlation ActivityID="{{f4203b90-2593-4730-bb47-6b743c610000}}"/>'
            f'</System><EventData>{data}</EventData></Event>')


class Handle:
    def __init__(self, data=None):
        self.data, self.closed = data, False

    def Close(self):
        self.closed = True


class Api:
    EvtQueryChannelPath = 0
    EvtQueryForwardDirection = 1
    EvtQueryReverseDirection = 2
    EvtRenderEventXml = 1
    EvtOpenChannelPath = 1
    EvtChannelConfigEnabled = 1
    EvtChannelLoggingConfigRetention = 2
    EvtChannelLoggingConfigAutoBackup = 3
    EvtChannelLoggingConfigMaxSize = 4
    EvtLogNumberOfLogRecords = 5
    EvtLogOldestRecordNumber = 6

    def __init__(self, records=None):
        self.records = records or [xml(131, 10, NOW-33), xml(140, 11, NOW-20)]
        self.handles, self.queries = [], []
        self.enabled, self.fail, self.rollover = True, False, False
        self.metadata_reads = 0

    def handle(self, data=None):
        result = Handle(data)
        self.handles.append(result)
        return result

    def EvtOpenChannelConfig(self, channel, Session=None, Flags=0):
        assert channel == CHANNEL and Session is None and Flags == 0
        self.metadata_reads += 1
        return self.handle()

    def EvtGetChannelConfigProperty(self, handle, prop, flags):
        return {1: self.enabled, 2: False, 3: False, 4: 1052672}[prop], 1

    def EvtOpenLog(self, *args):
        return self.handle()

    def EvtGetLogInfo(self, handle, prop):
        return {5: 100, 6: 1}[prop], 1

    def EvtQuery(self, channel, flags, query):
        assert channel == CHANNEL
        self.queries.append(query)
        if query == "*":
            if flags == self.EvtQueryForwardDirection:
                rows = [xml(131, 101 if self.rollover and self.metadata_reads == 2 else 1,
                            NOW-30 if self.rollover and self.metadata_reads == 2 else NOW-100)]
            else:
                rows = [xml(140, 200, NOW-1)]
        else:
            if self.fail:
                raise OSError("Query failed")
            rows = list(self.records)
        return self.handle(rows)

    def EvtNext(self, handle, limit, timeout, flags):
        rows = handle.data[:limit]
        del handle.data[:limit]
        return [self.handle(row) for row in rows]

    def EvtRender(self, handle, flags):
        return handle.data


def export(api, **kwargs):
    return NativeProxyExporter(api, clock=lambda: NOW).export(utc(NOW-32), utc(NOW-2), **kwargs)


def test_native_export_keeps_raw_fields_and_closes_all_handles():
    api = Api()
    result = export(api)
    assert result["complete"] is True and result["log_coverage"]["status"] == "retained"
    assert result["computer"] == "WIN-TEST"
    assert result["events"][0]["raw_xml"] == api.records[0]
    assert result["events"][0]["in_requested_window"] is False
    assert result["events"][1]["in_requested_window"] is True
    assert all(handle.closed for handle in api.handles)
    assert utc(NOW-37) in api.queries[2]
    json.dumps(result)


def test_native_query_cap_marks_incomplete():
    api = Api()
    result = export(api, max_events=1)
    assert result["complete"] is False and result["truncated"] is True
    assert result["queried_event_count"] == 2
    assert all(handle.closed for handle in api.handles)


@pytest.mark.parametrize("change,status", [("rollover", "insufficient"), ("enabled", "unknown"), ("fail", "retained")])
def test_native_failure_and_retention_are_separate(change, status):
    api = Api()
    setattr(api, change, change != "enabled")
    result = export(api)
    assert result["log_coverage"]["status"] == status
    assert result["complete"] is (change != "fail")
    assert all(handle.closed for handle in api.handles)


def test_native_host_mismatch_is_not_retained():
    api = Api([xml(140, 11, NOW-20, computer="OTHER")])
    assert export(api)["log_coverage"]["status"] == "unknown"


def test_native_future_end_is_rejected_without_querying():
    api = Api()
    with pytest.raises(ValueError, match="elapsed"):
        NativeProxyExporter(api, clock=lambda: NOW).export(utc(NOW-2), utc(NOW+1))
    assert api.queries == []


def test_native_out_of_window_failures_do_not_get_counted():
    api = Api([xml(140, 8, NOW-33), xml(131, 9, NOW-38), xml(140, 11, NOW-20), xml(140, 12, NOW-2)])
    result = export(api)
    assert result["event_count"] == 1 and result["filtered_out_count"] == 3


def test_native_unsupported_xml_marks_incomplete():
    api = Api()
    api.records = copy.copy(api.records)
    api.records[1] = api.records[1].replace("<Version>0", "<Version>1")
    result = export(api)
    assert not result["complete"] and result["event_count"] == 1


def test_native_export_is_accepted_by_agent_provenance_validator():
    from rdp_guard.proxy_agent import verify_document
    result = export(Api())
    verified = verify_document(result, "WIN-TEST", NOW)
    assert [item["event_id"] for item in verified] == [131, 140]
