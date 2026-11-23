"""Synthetic socket/evidence tests; these do not simulate Windows authentication."""
from copy import deepcopy
import json

import pytest

from rdp_guard.proxy_evidence import (
    CHANNEL, PROVIDER, PROVIDER_GUID, WINDOWS_SCHEMA,
    correlate_evidence, endpoint, main,
)


ACTIVITY = "{f4203b90-2593-4730-bb47-6b743c610000}"


def timestamp(second):
    return f"2026-11-23T16:54:{second:02d}Z"


def native(event_id, record_id, second, activity=ACTIVITY, data=None):
    return {
        "channel": CHANNEL, "provider_name": PROVIDER, "provider_guid": "{" + PROVIDER_GUID + "}",
        "event_id": event_id, "version": 0, "record_id": record_id, "computer": "TEST-WINDOWS",
        "timestamp_utc": timestamp(second), "activity_id": activity, "related_activity_id": None,
        "in_requested_window": True, "data": [{"name": key, "value": value} for key, value in data.items()],
    }


def connection_lines(identifier=1, client="198.51.100.7:40000", upstream="172.18.0.2:59034",
                     backend="203.0.113.20:45451", accepted=20, closed=23):
    return [
        f"2026/11/23 16:54:{accepted:02d} [info] 123#0: *{identifier} client {client} connected to 0.0.0.0:45451",
        f"2026/11/23 16:54:{accepted:02d} [info] 123#0: *{identifier} proxy {upstream} connected to {backend}",
        f"2026/11/23 16:54:{closed:02d} [info] 123#0: *{identifier} upstream disconnected, bytes from/to client:4/4",
    ]


def record(kind, second, **values):
    return dict(kind=kind, capture_id="capture-a", observed_utc=timestamp(second), monotonic_ns=second * 10**9,
                **values)


def nat(second=21, *, local_port=59034, wire_port=62000, identity=99, operation="new"):
    return record("conntrack", second, operation=operation, conntrack_id=identity, zone=0,
                  original={"src": "172.18.0.2", "sport": local_port, "dst": "203.0.113.20",
                            "dport": 45451, "protocol": 6},
                  reply={"src": "203.0.113.20", "sport": 45451, "dst": "203.0.113.10",
                         "dport": wire_port, "protocol": 6})


def evidence():
    boundary = {"observed_at_utc": timestamp(45), "computer": "TEST-WINDOWS", "channel": CHANNEL,
                "is_enabled": True, "errors": [],
                "oldest": {"record_id": 1, "timestamp_utc": timestamp(0), "computer": "TEST-WINDOWS"},
                "newest": {"record_id": 200, "timestamp_utc": timestamp(40), "computer": "TEST-WINDOWS"}}
    windows = {
        "schema": WINDOWS_SCHEMA, "requested_start_utc": timestamp(10), "requested_end_utc": timestamp(40),
        "query_start_utc": timestamp(0), "exported_at_utc": timestamp(45), "max_events": 100,
        "complete": True, "truncated": False, "errors": [],
        "log_coverage": {"status": "retained", "reasons": [], "before": deepcopy(boundary),
                         "after": deepcopy(boundary)}, "events": [
            native(131, 100, 21, data={"ConnType": "TCP", "ClientIP": "203.0.113.10:62000"}),
            native(140, 101, 22, data={"IPString": "203.0.113.10"}),
        ],
    }
    linux = [record("capture_start", 10, nginx_utc_offset_minutes=0,
                    nginx_pid_namespace="pid:[123]", nginx_processes=[process()],
                    backend={"ip": "203.0.113.20", "port": 45451},
                    listener={"ip": "203.0.113.10", "port": 45451})]
    linux += [record("nginx_line", 24, line=line, source_inode=1234, offset=index * 100)
              for index, line in enumerate(connection_lines())]
    linux += [nat(), record("capture_end", 40, complete=True)]
    return windows, linux


def process(log_pid=123, host_pid=1000, start_ticks=100):
    return {"host_pid": host_pid, "namespace_pids": [host_pid, log_pid],
            "start_ticks": start_ticks, "pid_namespace": "pid:[123]"}


def result(windows, linux):
    return correlate_evidence(windows, linux)["results"][0]


def test_exact_nat_port_translation_maps_to_original_client():
    windows, linux = evidence()
    report = correlate_evidence(windows, linux)
    candidate, = report["results"]
    assert candidate["status"] == "demonstrated_candidate"
    assert candidate["client_ip"] == "198.51.100.7"
    assert candidate["proxy_peer"] == {"ip": "203.0.113.10", "port": 62000}
    assert candidate["nat_observation"]["original"]["sport"] == 59034
    assert report["shadow_only"] is True and report["enforcement_supported"] is False
    assert report["counts"] == {"failures": 1, "demonstrated_candidates": 1}
    assert report["assessment"]["status"] == "mapping_demonstrated"


@pytest.mark.parametrize("include_connection_only", [False, True])
def test_valid_windows_export_without_failures_is_insufficient_not_a_success(include_connection_only):
    windows, linux = evidence()
    windows["events"] = windows["events"][:1] if include_connection_only else []
    report = correlate_evidence(windows, linux)
    assert report["issues"] == []  # An empty native query is valid, not corrupt evidence.
    assert report["assessment"]["status"] == "insufficient_windows_evidence"
    assert "has not been demonstrated" in report["assessment"]["summary"]
    assert report["counts"] == {"failures": 0, "demonstrated_candidates": 0}
    assert report["enforcement_supported"] is False


def test_capture_integrity_takes_precedence_over_missing_windows_failures():
    windows, linux = evidence()
    windows["events"] = []
    linux.insert(-1, record("gap", 25, reason="netlink_overrun"))
    report = correlate_evidence(windows, linux)
    assert report["assessment"]["status"] == "invalid_or_incomplete_evidence"
    assert report["issues"]


def test_present_but_unmapped_windows_failure_is_not_demonstrated():
    windows, linux = evidence()
    linux = [item for item in linux if item["kind"] != "conntrack"]
    report = correlate_evidence(windows, linux)
    assert report["assessment"]["status"] == "mapping_not_demonstrated"
    assert report["counts"] == {"failures": 1, "demonstrated_candidates": 0}


def test_partial_mapping_assessment_does_not_claim_all_failures_resolved():
    windows, linux = evidence()
    windows["events"].append(native(140, 102, 22, "{f4209a59-bee6-4230-a29c-04e0f6110000}",
                                   {"IPString": "203.0.113.10"}))
    report = correlate_evidence(windows, linux)
    assert report["assessment"]["status"] == "partial_mapping_demonstrated"
    assert report["counts"] == {"failures": 2, "demonstrated_candidates": 1}


@pytest.mark.parametrize("change", ["missing", "overwritten", "disabled", "missing_boundary", "reset"])
def test_successful_query_without_verified_retention_never_demonstrates_mapping(change):
    windows, linux = evidence()
    if change == "missing":
        del windows["log_coverage"]
    elif change == "overwritten":
        windows["log_coverage"]["after"]["oldest"].update(record_id=50, timestamp_utc=timestamp(15))
    elif change == "disabled":
        windows["log_coverage"]["after"]["is_enabled"] = False
    elif change == "missing_boundary":
        windows["log_coverage"]["after"]["oldest"] = None
    else:
        windows["log_coverage"]["after"]["newest"]["record_id"] = 100
    report = correlate_evidence(windows, linux)
    assert report["issues"] == []
    assert report["windows_log_coverage"]["status"] in ("unknown", "insufficient")
    assert report["assessment"]["status"] == "insufficient_windows_evidence"
    assert report["counts"] == {"failures": 1, "demonstrated_candidates": 0}


def test_legacy_empty_export_is_insufficient_evidence_with_unknown_retention():
    windows, linux = evidence()
    windows["events"] = []
    del windows["log_coverage"]
    report = correlate_evidence(windows, linux)
    assert report["assessment"]["status"] == "insufficient_windows_evidence"
    assert report["windows_log_coverage"]["status"] == "unknown"
    assert report["issues"] == [] and report["counts"]["demonstrated_candidates"] == 0


def test_parallel_connections_are_not_matched_to_nearest_time():
    windows, linux = evidence()
    second_guid = "{f4209a59-bee6-4230-a29c-04e0f6110000}"
    windows["events"] += [
        native(131, 102, 21, second_guid, {"ConnType": "TCP", "ClientIP": "203.0.113.10:62001"}),
        native(140, 103, 22, second_guid, {"IPString": "203.0.113.10"}),
    ]
    linux[1:1] = [record("nginx_line", 24, line=line) for line in connection_lines(
        2, "198.51.100.8:40001", "172.18.0.2:59035")]
    linux.insert(-1, nat(local_port=59035, wire_port=62001, identity=100))
    results = correlate_evidence(windows, linux)["results"]
    assert [r["client_ip"] for r in results] == ["198.51.100.7", "198.51.100.8"]


@pytest.mark.parametrize("remove", ["client", "proxy", "upstream disconnected"])
def test_complete_nginx_lifecycle_is_required(remove):
    windows, linux = evidence()
    linux = [r for r in linux if r.get("kind") != "nginx_line" or f"*1 {remove}" not in r["line"]]
    assert result(windows, linux)["status"] == "unresolved"


def test_reused_activity_for_two_windows_connections_is_ambiguous():
    windows, linux = evidence()
    windows["events"].append(native(131, 102, 21, data={"ConnType": "TCP", "ClientIP": "203.0.113.10:62001"}))
    assert result(windows, linux)["reason"] == "ambiguous_activity_id"


def test_repeated_delivery_of_identical_windows_records_is_deduplicated():
    windows, linux = evidence()
    windows["events"] += deepcopy(windows["events"])
    report = correlate_evidence(windows, linux)
    assert report["counts"] == {"failures": 1, "demonstrated_candidates": 1}


def test_same_record_id_with_different_native_data_blocks_report():
    windows, linux = evidence()
    conflict = deepcopy(windows["events"][0])
    conflict["timestamp_utc"] = timestamp(20)
    windows["events"].append(conflict)
    report = correlate_evidence(windows, linux)
    assert "windows_record_conflict_or_log_reset" in report["issues"]
    assert report["counts"]["demonstrated_candidates"] == 0


@pytest.mark.parametrize("field,value", [
    ("provider_name", "Microsoft-Windows-Security-Auditing"),
    ("provider_guid", "{00000000-0000-0000-0000-000000000001}"),
    ("channel", "Security"), ("version", 1), ("activity_id", "{00000000-0000-0000-0000-000000000000}"),
])
def test_invalid_native_provenance_or_schema_is_never_a_candidate(field, value):
    windows, linux = evidence()
    windows["events"][0][field] = value
    report = correlate_evidence(windows, linux)
    assert "invalid_windows_event" in report["issues"]
    assert report["counts"]["demonstrated_candidates"] == 0


def test_failure_ip_must_equal_connection_peer():
    windows, linux = evidence()
    windows["events"][1]["data"][0]["value"] = "203.0.113.99"
    assert result(windows, linux)["reason"] == "windows_failure_ip_mismatch"


def test_nat_source_port_must_not_be_assumed_preserved():
    windows, linux = evidence()
    linux[-2]["reply"]["dport"] = 59034
    assert result(windows, linux)["reason"] == "missing_nat_mapping"


def test_reused_nginx_upstream_tuple_is_rejected_even_at_different_times():
    windows, linux = evidence()
    linux[1:1] = [record("nginx_line", 31, line=line) for line in connection_lines(
        2, "198.51.100.9:40002", accepted=30, closed=31)]
    assert result(windows, linux)["reason"] == "reused_upstream_tuple"


def test_duplicate_accept_id_or_upstream_retry_is_rejected():
    windows, linux = evidence()
    linux.insert(2, deepcopy(linux[1]))
    assert result(windows, linux)["reason"] == "incomplete_nginx_lifecycle"
    windows, linux = evidence()
    linux.insert(3, deepcopy(linux[2]))
    assert result(windows, linux)["reason"] == "incomplete_nginx_lifecycle"


@pytest.mark.parametrize("change", ["original", "generation", "zone"])
def test_reused_wire_nat_tuple_cannot_be_resolved_by_nearest_time(change):
    windows, linux = evidence()
    other = deepcopy(linux[-2])
    if change == "original":
        other["original"]["sport"] = 59999
    elif change == "generation":
        other["conntrack_id"] = 100
    else:
        other["zone"] = 1
    linux.insert(-1, other)
    assert result(windows, linux)["reason"] == "reused_or_ambiguous_nat_tuple"


def test_conntrack_time_wait_observation_does_not_invalidate_live_observation():
    windows, linux = evidence()
    linux.insert(-1, nat(second=30, operation="update"))
    assert result(windows, linux)["status"] == "demonstrated_candidate"


def test_conntrack_snapshot_outside_entire_lifecycle_is_insufficient():
    windows, linux = evidence()
    linux[-2]["observed_utc"] = timestamp(30)
    assert result(windows, linux)["reason"] == "connection_lifetime_mismatch"


@pytest.mark.parametrize("cause", ["gap", "epoch", "linux_incomplete", "windows_truncated", "windows_error"])
def test_capture_integrity_problems_block_all_candidates(cause):
    windows, linux = evidence()
    if cause == "gap":
        linux.insert(-1, record("gap", 25, reason="netlink_overrun"))
    elif cause == "epoch":
        linux[1]["capture_id"] = "another-capture"
    elif cause == "linux_incomplete":
        linux[-1]["complete"] = False
    elif cause == "windows_truncated":
        windows["truncated"] = True
    else:
        windows["errors"] = ["native read error"]
    report = correlate_evidence(windows, linux)
    assert report["issues"] and report["counts"]["demonstrated_candidates"] == 0


@pytest.mark.parametrize("value,expected", [
    ("203.0.113.10:45451", ("203.0.113.10", 45451)),
    ("[2001:db8::1]:45451", ("2001:db8::1", 45451)),
    ("[::ffff:203.0.113.10]:45451", ("203.0.113.10", 45451)),
])
def test_endpoint_parser_handles_ipv6_and_mapped_ipv4(value, expected):
    assert endpoint(value) == expected


def test_complete_ipv6_chain_uses_canonical_addresses():
    windows, linux = evidence()
    linux[0]["backend"]["ip"] = "2001:db8::20"
    linux[0]["listener"]["ip"] = "2001:db8::10"
    for item in linux:
        if item["kind"] == "nginx_line":
            item["line"] = (item["line"].replace("198.51.100.7:40000", "[2001:db8::7]:40000")
                            .replace("172.18.0.2:59034", "[fd00::2]:59034")
                            .replace("203.0.113.20:45451", "[2001:db8::20]:45451")
                            .replace("0.0.0.0:45451", "[::]:45451"))
    linux[-2]["original"].update(src="fd00::2", dst="2001:db8::20")
    linux[-2]["reply"].update(src="2001:db8::20", dst="2001:db8::10")
    windows["events"][0]["data"][1]["value"] = "[2001:0db8::10]:62000"
    windows["events"][1]["data"][0]["value"] = "2001:db8::10"
    assert result(windows, linux)["client_ip"] == "2001:db8::7"


@pytest.mark.parametrize("value", ["hostname:45451", "::1:45451", "203.0.113.10:0", "203.0.113.10:70000",
                                   "[fe80::1%1]:45451", "[::1]junk:45451"])
def test_endpoint_parser_rejects_ambiguous_or_invalid_endpoints(value):
    with pytest.raises(ValueError):
        endpoint(value)


def test_non_utc_nginx_log_timestamp_is_normalized_explicitly():
    windows, linux = evidence()
    linux[0]["nginx_utc_offset_minutes"] = 60
    for item in linux:
        if item["kind"] == "nginx_line":
            item["line"] = item["line"].replace(" 16:54:", " 17:54:")
    assert result(windows, linux)["status"] == "demonstrated_candidate"


@pytest.mark.parametrize("listen_ip,logged_endpoint", [
    (None, "0.0.0.0:45451"), (None, "[::]:45451"),
    ("0.0.0.0", "0.0.0.0:45451"), ("203.0.113.10", "[::]:45451"),
])
def test_optional_listener_address_and_wildcards(listen_ip, logged_endpoint):
    windows, linux = evidence()
    linux[0]["listener"]["ip"] = listen_ip
    linux[1]["line"] = linux[1]["line"].replace("0.0.0.0:45451", logged_endpoint)
    assert result(windows, linux)["status"] == "demonstrated_candidate"


def test_listener_port_must_match_even_without_configured_ip():
    windows, linux = evidence()
    linux[0]["listener"]["ip"] = None
    linux[1]["line"] = linux[1]["line"].replace("0.0.0.0:45451", "0.0.0.0:45452")
    assert result(windows, linux)["reason"] == "unexpected_nginx_listener"


@pytest.mark.parametrize("change,value", [("operation", "unknown"), ("zone", -1), ("conntrack_id", True)])
def test_invalid_conntrack_metadata_blocks_report(change, value):
    windows, linux = evidence()
    linux[-2][change] = value
    report = correlate_evidence(windows, linux)
    assert "invalid_conntrack_record" in report["issues"]
    assert report["counts"]["demonstrated_candidates"] == 0


def test_unknown_nginx_namespace_pid_never_maps_despite_complete_socket_logs():
    windows, linux = evidence()
    linux[0]["nginx_processes"] = [process(log_pid=124)]
    assert result(windows, linux)["reason"] == "unknown_nginx_process_identity"


def test_host_pid_is_not_mistaken_for_nginx_namespace_pid():
    windows, linux = evidence()
    linux[0]["nginx_processes"] = [process(log_pid=999, host_pid=123)]
    assert result(windows, linux)["reason"] == "unknown_nginx_process_identity"


@pytest.mark.parametrize("kind", ["nginx_process_change", "nginx_process_snapshot"])
def test_new_worker_observed_after_log_record_is_accepted(kind):
    windows, linux = evidence()
    linux[0]["nginx_processes"] = [process(log_pid=124)]
    values = {"added": [process()], "removed": []} if kind == "nginx_process_change" else {
        "nginx_processes": [process()]}
    linux.insert(-1, record(kind, 25, pid_namespace="pid:[123]", **values))
    assert result(windows, linux)["status"] == "demonstrated_candidate"


def test_graceful_worker_exit_does_not_invalidate_observed_connection():
    windows, linux = evidence()
    linux.insert(-1, record("nginx_process_change", 25, pid_namespace="pid:[123]",
                            added=[process(log_pid=124, host_pid=1001)], removed=[process()]))
    linux.insert(-1, record("nginx_process_snapshot", 25, pid_namespace="pid:[123]",
                            nginx_processes=[process(log_pid=124, host_pid=1001)]))
    assert result(windows, linux)["status"] == "demonstrated_candidate"


def test_reused_namespace_pid_with_new_start_time_blocks_capture():
    windows, linux = evidence()
    linux.insert(-1, record("nginx_process_change", 25, pid_namespace="pid:[123]",
                            added=[process(start_ticks=200)], removed=[]))
    report = correlate_evidence(windows, linux)
    assert "nginx_namespace_pid_reused" in report["issues"]
    assert report["counts"]["demonstrated_candidates"] == 0


def test_process_metadata_from_another_namespace_cannot_supply_log_pid():
    windows, linux = evidence()
    linux[0]["nginx_processes"] = []
    linux.insert(-1, record("nginx_process_snapshot", 25, pid_namespace="pid:[999]",
                            nginx_processes=[process()]))
    report = correlate_evidence(windows, linux)
    assert "mixed_nginx_pid_namespaces" in report["issues"]
    assert report["counts"]["demonstrated_candidates"] == 0


def test_cli_reads_files_and_only_prints_shadow_json(tmp_path, capsys):
    windows, linux = evidence()
    win_path, linux_path = tmp_path / "windows.json", tmp_path / "linux.jsonl"
    win_path.write_text(json.dumps(windows), encoding="utf-8")
    linux_path.write_text("\n".join(json.dumps(item) for item in linux), encoding="utf-8")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert main(["--windows", str(win_path), "--linux", str(linux_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["demonstrated_candidates"] == 1
    assert report["enforcement_supported"] is False
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
