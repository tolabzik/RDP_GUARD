from copy import deepcopy
import hashlib
import json
import ssl
import subprocess
import threading
import http.client
from xml.sax.saxutils import escape

import pytest

from rdp_guard.proxy_agent import Agent, load_config, make_server, verify_document
from rdp_guard.proxy_evidence import instant
from test_proxy_evidence import evidence, native, record, nat, connection_lines, timestamp


def xml_for(row):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{row["provider_name"]}" Guid="{row["provider_guid"]}"/>'
            f'<EventID>{row["event_id"]}</EventID><Version>{row["version"]}</Version>'
            f'<TimeCreated SystemTime="{row["timestamp_utc"]}"/>'
            f'<EventRecordID>{row["record_id"]}</EventRecordID>'
            f'<Correlation ActivityID="{row["activity_id"]}"/>'
            f'<Channel>{row["channel"]}</Channel><Computer>{row["computer"]}</Computer>'
            '</System><EventData>' + ''.join(f'<Data Name="{item["name"]}">{escape(item["value"])}</Data>'
                                           for item in row["data"]) + '</EventData></Event>')


def documents():
    win, linux = evidence()
    activity = "{04203b90-2593-4730-bb47-6b743c610001}"
    win["events"] += [native(131, 102, 26, activity, {"ConnType": "TCP", "ClientIP": "203.0.113.10:62001"}),
                      native(140, 103, 27, activity, {"IPString": "203.0.113.10"})]
    for i, line in enumerate(connection_lines(identifier=2, upstream="172.18.0.2:59035", accepted=25, closed=28)):
        linux.insert(-1, record("nginx_line", 29, line=line, source_inode=1234, offset=1000 + i * 100))
    linux.insert(-1, nat(second=26, local_port=59035, wire_port=62001, identity=100))
    win.update(computer="TEST-WINDOWS", event_count=len(win["events"]))
    for row in win["events"]:
        row["raw_xml"] = xml_for(row)
    return win, linux


def config(tmp_path):
    return load_config(dict(stream_id="rdp", backend_id="windows", computer="TEST-WINDOWS",
        client_sha256="a" * 64, api_host="127.0.0.1", api_port=9443,
        ca_file=str(tmp_path / "ca.pem"), cert_file=str(tmp_path / "server.pem"), key_file=str(tmp_path / "server.key"),
        nginx_log=str(tmp_path / "stream.log"), backend_ip="203.0.113.20", backend_port=45451,
        listener_ip="203.0.113.10", listener_port=45451, relay_ips=["203.0.113.10"],
        nginx_utc_offset_minutes=0, whitelist=["203.0.113.50/32"], threshold=2,
        state_file=str(tmp_path / "state.sqlite3")))


class Capture:
    def __init__(self, records):
        self.value = dict(healthy=True, error="", epoch="capture-a", records=records, checkpoint_utc=timestamp(40))

    def snapshot(self):
        return deepcopy(self.value)


class Firewall:
    def __init__(self):
        self.calls = []

    def sync(self, bans):
        self.calls.append(dict(bans))


def setup_agent(tmp_path, enforce=False):
    win, linux = documents()
    cfg = config(tmp_path)
    cfg["enforcement_validated"] = enforce
    clock = [instant(timestamp(15))]
    capture, firewall = Capture(linux), Firewall()
    agent = Agent(cfg, capture, firewall=firewall, clock=lambda: clock[0])
    initial = deepcopy(win)
    initial.update(events=[], event_count=0, requested_start_utc=timestamp(5), requested_end_utc=timestamp(10))
    for boundary in ("before", "after"):
        initial["log_coverage"][boundary]["observed_at_utc"] = timestamp(15)
        initial["log_coverage"][boundary]["newest"]["timestamp_utc"] = timestamp(10)
    agent.handle("/v1/evidence", dict(stream_id="rdp", backend_id="windows", mode="enforce", document=initial), "a" * 64)
    clock[0] = instant(timestamp(45))
    envelope = dict(stream_id="rdp", backend_id="windows", mode="enforce", document=win)
    return agent, envelope, clock, capture, firewall


def test_default_monitor_matches_without_enforcement(tmp_path):
    agent, envelope, _, _, fw = setup_agent(tmp_path)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    assert agent.status()["matched"] == 2
    assert agent.status()["proposed"] == 1
    assert agent.status()["active_bans"] == 0
    assert fw.calls == [{}]


def test_threshold_replay_lease_and_unblock(tmp_path):
    agent, envelope, clock, _, fw = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    assert fw.calls[-1] == {"198.51.100.7": 30}
    assert agent.status()["active_bans"] == 1
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    assert agent.status()["matched"] == 2  # overlapping exports never count twice
    clock[0] += 20
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    assert fw.calls[-1] == {}  # old valid exports do not renew authority
    agent.handle("/v1/unblock", dict(stream_id="rdp", backend_id="windows", client_ip="198.51.100.7"), "a" * 64)
    assert agent.status()["active_bans"] == 0


@pytest.mark.parametrize("change", ["certificate", "stream", "host", "raw_xml", "ip", "coverage", "stale"])
def test_untrusted_or_inconsistent_evidence_rejected(tmp_path, change):
    agent, envelope, clock, _, _ = setup_agent(tmp_path, enforce=True)
    fingerprint = "a" * 64
    if change == "certificate":
        fingerprint = "b" * 64
    elif change == "stream":
        envelope["stream_id"] = "another"
    elif change == "host":
        envelope["document"]["computer"] = "ANOTHER"
    elif change == "raw_xml":
        envelope["document"]["events"][0].pop("raw_xml")
    elif change == "ip":
        envelope["document"]["events"][1]["data"][0]["value"] = "198.51.100.99"
    elif change == "coverage":
        envelope["document"]["log_coverage"]["status"] = "insufficient"
    else:
        clock[0] += 200
    with pytest.raises((ValueError, PermissionError)):
        agent.handle("/v1/evidence", envelope, fingerprint)
    assert agent.status()["active_bans"] == 0


def test_capture_gap_inhibits_and_whitelist_protects(tmp_path):
    agent, envelope, _, capture, fw = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    capture.value["healthy"] = False
    agent.tick()
    assert agent.status()["matched"] == 0
    assert fw.calls == [{}]
    capture.value["healthy"] = True
    agent.config["whitelist"].append("198.51.100.7/32")
    agent.tick()
    assert {r["status"] for r in agent.results()} == {"whitelisted"}
    assert agent.status()["active_bans"] == 0


def test_no_raw_ip_ban_api_and_config_guardrails(tmp_path):
    agent, _, _, _, _ = setup_agent(tmp_path)
    with pytest.raises(LookupError):
        agent.handle("/v1/ban", dict(stream_id="rdp", backend_id="windows", client_ip="198.51.100.7"), "a" * 64)
    cfg = config(tmp_path)
    cfg["whitelist"] = []
    with pytest.raises(ValueError):
        load_config(cfg)
    cfg = config(tmp_path)
    cfg["arbitrary_shell"] = "echo bad"
    with pytest.raises(ValueError):
        load_config(cfg)


def test_native_xml_is_cross_checked(tmp_path):
    win, _ = documents()
    assert len(verify_document(win, "TEST-WINDOWS", instant(timestamp(45)))) == 4
    win["events"][0]["raw_xml"] = win["events"][0]["raw_xml"].replace("62000", "62099")
    with pytest.raises(ValueError, match="disagree"):
        verify_document(win, "TEST-WINDOWS", instant(timestamp(45)))


def test_agent_does_not_restore_heartbeat_on_restart(tmp_path):
    agent, envelope, clock, capture, fw = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    cfg = agent.config
    agent.close()
    restarted = Agent(cfg, capture, firewall=fw, clock=lambda: clock[0])
    restarted.tick()
    assert restarted.status()["mode"] == "monitor"
    assert fw.calls[-1] == {}


def test_old_monitor_pending_never_becomes_enforcement(tmp_path):
    agent, envelope, clock, capture, _ = setup_agent(tmp_path, enforce=True)
    envelope["mode"] = "monitor"
    capture.value["healthy"] = False
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    newer = deepcopy(envelope)
    newer["mode"] = "enforce"
    newer["document"]["requested_end_utc"] = timestamp(41)
    agent.handle("/v1/evidence", newer, "a" * 64)
    capture.value["healthy"] = True
    agent.tick()
    assert agent.status()["active_bans"] == 0
    assert agent.db.execute("SELECT COUNT(*) FROM bans").fetchone()[0] == 0
    # An older enforce retry cannot undo a newer monitor instruction.
    clock[0] += 1
    newer["mode"] = "monitor"
    newer["document"]["requested_end_utc"] = timestamp(42)
    agent.handle("/v1/evidence", newer, "a" * 64)
    envelope["mode"] = "enforce"
    agent.handle("/v1/evidence", envelope, "a" * 64)
    assert agent.mode == "monitor"


def test_state_scope_is_immutable(tmp_path):
    agent, _, clock, capture, _ = setup_agent(tmp_path)
    cfg = dict(agent.config, listener_port=45452)
    agent.close()
    with pytest.raises(ValueError, match="different proxy binding"):
        Agent(cfg, capture, clock=lambda: clock[0])


def certificates(tmp_path):
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], cwd=tmp_path, check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=TestCA",
            "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name in ("server", "client", "other"):
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
                "-keyout", name + ".key", "-out", name + ".csr")
        extension = "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" if name == "server" else "extendedKeyUsage=clientAuth\n"
        (tmp_path / (name + ".ext")).write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n" + extension)
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", name + ".pem", "-days", "1", "-extfile", name + ".ext")


def test_real_mtls_transport_requires_enrolled_certificate_and_scope(tmp_path):
    from rdp_guard.proxy_client import ProxyTransport
    certificates(tmp_path)
    agent, envelope, _, _, _ = setup_agent(tmp_path)
    der = ssl.PEM_cert_to_DER_cert((tmp_path / "client.pem").read_text())
    agent.config["client_sha256"] = hashlib.sha256(der).hexdigest()
    agent.config["api_port"] = 0
    server = make_server(agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    binding = dict(agent_url=f"https://127.0.0.1:{server.server_address[1]}",
                   ca_file=str(tmp_path / "ca.pem"), cert_file=str(tmp_path / "client.pem"), key_file=str(tmp_path / "client.key"))
    try:
        receipt = ProxyTransport(binding).post("/v1/evidence", envelope)
        assert receipt["ok"] and receipt["status"]["computer"] == "TEST-WINDOWS"
        agent.tick()
        assert agent.status()["matched"] == 2
        denied = dict(binding, cert_file=str(tmp_path / "other.pem"), key_file=str(tmp_path / "other.key"))
        with pytest.raises(ValueError):
            ProxyTransport(denied).post("/v1/status", {"stream_id": "rdp", "backend_id": "windows"})
        context = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
        unauth = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=context, timeout=2)
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            unauth.request("POST", "/v1/status", body=json.dumps({}), headers={"Content-Type": "application/json"})
            unauth.getresponse()
        unauth.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
