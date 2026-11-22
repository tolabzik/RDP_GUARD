"""Native tests run only in an explicitly opted-in disposable Windows CI machine."""
import os
import sys

import pytest

pytestmark = [pytest.mark.windows, pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("RDP_GUARD_NATIVE_TESTS") != "1",
    reason="Native firewall tests require an explicitly opted-in isolated Windows host")]


def test_native_event_subscription_and_bookmark():
    import win32event
    import win32evtlog
    signal = win32event.CreateEvent(None, False, False, None)
    bookmark = win32evtlog.EvtCreateBookmark(None)
    subscription = None
    try:
        xml = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
        assert "BookmarkList" in xml
        subscription = win32evtlog.EvtSubscribe("Security", win32evtlog.EvtSubscribeToFutureEvents,
            SignalEvent=signal, Query="*[System[EventID=4625]]")
        for event in win32evtlog.EvtNext(subscription, 1, 0, 0):
            event.Close()
    finally:
        if subscription:
            subscription.Close()
        bookmark.Close()
        signal.Close()


def test_native_firewall_roundtrip_and_empty_cleanup():
    from rdp_guard.firewall import FirewallEngine, owned
    from rdp_guard.windows.firewall import WindowsFirewall
    from rdp_guard.windows.platform import firewall_mutex, require_admin
    require_admin()
    backend = WindowsFirewall()
    engine = FirewallEngine(backend)
    before = {r.name for r in backend.list_rules()}
    assert not any(owned(r) for r in backend.list_rules()), "Refuse tests on an existing RDP Guard installation"
    with firewall_mutex():
        try:
            engine.reconcile(["198.51.100.254", "2001:db8::ffff"], 33345)
            rules = [r for r in backend.list_rules() if owned(r)]
            assert len(rules) == 2 and all(r.port == 33345 for r in rules)
            engine.reconcile(["198.51.100.253"], 33345)
            engine.reconcile([], 33345)
            assert not any(owned(r) for r in backend.list_rules())
        finally:
            engine.clear()
    assert {r.name for r in backend.list_rules()} == before


def test_web_rejects_administrative_process():
    from rdp_guard.windows.platform import require_unprivileged
    with pytest.raises(PermissionError):
        require_unprivileged()
