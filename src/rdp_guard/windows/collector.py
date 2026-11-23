import logging
import threading
import time

from ..events import LSM, RCM, RDP_CORE, SECURITY

LOG = logging.getLogger(__name__)
QUERIES = {
    SECURITY: "*[System[(EventID=4624 or EventID=4625 or EventID=4778)]]",
    RCM: "*[System[EventID=1149]]",
    LSM: "*[System[(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25)]]",
    RDP_CORE: "*[System[EventID=140]]",
}


class Collector(threading.Thread):
    def __init__(self, guard, channel, stop):
        super().__init__(name=f"events-{channel}", daemon=True)
        self.guard, self.channel, self.stop = guard, channel, stop

    def run(self):
        import win32event
        import win32evtlog
        delay = 1
        while not self.stop.is_set():
            subscription = bookmark = signal = None
            try:
                saved = self.guard.store.rows("SELECT xml FROM bookmarks WHERE channel=?", (self.channel,))
                bookmark = win32evtlog.EvtCreateBookmark(saved[0]["xml"] if saved else None)
                signal = win32event.CreateEvent(None, False, False, None)
                flags = win32evtlog.EvtSubscribeStartAfterBookmark if saved else win32evtlog.EvtSubscribeStartAtOldestRecord
                subscription = win32evtlog.EvtSubscribe(
                    self.channel, flags | win32evtlog.EvtSubscribeStrict, SignalEvent=signal,
                    Query=QUERIES[self.channel], Bookmark=bookmark if saved else None)
                with self.guard.lock:
                    self.guard.collectors[self.channel] = {"healthy": True, "error": "", "connected": time.time()}
                delay = 1
                while not self.stop.is_set():
                    win32event.WaitForSingleObject(signal, 1000)
                    while not self.stop.is_set():
                        batch = win32evtlog.EvtNext(subscription, 128, 0, 0)
                        if not batch:
                            break
                        try:
                            for event in batch:
                                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                                win32evtlog.EvtUpdateBookmark(bookmark, event)
                                position = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
                                self.guard.ingest(xml, self.channel, position)
                        finally:
                            for event in batch:
                                event.Close()
            except Exception as exc:
                LOG.exception("Event subscription failed for %s", self.channel)
                with self.guard.lock:
                    self.guard.collectors[self.channel] = {"healthy": False, "error": str(exc)}
                    self.guard.store.audit("collector", "subscription-error", {"channel": self.channel, "error": str(exc)})
                    if getattr(exc, "winerror", None) in (15011, 15012):
                        with self.guard.store.transaction() as db:
                            db.execute("DELETE FROM bookmarks WHERE channel=?", (self.channel,))
                            self.guard.store.audit("collector", "log-gap", {"channel": self.channel,
                                "recovery": "Resubscribe at oldest available; unavailable records cannot be recovered"})
                self.stop.wait(delay)
                delay = min(delay * 2, 60)
            finally:
                for handle in (subscription, bookmark, signal):
                    if handle is not None:
                        handle.Close()
