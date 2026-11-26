import io
import json
import sys
from types import SimpleNamespace

from rdp_guard.cli import main


def test_status_preserves_unicode_in_legacy_windows_pipe(tmp_path, monkeypatch):
    result = {"recovery": {"reason": "Ожидание синхронизации"}, "user": "Администратор"}
    monkeypatch.setitem(sys.modules, "rdp_guard.windows.platform",
                        SimpleNamespace(DATA_DIR=tmp_path, require_admin=lambda: None))
    monkeypatch.setitem(sys.modules, "rdp_guard.windows.ipc",
                        SimpleNamespace(PipeClient=lambda: SimpleNamespace(call=lambda request: result)))
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    assert main(["status"]) == 0
    stream.flush()
    assert json.loads(buffer.getvalue().decode("ascii")) == result


def test_unicode_error_does_not_crash_legacy_windows_stderr(tmp_path, monkeypatch):
    def fail():
        raise RuntimeError("Служба недоступна")
    monkeypatch.setitem(sys.modules, "rdp_guard.windows.platform",
                        SimpleNamespace(DATA_DIR=tmp_path, require_admin=fail))
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")
    monkeypatch.setattr(sys, "stderr", stream)
    assert main(["status"]) == 1
    stream.flush()
    assert buffer.getvalue().startswith(b"RDP Guard: ")
