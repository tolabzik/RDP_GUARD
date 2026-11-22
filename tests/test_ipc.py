"""Deterministic connection-contention checks; the real API is covered on Windows."""
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from rdp_guard.windows import ipc


class PipeError(Exception):
    def __init__(self, code):
        self.winerror = code


@pytest.fixture
def pipe_api(monkeypatch):
    create = Mock()
    wait = Mock()
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(error=PipeError))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(OPEN_EXISTING=3, FILE_FLAG_OVERLAPPED=0x40000000))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateFile=create))
    monkeypatch.setitem(sys.modules, "win32pipe", SimpleNamespace(WaitNamedPipe=wait))
    return create, wait


def test_open_retries_when_another_client_wins_after_wait(pipe_api):
    create, wait = pipe_api
    handle = object()
    create.side_effect = [PipeError(231), PipeError(231), handle]
    assert ipc._connect() is handle
    assert create.call_count == 3 and wait.call_count == 2


@pytest.mark.parametrize("code", [2, 5])
def test_open_does_not_retry_missing_service_or_denied_access(pipe_api, code):
    create, wait = pipe_api
    create.side_effect = PipeError(code)
    with pytest.raises(PipeError) as error:
        ipc._connect()
    assert error.value.winerror == code
    assert create.call_count == 1 and wait.call_count == 0


def test_busy_connection_has_a_total_deadline(pipe_api, monkeypatch):
    create, wait = pipe_api
    create.side_effect = PipeError(231)
    monkeypatch.setattr(ipc.time, "monotonic", Mock(side_effect=[0, 1, 5]))
    with pytest.raises(TimeoutError):
        ipc._connect(timeout=5000)
    assert create.call_count == 2 and wait.call_count == 1
    assert wait.call_args.args[1] == 4000


def test_busy_wait_timeout_is_not_retried(pipe_api):
    create, wait = pipe_api
    create.side_effect = PipeError(231)
    wait.side_effect = PipeError(121)
    with pytest.raises(TimeoutError):
        ipc._connect()
    assert create.call_count == 1 and wait.call_count == 1


def test_request_is_never_replayed_after_write(pipe_api, monkeypatch):
    create, _ = pipe_api
    handle = Mock()
    create.return_value = handle
    monkeypatch.setattr(sys.modules["win32pipe"], "SetNamedPipeHandleState", Mock(), raising=False)
    monkeypatch.setattr(sys.modules["win32pipe"], "PIPE_READMODE_MESSAGE", 2, raising=False)
    monkeypatch.setattr(ipc, "verify_server", Mock())
    write = Mock()
    monkeypatch.setattr(ipc, "write_message", write)
    monkeypatch.setattr(ipc, "read_message", Mock(side_effect=TimeoutError("lost reply")))
    request = {"op": "block", "args": {"ip": "198.51.100.1"}}
    with pytest.raises(TimeoutError):
        ipc.PipeClient().call(request)
    write.assert_called_once_with(handle, request, ipc.MAX_REQUEST)
    assert create.call_count == 1
    handle.Close.assert_called_once()
