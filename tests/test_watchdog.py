"""Task Scheduler identity must be verified by SID, not a translated account name."""
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from rdp_guard.windows.platform import principal_sid, watchdog_checks

SYSTEM_SID = "S-1-5-18"
EXECUTABLE = r"C:\Program Files\RDPGuard\rdpguard.exe"


@pytest.fixture
def identities(monkeypatch):
    names = {name: SYSTEM_SID for name in ("SYSTEM", r"NT AUTHORITY\SYSTEM", "СИСТЕМА", r"NT AUTHORITY\СИСТЕМА")}
    names["ordinary-user"] = "S-1-5-21-1-2-3-1001"
    def lookup(machine, name):
        if name not in names:
            raise OSError("No mapping between account names and security IDs")
        return names[name], "NT AUTHORITY", 5
    api = SimpleNamespace(LookupAccountName=Mock(side_effect=lookup),
                          ConvertStringSidToSid=Mock(side_effect=lambda sid: sid),
                          ConvertSidToStringSid=Mock(side_effect=lambda sid: sid))
    monkeypatch.setitem(sys.modules, "win32security", api)
    return names, api


@pytest.fixture
def task():
    action = SimpleNamespace(Path=EXECUTABLE, Arguments="watchdog")
    return SimpleNamespace(Enabled=True, LastTaskResult=0, State=3,
        Definition=SimpleNamespace(Principal=SimpleNamespace(UserId="СИСТЕМА"),
            Actions=SimpleNamespace(Count=1, Item=lambda index: action)))


@pytest.mark.parametrize("name", ["SYSTEM", r"NT AUTHORITY\SYSTEM", "СИСТЕМА", r"NT AUTHORITY\СИСТЕМА", SYSTEM_SID])
def test_localized_system_principal_passes_by_sid(identities, task, name):
    _, api = identities
    task.Definition.Principal.UserId = name
    assert all(watchdog_checks(task, EXECUTABLE, 2).values())
    if name == SYSTEM_SID:
        api.LookupAccountName.assert_not_called()
        api.ConvertStringSidToSid.assert_called_once_with(SYSTEM_SID)
    else:
        api.LookupAccountName.assert_called_once_with(None, name)


def test_display_name_alone_never_grants_system_identity(identities, task):
    names, _ = identities
    names["СИСТЕМА"] = "S-1-5-21-1-2-3-1001"
    assert not watchdog_checks(task, EXECUTABLE, 2)["system_account"]


def test_unresolvable_principal_is_not_accepted(identities):
    with pytest.raises(OSError):
        principal_sid("missing-account")


@pytest.mark.parametrize("case, failed", [
    ("disabled", "task_enabled"), ("extra-action", "single_action"),
    ("no-action", "single_action"), ("wrong-exe", "expected_executable"),
    ("wrong-args", "watchdog_argument"), ("ordinary-user", "system_account"),
    ("run-error", "successful_run"), ("stale", "recent_heartbeat"),
    ("future", "recent_heartbeat"), ("running-code-but-stopped", "successful_run"),
])
def test_localization_fix_preserves_other_watchdog_checks(identities, task, case, failed):
    age = 2
    if case == "disabled":
        task.Enabled = False
    elif case in ("extra-action", "no-action"):
        task.Definition.Actions.Count = 2 if case == "extra-action" else 0
    elif case == "wrong-exe":
        task.Definition.Actions.Item(1).Path = r"C:\other.exe"
    elif case == "wrong-args":
        task.Definition.Actions.Item(1).Arguments = "status"
    elif case == "ordinary-user":
        task.Definition.Principal.UserId = "ordinary-user"
    elif case in ("run-error", "running-code-but-stopped"):
        task.LastTaskResult = 1 if case == "run-error" else 267009
    elif case == "stale":
        age = 150
    elif case == "future":
        age = -1
    checks = watchdog_checks(task, EXECUTABLE, age)
    assert checks[failed] is False
    assert not all(checks.values())


def test_running_task_requires_fresh_heartbeat(identities, task):
    task.LastTaskResult, task.State = 267009, 4
    assert all(watchdog_checks(task, EXECUTABLE, 2).values())
    assert not all(watchdog_checks(task, EXECUTABLE, 150).values())
