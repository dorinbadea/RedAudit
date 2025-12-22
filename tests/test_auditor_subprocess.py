#!/usr/bin/env python3
"""
Coverage for auditor subprocess management and signal handling.
"""

import subprocess
import threading

import pytest

from redaudit.core.auditor import InteractiveNetworkAuditor


class _DummyProc:
    def __init__(self, *, running=True, timeout_once=False):
        self._running = running
        self._timeout_once = timeout_once
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self):
        return None if self._running else 0

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self._timeout_once and self.wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd="dummy", timeout=timeout or 0)
        self._running = False

    def kill(self):
        self.killed = True


def _make_auditor():
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor._subprocess_lock = threading.Lock()
    auditor._active_subprocesses = []
    auditor.logger = None
    return auditor


def test_register_and_unregister_subprocess():
    auditor = _make_auditor()
    proc = _DummyProc()

    InteractiveNetworkAuditor.register_subprocess(auditor, proc)
    assert proc in auditor._active_subprocesses

    InteractiveNetworkAuditor.unregister_subprocess(auditor, proc)
    assert proc not in auditor._active_subprocesses


def test_kill_all_subprocesses_terminates_and_kills():
    auditor = _make_auditor()
    proc_ok = _DummyProc()
    proc_timeout = _DummyProc(timeout_once=True)
    auditor._active_subprocesses = [proc_ok, proc_timeout]

    InteractiveNetworkAuditor.kill_all_subprocesses(auditor)

    assert proc_ok.terminated is True
    assert proc_timeout.killed is True
    assert auditor._active_subprocesses == []


def test_signal_handler_exits_when_scan_not_started():
    auditor = _make_auditor()
    calls = []

    auditor.print_status = lambda *_args, **_kwargs: calls.append("status")
    auditor.t = lambda key, *_args: key
    auditor.kill_all_subprocesses = lambda: calls.append("kill")
    auditor.stop_heartbeat = lambda: calls.append("heartbeat")
    auditor._active_subprocesses = [object()]
    auditor.current_phase = ""
    auditor.interrupted = False
    auditor.scan_start_time = None

    with pytest.raises(SystemExit):
        InteractiveNetworkAuditor.signal_handler(auditor, None, None)

    assert auditor.current_phase == "interrupted"
    assert auditor.interrupted is True
    assert "kill" in calls
    assert "heartbeat" in calls
