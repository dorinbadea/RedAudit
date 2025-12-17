#!/usr/bin/env python3
"""
RedAudit - Power/Sleep Inhibition Helpers

Best-effort utilities to prevent system sleep (and, when possible, display sleep)
while a scan is running.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class _XsetState:
    screensaver_enabled: Optional[bool] = None
    screensaver_timeout: Optional[int] = None
    screensaver_cycle: Optional[int] = None
    dpms_enabled: Optional[bool] = None
    dpms_standby: Optional[int] = None
    dpms_suspend: Optional[int] = None
    dpms_off: Optional[int] = None


class SleepInhibitor:
    """
    Best-effort inhibitor for long-running scans.

    - macOS: uses `caffeinate` (prevents idle sleep + display sleep)
    - Linux/systemd: uses `systemd-inhibit` (prevents idle/system sleep)
    - Linux/X11: uses `xset` to disable DPMS/screen saver while running
    """

    def __init__(self, *, reason: str = "RedAudit scan", logger: Any = None):
        self._reason = reason
        self._logger = logger
        self._proc: Optional[subprocess.Popen] = None
        self._xset_state: Optional[_XsetState] = None

    def start(self) -> None:
        if self._proc is not None:
            return

        system = platform.system().lower()
        if system == "darwin":
            self._start_caffeinate()
        elif system == "linux":
            self._start_systemd_inhibit()
            self._apply_x11_no_sleep()
        else:
            return

    def stop(self) -> None:
        self._restore_x11_state()
        proc = self._proc
        self._proc = None
        if not proc:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def __enter__(self) -> "SleepInhibitor":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _log(self, level: str, message: str) -> None:
        if not self._logger:
            return
        try:
            if level == "DEBUG" and hasattr(self._logger, "debug"):
                self._logger.debug(message)
            elif level == "WARNING" and hasattr(self._logger, "warning"):
                self._logger.warning(message)
            elif hasattr(self._logger, "info"):
                self._logger.info(message)
        except Exception:
            return

    def _start_caffeinate(self) -> None:
        caffeinate = shutil.which("caffeinate")
        if not caffeinate:
            return
        try:
            # -d: display, -i: idle sleep, -m: disk, -s: system sleep (AC), -u: user activity
            # -w <pid>: stay active while this pid is running
            self._proc = subprocess.Popen(
                [caffeinate, "-dimsu", "-w", str(os.getpid())],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._log("DEBUG", "Sleep inhibitor enabled via caffeinate")
        except Exception:
            self._proc = None

    def _start_systemd_inhibit(self) -> None:
        systemd_inhibit = shutil.which("systemd-inhibit")
        if not systemd_inhibit:
            return
        try:
            # Keep an inhibitor alive while RedAudit runs.
            # Note: display sleep is handled separately (X11) when possible.
            self._proc = subprocess.Popen(
                [
                    systemd_inhibit,
                    "--what=idle:sleep:handle-lid-switch",
                    f"--why={self._reason}",
                    "--mode=block",
                    "bash",
                    "-lc",
                    "while true; do sleep 3600; done",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            self._log("DEBUG", "Sleep inhibitor enabled via systemd-inhibit")
        except Exception:
            self._proc = None

    def _apply_x11_no_sleep(self) -> None:
        # Only applies to X11 sessions with DISPLAY.
        if not os.environ.get("DISPLAY"):
            return
        xset = shutil.which("xset")
        if not xset:
            return
        try:
            state = self._capture_xset_state(xset)
            self._xset_state = state
            subprocess.run([xset, "s", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(
                [xset, "s", "noblank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run([xset, "-dpms"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._log("DEBUG", "Display sleep inhibited via xset")
        except Exception:
            self._xset_state = None

    def _restore_x11_state(self) -> None:
        if not os.environ.get("DISPLAY"):
            return
        xset = shutil.which("xset")
        if not xset or not self._xset_state:
            return
        try:
            self._restore_xset_state(xset, self._xset_state)
        except Exception:
            return
        finally:
            self._xset_state = None

    def _capture_xset_state(self, xset: str) -> _XsetState:
        state = _XsetState()
        res = subprocess.run([xset, "q"], capture_output=True, text=True, timeout=2)
        out = (res.stdout or "") + "\n" + (res.stderr or "")

        # Screen Saver: prefer parsing "timeout:" and "cycle:"
        m = re.search(r"timeout:\s*(\d+)\s+cycle:\s*(\d+)", out, re.IGNORECASE)
        if m:
            state.screensaver_timeout = int(m.group(1))
            state.screensaver_cycle = int(m.group(2))

        # DPMS timeouts: "Standby: X    Suspend: Y    Off: Z"
        m = re.search(r"Standby:\s*(\d+)\s+Suspend:\s*(\d+)\s+Off:\s*(\d+)", out, re.IGNORECASE)
        if m:
            state.dpms_standby = int(m.group(1))
            state.dpms_suspend = int(m.group(2))
            state.dpms_off = int(m.group(3))

        state.dpms_enabled = bool(re.search(r"DPMS is Enabled", out, re.IGNORECASE))
        # No reliable single string for screensaver enabled; treat timeout==0 as "off".
        if state.screensaver_timeout is not None:
            state.screensaver_enabled = state.screensaver_timeout > 0

        return state

    def _restore_xset_state(self, xset: str, state: _XsetState) -> None:
        # Restore screen saver
        if state.screensaver_enabled is not None:
            subprocess.run(
                [xset, "s", "on" if state.screensaver_enabled else "off"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if state.screensaver_timeout is not None and state.screensaver_cycle is not None:
            subprocess.run(
                [xset, "s", str(state.screensaver_timeout), str(state.screensaver_cycle)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        # Restore DPMS
        if state.dpms_enabled is not None:
            subprocess.run(
                [xset, "+dpms" if state.dpms_enabled else "-dpms"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if (
            state.dpms_standby is not None
            and state.dpms_suspend is not None
            and state.dpms_off is not None
        ):
            subprocess.run(
                [
                    xset,
                    "dpms",
                    str(state.dpms_standby),
                    str(state.dpms_suspend),
                    str(state.dpms_off),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
