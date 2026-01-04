"""
RedAudit - UI Manager (Extracted from AuditorUI)

This module provides standalone UI functionality that can be tested
independently from the main Auditor class.

Part of v4.0 Architecture Refactoring - Phase 1.
"""

from __future__ import annotations

import sys
import textwrap
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Optional

from redaudit.utils.constants import COLORS
from redaudit.utils.i18n import get_text


class UIManager:
    """
    Standalone UI manager for RedAudit.

    Handles all user interface operations including:
    - Status message printing with colors
    - Progress bar management
    - Translation (i18n)
    - Terminal utilities
    """

    def __init__(
        self,
        lang: str = "en",
        colors: Optional[Dict[str, str]] = None,
        logger: Optional[Any] = None,
    ):
        self.lang = lang
        self.colors = colors or COLORS
        self.logger = logger

        # Thread safety locks
        self._print_lock = threading.Lock()
        self._activity_lock = threading.Lock()
        self._ui_detail_lock = threading.Lock()

        # State
        self._ui_progress_active = False
        self._ui_detail = ""
        self.last_activity = datetime.now()
        self.current_phase = "init"

    def t(self, key: str, *args) -> str:
        """Get translated text."""
        return get_text(key, self.lang, *args)

    def touch_activity(self) -> None:
        """Update last activity timestamp."""
        with self._activity_lock:
            self.last_activity = datetime.now()

    def print_status(
        self,
        message: str,
        status: str = "INFO",
        update_activity: bool = True,
        *,
        force: bool = False,
    ) -> None:
        """Print status message with timestamp and color."""
        if update_activity:
            self.touch_activity()

        ts = datetime.now().strftime("%H:%M:%S")

        # Map internal status tokens to professional display labels
        status_map = {
            "OKGREEN": "OK",
            "OKBLUE": "INFO",
            "HEADER": "INFO",
            "WARNING": "WARN",
            "FAIL": "FAIL",
            "INFO": "INFO",
            "OK": "OK",
        }
        is_tty = sys.stdout.isatty()
        status_display = status_map.get(status, status)

        color_key = status
        if status_display == "OK":
            color_key = "OKGREEN"
        elif status_display in ("WARN", "WARNING"):
            color_key = "WARNING"
        elif status_display in ("FAIL", "ERROR"):
            color_key = "FAIL"
        elif status_display == "INFO":
            color_key = "OKBLUE"
        color = self.colors.get(color_key, self.colors.get("OKBLUE", "")) if is_tty else ""
        endc = self.colors.get("ENDC", "") if is_tty else ""

        msg = "" if message is None else str(message)
        if self._ui_progress_active and not force:
            if not self._should_emit_during_progress(msg, status_display):
                try:
                    if msg:
                        self._set_ui_detail(msg, status_display)
                except Exception:
                    pass
                if self.logger:
                    self.logger.debug("UI suppressed [%s]: %s", status_display, msg)
                return

        lines = []
        for raw_line in msg.splitlines() or [""]:
            if not raw_line:
                lines.append("")
                continue
            wrapped = textwrap.wrap(
                raw_line,
                width=100,
                break_long_words=False,
                break_on_hyphens=False,
            )
            lines.extend(wrapped if wrapped else [""])

        with self._print_lock:
            if self._ui_progress_active:
                self._print_with_rich(ts, status_display, color_key, lines)
            else:
                self._print_ansi(ts, status_display, color, endc, lines)
            sys.stdout.flush()

    def _print_with_rich(self, ts: str, status_display: str, color_key: str, lines: list) -> None:
        """Print using Rich console for progress compatibility."""
        rich_color_map = {
            "OKBLUE": "bright_blue",
            "OKGREEN": "green",
            "WARNING": "yellow",
            "FAIL": "red",
            "HEADER": "magenta",
        }
        rich_style = rich_color_map.get(color_key, "bright_blue")
        try:
            from rich.console import Console

            console = Console(
                file=getattr(sys, "__stdout__", sys.stdout),
                width=self._terminal_width(),
            )
            console.print(f"[{rich_style}][{ts}] [{status_display}][/{rich_style}] {lines[0]}")
            for line in lines[1:]:
                console.print(f"  {line}")
        except ImportError:
            self._print_ansi(ts, status_display, "", "", lines)

    def _print_ansi(self, ts: str, status_display: str, color: str, endc: str, lines: list) -> None:
        """Print using standard ANSI codes."""
        print(f"{color}[{ts}] [{status_display}]{endc} {lines[0]}")
        for line in lines[1:]:
            print(f"  {line}")

    def _should_emit_during_progress(self, msg: str, status_display: str) -> bool:
        """
        Reduce terminal noise while progress UIs are active.

        Keep FAIL always; keep WARN only for "signal" messages; suppress routine INFO/OK.
        """
        if status_display in ("FAIL", "ERROR"):
            return True

        signal_patterns = (
            "deep identity scan",
            "finished",
            "complete",
            "detected",
            "found",
            "backdoor",
            "suspicious",
        )
        if status_display in ("WARN", "WARNING"):
            msg_lower = msg.lower()
            return any(pat in msg_lower for pat in signal_patterns)

        return False

    def _set_ui_detail(self, text: str, status_display: Optional[str] = None) -> None:
        """Set current UI detail for progress displays."""
        with self._ui_detail_lock:
            self._ui_detail = self._format_ui_detail(text, status_display or "INFO")

    def _get_ui_detail(self) -> str:
        """Get current UI detail."""
        with self._ui_detail_lock:
            return self._ui_detail

    def _format_ui_detail(self, text: str, status_display: str) -> str:
        """Format UI detail text."""
        condensed = self._condense_for_ui(text)
        if len(condensed) > 60:
            condensed = condensed[:57] + "..."
        return condensed

    def _condense_for_ui(self, text: str) -> str:
        """
        Condense a log message for progress bar display.

        Extracts only essential info (IP + scan type) from verbose nmap commands.
        """
        if not text:
            return ""

        # Pattern: [nmap] 10.0.0.1 → nmap -A -sV ...
        if "[nmap]" in text and "→" in text:
            parts = text.split("→")
            if len(parts) >= 2:
                left = parts[0].replace("[nmap]", "").strip()
                cmd = parts[1].strip()
                scan_type = "scan"
                if "-A" in cmd or "-p-" in cmd:
                    scan_type = "full scan"
                elif "--top-ports" in cmd:
                    scan_type = "quick scan"
                return f"nmap {left} ({scan_type})"

        return text

    def _terminal_width(self, fallback: int = 100) -> int:
        """Get terminal width."""
        try:
            import shutil

            return shutil.get_terminal_size().columns
        except Exception:
            return fallback

    @staticmethod
    def format_eta(seconds: float) -> str:
        """Format ETA as MM:SS or H:MM:SS."""
        try:
            s = int(seconds)
            if s < 3600:
                return f"{s // 60}:{s % 60:02d}"
            return f"{s // 3600}:{(s % 3600) // 60:02d}:{s % 60:02d}"
        except (TypeError, ValueError):
            return "--:--"

    @contextmanager
    def progress_context(self):
        """Context manager for progress UI state."""
        self._ui_progress_active = True
        try:
            yield
        finally:
            self._ui_progress_active = False

    def get_progress_console(self):
        """Get a Rich console for progress displays."""
        try:
            from rich.console import Console

            return Console(width=self._terminal_width())
        except ImportError:
            return None


# Convenience function for backward compatibility
def create_ui_manager(
    lang: str = "en",
    colors: Optional[Dict[str, str]] = None,
    logger: Optional[Any] = None,
) -> UIManager:
    """Factory function to create UIManager instances."""
    return UIManager(lang=lang, colors=colors, logger=logger)
