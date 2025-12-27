#!/usr/bin/env python3
"""
RedAudit - Session Log Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.7: Captures terminal output during scan execution for auditability.
Creates both raw (.log with ANSI) and clean (.txt without ANSI) versions.
"""

import io
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, TextIO

# ANSI escape code pattern for stripping colors
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class SessionLogger:
    """
    Captures stdout/stderr to log files while preserving terminal output.

    Usage:
        logger = SessionLogger(output_dir)
        logger.start()
        # ... run scan ...
        logger.stop()
    """

    def __init__(
        self,
        output_dir: str,
        session_name: Optional[str] = None,
        *,
        mode: Optional[str] = None,
    ):
        """
        Initialize session logger.

        Args:
            output_dir: Base directory for reports
            session_name: Optional name for session (defaults to timestamp)
        """
        self.output_dir = Path(output_dir)
        self.session_dir = self.output_dir / "session_logs"
        self.session_name = session_name or datetime.now().strftime("%Y%m%d_%H%M%S")

        self.log_file: Optional[TextIO] = None
        self.original_stdout: Optional[TextIO] = None
        self.original_stderr: Optional[TextIO] = None
        self.tee_stdout: Optional["TeeStream"] = None
        self.tee_stderr: Optional["TeeStream"] = None
        self.active = False
        self._encoding = "utf-8"
        self._mode = (
            (mode or os.environ.get("REDAUDIT_SESSION_LOG_MODE") or "lines").strip().lower()
        )

    def start(self) -> bool:
        """
        Start capturing terminal output.

        Returns:
            True if started successfully
        """
        if self.active:
            return True
        if self._mode in {"off", "disabled", "false", "0", "none"}:
            return False

        try:
            # Create session_logs directory
            self.session_dir.mkdir(parents=True, exist_ok=True)

            # Open raw log file
            log_path = self.session_dir / f"session_{self.session_name}.log"
            self.log_file = open(log_path, "w", encoding="utf-8", buffering=1)

            # Write header
            self._write_header()

            # Save original streams
            self.original_stdout = sys.stdout
            self.original_stderr = sys.stderr

            # Create tee streams
            self.tee_stdout = TeeStream(self.original_stdout, self.log_file, mode=self._mode)
            self.tee_stderr = TeeStream(
                self.original_stderr,
                self.log_file,
                prefix="[stderr] ",
                mode=self._mode,
            )

            # Replace sys streams
            sys.stdout = self.tee_stdout  # type: ignore[assignment]
            sys.stderr = self.tee_stderr  # type: ignore[assignment]

            self.active = True
            return True

        except Exception as e:
            # Don't fail the scan if logging fails
            if self.original_stdout:
                print(
                    f"[session_log] Warning: Could not start session logging: {e}",
                    file=self.original_stdout,
                )
            return False

    def stop(self) -> Optional[str]:
        """
        Stop capturing and finalize log files.

        Returns:
            Path to the clean .txt log, or None if not started
        """
        if not self.active:
            return None

        try:
            # Restore original streams
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr

            # Write footer
            self._write_footer()

            # Close log file
            if self.log_file:
                self.log_file.close()

            # Create clean .txt version (strip ANSI codes)
            txt_path = self._create_clean_version()

            self.active = False
            return str(txt_path) if txt_path else None

        except Exception as e:
            print(f"[session_log] Warning: Error stopping session log: {e}")
            self.active = False
            return None

    def _write_header(self) -> None:
        """Write session header to log."""
        if not self.log_file:
            return

        header = f"""
{'=' * 70}
RedAudit Session Log
{'=' * 70}
Started: {datetime.now().isoformat()}
User: {os.environ.get('USER', 'unknown')}
Working Directory: {os.getcwd()}
{'=' * 70}

"""
        self.log_file.write(header)

    def _write_footer(self) -> None:
        """Write session footer to log."""
        if not self.log_file:
            return

        footer = f"""

{'=' * 70}
Session Ended: {datetime.now().isoformat()}
{'=' * 70}
"""
        self.log_file.write(footer)

    def _create_clean_version(self) -> Optional[Path]:
        """
        Create a clean .txt version without ANSI codes.

        Returns:
            Path to the .txt file
        """
        log_path = self.session_dir / f"session_{self.session_name}.log"
        txt_path = self.session_dir / f"session_{self.session_name}.txt"

        try:
            with open(log_path, "r", encoding="utf-8") as f_in:
                content = f_in.read()

            # Strip ANSI escape codes
            clean_content = ANSI_ESCAPE.sub("", content)

            with open(txt_path, "w", encoding="utf-8") as f_out:
                f_out.write(clean_content)

            return txt_path

        except Exception:
            return None


class TeeStream(io.TextIOBase):
    """
    Stream that writes to both terminal and log file.

    v3.9.0: Enhanced filtering to reduce log noise while preserving meaningful output.
    - Deduplicates repeated heartbeat messages
    - Filters spinner-only progress changes
    - Keeps state transitions (percentage jumps, phase changes)
    """

    # Patterns for deduplication
    HEARTBEAT_PATTERN = re.compile(
        r"\[\d{2}:\d{2}:\d{2}\] \[INFO\] .*(en progreso|in progress).*\(\d+:\d+"
    )
    PROGRESS_PATTERN = re.compile(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏].*━+.*\d+%")

    def __init__(
        self, terminal: TextIO, log_file: TextIO, prefix: str = "", *, mode: str = "lines"
    ):
        """
        Initialize tee stream.

        Args:
            terminal: Original terminal stream
            log_file: Log file to write to
            prefix: Optional prefix for log entries
        """
        self.terminal = terminal
        self.log_file = log_file
        self.prefix = prefix
        self.mode = (mode or "lines").strip().lower()
        self._log_buf = ""
        self._max_buf = 4096
        # v3.9.0: Deduplication state
        self._last_heartbeat_key = ""
        self._last_progress_pct = -1
        self._last_progress_phase = ""
        self._heartbeat_count = 0

    def write(self, data: str) -> int:
        """Write to both streams."""
        # Write to terminal (always)
        self.terminal.write(data)
        self.terminal.flush()

        # Write to log file
        try:
            if self.mode == "raw":
                if self.prefix and data.strip():
                    self.log_file.write(self.prefix)
                self.log_file.write(data)
                self.log_file.flush()
            else:
                self._write_lines(data)
        except Exception:
            pass  # Don't fail if log write fails

        return len(data)

    def _write_lines(self, data: str) -> None:
        """
        Log only stable newline-terminated output with smart filtering.

        v3.9.0 enhancements:
        - Deduplicates heartbeat messages (shows first + summary count)
        - Filters spinner-only progress changes (only logs 10% jumps or phase changes)
        - Keeps all non-progress output intact
        """
        if not data:
            return

        self._log_buf += data

        # Drop overwritten frames (common in progress redraws)
        if "\n" not in self._log_buf and "\r" in self._log_buf:
            self._log_buf = self._log_buf.split("\r")[-1]

        # Keep memory bounded if a tool writes without newlines
        if len(self._log_buf) > self._max_buf and "\n" not in self._log_buf:
            self._log_buf = self._log_buf[-self._max_buf :]

        if "\n" not in self._log_buf:
            return

        lines = self._log_buf.splitlines(keepends=True)
        if not lines:
            return

        # Preserve trailing partial line (no newline yet)
        if not lines[-1].endswith("\n"):
            self._log_buf = lines.pop()
        else:
            self._log_buf = ""

        for line in lines:
            # v3.9.0: Smart filtering
            if self._should_skip_line(line):
                continue

            if self.prefix and line.strip():
                self.log_file.write(self.prefix)
            self.log_file.write(line)
        self.log_file.flush()

    def _should_skip_line(self, line: str) -> bool:
        """
        Determine if a line should be skipped (noise reduction).

        v3.9.0: CONSERVATIVE filtering - only skip pure noise, never meaningful info.
        Returns True ONLY for:
        - Repeated heartbeats (first one kept, count shown at end)
        - Pure spinner redraws with <5% change in same phase
        """
        stripped = line.strip()
        if not stripped:
            return False  # Keep blank lines

        # ALWAYS keep: status messages with [OK], [WARN], [FAIL], [INFO] that have results
        if any(tag in stripped for tag in ["[OK]", "[WARN]", "[FAIL]", "✓", "✅", "⚠️", "❌"]):
            return False  # Never skip status messages

        # ALWAYS keep: lines with actual scan results (hosts, ports, vulns, durations)
        if any(
            kw in stripped.lower()
            for kw in [
                "hosts",
                "puertos",
                "ports",
                "vulns",
                "duración",
                "duration",
                "finalizado",
                "completed",
                "detected",
                "detectado",
            ]
        ):
            return False

        # 1. Deduplicate heartbeat messages like "[22:30:37] [INFO] Net Discovery en progreso... (8:26 transcurrido)"
        heartbeat_match = self.HEARTBEAT_PATTERN.search(stripped)
        if heartbeat_match:
            # Extract key (everything except the timestamp and duration)
            key = re.sub(r"\[\d{2}:\d{2}:\d{2}\]", "", stripped)
            key = re.sub(r"\(\d+:\d+ (transcurrido|elapsed)\)", "", key).strip()

            if key == self._last_heartbeat_key:
                self._heartbeat_count += 1
                return True  # Skip duplicate (count will be shown)
            else:
                # New heartbeat type - flush previous count if any
                if self._heartbeat_count > 1:
                    self.log_file.write(f"  ... ({self._heartbeat_count} updates)\n")
                self._last_heartbeat_key = key
                self._heartbeat_count = 1
                return False  # Keep first occurrence

        # 2. Filter ONLY pure spinner progress lines (⠋⠙⠹... with no new info)
        progress_match = self.PROGRESS_PATTERN.search(stripped)
        if progress_match:
            # Extract percentage and phase
            pct_match = re.search(r"(\d+)%", stripped)
            phase_match = re.search(
                r"(discovery|scan|probe|enum|verify|Nuclei|testssl|nmap|banner|deep|ARP|UDP|TCP|SMB|RPC|LDAP)\b",
                stripped,
                re.I,
            )

            current_pct = int(pct_match.group(1)) if pct_match else -1
            current_phase = phase_match.group(1).lower() if phase_match else ""

            # Only skip if SAME phase AND percentage change < 5%
            if current_phase == self._last_progress_phase:
                if abs(current_pct - self._last_progress_pct) < 5:
                    return True  # Skip minor spinner update

            # Keep - significant change
            self._last_progress_pct = current_pct
            self._last_progress_phase = current_phase
            return False

        # 3. Keep ALL other lines
        return False

    def flush(self) -> None:
        """Flush both streams."""
        self.terminal.flush()
        try:
            # Flush pending heartbeat count if any
            if self._heartbeat_count > 1:
                self.log_file.write(f"  ... (repeated {self._heartbeat_count}x)\n")
                self._heartbeat_count = 0
            self.log_file.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        """Return terminal's isatty status."""
        return self.terminal.isatty()

    @property
    def encoding(self) -> str:  # type: ignore[override]
        """Return terminal's encoding."""
        enc = getattr(self.terminal, "encoding", None)
        return enc if isinstance(enc, str) else "utf-8"


# Singleton instance for easy access
_session_logger: Optional[SessionLogger] = None


def start_session_log(
    output_dir: str, session_name: Optional[str] = None, *, mode: Optional[str] = None
) -> bool:
    """
    Start session logging (convenience function).

    Args:
        output_dir: Directory for session logs
        session_name: Optional session name

    Returns:
        True if started successfully
    """
    global _session_logger
    _session_logger = SessionLogger(output_dir, session_name, mode=mode)
    return _session_logger.start()


def stop_session_log() -> Optional[str]:
    """
    Stop session logging (convenience function).

    Returns:
        Path to clean .txt log, or None
    """
    global _session_logger
    if _session_logger:
        result = _session_logger.stop()
        _session_logger = None
        return result
    return None
