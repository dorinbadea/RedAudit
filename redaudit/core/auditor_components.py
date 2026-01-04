"""
RedAudit - Auditor components and utilities.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional

from redaudit.core.crypto import (
    ask_password_twice,
    derive_key_from_password,
    generate_random_password,
)
from redaudit.utils.constants import (
    HEARTBEAT_FAIL_THRESHOLD,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_WARN_THRESHOLD,
)
from redaudit.utils.i18n import get_text


class _ActivityIndicator:
    def __init__(
        self,
        *,
        label: str,
        initial: str = "running...",
        refresh_s: float = 0.25,
        stream=None,
        touch_activity: Optional[Callable[[], None]] = None,
    ):
        self._label = str(label)[:50]
        self._message = str(initial)[:200]
        self._refresh_s = float(refresh_s) if refresh_s and refresh_s > 0 else 0.25
        self._stream = stream if stream is not None else getattr(sys, "__stdout__", sys.stdout)
        self._touch_activity = touch_activity
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _terminal_width(self) -> int:
        try:
            width = shutil.get_terminal_size((80, 24)).columns
        except Exception:
            width = 80
        return max(40, int(width))

    def update(self, message: str) -> None:
        with self._lock:
            self._message = str(message)[:200]

    def __enter__(self) -> "_ActivityIndicator":
        if self._thread:
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        if self._thread:
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass
        self._thread = None
        self._clear_line()

    def _clear_line(self) -> None:
        try:
            if getattr(self._stream, "isatty", lambda: False)():
                width = max(10, self._terminal_width() - 1)
                self._stream.write("\r" + (" " * width) + "\r")
                self._stream.flush()
        except Exception:
            pass

    def _run(self) -> None:
        start = time.monotonic()
        tick = 0
        last_line = ""
        while not self._stop.is_set():
            tick += 1
            try:
                if self._touch_activity:
                    self._touch_activity()
            except Exception:
                pass

            elapsed = time.monotonic() - start
            with self._lock:
                msg = self._message

            if getattr(self._stream, "isatty", lambda: False)():
                frame = self._frames[tick % len(self._frames)]
                width = max(10, self._terminal_width() - 1)
                if width >= 70:
                    line = f"{frame} {self._label}: {msg}  (elapsed {elapsed:0.0f}s)"
                else:
                    line = f"{frame} {self._label}: {msg}"
                # Avoid excessive writes if the line didn't change.
                if line != last_line:
                    try:
                        self._stream.write("\r" + line[:width].ljust(width))
                        self._stream.flush()
                    except Exception:
                        pass
                last_line = line
            else:
                # Non-TTY: emit a bounded heartbeat every ~10 seconds.
                if int(elapsed) % 10 == 0 and int(elapsed) != int(elapsed - self._refresh_s):
                    try:
                        self._stream.write(
                            f"[INFO] {self._label}: {msg} (elapsed {int(elapsed)}s)\n"
                        )
                        self._stream.flush()
                    except Exception:
                        pass

            time.sleep(self._refresh_s)


class AuditorUI:
    """
    UI component for auditor class.

    v4.0: Gradually migrating to UIManager via adapter pattern.
    The `ui` property provides access to standalone UIManager.
    """

    activity_lock: threading.Lock
    COLORS: dict
    logger: Optional[logging.Logger]
    _print_lock: threading.Lock
    _ui_detail_lock: threading.Lock
    _ui_detail: str
    _ui_progress_active: bool
    current_phase: str
    last_activity: datetime
    lang: str

    # v4.0: Adapter property for gradual migration to UIManager
    @property
    def ui(self):
        """
        Get UIManager instance (adapter pattern).

        This allows gradual migration from component helpers to composed UIManager.
        Eventually, all UI calls will go through self.ui instead of self.method.
        """
        if not hasattr(self, "_ui_manager"):
            from redaudit.core.ui_manager import UIManager

            self._ui_manager = UIManager(
                lang=getattr(self, "lang", "en"),
                colors=getattr(self, "COLORS", None),
                logger=getattr(self, "logger", None),
            )
        return self._ui_manager

    def t(self, key, *args):
        """Get translated text."""
        return get_text(key, self.lang, *args)

    def print_status(self, message, status="INFO", update_activity=True, *, force: bool = False):
        """Print status message with timestamp and color."""
        if update_activity:
            with self.activity_lock:
                self.last_activity = datetime.now()

        ts = datetime.now().strftime("%H:%M:%S")

        # v3.2.2+: Map internal status tokens to professional display labels
        # Applied for ALL modes (TTY and non-TTY) to avoid leaking internal names
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
        color = self.COLORS.get(color_key, self.COLORS["OKBLUE"]) if is_tty else ""
        endc = self.COLORS["ENDC"] if is_tty else ""

        # Wrap long messages on word boundaries to avoid splitting words mid-line.
        msg = "" if message is None else str(message)
        if self._ui_progress_active and not force:
            if not self._should_emit_during_progress(msg, status_display):
                # Store last suppressed line so progress UIs can surface "what's happening"
                # without flooding the terminal with logs.
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
        # NOTE: These print statements output status messages (e.g., "Scanning host X"),
        # NOT passwords or sensitive data. CodeQL incorrectly flags these.
        # v3.8.4: Use Rich console.print when progress is active to handle colors correctly
        with self._print_lock:
            if self._ui_progress_active:
                # Rich Progress is active - use Rich markup instead of ANSI codes
                # This ensures colors display correctly even when Progress bar is updating
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
                    console.print(
                        f"[{rich_style}][{ts}] [{status_display}][/{rich_style}] {lines[0]}"
                    )
                    for line in lines[1:]:
                        console.print(f"  {line}")
                except ImportError:
                    # Fallback to ANSI if Rich not available
                    print(
                        f"{color}[{ts}] [{status_display}]{endc} {lines[0]}"
                    )  # lgtm[py/clear-text-logging-sensitive-data]
                    for line in lines[1:]:
                        print(f"  {line}")  # lgtm[py/clear-text-logging-sensitive-data]
            else:
                # No progress active - use standard ANSI codes
                print(
                    f"{color}[{ts}] [{status_display}]{endc} {lines[0]}"
                )  # lgtm[py/clear-text-logging-sensitive-data]
                for line in lines[1:]:
                    print(f"  {line}")  # lgtm[py/clear-text-logging-sensitive-data]
            sys.stdout.flush()

    def _condense_for_ui(self, text: str) -> str:
        """
        Condense a log message for progress bar display.

        Extracts only essential info (IP + scan type) from verbose nmap commands
        to prevent terminal overflow when window is narrow.

        v3.6.1: Addresses noisy progress bar issue during host scanning.
        """
        text = (text or "").replace("\r", " ").replace("\t", " ").strip()
        if not text:
            return ""
        text = " ".join(text.split())

        # Pattern: [type] TARGET → command ...
        # TARGET may be IP, host, or IP:port.
        m = re.match(r"^\[([^\]]+)\]\s+([^\s]+)\s*→\s*(.*)$", text)
        if m:
            scan_type, ip, command = m.groups()
            scan_type_norm = scan_type.lower()

            if scan_type_norm in ("testssl", "nikto", "whatweb", "nuclei"):
                return f"{scan_type_norm} {ip}"
            if scan_type_norm in ("agentless", "verify"):
                return f"agentless {ip}"

            # Determine mode from command for user-friendly hint
            mode_hint = ""
            if "async udp probe" in command.lower():
                mode_hint = "UDP probe"
            elif "-sU" in command:
                mode_hint = "UDP scan"
            elif "-p-" in command and ("-A" in command or "-sV" in command):
                mode_hint = "full scan"
            elif "--top-ports" in command:
                mode_hint = "top ports"
            elif "banner" in text.lower():
                mode_hint = "banner grab"

            if mode_hint:
                return f"{scan_type} {ip} ({mode_hint})"
            return f"{scan_type} {ip}"

        # For other messages, just take first 60 chars
        return text[:60] + ("…" if len(text) > 60 else "")

    def _set_ui_detail(self, text: str, status_display: Optional[str] = None) -> None:
        condensed = self._condense_for_ui(text)
        if not condensed:
            return
        if status_display:
            condensed = self._format_ui_detail(condensed, status_display)
        with self._ui_detail_lock:
            self._ui_detail = condensed

    def _format_ui_detail(self, text: str, status_display: str) -> str:
        color_map = {
            "INFO": "bright_blue",
            "OK": "green",
            "WARN": "yellow",
            "WARNING": "yellow",
            "FAIL": "red",
            "ERROR": "red",
        }
        color = color_map.get(status_display)
        if not color:
            return text
        return f"[{color}]{text}[/{color}]"

    @staticmethod
    def _coerce_text(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            return value
        return str(value)

    def _phase_detail(self) -> str:
        phase = (self.current_phase or "").strip()
        if not phase:
            return ""
        if phase.startswith("vulns:testssl:"):
            target = ":".join(phase.split(":")[2:])
            return f"testssl {target}"
        if phase.startswith("vulns:nikto:"):
            target = ":".join(phase.split(":")[2:])
            return f"nikto {target}"
        if phase.startswith("vulns:whatweb:"):
            target = ":".join(phase.split(":")[2:])
            return f"whatweb {target}"
        if phase.startswith("ports:"):
            target = phase.split(":", 1)[1]
            return f"nmap {target}"
        if phase.startswith("deep:"):
            target = phase.split(":", 1)[1]
            return f"deep scan {target}"
        if phase.startswith("discovery:"):
            target = phase.split(":", 1)[1]
            return f"discovery {target}"
        if phase == "vulns":
            return "web vuln scan"
        if phase == "net_discovery":
            return "net discovery"
        if phase == "topology":
            return "topology"
        return phase[:60]

    def _get_ui_detail(self) -> str:
        with self._ui_detail_lock:
            detail = self._ui_detail
        return detail or self._phase_detail()

    def _touch_activity(self) -> None:
        with self.activity_lock:
            self.last_activity = datetime.now()

    def _should_emit_during_progress(self, msg: str, status_display: str) -> bool:
        """
        Reduce terminal noise while progress UIs are active.

        Keep FAIL always; keep WARN only for "signal" messages; suppress routine INFO/OK.
        """
        if status_display in ("FAIL",):
            return True
        if status_display in ("INFO",):
            return False
        if status_display in ("OK",):
            text = (msg or "").lower()
            ok_terms = (
                "identidad profundo finalizado",
                "deep identity scan finished",
            )
            return any(term in text for term in ok_terms)
        text = (msg or "").lower()
        if "⚠" in msg:
            return True
        signal_terms = (
            "vulnerab",
            "exploit",
            "cve",
            "backdoor",
            "error",
            "failed",
            "timeout",
        )
        return any(term in text for term in signal_terms)

    @staticmethod
    def _format_eta(seconds: float) -> str:
        try:
            sec = int(max(0, round(float(seconds))))
        except Exception:
            return "--:--"
        h = sec // 3600
        m = (sec % 3600) // 60
        s = sec % 60
        return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"

    def _terminal_width(self, fallback: int = 100) -> int:
        try:
            width = shutil.get_terminal_size((fallback, 24)).columns
        except Exception:
            width = fallback
        return max(60, int(width))

    def _progress_console(self):
        try:
            from rich.console import Console
        except ImportError:
            return None
        return Console(
            file=getattr(sys, "__stdout__", sys.stdout),
            width=self._terminal_width(),
        )

    def _safe_text_column(self, *args, **kwargs):
        try:
            from rich.progress import TextColumn
        except ImportError:
            return None
        try:
            return TextColumn(*args, **kwargs)
        except TypeError:
            kwargs.pop("overflow", None)
            kwargs.pop("no_wrap", None)
            kwargs.pop("markup", None)
            return TextColumn(*args, **kwargs)

    def _progress_columns(self, *, show_detail: bool, show_eta: bool, show_elapsed: bool):
        """v3.8.2: Simplified progress columns - removed spinner (caused display issues)."""
        try:
            from rich.progress import BarColumn, TimeElapsedColumn
        except ImportError:
            return []
        width = self._terminal_width()
        bar_width = max(8, min(28, width // 4))
        columns = [
            self._safe_text_column(
                "[progress.description]{task.description}",
                overflow="ellipsis",
                no_wrap=True,
            ),
        ]
        if width >= 70:
            columns.append(BarColumn(bar_width=bar_width))
            columns.append(self._safe_text_column("[progress.percentage]{task.percentage:>3.0f}%"))
        if width >= 90:
            columns.append(self._safe_text_column("({task.completed}/{task.total})"))
        # v3.8.1: Always show elapsed time for visibility
        columns.append(TimeElapsedColumn())
        if show_detail and width >= 70:
            columns.append(
                self._safe_text_column(
                    "{task.fields[detail]}",
                    overflow="ellipsis",
                    markup=True,
                )
            )
        # v3.8.2: Removed SpinnerColumn - caused display issues during long phases
        return [c for c in columns if c is not None]

    @contextmanager
    def _progress_ui(self):
        prev = self._ui_progress_active
        self._ui_progress_active = True
        try:
            yield
        finally:
            self._ui_progress_active = prev


class AuditorLogging:
    def _setup_logging(self):
        """Configure logging with rotation."""
        log_dir = os.path.expanduser("~/.redaudit/logs")
        logger = logging.getLogger("RedAudit")
        logger.setLevel(logging.DEBUG)

        class _NoTracebackFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                exc_info = record.exc_info
                stack_info = record.stack_info
                record.exc_info = None
                record.stack_info = None
                try:
                    return super().format(record)
                finally:
                    record.exc_info = exc_info
                    record.stack_info = stack_info

        class _UIAwareStreamHandler(logging.StreamHandler):
            def __init__(self, *, ui_active, stream=None):
                super().__init__(stream=stream)
                self._ui_active = ui_active

            def emit(self, record: logging.LogRecord) -> None:
                try:
                    if callable(self._ui_active) and self._ui_active():
                        return
                except Exception:
                    pass
                return super().emit(record)

        file_handler = None
        try:
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f"redaudit_{datetime.now().strftime('%Y%m%d')}.log")
            fmt = logging.Formatter(
                "%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s"
            )
            file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
            file_handler.setFormatter(fmt)
            file_handler.setLevel(logging.DEBUG)
        except Exception:
            file_handler = None

        ch = _UIAwareStreamHandler(
            ui_active=lambda: bool(getattr(self, "_ui_progress_active", False)),
            stream=getattr(sys, "__stdout__", sys.stdout),
        )
        ch.setLevel(logging.ERROR)
        ch.setFormatter(_NoTracebackFormatter("%(levelname)s: %(message)s"))

        if not logger.handlers:
            if file_handler:
                logger.addHandler(file_handler)
            logger.addHandler(ch)
        else:
            has_file = any(isinstance(h, RotatingFileHandler) for h in logger.handlers)
            if file_handler and not has_file:
                logger.addHandler(file_handler)

        self.logger = logger
        if file_handler is None:
            logger.warning("File logging disabled (permission or path issue)")
        logger.info("=" * 60)
        logger.info("RedAudit session start")
        logger.info("User: %s", os.getenv("SUDO_USER", os.getenv("USER", "unknown")))
        logger.info("PID: %s", os.getpid())

    def start_heartbeat(self):
        """Start the heartbeat monitoring thread."""
        if self.heartbeat_thread:
            return
        self.heartbeat_stop = False
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop_heartbeat(self):
        """Stop the heartbeat monitoring thread."""
        self.heartbeat_stop = True
        if self.heartbeat_thread:
            try:
                self.heartbeat_thread.join(timeout=1.0)
            except RuntimeError:
                if self.logger:
                    self.logger.debug("Heartbeat thread join failed", exc_info=True)
                pass
            self.heartbeat_thread = None

    def _heartbeat_loop(self):
        """Background heartbeat monitoring loop."""
        while not self.heartbeat_stop:
            with self.activity_lock:
                delta = (datetime.now() - self.last_activity).total_seconds()

            phase = self.current_phase
            if phase not in ("init", "saving", "interrupted"):
                if HEARTBEAT_WARN_THRESHOLD <= delta < HEARTBEAT_FAIL_THRESHOLD:
                    # Keep the terminal UI quiet: prefer progress bars (when available) over periodic
                    # "clocking" warnings. Still record a debug trace in logs for troubleshooting.
                    if self.logger:
                        self.logger.debug("Heartbeat silence %ss in %s", int(delta), phase)
                elif delta >= HEARTBEAT_FAIL_THRESHOLD:
                    if self.logger:
                        self.logger.warning("Heartbeat silence > %ss in %s", delta, phase)
            time.sleep(HEARTBEAT_INTERVAL)


class AuditorCrypto:
    def setup_encryption(self, non_interactive=False, password=None):
        """
        Setup encryption if requested and available.

        Args:
            non_interactive: If True, skip interactive prompts
            password: Password to use (required if non_interactive=True and --encrypt is used)
        """
        # Expose a non-secret flag for downstream modules (e.g., evidence/jsonl export behavior).
        self.config["encryption_enabled"] = False

        if not self.cryptography_available:
            self.ui.print_status(self.ui.t("crypto_missing"), "WARNING")
            if non_interactive:
                self.ui.print_status(self.ui.t("cryptography_required"), "FAIL")
            return

        if not non_interactive:
            if self.ask_yes_no(self.ui.t("encrypt_reports"), default="no"):
                try:
                    pwd = ask_password_twice(self.ui.t("encryption_password"), self.lang)
                    key, salt = derive_key_from_password(pwd)
                    self.encryption_key = key
                    self.config["encryption_salt"] = base64.b64encode(salt).decode()
                    self.encryption_enabled = True
                    self.config["encryption_enabled"] = True
                    self.ui.print_status(self.ui.t("encryption_enabled"), "OKGREEN")
                except RuntimeError as exc:
                    if "cryptography not available" in str(exc):
                        self.ui.print_status(self.ui.t("cryptography_required"), "FAIL")
                    else:
                        raise
        else:
            if not self.cryptography_available:
                self.ui.print_status(self.ui.t("cryptography_required"), "FAIL")
                return

            if password is None:
                password = generate_random_password()
                self.ui.print_status(
                    f"⚠️  Generated random encryption password (save this!): {password}", "WARNING"
                )

            try:
                key, salt = derive_key_from_password(password)
                self.encryption_key = key
                self.config["encryption_salt"] = base64.b64encode(salt).decode()
                self.encryption_enabled = True
                self.config["encryption_enabled"] = True
                self.ui.print_status(self.ui.t("encryption_enabled"), "OKGREEN")
            except RuntimeError as exc:
                if "cryptography not available" in str(exc):
                    self.ui.print_status(self.ui.t("cryptography_required"), "FAIL")
                else:
                    raise


class AuditorNVD:
    def setup_nvd_api_key(self, non_interactive=False, api_key=None):
        """
        Setup NVD API key for CVE correlation.

        v3.0.1: Interactive prompt for API key storage preference.

        Args:
            non_interactive: If True, skip interactive prompts
            api_key: API key to use (from CLI --nvd-key)
        """
        # Import config functions
        try:
            from redaudit.utils.config import (
                get_nvd_api_key,
                set_nvd_api_key,
                validate_nvd_api_key,
            )
        except ImportError:
            self.ui.print_status(self.ui.t("config_module_missing"), "WARNING")
            return

        # If key provided via CLI, just use it
        if api_key:
            if validate_nvd_api_key(api_key):
                self.config["nvd_api_key"] = api_key
                self.ui.print_status(self.ui.t("nvd_key_set_cli"), "OKGREEN")
            else:
                self.ui.print_status(self.ui.t("nvd_key_invalid"), "WARNING")
            return

        # If already configured, use existing
        existing_key = get_nvd_api_key()
        if existing_key:
            self.config["nvd_api_key"] = existing_key
            return

        # Non-interactive mode without key - warn but continue
        if non_interactive:
            self.ui.print_status(self.ui.t("nvd_key_not_configured"), "WARNING")
            return

        # Interactive: ask user
        if not self.config.get("cve_lookup_enabled"):
            return  # Only prompt if CVE lookup is enabled

        print(f"\n{self.ui.colors['WARNING']}")
        print("=" * 60)
        print(self.ui.t("nvd_setup_header"))
        print("=" * 60)
        print(f"{self.ui.colors['ENDC']}")
        print(self.ui.t("nvd_setup_info"))
        print(
            f"\n{self.ui.colors['CYAN']}https://nvd.nist.gov/developers/request-an-api-key{self.ui.colors['ENDC']}\n"
        )

        options = [
            self.ui.t("nvd_option_config"),  # Save in config file
            self.ui.t("nvd_option_env"),  # Use environment variable
            self.ui.t("nvd_option_skip"),  # Continue without
        ]

        choice = self.ask_choice(self.ui.t("nvd_ask_storage"), options, default=2)

        if choice == 0:  # Save in config file
            while True:
                try:
                    key = input(
                        f"\n{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} API Key: "
                    ).strip()
                    if not key:
                        self.ui.print_status(self.ui.t("nvd_key_skipped"), "INFO")
                        break

                    if validate_nvd_api_key(key):
                        if set_nvd_api_key(key, "config"):
                            self.config["nvd_api_key"] = key
                            self.ui.print_status(self.ui.t("nvd_key_saved"), "OKGREEN")
                        else:
                            self.ui.print_status(self.ui.t("nvd_key_save_error"), "WARNING")
                        break
                    else:
                        self.ui.print_status(self.ui.t("nvd_key_invalid_format"), "WARNING")
                except KeyboardInterrupt:
                    print("")
                    break

        elif choice == 1:  # Environment variable
            print(f"\n{self.ui.t('nvd_env_instructions')}")
            print(
                f"  {self.ui.colors['CYAN']}export NVD_API_KEY='your-api-key-here'{self.ui.colors['ENDC']}"
            )
            self.ui.print_status(self.ui.t("nvd_env_set_later"), "INFO")

        else:  # Skip
            self.ui.print_status(self.ui.t("nvd_slow_mode"), "WARNING")
