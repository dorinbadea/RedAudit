#!/usr/bin/env python3
"""
RedAudit - Main Auditor Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Main orchestrator class for network auditing operations.
"""

import os
import sys
import signal
import shutil
import subprocess
import shlex
import threading
import time
import random
import math
import importlib
import ipaddress
import logging
import base64
import textwrap
import re
from contextlib import contextmanager
from datetime import datetime
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, List, Optional, Tuple

from redaudit.utils.constants import (
    VERSION,
    DEFAULT_LANG,
    COLORS,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_WARN_THRESHOLD,
    HEARTBEAT_FAIL_THRESHOLD,
    MAX_PORTS_DISPLAY,
    DEEP_SCAN_TIMEOUT,
    UDP_PRIORITY_PORTS,
    UDP_SCAN_MODE_QUICK,
    UDP_SCAN_MODE_FULL,
    DEFAULT_UDP_MODE,
    UDP_TOP_PORTS,
    UDP_HOST_TIMEOUT_STRICT,
    UDP_MAX_RETRIES_LAN,
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
)
from redaudit.utils.paths import (
    expand_user_path,
    get_default_reports_base_dir,
    maybe_chown_to_invoking_user,
)
from redaudit.utils.i18n import TRANSLATIONS, get_text
from redaudit.utils.dry_run import is_dry_run
from redaudit.core.command_runner import CommandRunner
from redaudit.core.wizard import WizardMixin
from redaudit.core.nuclei import (
    is_nuclei_available,
    run_nuclei_scan,
    get_http_targets_from_hosts,
)
from redaudit.core.agentless_verify import (
    select_agentless_probe_targets,
    probe_agentless_services,
    summarize_agentless_fingerprint,
)
from redaudit.core.crypto import (
    is_crypto_available,
    derive_key_from_password,
    ask_password_twice,
    generate_random_password,
)
from redaudit.core.network import detect_all_networks, get_neighbor_mac
from redaudit.core.udp_probe import run_udp_probe
from redaudit.core.scanner import (
    sanitize_ip,
    sanitize_hostname,
    is_web_service,
    is_suspicious_service,
    get_nmap_arguments,
    extract_vendor_mac,
    extract_os_detection,
    output_has_identity,
    run_nmap_command,
    enrich_host_with_dns,
    enrich_host_with_whois,
    http_enrichment,
    tls_enrichment,
    exploit_lookup,
    ssl_deep_analysis,
    start_background_capture,
    stop_background_capture,
    banner_grab_fallback,
    finalize_host_status,
)
from redaudit.core.reporter import (
    generate_summary,
    save_results,
    show_config_summary,
    show_results_summary,
)

# Try to import nmap
nmap = None


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


class InteractiveNetworkAuditor(WizardMixin):
    """Main orchestrator for RedAudit scans."""

    def __init__(self):
        self.lang = DEFAULT_LANG if DEFAULT_LANG in TRANSLATIONS else "en"
        # How to apply persisted defaults: ask/use/ignore (CLI may override).
        self.defaults_mode = "ask"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "network_info": [],
            "hosts": [],
            "vulnerabilities": [],
            "summary": {},
        }
        self.config = {
            "target_networks": [],
            "max_hosts": "all",
            "max_hosts_value": "all",
            "scan_mode": "normal",
            "threads": DEFAULT_THREADS,
            "output_dir": get_default_reports_base_dir(),
            # v3.5: Dry-run (print commands without executing)
            "dry_run": False,
            # v3.5: Best-effort prevent system/display sleep during scan
            "prevent_sleep": True,
            "scan_vulnerabilities": True,
            "save_txt_report": True,
            "encryption_salt": None,
            # Pre-scan config (v2.7)
            "prescan_enabled": False,
            "prescan_ports": "1-1024",
            "prescan_timeout": 0.5,
            # UDP scan config (v2.8)
            "udp_mode": DEFAULT_UDP_MODE,
            "udp_top_ports": UDP_TOP_PORTS,
            # v3.0 configuration
            "ipv6_only": False,
            "cve_lookup_enabled": False,
            "nvd_api_key": None,
            # v2.8: Adaptive deep identity scan
            "deep_id_scan": True,
            # v3.1+: Optional topology discovery
            "topology_enabled": False,
            "topology_only": False,
            # v3.2+: Enhanced network discovery
            # None = auto (enabled in full/topology), True/False = explicit override
            "net_discovery_enabled": None,
            "net_discovery_protocols": None,  # None = all, or list like ["dhcp", "netbios"]
            "net_discovery_redteam": False,
            "net_discovery_interface": None,
            "net_discovery_max_targets": 50,
            "net_discovery_snmp_community": "public",
            "net_discovery_dns_zone": None,
            "net_discovery_kerberos_realm": None,
            "net_discovery_kerberos_userlist": None,
            "net_discovery_active_l2": False,
            # v3.8: Agentless Windows verification (SMB/RDP/LDAP)
            "windows_verify_enabled": False,
            "windows_verify_max_targets": 20,
        }

        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = is_crypto_available()
        self.rate_limit_delay = 0.0
        self.extra_tools = {}

        # v3.0: Proxy manager (set by CLI if --proxy used)
        self.proxy_manager = None

        self.last_activity = datetime.now()
        self.activity_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._ui_progress_active = False
        self._ui_detail_lock = threading.Lock()
        self._ui_detail = ""
        self.heartbeat_stop = False
        self.heartbeat_thread = None
        self.current_phase = "init"
        self.interrupted = False
        self.scan_start_time = None

        # Subprocess tracking for cleanup on interruption (C1 fix)
        self._active_subprocesses = []
        self._subprocess_lock = threading.Lock()

        self.COLORS = COLORS

        self.logger = None
        self._setup_logging()
        signal.signal(signal.SIGINT, self.signal_handler)

    # ---------- Helpers & i18n ----------

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
            if "async UDP probe" in command.lower():
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

    @staticmethod
    def _parse_url_target(value: object) -> Tuple[str, int, str]:
        if not isinstance(value, str):
            return "", 0, ""
        raw = value.strip()
        if not raw:
            return "", 0, ""
        if "://" not in raw:
            host = raw
            port = 0
            scheme = ""
            if raw.count(":") == 1:
                host_part, port_part = raw.split(":", 1)
                host = host_part.strip()
                try:
                    port = int(port_part)
                except Exception:
                    port = 0
            return host, port, scheme
        try:
            from urllib.parse import urlparse

            parsed = urlparse(raw)
            host = parsed.hostname or ""
            port = parsed.port or 0
            scheme = parsed.scheme or ""
            if not port:
                if scheme == "https":
                    port = 443
                elif scheme == "http":
                    port = 80
            return host, port, scheme
        except Exception:
            return "", 0, ""

    def _merge_nuclei_findings(self, findings: List[Dict[str, Any]]) -> int:
        if not findings:
            return 0
        host_map: Dict[str, Dict[str, Any]] = {}
        for entry in self.results.get("vulnerabilities", []):
            if not isinstance(entry, dict):
                continue
            host = entry.get("host")
            if host and isinstance(entry.get("vulnerabilities"), list):
                host_map[str(host)] = entry

        merged = 0
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            matched_at = finding.get("matched_at") or finding.get("host") or ""
            host, port, scheme = self._parse_url_target(str(matched_at))
            if not host:
                host, port, scheme = self._parse_url_target(str(finding.get("host") or ""))
            if not host:
                continue

            name = finding.get("name") or finding.get("template_id") or "nuclei"
            vuln = {
                "url": matched_at or "",
                "port": port or 0,
                "severity": finding.get("severity", "info"),
                "category": "vuln",
                "source": "nuclei",
                "template_id": finding.get("template_id"),
                "name": name,
                "description": finding.get("description", ""),
                "matched_at": matched_at or "",
                "matcher_name": finding.get("matcher_name", ""),
                "reference": finding.get("reference", []),
                "tags": finding.get("tags", []),
                "cve_ids": finding.get("cve_ids", []),
                "descriptive_title": f"Nuclei: {name}",
            }
            if scheme:
                vuln["scheme"] = scheme

            entry = host_map.get(host)
            if not entry:
                entry = {"host": host, "vulnerabilities": []}
                self.results.setdefault("vulnerabilities", []).append(entry)
                host_map[host] = entry
            entry["vulnerabilities"].append(vuln)
            merged += 1
        return merged

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

    def _scan_mode_host_timeout_s(self) -> float:
        mode = str(self.config.get("scan_mode") or "").strip().lower()
        if mode in ("fast", "rapido"):
            return 10.0
        if mode in ("full", "completo"):
            return 300.0
        return 60.0

    @staticmethod
    def _extract_nmap_xml(raw: str) -> str:
        if not raw:
            return ""
        start = raw.find("<nmaprun")
        if start < 0:
            start = raw.find("<?xml")
        if start > 0:
            raw = raw[start:]
        end = raw.rfind("</nmaprun>")
        if end >= 0:
            raw = raw[: end + len("</nmaprun>")]
        return raw.strip()

    def _lookup_topology_identity(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        topo = self.results.get("topology") if isinstance(self.results, dict) else None
        if not isinstance(topo, dict):
            return None, None
        for iface in topo.get("interfaces", []) or []:
            arp = (iface or {}).get("arp") or {}
            for host in arp.get("hosts", []) or []:
                if host.get("ip") == ip:
                    mac = host.get("mac")
                    vendor = host.get("vendor")
                    if isinstance(vendor, str) and "unknown" in vendor.lower():
                        vendor = None
                    return mac, vendor
        return None, None

    def _run_nmap_xml_scan(self, target: str, args: str) -> Tuple[Optional[Any], str]:
        """
        Run an nmap scan with XML output and enforce a hard timeout.

        Returns:
            (PortScanner or None, error message string if any)
        """
        if is_dry_run(self.config.get("dry_run")):
            return None, "dry_run"
        if shutil.which("nmap") is None:
            return None, "nmap_not_available"
        if nmap is None:
            return None, "python_nmap_missing"

        host_timeout_s = self._parse_host_timeout_s(args)
        if host_timeout_s is None:
            host_timeout_s = self._scan_mode_host_timeout_s()
        timeout_s = max(30.0, host_timeout_s + 30.0)
        cmd = ["nmap"] + shlex.split(args) + ["-oX", "-", target]

        record_sink: Dict[str, Any] = {"commands": []}
        rec = run_nmap_command(
            cmd,
            int(timeout_s),
            target,
            record_sink,
            logger=self.logger,
            dry_run=False,
            max_stdout=0,
            max_stderr=2000,
            include_full_output=True,
        )

        if rec.get("error"):
            return None, str(rec["error"])

        raw_stdout = self._coerce_text(rec.get("stdout_full") or rec.get("stdout") or "")
        xml_output = self._extract_nmap_xml(raw_stdout)
        if not xml_output:
            raw_stderr = self._coerce_text(rec.get("stderr_full") or rec.get("stderr") or "")
            xml_output = self._extract_nmap_xml(raw_stderr)
        if not xml_output:
            stderr = self._coerce_text(rec.get("stderr", "")).strip()
            if len(stderr) > 200:
                stderr = f"{stderr[:200].rstrip()}..."
            return None, stderr or "empty_nmap_output"

        nm = nmap.PortScanner()
        analyser = getattr(nm, "analyse_nmap_xml_scan", None) or getattr(
            nm, "analyze_nmap_xml_scan", None
        )
        if analyser:
            try:
                analyser(
                    xml_output,
                    nmap_err=self._coerce_text(rec.get("stderr", "")),
                    nmap_err_keep_trace=self._coerce_text(rec.get("stderr", "")),
                    nmap_warn_keep_trace="",
                )
            except Exception as exc:
                msg = str(exc).strip().replace("\n", " ")
                if len(msg) > 200:
                    msg = f"{msg[:200].rstrip()}..."
                return None, f"nmap_xml_parse_error: {msg or 'invalid_xml'}"
        else:
            # Fallback for stubs or older python-nmap builds without XML parser.
            try:
                nm.scan(target, arguments=args)
            except Exception as exc:
                return None, f"nmap_scan_fallback_error: {exc}"

        return nm, ""

    @staticmethod
    def _parse_host_timeout_s(nmap_args: str) -> Optional[float]:
        if not isinstance(nmap_args, str):
            return None
        m = re.search(r"--host-timeout\\s+(\\d+)(ms|s|m|h)\\b", nmap_args)
        if not m:
            return None
        val = int(m.group(1))
        unit = m.group(2)
        if unit == "ms":
            return val / 1000.0
        if unit == "s":
            return float(val)
        if unit == "m":
            return float(val) * 60.0
        if unit == "h":
            return float(val) * 3600.0
        return None

    def _estimate_vuln_budget_s(self, host_info: Dict[str, Any]) -> float:
        """
        Timeout-aware upper bound for vulnerability scanning on a host.

        Uses tool timeouts configured in code paths (curl/wget/openssl/whatweb/nikto/testssl).
        """
        ports = [p for p in host_info.get("ports", []) if p.get("is_web_service")]
        if not ports:
            count = host_info.get("web_ports_count", 0)
            try:
                count_int = int(count)
            except Exception:
                count_int = 0
            ports = [{"port": 80, "service": "http"}] * max(0, count_int)

        has_http = bool(self.extra_tools.get("curl") or self.extra_tools.get("wget"))
        has_tls = bool(self.extra_tools.get("openssl"))
        has_whatweb = bool(self.extra_tools.get("whatweb"))
        has_nikto = bool(self.extra_tools.get("nikto"))
        has_testssl = bool(self.extra_tools.get("testssl.sh"))
        is_full = self.config.get("scan_mode") == "completo"

        budget = 0.0
        for p in ports:
            try:
                port = int(p.get("port", 0) or 0)
            except Exception:
                port = 0
            service = str(p.get("service", "") or "")
            service_l = service.lower()
            is_https = ("https" in service_l) or ("ssl" in service_l) or port == 443

            if has_http:
                budget += 15.0
            if has_tls and is_https:
                budget += 10.0
            if has_whatweb:
                budget += 30.0
            if is_full and has_nikto:
                budget += 150.0
            if is_full and has_testssl and is_https:
                budget += 90.0

        return max(5.0, budget)

    @contextmanager
    def _progress_ui(self):
        prev = self._ui_progress_active
        self._ui_progress_active = True
        try:
            yield
        finally:
            self._ui_progress_active = prev

    @staticmethod
    def sanitize_ip(ip_str):
        """Sanitize and validate IP address."""
        return sanitize_ip(ip_str)

    @staticmethod
    def sanitize_hostname(hostname):
        """Sanitize and validate hostname."""
        return sanitize_hostname(hostname)

    # ---------- Logging & heartbeat ----------

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

    # ---------- Crypto ----------

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
            self.print_status(self.t("crypto_missing"), "WARNING")
            if non_interactive:
                self.print_status(self.t("cryptography_required"), "FAIL")
            return

        if not non_interactive:
            if self.ask_yes_no(self.t("encrypt_reports"), default="no"):
                try:
                    pwd = ask_password_twice(self.t("encryption_password"), self.lang)
                    key, salt = derive_key_from_password(pwd)
                    self.encryption_key = key
                    self.config["encryption_salt"] = base64.b64encode(salt).decode()
                    self.encryption_enabled = True
                    self.config["encryption_enabled"] = True
                    self.print_status(self.t("encryption_enabled"), "OKGREEN")
                except RuntimeError as exc:
                    if "cryptography not available" in str(exc):
                        self.print_status(self.t("cryptography_required"), "FAIL")
                    else:
                        raise
        else:
            if not self.cryptography_available:
                self.print_status(self.t("cryptography_required"), "FAIL")
                return

            if password is None:
                password = generate_random_password()
                self.print_status(
                    f"⚠️  Generated random encryption password (save this!): {password}", "WARNING"
                )

            try:
                key, salt = derive_key_from_password(password)
                self.encryption_key = key
                self.config["encryption_salt"] = base64.b64encode(salt).decode()
                self.encryption_enabled = True
                self.config["encryption_enabled"] = True
                self.print_status(self.t("encryption_enabled"), "OKGREEN")
            except RuntimeError as exc:
                if "cryptography not available" in str(exc):
                    self.print_status(self.t("cryptography_required"), "FAIL")
                else:
                    raise

    # ---------- NVD API Key Configuration ----------

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
            self.print_status(self.t("config_module_missing"), "WARNING")
            return

        # If key provided via CLI, just use it
        if api_key:
            if validate_nvd_api_key(api_key):
                self.config["nvd_api_key"] = api_key
                self.print_status(self.t("nvd_key_set_cli"), "OKGREEN")
            else:
                self.print_status(self.t("nvd_key_invalid"), "WARNING")
            return

        # If already configured, use existing
        existing_key = get_nvd_api_key()
        if existing_key:
            self.config["nvd_api_key"] = existing_key
            return

        # Non-interactive mode without key - warn but continue
        if non_interactive:
            self.print_status(self.t("nvd_key_not_configured"), "WARNING")
            return

        # Interactive: ask user
        if not self.config.get("cve_lookup_enabled"):
            return  # Only prompt if CVE lookup is enabled

        print(f"\n{self.COLORS['WARNING']}")
        print("=" * 60)
        print(self.t("nvd_setup_header"))
        print("=" * 60)
        print(f"{self.COLORS['ENDC']}")
        print(self.t("nvd_setup_info"))
        print(
            f"\n{self.COLORS['CYAN']}https://nvd.nist.gov/developers/request-an-api-key{self.COLORS['ENDC']}\n"
        )

        options = [
            self.t("nvd_option_config"),  # Save in config file
            self.t("nvd_option_env"),  # Use environment variable
            self.t("nvd_option_skip"),  # Continue without
        ]

        choice = self.ask_choice(self.t("nvd_ask_storage"), options, default=2)

        if choice == 0:  # Save in config file
            while True:
                try:
                    key = input(f"\n{self.COLORS['CYAN']}?{self.COLORS['ENDC']} API Key: ").strip()
                    if not key:
                        self.print_status(self.t("nvd_key_skipped"), "INFO")
                        break

                    if validate_nvd_api_key(key):
                        if set_nvd_api_key(key, "config"):
                            self.config["nvd_api_key"] = key
                            self.print_status(self.t("nvd_key_saved"), "OKGREEN")
                        else:
                            self.print_status(self.t("nvd_key_save_error"), "WARNING")
                        break
                    else:
                        self.print_status(self.t("nvd_key_invalid_format"), "WARNING")
                except KeyboardInterrupt:
                    print("")
                    break

        elif choice == 1:  # Environment variable
            print(f"\n{self.t('nvd_env_instructions')}")
            print(
                f"  {self.COLORS['CYAN']}export NVD_API_KEY='your-api-key-here'{self.COLORS['ENDC']}"
            )
            self.print_status(self.t("nvd_env_set_later"), "INFO")

        else:  # Skip
            self.print_status(self.t("nvd_slow_mode"), "WARNING")

    # ---------- Dependencies ----------

    def check_dependencies(self):
        """Check and verify required dependencies."""
        self.print_status(self.t("verifying_env"), "HEADER")

        if shutil.which("nmap") is None:
            self.print_status(self.t("nmap_binary_missing"), "FAIL")
            return False

        global nmap
        try:
            nmap = importlib.import_module("nmap")
            self.print_status(self.t("nmap_avail"), "OKGREEN")
        except ImportError:
            self.print_status(self.t("nmap_missing"), "FAIL")
            return False

        self.cryptography_available = is_crypto_available()
        if not self.cryptography_available:
            self.print_status(self.t("crypto_missing"), "WARNING")

        tools = [
            "whatweb",
            "nikto",
            "curl",
            "wget",
            "openssl",
            "tcpdump",
            "tshark",
            "whois",
            "dig",
            "searchsploit",
            "testssl.sh",
            "nuclei",
            # v3.1+: Topology discovery (optional)
            "arp-scan",
            "lldpctl",
            "traceroute",
        ]
        # Fallback paths for tools not in standard PATH
        fallback_paths = {
            "testssl.sh": [
                "/usr/local/bin/testssl.sh",
                "/opt/testssl.sh/testssl.sh",
                "/usr/bin/testssl.sh",
            ],
        }
        missing = []
        for tname in tools:
            path = shutil.which(tname)
            # Check fallback paths if not found
            if not path and tname in fallback_paths:
                for fpath in fallback_paths[tname]:
                    if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                        path = fpath
                        break
            if path:
                self.extra_tools[tname] = path
                self.print_status(self.t("avail_at", tname, path), "OKGREEN")
            else:
                self.extra_tools[tname] = None
                missing.append(tname)

        if missing:
            self.print_status(self.t("missing_opt", ", ".join(missing)), "WARNING")
        return True

    # ---------- Input utilities (inherited from WizardMixin) ----------

    # ---------- Network detection ----------

    def detect_all_networks(self):
        """Detect all local networks."""
        self.print_status(self.t("analyzing_nets"), "INFO")
        nets = detect_all_networks(self.lang, self.print_status)
        self.results["network_info"] = nets
        return nets

    def _collect_discovery_hosts(self, target_networks: List[str]) -> List[str]:
        """Collect host IPs from enhanced discovery results (best-effort)."""
        discovery = self.results.get("net_discovery") or {}
        ips = set()

        def _add_ip(value):
            ip = sanitize_ip(value)
            if ip:
                ips.add(ip)

        for ip in discovery.get("alive_hosts", []) or []:
            _add_ip(ip)
        for host in discovery.get("arp_hosts", []) or []:
            if isinstance(host, dict):
                _add_ip(host.get("ip"))
        for host in discovery.get("netbios_hosts", []) or []:
            if isinstance(host, dict):
                _add_ip(host.get("ip"))
        for host in discovery.get("upnp_devices", []) or []:
            if isinstance(host, dict):
                _add_ip(host.get("ip"))
        for svc in discovery.get("mdns_services", []) or []:
            if isinstance(svc, dict):
                _add_ip(svc.get("ip"))
        for srv in discovery.get("dhcp_servers", []) or []:
            if isinstance(srv, dict):
                _add_ip(srv.get("ip"))
        for ip in (discovery.get("hyperscan_tcp_hosts") or {}).keys():
            _add_ip(ip)

        if not ips:
            return []

        networks = []
        for net in target_networks or []:
            try:
                networks.append(ipaddress.ip_network(str(net), strict=False))
            except Exception:
                continue

        if networks:
            filtered = []
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                except Exception:
                    continue
                if any(ip_obj in net for net in networks if net.version == ip_obj.version):
                    filtered.append(ip)
            return sorted(filtered)

        return sorted(ips)

    def ask_network_range(self):
        """Ask user to select target network(s)."""
        print(f"\n{self.COLORS['HEADER']}{self.t('selection_target')}{self.COLORS['ENDC']}")
        print("-" * 60)
        nets = self.detect_all_networks()
        if nets:
            print(f"{self.COLORS['OKGREEN']}{self.t('interface_detected')}{self.COLORS['ENDC']}")
            opts = []
            for n in nets:
                info = f" ({n['interface']})" if n["interface"] else ""
                opts.append(f"{n['network']}{info} - ~{n['hosts_estimated']} hosts")
            opts.append(self.t("manual_entry"))
            opts.append(self.t("scan_all"))
            choice = self.ask_choice(self.t("select_net"), opts)
            if choice == len(opts) - 2:
                return [self.ask_manual_network()]
            if choice == len(opts) - 1:
                # v3.2.3: Deduplicate networks (same CIDR on multiple interfaces)
                seen = set()
                unique_nets = []
                for n in nets:
                    cidr = n["network"]
                    if cidr not in seen:
                        seen.add(cidr)
                        unique_nets.append(cidr)
                return unique_nets
            return [nets[choice]["network"]]
        else:
            self.print_status(self.t("no_nets_auto"), "WARNING")
            return [self.ask_manual_network()]

    def _select_net_discovery_interface(self) -> Optional[str]:
        explicit = self.config.get("net_discovery_interface")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()

        nets = self.results.get("network_info", []) or []
        targets = []
        for token in self.config.get("target_networks", []) or []:
            try:
                targets.append(ipaddress.ip_network(str(token), strict=False))
            except Exception:
                continue

        for t in targets:
            for n in nets:
                iface = n.get("interface")
                net_str = n.get("network")
                if not iface or not net_str:
                    continue
                try:
                    net_obj = ipaddress.ip_network(str(net_str), strict=False)
                    if net_obj.version != t.version:
                        continue
                    if t.overlaps(net_obj):
                        return iface
                except Exception:
                    continue

        for n in nets:
            iface = n.get("interface")
            if iface:
                return iface

        return None

    # ---------- Scanning ----------

    def is_web_service(self, name):
        """Check if service is web-related."""
        return is_web_service(name)

    def deep_scan_host(self, host_ip):
        """
        Adaptive Deep Scan v2.8.0

        Improvements over v2.5:
        - Concurrent traffic capture (starts before scanning, stops after)
        - Intelligent 3-phase UDP: Priority ports first, then full scan (optional)
        - Better identity detection with MAC/OS fallback

        Phase 1: TCP Connect + Service Version + Scripts (Aggressive)
        Phase 2a: UDP Priority Ports scan (quick, common services)
        Phase 2b: Full UDP scan (only if udp_mode == 'full' and no identity yet)
        """
        safe_ip = sanitize_ip(host_ip)
        if not safe_ip:
            return None

        self.current_phase = f"deep:{safe_ip}"
        self._set_ui_detail(f"[deep] {safe_ip} tcp")
        deep_obj = {"strategy": "adaptive_v2.8", "commands": []}

        self.print_status(
            self.t("deep_identity_start", safe_ip, self.t("deep_strategy_adaptive")),
            "WARNING",
        )

        # Start background traffic capture BEFORE scanning
        # v2.8.1: Use actual output dir (timestamped folder) for PCAP files
        capture_info = start_background_capture(
            safe_ip,
            self.config.get("_actual_output_dir", self.config["output_dir"]),
            self.results.get("network_info", []),
            self.extra_tools,
            logger=self.logger,
        )

        try:
            # Phase 1: Aggressive TCP
            cmd_p1 = [
                "nmap",
                "-A",
                "-sV",
                "-Pn",
                "-p-",
                "--open",
                "--version-intensity",
                "9",
                safe_ip,
            ]
            self.print_status(
                self.t("deep_identity_cmd", safe_ip, " ".join(cmd_p1), "120-180"), "WARNING"
            )
            rec1 = run_nmap_command(
                cmd_p1,
                DEEP_SCAN_TIMEOUT,
                safe_ip,
                deep_obj,
                logger=self.logger,
                dry_run=bool(self.config.get("dry_run", False)),
            )

            # Check for Identity
            has_identity = output_has_identity([rec1])
            mac, vendor = extract_vendor_mac(rec1.get("stdout", ""))
            os_detected = extract_os_detection(
                f"{self._coerce_text(rec1.get('stdout'))}\n{self._coerce_text(rec1.get('stderr'))}"
            )

            if mac:
                deep_obj["mac_address"] = mac
            if vendor:
                deep_obj["vendor"] = vendor
            if os_detected:
                deep_obj["os_detected"] = os_detected

            # Phase 2: UDP scanning (Intelligent strategy)
            if has_identity:
                self.print_status(self.t("deep_scan_skip"), "OKGREEN")
                deep_obj["phase2_skipped"] = True
            else:
                # Phase 2a: Quick UDP scan of priority ports only
                udp_mode = self.config.get("udp_mode", DEFAULT_UDP_MODE)
                priority_ports = []
                for p in str(UDP_PRIORITY_PORTS).split(","):
                    try:
                        pi = int(p.strip())
                        if 1 <= pi <= 65535:
                            priority_ports.append(pi)
                    except Exception:
                        if self.logger:
                            self.logger.debug(
                                "Skipping invalid UDP priority port token: %r", p, exc_info=True
                            )
                        continue
                self.print_status(
                    self.t(
                        "deep_udp_priority_cmd",
                        safe_ip,
                        f"async UDP probe ({len(priority_ports)} ports)",
                    ),
                    "WARNING",
                )
                self._set_ui_detail(f"[deep] {safe_ip} udp probe")
                udp_probe_timeout = 0.8
                probe_start = time.time()
                udp_probe = run_udp_probe(
                    safe_ip,
                    priority_ports,
                    timeout=udp_probe_timeout,
                    concurrency=200,
                )
                probe_dur = time.time() - probe_start

                responded = [str(r.get("port")) for r in udp_probe if r.get("state") == "responded"]
                closed = [str(r.get("port")) for r in udp_probe if r.get("state") == "closed"]
                noresp_count = sum(1 for r in udp_probe if r.get("state") == "no_response")

                record = {
                    "command": f"udp_probe {safe_ip} priority_ports={len(priority_ports)} timeout={udp_probe_timeout}",
                    "returncode": 0,
                    "stdout": (
                        f"responded_ports: {', '.join(responded) if responded else 'none'}\n"
                        f"closed_ports: {', '.join(closed) if closed else 'none'}\n"
                        f"no_response_ports: {noresp_count}\n"
                    ),
                    "stderr": "",
                    "duration_seconds": round(probe_dur, 2),
                }
                deep_obj.setdefault("commands", []).append(record)
                deep_obj["udp_priority_probe"] = {
                    "timeout_seconds": udp_probe_timeout,
                    "results": udp_probe,
                }

                # Extract MAC from neighbor cache if not found yet (LAN best-effort).
                if not mac:
                    neigh_mac = get_neighbor_mac(safe_ip)
                    if neigh_mac:
                        deep_obj["mac_address"] = neigh_mac
                        mac = neigh_mac

                # Phase 2b: Full UDP scan (only if mode is 'full' and still no identity)
                # v2.9: Optimized to use top-ports instead of full 65535 port scan
                has_identity_now = output_has_identity(deep_obj.get("commands", []))
                if udp_mode == UDP_SCAN_MODE_FULL and not has_identity_now and not mac:
                    udp_top_ports = self.config.get("udp_top_ports", UDP_TOP_PORTS)
                    if not isinstance(udp_top_ports, int) or not (50 <= udp_top_ports <= 500):
                        udp_top_ports = UDP_TOP_PORTS
                    cmd_p2b = [
                        "nmap",
                        "-O",
                        "-sU",
                        "-Pn",
                        "--top-ports",
                        str(udp_top_ports),
                        "--max-retries",
                        str(UDP_MAX_RETRIES_LAN),
                        "--host-timeout",
                        UDP_HOST_TIMEOUT_STRICT,
                        safe_ip,
                    ]
                    self.print_status(
                        self.t("deep_udp_full_cmd", safe_ip, " ".join(cmd_p2b), udp_top_ports),
                        "WARNING",
                    )
                    self._set_ui_detail(f"[deep] {safe_ip} udp top {udp_top_ports}")
                    deep_obj["udp_top_ports"] = udp_top_ports
                    rec2b = run_nmap_command(
                        cmd_p2b,
                        DEEP_SCAN_TIMEOUT,
                        safe_ip,
                        deep_obj,
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                    )
                    if not mac:
                        m2b, v2b = extract_vendor_mac(rec2b.get("stdout", ""))
                        if m2b:
                            deep_obj["mac_address"] = m2b
                        if v2b:
                            deep_obj["vendor"] = v2b
                    if "os_detected" not in deep_obj:
                        os2b = extract_os_detection(
                            f"{self._coerce_text(rec2b.get('stdout'))}\n{self._coerce_text(rec2b.get('stderr'))}"
                        )
                        if os2b:
                            deep_obj["os_detected"] = os2b
                elif udp_mode == UDP_SCAN_MODE_QUICK:
                    deep_obj["phase2b_skipped"] = True
                    deep_obj["udp_mode"] = "quick"

        finally:
            # Stop background capture and collect results
            if capture_info:
                pcap_result = stop_background_capture(capture_info, self.extra_tools, self.logger)
                if pcap_result:
                    deep_obj["pcap_capture"] = pcap_result

        total_dur = sum(c.get("duration_seconds", 0) for c in deep_obj["commands"])
        self.print_status(self.t("deep_identity_done", safe_ip, total_dur), "OKGREEN")
        return deep_obj

    def scan_network_discovery(self, network):
        """Perform network discovery scan."""
        self.current_phase = f"discovery:{network}"
        self._set_ui_detail(f"[nmap] {network} discovery")
        self.logger.info("Discovery on %s", network)
        args = get_nmap_arguments("rapido")
        self.print_status(self.t("nmap_cmd", network, f"nmap {args} {network}"), "INFO")
        if is_dry_run(self.config.get("dry_run")):
            return []
        nm = nmap.PortScanner()
        try:
            # Nmap host discovery can look "stuck" on larger subnets; keep a visible activity
            # indicator while the scan is running.
            try:
                from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

                with self._progress_ui():
                    with Progress(
                        SpinnerColumn(),
                        self._safe_text_column(
                            f"[cyan]Discovery {network}[/cyan] {{task.description}}",
                            overflow="ellipsis",
                            no_wrap=True,
                        ),
                        TimeElapsedColumn(),
                        console=self._progress_console(),
                        transient=True,
                    ) as progress:
                        task = progress.add_task("nmap host discovery...", total=None)
                        nm.scan(hosts=network, arguments=args)
                        progress.update(task, description="complete")
            except Exception:
                with _ActivityIndicator(
                    label=f"Discovery {network}",
                    initial="nmap host discovery...",
                    touch_activity=self._touch_activity,
                ):
                    nm.scan(hosts=network, arguments=args)
        except Exception as exc:
            self.logger.error("Discovery failed on %s: %s", network, exc)
            self.logger.debug("Discovery exception details for %s", network, exc_info=True)
            self.print_status(self.t("scan_error", exc), "FAIL")
            return []
        hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        self.print_status(self.t("hosts_active", network, len(hosts)), "OKGREEN")
        return hosts

    def scan_host_ports(self, host):
        """
        Scan ports on a single host (v2.8.0).

        Improvements:
        - Intelligent status finalization based on deep scan results
        - Banner grab fallback for unidentified services
        - Better handling of filtered/no-response hosts
        """
        safe_ip = sanitize_ip(host)
        if not safe_ip:
            self.logger.warning("Invalid IP: %s", host)
            return {"ip": host, "error": "Invalid IP"}

        self.current_phase = f"ports:{safe_ip}"
        mode_label = str(self.config.get("scan_mode", "") or "").strip()
        if mode_label:
            self._set_ui_detail(f"[nmap] {safe_ip} ({mode_label})")
        else:
            self._set_ui_detail(f"[nmap] {safe_ip}")
        args = get_nmap_arguments(self.config["scan_mode"])
        self.logger.debug("Nmap scan %s %s", safe_ip, args)
        self.print_status(self.t("nmap_cmd", safe_ip, f"nmap {args} {safe_ip}"), "INFO")
        if is_dry_run(self.config.get("dry_run")):
            return {
                "ip": safe_ip,
                "hostname": "",
                "ports": [],
                "web_ports_count": 0,
                "total_ports_found": 0,
                "status": STATUS_DOWN,
                "dry_run": True,
            }
        try:
            nm, scan_error = self._run_nmap_xml_scan(safe_ip, args)
            if not nm:
                self.logger.warning("Nmap scan failed for %s: %s", safe_ip, scan_error)
                self.print_status(
                    f"⚠️  Nmap scan failed {safe_ip}: {scan_error}",
                    "FAIL",
                    force=True,
                )
                mac, vendor = self._lookup_topology_identity(safe_ip)
                if not mac:
                    mac = get_neighbor_mac(safe_ip)
                deep_meta = None
                if mac or vendor:
                    deep_meta = {"strategy": "topology", "commands": []}
                    if mac:
                        deep_meta["mac_address"] = mac
                    if vendor:
                        deep_meta["vendor"] = vendor
                return {
                    "ip": safe_ip,
                    "hostname": "",
                    "ports": [],
                    "web_ports_count": 0,
                    "total_ports_found": 0,
                    "status": STATUS_NO_RESPONSE,
                    "error": scan_error,
                    "scan_timeout_s": (
                        self._parse_host_timeout_s(args) or self._scan_mode_host_timeout_s()
                    ),
                    "deep_scan": deep_meta,
                }
            if safe_ip not in nm.all_hosts():
                # Host didn't respond to initial scan - do deep scan
                deep = None
                if self.config.get("deep_id_scan", True):
                    deep = self.deep_scan_host(safe_ip)
                base = {
                    "ip": safe_ip,
                    "hostname": "",
                    "ports": [],
                    "web_ports_count": 0,
                    "total_ports_found": 0,
                }
                result = (
                    {**base, "status": STATUS_NO_RESPONSE, "deep_scan": deep}
                    if deep
                    else {**base, "status": STATUS_DOWN}
                )
                if deep and deep.get("os_detected"):
                    result["os_detected"] = deep["os_detected"]
                # Finalize status based on deep scan results
                result["status"] = finalize_host_status(result)
                return result

            data = nm[safe_ip]
            hostname = ""
            try:
                hostnames = data.hostnames()
                if hostnames:
                    hostname = hostnames[0].get("name") or ""
            except Exception:
                if self.logger:
                    self.logger.debug("Failed to parse hostnames for %s", safe_ip, exc_info=True)
                hostname = ""

            ports = []
            web_count = 0
            suspicious = False
            any_version = False
            unknown_ports = []

            for proto in data.all_protocols():
                for p in data[proto]:
                    svc = data[proto][p]
                    name = svc.get("name", "") or ""
                    product = svc.get("product", "") or ""
                    version = svc.get("version", "") or ""
                    extrainfo = svc.get("extrainfo", "") or ""
                    cpe = svc.get("cpe") or []
                    is_web = is_web_service(name)
                    if is_web:
                        web_count += 1

                    if is_suspicious_service(name):
                        suspicious = True
                    if product or version:
                        any_version = True

                    # Track ports with no useful info for banner fallback
                    if not product and name in ("", "tcpwrapped", "unknown"):
                        unknown_ports.append(p)

                    ports.append(
                        {
                            "port": p,
                            "protocol": proto,
                            "service": name,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "cpe": cpe,
                            "is_web_service": is_web,
                        }
                    )

            total_ports = len(ports)
            if total_ports > MAX_PORTS_DISPLAY:
                self.print_status(self.t("ports_truncated", safe_ip, total_ports), "WARNING")
                ports = ports[:MAX_PORTS_DISPLAY]

            host_record = {
                "ip": safe_ip,
                "hostname": sanitize_hostname(hostname) or "",
                "ports": ports,
                "web_ports_count": web_count,
                "status": data.state(),
                "total_ports_found": total_ports,
            }

            # Best-effort identity capture from nmap host data (fast, avoids deep scan for quiet hosts).
            try:
                addresses = (data.get("addresses") or {}) if hasattr(data, "get") else {}
                mac = addresses.get("mac") if isinstance(addresses, dict) else None
                if mac:
                    deep_meta = host_record.setdefault(
                        "deep_scan", {"strategy": "nmap", "commands": []}
                    )
                    deep_meta["mac_address"] = mac
                    vendor_map = (data.get("vendor") or {}) if hasattr(data, "get") else {}
                    if isinstance(vendor_map, dict):
                        vendor = (
                            vendor_map.get(mac)
                            or vendor_map.get(mac.upper())
                            or vendor_map.get(mac.lower())
                        )
                        # v3.6.1: Online fallback for unknown vendors
                        if not vendor:
                            try:
                                from redaudit.utils.oui_lookup import lookup_vendor_online

                                vendor = lookup_vendor_online(mac)
                            except Exception:
                                pass
                        if vendor:
                            deep_meta["vendor"] = vendor
            except Exception:
                if self.logger:
                    self.logger.debug(
                        "Failed to read nmap identity metadata for %s", safe_ip, exc_info=True
                    )

            # v2.8.0: Banner grab fallback for unidentified ports
            if unknown_ports and len(unknown_ports) <= 20:
                self.print_status(self.t("banner_grab", safe_ip, len(unknown_ports)), "INFO")
                banner_info = banner_grab_fallback(safe_ip, unknown_ports, logger=self.logger)
                if banner_info:
                    # Merge banner info into ports
                    for port_info in ports:
                        port_num = port_info.get("port")
                        if port_num in banner_info:
                            extra = banner_info[port_num]
                            if extra.get("banner"):
                                port_info["banner"] = extra["banner"]
                            if extra.get("service") and not port_info.get("service"):
                                port_info["service"] = extra["service"]
                            if extra.get("ssl_cert"):
                                port_info["ssl_cert"] = extra["ssl_cert"]

            # v3.8.0: Enhanced evidence-based identity scoring with topology/net_discovery signals
            identity_score = 0
            identity_signals = []
            device_type_hints = []  # v3.8: Collect device type indicators

            # --- Standard signals ---
            if host_record.get("hostname"):
                identity_score += 1
                identity_signals.append("hostname")
            if any_version:
                identity_score += 1
                identity_signals.append("service_version")
            if any(p.get("cpe") for p in ports):
                identity_score += 1
                identity_signals.append("cpe")
            deep_meta = host_record.get("deep_scan") or {}
            if deep_meta.get("mac_address") or deep_meta.get("vendor"):
                identity_score += 1
                identity_signals.append("mac_vendor")
                # v3.8.1: Device type from vendor (IoT, mobile, printer, router, etc.)
                vendor_lower = str(deep_meta.get("vendor") or "").lower()
                if any(
                    x in vendor_lower
                    for x in ("apple", "samsung", "xiaomi", "huawei", "oppo", "oneplus")
                ):
                    device_type_hints.append("mobile")
                elif any(
                    x in vendor_lower
                    for x in ("hp", "canon", "epson", "brother", "lexmark", "xerox")
                ):
                    device_type_hints.append("printer")
                elif any(
                    x in vendor_lower
                    for x in ("philips", "signify", "wiz", "yeelight", "lifx", "tp-link tapo")
                ):
                    device_type_hints.append("iot_lighting")
                elif any(
                    x in vendor_lower
                    for x in (
                        "avm",
                        "fritz",
                        "cisco",
                        "juniper",
                        "mikrotik",
                        "ubiquiti",
                        "netgear",
                        "dlink",
                        "asus",
                        "linksys",
                        "tp-link",
                    )
                ):
                    device_type_hints.append("router")
                elif any(
                    x in vendor_lower for x in ("google", "amazon", "roku", "lg", "sony", "vizio")
                ):
                    device_type_hints.append("smart_tv")

            # v3.8.1: Hostname-based device detection (catches Apple devices without vendor)
            hostname_lower = str(host_record.get("hostname") or "").lower()
            if any(x in hostname_lower for x in ("iphone", "ipad", "ipod", "macbook", "imac")):
                if "mobile" not in device_type_hints:
                    device_type_hints.append("mobile")
            elif any(x in hostname_lower for x in ("android", "galaxy", "pixel", "oneplus")):
                if "mobile" not in device_type_hints:
                    device_type_hints.append("mobile")
            if host_record.get("os_detected"):
                identity_score += 1
                identity_signals.append("os_detected")
            if any(p.get("banner") for p in ports):
                identity_score += 1
                identity_signals.append("banner")

            # --- v3.8: New topology/net_discovery signals ---
            # Check if this host appeared in net_discovery results (UPNP, mDNS, ARP, etc.)
            nd_results = self.results.get("net_discovery") or {}
            nd_hosts_ips = set()
            for h in nd_results.get("arp_hosts", []):
                nd_hosts_ips.add(h.get("ip"))
            for h in nd_results.get("upnp_devices", []):
                nd_hosts_ips.add(h.get("ip"))
            for svc in nd_results.get("mdns_services", []):
                for addr in svc.get("addresses", []):
                    nd_hosts_ips.add(addr)

            if safe_ip in nd_hosts_ips:
                identity_score += 1
                identity_signals.append("net_discovery")

            # UPNP device type enrichment
            for upnp in nd_results.get("upnp_devices", []):
                if upnp.get("ip") == safe_ip:
                    upnp_type = str(upnp.get("device_type") or upnp.get("st") or "").lower()
                    if "router" in upnp_type or "gateway" in upnp_type:
                        device_type_hints.append("router")
                        identity_score += 1
                        identity_signals.append("upnp_router")
                    elif "printer" in upnp_type:
                        device_type_hints.append("printer")
                    elif "mediarenderer" in upnp_type or "mediaplayer" in upnp_type:
                        device_type_hints.append("smart_tv")
                    break

            # mDNS service type enrichment
            for svc in nd_results.get("mdns_services", []):
                if safe_ip in svc.get("addresses", []):
                    svc_type = str(svc.get("type") or "").lower()
                    if "_ipp" in svc_type or "_printer" in svc_type:
                        device_type_hints.append("printer")
                    elif "_airplay" in svc_type or "_raop" in svc_type:
                        device_type_hints.append("apple_device")
                    elif "_googlecast" in svc_type:
                        device_type_hints.append("chromecast")
                    elif "_hap" in svc_type or "_homekit" in svc_type:
                        device_type_hints.append("homekit")

            # Service-based device detection
            for p in ports:
                svc = str(p.get("service") or "").lower()
                prod = str(p.get("product") or "").lower()
                if any(x in svc or x in prod for x in ("ipp", "printer", "cups")):
                    device_type_hints.append("printer")
                elif any(x in svc or x in prod for x in ("router", "mikrotik", "routeros")):
                    device_type_hints.append("router")
                elif "esxi" in prod or "vmware" in prod or "vcenter" in prod:
                    device_type_hints.append("hypervisor")

            # Store device type hints (deduplicated)
            host_record["device_type_hints"] = list(set(device_type_hints))

            # v3.8: Visible logging of SmartScan decision
            if self.logger:
                self.logger.debug(
                    "Identity signals for %s: score=%s (%s), device_hints=%s",
                    safe_ip,
                    identity_score,
                    ",".join(identity_signals) or "none",
                    ",".join(device_type_hints) or "none",
                )

            # Heuristics for deep identity scan
            trigger_deep = False
            deep_enabled = self.config.get("deep_id_scan", True)
            # v3.8: In full scan mode still allow deep heuristic, but with higher threshold
            is_full_mode = self.config.get("scan_mode") in ("completo", "full")
            deep_reasons = []
            if deep_enabled:
                # v3.8: More triggers for thorough discovery
                if total_ports > 8:
                    trigger_deep = True
                    deep_reasons.append("many_ports")
                if suspicious:
                    trigger_deep = True
                    deep_reasons.append("suspicious_service")
                # Low visibility hosts need deep scan to identify
                if 0 < total_ports <= 3:
                    trigger_deep = True
                    deep_reasons.append("low_visibility")
                if total_ports > 0 and not any_version:
                    trigger_deep = True
                    deep_reasons.append("no_version_info")
                # v3.8: Network devices (routers/switches) always get deep treatment
                if "router" in device_type_hints or "network_device" in device_type_hints:
                    trigger_deep = True
                    deep_reasons.append("network_infrastructure")
                # v3.8: Adjust threshold based on scan mode (full mode is more lenient)
                identity_threshold = 4 if is_full_mode else 3
                if (
                    identity_score >= identity_threshold
                    and not suspicious
                    and total_ports <= 12
                    and any_version
                ):
                    trigger_deep = False
                    deep_reasons.append("identity_strong")

            host_record["smart_scan"] = {
                "mode": self.config.get("scan_mode"),
                "identity_score": identity_score,
                "signals": identity_signals,
                "suspicious_service": suspicious,
                "trigger_deep": bool(trigger_deep),
                "reasons": deep_reasons,
                "deep_scan_executed": False,
            }

            # SearchSploit exploit lookup for services with version info
            if self.extra_tools.get("searchsploit"):
                for port_info in ports:
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    if product and version:
                        exploits = exploit_lookup(product, version, self.extra_tools, self.logger)
                        if exploits:
                            port_info["known_exploits"] = exploits
                            self.print_status(
                                self.t("exploits_found", len(exploits), f"{product} {version}"),
                                "WARNING",
                            )

            if trigger_deep:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    host_record["deep_scan"] = deep
                    if deep.get("os_detected"):
                        host_record["os_detected"] = deep["os_detected"]
                    host_record["smart_scan"]["deep_scan_executed"] = True

            enrich_host_with_dns(host_record, self.extra_tools)
            enrich_host_with_whois(host_record, self.extra_tools)

            # v2.8.0: Finalize status based on all collected data
            host_record["status"] = finalize_host_status(host_record)

            return host_record

        except Exception as exc:
            self.logger.error("Scan error %s: %s", safe_ip, exc, exc_info=True)
            # Keep terminal output clean while progress UIs are active.
            self.print_status(f"⚠️  Scan error {safe_ip}: {exc}", "FAIL", force=True)
            result = {"ip": safe_ip, "error": str(exc)}
            try:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    result["deep_scan"] = deep
                    result["status"] = finalize_host_status(result)
            except Exception:
                if self.logger:
                    self.logger.debug("Deep scan fallback failed for %s", safe_ip, exc_info=True)
                pass
            return result

    def scan_hosts_concurrent(self, hosts):
        """Scan multiple hosts concurrently with progress bar."""
        self.print_status(self.t("scan_start", len(hosts)), "HEADER")
        unique_hosts = sorted(set(hosts))
        results = []
        threads = max(1, int(self.config.get("threads", 1)))
        start_t = time.time()
        host_timeout_s = self._parse_host_timeout_s(
            get_nmap_arguments(self.config.get("scan_mode"), self.config)
        )
        if host_timeout_s is None:
            host_timeout_s = self._scan_mode_host_timeout_s()

        # Try to use rich for better progress visualization
        try:
            from rich.progress import Progress

            use_rich = True
        except ImportError:
            use_rich = False

        # Keep output quiet from the moment worker threads start.
        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for h in unique_hosts:
                    if self.interrupted:
                        break
                    fut = executor.submit(self.scan_host_ports, h)
                    futures[fut] = h
                    if self.rate_limit_delay > 0:
                        # A3: Jitter ±30% for IDS evasion
                        jitter = random.uniform(-0.3, 0.3) * self.rate_limit_delay
                        actual_delay = max(0.1, self.rate_limit_delay + jitter)
                        time.sleep(actual_delay)

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    # Rich progress bar (quiet UI + timeout-aware upper bound ETA)
                    with Progress(
                        *self._progress_columns(
                            show_detail=True,
                            show_eta=True,
                            show_elapsed=True,
                        ),
                        console=self._progress_console(),
                    ) as progress:
                        initial_detail = self._get_ui_detail()
                        # v3.8.1: Simplified task - no ETA fields
                        task = progress.add_task(
                            f"[cyan]{self.t('scanning_hosts')}",
                            total=total,
                            detail=initial_detail,
                        )
                        pending = set(futures)
                        last_detail = initial_detail
                        last_heartbeat = start_t
                        while pending:
                            if self.interrupted:
                                for pending_fut in pending:
                                    pending_fut.cancel()
                                break

                            completed, pending = wait(
                                pending, timeout=0.25, return_when=FIRST_COMPLETED
                            )
                            detail = self._get_ui_detail()
                            if detail != last_detail:
                                progress.update(task, detail=detail)
                                last_detail = detail

                            # v3.8.1: Heartbeat every 60s for visibility
                            now = time.time()
                            if now - last_heartbeat >= 60.0:
                                elapsed = int(now - start_t)
                                mins, secs = divmod(elapsed, 60)
                                self.print_status(
                                    f"Escaneando hosts... {done}/{total} ({mins}:{secs:02d} transcurrido)",
                                    "INFO",
                                    force=True,
                                )
                                last_heartbeat = now
                            detail = self._get_ui_detail()
                            if detail != last_detail:
                                progress.update(task, detail=detail)
                                last_detail = detail

                            for fut in completed:
                                host_ip = futures.get(fut)
                                try:
                                    res = fut.result()
                                    results.append(res)
                                except Exception as exc:
                                    self.logger.error("Worker error for %s: %s", host_ip, exc)
                                    self.logger.debug(
                                        "Worker exception details for %s", host_ip, exc_info=True
                                    )
                                done += 1
                                # v3.8.1: Simplified progress update - no ETA
                                progress.update(
                                    task,
                                    advance=1,
                                    description=f"[cyan]{self.t('scanned_host', host_ip)}",
                                    detail=last_detail,
                                )
                else:
                    # Fallback to basic progress (throttled, includes timeout-aware upper bound ETA)
                    for fut in as_completed(futures):
                        if self.interrupted:
                            # C2 fix: Cancel pending futures
                            for pending_fut in futures:
                                pending_fut.cancel()
                            break
                        host_ip = futures[fut]
                        try:
                            res = fut.result()
                            results.append(res)
                        except Exception as exc:
                            self.logger.error("Worker error for %s: %s", host_ip, exc)
                            self.logger.debug(
                                "Worker exception details for %s", host_ip, exc_info=True
                            )
                        done += 1
                        # v3.8.1: Show elapsed instead of ETA
                        if total and done % max(1, total // 10) == 0:
                            elapsed = int(time.time() - start_t)
                            mins, secs = divmod(elapsed, 60)
                            self.print_status(
                                f"{self.t('progress', done, total)} ({mins}:{secs:02d} transcurrido)",
                                "INFO",
                                update_activity=False,
                                force=True,
                            )

        self.results["hosts"] = results
        return results

    def scan_vulnerabilities_web(self, host_info):
        """Scan web vulnerabilities on a host."""
        web_ports = [p for p in host_info.get("ports", []) if p.get("is_web_service")]
        if not web_ports:
            return None

        ip = host_info["ip"]
        vulns = []

        for p in web_ports:
            port = p["port"]
            service = p["service"].lower()
            # v3.6.1: Expanded HTTPS detection for non-standard ports
            HTTPS_PORTS = {443, 8443, 4443, 9443, 49443}
            scheme = "https" if port in HTTPS_PORTS or "ssl" in service else "http"
            url = f"{scheme}://{ip}:{port}/"
            finding = {"url": url, "port": port}

            # HTTP enrichment
            http_data = http_enrichment(
                url,
                self.extra_tools,
                dry_run=bool(self.config.get("dry_run", False)),
                logger=self.logger,
            )
            finding.update(http_data)

            # TLS enrichment
            if scheme == "https":
                tls_data = tls_enrichment(
                    ip,
                    port,
                    self.extra_tools,
                    dry_run=bool(self.config.get("dry_run", False)),
                    logger=self.logger,
                )
                finding.update(tls_data)

                # TestSSL deep analysis (only in completo mode)
                if self.config["scan_mode"] == "completo" and self.extra_tools.get("testssl.sh"):
                    self.current_phase = f"vulns:testssl:{ip}:{port}"
                    self._set_ui_detail(f"[testssl] {ip}:{port}")
                    self.print_status(
                        f"[testssl] {ip}:{port} → {self.t('testssl_analysis', ip, port)}", "INFO"
                    )
                    ssl_analysis = ssl_deep_analysis(ip, port, self.extra_tools, self.logger)
                    if ssl_analysis:
                        finding["testssl_analysis"] = ssl_analysis
                        # Alert if vulnerabilities found
                        if ssl_analysis.get("vulnerabilities"):
                            self.print_status(
                                f"⚠️  SSL/TLS vulnerabilities detected on {ip}:{port}", "WARNING"
                            )

            # WhatWeb
            if self.extra_tools.get("whatweb"):
                try:
                    self.current_phase = f"vulns:whatweb:{ip}:{port}"
                    self._set_ui_detail(f"[whatweb] {ip}:{port}")
                    runner = CommandRunner(
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                        default_timeout=30.0,
                        default_retries=0,
                        backoff_base_s=0.0,
                        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    )
                    res = runner.run(
                        [self.extra_tools["whatweb"], "-q", "-a", "3", url],
                        capture_output=True,
                        check=False,
                        text=True,
                        timeout=30.0,
                    )
                    if not res.timed_out:
                        output = str(res.stdout or "").strip()
                        if output:
                            finding["whatweb"] = output[:2000]
                except Exception:
                    if self.logger:
                        self.logger.debug("WhatWeb scan failed for %s", url, exc_info=True)

            # Nikto (only in full mode)
            # v2.9: Smart-Check integration for false positive filtering
            if self.config["scan_mode"] == "completo" and self.extra_tools.get("nikto"):
                try:
                    self.current_phase = f"vulns:nikto:{ip}:{port}"
                    self._set_ui_detail(f"[nikto] {ip}:{port}")
                    from redaudit.core.verify_vuln import filter_nikto_false_positives

                    runner = CommandRunner(
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                        default_timeout=150.0,
                        default_retries=0,
                        backoff_base_s=0.0,
                        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
                    )
                    res = runner.run(
                        [self.extra_tools["nikto"], "-h", url, "-maxtime", "120s", "-Tuning", "x"],
                        capture_output=True,
                        check=False,
                        text=True,
                        timeout=150.0,
                    )
                    if not res.timed_out:
                        output = str(res.stdout or "") or str(res.stderr or "")
                        if output:
                            findings_list = [line for line in output.splitlines() if "+ " in line][
                                :20
                            ]
                            if findings_list:
                                # v2.9: Filter false positives using Smart-Check
                                original_count = len(findings_list)
                                verified = filter_nikto_false_positives(
                                    findings_list, url, self.extra_tools, self.logger
                                )
                                if verified:
                                    finding["nikto_findings"] = verified
                                    # Track how many were filtered
                                    filtered = original_count - len(verified)
                                    if filtered > 0:
                                        finding["nikto_filtered_count"] = filtered
                                        self.print_status(
                                            f"[nikto] {ip}:{port} → Filtered {filtered}/{original_count} false positives",
                                            "INFO",
                                        )
                except Exception:
                    if self.logger:
                        self.logger.debug("Nikto scan failed for %s", url, exc_info=True)

            if len(finding) > 2:
                vulns.append(finding)

        return {"host": ip, "vulnerabilities": vulns} if vulns else None

    def scan_vulnerabilities_concurrent(self, host_results):
        """Scan vulnerabilities on multiple hosts concurrently with progress bar."""
        web_hosts = [h for h in host_results if h.get("web_ports_count", 0) > 0]
        if not web_hosts:
            return

        # Count total web ports for info
        total_ports = sum(h.get("web_ports_count", 0) for h in web_hosts)
        budgets = {h["ip"]: self._estimate_vuln_budget_s(h) for h in web_hosts if h.get("ip")}
        remaining_budget_s = float(sum(budgets.values()))

        self.current_phase = "vulns"
        self._set_ui_detail("web vuln scan")
        self.print_status(self.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])
        workers = max(1, int(workers))

        # Try to use rich for progress visualization
        try:
            from rich.progress import Progress

            use_rich = True
        except ImportError:
            use_rich = False

        # Keep output quiet from the moment worker threads start.
        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self.scan_vulnerabilities_web, h): h["ip"] for h in web_hosts
                }

                total = len(futures)
                done = 0
                start_t = time.time()

                if use_rich and total > 0:
                    # Rich progress bar for vulnerability scanning (quiet UI + timeout-aware upper bound ETA)
                    with Progress(
                        *self._progress_columns(
                            show_detail=True,
                            show_eta=True,
                            show_elapsed=True,
                        ),
                        console=self._progress_console(),
                    ) as progress:
                        eta_upper_init = self._format_eta(remaining_budget_s / workers)
                        initial_detail = self._get_ui_detail()
                        task = progress.add_task(
                            f"[cyan]Vuln scan ({total_ports} ports)",
                            total=total,
                            eta_upper=eta_upper_init,
                            eta_est="",
                            detail=initial_detail,
                        )
                        pending = set(futures)
                        last_detail = initial_detail
                        while pending:
                            if self.interrupted:
                                for pending_fut in pending:
                                    pending_fut.cancel()
                                break

                            completed, pending = wait(
                                pending, timeout=0.25, return_when=FIRST_COMPLETED
                            )
                            detail = self._get_ui_detail()
                            if detail != last_detail:
                                progress.update(task, detail=detail)
                                last_detail = detail

                            for fut in completed:
                                host_ip = futures[fut]
                                try:
                                    res = fut.result()
                                    if res:
                                        self.results["vulnerabilities"].append(res)
                                        vuln_count = len(res.get("vulnerabilities", []))
                                        if vuln_count > 0 and self.logger:
                                            self.logger.info(
                                                "Vulnerabilities recorded on %s", res["host"]
                                            )
                                except Exception as exc:
                                    self.logger.error("Vuln worker error for %s: %s", host_ip, exc)
                                    self.logger.debug(
                                        "Vuln worker exception details for %s",
                                        host_ip,
                                        exc_info=True,
                                    )
                                done += 1
                                remaining_budget_s = max(
                                    0.0, remaining_budget_s - budgets.get(host_ip, 0.0)
                                )
                                remaining = max(0, total - done)
                                elapsed_s = max(0.001, time.time() - start_t)
                                rate = done / elapsed_s if done else 0.0
                                eta_est_val = (
                                    self._format_eta(remaining / rate)
                                    if rate > 0.0 and remaining
                                    else ""
                                )
                                progress.update(
                                    task,
                                    advance=1,
                                    description=f"[cyan]{self.t('scanned_host', host_ip)}",
                                    eta_upper=self._format_eta(remaining_budget_s / workers),
                                    eta_est=f"ETA≈ {eta_est_val}" if eta_est_val else "",
                                    detail=last_detail,
                                )
                else:
                    # Fallback without rich (throttled)
                    for fut in as_completed(futures):
                        if self.interrupted:
                            for pending_fut in futures:
                                pending_fut.cancel()
                            break
                        host_ip = futures[fut]
                        try:
                            res = fut.result()
                            if res:
                                self.results["vulnerabilities"].append(res)
                        except Exception as exc:
                            self.print_status(self.t("worker_error", exc), "WARNING", force=True)
                            if self.logger:
                                self.logger.debug(
                                    "Vuln worker exception details for %s", host_ip, exc_info=True
                                )
                        done += 1
                        remaining_budget_s = max(
                            0.0, remaining_budget_s - budgets.get(host_ip, 0.0)
                        )
                        if total and done % max(1, total // 10) == 0:
                            self.print_status(
                                f"{self.t('progress', done, total)} | ETA≤ {self._format_eta(remaining_budget_s / workers)}",
                                "INFO",
                                update_activity=False,
                                force=True,
                            )

    def run_agentless_verification(self, host_results):
        """
        Agentless verification (SMB/RDP/LDAP/SSH/HTTP) using Nmap scripts.

        This is opt-in and best-effort. It enriches host records with
        fingerprint hints (domain/computer name/signing posture/title/server).
        """
        if self.interrupted or not self.config.get("windows_verify_enabled", False):
            return

        targets = select_agentless_probe_targets(host_results)
        if not targets:
            self.print_status(self.t("windows_verify_none"), "INFO")
            return

        max_targets = int(self.config.get("windows_verify_max_targets", 20) or 20)
        max_targets = min(max(max_targets, 1), 200)
        if len(targets) > max_targets:
            targets = sorted(targets, key=lambda t: t.ip)[:max_targets]
            self.print_status(self.t("windows_verify_limit", max_targets), "WARNING")

        self.print_status(self.t("windows_verify_start", len(targets)), "HEADER")

        host_index = {h.get("ip"): h for h in host_results if isinstance(h, dict)}
        results: List[Dict[str, Any]] = []

        workers = min(4, max(1, int(self.config.get("threads", 1))))
        start_t = time.time()

        try:
            from rich.progress import Progress

            use_rich = True
        except ImportError:
            use_rich = False

        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(
                        probe_agentless_services,
                        t,
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                    ): t.ip
                    for t in targets
                }

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    upper_per_target_s = 60.0
                    with Progress(
                        *self._progress_columns(
                            show_detail=True,
                            show_eta=True,
                            show_elapsed=True,
                        ),
                        console=self._progress_console(),
                    ) as progress:
                        task = progress.add_task(
                            f"[cyan]{self.t('windows_verify_label')}",
                            total=total,
                            detail="",
                            eta_upper=self._format_eta(
                                upper_per_target_s * math.ceil(total / workers)
                            ),
                            eta_est="",
                        )
                        pending = set(futures)
                        while pending:
                            if self.interrupted:
                                for pending_fut in pending:
                                    pending_fut.cancel()
                                break
                            completed, pending = wait(
                                pending, timeout=0.25, return_when=FIRST_COMPLETED
                            )
                            for fut in completed:
                                ip = futures.get(fut)
                                try:
                                    res = fut.result()
                                except Exception as exc:
                                    res = {"ip": ip, "error": str(exc)}
                                    if self.logger:
                                        self.logger.debug(
                                            "Windows verify failed for %s", ip, exc_info=True
                                        )
                                results.append(res)
                                done += 1
                                elapsed_s = max(0.001, time.time() - start_t)
                                rate = done / elapsed_s if done else 0.0
                                remaining = max(0, total - done)
                                eta_est_val = (
                                    self._format_eta(remaining / rate)
                                    if rate > 0.0 and remaining
                                    else ""
                                )
                                if ip:
                                    progress.update(task, detail=f"{ip}")
                                progress.update(
                                    task,
                                    advance=1,
                                    description=f"[cyan]{self.t('windows_verify_label')} ({done}/{total})",
                                    eta_upper=self._format_eta(
                                        upper_per_target_s * math.ceil(remaining / workers)
                                        if remaining
                                        else 0
                                    ),
                                    eta_est=f"ETA≈ {eta_est_val}" if eta_est_val else "",
                                )
                else:
                    for fut in as_completed(futures):
                        if self.interrupted:
                            for pending_fut in futures:
                                pending_fut.cancel()
                            break
                        ip = futures.get(fut)
                        try:
                            res = fut.result()
                        except Exception as exc:
                            res = {"ip": ip, "error": str(exc)}
                            if self.logger:
                                self.logger.debug("Windows verify failed for %s", ip, exc_info=True)
                        results.append(res)
                        done += 1
                        if total and done % max(1, total // 10) == 0:
                            remaining = max(0, total - done)
                            rate = done / max(0.001, (time.time() - start_t))
                            eta_est_val = (
                                self._format_eta(remaining / rate)
                                if rate > 0.0 and remaining
                                else "--:--"
                            )
                            self.print_status(
                                f"{self.t('windows_verify_label')} {done}/{total} | ETA≈ {eta_est_val}",
                                "INFO",
                                update_activity=False,
                                force=True,
                            )

        for res in results:
            ip = res.get("ip")
            if not ip or ip not in host_index:
                continue
            host = host_index[ip]
            host["agentless_probe"] = res
            agentless_fp = summarize_agentless_fingerprint(res)
            host["agentless_fingerprint"] = agentless_fp
            smart = host.get("smart_scan")
            if isinstance(smart, dict) and isinstance(agentless_fp, dict) and agentless_fp:
                signals = list(smart.get("signals") or [])
                if "agentless" not in signals:
                    signals.append("agentless")
                    try:
                        smart["identity_score"] = int(smart.get("identity_score", 0)) + 1
                    except Exception:
                        smart["identity_score"] = smart.get("identity_score", 0)
                hint_keys = []
                for key in (
                    "domain",
                    "dns_domain_name",
                    "dns_computer_name",
                    "computer_name",
                    "os",
                    "http_title",
                    "http_server",
                    "smb_signing_required",
                    "smbv1_detected",
                ):
                    if agentless_fp.get(key) not in (None, ""):
                        hint_keys.append(key)
                if hint_keys:
                    smart["agentless_hints"] = hint_keys
                smart["signals"] = signals

        self.results["agentless_verify"] = {
            "targets": len(targets),
            "completed": len(results),
        }
        self.results["hosts"] = host_results
        self.print_status(self.t("windows_verify_done", len(results)), "OKGREEN")

    # ---------- Reporting ----------

    def show_config_summary(self):
        """Display configuration summary."""
        show_config_summary(self.config, self.t, self.COLORS)

    def show_results(self):
        """Display final results summary."""
        show_results_summary(self.results, self.t, self.COLORS, self.config["output_dir"])

    def show_legal_warning(self):
        """Display legal warning and ask for confirmation."""
        print(f"{self.COLORS['FAIL']}{self.t('legal_warn')}{self.COLORS['ENDC']}")
        return self.ask_yes_no(self.t("legal_ask"), default="no")

    def save_results(self, partial=False):
        """Save results to files."""
        self.current_phase = "saving"
        if self.config.get("lang") is None:
            self.config["lang"] = self.lang
        save_results(
            self.results,
            self.config,
            self.encryption_enabled,
            self.encryption_key,
            partial,
            self.print_status,
            self.t,
            self.logger,
        )

    # ---------- Interactive flow (UI methods inherited from WizardMixin) ----------

    def interactive_setup(self):
        """Run interactive configuration setup."""
        # Apply persisted defaults early (language affects the banner/prompt text).
        persisted_defaults = {}
        try:
            from redaudit.utils.config import get_persistent_defaults

            persisted_defaults = get_persistent_defaults()
        except Exception:
            if self.logger:
                self.logger.debug("Failed to load persisted defaults", exc_info=True)
            persisted_defaults = {}

        default_lang = persisted_defaults.get("lang")
        if default_lang in TRANSLATIONS:
            self.lang = default_lang

        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies():
            return False
        if not self.show_legal_warning():
            return False

        # v3.2.1+: Give explicit control over persisted defaults.
        defaults_for_run = persisted_defaults
        should_skip_config = False
        auto_start = False
        scan_default_keys = (
            "target_networks",
            "threads",
            "output_dir",
            "rate_limit",
            "udp_mode",
            "udp_top_ports",
            "topology_enabled",
            "topology_only",
            "scan_mode",
            "scan_vulnerabilities",
            "nuclei_enabled",
            "cve_lookup_enabled",
            "generate_txt",
            "generate_html",
            "net_discovery_enabled",
            "net_discovery_redteam",
            "net_discovery_active_l2",
            "net_discovery_kerberos_userenum",
            "net_discovery_kerberos_realm",
            "net_discovery_kerberos_userlist",
        )
        has_scan_defaults = any(persisted_defaults.get(k) is not None for k in scan_default_keys)

        if has_scan_defaults:
            mode = getattr(self, "defaults_mode", "ask") or "ask"
            if mode == "ignore":
                defaults_for_run = {}
                self.print_status(self.t("defaults_ignore_confirm"), "INFO")
            elif mode == "ask":
                self.print_status(self.t("defaults_detected"), "INFO")
                options = [
                    self.t("defaults_action_use"),
                    self.t("defaults_action_review"),
                    self.t("defaults_action_ignore"),
                ]
                choice = self.ask_choice(self.t("defaults_action_q"), options, 0)
                if choice == 2:
                    defaults_for_run = {}
                    self.print_status(self.t("defaults_ignore_confirm"), "INFO")
                elif choice == 0:
                    # Use defaults and continue immediately (no re-asking scan parameters).
                    should_skip_config = True
                    auto_start = True
                elif choice == 1:
                    show_summary = self.ask_yes_no(self.t("defaults_show_summary_q"), default="no")
                    if show_summary:
                        self._show_defaults_summary(persisted_defaults)

        print(f"\n{self.COLORS['HEADER']}{self.t('scan_config')}{self.COLORS['ENDC']}")
        print("=" * 60)

        # Targets: if the user chose to start immediately, prefer persisted targets when valid.
        target_networks = (
            defaults_for_run.get("target_networks") if isinstance(defaults_for_run, dict) else None
        )
        if (
            should_skip_config
            and isinstance(target_networks, list)
            and target_networks
            and all(isinstance(t, str) and t.strip() for t in target_networks)
        ):
            self.config["target_networks"] = [t.strip() for t in target_networks]
            self.print_status(
                self.t("defaults_targets_applied", len(self.config["target_networks"])), "INFO"
            )
        else:
            self.config["target_networks"] = self.ask_network_range()

        if should_skip_config:
            self._apply_run_defaults(defaults_for_run)
            self.encryption_enabled = False
        else:
            self._configure_scan_interactive(defaults_for_run)

        self.show_config_summary()

        if auto_start:
            return True

        # v3.1+: Save chosen settings as persistent defaults (optional).
        # v3.2.2+: Simplified - max 2 final prompts (save + start)
        wants_save_defaults = self.ask_yes_no(self.t("save_defaults_q"), default="no")
        if wants_save_defaults:
            try:
                from redaudit.utils.config import update_persistent_defaults

                ok = update_persistent_defaults(
                    target_networks=self.config.get("target_networks"),
                    threads=self.config.get("threads"),
                    output_dir=self.config.get("output_dir"),
                    rate_limit=self.rate_limit_delay,
                    udp_mode=self.config.get("udp_mode"),
                    udp_top_ports=self.config.get("udp_top_ports"),
                    topology_enabled=self.config.get("topology_enabled"),
                    topology_only=self.config.get("topology_only"),
                    # v3.2.3+: New defaults
                    scan_mode=self.config.get("scan_mode"),
                    scan_vulnerabilities=self.config.get("scan_vulnerabilities"),
                    nuclei_enabled=self.config.get("nuclei_enabled"),
                    cve_lookup_enabled=self.config.get("cve_lookup_enabled"),
                    generate_txt=self.config.get("save_txt_report"),
                    generate_html=self.config.get("save_html_report"),
                    # v3.6.0+: Net discovery / red team
                    net_discovery_enabled=self.config.get("net_discovery_enabled"),
                    net_discovery_redteam=self.config.get("net_discovery_redteam"),
                    net_discovery_active_l2=self.config.get("net_discovery_active_l2"),
                    net_discovery_kerberos_userenum=self.config.get(
                        "net_discovery_kerberos_userenum"
                    ),
                    net_discovery_kerberos_realm=self.config.get("net_discovery_kerberos_realm"),
                    net_discovery_kerberos_userlist=self.config.get(
                        "net_discovery_kerberos_userlist"
                    ),
                    windows_verify_enabled=self.config.get("windows_verify_enabled"),
                    windows_verify_max_targets=self.config.get("windows_verify_max_targets"),
                    auditor_name=self.config.get("auditor_name"),
                    lang=self.lang,
                )
                self.print_status(
                    self.t("defaults_saved") if ok else self.t("defaults_save_error"),
                    "OKGREEN" if ok else "WARNING",
                )
            except Exception:
                self.print_status(self.t("defaults_save_error"), "WARNING")
                if self.logger:
                    self.logger.debug("Failed to persist defaults", exc_info=True)

        return self.ask_yes_no(self.t("start_audit"), default="yes")

    def run_complete_scan(self):
        """Execute the complete scan workflow."""
        self.scan_start_time = datetime.now()
        self.start_heartbeat()

        inhibitor = None
        if self.config.get("prevent_sleep", True):
            try:
                from redaudit.core.power import SleepInhibitor

                inhibitor = SleepInhibitor(logger=self.logger)
                inhibitor.start()
            except Exception:
                inhibitor = None

        try:
            # v2.8.1: Create timestamped output folder BEFORE scanning
            # This ensures PCAP files are saved inside the result folder
            ts_folder = self.scan_start_time.strftime("%Y-%m-%d_%H-%M-%S")
            output_base = self.config.get("output_dir", get_default_reports_base_dir())
            self.config["_actual_output_dir"] = os.path.join(output_base, f"RedAudit_{ts_folder}")
            os.makedirs(self.config["_actual_output_dir"], exist_ok=True)
            maybe_chown_to_invoking_user(self.config["_actual_output_dir"])

            # v3.7: Start session logging
            from redaudit.utils.session_log import start_session_log

            start_session_log(self.config["_actual_output_dir"], ts_folder)

            # Ensure network_info is populated for reports and topology discovery.
            if not self.results.get("network_info"):
                try:
                    self.detect_all_networks()
                except Exception:
                    if self.logger:
                        self.logger.debug("Failed to detect local networks", exc_info=True)
                    pass

            # v3.1+: Optional topology discovery (best-effort)
            if self.config.get("topology_enabled") and not self.interrupted:
                try:
                    from redaudit.core.topology import discover_topology

                    self.current_phase = "topology"
                    self.print_status(self.t("topology_start"), "INFO")

                    # v3.2.3: Add spinner progress for topology phase
                    try:
                        from rich.progress import (
                            Progress,
                            SpinnerColumn,
                            TimeElapsedColumn,
                        )

                        with Progress(
                            SpinnerColumn(),
                            self._safe_text_column(
                                "[bold cyan]Topology[/bold cyan] {task.description}",
                                overflow="ellipsis",
                                no_wrap=True,
                            ),
                            TimeElapsedColumn(),
                            console=self._progress_console(),
                            transient=True,
                        ) as progress:
                            task = progress.add_task("discovering...", total=None)
                            self.results["topology"] = discover_topology(
                                target_networks=self.config.get("target_networks", []),
                                network_info=self.results.get("network_info", []),
                                extra_tools=self.extra_tools,
                                logger=self.logger,
                            )
                            progress.update(task, description="complete")
                    except ImportError:
                        self.results["topology"] = discover_topology(
                            target_networks=self.config.get("target_networks", []),
                            network_info=self.results.get("network_info", []),
                            extra_tools=self.extra_tools,
                            logger=self.logger,
                        )
                except Exception as exc:
                    if self.logger:
                        self.logger.warning("Topology discovery failed: %s", exc)
                        self.logger.debug("Topology discovery exception details", exc_info=True)
                    self.results["topology"] = {"enabled": True, "error": str(exc)}

                if self.config.get("topology_only"):
                    self.config["rate_limit_delay"] = self.rate_limit_delay
                    generate_summary(self.results, self.config, [], [], self.scan_start_time)
                    self.save_results(partial=self.interrupted)
                    self.show_results()
                    return True

            # v3.2+: Enhanced network discovery (best-effort)
            # v3.2.1: Auto-enabled in 'completo' mode for complete network visibility
            # v3.2.3: Also auto-enabled when topology is enabled (intelligent discovery)
            net_discovery_auto = self.config.get("scan_mode") == "completo"
            topology_enabled = self.config.get("topology_enabled")
            net_discovery_setting = self.config.get("net_discovery_enabled")
            net_discovery_explicit = net_discovery_setting is True
            net_discovery_disabled = net_discovery_setting is False
            if (
                (not net_discovery_disabled)
                and (net_discovery_explicit or net_discovery_auto or topology_enabled)
            ) and not self.interrupted:
                try:
                    from redaudit.core.net_discovery import discover_networks

                    self.current_phase = "net_discovery"
                    self.print_status(self.t("net_discovery_start"), "INFO")

                    iface = self._select_net_discovery_interface()
                    redteam_options = {
                        "max_targets": self.config.get("net_discovery_max_targets", 50),
                        "snmp_community": self.config.get("net_discovery_snmp_community", "public"),
                        "dns_zone": self.config.get("net_discovery_dns_zone"),
                        "kerberos_realm": self.config.get("net_discovery_kerberos_realm"),
                        "kerberos_userlist": self.config.get("net_discovery_kerberos_userlist"),
                        "active_l2": bool(self.config.get("net_discovery_active_l2", False)),
                    }

                    # v3.2.3: Add spinner progress for net_discovery phase
                    try:
                        from rich.progress import (
                            BarColumn,
                            Progress,
                            SpinnerColumn,
                            TextColumn,
                            TimeElapsedColumn,
                        )

                        with self._progress_ui():
                            with Progress(
                                SpinnerColumn(),
                                self._safe_text_column(
                                    "[bold blue]Net Discovery[/bold blue] {task.description}",
                                    overflow="ellipsis",
                                    no_wrap=True,
                                ),
                                BarColumn(bar_width=20),
                                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                                TimeElapsedColumn(),
                                console=self._progress_console(),
                                transient=True,
                            ) as progress:
                                # v3.8.1: Simplified progress - elapsed only, no ETA
                                task = progress.add_task(
                                    "initializing...",
                                    total=100,
                                )
                                nd_start_time = time.time()
                                last_heartbeat = nd_start_time

                                def _nd_progress(
                                    label: str, step_index: int, step_total: int
                                ) -> None:
                                    nonlocal last_heartbeat
                                    try:
                                        pct = (
                                            int((step_index / step_total) * 100)
                                            if step_total
                                            else 0
                                        )
                                        if step_total and step_index >= step_total:
                                            pct = min(pct, 99)
                                        # v3.8.1: Truncate label to 35 chars for clean display
                                        label_short = label[:35] + "…" if len(label) > 35 else label
                                        progress.update(
                                            task,
                                            completed=pct,
                                            description=f"{label_short}",
                                        )
                                        # v3.8.1: Heartbeat every 30s for long phases
                                        now = time.time()
                                        if now - last_heartbeat >= 30.0:
                                            elapsed = int(now - nd_start_time)
                                            mins, secs = divmod(elapsed, 60)
                                            self.print_status(
                                                f"Net Discovery en progreso... ({mins}:{secs:02d} transcurrido)",
                                                "INFO",
                                                force=True,
                                            )
                                            last_heartbeat = now
                                    except Exception:
                                        pass

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=self.config.get("net_discovery_redteam", False),
                                    redteam_options=redteam_options,
                                    extra_tools=self.extra_tools,
                                    progress_callback=_nd_progress,
                                    logger=self.logger,
                                )
                                progress.update(task, completed=100, description="complete")
                    except ImportError:
                        # Fallback without progress bar
                        with self._progress_ui():
                            with _ActivityIndicator(
                                label="Net Discovery",
                                touch_activity=self._touch_activity,
                            ) as indicator:

                                def _nd_progress(
                                    label: str, step_index: int, step_total: int
                                ) -> None:
                                    indicator.update(f"{label} ({step_index}/{step_total})")

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=self.config.get("net_discovery_redteam", False),
                                    redteam_options=redteam_options,
                                    extra_tools=self.extra_tools,
                                    progress_callback=_nd_progress,
                                    logger=self.logger,
                                )

                    # Log discovered DHCP servers
                    dhcp_servers = self.results["net_discovery"].get("dhcp_servers", [])
                    if dhcp_servers:
                        self.print_status(
                            self.t("net_discovery_dhcp_found", len(dhcp_servers)),
                            "OKGREEN",
                        )
                    candidate_vlans = self.results["net_discovery"].get("candidate_vlans", [])
                    if candidate_vlans:
                        self.print_status(
                            self.t("net_discovery_vlans_found", len(candidate_vlans)),
                            "WARNING",
                        )

                    # v3.2.3: Visible CLI logging for HyperScan results
                    hyperscan_dur = self.results["net_discovery"].get("hyperscan_duration", 0)
                    if hyperscan_dur > 0:
                        arp_hosts = self.results["net_discovery"].get("arp_hosts", [])
                        upnp_devices = self.results["net_discovery"].get("upnp_devices", [])
                        tcp_hosts = self.results["net_discovery"].get("hyperscan_tcp_hosts", {})
                        self.print_status(
                            f"✓ HyperScan: {len(arp_hosts)} ARP, {len(upnp_devices)} IoT/UPNP, {len(tcp_hosts)} TCP hosts ({hyperscan_dur:.1f}s)",
                            "OKGREEN",
                        )
                    backdoors = self.results["net_discovery"].get("potential_backdoors", [])
                    if backdoors:
                        self.print_status(
                            f"⚠️  {len(backdoors)} puertos sospechosos (backdoor) detectados",
                            "WARNING",
                        )
                except Exception as exc:
                    if self.logger:
                        self.logger.warning("Net discovery failed: %s", exc)
                        self.logger.debug("Net discovery exception details", exc_info=True)
                    self.results["net_discovery"] = {"enabled": True, "error": str(exc)}

            discovery_hosts = self._collect_discovery_hosts(
                self.config.get("target_networks", []) or []
            )
            if discovery_hosts:
                self.print_status(
                    self.t("net_discovery_seed_hosts", len(discovery_hosts)),
                    "INFO",
                )

            all_hosts = []
            for network in self.config["target_networks"]:
                if self.interrupted:
                    break
                hosts = self.scan_network_discovery(network)
                all_hosts.extend(hosts)

            if discovery_hosts:
                before = set(all_hosts)
                all_hosts.extend(discovery_hosts)
                added = len(set(all_hosts) - before)
                if added > 0:
                    self.print_status(
                        self.t("net_discovery_seed_added", added),
                        "INFO",
                    )

            if not all_hosts:
                self.print_status(self.t("no_hosts"), "WARNING")
                self.stop_heartbeat()
                return False

            max_val = self.config["max_hosts_value"]
            if max_val != "all" and isinstance(max_val, int):
                all_hosts = all_hosts[:max_val]

            results = self.scan_hosts_concurrent(all_hosts)

            # v3.8: Agentless Windows verification (SMB/RDP/LDAP) - opt-in
            if not self.interrupted:
                self.run_agentless_verification(results)

            # v3.0.1: CVE correlation via NVD (optional; can be slow)
            if self.config.get("cve_lookup_enabled") and not self.interrupted:
                try:
                    from redaudit.core.nvd import enrich_host_with_cves, get_api_key_from_config

                    # Ensure API key is loaded (from CLI, env, or config) without mislabeling the source.
                    if not self.config.get("nvd_api_key"):
                        self.setup_nvd_api_key(non_interactive=True)
                    api_key = self.config.get("nvd_api_key") or get_api_key_from_config()
                    for i, host_record in enumerate(results):
                        if self.interrupted:
                            break
                        results[i] = enrich_host_with_cves(
                            host_record, api_key=api_key, logger=self.logger
                        )
                    self.results["hosts"] = results
                except Exception:
                    # Best-effort: CVE enrichment should never break scans
                    if self.logger:
                        self.logger.debug("CVE enrichment failed (best-effort)", exc_info=True)
                    pass

            if self.config.get("scan_vulnerabilities") and not self.interrupted:
                self.scan_vulnerabilities_concurrent(results)

            # Nuclei template scanning (optional; full mode only, if installed and enabled)
            if (
                self.config.get("scan_vulnerabilities")
                and self.config.get("scan_mode") == "completo"
                and self.config.get("nuclei_enabled", False)
                and is_nuclei_available()
                and not self.interrupted
            ):
                self.print_status(self.t("nuclei_scan_start"), "INFO")
                try:
                    nuclei_targets = get_http_targets_from_hosts(results)
                    if nuclei_targets:
                        output_dir = (
                            self.config.get("_actual_output_dir")
                            or self.config.get("output_dir")
                            or get_default_reports_base_dir()
                        )

                        # Prefer a single Progress instance managed by the auditor to avoid
                        # competing Rich Live displays (which can cause flicker/no output).
                        nuclei_result = None
                        try:
                            from rich.progress import Progress

                            batch_size = 25
                            nuclei_timeout_s = 300
                            total_batches = max(1, int(math.ceil(len(nuclei_targets) / batch_size)))
                            progress_start_t = time.time()
                            with self._progress_ui():
                                with Progress(
                                    *self._progress_columns(
                                        show_detail=True,
                                        show_eta=True,
                                        show_elapsed=False,
                                    ),
                                    console=self._progress_console(),
                                    transient=False,
                                ) as progress:
                                    task = progress.add_task(
                                        f"[cyan]Nuclei (0/{total_batches})",
                                        total=total_batches,
                                        eta_upper=self._format_eta(
                                            total_batches * nuclei_timeout_s
                                        ),
                                        eta_est="",
                                        detail=f"{len(nuclei_targets)} targets",
                                    )

                                    def _nuclei_progress(
                                        completed: int, total: int, eta: str
                                    ) -> None:
                                        try:
                                            remaining = max(0, total - completed)
                                            elapsed_s = max(0.001, time.time() - progress_start_t)
                                            rate = completed / elapsed_s if completed else 0.0
                                            eta_est_val = (
                                                self._format_eta(remaining / rate)
                                                if rate > 0.0 and remaining
                                                else ""
                                            )
                                            progress.update(
                                                task,
                                                completed=completed,
                                                description=f"[cyan]Nuclei ({completed}/{total})",
                                                eta_upper=self._format_eta(
                                                    remaining * nuclei_timeout_s if remaining else 0
                                                ),
                                                eta_est=(
                                                    f"ETA≈ {eta_est_val}" if eta_est_val else ""
                                                ),
                                                detail=f"batch {completed}/{total}",
                                            )
                                        except Exception:
                                            pass

                                    nuclei_result = run_nuclei_scan(
                                        targets=nuclei_targets,
                                        output_dir=output_dir,
                                        severity="medium,high,critical",
                                        timeout=nuclei_timeout_s,
                                        batch_size=batch_size,
                                        progress_callback=_nuclei_progress,
                                        use_internal_progress=False,
                                        logger=self.logger,
                                        dry_run=bool(self.config.get("dry_run", False)),
                                        print_status=self.print_status,
                                    )
                        except Exception:
                            nuclei_result = run_nuclei_scan(
                                targets=nuclei_targets,
                                output_dir=output_dir,
                                severity="medium,high,critical",
                                timeout=300,
                                logger=self.logger,
                                dry_run=bool(self.config.get("dry_run", False)),
                                print_status=self.print_status,
                            )

                        findings = nuclei_result.get("findings") or []
                        nuclei_summary = {
                            "enabled": True,
                            "targets": len(nuclei_targets),
                            "findings": len(findings),
                            "success": bool(nuclei_result.get("success")),
                            "error": nuclei_result.get("error"),
                        }
                        raw_file = nuclei_result.get("raw_output_file")
                        if raw_file and isinstance(raw_file, str):
                            try:
                                nuclei_summary["output_file"] = os.path.relpath(
                                    raw_file, output_dir
                                )
                            except Exception:
                                nuclei_summary["output_file"] = raw_file
                        self.results["nuclei"] = nuclei_summary

                        merged = self._merge_nuclei_findings(findings)
                        if merged > 0:
                            self.print_status(self.t("nuclei_findings", merged), "OK")
                        else:
                            self.print_status(self.t("nuclei_no_findings"), "INFO")
                except Exception as e:
                    if self.logger:
                        self.logger.warning("Nuclei scan failed: %s", e, exc_info=True)
                    self.print_status(f"Nuclei: {e}", "WARNING")

            self.config["rate_limit_delay"] = self.rate_limit_delay
            generate_summary(self.results, self.config, all_hosts, results, self.scan_start_time)
            self.save_results(partial=self.interrupted)
            self.show_results()

        finally:
            # v3.7: Stop session logging
            from redaudit.utils.session_log import stop_session_log

            session_log_path = stop_session_log()
            if session_log_path and self.logger:
                self.logger.info("Session log saved: %s", session_log_path)

            if inhibitor is not None:
                try:
                    inhibitor.stop()
                except Exception:
                    pass
            self.stop_heartbeat()

        return not self.interrupted

    # ---------- Subprocess management (C1 fix) ----------

    def register_subprocess(self, proc: subprocess.Popen) -> None:
        """Register a subprocess for tracking and cleanup on interruption."""
        with self._subprocess_lock:
            self._active_subprocesses.append(proc)

    def unregister_subprocess(self, proc: subprocess.Popen) -> None:
        """Unregister a completed subprocess from tracking."""
        with self._subprocess_lock:
            if proc in self._active_subprocesses:
                self._active_subprocesses.remove(proc)

    def kill_all_subprocesses(self) -> None:
        """Terminate all tracked subprocesses (nmap, tcpdump, etc.)."""
        with self._subprocess_lock:
            for proc in self._active_subprocesses:
                try:
                    if proc.poll() is None:  # Still running
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                except Exception as exc:
                    if self.logger:
                        self.logger.debug("Error killing subprocess: %s", exc, exc_info=True)
            self._active_subprocesses.clear()

    def signal_handler(self, sig, frame):
        """Handle SIGINT (Ctrl+C) with proper cleanup."""
        self.print_status(self.t("interrupted"), "WARNING")
        self.current_phase = "interrupted"
        self.interrupted = True

        # Kill all active subprocesses (nmap, tcpdump, etc.)
        if self._active_subprocesses:
            self.print_status(self.t("terminating_scans"), "WARNING")
            self.kill_all_subprocesses()

        # Stop heartbeat monitoring
        self.stop_heartbeat()

        # v2.8.1: If scan hasn't started yet, exit immediately
        if self.scan_start_time is None:
            sys.exit(0)

    def _apply_run_defaults(self, defaults_for_run: Dict) -> None:
        """Apply persisted defaults to self.config without prompts."""
        # 1. Scan Mode
        self.config["scan_mode"] = defaults_for_run.get("scan_mode", "normal")

        # 2. Max Hosts
        self.config["max_hosts_value"] = "all"

        # 3. Threads
        threads = defaults_for_run.get("threads")
        if isinstance(threads, int) and MIN_THREADS <= threads <= MAX_THREADS:
            self.config["threads"] = threads
        else:
            self.config["threads"] = DEFAULT_THREADS

        # 4. Rate Limit
        rate_limit = defaults_for_run.get("rate_limit")
        if isinstance(rate_limit, (int, float)) and rate_limit > 0:
            self.rate_limit_delay = float(min(max(rate_limit, 0), 60))
        else:
            self.rate_limit_delay = 0.0

        # 5. Vulnerabilities
        self.config["scan_vulnerabilities"] = defaults_for_run.get("scan_vulnerabilities", True)
        self.config["nuclei_enabled"] = bool(defaults_for_run.get("nuclei_enabled", False))
        self.config["cve_lookup_enabled"] = defaults_for_run.get("cve_lookup_enabled", False)

        # 6. Output Dir
        out_dir = defaults_for_run.get("output_dir")
        if isinstance(out_dir, str) and out_dir.strip():
            self.config["output_dir"] = expand_user_path(out_dir.strip())
        else:
            self.config["output_dir"] = get_default_reports_base_dir()

        self.config["save_txt_report"] = defaults_for_run.get("generate_txt", True)
        self.config["save_html_report"] = defaults_for_run.get("generate_html", True)
        self.config["auditor_name"] = defaults_for_run.get("auditor_name")

        # 7. UDP Configuration
        self.config["udp_mode"] = defaults_for_run.get("udp_mode", UDP_SCAN_MODE_QUICK)
        self.config["udp_top_ports"] = defaults_for_run.get("udp_top_ports", UDP_TOP_PORTS)

        # 8. Topology
        self.config["topology_enabled"] = defaults_for_run.get("topology_enabled", False)
        self.config["topology_only"] = defaults_for_run.get("topology_only", False)

        # 9. Net discovery / Red team (wizard)
        self.config["net_discovery_enabled"] = bool(
            defaults_for_run.get("net_discovery_enabled", False)
        )
        self.config["net_discovery_redteam"] = bool(
            defaults_for_run.get("net_discovery_redteam", False)
        )
        self.config["net_discovery_active_l2"] = bool(
            defaults_for_run.get("net_discovery_active_l2", False)
        )
        self.config["net_discovery_kerberos_userenum"] = bool(
            defaults_for_run.get("net_discovery_kerberos_userenum", False)
        )
        self.config["net_discovery_kerberos_realm"] = defaults_for_run.get(
            "net_discovery_kerberos_realm"
        )
        userlist = defaults_for_run.get("net_discovery_kerberos_userlist")
        self.config["net_discovery_kerberos_userlist"] = (
            expand_user_path(userlist) if userlist else None
        )

        # 10. Agentless Windows verification
        self.config["windows_verify_enabled"] = bool(
            defaults_for_run.get("windows_verify_enabled", False)
        )
        max_targets = defaults_for_run.get("windows_verify_max_targets")
        if isinstance(max_targets, int) and 1 <= max_targets <= 200:
            self.config["windows_verify_max_targets"] = max_targets
        else:
            self.config["windows_verify_max_targets"] = 20

    def _configure_scan_interactive(self, defaults_for_run: Dict) -> None:
        """
        v3.8.1: Interactive prompt sequence with step-by-step navigation.

        Uses a state machine pattern allowing users to go back to previous steps
        without restarting the entire wizard.
        """
        # v3.8.1: Wizard step machine for "< Volver" / "< Go Back" navigation
        TOTAL_STEPS = 8
        step = 1

        # Store choices for navigation (allows going back and reusing previous values)
        wizard_state: Dict = {}

        while step <= TOTAL_STEPS:
            # ═══════════════════════════════════════════════════════════════════
            # STEP 1: Scan Mode
            # ═══════════════════════════════════════════════════════════════════
            if step == 1:
                scan_modes = [
                    self.t("mode_fast"),
                    self.t("mode_normal"),
                    self.t("mode_full"),
                ]
                modes_map = {0: "rapido", 1: "normal", 2: "completo"}
                persisted = defaults_for_run.get("scan_mode")
                default_idx = wizard_state.get(
                    "scan_mode_idx", {"rapido": 0, "normal": 1, "completo": 2}.get(persisted, 1)
                )

                choice = self.ask_choice_with_back(
                    self.t("scan_mode"),
                    scan_modes,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    continue  # Can't go back from step 1

                wizard_state["scan_mode_idx"] = choice
                self.config["scan_mode"] = modes_map[choice]

                # Set max_hosts based on mode
                if self.config["scan_mode"] != "rapido":
                    limit = self.ask_number(self.t("ask_num_limit"), default="all")
                    self.config["max_hosts_value"] = limit
                else:
                    self.config["max_hosts_value"] = "all"

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 2: Threads & Rate Limiting
            # ═══════════════════════════════════════════════════════════════════
            elif step == 2:
                # Show step header for UX
                self.print_status(f"[{step}/{TOTAL_STEPS}] " + self.t("threads"), "INFO")

                default_threads = wizard_state.get(
                    "threads",
                    (
                        defaults_for_run.get("threads")
                        if isinstance(defaults_for_run.get("threads"), int)
                        and MIN_THREADS <= defaults_for_run.get("threads") <= MAX_THREADS
                        else DEFAULT_THREADS
                    ),
                )
                self.config["threads"] = self.ask_number(
                    self.t("threads"),
                    default=default_threads,
                    min_val=MIN_THREADS,
                    max_val=MAX_THREADS,
                )
                wizard_state["threads"] = self.config["threads"]

                # Rate limiting
                default_rate = defaults_for_run.get("rate_limit")
                if not isinstance(default_rate, (int, float)) or default_rate < 0:
                    default_rate = 0.0
                if self.ask_yes_no(
                    self.t("rate_limiting"), default="yes" if default_rate > 0 else "no"
                ):
                    delay_default = int(default_rate) if default_rate > 0 else 1
                    delay_default = min(max(delay_default, 0), 60)
                    self.rate_limit_delay = float(
                        self.ask_number(
                            self.t("rate_delay"), default=delay_default, min_val=0, max_val=60
                        )
                    )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 3: Vulnerability Scanning
            # ═══════════════════════════════════════════════════════════════════
            elif step == 3:
                vuln_options = [
                    self.t("yes_option") + " — " + self.t("vuln_scan_opt"),
                    self.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("scan_vulnerabilities") is not False else 1
                default_idx = wizard_state.get("vuln_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.t("vuln_scan_q"),
                    vuln_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["vuln_idx"] = choice
                self.config["scan_vulnerabilities"] = choice == 0

                # Nuclei (conditional)
                self.config["nuclei_enabled"] = False
                if (
                    self.config.get("scan_vulnerabilities")
                    and self.config.get("scan_mode") == "completo"
                    and is_nuclei_available()
                ):
                    self.config["nuclei_enabled"] = self.ask_yes_no(
                        self.t("nuclei_q"),
                        default="yes" if defaults_for_run.get("nuclei_enabled") else "no",
                    )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 4: CVE Correlation
            # ═══════════════════════════════════════════════════════════════════
            elif step == 4:
                cve_options = [
                    self.t("yes_option") + " — NVD API",
                    self.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("cve_lookup_enabled") else 1
                default_idx = wizard_state.get("cve_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.t("cve_lookup_q"),
                    cve_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["cve_idx"] = choice
                if choice == 0:
                    self.config["cve_lookup_enabled"] = True
                    self.setup_nvd_api_key()
                else:
                    self.config["cve_lookup_enabled"] = False

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 5: Output Directory
            # ═══════════════════════════════════════════════════════════════════
            elif step == 5:
                self.print_status(f"[{step}/{TOTAL_STEPS}] " + self.t("output_dir"), "INFO")

                auditor_default = wizard_state.get(
                    "auditor_name",
                    (
                        defaults_for_run.get("auditor_name")
                        if isinstance(defaults_for_run, dict)
                        else ""
                    ),
                )
                auditor_default = auditor_default or ""
                auditor_prompt = self.t("auditor_name_q")
                auditor_name = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {auditor_prompt} "
                    f"[{auditor_default}]: "
                ).strip()
                if not auditor_name:
                    auditor_name = auditor_default
                auditor_name = auditor_name.strip()
                self.config["auditor_name"] = auditor_name if auditor_name else None
                wizard_state["auditor_name"] = self.config["auditor_name"] or ""

                default_reports = get_default_reports_base_dir()
                persisted_output = defaults_for_run.get("output_dir")
                if isinstance(persisted_output, str) and persisted_output.strip():
                    default_reports = expand_user_path(persisted_output.strip())

                out_dir = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('output_dir')} "
                    f"[{default_reports}]: "
                ).strip()
                if not out_dir:
                    out_dir = default_reports
                self.config["output_dir"] = expand_user_path(out_dir)

                # TXT and HTML always on
                self.config["save_txt_report"] = True
                self.config["save_html_report"] = True

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 6: UDP & Topology
            # ═══════════════════════════════════════════════════════════════════
            elif step == 6:
                # UDP configuration (only for non-rapido modes with deep scan)
                if self.config["scan_mode"] != "rapido" and self.config.get("deep_id_scan"):
                    udp_modes = [self.t("udp_mode_quick"), self.t("udp_mode_full")]
                    udp_map = {0: UDP_SCAN_MODE_QUICK, 1: UDP_SCAN_MODE_FULL}
                    persisted_udp = defaults_for_run.get("udp_mode")
                    default_idx = wizard_state.get(
                        "udp_idx", 1 if persisted_udp == UDP_SCAN_MODE_FULL else 0
                    )

                    choice = self.ask_choice_with_back(
                        self.t("udp_mode_q"),
                        udp_modes,
                        default_idx,
                        step_num=step,
                        total_steps=TOTAL_STEPS,
                    )
                    if choice == self.WIZARD_BACK:
                        step -= 1
                        continue

                    wizard_state["udp_idx"] = choice
                    self.config["udp_mode"] = udp_map[choice]

                    # UDP ports profile
                    persisted_ports = defaults_for_run.get("udp_top_ports")
                    udp_ports_default = min(
                        max(
                            persisted_ports if isinstance(persisted_ports, int) else UDP_TOP_PORTS,
                            50,
                        ),
                        500,
                    )
                    self.config["udp_top_ports"] = udp_ports_default

                    if self.config["udp_mode"] == UDP_SCAN_MODE_FULL:
                        udp_profiles = [
                            (50, self.t("udp_ports_profile_fast")),
                            (100, self.t("udp_ports_profile_balanced")),
                            (200, self.t("udp_ports_profile_thorough")),
                            (500, self.t("udp_ports_profile_aggressive")),
                            ("custom", self.t("udp_ports_profile_custom")),
                        ]
                        options = [label for _, label in udp_profiles]
                        profile_default = next(
                            (i for i, (v, _) in enumerate(udp_profiles) if v == udp_ports_default),
                            len(udp_profiles) - 1,
                        )
                        selected_idx = self.ask_choice(
                            self.t("udp_ports_profile_q"), options, profile_default
                        )
                        selected = udp_profiles[selected_idx][0]
                        if selected == "custom":
                            self.config["udp_top_ports"] = self.ask_number(
                                self.t("udp_ports_q"),
                                default=udp_ports_default,
                                min_val=50,
                                max_val=500,
                            )
                        else:
                            self.config["udp_top_ports"] = selected

                # Topology discovery
                topo_options = [
                    self.t("topology_disabled"),
                    self.t("topology_enabled_scan"),
                    self.t("topology_only_mode"),
                ]
                persisted_topo = defaults_for_run.get("topology_enabled")
                persisted_only = defaults_for_run.get("topology_only")
                default_idx = 2 if persisted_only else (1 if persisted_topo else 0)
                default_idx = wizard_state.get("topo_idx", default_idx)

                topo_choice = self.ask_choice_with_back(
                    self.t("topology_discovery_q"),
                    topo_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if topo_choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["topo_idx"] = topo_choice
                self.config["topology_enabled"] = topo_choice != 0
                self.config["topology_only"] = topo_choice == 2

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 7: Net Discovery & Red Team
            # ═══════════════════════════════════════════════════════════════════
            elif step == 7:
                nd_options = [
                    self.t("yes_option") + " — DHCP/NetBIOS/mDNS/UPNP",
                    self.t("no_option"),
                ]
                persisted_nd = defaults_for_run.get("net_discovery_enabled")
                nd_default = (
                    bool(persisted_nd)
                    if isinstance(persisted_nd, bool)
                    else bool(
                        self.config.get("topology_enabled")
                        or self.config.get("scan_mode") == "completo"
                    )
                )
                default_idx = 0 if nd_default else 1
                default_idx = wizard_state.get("nd_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.t("net_discovery_q"),
                    nd_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["nd_idx"] = choice
                enable_net_discovery = choice == 0
                self.config["net_discovery_enabled"] = enable_net_discovery

                if enable_net_discovery:
                    # Red Team options
                    rt_options = [self.t("redteam_mode_a"), self.t("redteam_mode_b")]
                    rt_default = 1 if defaults_for_run.get("net_discovery_redteam") else 0
                    redteam_choice = self.ask_choice(
                        self.t("redteam_mode_q"), rt_options, rt_default
                    )

                    wants_redteam = redteam_choice == 1
                    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
                    if wants_redteam and not is_root:
                        self.print_status(self.t("redteam_requires_root"), "WARNING")
                        wants_redteam = False

                    self.config["net_discovery_redteam"] = bool(wants_redteam)
                    self.config["net_discovery_active_l2"] = False
                    self.config["net_discovery_kerberos_userenum"] = False
                    self.config["net_discovery_kerberos_realm"] = None
                    self.config["net_discovery_kerberos_userlist"] = None

                    if self.config["net_discovery_redteam"]:
                        # L2 Active probing
                        persisted_l2 = defaults_for_run.get("net_discovery_active_l2")
                        self.config["net_discovery_active_l2"] = self.ask_yes_no(
                            self.t("redteam_active_l2_q"), default="yes" if persisted_l2 else "no"
                        )

                        # Kerberos enumeration
                        persisted_krb = defaults_for_run.get("net_discovery_kerberos_userenum")
                        enable_kerberos = self.ask_yes_no(
                            self.t("redteam_kerberos_userenum_q"),
                            default="yes" if persisted_krb else "no",
                        )
                        self.config["net_discovery_kerberos_userenum"] = enable_kerberos

                        if enable_kerberos:
                            persisted_realm = (
                                defaults_for_run.get("net_discovery_kerberos_realm") or ""
                            )
                            realm = input(
                                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('kerberos_realm_q')} "
                                f"[{persisted_realm}]: "
                            ).strip()
                            self.config["net_discovery_kerberos_realm"] = (
                                realm or persisted_realm or None
                            )

                            persisted_userlist = (
                                defaults_for_run.get("net_discovery_kerberos_userlist") or ""
                            )
                            userlist = input(
                                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('kerberos_userlist_q')} "
                                f"[{persisted_userlist}]: "
                            ).strip()
                            self.config["net_discovery_kerberos_userlist"] = (
                                expand_user_path(userlist)
                                if userlist
                                else (
                                    expand_user_path(persisted_userlist)
                                    if persisted_userlist
                                    else None
                                )
                            )

                        # Advanced Net Discovery options
                        nd_settings = self.ask_net_discovery_options()
                        self.config["net_discovery_snmp_community"] = nd_settings.get(
                            "snmp_community", "public"
                        )
                        self.config["net_discovery_dns_zone"] = nd_settings.get("dns_zone", "")
                        self.config["net_discovery_max_targets"] = nd_settings.get(
                            "redteam_max_targets", 50
                        )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 8: Windows Verification & Webhook
            # ═══════════════════════════════════════════════════════════════════
            elif step == 8:
                win_options = [
                    self.t("yes_option") + " — SMB/RDP/LDAP/SSH/HTTP",
                    self.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("windows_verify_enabled") else 1
                default_idx = wizard_state.get("win_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.t("windows_verify_q"),
                    win_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["win_idx"] = choice
                if choice == 0:
                    self.config["windows_verify_enabled"] = True
                    persisted_max = defaults_for_run.get("windows_verify_max_targets")
                    max_default = (
                        persisted_max
                        if isinstance(persisted_max, int) and 1 <= persisted_max <= 200
                        else 20
                    )
                    self.config["windows_verify_max_targets"] = self.ask_number(
                        self.t("windows_verify_max_q"), default=max_default, min_val=1, max_val=200
                    )
                else:
                    self.config["windows_verify_enabled"] = False

                # Webhook configuration
                webhook_url = self.ask_webhook_url()
                if webhook_url:
                    self.config["webhook_url"] = webhook_url

                step += 1
                continue

        # Final step: Encryption setup
        self.setup_encryption()

    def _show_defaults_summary(self, persisted_defaults: Dict) -> None:
        """Display summary of persisted defaults."""
        # v3.2.3: Display ALL saved defaults
        self.print_status(self.t("defaults_summary_title"), "INFO")

        def fmt_targets(val):
            if not isinstance(val, list) or not val:
                return "-"
            cleaned = [t.strip() for t in val if isinstance(t, str) and t.strip()]
            return ", ".join(cleaned) if cleaned else "-"

        # Helper to format boolean values
        def fmt_bool(val):
            if val is None:
                return "-"
            return self.t("enabled") if val else self.t("disabled")

        # Display all saved defaults
        fields = [
            ("defaults_summary_targets", fmt_targets(persisted_defaults.get("target_networks"))),
            ("defaults_summary_scan_mode", persisted_defaults.get("scan_mode")),
            ("defaults_summary_threads", persisted_defaults.get("threads")),
            ("defaults_summary_output", persisted_defaults.get("output_dir")),
            ("defaults_summary_rate_limit", persisted_defaults.get("rate_limit")),
            ("defaults_summary_udp_mode", persisted_defaults.get("udp_mode")),
            ("defaults_summary_udp_ports", persisted_defaults.get("udp_top_ports")),
            (
                "defaults_summary_topology",
                fmt_bool(persisted_defaults.get("topology_enabled")),
            ),
            (
                "defaults_summary_net_discovery",
                fmt_bool(persisted_defaults.get("net_discovery_enabled")),
            ),
            (
                "defaults_summary_redteam",
                fmt_bool(persisted_defaults.get("net_discovery_redteam")),
            ),
            (
                "defaults_summary_active_l2",
                fmt_bool(persisted_defaults.get("net_discovery_active_l2")),
            ),
            (
                "defaults_summary_kerbrute",
                fmt_bool(persisted_defaults.get("net_discovery_kerberos_userenum")),
            ),
            (
                "defaults_summary_web_vulns",
                fmt_bool(persisted_defaults.get("scan_vulnerabilities")),
            ),
            (
                "defaults_summary_nuclei",
                fmt_bool(persisted_defaults.get("nuclei_enabled")),
            ),
            (
                "defaults_summary_cve_lookup",
                fmt_bool(persisted_defaults.get("cve_lookup_enabled")),
            ),
            (
                "defaults_summary_txt_report",
                fmt_bool(persisted_defaults.get("generate_txt")),
            ),
            (
                "defaults_summary_html_report",
                fmt_bool(persisted_defaults.get("generate_html")),
            ),
            (
                "defaults_summary_windows_verify",
                fmt_bool(persisted_defaults.get("windows_verify_enabled")),
            ),
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.print_status(f"- {self.t(key)}: {display_val}", "INFO")
