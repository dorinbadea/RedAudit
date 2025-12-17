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
import threading
import time
import random
import importlib
import ipaddress
import logging
import base64
import textwrap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional

from redaudit.utils.constants import (
    VERSION,
    DEFAULT_LANG,
    MAX_CIDR_LENGTH,
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


class InteractiveNetworkAuditor:
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

    def print_status(self, message, status="INFO", update_activity=True):
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

        color = self.COLORS.get(status, self.COLORS["OKBLUE"]) if is_tty else ""
        endc = self.COLORS["ENDC"] if is_tty else ""

        # Wrap long messages on word boundaries to avoid splitting words mid-line.
        msg = "" if message is None else str(message)
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
        with self._print_lock:
            print(
                f"{color}[{ts}] [{status_display}]{endc} {lines[0]}"
            )  # lgtm[py/clear-text-logging-sensitive-data]
            for line in lines[1:]:
                print(f"  {line}")  # lgtm[py/clear-text-logging-sensitive-data]
            sys.stdout.flush()

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

        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

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

    # ---------- Input utilities ----------

    def ask_yes_no(self, question, default="yes"):
        """Ask a yes/no question."""
        default = default.lower()
        opts = (
            self.t("ask_yes_no_opts")
            if default in ("yes", "y", "s", "si", "sí")
            else self.t("ask_yes_no_opts_neg")
        )
        valid = {
            "yes": True,
            "y": True,
            "s": True,
            "si": True,
            "sí": True,
            "no": False,
            "n": False,
        }
        while True:
            try:
                print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
                ans = (
                    input(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}{opts}: ")
                    .strip()
                    .lower()
                )
                if ans == "":
                    return valid.get(default, True)
                if ans in valid:
                    return valid[ans]
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_number(self, question, default=10, min_val=1, max_val=1000):
        """Ask for a number within a range."""
        default_return = default
        default_display = default
        if isinstance(default, str) and default.lower() in ("all", "todos", "todo"):
            default_return = "all"
            default_display = "todos" if self.lang == "es" else "all"
        while True:
            try:
                print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
                ans = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question} [{default_display}]: "
                ).strip()
                if ans == "":
                    return default_return
                if ans.lower() in ("todos", "todo", "all"):
                    return "all"
                try:
                    num = int(ans)
                    if min_val <= num <= max_val:
                        return num
                    self.print_status(self.t("val_out_of_range", min_val, max_val), "WARNING")
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_choice(self, question, options, default=0):
        """Ask to choose from a list of options."""
        print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            # Use an ASCII marker for maximum terminal compatibility.
            marker = f"{self.COLORS['BOLD']}>{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i + 1}. {opt}")
        while True:
            try:
                ans = input(
                    f"\n{self.t('select_opt')} [1-{len(options)}] ({default + 1}): "
                ).strip()
                if ans == "":
                    return default
                try:
                    idx = int(ans) - 1
                    if 0 <= idx < len(options):
                        return idx
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_manual_network(self):
        """Ask for manual network CIDR input."""
        while True:
            try:
                net = input(
                    f"\n{self.COLORS['CYAN']}?{self.COLORS['ENDC']} CIDR (e.g. 192.168.1.0/24): "
                ).strip()
                if len(net) > MAX_CIDR_LENGTH:
                    self.print_status(self.t("invalid_cidr"), "WARNING")
                    continue
                try:
                    ipaddress.ip_network(net, strict=False)
                    return net
                except ValueError:
                    self.print_status(self.t("invalid_cidr"), "WARNING")
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    # ---------- Network detection ----------

    def detect_all_networks(self):
        """Detect all local networks."""
        self.print_status(self.t("analyzing_nets"), "INFO")
        nets = detect_all_networks(self.lang, self.print_status)
        self.results["network_info"] = nets
        return nets

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
                (rec1.get("stdout", "") or "") + "\n" + (rec1.get("stderr", "") or "")
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
                            (rec2b.get("stdout", "") or "") + "\n" + (rec2b.get("stderr", "") or "")
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
        self.logger.info("Discovery on %s", network)
        args = get_nmap_arguments("rapido")
        self.print_status(self.t("nmap_cmd", network, f"nmap {args} {network}"), "INFO")
        if is_dry_run(self.config.get("dry_run")):
            return []
        nm = nmap.PortScanner()
        try:
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
        nm = nmap.PortScanner()

        try:
            nm.scan(safe_ip, arguments=args)
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

            # Heuristics for deep identity scan
            trigger_deep = False
            deep_enabled = self.config.get("deep_id_scan", True)
            # In full scan mode we already run aggressive nmap; avoid redundant deep scans.
            allow_deep_heuristic = self.config.get("scan_mode") != "completo"
            if deep_enabled and allow_deep_heuristic:
                if total_ports > 8:
                    trigger_deep = True
                if suspicious:
                    trigger_deep = True
                # Skip deep scan for completely quiet hosts (0 open ports); it tends to add a lot of time
                # and usually yields little beyond MAC/vendor (which we already capture when available).
                if 0 < total_ports <= 3:
                    trigger_deep = True
                if total_ports > 0 and not any_version:
                    trigger_deep = True

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

            enrich_host_with_dns(host_record, self.extra_tools)
            enrich_host_with_whois(host_record, self.extra_tools)

            # v2.8.0: Finalize status based on all collected data
            host_record["status"] = finalize_host_status(host_record)

            return host_record

        except Exception as exc:
            self.logger.error("Scan error %s: %s", safe_ip, exc, exc_info=True)
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

        # Try to use rich for better progress visualization
        try:
            from rich.progress import (
                Progress,
                SpinnerColumn,
                BarColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )
            from rich.console import Console

            use_rich = True
        except ImportError:
            use_rich = False

        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
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
                # Rich progress bar
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=Console(stderr=True),
                ) as progress:
                    task = progress.add_task(f"[cyan]{self.t('scanning_hosts')}", total=total)
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
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]{self.t('scanned_host', host_ip)}",
                        )
            else:
                # Fallback to basic progress
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
                        self.logger.debug("Worker exception details for %s", host_ip, exc_info=True)
                    done += 1
                    if total and done % max(1, total // 10) == 0:
                        self.print_status(
                            self.t("progress", done, total), "INFO", update_activity=False
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
            scheme = "https" if "ssl" in p["service"].lower() or port == 443 else "http"
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

        self.current_phase = "vulns"
        self.print_status(self.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])

        # Try to use rich for progress visualization
        try:
            from rich.progress import (
                Progress,
                SpinnerColumn,
                BarColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )
            from rich.console import Console

            use_rich = True
        except ImportError:
            use_rich = False

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.scan_vulnerabilities_web, h): h["ip"] for h in web_hosts
            }

            total = len(futures)
            done = 0

            if use_rich and total > 0:
                # Rich progress bar for vulnerability scanning
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=Console(stderr=True),
                ) as progress:
                    task = progress.add_task(f"[cyan]Vuln scan ({total_ports} ports)", total=total)
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
                                vuln_count = len(res.get("vulnerabilities", []))
                                if vuln_count > 0:
                                    # Avoid noisy per-host warnings; progress + final summary is enough.
                                    if self.logger:
                                        self.logger.info(
                                            "Vulnerabilities recorded on %s", res["host"]
                                        )
                        except Exception as exc:
                            self.logger.error("Vuln worker error for %s: %s", host_ip, exc)
                            self.logger.debug(
                                "Vuln worker exception details for %s", host_ip, exc_info=True
                            )
                        done += 1
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]{self.t('scanned_host', host_ip)}",
                        )
            else:
                # Fallback without rich
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
                            self.print_status(self.t("vulns_found", res["host"]), "WARNING")
                    except Exception as exc:
                        self.print_status(self.t("worker_error", exc), "WARNING")
                        if self.logger:
                            self.logger.debug(
                                "Vuln worker exception details for %s", host_ip, exc_info=True
                            )
                    done += 1

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

    # ---------- Interactive flow ----------

    def clear_screen(self):
        """Clear the terminal screen."""
        if is_dry_run(self.config.get("dry_run")):
            return
        os.system("clear" if os.name == "posix" else "cls")

    def print_banner(self):
        """Print the RedAudit banner."""
        subtitle = self.t("banner_subtitle")
        banner = f"""
{self.COLORS['FAIL']}
 ____          _    {self.COLORS['BOLD']}{self.COLORS['HEADER']}_             _ _ _{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|  _ \\ ___  __| |  {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ \\  _   _  __| (_) |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
| |_) / _ \\/ _` | {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ _ \\| | | |/ _` | | __|{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|  _ <  __/ (_| |{self.COLORS['BOLD']}{self.COLORS['HEADER']}/ ___ \\ |_| | (_| | | |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|_| \\_\\___|\\__,_|{self.COLORS['BOLD']}{self.COLORS['HEADER']}/_/   \\_\\__,_|\\__,_|_|\\__|{self.COLORS['ENDC']}
                                     {self.COLORS['CYAN']}v{VERSION}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
{self.COLORS['BOLD']}{subtitle}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
"""
        print(banner)

    def show_main_menu(self):
        """
        Display main menu and return user choice.

        Returns:
            int: 0=exit, 1=scan, 2=update, 3=diff
        """
        print(f"\n{self.COLORS['HEADER']}RedAudit v{VERSION}{self.COLORS['ENDC']}")
        print("─" * 60)
        print(f"  {self.COLORS['CYAN']}1){self.COLORS['ENDC']} {self.t('menu_option_scan')}")
        print(f"  {self.COLORS['CYAN']}2){self.COLORS['ENDC']} {self.t('menu_option_update')}")
        print(f"  {self.COLORS['CYAN']}3){self.COLORS['ENDC']} {self.t('menu_option_diff')}")
        print(f"  {self.COLORS['CYAN']}0){self.COLORS['ENDC']} {self.t('menu_option_exit')}")
        print("─" * 60)

        while True:
            try:
                ans = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('menu_prompt')} "
                ).strip()
                if ans in ("0", "1", "2", "3"):
                    return int(ans)
                self.print_status(self.t("menu_invalid_option"), "WARNING")
            except KeyboardInterrupt:
                print("")
                return 0

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
                    if self.ask_yes_no(self.t("defaults_show_summary_q"), default="no"):
                        self._show_defaults_summary(persisted_defaults)

                    if self.ask_yes_no(self.t("defaults_use_immediately_q"), default="yes"):
                        should_skip_config = True
                        auto_start = True

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
                    cve_lookup_enabled=self.config.get("cve_lookup_enabled"),
                    generate_txt=self.config.get("save_txt_report"),
                    generate_html=self.config.get("save_html_report"),
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
                            TextColumn,
                            TimeElapsedColumn,
                        )
                        from rich.console import Console

                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[bold cyan]Topology[/bold cyan] {task.description}"),
                            TimeElapsedColumn(),
                            console=Console(stderr=True),
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
                            Progress,
                            SpinnerColumn,
                            TextColumn,
                            TimeElapsedColumn,
                        )
                        from rich.console import Console

                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[bold blue]Net Discovery[/bold blue] {task.description}"),
                            TimeElapsedColumn(),
                            console=Console(stderr=True),
                            transient=True,
                        ) as progress:
                            task = progress.add_task("running...", total=None)
                            self.results["net_discovery"] = discover_networks(
                                target_networks=self.config.get("target_networks", []),
                                interface=iface,
                                protocols=self.config.get("net_discovery_protocols"),
                                redteam=self.config.get("net_discovery_redteam", False),
                                redteam_options=redteam_options,
                                extra_tools=self.extra_tools,
                                logger=self.logger,
                            )
                            progress.update(task, description="complete")
                    except ImportError:
                        # Fallback without progress bar
                        self.results["net_discovery"] = discover_networks(
                            target_networks=self.config.get("target_networks", []),
                            interface=iface,
                            protocols=self.config.get("net_discovery_protocols"),
                            redteam=self.config.get("net_discovery_redteam", False),
                            redteam_options=redteam_options,
                            extra_tools=self.extra_tools,
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

            all_hosts = []
            for network in self.config["target_networks"]:
                if self.interrupted:
                    break
                hosts = self.scan_network_discovery(network)
                all_hosts.extend(hosts)

            if not all_hosts:
                self.print_status(self.t("no_hosts"), "WARNING")
                self.stop_heartbeat()
                return False

            max_val = self.config["max_hosts_value"]
            if max_val != "all" and isinstance(max_val, int):
                all_hosts = all_hosts[:max_val]

            results = self.scan_hosts_concurrent(all_hosts)

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

            generate_summary(self.results, self.config, all_hosts, results, self.scan_start_time)
            self.save_results(partial=self.interrupted)
            self.show_results()

        finally:
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
        self.config["cve_lookup_enabled"] = defaults_for_run.get("cve_lookup_enabled", False)

        # 6. Output Dir
        out_dir = defaults_for_run.get("output_dir")
        if isinstance(out_dir, str) and out_dir.strip():
            self.config["output_dir"] = expand_user_path(out_dir.strip())
        else:
            self.config["output_dir"] = get_default_reports_base_dir()

        self.config["save_txt_report"] = defaults_for_run.get("generate_txt", True)
        self.config["save_html_report"] = defaults_for_run.get("generate_html", True)

        # 7. UDP Configuration
        self.config["udp_mode"] = defaults_for_run.get("udp_mode", UDP_SCAN_MODE_QUICK)
        self.config["udp_top_ports"] = defaults_for_run.get("udp_top_ports", UDP_TOP_PORTS)

        # 8. Topology
        self.config["topology_enabled"] = defaults_for_run.get("topology_enabled", False)
        self.config["topology_only"] = defaults_for_run.get("topology_only", False)

    def _configure_scan_interactive(self, defaults_for_run: Dict) -> None:
        """Interactive prompt sequence for scan configuration."""
        scan_modes = [
            self.t("mode_fast"),
            self.t("mode_normal"),
            self.t("mode_full"),
        ]
        modes_map = {0: "rapido", 1: "normal", 2: "completo"}
        self.config["scan_mode"] = modes_map[self.ask_choice(self.t("scan_mode"), scan_modes, 1)]

        if self.config["scan_mode"] != "rapido":
            limit = self.ask_number(self.t("ask_num_limit"), default="all")
            self.config["max_hosts_value"] = limit
        else:
            self.config["max_hosts_value"] = "all"

        self.config["threads"] = self.ask_number(
            self.t("threads"),
            default=(
                defaults_for_run.get("threads")
                if isinstance(defaults_for_run.get("threads"), int)
                and MIN_THREADS <= defaults_for_run.get("threads") <= MAX_THREADS
                else DEFAULT_THREADS
            ),
            min_val=MIN_THREADS,
            max_val=MAX_THREADS,
        )

        default_rate = defaults_for_run.get("rate_limit")
        if not isinstance(default_rate, (int, float)) or default_rate < 0:
            default_rate = 0.0
        if self.ask_yes_no(self.t("rate_limiting"), default="yes" if default_rate > 0 else "no"):
            delay_default = int(default_rate) if default_rate > 0 else 1
            delay_default = min(max(delay_default, 0), 60)
            delay = self.ask_number(
                self.t("rate_delay"), default=delay_default, min_val=0, max_val=60
            )
            self.rate_limit_delay = float(delay)

        self.config["scan_vulnerabilities"] = self.ask_yes_no(self.t("vuln_scan_q"), default="yes")

        # v3.0.1: Ask about CVE correlation
        if self.ask_yes_no(self.t("cve_lookup_q"), default="no"):
            self.config["cve_lookup_enabled"] = True
            # Trigger API key setup if not configured
            self.setup_nvd_api_key()
        else:
            self.config["cve_lookup_enabled"] = False

        default_reports = get_default_reports_base_dir()
        persisted_output = defaults_for_run.get("output_dir")
        if isinstance(persisted_output, str) and persisted_output.strip():
            default_reports = expand_user_path(persisted_output.strip())
        out_dir = input(
            f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('output_dir')} [{default_reports}]: "
        ).strip()
        if not out_dir:
            out_dir = default_reports
        self.config["output_dir"] = expand_user_path(out_dir)

        # v3.3.1: TXT and HTML reports are always generated (no prompt)
        self.config["save_txt_report"] = True
        self.config["save_html_report"] = True

        # v3.1+: UDP coverage configuration (affects adaptive deep scan)
        if self.config["scan_mode"] != "rapido" and self.config.get("deep_id_scan"):
            udp_modes = [self.t("udp_mode_quick"), self.t("udp_mode_full")]
            udp_map = {0: UDP_SCAN_MODE_QUICK, 1: UDP_SCAN_MODE_FULL}

            persisted_udp_mode = defaults_for_run.get("udp_mode")
            udp_default_idx = 0 if persisted_udp_mode != UDP_SCAN_MODE_FULL else 1
            self.config["udp_mode"] = udp_map[
                self.ask_choice(self.t("udp_mode_q"), udp_modes, udp_default_idx)
            ]

            persisted_udp_ports = defaults_for_run.get("udp_top_ports")
            udp_ports_default = (
                persisted_udp_ports if isinstance(persisted_udp_ports, int) else UDP_TOP_PORTS
            )
            udp_ports_default = min(max(udp_ports_default, 50), 500)
            # Store a sensible default even if UDP mode is QUICK (value is used only in FULL mode).
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
                default_idx = next(
                    (
                        idx
                        for idx, (value, _) in enumerate(udp_profiles)
                        if value == udp_ports_default
                    ),
                    len(udp_profiles) - 1,
                )
                selected_idx = self.ask_choice(self.t("udp_ports_profile_q"), options, default_idx)
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

        # v3.1+: Optional topology discovery (simplified v3.2.2+)
        topo_options = [
            self.t("topology_disabled"),
            self.t("topology_enabled_scan"),
            self.t("topology_only_mode"),
        ]
        # Determine default based on persisted values
        persisted_topo = defaults_for_run.get("topology_enabled")
        persisted_only = defaults_for_run.get("topology_only")
        if persisted_only:
            topo_default_idx = 2
        elif persisted_topo:
            topo_default_idx = 1
        else:
            topo_default_idx = 0

        topo_choice = self.ask_choice(
            self.t("topology_discovery_q"), topo_options, topo_default_idx
        )
        self.config["topology_enabled"] = topo_choice != 0
        self.config["topology_only"] = topo_choice == 2

        # Enhanced network discovery + optional Red Team block (explicit opt-in).
        # Keep this best-effort, and default to OFF for Red Team options.
        persisted_nd = defaults_for_run.get("net_discovery_enabled")
        nd_default = (
            bool(persisted_nd)
            if isinstance(persisted_nd, bool)
            else bool(
                self.config.get("topology_enabled") or self.config.get("scan_mode") == "completo"
            )
        )
        enable_net_discovery = self.ask_yes_no(
            self.t("net_discovery_q"), default="yes" if nd_default else "no"
        )
        self.config["net_discovery_enabled"] = bool(enable_net_discovery)

        if enable_net_discovery:
            # Red Team recon requires explicit opt-in; default is NO.
            redteam_choice = self.ask_choice(
                self.t("redteam_mode_q"),
                [self.t("redteam_mode_a"), self.t("redteam_mode_b")],
                default=0,
            )

            wants_redteam = redteam_choice == 1
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0
            if wants_redteam and not is_root:
                # Should not happen in the default interactive flow (root required),
                # but keep behavior safe for --allow-non-root runs.
                self.print_status(self.t("redteam_requires_root"), "WARNING")
                wants_redteam = False

            self.config["net_discovery_redteam"] = bool(wants_redteam)
            self.config["net_discovery_active_l2"] = False
            self.config["net_discovery_kerberos_realm"] = None
            self.config["net_discovery_kerberos_userlist"] = None

            if self.config["net_discovery_redteam"]:
                self.config["net_discovery_active_l2"] = self.ask_yes_no(
                    self.t("redteam_active_l2_q"),
                    default="no",
                )

                # Kerberos user enumeration via kerbrute (requires userlist + authorization).
                enable_kerberos_userenum = self.ask_yes_no(
                    self.t("redteam_kerberos_userenum_q"),
                    default="no",
                )
                if enable_kerberos_userenum:
                    realm_hint = input(
                        f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('kerberos_realm_q')}: "
                    ).strip()
                    self.config["net_discovery_kerberos_realm"] = realm_hint or None

                    userlist = input(
                        f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('kerberos_userlist_q')}: "
                    ).strip()
                    self.config["net_discovery_kerberos_userlist"] = (
                        expand_user_path(userlist) if userlist else None
                    )

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
                "defaults_summary_web_vulns",
                fmt_bool(persisted_defaults.get("scan_vulnerabilities")),
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
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.print_status(f"- {self.t(key)}: {display_val}", "INFO")
