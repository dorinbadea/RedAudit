#!/usr/bin/env python3
"""
RedAudit - Main Auditor Module
Copyright (C) 2026  Dorin Badea
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

from redaudit.utils.constants import (
    VERSION,
    DEFAULT_LANG,
    MAX_CIDR_LENGTH,
    COLORS,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_WARN_THRESHOLD,
    HEARTBEAT_FAIL_THRESHOLD,
    MAX_PORTS_DISPLAY,
    DEEP_SCAN_TIMEOUT,
)
from redaudit.utils.i18n import TRANSLATIONS, get_text
from redaudit.core.crypto import (
    is_crypto_available,
    derive_key_from_password,
    ask_password_twice,
    generate_random_password,
)
from redaudit.core.network import detect_all_networks
from redaudit.core.scanner import (
    sanitize_ip,
    sanitize_hostname,
    is_web_service,
    is_suspicious_service,
    get_nmap_arguments,
    extract_vendor_mac,
    output_has_identity,
    run_nmap_command,
    capture_traffic_snippet,
    enrich_host_with_dns,
    enrich_host_with_whois,
    http_enrichment,
    tls_enrichment,
    exploit_lookup,
    ssl_deep_analysis,
)
from redaudit.core.reporter import (
    generate_summary,
    save_results,
    show_config_summary,
    show_results_summary,
)
from redaudit.core.prescan import run_prescan, parse_port_range

# Try to import nmap
nmap = None


class InteractiveNetworkAuditor:
    """Main orchestrator for RedAudit scans."""

    def __init__(self):
        self.lang = DEFAULT_LANG if DEFAULT_LANG in TRANSLATIONS else "en"
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
            "output_dir": os.path.expanduser(DEFAULT_OUTPUT_DIR),
            "scan_vulnerabilities": True,
            "save_txt_report": True,
            "encryption_salt": None,
            # Pre-scan config (v2.7)
            "prescan_enabled": False,
            "prescan_ports": "1-1024",
            "prescan_timeout": 0.5,
        }

        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = is_crypto_available()
        self.rate_limit_delay = 0.0
        self.extra_tools = {}

        self.last_activity = datetime.now()
        self.activity_lock = threading.Lock()
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
        color = self.COLORS.get(status, self.COLORS["OKBLUE"])

        if len(message) > 100:
            lines = [message[i:i + 100] for i in range(0, len(message), 100)]
        else:
            lines = [message]

        print(f"{color}[{ts}] [{status}]{self.COLORS['ENDC']} {lines[0]}")
        for line in lines[1:]:
            print(f"  {line}")
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
                    self.print_status(self.t("heartbeat_warn", phase, int(delta)), "WARNING", False)
                elif delta >= HEARTBEAT_FAIL_THRESHOLD:
                    self.print_status(self.t("heartbeat_fail", phase, int(delta)), "FAIL", False)
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
                    f"⚠️  Generated random encryption password (save this!): {password}",
                    "WARNING"
                )

            try:
                key, salt = derive_key_from_password(password)
                self.encryption_key = key
                self.config["encryption_salt"] = base64.b64encode(salt).decode()
                self.encryption_enabled = True
                self.print_status(self.t("encryption_enabled"), "OKGREEN")
            except RuntimeError as exc:
                if "cryptography not available" in str(exc):
                    self.print_status(self.t("cryptography_required"), "FAIL")
                else:
                    raise

    # ---------- Dependencies ----------

    def check_dependencies(self):
        """Check and verify required dependencies."""
        self.print_status(self.t("verifying_env"), "HEADER")

        if shutil.which("nmap") is None:
            self.print_status("Error: nmap binary not found.", "FAIL")
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
            "whatweb", "nikto", "curl", "wget", "openssl",
            "tcpdump", "tshark", "whois", "dig",
            "searchsploit", "testssl.sh",
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
            "yes": True, "y": True, "s": True, "si": True, "sí": True,
            "no": False, "n": False,
        }
        while True:
            ans = input(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}{opts}: "
            ).strip().lower()
            if ans == "":
                return valid.get(default, True)
            if ans in valid:
                return valid[ans]

    def ask_number(self, question, default=10, min_val=1, max_val=1000):
        """Ask for a number within a range."""
        while True:
            ans = input(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question} [{default}]: "
            ).strip()
            if ans == "":
                return default
            if ans.lower() in ("todos", "all"):
                return "all"
            try:
                num = int(ans)
                if min_val <= num <= max_val:
                    return num
                self.print_status(self.t("val_out_of_range", min_val, max_val), "WARNING")
            except ValueError:
                continue

    def ask_choice(self, question, options, default=0):
        """Ask to choose from a list of options."""
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.COLORS['BOLD']}▶{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i + 1}. {opt}")
        while True:
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

    def ask_manual_network(self):
        """Ask for manual network CIDR input."""
        while True:
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
                return [n["network"] for n in nets]
            return [nets[choice]["network"]]
        else:
            self.print_status(self.t("no_nets_auto"), "WARNING")
            return [self.ask_manual_network()]

    # ---------- Scanning ----------

    def is_web_service(self, name):
        """Check if service is web-related."""
        return is_web_service(name)

    def deep_scan_host(self, host_ip):
        """
        Adaptive Deep Scan v2.5
        Phase 1: TCP Connect + Service Version + Scripts (Aggressive)
        Phase 2: OS Detection + UDP Scan (only if Phase 1 yields no identity)
        """
        safe_ip = sanitize_ip(host_ip)
        if not safe_ip:
            return None

        self.current_phase = f"deep:{safe_ip}"
        deep_obj = {"strategy": "adaptive_v2.5", "commands": []}

        self.print_status(self.t("deep_identity_start", safe_ip, "Adaptive (2-Phase)"), "WARNING")

        # Phase 1: Aggressive TCP
        cmd_p1 = ["nmap", "-A", "-sV", "-Pn", "-p-", "--open", "--version-intensity", "9", safe_ip]
        self.print_status(self.t("deep_identity_cmd", safe_ip, " ".join(cmd_p1), "120-180"), "WARNING")
        rec1 = run_nmap_command(cmd_p1, DEEP_SCAN_TIMEOUT, safe_ip, deep_obj)

        # Check for Identity
        has_identity = output_has_identity([rec1])
        mac, vendor = extract_vendor_mac(rec1.get("stdout", ""))

        if mac:
            deep_obj["mac_address"] = mac
        if vendor:
            deep_obj["vendor"] = vendor

        # Phase 2: UDP + OS (Conditional)
        if has_identity:
            self.print_status(self.t("deep_scan_skip"), "OKGREEN")
            deep_obj["phase2_skipped"] = True
        else:
            cmd_p2 = ["nmap", "-O", "-sSU", "-Pn", "-p-", "--max-retries", "2", safe_ip]
            self.print_status(self.t("deep_identity_cmd", safe_ip, " ".join(cmd_p2), "150-300"), "WARNING")
            rec2 = run_nmap_command(cmd_p2, DEEP_SCAN_TIMEOUT, safe_ip, deep_obj)
            if not mac:
                m2, v2 = extract_vendor_mac(rec2.get("stdout", ""))
                if m2:
                    deep_obj["mac_address"] = m2
                if v2:
                    deep_obj["vendor"] = v2

        # Traffic Capture
        pcap_info = capture_traffic_snippet(
            safe_ip,
            self.config["output_dir"],
            self.results.get("network_info", []),
            self.extra_tools,
            logger=self.logger
        )
        if pcap_info:
            deep_obj["pcap_capture"] = pcap_info

        total_dur = sum(c.get("duration_seconds", 0) for c in deep_obj["commands"])
        self.print_status(self.t("deep_identity_done", safe_ip, total_dur), "OKGREEN")
        return deep_obj

    def scan_network_discovery(self, network):
        """Perform network discovery scan."""
        self.current_phase = f"discovery:{network}"
        self.logger.info("Discovery on %s", network)
        nm = nmap.PortScanner()
        args = get_nmap_arguments("rapido")
        self.print_status(self.t("nmap_cmd", network, f"nmap {args} {network}"), "INFO")
        try:
            nm.scan(hosts=network, arguments=args)
        except Exception as exc:
            self.logger.error("Discovery failed on %s: %s", network, exc)
            self.print_status(self.t("scan_error", exc), "FAIL")
            return []
        hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        self.print_status(self.t("hosts_active", network, len(hosts)), "OKGREEN")
        return hosts

    def scan_host_ports(self, host):
        """Scan ports on a single host."""
        safe_ip = sanitize_ip(host)
        if not safe_ip:
            self.logger.warning("Invalid IP: %s", host)
            return {"ip": host, "error": "Invalid IP"}

        self.current_phase = f"ports:{safe_ip}"
        nm = nmap.PortScanner()
        args = get_nmap_arguments(self.config["scan_mode"])
        self.logger.debug("Nmap scan %s %s", safe_ip, args)
        self.print_status(self.t("nmap_cmd", safe_ip, f"nmap {args} {safe_ip}"), "INFO")

        try:
            nm.scan(safe_ip, arguments=args)
            if safe_ip not in nm.all_hosts():
                deep = self.deep_scan_host(safe_ip)
                return {"ip": safe_ip, "status": "down", "deep_scan": deep} if deep else {"ip": safe_ip, "status": "down"}

            data = nm[safe_ip]
            hostname = ""
            try:
                hostnames = data.hostnames()
                if hostnames:
                    hostname = hostnames[0].get("name") or ""
            except Exception:
                hostname = ""

            ports = []
            web_count = 0
            suspicious = False
            any_version = False

            for proto in data.all_protocols():
                for p in data[proto]:
                    svc = data[proto][p]
                    name = svc.get("name", "") or ""
                    product = svc.get("product", "") or ""
                    version = svc.get("version", "") or ""
                    is_web = is_web_service(name)
                    if is_web:
                        web_count += 1

                    if is_suspicious_service(name):
                        suspicious = True
                    if product or version:
                        any_version = True

                    ports.append({
                        "port": p,
                        "protocol": proto,
                        "service": name,
                        "product": product,
                        "version": version,
                        "is_web_service": is_web,
                    })

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

            # Heuristics for deep identity scan
            trigger_deep = False
            if total_ports > 8:
                trigger_deep = True
            if suspicious:
                trigger_deep = True
            if total_ports <= 3:
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
                                "WARNING"
                            )

            if trigger_deep:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    host_record["deep_scan"] = deep

            enrich_host_with_dns(host_record, self.extra_tools)
            enrich_host_with_whois(host_record, self.extra_tools)
            return host_record

        except Exception as exc:
            self.logger.error("Scan error %s: %s", safe_ip, exc, exc_info=True)
            result = {"ip": safe_ip, "error": str(exc)}
            try:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    result["deep_scan"] = deep
            except Exception:
                pass
            return result

    def scan_hosts_concurrent(self, hosts):
        """Scan multiple hosts concurrently with progress bar."""
        self.print_status(self.t("scan_start", len(hosts)), "HEADER")
        unique_hosts = sorted(set(hosts))
        results = []

        # Try to use rich for better progress visualization
        try:
            from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
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
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]{self.t('scanning_hosts')}", total=total
                    )
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
                        done += 1
                        progress.update(task, advance=1, description=f"[cyan]Scanned {host_ip}")
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
            http_data = http_enrichment(url, self.extra_tools)
            finding.update(http_data)

            # TLS enrichment
            if scheme == "https":
                tls_data = tls_enrichment(ip, port, self.extra_tools)
                finding.update(tls_data)
                
                # TestSSL deep analysis (only in completo mode)
                if self.config["scan_mode"] == "completo" and self.extra_tools.get("testssl.sh"):
                    self.print_status(
                        self.t("testssl_analysis", ip, port),
                        "INFO"
                    )
                    ssl_analysis = ssl_deep_analysis(ip, port, self.extra_tools, self.logger)
                    if ssl_analysis:
                        finding["testssl_analysis"] = ssl_analysis
                        # Alert if vulnerabilities found
                        if ssl_analysis.get("vulnerabilities"):
                            self.print_status(
                                f"⚠️  SSL/TLS vulnerabilities detected on {ip}:{port}",
                                "WARNING"
                            )

            # WhatWeb
            if self.extra_tools.get("whatweb"):
                try:
                    import subprocess
                    res = subprocess.run(
                        [self.extra_tools["whatweb"], "-q", "-a", "3", url],
                        capture_output=True, text=True, timeout=30,
                    )
                    if res.stdout.strip():
                        finding["whatweb"] = res.stdout.strip()[:2000]
                except Exception:
                    pass

            # Nikto (only in full mode)
            if self.config["scan_mode"] == "completo" and self.extra_tools.get("nikto"):
                try:
                    import subprocess
                    res = subprocess.run(
                        [self.extra_tools["nikto"], "-h", url, "-maxtime", "120s", "-Tuning", "x"],
                        capture_output=True, text=True, timeout=150,
                    )
                    output = res.stdout or res.stderr
                    if output:
                        findings_list = [line for line in output.splitlines() if "+ " in line][:20]
                        if findings_list:
                            finding["nikto_findings"] = findings_list
                except Exception:
                    pass

            if len(finding) > 2:
                vulns.append(finding)

        return {"host": ip, "vulnerabilities": vulns} if vulns else None

    def scan_vulnerabilities_concurrent(self, host_results):
        """Scan vulnerabilities on multiple hosts concurrently."""
        web_hosts = [h for h in host_results if h.get("web_ports_count", 0) > 0]
        if not web_hosts:
            return
        self.current_phase = "vulns"
        self.print_status(self.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.scan_vulnerabilities_web, h): h["ip"]
                for h in web_hosts
            }
            for fut in as_completed(futures):
                if self.interrupted:
                    break
                try:
                    res = fut.result()
                    if res:
                        self.results["vulnerabilities"].append(res)
                        self.print_status(self.t("vulns_found", res["host"]), "WARNING")
                except Exception as exc:
                    self.print_status(f"[worker error] {exc}", "WARNING")

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
            self.logger
        )

    # ---------- Interactive flow ----------

    def clear_screen(self):
        """Clear the terminal screen."""
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

    def interactive_setup(self):
        """Run interactive configuration setup."""
        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies():
            return False
        if not self.show_legal_warning():
            return False

        print(f"\n{self.COLORS['HEADER']}{self.t('scan_config')}{self.COLORS['ENDC']}")
        print("=" * 60)

        self.config["target_networks"] = self.ask_network_range()

        scan_modes = [
            self.t("mode_fast"),
            self.t("mode_normal"),
            self.t("mode_full"),
        ]
        modes_map = {0: "rapido", 1: "normal", 2: "completo"}
        self.config["scan_mode"] = modes_map[self.ask_choice(self.t("scan_mode"), scan_modes, 1)]

        if self.config["scan_mode"] != "rapido":
            limit = self.ask_number(self.t("ask_num_limit"), default=25)
            self.config["max_hosts_value"] = limit
        else:
            self.config["max_hosts_value"] = "all"

        self.config["threads"] = self.ask_number(
            self.t("threads"), default=DEFAULT_THREADS, min_val=MIN_THREADS, max_val=MAX_THREADS
        )

        if self.ask_yes_no(self.t("rate_limiting"), default="no"):
            delay = self.ask_number(self.t("rate_delay"), default=1, min_val=0, max_val=60)
            self.rate_limit_delay = float(delay)

        self.config["scan_vulnerabilities"] = self.ask_yes_no(self.t("vuln_scan_q"), default="yes")

        default_reports = os.path.expanduser(DEFAULT_OUTPUT_DIR)
        out_dir = input(
            f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('output_dir')} [{default_reports}]: "
        ).strip()
        if not out_dir:
            out_dir = default_reports
        self.config["output_dir"] = out_dir

        self.config["save_txt_report"] = self.ask_yes_no(self.t("gen_txt"), default="yes")

        self.setup_encryption()

        self.show_config_summary()
        return self.ask_yes_no(self.t("start_audit"), default="yes")

    def run_complete_scan(self):
        """Execute the complete scan workflow."""
        self.scan_start_time = datetime.now()
        self.start_heartbeat()

        try:
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

            if self.config.get("scan_vulnerabilities") and not self.interrupted:
                self.scan_vulnerabilities_concurrent(results)

            generate_summary(
                self.results,
                self.config,
                all_hosts,
                results,
                self.scan_start_time
            )
            self.save_results(partial=self.interrupted)
            self.show_results()

        finally:
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
                        self.logger.debug("Error killing subprocess: %s", exc)
            self._active_subprocesses.clear()

    def signal_handler(self, sig, frame):
        """Handle SIGINT (Ctrl+C) with proper cleanup."""
        self.print_status(self.t("interrupted"), "WARNING")
        self.current_phase = "interrupted"
        self.interrupted = True

        # Kill all active subprocesses (nmap, tcpdump, etc.)
        if self._active_subprocesses:
            self.print_status("Terminating active scans...", "WARNING")
            self.kill_all_subprocesses()

        # Stop heartbeat monitoring
        self.stop_heartbeat()
