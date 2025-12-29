"""
RedAudit - Auditor scanning mixin.
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import math
import os
import random
import re
import shlex
import shutil
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from redaudit.core.agentless_verify import (
    probe_agentless_services,
    select_agentless_probe_targets,
    summarize_agentless_fingerprint,
)
from redaudit.core.auditor_mixins import _ActivityIndicator
from redaudit.core.crypto import is_crypto_available
from redaudit.core.network import detect_all_networks, get_neighbor_mac
from redaudit.core.scanner import (
    banner_grab_fallback,
    enrich_host_with_dns,
    enrich_host_with_whois,
    exploit_lookup,
    extract_os_detection,
    extract_vendor_mac,
    finalize_host_status,
    get_nmap_arguments,
    http_identity_probe,
    is_suspicious_service,
    is_web_service,
    output_has_identity,
    run_nmap_command,
    sanitize_hostname,
    sanitize_ip,
    start_background_capture,
    stop_background_capture,
)
from redaudit.core.udp_probe import run_udp_probe
from redaudit.utils.constants import (
    DEFAULT_UDP_MODE,
    DEEP_SCAN_TIMEOUT,
    MAX_PORTS_DISPLAY,
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
    UDP_HOST_TIMEOUT_STRICT,
    UDP_MAX_RETRIES_LAN,
    UDP_PRIORITY_PORTS,
    UDP_SCAN_MODE_FULL,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
)
from redaudit.utils.dry_run import is_dry_run
from redaudit.utils.oui_lookup import get_vendor_with_fallback

# Try to import nmap
nmap = None


class AuditorScanMixin:
    results: Dict[str, Any]
    config: Dict[str, Any]
    extra_tools: Dict[str, Optional[str]]
    logger: Optional[logging.Logger]
    rate_limit_delay: float
    interrupted: bool

    if TYPE_CHECKING:

        def _coerce_text(self, value: object) -> str:
            raise NotImplementedError

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

    @staticmethod
    def sanitize_ip(ip_str):
        """Sanitize and validate IP address."""
        return sanitize_ip(ip_str)

    @staticmethod
    def sanitize_hostname(hostname):
        """Sanitize and validate hostname."""
        return sanitize_hostname(hostname)

    def is_web_service(self, name):
        """Check if service is web-related."""
        return is_web_service(name)

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

    def _apply_net_discovery_identity(self, host_record: Dict[str, Any]) -> None:
        """Merge net_discovery hints (MAC/vendor/hostname/UPnP) into host record."""
        nd_results = self.results.get("net_discovery") if isinstance(self.results, dict) else None
        if not isinstance(nd_results, dict):
            return

        ip = host_record.get("ip")
        if not ip:
            return

        if not host_record.get("hostname"):
            for host in nd_results.get("netbios_hosts", []) or []:
                if isinstance(host, dict) and host.get("ip") == ip and host.get("name"):
                    name = str(host.get("name") or "").strip()
                    if name:
                        host_record["hostname"] = sanitize_hostname(name) or name
                    break

        mac = None
        vendor = None
        for host in nd_results.get("arp_hosts", []) or []:
            if isinstance(host, dict) and host.get("ip") == ip:
                mac = host.get("mac") or None
                vendor = host.get("vendor") or None
                break

        if isinstance(vendor, str) and "unknown" in vendor.lower():
            vendor = None

        if mac and not vendor:
            try:
                vendor = get_vendor_with_fallback(mac, None, online_fallback=True)
            except Exception:
                vendor = None

        if mac or vendor:
            deep_meta = host_record.setdefault(
                "deep_scan", {"strategy": "net_discovery", "commands": []}
            )
            if mac and not deep_meta.get("mac_address"):
                deep_meta["mac_address"] = mac
            if vendor and not deep_meta.get("vendor"):
                deep_meta["vendor"] = vendor

        for device in nd_results.get("upnp_devices", []) or []:
            if isinstance(device, dict) and device.get("ip") == ip:
                device_name = str(device.get("device") or "").strip()
                if device_name:
                    agentless = host_record.setdefault("agentless_fingerprint", {})
                    if not agentless.get("http_title"):
                        agentless["http_title"] = device_name[:80]
                break

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
        m = re.search(r"--host-timeout\s+(\d+)(ms|s|m|h)\b", nmap_args)
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
        args = get_nmap_arguments("rapido", self.config)  # v3.9.0: Pass config for timing
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
                        refresh_per_second=4,
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
        # v3.9.0: Pass config so nmap_timing (T1/T4/T5) is applied
        args = get_nmap_arguments(self.config["scan_mode"], self.config)
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

            # v3.9.8: Merge net_discovery identity hints (ARP/NetBIOS/UPnP) before heuristics.
            self._apply_net_discovery_identity(host_record)

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
                elif "tuya" in vendor_lower:
                    device_type_hints.append("iot")
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
                        "sercomm",
                        "sagemcom",
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

            if total_ports == 0 and self.config.get("deep_id_scan", True):
                identity_source = host_record.get("deep_scan") or {}
                has_identity_hint = bool(
                    identity_source.get("vendor")
                    or host_record.get("hostname")
                    or host_record.get("device_type_hints")
                )
                if has_identity_hint and host_record.get("status") != STATUS_DOWN:
                    http_probe = http_identity_probe(
                        safe_ip,
                        self.extra_tools,
                        dry_run=bool(self.config.get("dry_run", False)),
                        logger=self.logger,
                    )
                    if http_probe:
                        agentless_fp = host_record.setdefault("agentless_fingerprint", {})
                        for key in ("http_title", "http_server"):
                            if http_probe.get(key) and not agentless_fp.get(key):
                                agentless_fp[key] = http_probe[key]
                        smart = host_record.get("smart_scan")
                        if isinstance(smart, dict):
                            signals = list(smart.get("signals") or [])
                            if "http_probe" not in signals:
                                signals.append("http_probe")
                            smart["signals"] = signals
                            try:
                                smart["identity_score"] = int(smart.get("identity_score", 0)) + 1
                            except Exception:
                                smart["identity_score"] = smart.get("identity_score", 0)

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
                        refresh_per_second=4,
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
                        refresh_per_second=4,
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
                            elapsed = int(time.time() - start_t)
                            mins, secs = divmod(elapsed, 60)
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
            existing_fp = host.get("agentless_fingerprint") or {}
            if existing_fp:
                merged = dict(existing_fp)
                for key, value in (agentless_fp or {}).items():
                    if value not in (None, ""):
                        merged[key] = value
                agentless_fp = merged
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
                    # v3.8.9: Device fingerprinting from HTTP probes
                    "device_vendor",
                    "device_model",
                    "device_type",
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
