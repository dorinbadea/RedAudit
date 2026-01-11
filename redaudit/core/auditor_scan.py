"""
RedAudit - Auditor scanning component.
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import os
import random
import re

import shutil
import socket
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from redaudit.core.agentless_verify import (
    probe_agentless_services,
    select_agentless_probe_targets,
    summarize_agentless_fingerprint,
)
from redaudit.core.command_runner import CommandRunner
from redaudit.core.crypto import is_crypto_available
from redaudit.core.models import Host, Service
from redaudit.core.network import get_neighbor_mac
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
from redaudit.core.network_scanner import NetworkScanner
from redaudit.core.tool_compat import check_tool_compatibility
from redaudit.utils.constants import (
    DEFAULT_IDENTITY_THRESHOLD,
    DEFAULT_UDP_MODE,
    DEEP_SCAN_TIMEOUT,
    MAX_PORTS_DISPLAY,
    PHASE0_TIMEOUT,
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

# v4.0: Authenticated Scanning
from redaudit.core.auth_ssh import SSHScanner, SSHConnectionError
from redaudit.core.credentials import Credential, get_credential_provider
from dataclasses import asdict

# Try to import nmap
nmap = None


class AuditorScan:
    results: Dict[str, Any]
    config: Dict[str, Any]
    extra_tools: Dict[str, Optional[str]]
    logger: Optional[logging.Logger]
    rate_limit_delay: float
    interrupted: bool
    scanner: NetworkScanner
    ui: Any  # Defined in Auditor subclass, typed as Any to satisfy mypy
    proxy_manager: Any  # Defined in Auditor subclass
    # v4.1: Pre-discovered ports from sequential HyperScan-First phase
    _hyperscan_discovery_ports: Dict[str, List[int]]

    if TYPE_CHECKING:

        def _coerce_text(self, value: object) -> str:
            raise NotImplementedError

        def _set_ui_detail(self, detail: str) -> None:
            raise NotImplementedError

    # v4.0: Authenticated Scanning Helpers
    @property
    def credential_provider(self):
        """Lazy initialization of credential provider."""
        if not hasattr(self, "_credential_provider_instance"):
            auth_backend = self.config.get("auth_provider", "keyring")
            try:
                self._credential_provider_instance = get_credential_provider(auth_backend)
            except Exception as e:
                if self.logger:
                    self.logger.warning("Error initializing credential provider: %s", e)
                # Fallback
                from redaudit.core.credentials import EnvironmentCredentialProvider

                self._credential_provider_instance = EnvironmentCredentialProvider()
        return self._credential_provider_instance

    def _resolve_ssh_credential(self, host: str) -> Optional[Credential]:
        """Resolve SSH credential for host (Global Config > Provider)."""
        # 1. Global Config (CLI/Wizard) overrides provider for now (MVP simplified)
        # Or better: check Config, if not present, check Provider.
        # But if user provided --ssh-user, they likely want to use it for all targets
        # (or at least try it).

        user = self.config.get("auth_ssh_user")
        key = self.config.get("auth_ssh_key")
        password = self.config.get("auth_ssh_pass")
        # v4.1: Key Passphrase
        key_pass = self.config.get("auth_ssh_key_pass")

        if user and (key or password):
            return Credential(
                username=user, password=password, private_key=key, private_key_passphrase=key_pass
            )

        # 2. Provider
        return self.credential_provider.get_credential(host, "ssh")

    def _resolve_smb_credential(self, host: str) -> Optional[Credential]:
        """Resolve SMB/Windows credential for host."""
        user = self.config.get("auth_smb_user")
        password = self.config.get("auth_smb_pass")
        domain = self.config.get("auth_smb_domain")

        if user and password:
            # Handle DOMAIN\User in username if domain not separate?
            # Impacket usually handles this, or we split properly.
            # But let's pass as provided, and use domain arg if present.
            return Credential(username=user, password=password, domain=domain)

        return self.credential_provider.get_credential(host, "smb")

    def _resolve_snmp_credential(self, host: str) -> Optional[Credential]:
        """Resolve SNMP v3 credential for host."""
        user = self.config.get("auth_snmp_user")
        if user:
            c = Credential(username=user)
            c.snmp_auth_proto = self.config.get("auth_snmp_auth_proto")
            c.snmp_auth_pass = self.config.get("auth_snmp_auth_pass")
            c.snmp_priv_proto = self.config.get("auth_snmp_priv_proto")
            c.snmp_priv_pass = self.config.get("auth_snmp_priv_pass")
            return c
        return self.credential_provider.get_credential(host, "snmp")

    # ---------- Dependencies ----------

    def check_dependencies(self):
        """Check and verify required dependencies."""
        self.ui.print_status(self.ui.t("verifying_env"), "HEADER")

        if shutil.which("nmap") is None:
            self.ui.print_status(self.ui.t("nmap_binary_missing"), "FAIL")
            return False

        global nmap
        try:
            nmap = importlib.import_module("nmap")
            self.ui.print_status(self.ui.t("nmap_avail"), "OKGREEN")

            # v4.2: Impacket check
            try:
                import impacket  # noqa: F401

                # self.ui.print_status(self.ui.t("impacket_avail"), "OKGREEN") # Use generic message for now
                self.ui.print_status("Impacket available (SMB/WMI)", "OKGREEN")
            except ImportError:
                self.ui.print_status(
                    "Impacket missing (pip install impacket) - SMB/WMI auth disabled", "WARN"
                )

            # v4.3: PySNMP check
            try:
                import pysnmp  # noqa: F401

                self.ui.print_status("PySNMP available (SNMP v3)", "OKGREEN")
            except ImportError:
                self.ui.print_status(
                    "PySNMP missing (pip install pysnmp) - SNMP v3 auth disabled", "WARN"
                )
        except ImportError:
            self.ui.print_status(self.ui.t("nmap_missing"), "FAIL")
            return False

        self.cryptography_available = is_crypto_available()
        if not self.cryptography_available:
            self.ui.print_status(self.ui.t("crypto_missing"), "WARNING")

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
            "sqlmap",
            "zap.sh",
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
                self.ui.print_status(self.ui.t("avail_at", tname, path), "OKGREEN")
            else:
                self.extra_tools[tname] = None
                missing.append(tname)

        if missing:
            msg = self.ui.t("missing_opt", ", ".join(missing))
            self.ui.print_status(msg, "WARNING")

        dry_run = self.config.get("dry_run") if hasattr(self.config, "get") else None
        compat_issues = check_tool_compatibility(("nmap", "nuclei"), dry_run=dry_run)
        for issue in compat_issues:
            if issue.reason == "unsupported_major":
                msg = self.ui.t("tool_version_warn", issue.tool, issue.version, issue.expected)
            else:
                msg = self.ui.t("tool_version_unknown", issue.tool, issue.expected)
            self.ui.print_status(msg, "WARNING")
        return True

    # ---------- Input utilities (inherited from Wizard) ----------

    # ---------- Network detection ----------

    def _collect_discovery_hosts(self, target_networks: List[str]) -> List[str]:
        """Collect host IPs from enhanced discovery results (best-effort)."""
        discovery = self.results.get("net_discovery") or {}
        ips = set()

        def _add_safe(val):
            if val:
                s = sanitize_ip(val)
                if s:
                    ips.add(s)

        # Collect from all sources
        for ip in discovery.get("alive_hosts", []) or []:
            _add_safe(ip)

        # Flatten dictionary-based lists
        for key in ["arp_hosts", "netbios_hosts", "upnp_devices", "dhcp_servers", "mdns_services"]:
            for item in discovery.get(key, []) or []:
                if isinstance(item, dict):
                    _add_safe(item.get("ip"))

        # HyperScan keys
        for ip in (discovery.get("hyperscan_tcp_hosts") or {}).keys():
            _add_safe(ip)

        if not ips:
            return []

        # Filter by target networks if specified
        if target_networks:
            try:
                # Compile networks once
                networks = [ipaddress.ip_network(str(n), strict=False) for n in target_networks]

                filtered = []
                for ip in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        # Check strict overlaps
                        if any(ip_obj in net for net in networks):
                            filtered.append(ip)
                    except ValueError:
                        continue
                return sorted(filtered)
            except Exception:
                # Fallback if network parsing fails
                return sorted(ips)

        return sorted(ips)

    def ask_network_range(self):
        """Ask user to select target network(s)."""
        h = self.ui.colors["HEADER"]
        print(f"\n{h}{self.ui.t('selection_target')}{self.ui.colors['ENDC']}")
        print("-" * 60)
        # v4.0: Use Scanner directly (Populate results for consistency)
        nets = self.scanner.detect_local_networks()
        self.results["network_info"] = nets
        if nets:
            g = self.ui.colors["OKGREEN"]
            print(f"{g}{self.ui.t('interface_detected')}{self.ui.colors['ENDC']}")
            opts = []
            for n in nets:
                info = f" ({n['interface']})" if n["interface"] else ""
                h_est = n["hosts_estimated"]
                opts.append(f"{n['network']}{info} - ~{h_est} hosts")
            opts.append(self.ui.t("manual_entry"))
            opts.append(self.ui.t("scan_all"))
            choice = self.ask_choice(self.ui.t("select_net"), opts)
            if choice == len(opts) - 2:
                return [self.ask_manual_network()]
            if choice == len(opts) - 1:
                # v3.2.3: Deduplicate networks (same CIDR on multiple
                # interfaces)
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
            self.ui.print_status(self.ui.t("no_nets_auto"), "WARNING")
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
        return NetworkScanner.sanitize_ip(ip_str)

    @staticmethod
    def sanitize_hostname(hostname):
        """Sanitize and validate hostname."""
        return NetworkScanner.sanitize_hostname(hostname)

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

    def _lookup_topology_identity(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        t = self.results.get("topology")
        topo = t if isinstance(self.results, dict) else None
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
        """
        Merge net_discovery hints (MAC/vendor/hostname/UPnP) into host record.
        v3.10.1: Also check topology neighbor_cache as fallback MAC source.
        """
        r = self.results
        nd_results = r.get("net_discovery") if isinstance(r, dict) else None
        if not isinstance(nd_results, dict):
            nd_results = {}

        ip = host_record.get("ip")
        if not ip:
            return

        if not host_record.get("hostname"):
            for host in nd_results.get("netbios_hosts", []) or []:
                is_match = isinstance(host, dict) and host.get("ip") == ip and host.get("name")
                if is_match:
                    name = str(host.get("name") or "").strip()
                    if name:
                        host_record["hostname"] = sanitize_hostname(name) or name
                    break

        mac = None
        vendor = None
        # Source 1: net_discovery.arp_hosts
        for host in nd_results.get("arp_hosts", []) or []:
            if isinstance(host, dict) and host.get("ip") == ip:
                mac = host.get("mac") or None
                vendor = host.get("vendor") or None
                break

        # Source 2: topology.interfaces[].arp.hosts + neighbor_cache (fallback)
        if not mac:
            pipeline = r.get("pipeline", {}) if isinstance(r, dict) else {}
            topology = pipeline.get("topology", {}) if isinstance(pipeline, dict) else {}
            for iface in topology.get("interfaces", []) or []:
                if not isinstance(iface, dict):
                    continue
                # Check arp.hosts first
                arp = iface.get("arp", {}) or {}
                for h in arp.get("hosts", []) or []:
                    if isinstance(h, dict) and h.get("ip") == ip:
                        mac = h.get("mac") or None
                        vendor = h.get("vendor") or None
                        break
                if mac:
                    break
                # Check neighbor_cache
                neighbor_cache = iface.get("neighbor_cache", {}) or {}
                for entry in neighbor_cache.get("entries", []) or []:
                    if isinstance(entry, dict) and entry.get("ip") == ip and entry.get("mac"):
                        mac = entry.get("mac")
                        break
                if mac:
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

    def _run_low_impact_enrichment(self, host: str) -> Dict[str, Any]:
        """Best-effort DNS/mDNS/SNMP probes with short timeouts (opt-in)."""
        signals: Dict[str, Any] = {}
        safe_ip = sanitize_ip(host)
        if not safe_ip:
            return signals
        if is_dry_run(self.config.get("dry_run")):
            return signals

        # DNS reverse lookup (fast, low-impact).
        try:
            dns_value = None
            dig = self.extra_tools.get("dig")
            if dig:
                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=False,
                    default_timeout=float(PHASE0_TIMEOUT),
                    default_retries=0,
                    backoff_base_s=0.0,
                )
                res = runner.run(
                    [dig, "+short", "-x", safe_ip],
                    timeout=float(PHASE0_TIMEOUT),
                    capture_output=True,
                    check=False,
                    text=True,
                )
                output = str(res.stdout or "").strip()
                if output:
                    dns_value = output.splitlines()[0].strip().rstrip(".")[:255]
            else:
                result_holder = {"value": None}

                def _lookup():
                    try:
                        name = socket.gethostbyaddr(safe_ip)[0]
                        result_holder["value"] = name
                    except Exception:
                        result_holder["value"] = None

                worker = threading.Thread(target=_lookup, daemon=True)
                worker.start()
                worker.join(timeout=float(PHASE0_TIMEOUT))
                if result_holder["value"]:
                    dns_value = result_holder["value"].strip().rstrip(".")[:255]

            if dns_value:
                signals["dns_reverse"] = dns_value
        except Exception:
            if self.logger:
                self.logger.debug("Phase0 DNS reverse failed for %s", safe_ip, exc_info=True)

        # mDNS unicast probe (best-effort, short timeout).
        try:
            mdns_timeout = min(1.0, float(PHASE0_TIMEOUT))
            try:
                from redaudit.core.hyperscan import _build_mdns_query

                payload = _build_mdns_query()
            except Exception:
                payload = b"\x00"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(mdns_timeout)
                sock.sendto(payload, (safe_ip, 5353))
                data, _addr = sock.recvfrom(4096)
                if data:
                    mdns_name = self._extract_mdns_name(data) or "mdns_response"
                    signals["mdns_name"] = mdns_name[:255]
            except (socket.timeout, TimeoutError):
                # Expected behavior for most hosts (no mDNS response)
                if self.logger:
                    self.logger.debug("Phase0 mDNS probe timed out for %s (expected)", safe_ip)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception:
            if self.logger:
                self.logger.debug("Phase0 mDNS probe failed for %s", safe_ip, exc_info=True)

        # SNMP sysDescr (read-only, only if community is public).
        try:
            comm_cfg = self.config.get("net_discovery_snmp_community", "public")
            community = str(comm_cfg or "").strip()
            if community.lower() == "public" and shutil.which("snmpwalk"):
                snmp_timeout = min(1.0, float(PHASE0_TIMEOUT))
                runner = CommandRunner(
                    logger=self.logger,
                    dry_run=False,
                    default_timeout=snmp_timeout,
                    default_retries=0,
                    backoff_base_s=0.0,
                )
                cmd = [
                    "snmpwalk",
                    "-v2c",
                    "-c",
                    "public",
                    "-t",
                    "1",
                    "-r",
                    "0",
                    "-On",
                    safe_ip,
                    "1.3.6.1.2.1.1.1.0",
                ]
                res = runner.run(
                    cmd,
                    timeout=snmp_timeout,
                    capture_output=True,
                    check=False,
                    text=True,
                )
                text = str(res.stdout or "").strip() or str(res.stderr or "").strip()
                if text and "timeout" not in text.lower():
                    line = text.splitlines()[0].strip()
                    if "=" in line:
                        line = line.split("=", 1)[1].strip()
                    line = re.sub(r"^[A-Z][A-Z0-9-]*:\s*", "", line).strip().strip('"')
                    if line:
                        signals["snmp_sysDescr"] = line[:255]
        except Exception:
            if self.logger:
                self.logger.debug("Phase0 SNMP probe failed for %s", safe_ip, exc_info=True)

        return signals

    @staticmethod
    def _extract_mdns_name(data: bytes) -> str:
        if not data:
            return ""
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return ""
        match = re.search(r"([A-Za-z0-9._-]+\\.local)", text)
        return match.group(1) if match else ""

    def _compute_identity_score(self, host_record: Dict[str, Any]) -> Tuple[int, List[str]]:
        """Compute identity/confidence score (delegated to NetworkScanner)."""
        nd_results = self.results.get("net_discovery") or {}
        # v4.0: Usage of composed NetworkScanner
        return self.scanner.compute_identity_score(host_record, nd_results)

    def _should_trigger_deep(
        self,
        *,
        total_ports: int,
        any_version: bool,
        suspicious: bool,
        device_type_hints: List[str],
        identity_score: int,
        identity_threshold: int,
    ) -> Tuple[bool, List[str]]:
        trigger_deep = False
        deep_reasons: List[str] = []
        if not self.config.get("deep_id_scan", True):
            return False, deep_reasons
        identity_is_weak = identity_score < identity_threshold

        if total_ports > 8:
            trigger_deep = True
            deep_reasons.append("many_ports")
        if suspicious:
            trigger_deep = True
            deep_reasons.append("suspicious_service")
        if 0 < total_ports <= 3 and identity_is_weak:
            trigger_deep = True
            deep_reasons.append("low_visibility")
        if total_ports > 0 and not any_version:
            trigger_deep = True
            deep_reasons.append("no_version_info")
        if "router" in device_type_hints or "network_device" in device_type_hints:
            trigger_deep = True
            deep_reasons.append("network_infrastructure")
        if total_ports > 0 and identity_is_weak:
            trigger_deep = True
            deep_reasons.append("identity_weak")

        # v4.5.15: Ghost Identity - If we have NO ports but identity is weak,
        # force deep scan to discover hidden/filtered services (UDP, etc.)
        if total_ports == 0 and identity_is_weak:
            trigger_deep = True
            deep_reasons.append("ghost_identity")

        # v4.5.17: Raised port limit from 12 to 20 to allow well-identified routers
        # (which often have 14+ ports) to reach identity_strong and skip deep scan
        if (
            identity_score >= identity_threshold
            and not suspicious
            and total_ports <= 20
            and any_version
        ):
            trigger_deep = False
            deep_reasons.append("identity_strong")

        return trigger_deep, deep_reasons

    def _prune_weak_identity_reasons(self, smart_scan: Dict[str, Any]) -> None:
        if not isinstance(smart_scan, dict):
            return
        reasons = list(smart_scan.get("reasons") or [])
        if not reasons:
            return
        try:
            identity_score = int(smart_scan.get("identity_score", 0))
            identity_threshold = int(
                smart_scan.get("identity_threshold", DEFAULT_IDENTITY_THRESHOLD)
            )
        except Exception:
            return
        if identity_score < identity_threshold:
            return
        pruned = [r for r in reasons if r not in ("low_visibility", "identity_weak")]
        if pruned != reasons:
            smart_scan["reasons"] = pruned
            smart_scan["escalation_reason"] = "|".join(pruned) if pruned else None

    def _run_udp_priority_probe(self, host_record: Dict[str, Any]) -> bool:
        safe_ip = sanitize_ip(host_record.get("ip"))
        if not safe_ip:
            return False
        if is_dry_run(self.config.get("dry_run")):
            return False

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

        udp_probe = run_udp_probe(
            safe_ip,
            priority_ports,
            timeout=0.8,
            concurrency=200,
        )
        identity_found = False
        for res in udp_probe:
            if (
                res.get("port") == 5353
                and res.get("state") == "responded"
                and res.get("response_bytes", 0) > 0
            ):
                phase0 = host_record.setdefault("phase0_enrichment", {})
                if not phase0.get("mdns_name"):
                    phase0["mdns_name"] = "mdns_response"
                identity_found = True
                break

        return identity_found

    def _reserve_deep_scan_slot(self, budget: int) -> Tuple[bool, int]:
        if not isinstance(budget, int) or budget <= 0:
            return True, 0
        lock = getattr(self, "_deep_budget_lock", None)
        if lock is None:
            lock = threading.Lock()
            setattr(self, "_deep_budget_lock", lock)
        with lock:
            deep_count = getattr(self, "_deep_executed_count", 0)
            if deep_count >= budget:
                return False, deep_count
            setattr(self, "_deep_executed_count", deep_count + 1)
            return True, deep_count + 1

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

    def deep_scan_host(self, host_ip, trusted_ports: List[int] = None):
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
        deep_obj: Dict[str, Any] = {"strategy": "adaptive_v2.8", "commands": []}

        self.ui.print_status(
            self.ui.t("deep_identity_start", safe_ip, self.ui.t("deep_strategy_adaptive")),
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
            # Phase 1: Aggressive TCP - ALWAYS -p- (65,535 ports) as per scan logic diagram
            # Infrastructure devices should be excluded via identity_strong at evaluation level
            cmd_p1 = [
                "nmap",
                "-A",
                "-Pn",
                safe_ip,
            ]

            # v4.6.0: Trust HyperScan Optimization
            # If enabled and we have discovery ports, use them instead of -p-
            # v4.6.2: Handle "Mute" hosts (0 ports). If untrusted -> -p- (def). If trusted -> top-1000 sanity check.
            if self.config.get("trust_hyperscan"):
                if trusted_ports is not None:
                    # Case A: Ports found (Speed++)
                    if len(trusted_ports) > 0:
                        port_list = ",".join(map(str, trusted_ports))
                        cmd_p1 = [
                            "nmap",
                            "-A",
                            "-Pn",
                            f"-p{port_list}",
                            "--open",
                            "--version-intensity",
                            "9",
                            safe_ip,
                        ]
                        self.ui.print_status(
                            f"⚡ Trust HyperScan active: Scanning {len(trusted_ports)} ports instead of 65k",
                            "OKBLUE",
                        )
                    # Case B: No ports found (Sanity Check)
                    else:
                        # Scan top 1000 ports to be safe, but fast (skip 64k empty ports)
                        cmd_p1 = [
                            "nmap",
                            "-A",
                            "-Pn",
                            "--top-ports",
                            "1000",
                            "--open",
                            "--version-intensity",
                            "9",
                            safe_ip,
                        ]
                        self.ui.print_status(
                            "⚡ Trust HyperScan active: 0 ports found, sanity checking top-1000",
                            "OKBLUE",
                        )

            self.ui.print_status(
                self.ui.t("deep_identity_cmd", safe_ip, " ".join(cmd_p1), "120-180"), "WARNING"
            )
            rec1: Dict[str, Any] = run_nmap_command(
                cmd_p1,
                DEEP_SCAN_TIMEOUT,
                safe_ip,
                deep_obj,
                logger=self.logger,
                dry_run=bool(self.config.get("dry_run", False)),
                proxy_manager=self.proxy_manager,
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
                self.ui.print_status(self.ui.t("deep_scan_skip"), "OKGREEN")
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
                self.ui.print_status(
                    self.ui.t(
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
                        # v3.10.1: Perform OUI vendor lookup for neighbor cache MACs
                        if not deep_obj.get("vendor"):
                            try:
                                neigh_vendor = get_vendor_with_fallback(
                                    neigh_mac, None, online_fallback=True
                                )
                                if neigh_vendor:
                                    deep_obj["vendor"] = neigh_vendor
                            except Exception:
                                pass

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
                    self.ui.print_status(
                        self.ui.t("deep_udp_full_cmd", safe_ip, " ".join(cmd_p2b), udp_top_ports),
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
                        proxy_manager=self.proxy_manager,
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
        self.ui.print_status(self.ui.t("deep_identity_done", safe_ip, total_dur), "OKGREEN")
        return deep_obj

    def scan_network_discovery(self, network):
        """Perform network discovery scan."""
        self.current_phase = f"discovery:{network}"
        self._set_ui_detail(f"[nmap] {network} discovery")
        self.logger.info("Discovery on %s", network)
        args = get_nmap_arguments("rapido", self.config)  # v3.9.0: Pass config for timing
        self.ui.print_status(self.ui.t("nmap_cmd", network, f"nmap {args} {network}"), "INFO")

        # v4.0: Delegate to NetworkScanner (cleaner, robust error handling)
        nm, err = self.scanner.run_nmap_scan(network, args)

        if err:
            self.logger.error("Discovery failed on %s: %s", network, err)
            self.ui.print_status(self.ui.t("scan_error", err), "FAIL")
            return []

        if not nm:
            return []

        hosts_out = []
        for ip in nm.all_hosts():
            if nm[ip].state() == "up":
                # v4.0: Populate central Host model
                host_obj = self.scanner.get_or_create_host(ip)
                host_obj.status = "up"

                # Extract discovery metadata
                if "addresses" in nm[ip]:
                    addrs = nm[ip]["addresses"]
                    if "mac" in addrs:
                        host_obj.mac_address = addrs["mac"]

                if "vendor" in nm[ip]:
                    # python-nmap vendor is {mac: name}
                    for mac, vendor in nm[ip]["vendor"].items():
                        if mac == host_obj.mac_address:
                            host_obj.vendor = vendor
                            break

                if "hostnames" in nm[ip]:
                    for h_rec in nm[ip]["hostnames"]:
                        if h_rec.get("name"):
                            host_obj.hostname = h_rec["name"]
                            break

                hosts_out.append(ip)

        self.ui.print_status(self.ui.t("hosts_active", network, len(hosts_out)), "OKGREEN")
        return hosts_out

    def scan_host_ports(self, host):
        """
        Scan ports on a single host.
        Accepts IP string or Host object (v4.0).
        """
        if isinstance(host, Host):
            safe_ip = host.ip
        else:
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
        self.ui.print_status(self.ui.t("nmap_cmd", safe_ip, f"nmap {args} {safe_ip}"), "INFO")
        if is_dry_run(self.config.get("dry_run")):
            host_obj = self.scanner.get_or_create_host(safe_ip)
            host_obj.status = STATUS_DOWN
            host_obj.raw_nmap_data = {"dry_run": True}
            return host_obj
        phase0_enrichment: Dict[str, Any] = {}
        if self.config.get("low_impact_enrichment"):
            phase0_enrichment = self._run_low_impact_enrichment(safe_ip)

        # v4.1: HyperScan-First optimization - now uses discovery results
        # All HyperScan work happens in _run_hyperscan_discovery() before ThreadPoolExecutor
        is_full_mode = mode_label in ("full", "completo")
        hyperscan_first_enabled = (
            is_full_mode
            and not self.config.get("stealth")
            and not self.config.get("no_hyperscan_first")
        )

        # v4.5.17: Always check for HyperScan ports (for port preservation, even if not in full mode)
        discovery_ports: List[int] = []
        if "_hyperscan_discovery_ports" in self.__dict__:
            discovery_ports = self._hyperscan_discovery_ports.get(safe_ip, [])

        if hyperscan_first_enabled and discovery_ports:
            # Use pre-discovered ports for nmap fingerprinting (-A includes -sV -sC -O)
            port_list = ",".join(str(p) for p in discovery_ports)
            args = f"-A -Pn -p {port_list}"
            timing = self.config.get("nmap_timing")
            if timing:
                args = f"-T{timing} {args}"
        else:
            # No discovery results or not in full mode - fall back to standard nmap scan
            args = get_nmap_arguments(self.config["scan_mode"], self.config)

        self._set_ui_detail(f"[nmap] {safe_ip} ({mode_label})")
        self.logger.debug("Nmap scan %s %s", safe_ip, args)
        self.ui.print_status(self.ui.t("nmap_cmd", safe_ip, f"nmap {args} {safe_ip}"), "INFO")

        try:
            # v4.0: Use NetworkScanner direct execution
            nm, scan_error = self.scanner.run_nmap_scan(safe_ip, args)
            if not nm:
                self.logger.warning("Nmap scan failed for %s: %s", safe_ip, scan_error)
                self.ui.print_status(
                    f"⚠️  Nmap scan failed {safe_ip}: {scan_error}",
                    "FAIL",
                    force=True,
                )
                mac, vendor = self._lookup_topology_identity(safe_ip)
                if not mac:
                    mac = get_neighbor_mac(safe_ip)
                    # v3.10.1: Perform OUI vendor lookup for neighbor cache MACs
                    if mac and not vendor:
                        try:
                            vendor = get_vendor_with_fallback(mac, None, online_fallback=True)
                        except Exception:
                            pass
                deep_meta = None
                if mac or vendor:
                    deep_meta = {"strategy": "topology", "commands": []}
                    if mac:
                        deep_meta["mac_address"] = mac
                    if vendor:
                        deep_meta["vendor"] = vendor
                    deep_meta["vendor"] = vendor

                # v4.0: Populate Host model on scan failure (topology only)
                host_obj = self.scanner.get_or_create_host(safe_ip)
                host_obj.status = STATUS_NO_RESPONSE
                host_obj.raw_nmap_data = {"error": scan_error}
                if deep_meta:
                    host_obj.deep_scan = deep_meta

                # Preserve result dict for phase0 logic below if needed, but we return object
                if self.config.get("low_impact_enrichment"):
                    host_obj.phase0_enrichment = phase0_enrichment or {}

                return host_obj

            if safe_ip not in nm.all_hosts():
                # v4.2: Deferred deep scan
                # We mark it for deep scan trigger
                deep = None
                # But we must update the host object later to indicate pending deep scan
                pass

                # v4.5.16: Preserve HyperScan-discovered ports when nmap doesn't find host
                preserved_ports = []
                if discovery_ports:
                    for mp in discovery_ports:
                        preserved_ports.append(
                            {
                                "port": mp,
                                "protocol": "tcp",
                                "service": "hyperscan-discovered",
                                "product": "",
                                "version": "",
                                "extrainfo": "(Port found by HyperScan, not confirmed by nmap)",
                                "cpe": [],
                                "is_web_service": mp in (80, 443, 8080, 8443, 3000, 8000),
                            }
                        )
                    if self.logger:
                        self.logger.info(
                            "Host %s not in nmap results, preserving %d HyperScan ports: %s",
                            safe_ip,
                            len(discovery_ports),
                            discovery_ports[:10],
                        )

                base = {
                    "ip": safe_ip,
                    "hostname": "",
                    "ports": preserved_ports,
                    "web_ports_count": sum(1 for p in preserved_ports if p.get("is_web_service")),
                    "total_ports_found": len(preserved_ports),
                }
                if self.config.get("low_impact_enrichment"):
                    base["phase0_enrichment"] = phase0_enrichment or {}
                result = (
                    {**base, "status": STATUS_NO_RESPONSE, "deep_scan": deep}
                    if deep
                    else {**base, "status": STATUS_DOWN}
                )
                if deep and deep.get("os_detected"):
                    result["os_detected"] = deep["os_detected"]
                # Finalize status based on deep scan results
                result["status"] = finalize_host_status(result)

                # v4.0: Populate Host model
                host_obj = self.scanner.get_or_create_host(safe_ip)
                host_obj.status = result["status"]
                host_obj.deep_scan = result.get("deep_scan") or {}
                host_obj.phase0_enrichment = result.get("phase0_enrichment") or {}
                host_obj.raw_nmap_data = {"error": scan_error}

                # v4.2: Mark for decoupled deep scan since initial scan failed
                host_obj.smart_scan = {
                    "trigger_deep": True,
                    "deep_scan_executed": False,
                    "reason": "initial_scan_no_response",
                }

                if result.get("os_detected"):
                    host_obj.os_detected = result["os_detected"]

                return host_obj

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

            # v4.0: Populate Host model services
            host_obj = self.scanner.get_or_create_host(safe_ip)
            host_obj.services = []

            for proto in data.all_protocols():
                for p in data[proto]:
                    svc = data[proto][p]
                    name = svc.get("name", "") or ""
                    product = svc.get("product", "") or ""
                    version = svc.get("version", "") or ""
                    extrainfo = svc.get("extrainfo", "") or ""
                    cpe = svc.get("cpe") or []
                    is_web = is_web_service(name)
                    # v4.0.4: Port-based fallback for misidentified web services
                    # e.g., Juice Shop on port 3000 detected as "ppp" by nmap
                    if not is_web:
                        from redaudit.utils.constants import WEB_LIKELY_PORTS

                        if p in WEB_LIKELY_PORTS:
                            is_web = True
                            if self.logger:
                                self.logger.debug(
                                    "Port-based web detection for %s:%d (service=%s)",
                                    safe_ip,
                                    p,
                                    name or "unknown",
                                )
                    if is_web:
                        web_count += 1

                    if is_suspicious_service(name):
                        suspicious = True
                    if product or version:
                        any_version = True

                    # Track ports with no useful info for banner fallback
                    if not product and name in ("", "tcpwrapped", "unknown"):
                        unknown_ports.append(p)

                    # Add to Host model
                    svc_obj = Service(
                        port=p,
                        protocol=proto,
                        name=name,
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                        state=svc.get("state", "open"),
                        reason=svc.get("reason", ""),
                        tunnel=svc.get("tunnel", ""),
                        cpe=(cpe if isinstance(cpe, list) else [cpe]) if cpe else [],
                    )
                    host_obj.add_service(svc_obj)

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

            # v4.5.16: Preserve HyperScan-discovered ports that nmap missed
            # This handles timing issues where ports close between HyperScan and nmap
            if self.logger:
                self.logger.info(
                    "[PORT-PRESERVE] %s: discovery_ports=%s, nmap_ports=%d",
                    safe_ip,
                    discovery_ports[:5] if discovery_ports else [],
                    len(ports),
                )
            if discovery_ports:
                nmap_port_nums = {p["port"] for p in ports}
                missing_ports = [p for p in discovery_ports if p not in nmap_port_nums]
                if missing_ports and self.logger:
                    self.logger.info(
                        "Preserving %d HyperScan ports not confirmed by nmap for %s: %s",
                        len(missing_ports),
                        safe_ip,
                        missing_ports[:10],  # Log first 10
                    )
                for mp in missing_ports:
                    ports.append(
                        {
                            "port": mp,
                            "protocol": "tcp",
                            "service": "hyperscan-discovered",
                            "product": "",
                            "version": "",
                            "extrainfo": "(Port found by HyperScan, not confirmed by nmap)",
                            "cpe": [],
                            "is_web_service": mp in (80, 443, 8080, 8443, 3000, 8000),
                        }
                    )

            # v4.0: Authenticated Scanning Integration (Phase 4)
            # Check if we have credentials for this host (CLI/Wizard or stored)
            ssh_credential = self._resolve_ssh_credential(safe_ip)

            if ssh_credential:
                # Check for open SSH port (22 or service name "ssh")
                ssh_port = 22
                ssh_open = False

                # Check if 22 is open in discovered ports
                for p_dict in ports:
                    if p_dict["port"] == 22:
                        ssh_open = True
                        break

                # If 22 wasn't found, check if any port is "ssh"
                if not ssh_open:
                    for p_dict in ports:
                        if p_dict["service"] == "ssh":
                            ssh_port = p_dict["port"]
                            ssh_open = True
                            break

                if ssh_open:
                    if hasattr(self, "ui") and self.ui:
                        self.ui.print_status(
                            self.ui.t("auth_scan_start", safe_ip, ssh_credential.username), "INFO"
                        )

                    # v4.5.15: Default to True for automated scanning environments
                    trust_keys = self.config.get("auth_ssh_trust_keys", True)
                    timeout = self.config.get("timeout", 30)

                    ssh_scanner = SSHScanner(
                        ssh_credential,
                        timeout=int(timeout) if timeout else 30,
                        trust_unknown_keys=trust_keys,
                    )

                    try:
                        if ssh_scanner.connect(safe_ip, port=ssh_port):
                            if hasattr(self, "ui") and self.ui:
                                self.ui.print_status(self.ui.t("auth_scan_connected"), "OKBLUE")

                            info = ssh_scanner.gather_host_info()
                            host_obj.auth_scan = asdict(info)

                            # Merge high-fidelity OS detection
                            if info.os_name and info.os_name != "unknown":
                                host_obj.os_detected = f"{info.os_name} {info.os_version}".strip()

                            # v4.3: Lynis Integration
                            should_run_lynis = self.config.get("lynis_enabled")
                            is_linux = "linux" in (info.os_name or "").lower()

                            if should_run_lynis and is_linux:
                                try:
                                    from redaudit.core.auth_lynis import LynisScanner

                                    if hasattr(self, "ui") and self.ui:
                                        self.ui.print_status(
                                            self.ui.t("auth_scan_start", safe_ip, "Lynis"), "INFO"
                                        )

                                    lynis = LynisScanner(ssh_scanner)
                                    l_res = lynis.run_audit(use_portable=True)

                                    if l_res:
                                        if not host_obj.auth_scan:
                                            host_obj.auth_scan = {}
                                        host_obj.auth_scan["lynis_hardening_index"] = (
                                            l_res.hardening_index
                                        )
                                        if hasattr(self, "ui") and self.ui:
                                            self.ui.print_status(
                                                f"Lynis Index: {l_res.hardening_index}", "OKBLUE"
                                            )

                                except Exception as e:
                                    if self.logger:
                                        self.logger.error("Lynis audit failed: %s", e)

                            ssh_scanner.close()
                    except SSHConnectionError as e:
                        if hasattr(self, "ui") and self.ui:
                            self.ui.print_status(self.ui.t("auth_scan_failed", str(e)), "WARN")
                        host_obj.auth_scan = {"error": str(e)}
                    except Exception as e:
                        if self.logger:
                            self.logger.error(
                                "Auth scan error on %s: %s", safe_ip, e, exc_info=True
                            )
                        host_obj.auth_scan = {"error": str(e)}

            # v4.2: SMB/WMI Authenticated Scan (Impacket)
            # Check port 445 (SMB) - Prefer 445 over 139 for modern Windows
            smb_open = False
            if host_obj.services:
                smb_open = any(s.port == 445 and s.state == "open" for s in host_obj.services)

            # Resolve credentials
            smb_credential = self._resolve_smb_credential(safe_ip)

            if smb_open and smb_credential:
                try:
                    from redaudit.core.auth_smb import SMBScanner

                    self._set_ui_detail(self.ui.t("auth_scan_start", safe_ip, "SMB"))

                    # Instantiate scanner
                    smb_scanner = SMBScanner(smb_credential)

                    # Connect
                    # Try 445 first
                    if smb_scanner.connect(safe_ip, 445):
                        self._set_ui_detail(self.ui.t("auth_scan_connected", safe_ip, "SMB"))

                        # Gather Info
                        info = smb_scanner.gather_host_info()
                        smb_scanner.close()

                        smb_data = asdict(info)

                        # Merge into auth_scan
                        # We use 'smb' namespace effectively or just merge
                        # Let's clean up 'unknown' values to avoid noise
                        clean_data = {k: v for k, v in smb_data.items() if v and v != "unknown"}

                        if not host_obj.auth_scan:
                            host_obj.auth_scan = {}

                        if isinstance(host_obj.auth_scan, dict):
                            host_obj.auth_scan.update(clean_data)

                        # Update OS detection if confident
                        if info.os_name and info.os_name != "unknown":
                            combined = f"{info.os_name} {info.os_version}".strip()
                            if (
                                not host_obj.os_detected
                                or "unknown" in host_obj.os_detected.lower()
                            ):
                                host_obj.os_detected = combined

                except ImportError:
                    if self.config.get("verbose"):
                        self.logger.warning("Impacket not installed, skipping SMB scan")
                except Exception as e:
                    if self.logger:
                        self.logger.error("SMB scan error on %s: %s", safe_ip, e)
                    # Graceful fail

            # v4.3: SNMP v3 Authenticated Scan (PySNMP)
            snmp_open = False
            if host_obj.services:
                snmp_open = any(
                    s.port == 161 and s.protocol == "udp" and "open" in s.state
                    for s in host_obj.services
                )

            snmp_credential = self._resolve_snmp_credential(safe_ip)

            if snmp_open and snmp_credential:
                try:
                    from redaudit.core.auth_snmp import SNMPScanner

                    self._set_ui_detail(self.ui.t("auth_scan_start", safe_ip, "SNMP"))

                    scanner = SNMPScanner(snmp_credential)
                    info = scanner.get_system_info(safe_ip)

                    snmp_data = asdict(info)
                    clean_data = {k: v for k, v in snmp_data.items() if v and v != "unknown"}

                    if not host_obj.auth_scan:
                        host_obj.auth_scan = {}

                    if isinstance(host_obj.auth_scan, dict):
                        host_obj.auth_scan.update(clean_data)

                    if info.sys_descr and info.sys_descr != "unknown":
                        current = host_obj.os_detected or ""
                        # Don't duplicate if already present
                        if info.sys_descr not in current:
                            host_obj.os_detected = (current + " " + info.sys_descr).strip()

                except ImportError:
                    if self.config.get("verbose"):
                        self.logger.warning("PySNMP not installed, skipping SNMP scan")
                except Exception as e:
                    if self.logger:
                        self.logger.error("SNMP scan error on %s: %s", safe_ip, e)

            total_ports = len(ports)
            if total_ports > MAX_PORTS_DISPLAY:
                self.ui.print_status(self.ui.t("ports_truncated", safe_ip, total_ports), "WARNING")
                ports = ports[:MAX_PORTS_DISPLAY]

            host_record = {
                "ip": safe_ip,
                "hostname": sanitize_hostname(hostname) or "",
                "ports": ports,
                "web_ports_count": web_count,
                "status": data.state(),
                "total_ports_found": total_ports,
            }
            if self.config.get("low_impact_enrichment"):
                host_record["phase0_enrichment"] = phase0_enrichment or {}

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
                self.ui.print_status(self.ui.t("banner_grab", safe_ip, len(unknown_ports)), "INFO")
                banner_info = banner_grab_fallback(
                    safe_ip,
                    unknown_ports,
                    logger=self.logger,
                    proxy_manager=self.proxy_manager,
                )
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

            identity_score, identity_signals = self._compute_identity_score(host_record)
            device_type_hints = host_record.get("device_type_hints") or []

            if self.logger:
                self.logger.debug(
                    "Identity signals for %s: score=%s (%s), device_hints=%s",
                    safe_ip,
                    identity_score,
                    ",".join(identity_signals) or "none",
                    ",".join(device_type_hints) or "none",
                )

            is_full_mode = self.config.get("scan_mode") in ("completo", "full")
            identity_threshold = self.config.get("identity_threshold", DEFAULT_IDENTITY_THRESHOLD)
            if not isinstance(identity_threshold, int) or identity_threshold < 0:
                identity_threshold = DEFAULT_IDENTITY_THRESHOLD
            if is_full_mode and identity_threshold < 4:
                identity_threshold = 4

            trigger_deep, deep_reasons = self._should_trigger_deep(
                total_ports=total_ports,
                any_version=any_version,
                suspicious=suspicious,
                device_type_hints=device_type_hints,
                identity_score=identity_score,
                identity_threshold=identity_threshold,
            )

            # v4.0.4: Use HyperScan results to override deep scan decision
            # HyperScan runs during net_discovery and may detect ports that nmap's quick scan missed
            nd_results = (
                self.results.get("net_discovery", {}) if isinstance(self.results, dict) else {}
            )
            hyperscan_ports = (nd_results.get("hyperscan_tcp_hosts") or {}).get(safe_ip, [])
            if hyperscan_ports and not trigger_deep:
                # HyperScan found ports but we decided not to deep scan - override
                if total_ports == 0:
                    trigger_deep = True
                    deep_reasons.append("hyperscan_ports_detected")
                    if self.logger:
                        self.logger.info(
                            "HyperScan detected %d ports on %s, forcing deep scan",
                            len(hyperscan_ports),
                            safe_ip,
                        )
                # Check for web ports in HyperScan results
                from redaudit.utils.constants import WEB_LIKELY_PORTS

                hyperscan_web_ports = [p for p in hyperscan_ports if p in WEB_LIKELY_PORTS]
                if hyperscan_web_ports and web_count == 0:
                    web_count = len(hyperscan_web_ports)
                    host_record["web_ports_count"] = web_count
                    if self.logger:
                        self.logger.info(
                            "HyperScan found web ports %s on %s, setting web_count=%d",
                            hyperscan_web_ports,
                            safe_ip,
                            web_count,
                        )

            # v4.0.4: Force web vuln scan for hosts with HTTP fingerprint from net_discovery
            # This fixes the detection gap where hosts passing identity threshold skip vuln scan
            agentless_fp = host_record.get("agentless_fingerprint") or {}
            if agentless_fp.get("http_title") or agentless_fp.get("http_server"):
                if web_count == 0:
                    web_count = 1  # Ensure host is included in web vulnerability scanning
                    host_record["web_ports_count"] = web_count
                    if self.logger:
                        self.logger.info(
                            "HTTP fingerprint detected for %s (%s), forcing web vuln scan",
                            safe_ip,
                            agentless_fp.get("http_title") or agentless_fp.get("http_server"),
                        )
                if not trigger_deep and total_ports == 0:
                    # Force deep scan to discover ports when we know HTTP is present
                    trigger_deep = True
                    deep_reasons.append("http_fingerprint_present")

            open_tcp_ports = sum(1 for p in ports if p.get("protocol") == "tcp")
            open_tcp_ports = sum(1 for p in ports if p.get("protocol") == "tcp")
            if (
                trigger_deep
                and not self.config.get("stealth_mode")
                and open_tcp_ports <= 1
                and identity_score < 2
            ):
                # udp_priority_used = True
                udp_identity = self._run_udp_priority_probe(host_record)
                if udp_identity:
                    identity_score, identity_signals = self._compute_identity_score(host_record)
                    device_type_hints = host_record.get("device_type_hints") or []
                    trigger_deep, deep_reasons = self._should_trigger_deep(
                        total_ports=total_ports,
                        any_version=any_version,
                        suspicious=suspicious,
                        device_type_hints=device_type_hints,
                        identity_score=identity_score,
                        identity_threshold=identity_threshold,
                    )
                    if identity_score >= identity_threshold:
                        trigger_deep = False
                        if "udp_resolved_identity" not in deep_reasons:
                            deep_reasons.append("udp_resolved_identity")

            if trigger_deep:
                budget = self.config.get("deep_scan_budget", 0)
                reserved, deep_count = self._reserve_deep_scan_slot(budget)
                if not reserved:
                    trigger_deep = False
                    deep_reasons.append("budget_exhausted")
                    if self.logger:
                        self.logger.info(
                            self.ui.t(
                                "deep_scan_budget_exhausted",
                                deep_count,
                                budget,
                                safe_ip,
                            )
                        )

            host_record["smart_scan"] = {
                "mode": self.config.get("scan_mode"),
                "identity_score": identity_score,
                "identity_threshold": identity_threshold,
                "signals": identity_signals,
                "suspicious_service": suspicious,
                "trigger_deep": bool(trigger_deep),
                "reasons": deep_reasons,
                "deep_scan_executed": False,
                "escalation_reason": "|".join(deep_reasons) if deep_reasons else None,
                "escalation_path": None,
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
                            self.ui.print_status(
                                self.ui.t("exploits_found", len(exploits), f"{product} {version}"),
                                "WARNING",
                            )

            if trigger_deep:
                # v4.2: Deep scan is now decoupled. Just mark passing the signal.
                # The orchestrator will run deep_scan_host later.

                if isinstance(host_record.get("smart_scan"), dict):
                    host_record["smart_scan"]["deep_scan_suggested"] = True

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
                        proxy_manager=self.proxy_manager,
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
                            self._prune_weak_identity_reasons(smart)

            enrich_host_with_dns(host_record, self.extra_tools)
            # v3.10.1: Consolidate DNS reverse from phase0 if enrichment failed
            if not host_record.get("dns", {}).get("reverse"):
                phase0 = host_record.get("phase0_enrichment", {})
                if phase0.get("dns_reverse"):
                    host_record.setdefault("dns", {})["reverse"] = [str(phase0["dns_reverse"])]
            enrich_host_with_whois(host_record, self.extra_tools)

            # v2.8.0: Finalize status based on all collected data
            host_record["status"] = finalize_host_status(host_record)

            # v4.0: Sync final enrichment data to Host model
            host_obj.hostname = host_record.get("hostname") or host_obj.hostname
            host_obj.ports = ports
            host_obj.web_ports_count = int(host_record.get("web_ports_count", 0) or 0)
            host_obj.total_ports_found = int(host_record.get("total_ports_found", 0) or 0)
            host_obj.device_type_hints = host_record.get("device_type_hints") or []
            host_obj.dns = host_record.get("dns", {})
            host_obj.status = host_record.get("status")
            host_obj.risk_score = host_record.get("risk_score", 0.0)
            if host_record.get("deep_scan"):
                host_obj.deep_scan = host_record["deep_scan"]
                deep_meta = host_record["deep_scan"]
                if deep_meta.get("mac_address"):
                    host_obj.mac_address = deep_meta["mac_address"]
                if deep_meta.get("vendor"):
                    host_obj.vendor = deep_meta["vendor"]
            if host_record.get("os_detected"):
                host_obj.os_detected = host_record["os_detected"]
            if host_record.get("phase0_enrichment"):
                host_obj.phase0_enrichment = host_record["phase0_enrichment"]
            if host_record.get("agentless_fingerprint"):
                host_obj.agentless_fingerprint = host_record["agentless_fingerprint"]
            if host_record.get("agentless_probe"):
                host_obj.agentless_probe = host_record["agentless_probe"]
            if host_record.get("smart_scan"):
                host_obj.smart_scan = host_record["smart_scan"]

            return host_obj

        except Exception as exc:
            self.logger.error("Scan error %s: %s", safe_ip, exc, exc_info=True)
            # Keep terminal output clean while progress UIs are active.
            self.ui.print_status(f"⚠️  Scan error {safe_ip}: {exc}", "FAIL", force=True)

            # v4.0: Return Host object on error
            host_obj = self.scanner.get_or_create_host(safe_ip)
            # We don't overwrite existing data on error, just status if needed?
            # Actually, standard behavior is to return a result indicating error.
            # We'll map the error state to the object for this scan session.

            result_dict = {"ip": safe_ip, "error": str(exc)}
            try:
                deep = None
                if self.config.get("deep_id_scan", True):
                    budget = self.config.get("deep_scan_budget", 0)
                    reserved, deep_count = self._reserve_deep_scan_slot(budget)
                    if not reserved:
                        if self.logger:
                            self.logger.info(
                                self.ui.t(
                                    "deep_scan_budget_exhausted",
                                    deep_count,
                                    budget,
                                    safe_ip,
                                )
                            )
                    else:
                        deep = self.deep_scan_host(safe_ip)
                        if deep:
                            result_dict["deep_scan"] = deep
                            result_dict["status"] = finalize_host_status(result_dict)

                            # Sync to Host object
                            host_obj.deep_scan = deep
                            host_obj.status = result_dict["status"]
                            if deep.get("os_detected"):
                                host_obj.os_detected = deep["os_detected"]

            except Exception:
                if self.logger:
                    self.logger.debug("Deep scan fallback failed for %s", safe_ip, exc_info=True)
                pass
            return host_obj

    def _run_hyperscan_discovery(self, host_ips: List[str]) -> Dict[str, List[int]]:
        """
        v4.1: Run HyperScan-First sequentially on all hosts BEFORE parallel nmap.

        This avoids file descriptor exhaustion by running HyperScan one at a time
        (or with limited concurrency), allowing higher batch_size for efficiency.

        Returns:
            Dict mapping IP -> list of discovered open ports
        """
        from redaudit.core.hyperscan import hyperscan_full_port_sweep

        # Check if HyperScan-First is enabled
        mode_label = self.config.get("scan_mode", "")
        is_full_mode = mode_label in ("full", "completo")
        if not is_full_mode or self.config.get("stealth") or self.config.get("no_hyperscan_first"):
            return {}

        # Initialize the discovery dict (use __dict__ to avoid __getattr__ recursion)
        if "_hyperscan_discovery_ports" not in self.__dict__:
            self._hyperscan_discovery_ports = {}

        # Check for existing masscan results to reuse
        net_discovery = self.results.get("net_discovery") or {}
        redteam = net_discovery.get("redteam") or {}
        masscan_result = redteam.get("masscan") or {}
        masscan_open = masscan_result.get("open_ports") or []

        # Build masscan port index
        masscan_ports: Dict[str, List[int]] = {}
        for entry in masscan_open:
            if isinstance(entry, dict):
                ip = entry.get("ip")
                port = entry.get("port")
                if ip and isinstance(port, int) and 1 <= port <= 65535:
                    if ip not in masscan_ports:
                        masscan_ports[ip] = []
                    masscan_ports[ip].append(port)

        discovery_count = len(host_ips)
        self.ui.print_status(
            self.ui.t("hyperscan_start").format(discovery_count),
            "INFO",
        )

        start_time = time.time()
        # Run HyperScan sequentially (one at a time to avoid FD exhaustion)
        for idx, ip in enumerate(host_ips, 1):
            if self.interrupted:
                break

            # Check if masscan already has ports for this host
            if ip in masscan_ports:
                self._hyperscan_discovery_ports[ip] = sorted(set(masscan_ports[ip]))
                self.ui.print_status(
                    self.ui.t("hyperscan_masscan_reuse").format(
                        idx, discovery_count, ip, len(masscan_ports[ip])
                    ),
                    "OKGREEN",
                )
                continue

            # Run HyperScan for this host
            try:
                ports = hyperscan_full_port_sweep(
                    ip,
                    batch_size=2000,  # High batch_size is safe with sequential execution
                    timeout=0.5,
                    logger=self.logger,
                )
                self._hyperscan_discovery_ports[ip] = ports
                if ports:
                    self.ui.print_status(
                        self.ui.t("hyperscan_ports_found").format(
                            idx, discovery_count, ip, len(ports)
                        ),
                        "OKGREEN",
                    )
                else:
                    self.ui.print_status(
                        self.ui.t("hyperscan_no_ports").format(idx, discovery_count, ip),
                        "WARNING",
                    )
            except Exception as e:
                self.logger.warning("HyperScan discovery failed for %s: %s", ip, e)
                self._hyperscan_discovery_ports[ip] = []  # Empty = fallback to nmap

        duration = time.time() - start_time
        total_ports = sum(len(p) for p in self._hyperscan_discovery_ports.values())
        self.ui.print_status(
            self.ui.t("hyperscan_complete").format(total_ports, duration),
            "OKGREEN",
        )

        return self._hyperscan_discovery_ports

    def run_deep_scans_concurrent(self, hosts):
        """v4.2: Run deep scans concurrently on selected hosts."""
        if not hosts:
            return

        self.ui.print_status(self.ui.t("deep_scan_running").format(len(hosts)), "HEADER")
        workers = int(self.config.get("threads", 1))
        # Cap at 50 to avoid system exhaustion, but respect aggression
        workers = max(1, min(50, workers))

        # Try to use rich for better progress visualization
        use_rich = self.ui.get_progress_console() is not None

        # Deduplicate hosts for Deep Scan
        unique_map = {}
        import re

        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        for h in hosts:
            if hasattr(h, "ip"):
                raw_ip = h.ip
                val = h
            else:
                raw_ip = str(h)
                val = raw_ip

            clean_ip = ansi_escape.sub("", raw_ip).strip()
            if clean_ip and clean_ip not in unique_map:
                unique_map[clean_ip] = val

        unique_hosts = [unique_map[ip] for ip in sorted(unique_map.keys())]

        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {}

                def _deep_worker(host):
                    try:
                        ip = host.ip if hasattr(host, "ip") else str(host)
                        host_obj = host if hasattr(host, "ip") else None

                        # Mark execution if it's a Host object
                        if host_obj and hasattr(host_obj, "smart_scan") and host_obj.smart_scan:
                            host_obj.smart_scan["deep_scan_executed"] = True

                        # Check budget
                        budget = self.config.get("deep_scan_budget", 0)
                        reserved, deep_count = self._reserve_deep_scan_slot(budget)
                        if not reserved:
                            if self.logger:
                                self.logger.info(f"Deep scan budget exhausted for {ip}")
                            return

                        # v4.6.0: Pass discovery ports
                        disc_ports = self._hyperscan_discovery_ports.get(ip, [])
                        deep = self.deep_scan_host(ip, trusted_ports=disc_ports)
                        if deep and host_obj:
                            host_obj.deep_scan = deep
                            if deep.get("os_detected"):
                                host_obj.os_detected = deep["os_detected"]
                            # Re-finalize status
                            host_obj.status = finalize_host_status(host_obj.to_dict())
                    except Exception as e:
                        if self.logger:
                            img_ip = host.ip if hasattr(host, "ip") else str(host)
                            self.logger.error(f"Deep scan error for {img_ip}: {e}", exc_info=True)

                for h in unique_hosts:
                    if self.interrupted:
                        break
                    fut = executor.submit(_deep_worker, h)
                    futures[fut] = h.ip

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    # v4.2: Multi-bar progress for DeepScan (consistent with host scan)
                    progress = self.ui.get_standard_progress(transient=False)
                    if progress:
                        with progress:
                            # Track per-host start times and tasks
                            host_tasks = {}  # future -> (task_id, ip, start_time)
                            for fut, ip in futures.items():
                                task_id = progress.add_task(
                                    f"[cyan]  {ip}",
                                    total=100,
                                    start=True,
                                )
                                host_tasks[fut] = (task_id, ip, time.time())

                            pending = set(futures)
                            last_heartbeat = time.time()
                            start_t = time.time()
                            # Deep scan typically takes longer, use generous estimate for bar pacing
                            deep_timeout_est = 120  # Nominal estimate for UI pacing

                            while pending:
                                if self.interrupted:
                                    for f in pending:
                                        f.cancel()
                                    break

                                completed, pending = wait(
                                    pending, timeout=0.5, return_when=FIRST_COMPLETED
                                )

                                now = time.time()
                                if now - last_heartbeat >= 60.0:
                                    elapsed = int(now - start_t)
                                    mins, secs = divmod(elapsed, 60)
                                    msg = f"Deep Scan... {done}/{total} ({mins}:{secs:02d})"
                                    progress.console.print(f"[dim]{msg}[/dim]")
                                    last_heartbeat = now

                                # Update progress for pending hosts
                                for pending_fut in pending:
                                    if pending_fut in host_tasks:
                                        task_id, ip, host_start = host_tasks[pending_fut]
                                        elapsed_host = now - host_start
                                        # Cap at 95% until complete
                                        pct = min(95, int((elapsed_host / deep_timeout_est) * 100))
                                        progress.update(task_id, completed=pct)

                                for fut in completed:
                                    if fut not in host_tasks:
                                        continue
                                    task_id, host_ip, _ = host_tasks[fut]
                                    done += 1
                                    try:
                                        fut.result()
                                        progress.update(
                                            task_id,
                                            completed=100,
                                            description=f"[green]✅ {host_ip}",
                                        )
                                    except Exception as e:
                                        self.logger.error(f"Deep scan error for {host_ip}: {e}")
                                        progress.update(
                                            task_id,
                                            completed=100,
                                            description=f"[red]❌ {host_ip}",
                                        )
                else:
                    # Fallback loop
                    for fut in as_completed(futures):
                        if self.interrupted:
                            for f in futures:
                                f.cancel()
                            break
                        host_ip = futures[fut]
                        try:
                            fut.result()
                        except Exception:
                            pass
                        done += 1
                        if total and done % max(1, total // 10) == 0:
                            self.ui.print_status(f"Deep Scan: {done}/{total}", "INFO", force=True)

    def scan_hosts_concurrent(self, hosts):
        """Scan multiple hosts concurrently with progress bar."""
        self.ui.print_status(self.ui.t("scan_start", len(hosts)), "HEADER")

        # v4.0: Deduplicate hosts (handling both str and Host objects)
        # v4.0: Deduplicate hosts (handling both str and Host objects)
        unique_map = {}
        from redaudit.core.models import Host
        import re

        # Regex to strip ANSI escape codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        for h in hosts:
            if isinstance(h, Host):
                raw_ip = h.ip
                val = h
            else:
                raw_ip = str(h)
                val = raw_ip

            # Sanitization: Strip ANSI codes and whitespace
            clean_ip = ansi_escape.sub("", raw_ip).strip()

            if clean_ip:
                if clean_ip in unique_map:
                    if self.logger:
                        self.logger.debug(
                            f"Duplicate host ignored in scan: '{clean_ip}' (raw: {repr(raw_ip)})"
                        )
                else:
                    unique_map[clean_ip] = val

        unique_hosts = [unique_map[ip] for ip in sorted(unique_map.keys())]
        results = []
        threads = max(1, int(self.config.get("threads", 1)))
        start_t = time.time()
        host_timeout_s = self._parse_host_timeout_s(
            get_nmap_arguments(self.config.get("scan_mode"), self.config)
        )
        if host_timeout_s is None:
            host_timeout_s = self._scan_mode_host_timeout_s()

        # Try to use rich for better progress visualization
        use_rich = self.ui.get_progress_console() is not None

        # Keep output quiet from the moment worker threads start.
        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for h in unique_hosts:
                    if self.interrupted:
                        break
                    fut = executor.submit(self.scan_host_ports, h)
                    # v4.0.4: Store IP string for progress display (not Host object)
                    futures[fut] = h.ip if hasattr(h, "ip") else str(h)
                    if self.rate_limit_delay > 0:
                        # A3: Jitter ±30% for IDS evasion
                        jitter = random.uniform(-0.3, 0.3) * self.rate_limit_delay
                        actual_delay = max(0.1, self.rate_limit_delay + jitter)
                        time.sleep(actual_delay)

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    # v4.2: Multi-bar progress - one bar per active host
                    progress = self.ui.get_standard_progress(transient=False)
                    if progress:
                        with progress:
                            # Track per-host start times and tasks
                            host_tasks = {}  # future -> (task_id, ip, start_time)
                            for fut, ip in futures.items():
                                task_id = progress.add_task(
                                    f"[cyan]  {ip}",
                                    total=100,
                                    start=True,
                                )
                                # v4.2 fix: Track individual host start time
                                host_tasks[fut] = (task_id, ip, time.time())

                            pending = set(futures)
                            last_heartbeat = start_t
                            while pending:
                                if self.interrupted:
                                    for pending_fut in pending:
                                        pending_fut.cancel()
                                    break

                                completed, pending = wait(
                                    pending, timeout=0.5, return_when=FIRST_COMPLETED
                                )

                                now = time.time()

                                # v3.8.1: Heartbeat every 60s for visibility
                                # v3.8.1: Heartbeat every 60s for visibility
                                if now - last_heartbeat >= 60.0:
                                    elapsed = int(now - start_t)
                                    mins, secs = divmod(elapsed, 60)
                                    # Use progress.console to print safely without breaking the Live display
                                    progress.console.print(
                                        f"[cyan][INFO][/cyan] {self.ui.t('scanning_hosts')}... {done}/{total} ({mins}:{secs:02d} elapsed)",
                                        highlight=False,
                                    )
                                    last_heartbeat = now

                                # Update progress for still-pending hosts
                                for pending_fut in pending:
                                    if pending_fut in host_tasks:
                                        task_id, ip, host_start = host_tasks[pending_fut]
                                        # v4.2 fix: Use per-host elapsed time
                                        elapsed_host = now - host_start
                                        # Cap at 95% until complete
                                        pct = min(
                                            95, int((elapsed_host / max(1, host_timeout_s)) * 100)
                                        )
                                        progress.update(task_id, completed=pct)

                                for fut in completed:
                                    if fut not in host_tasks:
                                        continue
                                    task_id, host_ip, _ = host_tasks[fut]
                                    try:
                                        res = fut.result()
                                        results.append(res)
                                        # Mark complete with green
                                        progress.update(
                                            task_id,
                                            completed=100,
                                            description=f"[green]✅ {host_ip}",
                                        )
                                    except Exception as exc:
                                        self.logger.error("Worker error for %s: %s", host_ip, exc)
                                        self.logger.debug(
                                            "Worker exception details for %s",
                                            host_ip,
                                            exc_info=True,
                                        )
                                        # Mark failed with red
                                        progress.update(
                                            task_id,
                                            completed=100,
                                            description=f"[red]❌ {host_ip}",
                                        )
                                    done += 1
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
                            self.ui.print_status(
                                f"{self.ui.t('progress', done, total)} ({mins}:{secs:02d} transcurrido)",
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

        # v4.2: Data Flow Pipeline - Extract findings from previous scans/phases
        from redaudit.core.agentless_verify import parse_smb_nmap, parse_ldap_rootdse

        for h in host_results:
            if not isinstance(h, Host):
                continue

            # Initialize if needed
            if not h.red_team_findings:
                h.red_team_findings = {}

            # Check for SMB findings in script output
            for svc in h.services:
                if svc.port == 445 and svc.script_output:
                    # Combine output for parsing
                    combined_out = "\n".join(svc.script_output.values())
                    if combined_out:
                        smb_data = parse_smb_nmap(combined_out)
                        if smb_data:
                            h.red_team_findings["smb"] = smb_data
                # Check for LDAP findings
                if svc.port in (389, 636) and svc.script_output:
                    combined_out = "\n".join(svc.script_output.values())
                    if combined_out:
                        ldap_data = parse_ldap_rootdse(combined_out)
                        if ldap_data:
                            h.red_team_findings["ldap"] = ldap_data

        targets = select_agentless_probe_targets(host_results)
        if not targets:
            self.ui.print_status(self.ui.t("windows_verify_none"), "INFO")
            return

        max_targets = int(self.config.get("windows_verify_max_targets", 20) or 20)
        max_targets = min(max(max_targets, 1), 200)
        if len(targets) > max_targets:
            targets = sorted(targets, key=lambda t: t.ip)[:max_targets]
            self.ui.print_status(self.ui.t("windows_verify_limit", max_targets), "WARNING")

        self.ui.print_status(self.ui.t("windows_verify_start", len(targets)), "HEADER")

        host_index = {}
        for h in host_results:
            # v4.4.3: Handle both dict and Host objects
            if isinstance(h, dict):
                ip = h.get("ip")
            else:
                ip = getattr(h, "ip", None)
            if ip:
                host_index[ip] = h

        results: List[Dict[str, Any]] = []

        workers = min(4, max(1, int(self.config.get("threads", 1))))
        start_t = time.time()

        use_rich = self.ui.get_progress_console() is not None

        with self._progress_ui():
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(
                        probe_agentless_services,
                        t,
                        logger=self.logger,
                        dry_run=bool(self.config.get("dry_run", False)),
                        proxy_manager=self.proxy_manager,
                    ): t.ip
                    for t in targets
                }

                total = len(futures)
                done = 0

                if use_rich and total > 0:
                    progress = self.ui.get_standard_progress(transient=False)
                    if progress:
                        with progress:
                            task = progress.add_task(
                                f"[cyan]{self.ui.t('windows_verify_label')}",
                                total=total,
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

                                    progress.update(
                                        task,
                                        advance=1,
                                        description=f"[cyan]{self.ui.t('windows_verify_label')} ({done}/{total})",
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
                            self.ui.print_status(
                                f"{self.ui.t('windows_verify_label')} {done}/{total} | ETA≈ {eta_est_val}",
                                "INFO",
                                force=True,
                            )

        for res in results:
            ip = res.get("ip")
            if not ip or ip not in host_index:
                continue
            host = host_index[ip]

            agentless_fp = summarize_agentless_fingerprint(res)

            if isinstance(host, dict):
                host["agentless_probe"] = res
                existing_fp = host.get("agentless_fingerprint") or {}
            else:
                setattr(host, "agentless_probe", res)
                existing_fp = getattr(host, "agentless_fingerprint", {}) or {}

            if existing_fp:
                merged = dict(existing_fp)
                for key, value in (agentless_fp or {}).items():
                    if value not in (None, ""):
                        merged[key] = value
                agentless_fp = merged

            if isinstance(host, dict):
                host["agentless_fingerprint"] = agentless_fp
                smart = host.get("smart_scan")
            else:
                setattr(host, "agentless_fingerprint", agentless_fp)
                smart = getattr(host, "smart_scan", None)

            if isinstance(smart, dict) and isinstance(agentless_fp, dict) and agentless_fp:
                signals = list(smart.get("signals") or [])
                if "agentless" not in signals:
                    signals.append("agentless")
                    try:
                        smart["identity_score"] = int(smart.get("identity_score", 0)) + 1
                    except Exception:
                        smart["identity_score"] = smart.get("identity_score", 0)
                    self._prune_weak_identity_reasons(smart)
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
