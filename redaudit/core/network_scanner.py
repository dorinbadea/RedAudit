"""
RedAudit - Network Scanner (Extracted from AuditorScan)

This module provides standalone network scanning logic that can be tested
independently from the main Auditor class.

Part of v4.0 Architecture Refactoring - Phase 3.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
import shutil
import socket
from typing import Any, Dict, List, Optional, Tuple

try:
    import nmap
except ImportError:
    nmap = None

from redaudit.core.scanner.nmap import run_nmap_command
from redaudit.utils.dry_run import is_dry_run

from redaudit.core.config_context import ConfigurationContext
from redaudit.core.models import Host
from redaudit.core.network import detect_all_networks
from redaudit.core.ui_manager import UIManager
from redaudit.utils.constants import (
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
)


class NetworkScanner:
    """
    Composed Network Scanner for RedAudit v4.0.
    Encapsulates all logic related to network discovery, Nmap execution,
    identity calculation, and result parsing.
    """

    def __init__(
        self,
        config: ConfigurationContext,
        ui: UIManager,
        logger=None,
        proxy_manager=None,
    ):
        """
        Initialize NetworkScanner.

        Args:
            config: Configuration context
            ui: UI manager for status output
            logger: Optional logger
        """
        self.config = config
        self.ui = ui
        self.logger = logger
        self.interrupted = False
        self.proxy_manager = proxy_manager

        # v4.0: Central Host Repository
        self.hosts: Dict[str, Host] = {}

    def get_or_create_host(self, ip: str) -> Host:
        """Get existing host or create new one."""
        if ip not in self.hosts:
            self.hosts[ip] = Host(ip=ip)
        return self.hosts[ip]

    def add_host(self, host: Host) -> None:
        """Add or update a host in the repository."""
        self.hosts[host.ip] = host

    # -------------------------------------------------------------------------
    # Network Discovery (Migrated)
    # -------------------------------------------------------------------------

    def detect_local_networks(self) -> List[Dict[str, Any]]:
        """Detect all local networks using net_discovery module."""
        self.ui.print_status(self.ui.t("analyzing_nets"), "INFO")
        lang = str(self.config.get("lang", "en"))
        return detect_all_networks(lang, self.ui.print_status)

    # -------------------------------------------------------------------------
    # Identity Scoring (Pure Logic - No I/O)
    # -------------------------------------------------------------------------

    def compute_identity_score(
        self,
        host_record: Dict[str, Any],
        net_discovery_results: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, List[str]]:
        """
        Compute identity confidence score and enrich device_type_hints.
        (Migrated from AuditorScan analysis logic).
        """
        if net_discovery_results is None:
            net_discovery_results = {}

        score = 0
        signals: List[str] = []
        ports = host_record.get("ports") or []
        device_type_hints: List[str] = []

        if host_record.get("hostname"):
            score += 1
            signals.append("hostname")
        if any(p.get("product") or p.get("version") for p in ports):
            score += 1
            signals.append("service_version")
        if any(p.get("cpe") for p in ports):
            score += 1
            signals.append("cpe")

        deep_meta = host_record.get("deep_scan") or {}
        if deep_meta.get("mac_address") or deep_meta.get("vendor"):
            score += 1
            signals.append("mac_vendor")
            vendor_lower = str(deep_meta.get("vendor") or "").lower()
            if any(
                x in vendor_lower
                for x in ("apple", "samsung", "xiaomi", "huawei", "oppo", "oneplus")
            ):
                device_type_hints.append("mobile")
            elif any(
                x in vendor_lower for x in ("hp", "canon", "epson", "brother", "lexmark", "xerox")
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

        hostname_lower = str(host_record.get("hostname") or "").lower()
        if any(x in hostname_lower for x in ("iphone", "ipad", "ipod", "macbook", "imac")):
            if "mobile" not in device_type_hints:
                device_type_hints.append("mobile")
        elif any(x in hostname_lower for x in ("android", "galaxy", "pixel", "oneplus")):
            if "mobile" not in device_type_hints:
                device_type_hints.append("mobile")

        if host_record.get("os_detected") or deep_meta.get("os_detected"):
            score += 1
            signals.append("os_detected")
        if any(p.get("banner") for p in ports):
            score += 1
            signals.append("banner")

        nd_hosts_ips = set()
        for h in net_discovery_results.get("arp_hosts", []) or []:
            nd_hosts_ips.add(h.get("ip"))
        for h in net_discovery_results.get("upnp_devices", []) or []:
            nd_hosts_ips.add(h.get("ip"))
        for svc in net_discovery_results.get("mdns_services", []):
            for addr in svc.get("addresses", []):
                nd_hosts_ips.add(addr)

        if host_record.get("ip") in nd_hosts_ips:
            score += 1
            signals.append("net_discovery")

        for upnp in net_discovery_results.get("upnp_devices", []) or []:
            if upnp.get("ip") == host_record.get("ip"):
                upnp_type = str(upnp.get("device_type") or upnp.get("st") or "").lower()
                if "router" in upnp_type or "gateway" in upnp_type:
                    device_type_hints.append("router")
                    score += 1
                    signals.append("upnp_router")
                elif "printer" in upnp_type:
                    device_type_hints.append("printer")
                elif "mediarenderer" in upnp_type or "mediaplayer" in upnp_type:
                    device_type_hints.append("smart_tv")
                break

        for svc in net_discovery_results.get("mdns_services", []):
            if host_record.get("ip") in svc.get("addresses", []):
                svc_type = str(svc.get("type") or "").lower()
                if "_ipp" in svc_type or "_printer" in svc_type:
                    device_type_hints.append("printer")
                elif "_airplay" in svc_type or "_raop" in svc_type:
                    device_type_hints.append("apple_device")
                elif "_googlecast" in svc_type:
                    device_type_hints.append("chromecast")
                elif "_hap" in svc_type or "_homekit" in svc_type:
                    device_type_hints.append("homekit")

        for p in ports:
            svc = str(p.get("service") or "").lower()
            prod = str(p.get("product") or "").lower()
            if any(x in svc or x in prod for x in ("ipp", "printer", "cups")):
                device_type_hints.append("printer")
            elif any(x in svc or x in prod for x in ("router", "mikrotik", "routeros")):
                device_type_hints.append("router")
            elif "esxi" in prod or "vmware" in prod or "vcenter" in prod:
                device_type_hints.append("hypervisor")

        agentless = host_record.get("agentless_fingerprint") or {}
        if agentless.get("http_title") or agentless.get("http_server"):
            score += 1
            signals.append("http_probe")

        phase0 = host_record.get("phase0_enrichment") or {}
        if phase0.get("dns_reverse"):
            score += 1
            signals.append("dns_reverse")
        if phase0.get("mdns_name"):
            score += 1
            signals.append("mdns_name")
        if phase0.get("snmp_sysDescr"):
            score += 1
            signals.append("snmp_sysDescr")

        host_record["device_type_hints"] = list(set(device_type_hints))
        return score, signals

    def should_trigger_deep_scan(
        self,
        *,
        total_ports: int,
        any_version: bool,
        suspicious: bool,
        device_type_hints: List[str],
        identity_score: int,
        identity_threshold: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Determine if deep scan should be triggered for a host.

        Returns:
            Tuple of (should_trigger, reason)
        """
        threshold = identity_threshold or self.config.identity_threshold

        # Always deep scan if identity is below threshold
        if identity_score < threshold:
            return True, f"low_identity:{identity_score}<{threshold}"

        # Deep scan suspicious services
        if suspicious:
            return True, "suspicious_service"

        # Deep scan if no version info and few ports
        if not any_version and total_ports <= 2:
            return True, "no_version_info"

        # Device type hints that warrant deep scan
        deep_scan_types = {"printer", "camera", "iot", "embedded", "unknown"}
        for hint in device_type_hints:
            if hint.lower() in deep_scan_types:
                return True, f"device_type:{hint}"

        return False, ""

    # -------------------------------------------------------------------------
    # Network Utilities (Pure Functions)
    # -------------------------------------------------------------------------

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Validate CIDR network notation."""
        try:
            ipaddress.ip_network(cidr.strip(), strict=False)
            return True
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def sanitize_ip(ip_str: str) -> str:
        """Sanitize IP address string."""
        if ip_str is None:
            return ""
        try:
            return str(ipaddress.ip_address(str(ip_str).strip()))
        except ValueError:
            return ""

    @staticmethod
    def sanitize_hostname(hostname: str) -> str:
        """Sanitize hostname string."""
        if not isinstance(hostname, str) or not hostname:
            return ""
        # Remove dangerous characters
        cleaned = re.sub(r"[^\w\.\-]", "", str(hostname))
        return cleaned[:253] if cleaned else ""

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is in private range."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.is_private
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int = 1000) -> List[str]:
        """
        Expand CIDR to list of IPs (with limit).

        Args:
            cidr: CIDR notation network
            max_hosts: Maximum hosts to return

        Returns:
            List of IP addresses as strings
        """
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            hosts = list(network.hosts())
            return [str(h) for h in hosts[:max_hosts]]
        except (ValueError, AttributeError):
            return []

    # -------------------------------------------------------------------------
    # DNS Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def reverse_dns(ip: str, timeout: float = 2.0) -> str:
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address to lookup
            timeout: Socket timeout in seconds

        Returns:
            Hostname or empty string
        """
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""
        finally:
            socket.setdefaulttimeout(None)

    # -------------------------------------------------------------------------
    # Host Status Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def is_host_up(host_record: Dict[str, Any]) -> bool:
        """Check if host is considered 'up'."""
        status = (host_record.get("status") or "").lower()
        return status not in (STATUS_DOWN, STATUS_NO_RESPONSE, "down", "no response", "")

    @staticmethod
    def get_open_ports(host_record: Dict[str, Any]) -> List[int]:
        """Get list of open port numbers from host record."""
        ports = host_record.get("ports") or []
        return [
            p.get("port")
            for p in ports
            if p.get("state") == "open" and isinstance(p.get("port"), int)
        ]

    @staticmethod
    def has_web_ports(host_record: Dict[str, Any]) -> bool:
        """Check if host has any web-related ports open."""
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        open_ports = set(NetworkScanner.get_open_ports(host_record))
        return bool(open_ports & web_ports)

    # -------------------------------------------------------------------------
    # Nmap Execution (Migrated)
    # -------------------------------------------------------------------------

    def run_nmap_scan(self, target: str, args: str) -> Tuple[Optional[Any], str]:
        """
        Run an nmap scan with XML output and timeout enforcement.

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
            host_timeout_s = self._get_default_host_timeout()

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
            proxy_manager=self.proxy_manager,
        )

        if rec.get("error"):
            return None, str(rec["error"])

        r_out = rec.get("stdout_full") or rec.get("stdout") or ""
        raw_stdout = self._coerce_text(r_out)
        xml_output = self._extract_nmap_xml(raw_stdout)
        if not xml_output:
            r_err = rec.get("stderr_full") or rec.get("stderr") or ""
            raw_stderr = self._coerce_text(r_err)
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

    def _get_default_host_timeout(self) -> float:
        mode = str(self.config.get("scan_mode") or "").strip().lower()
        if mode in ("fast", "rapido"):
            return 10.0
        if mode in ("full", "completo"):
            return 300.0
        return 60.0

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

    @staticmethod
    def _coerce_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value) if value is not None else ""


def create_network_scanner(
    config: ConfigurationContext,
    ui: UIManager,
    logger: Optional[logging.Logger] = None,
    proxy_manager=None,
) -> NetworkScanner:
    """Factory function for NetworkScanner."""
    return NetworkScanner(config=config, ui=ui, logger=logger, proxy_manager=proxy_manager)
