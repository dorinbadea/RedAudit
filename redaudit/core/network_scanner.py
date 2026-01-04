"""
RedAudit - Network Scanner (Extracted from AuditorScanMixin)

This module provides standalone network scanning logic that can be tested
independently from the main Auditor class.

Part of v4.0 Architecture Refactoring - Phase 3.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

from redaudit.core.config_context import ConfigurationContext
from redaudit.core.ui_manager import UIManager
from redaudit.utils.constants import (
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
)


class NetworkScanner:
    """
    Standalone network scanner with dependency injection.

    This class encapsulates network scanning logic that was previously
    in AuditorScanMixin, allowing for easier testing and composability.
    """

    def __init__(
        self,
        config: ConfigurationContext,
        ui: UIManager,
        logger: Optional[logging.Logger] = None,
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

    # -------------------------------------------------------------------------
    # Identity Scoring (Pure Logic - No I/O)
    # -------------------------------------------------------------------------

    def compute_identity_score(self, host_record: Dict[str, Any]) -> Tuple[int, List[str]]:
        """
        Compute identity confidence score for a host.

        Returns:
            Tuple of (score, list of reasons)
        """
        score = 0
        reasons = []

        # --- MAC-derived identity ---
        mac = host_record.get("mac") or ""
        vendor = host_record.get("vendor") or ""

        if mac and mac.upper() not in ("UNKNOWN", ""):
            score += 10
            reasons.append("mac_present")

            if vendor and vendor.lower() not in ("unknown", ""):
                score += 15
                reasons.append(f"vendor:{vendor[:20]}")

        # --- Hostname quality ---
        hostname = host_record.get("hostname") or ""
        if hostname:
            hostname_lower = hostname.lower()
            # Weak: just reverse DNS
            if hostname_lower.startswith("dhcp") or hostname_lower.startswith("ip-"):
                score += 5
                reasons.append("hostname_weak")
            # Strong: appears to be a real name
            elif "." in hostname or len(hostname) > 6:
                score += 20
                reasons.append("hostname_strong")
            else:
                score += 10
                reasons.append("hostname_present")

        # --- Port/service richness ---
        ports = host_record.get("ports") or []
        if isinstance(ports, list):
            open_ports = [p for p in ports if p.get("state") == "open"]
            num_open = len(open_ports)

            if num_open >= 5:
                score += 15
                reasons.append(f"ports:{num_open}")
            elif num_open >= 2:
                score += 10
                reasons.append(f"ports:{num_open}")
            elif num_open >= 1:
                score += 5
                reasons.append(f"ports:{num_open}")

            # Check for version info
            has_version = any(p.get("version") for p in open_ports)
            if has_version:
                score += 10
                reasons.append("version_info")

        # --- OS detection ---
        os_info = host_record.get("os_detection") or ""
        if os_info and os_info.lower() not in ("unknown", ""):
            score += 15
            reasons.append("os_detected")

        # --- Smart scan hints ---
        smart = host_record.get("smart_scan") or {}
        if smart.get("classification"):
            score += 10
            reasons.append(f"classified:{smart['classification']}")

        return score, reasons

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
        if not ip_str:
            return ""
        try:
            return str(ipaddress.ip_address(ip_str.strip()))
        except ValueError:
            return ""

    @staticmethod
    def sanitize_hostname(hostname: str) -> str:
        """Sanitize hostname string."""
        if not hostname:
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


def create_network_scanner(
    config: ConfigurationContext,
    ui: UIManager,
    logger: Optional[logging.Logger] = None,
) -> NetworkScanner:
    """Factory function for NetworkScanner."""
    return NetworkScanner(config=config, ui=ui, logger=logger)
