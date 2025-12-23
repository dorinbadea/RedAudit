#!/usr/bin/env python3
"""
RedAudit - Entity Resolution Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v2.9: Asset reconciliation module for identifying and merging duplicate host entries
that represent the same physical device with multiple network interfaces.
"""

import re
from typing import Dict, List, Optional
from collections import defaultdict


def normalize_hostname(hostname: str) -> str:
    """
    Normalize a hostname for comparison.

    Removes domain suffixes, converts to lowercase, and strips whitespace.

    Args:
        hostname: Raw hostname string

    Returns:
        Normalized hostname
    """
    if not hostname:
        return ""

    # Convert to lowercase and strip
    h = hostname.lower().strip()

    # Remove common domain suffixes
    suffixes = [".fritz.box", ".local", ".lan", ".home", ".localdomain"]
    for suffix in suffixes:
        if h.endswith(suffix):
            h = h[: -len(suffix)]
            break

    return h


def extract_identity_fingerprint(host_record: Dict) -> Optional[str]:
    """
    Extract an identity fingerprint from a host record.

    Priority order:
    1. Resolved hostname (most reliable)
    2. NetBIOS name from deep scan
    3. mDNS name

    Args:
        host_record: Host record dictionary

    Returns:
        Identity fingerprint string or None if no identity found
    """
    # Priority 1: Hostname
    hostname = host_record.get("hostname", "")
    if hostname:
        normalized = normalize_hostname(hostname)
        if normalized and normalized != "unknown" and len(normalized) > 2:
            return normalized

    # Priority 2: Check deep scan for additional identity info
    deep_scan = host_record.get("deep_scan", {})
    if deep_scan:
        # Look for NetBIOS name in command outputs
        for cmd in deep_scan.get("commands", []):
            stdout = cmd.get("stdout", "") or ""

            # Pattern: NetBIOS name
            match = re.search(r"NetBIOS name:\s*([A-Z0-9\-_]+)", stdout, re.IGNORECASE)
            if match:
                return match.group(1).lower()

            # Pattern: Computer name
            match = re.search(r"Computer name:\s*([A-Z0-9\-_]+)", stdout, re.IGNORECASE)
            if match:
                return match.group(1).lower()

    # Priority 3: DNS reverse lookup
    dns_info = host_record.get("dns", {})
    if dns_info:
        reverse = dns_info.get("reverse", [])
        if reverse and isinstance(reverse, list) and reverse[0]:
            normalized = normalize_hostname(reverse[0])
            if normalized and len(normalized) > 2:
                return normalized

    return None


def determine_interface_type(mac: str, ip: str) -> str:
    """
    Determine the likely interface type based on MAC prefix.

    Args:
        mac: MAC address
        ip: IP address

    Returns:
        Interface type string (WiFi, Ethernet, Virtual, Unknown)
    """
    if not mac:
        return "Unknown"

    mac_upper = mac.upper().replace(":", "").replace("-", "")[:6]

    # Common WiFi adapter prefixes (Apple, Intel WiFi, Broadcom WiFi)
    wifi_prefixes = [
        "D843AE",  # Micro-Star (often WiFi)
        "1091D1",  # Intel Corporate (often Ethernet/Dock)
        "F4F26D",  # TP-Link
        "AC220B",  # ASUSTek WiFi
    ]

    # Common Ethernet prefixes
    ethernet_prefixes = [
        "1091D1",  # Intel (often Ethernet dock)
        "000C29",  # VMware
        "001B21",  # Intel Ethernet
    ]

    # Virtual/Docker prefixes
    virtual_prefixes = [
        "0242AC",  # Docker
        "000C29",  # VMware
        "005056",  # VMware
        "080027",  # VirtualBox
    ]

    for prefix in virtual_prefixes:
        if mac_upper.startswith(prefix):
            return "Virtual"

    for prefix in ethernet_prefixes:
        if mac_upper.startswith(prefix):
            return "Ethernet"

    for prefix in wifi_prefixes:
        if mac_upper.startswith(prefix):
            return "WiFi"

    return "Unknown"


def create_unified_asset(host_group: List[Dict]) -> Dict:
    """
    Create a unified asset from a group of hosts that represent the same device.

    Args:
        host_group: List of host records for the same physical device

    Returns:
        Unified asset dictionary
    """
    if not host_group:
        return {}

    if len(host_group) == 1:
        # Single host, convert to unified format
        host = host_group[0]
        asset_name = _derive_asset_name(host) or f"Host-{host.get('ip', 'unknown')}"
        return {
            "asset_name": asset_name,
            "asset_type": guess_asset_type(host),
            "interfaces": [
                {
                    "ip": host.get("ip"),
                    "mac": host.get("deep_scan", {}).get("mac_address"),
                    "type": "Primary",
                    "hostname": host.get("hostname"),
                }
            ],
            "consolidated_ports": host.get("ports", []),
            "status": host.get("status", "unknown"),
            "source_ips": [host.get("ip")],
        }

    # Multiple interfaces - merge them
    primary_host = host_group[0]
    asset_name = ""

    # Find best hostname
    for host in host_group:
        hostname = host.get("hostname", "")
        if hostname and hostname != "unknown":
            asset_name = hostname
            break

    if not asset_name:
        asset_name = (
            _derive_asset_name(primary_host)
            or f"MultiInterface-{primary_host.get('ip', 'unknown')}"
        )

    # Collect interfaces
    interfaces = []
    for host in host_group:
        deep = host.get("deep_scan", {})
        iface = {
            "ip": host.get("ip"),
            "mac": deep.get("mac_address"),
            "vendor": deep.get("vendor"),
            "hostname": host.get("hostname"),
        }

        # Try to determine interface type from vendor
        vendor = deep.get("vendor", "")
        if vendor:
            if "intel" in vendor.lower():
                iface["type"] = "Ethernet/Dock"
            elif "micro-star" in vendor.lower() or "realtek" in vendor.lower():
                iface["type"] = "WiFi"
            else:
                iface["type"] = vendor[:20]
        else:
            iface["type"] = determine_interface_type(
                deep.get("mac_address", ""), host.get("ip", "")
            )

        interfaces.append(iface)

    # Consolidate ports from all interfaces
    all_ports = []
    seen_ports = set()
    for host in host_group:
        for port in host.get("ports", []):
            port_key = (port.get("port"), port.get("protocol"))
            if port_key not in seen_ports:
                seen_ports.add(port_key)
                all_ports.append(port)

    # Sort ports by number
    all_ports.sort(key=lambda p: p.get("port", 0))

    # Determine best status (prefer "up")
    statuses = [h.get("status") for h in host_group if h.get("status")]
    best_status = "up" if "up" in statuses else (statuses[0] if statuses else "unknown")

    return {
        "asset_name": normalize_hostname(asset_name) or asset_name,
        "asset_type": guess_asset_type(primary_host),
        "interfaces": interfaces,
        "consolidated_ports": all_ports,
        "status": best_status,
        "source_ips": [h.get("ip") for h in host_group],
        "interface_count": len(interfaces),
    }


def guess_asset_type(host: Dict) -> str:
    """
    Guess the type of asset based on available information.

    Args:
        host: Host record dictionary

    Returns:
        Asset type string
    """
    hostname = (host.get("hostname") or "").lower()
    ports = host.get("ports", [])
    deep = host.get("deep_scan", {})
    vendor = (deep.get("vendor") or "").lower()
    device_hints = host.get("device_type_hints") or []
    agentless = host.get("agentless_fingerprint") or {}
    http_title = str(agentless.get("http_title") or "").lower()
    http_server = str(agentless.get("http_server") or "").lower()
    os_detected = str(host.get("os_detected") or deep.get("os_detected") or "").lower()
    port_services = []
    for port in ports:
        for key in ("service", "product", "extrainfo"):
            value = str(port.get(key) or "").lower()
            if value:
                port_services.append(value)

    # Generic gateway hint: mark default gateway as router when known.
    if host.get("is_default_gateway") is True:
        return "router"

    # Check hostname patterns (generic first, avoid brand-specific assumptions).
    if any(x in hostname for x in ["iphone", "ipad", "android", "phone"]):
        return "mobile"
    if any(x in hostname for x in ["macbook", "imac", "laptop", "desktop", "workstation"]):
        return "workstation"
    if re.search(r"\bpc\b", hostname):
        return "workstation"
    if any(x in hostname for x in ["printer", "canon", "epson"]):
        return "printer"
    if any(x in hostname for x in ["tv", "chromecast", "roku", "firetv", "shield"]):
        return "media"
    if any(x in hostname for x in ["router", "gateway", "modem", "ont", "cpe", "firewall"]):
        return "router"

    # Check device type hints (from discovery/agentless signals).
    if isinstance(device_hints, list):
        normalized_hints = {str(hint).lower() for hint in device_hints if hint}
        if "router" in normalized_hints:
            return "router"
        if "printer" in normalized_hints:
            return "printer"
        if "mobile" in normalized_hints or "apple_device" in normalized_hints:
            return "mobile"
        if "smart_tv" in normalized_hints or "chromecast" in normalized_hints:
            return "media"
        if "iot_lighting" in normalized_hints:
            return "iot"
        if "hypervisor" in normalized_hints:
            return "server"

    # Check agentless HTTP hints when hostname is missing.
    http_hint = f"{http_title} {http_server}".strip()
    if http_hint:
        if any(
            token in http_hint
            for token in (
                "router",
                "gateway",
                "modem",
                "broadband",
                "ont",
                "cpe",
                "firewall",
                "home hub",
                "homehub",
            )
        ):
            return "router"
        if "switch" in http_hint:
            return "switch"
        if vendor and any(
            x in vendor for x in ["zyxel", "netgear", "d-link", "tp-link", "ubiquiti"]
        ):
            if re.search(r"\b(gs|xgs|xs|sg)\d", http_hint):
                return "switch"

    # Check service/product fingerprints for media devices.
    if any(
        token in svc
        for svc in port_services
        for token in ("chromecast", "castv2", "google cast", "dlna", "airplay")
    ):
        return "media"

    # OS-based hints (best-effort).
    if "android" in os_detected:
        return "mobile"
    if "ios" in os_detected or "iphone" in os_detected or "ipad" in os_detected:
        return "mobile"

    # Check vendor
    if any(x in vendor for x in ["apple", "microsoft"]):
        return "workstation"
    if any(x in vendor for x in ["wiz", "philips", "tp-link"]):
        return "iot"
    if any(x in vendor for x in ["amazon", "google"]):
        return "smart_device"

    # Check ports
    port_nums = {p.get("port") for p in ports}
    if 22 in port_nums or 3389 in port_nums:
        return "server"
    if 80 in port_nums or 443 in port_nums:
        if len(ports) <= 3:
            return "iot"
        return "server"

    return "unknown"


def _derive_asset_name(host: Dict) -> str:
    """
    Derive a human-friendly asset name from available identity hints.
    """
    hostname = str(host.get("hostname") or "").strip()
    if hostname:
        return hostname

    agentless = host.get("agentless_fingerprint") or {}
    http_title = str(agentless.get("http_title") or "").strip()
    if http_title:
        vendor = str((host.get("deep_scan") or {}).get("vendor") or "").strip()
        if vendor and vendor.lower() not in http_title.lower():
            return f"{vendor} {http_title}".strip()
        return http_title

    return ""


def reconcile_assets(hosts: List[Dict], logger=None) -> List[Dict]:
    """
    Main entry point for entity resolution.

    Groups hosts by identity fingerprint and creates unified asset records.

    Args:
        hosts: List of host records from scanning
        logger: Optional logger

    Returns:
        List of unified asset dictionaries
    """
    if not hosts:
        return []

    # Group hosts by identity fingerprint
    groups: Dict[str, List[Dict]] = defaultdict(list)
    ungrouped = []

    for host in hosts:
        fingerprint = extract_identity_fingerprint(host)
        if fingerprint:
            groups[fingerprint].append(host)
        else:
            ungrouped.append(host)

    # Create unified assets
    unified = []
    multi_interface_count = 0

    for fingerprint, host_group in groups.items():
        asset = create_unified_asset(host_group)
        if asset:
            if len(host_group) > 1:
                multi_interface_count += 1
            unified.append(asset)

    # Add ungrouped hosts as single-interface assets
    for host in ungrouped:
        asset = create_unified_asset([host])
        if asset:
            unified.append(asset)

    # Sort by asset name
    unified.sort(key=lambda a: a.get("asset_name", "").lower())

    if logger and multi_interface_count > 0:
        logger.info(
            "Entity Resolution: consolidated %d multi-interface devices (%d total assets)",
            multi_interface_count,
            len(unified),
        )

    return unified
