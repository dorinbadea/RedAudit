#!/usr/bin/env python3
"""
RedAudit - Network Detection Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Handles local network interface detection and enumeration.
"""

import subprocess
import ipaddress
from typing import List, Dict, Optional

from redaudit.utils.i18n import get_text


def detect_interface_type(iface: str) -> str:
    """
    Classify network interface by type based on naming convention.

    Args:
        iface: Interface name (e.g., 'eth0', 'wlan0', 'tun0')

    Returns:
        Interface type string: 'Ethernet', 'Wi-Fi', 'VPN', or 'Other'
    """
    if iface.startswith("e"):
        return "Ethernet"
    if iface.startswith("w"):
        return "Wi-Fi"
    if iface.startswith(("tun", "tap")):
        return "VPN"
    return "Other"


def detect_networks_netifaces(lang: str = "en", print_fn=None) -> List[Dict]:
    """
    Detect local networks using netifaces library.

    Args:
        lang: Language for messages
        print_fn: Optional print function for status messages

    Returns:
        List of network dictionaries with interface, ip, network, etc.
    """
    nets = []
    try:
        import netifaces

        for iface in netifaces.interfaces():
            if iface.startswith(("lo", "docker", "br-", "veth")):
                continue
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for info in addrs[netifaces.AF_INET]:
                        ip_addr = info.get("addr")
                        mask = info.get("netmask")
                        if ip_addr and mask and ip_addr != "127.0.0.1":
                            net = ipaddress.ip_network(
                                f"{ip_addr}/{mask}", strict=False
                            )
                            nets.append({
                                "interface": iface,
                                "ip": ip_addr,
                                "network": f"{net.network_address}/{net.prefixlen}",
                                "hosts_estimated": max(net.num_addresses - 2, 0),
                                "type": detect_interface_type(iface),
                            })
            except Exception:
                continue
    except ImportError:
        if print_fn:
            print_fn(get_text("netifaces_missing", lang), "WARNING")

    return nets


def detect_networks_fallback(lang: str = "en") -> List[Dict]:
    """
    Detect local networks using 'ip addr show' command as fallback.

    Args:
        lang: Language for messages

    Returns:
        List of network dictionaries
    """
    nets = []
    try:
        res = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in res.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if iface.startswith(("lo", "docker", "br-", "veth")):
                continue
            try:
                ipi = ipaddress.ip_interface(parts[3])
                nets.append({
                    "interface": iface,
                    "ip": str(ipi.ip),
                    "network": str(ipi.network),
                    "hosts_estimated": max(ipi.network.num_addresses - 2, 0),
                    "type": detect_interface_type(iface),
                })
            except ValueError:
                continue
    except Exception:
        pass

    return nets


def detect_all_networks(lang: str = "en", print_fn=None) -> List[Dict]:
    """
    Detect all local networks using available methods.

    Tries netifaces first, falls back to ip command.

    Args:
        lang: Language for messages
        print_fn: Optional print function for status messages

    Returns:
        List of unique network dictionaries
    """
    nets = detect_networks_netifaces(lang, print_fn)
    if not nets:
        nets = detect_networks_fallback(lang)

    # Deduplicate by (network, interface)
    unique = {(n["network"], n["interface"]): n for n in nets}
    return list(unique.values())


def find_interface_for_ip(ip_str: str, networks: List[Dict]) -> Optional[str]:
    """
    Find the interface that contains a given IP address.

    Args:
        ip_str: IP address string
        networks: List of network dictionaries from detect_all_networks()

    Returns:
        Interface name or None if not found
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    return net.get("interface")
            except Exception:
                continue
    except ValueError:
        pass
    return None
