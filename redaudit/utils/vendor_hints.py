#!/usr/bin/env python3
"""
RedAudit - Vendor Hints Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.10.1: Infer vendor hints from hostnames when MAC vendor is unavailable.
"""

import re
from typing import Optional, Tuple, List

# Hostname patterns for vendor inference (pattern, vendor_name)
# These are conservative patterns to avoid false positives
HOSTNAME_VENDOR_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)^msi[_-]"), "MSI"),
    (re.compile(r"(?i)\biphone\b"), "Apple"),
    (re.compile(r"(?i)\bipad\b"), "Apple"),
    (re.compile(r"(?i)\bmacbook\b"), "Apple"),
    (re.compile(r"(?i)\bimac\b"), "Apple"),
    (re.compile(r"(?i)^apple[_-]"), "Apple"),
    (re.compile(r"(?i)fritz\.?box|\.fritz\.box$"), "AVM"),
    (re.compile(r"(?i)^vodafone[_-]"), "Vodafone"),
    (re.compile(r"(?i)\bwiz[_-]|\.wiz$"), "WiZ"),
    (re.compile(r"(?i)\bsynology\b|diskstation"), "Synology"),
    (re.compile(r"(?i)\bqnap\b"), "QNAP"),
    (re.compile(r"(?i)^hp[_-]|hewlett[_-]?packard"), "HP"),
    (re.compile(r"(?i)\bsamsung\b"), "Samsung"),
    (re.compile(r"(?i)\bxiaomi\b|\bmi[_-]"), "Xiaomi"),
    (re.compile(r"(?i)\bsonos\b"), "Sonos"),
    (re.compile(r"(?i)\bhue[_-]|philips[_-]?hue"), "Philips"),
    (re.compile(r"(?i)\bunifi\b|ubnt"), "Ubiquiti"),
    (re.compile(r"(?i)\braspberry\b|^rpi[_-]"), "Raspberry Pi"),
    (re.compile(r"(?i)\bdell[_-]"), "Dell"),
    (re.compile(r"(?i)\blenovo[_-]"), "Lenovo"),
    (re.compile(r"(?i)\basus[_-]"), "ASUS"),
    (re.compile(r"(?i)\bacer[_-]"), "Acer"),
    (re.compile(r"(?i)\bandroid[_-]"), "Android"),
    (re.compile(r"(?i)\bnest[_-]|google[_-]?home"), "Google"),
    (re.compile(r"(?i)\balexa\b|echo[_-]|amazon[_-]"), "Amazon"),
    (re.compile(r"(?i)\btp[_-]?link\b"), "TP-Link"),
    (re.compile(r"(?i)\bnetgear\b"), "NETGEAR"),
    (re.compile(r"(?i)\blinksys\b"), "Linksys"),
    (re.compile(r"(?i)\bd[_-]?link\b"), "D-Link"),
]


def infer_vendor_from_hostname(hostname: Optional[str]) -> Optional[str]:
    """
    Infer vendor name from hostname patterns.

    Args:
        hostname: Hostname string to analyze

    Returns:
        Vendor name with "(guess)" suffix if pattern matches, None otherwise
    """
    if not hostname or not isinstance(hostname, str):
        return None

    hostname = hostname.strip()
    if not hostname or hostname == "-":
        return None

    for pattern, vendor in HOSTNAME_VENDOR_PATTERNS:
        if pattern.search(hostname):
            return f"{vendor} (guess)"

    return None


def get_best_vendor(
    mac_vendor: Optional[str],
    hostname: Optional[str],
    *,
    allow_guess: bool = True,
) -> Optional[str]:
    """
    Get best available vendor name, preferring MAC vendor over hostname guess.

    Args:
        mac_vendor: Vendor from MAC OUI lookup
        hostname: Hostname for fallback guess
        allow_guess: Whether to allow hostname-based guessing

    Returns:
        Best available vendor name or None
    """
    # Prefer MAC vendor if valid
    if mac_vendor and isinstance(mac_vendor, str):
        vendor = mac_vendor.strip()
        # Skip "unknown" variants
        if vendor and "unknown" not in vendor.lower():
            return vendor

    # Fallback to hostname guess
    if allow_guess:
        return infer_vendor_from_hostname(hostname)

    return None
