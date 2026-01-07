#!/usr/bin/env python3
"""
RedAudit - OUI Lookup Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.6.1: Online fallback for MAC vendor lookup when local OUI database is incomplete.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# In-memory cache to avoid repeated API calls
_VENDOR_CACHE: Dict[str, Optional[str]] = {}

# Rate limiting: max 1 request per second (macvendors.com free tier)
_LAST_REQUEST_TIME: float = 0.0


def normalize_oui(mac: str) -> str:
    """
    Extract and normalize OUI (first 6 hex chars) from MAC address.

    Args:
        mac: MAC address in various formats (aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, etc.)

    Returns:
        Uppercase 6-character OUI string
    """
    return mac.replace(":", "").replace("-", "").replace(".", "")[:6].upper()


# v4.3.1: Offline fallback with local manuf database
# Loads from redaudit/data/manuf (Wireshark format)
_OFFLINE_CACHE: Dict[str, str] = {}


def _load_offline_db() -> None:
    """Load OUI database from local file."""
    import os

    global _OFFLINE_CACHE

    try:
        # Locate data file relative to this module
        # utils/oui_lookup.py -> ../data/manuf
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manuf_path = os.path.join(base_dir, "data", "manuf")

        if not os.path.exists(manuf_path):
            logger.debug("Local OUI database not found at %s", manuf_path)
            return

        count = 0
        with open(manuf_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Format: OUI<TAB>ShortName<TAB>LongName
                # 00:00:0C	Cisco	Cisco Systems, Inc
                parts = line.split("\t")
                if len(parts) >= 2:
                    oui_raw = parts[0].strip()
                    name = parts[2].strip() if len(parts) > 2 else parts[1].strip()

                    # Normalize OUI
                    oui = normalize_oui(oui_raw)
                    if len(oui) == 6:
                        _OFFLINE_CACHE[oui] = name
                        count += 1

        logger.debug("Loaded %d vendors from local OUI database", count)

    except Exception as e:
        logger.warning("Failed to load local OUI database: %s", e)


# Initialize on module load
_load_offline_db()


def lookup_vendor_online(mac: str, timeout: float = 2.0) -> Optional[str]:
    """
    Lookup vendor via macvendors.com API (free, no API key required).

    Args:
        mac: MAC address
        timeout: Request timeout in seconds

    Returns:
        Vendor name or None if not found/error
    """
    import time

    global _LAST_REQUEST_TIME

    if not mac:
        return None

    oui = normalize_oui(mac)
    if len(oui) < 6:
        return None

    # Check offline cache first (optimization + reliability)
    if oui in _OFFLINE_CACHE:
        return _OFFLINE_CACHE[oui]

    # Check session cache
    if oui in _VENDOR_CACHE:
        return _VENDOR_CACHE[oui]

    # Rate limiting
    now = time.time()
    if now - _LAST_REQUEST_TIME < 1.0:
        time.sleep(1.0 - (now - _LAST_REQUEST_TIME))

    try:
        import requests

        _LAST_REQUEST_TIME = time.time()
        response = requests.get(
            f"https://api.macvendors.com/{oui}",
            timeout=timeout,
            headers={"User-Agent": "RedAudit/3.6"},
        )

        if response.status_code == 200:
            vendor = response.text.strip()
            if vendor and len(vendor) < 100:  # Sanity check
                _VENDOR_CACHE[oui] = vendor
                logger.debug("OUI lookup success: %s -> %s", oui, vendor)
                return vendor

        elif response.status_code == 404:
            # Not found - cache the miss
            _VENDOR_CACHE[oui] = None
            logger.debug("OUI lookup miss: %s", oui)

    except ImportError:
        logger.warning("requests library not available for OUI lookup")
    except Exception as e:
        logger.debug("OUI lookup failed for %s: %s", oui, e)

    return None


def is_locally_administered(mac: str) -> bool:
    """
    Check if MAC is a Locally Administered Address (LAA).
    Checks the 2nd least significant bit of the first byte (bit 1).
    x2, x6, xA, xE
    """
    if not mac:
        return False
    try:
        clean = mac.replace(":", "").replace("-", "").replace(".", "")
        if len(clean) < 2:
            return False
        first_byte = int(clean[:2], 16)
        return (first_byte & 0x02) != 0
    except ValueError:
        return False


def get_vendor_with_fallback(
    mac: str, local_vendor: Optional[str] = None, online_fallback: bool = True
) -> Optional[str]:
    """
    Get vendor name, falling back to online lookup if local is missing.
    v4.2: Returns "(MAC privado)" for Locally Administered Addresses.

    Args:
        mac: MAC address
        local_vendor: Vendor from local source (nmap, arp-scan)
        online_fallback: Whether to try online lookup

    Returns:
        Vendor name or None
    """
    # v4.2: Check Key: Private/Randomized MAC
    if is_locally_administered(mac):
        return "(MAC privado)"

    # If we already have a vendor, use it
    if local_vendor and local_vendor.strip():
        return local_vendor

    # Try online fallback
    if online_fallback and mac:
        return lookup_vendor_online(mac)

    return None


def clear_cache() -> None:
    """Clear the vendor cache (useful for testing)."""
    global _VENDOR_CACHE
    _VENDOR_CACHE.clear()
