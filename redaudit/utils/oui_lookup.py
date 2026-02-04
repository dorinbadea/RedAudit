#!/usr/bin/env python3
"""
RedAudit - OUI Lookup Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.6.1: Online fallback for MAC vendor lookup when local OUI database is incomplete.
"""

import logging
import os
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
    return _normalize_mac_hex(mac)[:6]


# v4.3.1: Offline fallback with local manuf database
# Loads from redaudit/data/manuf (Wireshark format)
_OFFLINE_CACHE: Dict[str, str] = {}
_OFFLINE_CACHE_EXT: Dict[int, Dict[str, str]] = {}
_CUSTOM_OUI_LOADED = False


def _normalize_mac_hex(value: str) -> str:
    return value.replace(":", "").replace("-", "").replace(".", "").upper()


def _get_builtin_oui_path() -> str:
    # utils/oui_lookup.py -> ../data/manuf
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "data", "manuf")


def _normalize_oui_paths(paths: list[str]) -> list[str]:
    normalized = []
    seen = set()
    for path in paths:
        if not path:
            continue
        expanded = os.path.expanduser(path)
        if expanded in seen:
            continue
        seen.add(expanded)
        normalized.append(expanded)
    return normalized


def _resolve_custom_oui_paths() -> list[str]:
    paths: list[str] = []
    env_paths = os.environ.get("REDAUDIT_OUI_DB") or os.environ.get("REDAUDIT_OUI_PATH")
    if env_paths:
        for part in env_paths.split(os.pathsep):
            if part:
                paths.append(part)

    try:
        from redaudit.utils.config import load_config

        config = load_config()
        cfg_paths = config.get("oui_db_paths") or config.get("oui_db_path") or []
        if isinstance(cfg_paths, str):
            paths.append(cfg_paths)
        elif isinstance(cfg_paths, list):
            paths.extend([p for p in cfg_paths if isinstance(p, str)])
    except Exception:  # pragma: no cover
        pass

    # Auto-discover OUI DB under config dir (if user dropped Wireshark manuf file)
    try:
        from redaudit.utils.config import get_config_paths

        config_dir, _ = get_config_paths()
        for candidate in ("manuf", "oui.manuf", "oui.txt"):
            path = os.path.join(config_dir, candidate)
            paths.append(path)
    except Exception:  # pragma: no cover
        pass

    return _normalize_oui_paths(paths)


def _load_offline_db(paths: list[str]) -> None:
    """Load OUI database from local file(s). Later files override earlier ones."""
    count = 0
    for raw_path in _normalize_oui_paths(paths):
        if not os.path.exists(raw_path):
            continue
        try:
            with open(raw_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Format: OUI<TAB>ShortName<TAB>LongName
                    # 00:00:0C	Cisco	Cisco Systems, Inc
                    parts = line.split("\t")
                    if len(parts) < 2:
                        continue
                    oui_raw = parts[0].strip()
                    name = parts[2].strip() if len(parts) > 2 else parts[1].strip()

                    prefix_len = 24
                    oui_part = oui_raw
                    if "/" in oui_raw:
                        oui_part, prefix_len_str = oui_raw.split("/", 1)
                        try:
                            prefix_len = int(prefix_len_str)
                        except ValueError:
                            continue

                    if prefix_len % 4 != 0:
                        continue

                    hex_len = prefix_len // 4
                    prefix = _normalize_mac_hex(oui_part)[:hex_len]
                    if len(prefix) != hex_len:
                        continue

                    if prefix_len == 24:
                        _OFFLINE_CACHE[prefix] = name
                    else:
                        _OFFLINE_CACHE_EXT.setdefault(prefix_len, {})[prefix] = name
                    count += 1
        except Exception as exc:  # pragma: no cover
            logger.debug("Failed to load OUI database %s: %s", raw_path, exc)

    if count == 0:
        logger.debug("No vendors loaded from local OUI database")
    else:
        logger.debug("Loaded %d vendors from local OUI database", count)


def reload_oui_db(paths: Optional[list[str]] = None) -> None:
    """Reload OUI database caches (used by tests or dynamic updates)."""
    global _CUSTOM_OUI_LOADED
    _OFFLINE_CACHE.clear()
    _OFFLINE_CACHE_EXT.clear()
    builtin = _get_builtin_oui_path()
    load_paths = [builtin]
    if paths:
        load_paths.extend(paths)
        _CUSTOM_OUI_LOADED = True
    else:
        _CUSTOM_OUI_LOADED = False
    _load_offline_db(load_paths)


def _ensure_custom_oui_loaded() -> None:
    global _CUSTOM_OUI_LOADED
    if _CUSTOM_OUI_LOADED:
        return
    custom_paths = _resolve_custom_oui_paths()
    if custom_paths:
        _load_offline_db(custom_paths)
    _CUSTOM_OUI_LOADED = True


# Initialize on module load with builtin DB
reload_oui_db()


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

    clean = _normalize_mac_hex(mac)
    if len(clean) < 6:
        return None

    _ensure_custom_oui_loaded()

    # Check offline cache first (optimization + reliability)
    if _OFFLINE_CACHE_EXT:
        for prefix_len in sorted(_OFFLINE_CACHE_EXT.keys(), reverse=True):
            hex_len = prefix_len // 4
            if len(clean) < hex_len:
                continue
            prefix = clean[:hex_len]
            vendor = _OFFLINE_CACHE_EXT.get(prefix_len, {}).get(prefix)
            if vendor:
                return vendor

    oui = clean[:6]
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
    _ensure_custom_oui_loaded()

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
    _VENDOR_CACHE.clear()
