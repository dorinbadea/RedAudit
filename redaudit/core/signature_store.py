#!/usr/bin/env python3
"""
RedAudit - Signature Store

Provides data-driven signatures for device hints and false-positive filters.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_DEVICE_VENDOR_HINTS: List[Dict[str, Any]] = [
    {
        "device_type": "mobile",
        "vendors": ["apple", "samsung", "xiaomi", "huawei", "oppo", "oneplus"],
        "hostname_keywords": ["iphone", "ipad", "phone", "android"],
        "hostname_keywords_identity": [
            "iphone",
            "ipad",
            "ipod",
            "phone",
            "android",
            "galaxy",
            "pixel",
            "oneplus",
        ],
        "hostname_keywords_media_override": ["android"],
    },
    {
        "device_type": "workstation",
        "hostname_keywords": [
            "macbook",
            "imac",
            "laptop",
            "desktop",
            "workstation",
            "msi",
            "lenovo",
            "thinkpad",
            "dell",
            "hp",
            "hewlett",
            "asus",
            "acer",
        ],
        "hostname_regex": [r"\bpc\b"],
    },
    {
        "device_type": "printer",
        "vendors": ["hp", "canon", "epson", "brother", "lexmark", "xerox"],
        "hostname_keywords": [
            "printer",
            "laserjet",
            "officejet",
            "deskjet",
            "pixma",
            "imageclass",
            "canon",
            "epson",
        ],
    },
    {
        "device_type": "iot_lighting",
        "vendors": ["philips", "signify", "wiz", "yeelight", "lifx", "tp-link tapo"],
    },
    {
        "device_type": "iot",
        "vendors": ["tuya"],
    },
    {
        "device_type": "router",
        "vendors": [
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
        ],
        "hostname_keywords": ["router", "gateway", "modem", "ont", "cpe", "firewall"],
    },
    {
        "device_type": "smart_tv",
        "vendors": ["google", "amazon", "roku", "lg", "sony", "vizio"],
        "hostname_keywords": ["tv", "chromecast", "roku", "firetv", "shield"],
    },
    {
        "device_type": "vpn",
        "hostname_keywords": ["vpn", "ipsec", "wireguard", "openvpn", "tunnel"],
    },
]

DEFAULT_NUCLEI_TEMPLATE_VENDORS: Dict[str, Dict[str, Any]] = {
    "CVE-2022-26143": {
        "expected_vendors": ["mitel", "micollab", "mivoice"],
        "false_positive_vendors": [
            "fritz",
            "fritz!os",
            "avm",
            "netgear",
            "tp-link",
            "asus",
            "linksys",
            "ubiquiti",
        ],
        "description": "Mitel MiCollab Information Disclosure",
    },
    "CVE-2021-44228": {
        "expected_vendors": ["java", "log4j", "apache"],
        "false_positive_vendors": [],
        "description": "Log4Shell",
    },
    "CVE-2024-54767": {
        "expected_vendors": ["avm", "fritz"],
        "expected_models": ["7530"],
        "false_positive_models": ["7590", "repeater", "1200", "2400", "3000"],
        "description": "AVM FRITZ!Box 7530 AX Unauthorized Access",
    },
}


def _data_path(filename: str) -> Path:
    base = Path(__file__).resolve().parents[1]
    return base / "data" / filename


def _load_json(filename: str) -> Any:
    path = _data_path(filename)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def _sanitize_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v.strip()]


def _sanitize_device_vendor_hints(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, list):
        return []
    cleaned: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        device_type = entry.get("device_type")
        vendors = _sanitize_string_list(entry.get("vendors"))
        hostname_keywords = _sanitize_string_list(entry.get("hostname_keywords"))
        hostname_keywords_identity = _sanitize_string_list(entry.get("hostname_keywords_identity"))
        hostname_regex = _sanitize_string_list(entry.get("hostname_regex"))
        hostname_keywords_media_override = _sanitize_string_list(
            entry.get("hostname_keywords_media_override")
        )
        if not isinstance(device_type, str) or not device_type.strip():
            continue
        if not (
            vendors
            or hostname_keywords
            or hostname_keywords_identity
            or hostname_regex
            or hostname_keywords_media_override
        ):
            continue
        cleaned_entry: Dict[str, Any] = {"device_type": device_type.strip()}
        if vendors:
            cleaned_entry["vendors"] = vendors
        if hostname_keywords:
            cleaned_entry["hostname_keywords"] = hostname_keywords
        if hostname_keywords_identity:
            cleaned_entry["hostname_keywords_identity"] = hostname_keywords_identity
        if hostname_regex:
            cleaned_entry["hostname_regex"] = hostname_regex
        if hostname_keywords_media_override:
            cleaned_entry["hostname_keywords_media_override"] = hostname_keywords_media_override
        cleaned.append(cleaned_entry)
    return cleaned


def _has_hostname_hints(entry: Dict[str, Any]) -> bool:
    return any(
        entry.get(key)
        for key in (
            "hostname_keywords",
            "hostname_keywords_identity",
            "hostname_regex",
            "hostname_keywords_media_override",
        )
    )


def _load_device_hints() -> List[Dict[str, Any]]:
    data = _load_json("device_vendor_hints.json")
    cleaned = _sanitize_device_vendor_hints(data)
    return cleaned if cleaned else DEFAULT_DEVICE_VENDOR_HINTS


@lru_cache(maxsize=1)
def load_device_vendor_hints() -> List[Dict[str, Any]]:
    cleaned = _load_device_hints()
    vendor_only = [entry for entry in cleaned if entry.get("vendors")]
    return vendor_only if vendor_only else DEFAULT_DEVICE_VENDOR_HINTS


@lru_cache(maxsize=1)
def load_device_hostname_hints() -> List[Dict[str, Any]]:
    cleaned = _load_device_hints()
    hostname_only = [entry for entry in cleaned if _has_hostname_hints(entry)]
    if hostname_only:
        return hostname_only
    return [entry for entry in DEFAULT_DEVICE_VENDOR_HINTS if _has_hostname_hints(entry)]


@lru_cache(maxsize=1)
def load_nuclei_template_vendors() -> Dict[str, Dict[str, Any]]:
    data = _load_json("nuclei_template_vendors.json")
    if isinstance(data, dict) and data:
        return data
    return DEFAULT_NUCLEI_TEMPLATE_VENDORS
