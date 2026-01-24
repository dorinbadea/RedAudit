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
    },
    {
        "device_type": "printer",
        "vendors": ["hp", "canon", "epson", "brother", "lexmark", "xerox"],
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
    },
    {
        "device_type": "smart_tv",
        "vendors": ["google", "amazon", "roku", "lg", "sony", "vizio"],
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


def _sanitize_device_vendor_hints(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, list):
        return []
    cleaned: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        device_type = entry.get("device_type")
        vendors = entry.get("vendors")
        if not isinstance(device_type, str) or not device_type.strip():
            continue
        if not isinstance(vendors, list) or not vendors:
            continue
        vendors_clean = [v for v in vendors if isinstance(v, str) and v.strip()]
        if not vendors_clean:
            continue
        cleaned.append({"device_type": device_type.strip(), "vendors": vendors_clean})
    return cleaned


@lru_cache(maxsize=1)
def load_device_vendor_hints() -> List[Dict[str, Any]]:
    data = _load_json("device_vendor_hints.json")
    cleaned = _sanitize_device_vendor_hints(data)
    return cleaned if cleaned else DEFAULT_DEVICE_VENDOR_HINTS


@lru_cache(maxsize=1)
def load_nuclei_template_vendors() -> Dict[str, Dict[str, Any]]:
    data = _load_json("nuclei_template_vendors.json")
    if isinstance(data, dict) and data:
        return data
    return DEFAULT_NUCLEI_TEMPLATE_VENDORS
