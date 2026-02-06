"""
Identity helpers shared across scanning and verification.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

INFRA_DEVICE_TYPES = frozenset(
    [
        "router",
        "switch",
        "gateway",
        "firewall",
        "modem",
        "ont",
        "repeater",
        "access_point",
        "access point",
        "ap",
        "network_device",
    ]
)

INFRA_KEYWORDS = frozenset(
    [
        "router",
        "gateway",
        "modem",
        "ont",
        "firewall",
        "switch",
        "repeater",
        "access point",
        "access_point",
        "fritz",
        "avm",
        "netgear",
        "tp-link",
        "asus",
        "linksys",
        "d-link",
        "ubiquiti",
        "unifi",
        "mikrotik",
        "routeros",
        "cisco",
        "aruba",
        "fortinet",
        "pfsense",
        "openwrt",
        "synology",
        "qnap",
        "hikvision",
        "dahua",
        "axis",
        "zyxel",
        "huawei",
        "vodafone",
        "samsung",
        "philips",
        "sonos",
        "roku",
    ]
)


def _normalize_text(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def is_infra_device_type(device_type: Optional[str]) -> bool:
    return _normalize_text(device_type) in INFRA_DEVICE_TYPES


def match_infra_keyword(text: Optional[str]) -> Optional[str]:
    haystack = _normalize_text(text)
    if not haystack:
        return None
    for keyword in INFRA_KEYWORDS:
        if keyword in haystack:
            return keyword
    return None


def is_infra_identity(
    *,
    device_type: Optional[str] = None,
    device_type_hints: Optional[Iterable[str]] = None,
    text: Optional[str] = None,
) -> Tuple[bool, str]:
    if is_infra_device_type(device_type):
        return True, "device_type"
    for hint in device_type_hints or []:
        if is_infra_device_type(hint):
            return True, "device_type_hint"
    keyword = match_infra_keyword(text)
    if keyword:
        return True, f"keyword:{keyword}"
    return False, ""
