#!/usr/bin/env python3
"""
Scanner Status Logic - RedAudit
Separated from scanner.py for modularity.
"""

import re
from typing import Dict, List, Optional

from redaudit.utils.constants import (
    STATUS_UP,
    STATUS_DOWN,
    STATUS_FILTERED,
    STATUS_NO_RESPONSE,
)


def extract_vendor_mac(text: str) -> tuple:
    """
    Extract MAC address and vendor from Nmap output.
    """
    if not text:
        return None, None
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str):
        text = str(text)
    # Standard Nmap MAC line: MAC Address: 00:11:22:33:44:55 (Vendor Name)
    match = re.search(r"MAC Address: ([0-9A-Fa-f:]+) \((.*?)\)", text)
    if match:
        return match.group(1), match.group(2)
    return None, None


def extract_os_detection(text: str) -> Optional[str]:
    """
    Extract OS detection information from Nmap output.
    """
    if not text:
        return None

    patterns = [
        r"OS details: (.+)",
        r"Running: (.+)",
        r"OS CPE: cpe:/o:([^\s]+)",
        r"Aggressive OS guesses: ([^,]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:100]

    return None


def extract_detailed_identity(text: str) -> Optional[Dict[str, str]]:
    """
    Extract detailed identity information from Nmap script output.
    Focuses on HTTP titles and known signatures (e.g., FRITZ!Repeater).
    """
    if not text:
        return None

    # Priority 1: HTTP Title
    # Example: |_http-title: FRITZ!Repeater
    title_match = re.search(r"\|_http-title:\s*(.+)$", text, re.MULTILINE)
    if title_match:
        title = title_match.group(1).strip()

        # FRITZ!Repeater Specific
        if "FRITZ!Repeater" in title:
            return {
                "vendor": "AVM",
                "model": "FRITZ!Repeater",
                "device_type": "iot_network_device",
                "os_detected": f"FRITZ!OS ({title})",
            }

        # FRITZ!Box Specific
        if "FRITZ!Box" in title:
            return {
                "vendor": "AVM",
                "model": "FRITZ!Box",
                "device_type": "router",
                "os_detected": f"FRITZ!OS ({title})",
            }

    return None


def output_has_identity(records: List[Dict]) -> bool:
    """
    Check if scan records contain sufficient identity information (MAC/OS).
    """
    for rec in records:
        stdout = rec.get("stdout", "") or ""
        stderr = rec.get("stderr", "") or ""
        # Ensure str type (may be bytes from subprocess)
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        combined = stdout + "\n" + stderr

        if not combined.strip():
            continue

        # Check for MAC address and vendor
        mac, vendor = extract_vendor_mac(combined)
        if mac or vendor:
            return True

        # Check for OS detection patterns
        os_patterns = [
            r"OS details?:",
            r"Running:\s*[A-Z]",
            r"OS CPE:",
            r"Aggressive OS guesses:",
            r"OS details:.*\(.*%\)",
            r"Device type:",
        ]

        for pattern in os_patterns:
            if re.search(pattern, combined, re.IGNORECASE | re.MULTILINE):
                return True

    return False


def finalize_host_status(host_record: Dict) -> str:
    """
    Finalize the 'status' of the host record based on all gathered data.
    """
    current_status = host_record.get("status", STATUS_DOWN)

    if current_status == STATUS_UP:
        return STATUS_UP

    # If ports were found, host is up regardless of MAC/vendor hints.
    # We prioritize ports because that's the most reliable sign of life.
    if host_record.get("ports") and len(host_record.get("ports", [])) > 0:
        return STATUS_UP

    deep_scan = host_record.get("deep_scan", {})
    if not deep_scan:
        return current_status

    # Check command outputs for any response indicators
    commands = deep_scan.get("commands", [])
    for cmd_record in commands:
        stdout = cmd_record.get("stdout", "") or ""
        if "Host is up" in stdout:
            return STATUS_FILTERED

        # Check for filtering messages
        if "filtered" in stdout.lower() and "unfiltered" not in stdout.lower():
            if "host is down" not in stdout.lower():
                return STATUS_FILTERED

    # Check for extracted metadata
    if deep_scan.get("mac_address") or deep_scan.get("vendor"):
        # We got MAC/vendor from deep commands even if status says down
        return STATUS_FILTERED

    # Check for OS detection
    os_info_list = deep_scan.get("os_detection", [])
    # os_detection is list of strings usually
    if os_info_list:
        return STATUS_FILTERED

    # Check simple command output analysis
    if output_has_identity(commands):
        return STATUS_FILTERED

    # If we ran commands but got minimal/no useful output
    if commands:
        all_output = "".join([c.get("stdout", "") + c.get("stderr", "") for c in commands])
        if len(all_output.strip()) < 10:
            return STATUS_NO_RESPONSE

    return STATUS_DOWN
