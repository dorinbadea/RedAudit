#!/usr/bin/env python3
"""
RedAudit - Vulnerability Verification Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v2.9: Smart-Check module for filtering false positives from Nikto and other scanners.
Uses Content-Type verification and Magic Bytes to detect Soft 404s.
"""

import re
from typing import Dict, List, Optional, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.utils.dry_run import is_dry_run

# File extensions that suggest sensitive/binary content
SENSITIVE_EXTENSIONS = (".tar", ".zip", ".gz", ".bak", ".config", ".pem", ".key", ".pfx", ".p12")

# Expected Content-Types for binary archives (if we get JSON/HTML, it's a false positive)
BINARY_CONTENT_TYPES = (
    "application/octet-stream",
    "application/x-tar",
    "application/zip",
    "application/x-gzip",
    "application/x-pem-file",
    "application/x-x509-ca-cert",
)

# Content-Types that indicate a false positive when expecting binary
FALSE_POSITIVE_CONTENT_TYPES = (
    "application/json",
    "text/html",
    "text/plain",
    "text/xml",
    "application/xml",
)

# Magic bytes for common archive formats
MAGIC_BYTES = {
    "tar": b"ustar",  # Found at offset 257
    "gzip": b"\x1f\x8b",
    "zip": b"PK\x03\x04",
    "pem": b"-----BEGIN",
}

# Minimum expected size for backup files (1KB)
MIN_BACKUP_SIZE = 1024


def extract_path_from_finding(finding: str) -> Optional[str]:
    """
    Extract the path/filename from a Nikto finding line.

    Nikto findings typically contain paths like:
    + /backup.tar: This file may contain...
    + OSVDB-12345: /admin/.htpasswd found

    Args:
        finding: Raw Nikto finding line

    Returns:
        Extracted path or None
    """
    if not finding or not isinstance(finding, str):
        return None

    # Pattern 1: "+ /path: description"
    match = re.search(r"\+ (/[^\s:]+)", finding)
    if match:
        return match.group(1)

    # Pattern 2: "OSVDB-XXXX: /path found"
    match = re.search(r"OSVDB-\d+:\s*(/[^\s]+)", finding)
    if match:
        return match.group(1)

    # Pattern 3: Any path-like string
    match = re.search(r"(/[a-zA-Z0-9_\-./]+\.[a-z]+)", finding)
    if match:
        return match.group(1)

    return None


def is_sensitive_file(path: str) -> bool:
    """
    Check if a path refers to a potentially sensitive file type.

    Args:
        path: URL path

    Returns:
        True if file extension suggests sensitive content
    """
    if not path:
        return False
    return any(path.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS)


def verify_content_type(
    url: str,
    extra_tools: Optional[Dict] = None,
    timeout: int = 10,
    proxy_manager=None,
) -> Tuple[Optional[str], Optional[int]]:
    """
    Perform HEAD request to verify Content-Type of a URL.

    Args:
        url: Full URL to check
        extra_tools: Dict of available tool paths (uses curl if available)
        timeout: Request timeout in seconds
        proxy_manager: Optional proxy manager for command wrapping

    Returns:
        Tuple of (content_type, content_length) or (None, None) on error
    """
    curl_path = extra_tools.get("curl") if extra_tools else "curl"
    if not curl_path:
        curl_path = "curl"

    runner = CommandRunner(
        dry_run=is_dry_run(),
        default_timeout=float(timeout + 5),
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
        command_wrapper=get_proxy_command_wrapper(proxy_manager),
    )

    try:
        res = runner.run(
            [curl_path, "-I", "-s", "--max-time", str(timeout), "-k", url],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )

        headers = str(res.stdout or "")
        content_type = None
        content_length = None

        for line in headers.splitlines():
            line_lower = line.lower()
            if line_lower.startswith("content-type:"):
                content_type = line.split(":", 1)[1].strip().split(";")[0].strip()
            elif line_lower.startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        return content_type, content_length
    except Exception:
        return None, None


def is_false_positive_by_content_type(
    expected_ext: str, actual_content_type: Optional[str]
) -> bool:
    """
    Determine if a finding is a false positive based on Content-Type mismatch.

    Args:
        expected_ext: Expected file extension (e.g., '.tar')
        actual_content_type: Actual Content-Type from response

    Returns:
        True if this is likely a false positive
    """
    if not actual_content_type:
        return False  # Can't determine, keep the finding

    actual_lower = actual_content_type.lower()

    # If we expected a binary file but got JSON/HTML, it's a false positive
    if expected_ext in SENSITIVE_EXTENSIONS:
        if any(fp_type in actual_lower for fp_type in FALSE_POSITIVE_CONTENT_TYPES):
            return True

    return False


def is_false_positive_by_size(expected_ext: str, content_length: Optional[int]) -> bool:
    """
    Determine if a finding is a false positive based on suspiciously small size.

    Args:
        expected_ext: Expected file extension
        content_length: Content-Length from response

    Returns:
        True if file is too small to be a real backup/config
    """
    if content_length is None:
        return False  # Can't determine, keep the finding

    # Backup/archive files should be at least 1KB
    if expected_ext in (".tar", ".zip", ".gz", ".bak"):
        if content_length < MIN_BACKUP_SIZE:
            return True

    return False


def verify_magic_bytes(
    url: str,
    expected_ext: str,
    extra_tools: Optional[Dict] = None,
    timeout: int = 10,
    proxy_manager=None,
) -> Tuple[bool, str]:
    """
    v3.0: Download first 512 bytes and verify magic signature.

    This is the most reliable false positive detection method as it
    actually inspects the file content, not just headers.

    Args:
        url: Full URL to check
        expected_ext: Expected file extension (e.g., '.tar')
        extra_tools: Dict of available tool paths
        timeout: Request timeout in seconds
        proxy_manager: Optional proxy manager for command wrapping

    Returns:
        Tuple of (is_valid, reason)
        - is_valid: True if magic bytes match expected type
        - reason: Explanation for decision
    """
    curl_path = extra_tools.get("curl") if extra_tools else "curl"
    if not curl_path:
        curl_path = "curl"

    # Map extensions to expected magic bytes
    ext_to_magic = {
        ".tar": ("tar", 257),  # ustar at offset 257
        ".gz": ("gzip", 0),  # 1f 8b at offset 0
        ".zip": ("zip", 0),  # PK\x03\x04 at offset 0
        ".pem": ("pem", 0),  # -----BEGIN at offset 0
        ".key": ("pem", 0),  # Also PEM format
    }

    if expected_ext not in ext_to_magic:
        return True, "kept:no_magic_check_for_ext"

    magic_key, offset = ext_to_magic[expected_ext]
    expected_magic = MAGIC_BYTES.get(magic_key)

    if not expected_magic:
        return True, "kept:magic_not_defined"

    runner = CommandRunner(
        dry_run=is_dry_run(),
        default_timeout=float(timeout + 5),
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
        command_wrapper=get_proxy_command_wrapper(proxy_manager),
    )

    try:
        # Download first 512 bytes (enough for all signatures including tar at offset 257)
        res = runner.run(
            [curl_path, "-s", "-r", "0-511", "--max-time", str(timeout), "-k", url],
            capture_output=True,
            text=False,
            timeout=timeout + 5,
        )

        data = res.stdout if isinstance(res.stdout, (bytes, bytearray)) else b""
        if not data or len(data) < offset + len(expected_magic):
            return True, "kept:insufficient_data"

        # Check magic bytes at expected offset
        actual_bytes = data[offset : offset + len(expected_magic)]

        if actual_bytes == expected_magic:
            return True, "kept:magic_bytes_match"
        else:
            # Check if it looks like HTML/JSON (common false positive)
            if data.startswith(b"<!") or data.startswith(b"<html") or data.startswith(b"{"):
                return False, "filtered:magic_mismatch:got_html_or_json"
            return False, f"filtered:magic_mismatch:expected_{magic_key}"

    except Exception as e:
        return True, f"kept:magic_check_error:{str(e)[:30]}"


def verify_nikto_finding(
    finding: str,
    base_url: str,
    extra_tools: Optional[Dict] = None,
    proxy_manager=None,
) -> Tuple[bool, str]:
    """
    Verify a single Nikto finding to determine if it's a false positive.

    v3.0: Now includes magic byte verification for enhanced accuracy.

    Args:
        finding: Raw Nikto finding line
        base_url: Base URL for the target (e.g., "http://192.168.1.1:8189")
        extra_tools: Dict of available tool paths
        proxy_manager: Optional proxy manager for command wrapping

    Returns:
        Tuple of (is_valid, reason)
        - is_valid: True if finding should be kept
        - reason: Explanation for decision
    """
    path = extract_path_from_finding(finding)
    if not path:
        return True, "kept:no_path_extracted"

    # Only verify sensitive file findings
    if not is_sensitive_file(path):
        return True, "kept:not_sensitive_file"

    # Get file extension
    ext = ""
    for e in SENSITIVE_EXTENSIONS:
        if path.lower().endswith(e):
            ext = e
            break

    # Build full URL and verify
    full_url = base_url.rstrip("/") + path
    content_type, content_length = verify_content_type(
        full_url, extra_tools, proxy_manager=proxy_manager
    )

    # Check 1: Content-Type mismatch
    if is_false_positive_by_content_type(ext, content_type):
        return False, f"filtered:content_type_mismatch:{content_type}"

    # Check 2: Suspiciously small size
    if is_false_positive_by_size(ext, content_length):
        return False, f"filtered:too_small:{content_length}bytes"

    # Check 3 (v3.0): Magic byte verification
    is_valid, reason = verify_magic_bytes(full_url, ext, extra_tools, proxy_manager=proxy_manager)
    if not is_valid:
        return False, reason

    return True, "kept:verified"


def filter_nikto_false_positives(
    findings: List[str],
    base_url: str,
    extra_tools: Optional[Dict] = None,
    logger=None,
    proxy_manager=None,
) -> List[str]:
    """
    Filter a list of Nikto findings to remove false positives.

    This is the main entry point for v2.9 Smart-Check functionality.

    Args:
        findings: List of raw Nikto finding lines
        base_url: Base URL for the target
        extra_tools: Dict of available tool paths
        logger: Optional logger

    Returns:
        Filtered list of findings (false positives removed)
    """
    if not findings:
        return []

    verified = []
    filtered_count = 0

    for finding in findings:
        is_valid, reason = verify_nikto_finding(
            finding,
            base_url,
            extra_tools,
            proxy_manager=proxy_manager,
        )

        if is_valid:
            verified.append(finding)
        else:
            filtered_count += 1
            if logger:
                logger.debug("Nikto FP filtered: %s - %s", finding[:50], reason)

    if filtered_count > 0 and logger:
        logger.info(
            "Nikto Smart-Check: filtered %d false positives from %d findings",
            filtered_count,
            len(findings),
        )

    return verified


# =============================================================================
# v3.9.0: Nuclei False Positive Detection
# =============================================================================

# Mapping of CVE/template IDs to their expected vendor/product identifiers
# If the actual Server header doesn't match, it's likely a false positive
NUCLEI_TEMPLATE_VENDORS = {
    # Mitel MiCollab - often false positive on routers with JSON endpoints
    "CVE-2022-26143": {
        "expected_vendors": ["mitel", "micollab", "mivoice"],
        "false_positive_vendors": [
            "fritz",
            "avm",
            "netgear",
            "tp-link",
            "asus",
            "linksys",
            "ubiquiti",
        ],
        "description": "Mitel MiCollab Information Disclosure",
    },
    # Add more templates as FPs are discovered
    "CVE-2021-44228": {
        "expected_vendors": ["java", "log4j", "apache"],
        "false_positive_vendors": [],  # Log4j can affect many products
        "description": "Log4Shell",
    },
}

# Common router/device vendors that often trigger CVE false positives
COMMON_INFRASTRUCTURE_VENDORS = frozenset(
    [
        "fritz",
        "avm",
        "netgear",
        "tp-link",
        "asus",
        "linksys",
        "d-link",
        "ubiquiti",
        "mikrotik",
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
        "samsung",
        "philips",
        "sonos",
        "roku",
    ]
)


def check_nuclei_false_positive(
    finding: Dict,
    agentless_data: Optional[Dict] = None,
    logger=None,
) -> Tuple[bool, str]:
    """
    Check if a Nuclei finding is a likely false positive.

    v3.9.0: Detects FPs by comparing Server header/product identification
    against expected vendors for the CVE template.

    Args:
        finding: Nuclei finding dict with template_id, response, etc.
        agentless_data: Optional agentless fingerprint for the host
        logger: Optional logger

    Returns:
        Tuple of (is_false_positive, reason)
        - is_false_positive: True if this is likely a false positive
        - reason: Explanation for the decision
    """
    template_id = finding.get("template-id", "") or finding.get("template_id", "")
    if not template_id:
        return False, "no_template_id"

    # Check if we have vendor expectations for this template
    template_upper = template_id.upper()
    template_config = None
    for known_id, config in NUCLEI_TEMPLATE_VENDORS.items():
        if known_id.upper() in template_upper:
            template_config = config
            break

    if not template_config:
        return False, "no_vendor_config"

    # Type assertion for mypy: template_config is guaranteed to be Dict here
    assert isinstance(template_config, dict)

    # Extract server/product info from response
    response = finding.get("response", "")
    if not response:
        raw = finding.get("raw")
        if isinstance(raw, dict):
            response = raw.get("response", "") or ""
    server_header = ""
    for line in response.split("\r\n"):
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip().lower()
            break

    # Also check agentless fingerprint
    agentless_vendor = ""
    agentless_title = ""
    if agentless_data:
        agentless_vendor = (agentless_data.get("device_vendor") or "").lower()
        agentless_title = (agentless_data.get("http_title") or "").lower()

    # Combine all identifiers
    identifiers = f"{server_header} {agentless_vendor} {agentless_title}".lower()

    # Check if any expected vendor is present
    expected = template_config.get("expected_vendors", [])
    if any(v in identifiers for v in expected):
        return False, "expected_vendor_found"

    # Check if a known FP vendor is present
    fp_vendors = template_config.get("false_positive_vendors", [])
    for fp_vendor in fp_vendors:
        if fp_vendor in identifiers:
            return True, f"fp_vendor_detected:{fp_vendor}"

    # Check against common infrastructure devices
    for infra_vendor in COMMON_INFRASTRUCTURE_VENDORS:
        if infra_vendor in identifiers:
            # Only flag if none of the expected vendors are present
            if not any(v in identifiers for v in expected):
                return True, f"infrastructure_device:{infra_vendor}"

    return False, "no_fp_indicators"


def filter_nuclei_false_positives(
    findings: List[Dict],
    host_agentless: Optional[Dict[str, Dict]] = None,
    logger=None,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Filter Nuclei findings to separate genuine findings from likely false positives.

    Unlike Nikto filtering which removes FPs, this returns both lists so the
    auditor can review flagged findings if needed.

    Args:
        findings: List of Nuclei finding dicts
        host_agentless: Dict mapping IP -> agentless fingerprint data
        logger: Optional logger

    Returns:
        Tuple of (genuine_findings, suspected_fp_findings)
    """
    if not findings:
        return [], []

    genuine = []
    suspected_fps = []
    host_agentless = host_agentless or {}

    for finding in findings:
        host_ip = finding.get("ip", "") or finding.get("host", "")
        agentless_data = host_agentless.get(host_ip, {})
        if not agentless_data and isinstance(host_ip, str) and host_ip:
            trimmed = host_ip
            if "://" in trimmed:
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(trimmed)
                    trimmed = parsed.hostname or trimmed
                except Exception:
                    pass
            if trimmed.count(":") == 1:
                trimmed = trimmed.split(":", 1)[0]
            agentless_data = host_agentless.get(trimmed, {})

        is_fp, reason = check_nuclei_false_positive(finding, agentless_data, logger)

        if is_fp:
            # Mark as suspected FP but don't remove
            finding["suspected_false_positive"] = True
            finding["fp_reason"] = reason
            suspected_fps.append(finding)
            if logger:
                logger.info(
                    "Nuclei FP suspected: %s on %s - %s",
                    finding.get("template-id", "unknown"),
                    host_ip,
                    reason,
                )
        else:
            finding["suspected_false_positive"] = False
            genuine.append(finding)

    return genuine, suspected_fps
