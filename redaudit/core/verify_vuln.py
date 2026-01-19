#!/usr/bin/env python3
"""
RedAudit - Vulnerability Verification Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v2.9: Smart-Check module for filtering false positives from Nikto and other scanners.
Uses Content-Type verification and Magic Bytes to detect Soft 404s.
"""

import re
from typing import Dict, List, Optional, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.core.identity_utils import match_infra_keyword
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
            "fritz!os",  # v4.4.2: Explicit FRITZ!OS detection
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
    # v4.14: CVE-2024-54767 affects ONLY FRITZ!Box 7530 AX v7.59 or earlier
    # FRITZ!Box 7590, Repeaters, and other models are NOT affected
    "CVE-2024-54767": {
        "expected_vendors": ["avm", "fritz"],
        "expected_models": ["7530"],  # Must contain "7530" in model
        "false_positive_models": ["7590", "repeater", "1200", "2400", "3000"],
        "description": "AVM FRITZ!Box 7530 AX Unauthorized Access",
    },
}


def parse_cpe_components(cpe_string: str) -> Dict[str, str]:
    """
    Parse CPE 2.3 or 2.2 string into vendor, product, version components.

    v4.3: Smart-Check helper for CPE-based validation.

    Args:
        cpe_string: CPE string like 'cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*'
                   or 'cpe:/a:apache:httpd:2.4.50'

    Returns:
        Dict with 'vendor', 'product', 'version' (may be empty strings)
    """
    result = {"vendor": "", "product": "", "version": ""}

    if not cpe_string or not isinstance(cpe_string, str):
        return result

    cpe = cpe_string.strip().lower()

    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) >= 5:
            result["vendor"] = parts[3] if parts[3] != "*" else ""
            result["product"] = parts[4] if parts[4] != "*" else ""
        if len(parts) >= 6:
            result["version"] = parts[5] if parts[5] not in ("*", "-") else ""
    # CPE 2.2 format: cpe:/part:vendor:product:version
    elif cpe.startswith("cpe:/"):
        rest = cpe[5:]  # Remove 'cpe:/'
        parts = rest.split(":")
        if len(parts) >= 3:
            # parts[0] = 'a' (application), parts[1] = vendor, parts[2] = product
            result["vendor"] = parts[1] if len(parts) > 1 else ""
            result["product"] = parts[2] if len(parts) > 2 else ""
            result["version"] = parts[3] if len(parts) > 3 else ""

    return result


def validate_cpe_against_template(
    host_cpe_list: List[str],
    template_config: Dict,
) -> Tuple[bool, str]:
    """
    Validate host CPEs against expected vendors for a template.

    v4.3: Smart-Check CPE validation.

    Args:
        host_cpe_list: List of CPE strings from host scan
        template_config: Template config with expected_vendors

    Returns:
        Tuple of (is_fp, reason)
    """
    if not host_cpe_list:
        return False, "no_host_cpe"

    expected_vendors = template_config.get("expected_vendors", [])
    fp_vendors = template_config.get("false_positive_vendors", [])

    for cpe in host_cpe_list:
        parsed = parse_cpe_components(cpe)
        vendor = parsed.get("vendor", "")
        product = parsed.get("product", "")

        # If host CPE matches an expected vendor, it's likely genuine
        for ev in expected_vendors:
            if ev in vendor or ev in product:
                return False, f"cpe_matches_expected:{ev}"

        # If host CPE matches a known FP vendor, flag it
        for fpv in fp_vendors:
            if fpv in vendor or fpv in product:
                return True, f"cpe_matches_fp_vendor:{fpv}"

        # Check against infrastructure devices
        infra_hit = match_infra_keyword(f"{vendor} {product}")
        if infra_hit:
            return True, f"cpe_is_infrastructure:{infra_hit}"

    return False, "cpe_no_match"


def extract_host_cpes(host_data: Dict) -> List[str]:
    """
    Extract all CPE strings from host scan data.

    v4.3: Helper to gather CPEs from various sources.

    Args:
        host_data: Host record or agentless data

    Returns:
        List of CPE strings found
    """
    cpes = []

    # From agentless fingerprint
    if "http_server" in host_data:
        server = host_data.get("http_server", "")
        # Some servers report CPE in headers
        if "cpe:/" in str(server).lower():
            cpes.append(server)

    # From ports data
    for port in host_data.get("ports", []):
        port_cpe = port.get("cpe")
        if isinstance(port_cpe, str) and port_cpe:
            cpes.append(port_cpe)
        elif isinstance(port_cpe, list):
            cpes.extend([c for c in port_cpe if isinstance(c, str) and c])

    return cpes


def check_nuclei_false_positive(
    finding: Dict,
    agentless_data: Optional[Dict] = None,
    logger=None,
    host_data: Optional[Dict] = None,
) -> Tuple[bool, str]:
    """
    Check if a Nuclei finding is a likely false positive.

    v3.9.0: Detects FPs by comparing Server header/product identification
    against expected vendors for the CVE template.

    v4.3: Added CPE validation for enhanced accuracy.

    Args:
        finding: Nuclei finding dict with template_id, response, etc.
        agentless_data: Optional agentless fingerprint for the host
        logger: Optional logger
        host_data: Optional full host record with ports/CPE data (v4.3)

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

    # v4.3: CPE-based validation (most reliable)
    if host_data:
        host_cpes = extract_host_cpes(host_data)
        if host_cpes:
            is_fp, reason = validate_cpe_against_template(host_cpes, template_config)
            if is_fp:
                return True, reason
            if "matches_expected" in reason:
                return False, reason  # Early exit if CPE confirms genuine

    # Extract server/product info from response
    response = finding.get("response", "")
    if not response:
        raw = finding.get("raw")
        if isinstance(raw, dict):
            response = raw.get("response", "") or ""
    server_header = ""
    # v4.3.1: Handle both CRLF and LF to ensure Server header is found
    lines = response.splitlines()
    for line in lines:
        if line.lower().startswith("server:"):
            try:
                server_header = line.split(":", 1)[1].strip().lower()
            except IndexError:
                pass
            break

    # Also check agentless fingerprint
    agentless_vendor = ""
    agentless_title = ""
    agentless_server = ""
    if agentless_data:
        agentless_vendor = (agentless_data.get("device_vendor") or "").lower()
        agentless_title = (agentless_data.get("http_title") or "").lower()
        agentless_server = (agentless_data.get("http_server") or "").lower()

    # Combine all identifiers
    # v4.13.2: Include full response body for better FP detection (e.g., "FRITZ!OS" in body)
    response_body_snippet = response[:2000].lower() if len(response) > 2000 else response.lower()
    identifiers = (
        f"{server_header} {agentless_vendor} {agentless_title} "
        f"{agentless_server} {response_body_snippet}"
    ).lower()

    if logger and "micollab" in template_config.get("description", "").lower():
        logger.debug(
            "Smart-Check Debug: template=%s identifiers_len=%d expected=%s fp=%s",
            template_id,
            len(identifiers),
            template_config.get("expected_vendors", []),
            template_config.get("false_positive_vendors", []),
        )

    # Check if any expected vendor is present
    expected = template_config.get("expected_vendors", [])
    if any(v in identifiers for v in expected):
        # v4.14: For model-specific CVEs, also check if the model matches
        expected_models = template_config.get("expected_models", [])
        fp_models = template_config.get("false_positive_models", [])

        if expected_models or fp_models:
            # Check for false positive models first
            for fp_model in fp_models:
                if fp_model in identifiers:
                    return True, f"fp_model_detected:{fp_model}"

            # Check if expected model is present (if specified)
            if expected_models:
                if not any(model in identifiers for model in expected_models):
                    return True, "fp_model_mismatch"

        return False, "expected_vendor_found"

    # Check if a known FP vendor is present
    fp_vendors = template_config.get("false_positive_vendors", [])
    for fp_vendor in fp_vendors:
        if fp_vendor in identifiers:
            return True, f"fp_vendor_detected:{fp_vendor}"

    # Check against common infrastructure devices
    infra_hit = match_infra_keyword(identifiers)
    if infra_hit:
        # Only flag if none of the expected vendors are present
        if not any(v in identifiers for v in expected):
            return True, f"infrastructure_device:{infra_hit}"

    return False, "no_fp_indicators"


def filter_nuclei_false_positives(
    findings: List[Dict],
    host_agentless: Optional[Dict[str, Dict]] = None,
    logger=None,
    host_records: Optional[List[Dict]] = None,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Filter Nuclei findings to separate genuine findings from likely false positives.

    Unlike Nikto filtering which removes FPs, this returns both lists so the
    auditor can review flagged findings if needed.

    v4.4.2: Added host_records parameter for CPE-based validation.

    Args:
        findings: List of Nuclei finding dicts
        host_agentless: Dict mapping IP -> agentless fingerprint data
        logger: Optional logger
        host_records: Optional list of host records with ports/CPE data

    Returns:
        Tuple of (genuine_findings, suspected_fp_findings)
    """
    if not findings:
        return [], []

    genuine = []
    # v4.4.2: Build IP -> host_data map for CPE lookups
    host_data_map: Dict[str, Dict] = {}
    if host_records:
        for hr in host_records:
            ip = hr.get("ip") if isinstance(hr, dict) else getattr(hr, "ip", None)
            if ip:
                host_data_map[ip] = hr if isinstance(hr, dict) else hr.__dict__
    suspected_fps = []
    host_agentless = host_agentless or {}

    for finding in findings:
        host_ip = finding.get("ip", "") or finding.get("host", "")
        agentless_data = host_agentless.get(host_ip, {})
        trimmed = host_ip
        if not agentless_data and isinstance(host_ip, str) and host_ip:
            if "://" in host_ip:
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(host_ip)
                    trimmed = parsed.hostname or host_ip
                except Exception:
                    pass
            if isinstance(trimmed, str) and trimmed.count(":") == 1:
                trimmed = trimmed.split(":", 1)[0]
            agentless_data = host_agentless.get(trimmed, {})

        # v4.4.2: Pass host_data for CPE-based validation
        host_data = host_data_map.get(trimmed) if trimmed else None
        is_fp, reason = check_nuclei_false_positive(finding, agentless_data, logger, host_data)

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
