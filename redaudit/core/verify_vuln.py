#!/usr/bin/env python3
"""
RedAudit - Vulnerability Verification Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v2.9: Smart-Check module for filtering false positives from Nikto and other scanners.
Uses Content-Type verification and Magic Bytes to detect Soft 404s.
"""

import re
import subprocess
from typing import Dict, List, Optional, Tuple

# File extensions that suggest sensitive/binary content
SENSITIVE_EXTENSIONS = ('.tar', '.zip', '.gz', '.bak', '.config', '.pem', '.key', '.pfx', '.p12')

# Expected Content-Types for binary archives (if we get JSON/HTML, it's a false positive)
BINARY_CONTENT_TYPES = (
    'application/octet-stream',
    'application/x-tar',
    'application/zip',
    'application/x-gzip',
    'application/x-pem-file',
    'application/x-x509-ca-cert',
)

# Content-Types that indicate a false positive when expecting binary
FALSE_POSITIVE_CONTENT_TYPES = (
    'application/json',
    'text/html',
    'text/plain',
    'text/xml',
    'application/xml',
)

# Magic bytes for common archive formats
MAGIC_BYTES = {
    'tar': b'ustar',  # Found at offset 257
    'gzip': b'\x1f\x8b',
    'zip': b'PK\x03\x04',
    'pem': b'-----BEGIN',
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
    match = re.search(r'\+ (/[^\s:]+)', finding)
    if match:
        return match.group(1)
    
    # Pattern 2: "OSVDB-XXXX: /path found"
    match = re.search(r'OSVDB-\d+:\s*(/[^\s]+)', finding)
    if match:
        return match.group(1)
    
    # Pattern 3: Any path-like string
    match = re.search(r'(/[a-zA-Z0-9_\-./]+\.[a-z]+)', finding)
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


def verify_content_type(url: str, extra_tools: Optional[Dict] = None, timeout: int = 10) -> Tuple[Optional[str], Optional[int]]:
    """
    Perform HEAD request to verify Content-Type of a URL.
    
    Args:
        url: Full URL to check
        extra_tools: Dict of available tool paths (uses curl if available)
        timeout: Request timeout in seconds
        
    Returns:
        Tuple of (content_type, content_length) or (None, None) on error
    """
    curl_path = extra_tools.get("curl") if extra_tools else "curl"
    if not curl_path:
        curl_path = "curl"
    
    try:
        res = subprocess.run(
            [curl_path, "-I", "-s", "--max-time", str(timeout), "-k", url],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        
        headers = res.stdout or ""
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


def is_false_positive_by_content_type(expected_ext: str, actual_content_type: Optional[str]) -> bool:
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
    if expected_ext in ('.tar', '.zip', '.gz', '.bak'):
        if content_length < MIN_BACKUP_SIZE:
            return True
    
    return False


def verify_nikto_finding(finding: str, base_url: str, extra_tools: Optional[Dict] = None) -> Tuple[bool, str]:
    """
    Verify a single Nikto finding to determine if it's a false positive.
    
    Args:
        finding: Raw Nikto finding line
        base_url: Base URL for the target (e.g., "http://192.168.1.1:8189")
        extra_tools: Dict of available tool paths
        
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
    content_type, content_length = verify_content_type(full_url, extra_tools)
    
    # Check Content-Type
    if is_false_positive_by_content_type(ext, content_type):
        return False, f"filtered:content_type_mismatch:{content_type}"
    
    # Check size
    if is_false_positive_by_size(ext, content_length):
        return False, f"filtered:too_small:{content_length}bytes"
    
    return True, "kept:verified"


def filter_nikto_false_positives(
    findings: List[str],
    base_url: str,
    extra_tools: Optional[Dict] = None,
    logger=None
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
        is_valid, reason = verify_nikto_finding(finding, base_url, extra_tools)
        
        if is_valid:
            verified.append(finding)
        else:
            filtered_count += 1
            if logger:
                logger.debug("Nikto FP filtered: %s - %s", finding[:50], reason)
    
    if filtered_count > 0 and logger:
        logger.info("Nikto Smart-Check: filtered %d false positives from %d findings", 
                   filtered_count, len(findings))
    
    return verified
