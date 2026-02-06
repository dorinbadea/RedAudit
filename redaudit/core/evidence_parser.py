#!/usr/bin/env python3
"""
RedAudit - Evidence Parser Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.1: Parse and structure tool output for SIEM/AI consumption.
Separates raw output from structured observations.
"""

import os
import re
import hashlib
from typing import Dict, List, Tuple, Optional

from redaudit.utils.constants import SECURE_FILE_MODE


# Patterns to extract meaningful observations from tool output
NIKTO_OBSERVATION_PATTERNS = [
    (
        r"The anti-clickjacking X-Frame-Options header is not present",
        "Missing X-Frame-Options header",
    ),
    (r"The X-Content-Type-Options header is not set", "Missing X-Content-Type-Options header"),
    (
        r"The site uses TLS and the Strict-Transport-Security HTTP header is not defined",
        "Missing HSTS header",
    ),
    (r"Directory indexing found", "Directory listing enabled"),
    (r"Server leaks inodes via ETags", "ETag inode leak"),
    (r"Retrieved x-powered-by header: (.+)", "X-Powered-By disclosure: {0}"),
    (r"Retrieved x-aspnet-version header: (.+)", "ASP.NET version disclosure: {0}"),
    (r"Server: (.+)", "Server banner: {0}"),
    (r"Allowed HTTP Methods: (.+)", "HTTP methods: {0}"),
    (r"OSVDB-\d+: (.+)", "{0}"),
    (r"CVE-(\d{4}-\d+)", "CVE-{0}"),
    (r"SSL certificate .* expired", "SSL certificate expired"),
    (r"hostname .* does not match certificate", "SSL hostname mismatch"),
]

TESTSSL_OBSERVATION_PATTERNS = [
    (r"vulnerable", "SSL/TLS vulnerability detected"),
    (r"LUCKY13", "LUCKY13 vulnerability"),
    (r"BEAST", "BEAST vulnerability"),
    (r"POODLE", "POODLE vulnerability"),
    (r"FREAK", "FREAK vulnerability"),
    (r"DROWN", "DROWN vulnerability"),
    (r"LOGJAM", "LOGJAM vulnerability"),
    (r"SWEET32", "SWEET32 vulnerability"),
    (r"RC4", "RC4 cipher in use"),
    (r"TLS 1\.0", "TLS 1.0 enabled"),
    (r"TLS 1\.1", "TLS 1.1 enabled"),
    (r"SSLv3", "SSLv3 enabled"),
    (r"SSLv2", "SSLv2 enabled"),
    (r"self.signed", "Self-signed certificate"),
    (r"expired", "Certificate expired"),
]

# Maximum size for inline raw output (4KB)
MAX_INLINE_OUTPUT_SIZE = 4096


_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _derive_descriptive_title(observations: List[str]) -> Optional[str]:
    """
    Derive a short human-readable title from parsed observations.

    The goal is to avoid generic "Finding on URL" titles for web findings that
    are represented as a single record per URL/port.

    v4.0.4: Improved priority order - SSL/TLS issues before minor info leaks.
    """

    if not observations:
        return None

    # Prefer explicit CVE signal.
    for obs in observations:
        match = _CVE_PATTERN.search(obs)
        if match:
            return match.group(0).upper()

    # Tier 1: Critical security issues (SSL/TLS, certificates, authentication)
    tier1_tokens = (
        "expired",
        "mismatch",
        "weak cipher",
        "self-signed",
        "invalid certificate",
        "vulnerability",
        "directory listing",
    )
    for obs in observations:
        if not isinstance(obs, str):
            continue
        lower = obs.strip().lower()
        if any(token in lower for token in tier1_tokens):
            return obs.strip()[:80]

    # Prefer "Missing ..." (headers, hardening, etc.).
    for obs in observations:
        if isinstance(obs, str) and obs.strip().lower().startswith("missing "):
            return obs.strip()[:80]

    # Tier 2: Secondary security-relevant observations (info leaks, disclosures)
    tier2_tokens = (
        "disclosure",
        "leak",
        "enabled",
    )
    for obs in observations:
        if not isinstance(obs, str):
            continue
        text = obs.strip()
        lower = text.lower()
        if lower.startswith(("server banner:", "technology:", "http methods:")):
            continue
        if any(token in lower for token in tier2_tokens):
            return text[:80]

    # Fallback: first non-metadata observation.
    for obs in observations:
        if not isinstance(obs, str):
            continue
        text = obs.strip()
        if not text:
            continue
        lower = text.lower()
        if lower.startswith(("server banner:", "technology:", "http methods:")):
            continue
        return text[:80]

    return None


def parse_nikto_findings(findings: List[str]) -> List[str]:
    """
    Extract structured observations from Nikto output lines.

    Args:
        findings: List of Nikto output lines

    Returns:
        List of structured observation strings
    """
    observations = []
    seen = set()

    for line in findings:
        # Skip metadata lines
        if any(
            x in line.lower()
            for x in [
                "target ip:",
                "target hostname:",
                "target port:",
                "start time:",
                "end time:",
                "host(s) tested",
                "scan terminated:",
                "no cgi directories",
            ]
        ):
            continue

        # Try to match known patterns
        matched = False
        for pattern, template in NIKTO_OBSERVATION_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                if match.groups():
                    obs = template.format(*match.groups())
                else:
                    obs = template

                if obs not in seen:
                    observations.append(obs)
                    seen.add(obs)
                matched = True
                break

        # If no pattern matched, use cleaned line if meaningful
        if not matched and line.strip().startswith("+"):
            cleaned = line.strip().lstrip("+ ").strip()
            if len(cleaned) > 10 and cleaned not in seen:
                # Truncate long observations
                if len(cleaned) > 100:
                    cleaned = cleaned[:97] + "..."
                observations.append(cleaned)
                seen.add(cleaned)

    return observations[:20]  # Limit to 20 observations


def parse_testssl_output(testssl_data: Dict) -> List[str]:
    """
    Extract structured observations from TestSSL analysis.

    Args:
        testssl_data: TestSSL analysis dictionary

    Returns:
        List of structured observation strings
    """
    observations = []

    # Check vulnerabilities list
    for vuln in testssl_data.get("vulnerabilities", []):
        vuln_str = str(vuln)
        for pattern, template in TESTSSL_OBSERVATION_PATTERNS:
            if re.search(pattern, vuln_str, re.IGNORECASE):
                if template not in observations:
                    observations.append(template)
                break

    # Check weak ciphers
    if testssl_data.get("weak_ciphers"):
        observations.append("Weak ciphers detected")

    # Check protocol issues
    if testssl_data.get("protocols"):
        protocols = testssl_data["protocols"]
        if isinstance(protocols, dict):
            if protocols.get("SSLv2"):
                observations.append("SSLv2 enabled")
            if protocols.get("SSLv3"):
                observations.append("SSLv3 enabled")
            if protocols.get("TLS1.0"):
                observations.append("TLS 1.0 enabled")
            if protocols.get("TLS1.1"):
                observations.append("TLS 1.1 enabled")

    return observations[:15]


def extract_observations(vuln_record: Dict) -> Tuple[List[str], str]:
    """
    Extract parsed observations from a vulnerability record.

    Args:
        vuln_record: Vulnerability dictionary with nikto_findings, testssl_analysis, etc.

    Returns:
        Tuple of (observations list, raw output string)
    """
    observations = []
    raw_parts = []

    # Parse Nikto findings
    nikto_findings = vuln_record.get("nikto_findings", [])
    if nikto_findings:
        observations.extend(parse_nikto_findings(nikto_findings))
        raw_parts.append("=== NIKTO ===\n" + "\n".join(nikto_findings))

    # Parse TestSSL
    testssl = vuln_record.get("testssl_analysis", {})
    if testssl:
        observations.extend(parse_testssl_output(testssl))
        if testssl.get("raw_output"):
            raw_parts.append("=== TESTSSL ===\n" + testssl["raw_output"])

    # Parse WhatWeb
    whatweb = vuln_record.get("whatweb")
    if whatweb and isinstance(whatweb, str):
        # Extract technology detections
        for tech in re.findall(r"\[([^\]]+)\]", whatweb):
            if len(tech) < 50 and tech not in observations:
                observations.append(f"Technology: {tech}")

    # v4.14: Generate fallback observations from service/port data
    # This ensures findings with source "redaudit" have some technical details
    if not observations:
        port = vuln_record.get("port")
        url = vuln_record.get("url")
        description = vuln_record.get("description")
        service = vuln_record.get("service")
        banner = vuln_record.get("banner")

        # Type-safe extraction with validation
        if isinstance(url, str) and url.strip():
            observations.append(f"Endpoint: {url.strip()}")
        elif port is not None:
            observations.append(f"Port: {port}")

        if isinstance(service, str) and service.strip():
            observations.append(f"Service: {service.strip()}")
        if isinstance(banner, str) and banner.strip():
            # Clean and truncate banner
            clean_banner = banner.strip()[:100]
            observations.append(f"Banner: {clean_banner}")

        if isinstance(description, str) and description.strip():
            # Use description as observation
            observations.append(description.strip()[:200])

        # Check for headers if available
        headers = vuln_record.get("headers", {})
        if isinstance(headers, dict):
            server = headers.get("server")
            powered_by = headers.get("x-powered-by")
            if isinstance(server, str) and server.strip():
                observations.append(f"Server: {server.strip()}")
            if isinstance(powered_by, str) and powered_by.strip():
                observations.append(f"X-Powered-By: {powered_by.strip()}")

    raw_output = "\n\n".join(raw_parts)

    return observations[:25], raw_output


def should_externalize_output(raw_output: str) -> bool:
    """Check if raw output should be saved to external file."""
    return len(raw_output.encode("utf-8")) > MAX_INLINE_OUTPUT_SIZE


def compute_output_hash(raw_output: str) -> str:
    """Compute SHA256 hash of raw output."""
    return hashlib.sha256(raw_output.encode("utf-8")).hexdigest()


def save_raw_output(raw_output: str, output_dir: str, host: str, port: int) -> str:
    """
    Save raw output to external file.

    Args:
        raw_output: Raw tool output string
        output_dir: Directory to save evidence files
        host: Target host IP
        port: Target port

    Returns:
        Relative path to saved file
    """
    evidence_dir = os.path.join(output_dir, "evidence")
    os.makedirs(evidence_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(evidence_dir, 0o700)
    except Exception:
        pass

    # Sanitize filename
    safe_host = host.replace(".", "_").replace(":", "_")
    filename = f"raw_{safe_host}_{port}.txt"
    filepath = os.path.join(evidence_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(raw_output)
    try:
        os.chmod(filepath, SECURE_FILE_MODE)
    except Exception:
        pass

    return f"evidence/{filename}"


def enrich_with_observations(vuln_record: Dict, output_dir: Optional[str] = None) -> Dict:
    """
    Enrich vulnerability record with parsed observations.

    v3.1: Adds parsed_observations, raw_tool_output_sha256, and optionally raw_tool_output_ref.

    Args:
        vuln_record: Vulnerability dictionary
        output_dir: Optional directory for external evidence files

    Returns:
        Enriched vulnerability record
    """
    enriched = vuln_record.copy()

    observations, raw_output = extract_observations(vuln_record)

    if observations:
        enriched["parsed_observations"] = observations

        # v4.9.0: Auto-extract CVEs from observations (Nikto/TestSSL legacy support)
        # This ensures SIEMs get structured CVE data even if the tool doesn't provide it natively.
        found_cves = set(enriched.get("cve_ids", []))

        # 1. Scan normalized observations (fastest)
        for obs in observations:
            cve_matches = _CVE_PATTERN.findall(obs)
            for cve in cve_matches:
                found_cves.add(cve.upper())

        # 2. Scan raw Nikto findings (source of truth)
        for line in vuln_record.get("nikto_findings", []):
            cve_matches = _CVE_PATTERN.findall(str(line))
            for cve in cve_matches:
                found_cves.add(cve.upper())

        # 3. Scan raw TestSSL vulnerabilities
        testssl = vuln_record.get("testssl_analysis", {})
        for vuln in testssl.get("vulnerabilities", []):
            cve_matches = _CVE_PATTERN.findall(str(vuln))
            for cve in cve_matches:
                found_cves.add(cve.upper())

        if found_cves:
            enriched["cve_ids"] = sorted(list(found_cves))

        if not enriched.get("descriptive_title"):
            title = _derive_descriptive_title(observations)
            if title:
                enriched["descriptive_title"] = title

    if raw_output:
        enriched["raw_tool_output_sha256"] = compute_output_hash(raw_output)

        # Externalize if too large
        if should_externalize_output(raw_output) and output_dir:
            host = (
                vuln_record.get("url", "").split("/")[2]
                if "://" in vuln_record.get("url", "")
                else "unknown"
            )
            port = vuln_record.get("port", 0)
            ref = save_raw_output(raw_output, output_dir, host, port)
            enriched["raw_tool_output_ref"] = ref

    return enriched
