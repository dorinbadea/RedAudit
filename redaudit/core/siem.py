#!/usr/bin/env python3
"""
RedAudit - SIEM Enhancement Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v2.9: SIEM-compatible output enhancements for Splunk, Elastic, QRadar, ArcSight.
Implements ECS (Elastic Common Schema), severity scoring, and CEF format.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple, TypedDict


# ECS Version for Elastic integration
ECS_VERSION = "8.11"

# v3.2.3: Schema version for JSONL/ECS output stability
SCHEMA_VERSION = "1.0"


class SeverityInfo(TypedDict):
    score: int
    color: str


# Severity levels with numeric scores for SIEM correlation
SEVERITY_LEVELS: Dict[str, SeverityInfo] = {
    "critical": {"score": 90, "color": "red"},
    "high": {"score": 70, "color": "orange"},
    "medium": {"score": 50, "color": "yellow"},
    "low": {"score": 30, "color": "blue"},
    "info": {"score": 10, "color": "gray"},
}


def _severity_from_label(label: str) -> Tuple[str, int]:
    value = (label or "").strip().lower()
    if value not in SEVERITY_LEVELS:
        value = "info"
    return value, SEVERITY_LEVELS[value]["score"]


# Keywords to detect severity from findings
SEVERITY_KEYWORDS = {
    "critical": [
        "rce",
        "remote code execution",
        "unauthenticated",
        "critical",
        "backdoor",
        "rootkit",
    ],
    "high": [
        "sql injection",
        "xss",
        "cross-site",
        "authentication bypass",
        "vulnerable",
        "exploit",
        "cve-",
    ],
    "medium": [
        "information disclosure",
        "directory listing",
        "weak cipher",
        "ssl",
        "tls 1.0",
        "tls 1.1",
    ],
    "low": ["cookie", "header", "missing", "deprecated", "outdated"],
}

# v4.6.19: Specific severity overrides for common Nikto/scanner findings
# These patterns are checked FIRST and override the generic keyword matching.
# Regex patterns (case-insensitive) mapped to severity level.
SEVERITY_OVERRIDES = {
    "low": [
        r"missing.*x-frame-options",
        r"anti-clickjacking.*x-frame-options",  # v4.6.21: Nikto wording
        r"x-frame-options.*not present",  # v4.6.21: Alternative Nikto wording
        r"missing.*x-content-type",
        r"missing.*strict-transport-security",
        r"missing.*content-security-policy",
        r"clickjacking",
        r"httponly.*flag",
        r"secure.*flag.*cookie",
        r"anti-clickjacking.*header",
        r"x-xss-protection",
    ],
    "info": [
        r"etag.*inode",
        r"server\s*banner",
        r"version\s*disclosed",
        r"x-powered-by",
        r"uncommon\s*header",
        r"items\s*checked.*error",
        r"no\s*cgi\s*directories",
        r"root\s*page.*redirects",
        r"allowed\s*http\s*methods",
    ],
}

# Asset type to tags mapping
ASSET_TYPE_TAGS = {
    "router": ["network", "infrastructure", "gateway"],
    "switch": ["network", "infrastructure", "switch"],
    "vpn": ["network", "infrastructure", "vpn-endpoint"],
    "workstation": ["endpoint", "user-device", "desktop"],
    "server": ["infrastructure", "backend"],
    "mobile": ["endpoint", "mobile", "user-device"],
    "iot": ["iot", "embedded", "smart-device"],
    "smart_device": ["iot", "consumer", "smart-device"],
    "media": ["entertainment", "smart-device"],
    "printer": ["peripheral", "print-service"],
}

# Service to tags mapping
SERVICE_TAGS = {
    "http": ["web", "http"],
    "https": ["web", "https", "encrypted"],
    "ssh": ["remote-access", "encrypted", "admin"],
    "ftp": ["file-transfer", "legacy"],
    "smb": ["file-sharing", "windows"],
    "mysql": ["database", "sql"],
    "postgresql": ["database", "sql"],
    "mongodb": ["database", "nosql"],
    "rdp": ["remote-access", "windows", "admin"],
    "telnet": ["remote-access", "legacy", "insecure"],
    "vnc": ["remote-access", "desktop"],
}

# v4.6.19: Known vulnerable service versions with backdoors or critical vulns
# Format: regex pattern -> (CVE-ID, severity, description)
KNOWN_VULNERABLE_SERVICES = {
    r"vsftpd[/ ]2\.3\.4": (
        "CVE-2011-2523",
        "critical",
        "vsftpd 2.3.4 backdoor - Remote code execution via :) trigger",
    ),
    r"unreal(ircd)?[/ ]?3\.2\.8\.1": (
        "CVE-2010-2075",
        "critical",
        "UnrealIRCd 3.2.8.1 backdoor - Remote code execution via DEBUG command",
    ),
    r"proftpd[/ ]1\.3\.3[a-c]": (
        "CVE-2010-4221",
        "critical",
        "ProFTPD 1.3.3a-c Telnet IAC buffer overflow",
    ),
    r"samba[/ ]3\.0\.(2[0-5]|[0-9])": (
        "CVE-2007-2447",
        "critical",
        "Samba 3.0.0-3.0.25 username map script RCE",
    ),
    r"distccd": (
        "CVE-2004-2687",
        "high",
        "distcc daemon allows arbitrary command execution",
    ),
    r"java rmi": (
        "JAVA-RMI-DESER",
        "high",
        "Java RMI registry - potential deserialization vulnerability",
    ),
    r"apache[/ ]2\.2\.[0-8]\\b": (
        "CVE-2011-3192",
        "high",
        "Apache 2.2.0-2.2.8 Range header DoS vulnerability",
    ),
    r"openssh[/ ][1-4]\\.": (
        "OPENSSH-OLD",
        "medium",
        "OpenSSH version < 5.0 has known vulnerabilities",
    ),
}

# v3.1: Finding categories for classification
FINDING_CATEGORIES = {
    "surface": ["open port", "exposed", "listening", "service detected"],
    "misconfig": [
        "directory listing",
        "missing header",
        "x-frame-options",
        "x-content-type",
        "hsts",
        "cors",
        "csp",
        "clickjacking",
    ],
    "crypto": [
        "ssl",
        "tls 1.0",
        "tls 1.1",
        "weak cipher",
        "certificate",
        "expired",
        "self-signed",
        "sha1",
        "md5",
        "rc4",
        "des",
        "3des",
    ],
    "auth": [
        "authentication",
        "unauthenticated",
        "no password",
        "default",
        "anonymous",
        "guest access",
        "password",
    ],
    "info-leak": [
        "disclosure",
        "internal ip",
        "version",
        "stack trace",
        "error message",
        "debug",
        "backup",
        "source code",
    ],
    "vuln": [
        "cve-",
        "vulnerability",
        "exploit",
        "injection",
        "xss",
        "sqli",
        "rce",
        "remote code",
        "command injection",
    ],
}


def detect_known_vulnerable_services(banner: str) -> List[Dict]:
    """
    Detect known vulnerable services from banner text.

    v4.6.19: Checks service banners against KNOWN_VULNERABLE_SERVICES patterns.

    Args:
        banner: Service banner or version string

    Returns:
        List of detected vulnerabilities, each with cve_id, severity, description
    """
    if not banner:
        return []

    banner_lower = banner.lower()
    detected = []

    for pattern, (cve_id, severity, description) in KNOWN_VULNERABLE_SERVICES.items():
        if re.search(pattern, banner_lower, re.IGNORECASE):
            detected.append(
                {
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": description,
                    "matched_pattern": pattern,
                    "banner_excerpt": banner[:100],
                }
            )

    return detected


def extract_finding_title(vuln: Dict) -> str:
    """
    Extract a descriptive title from vulnerability record.

    v4.6.20: Unified function for HTML and JSONL exporters.
    Previously duplicated in jsonl_exporter._extract_title and html_reporter._extract_finding_title.

    Priority:
    1. Use existing descriptive_title if available
    2. Use Nuclei template_id
    3. Use CVE IDs
    4. Generate from parsed_observations
    5. Fallback based on source/port

    Args:
        vuln: Vulnerability dictionary

    Returns:
        Human-readable title string
    """
    import re

    # 1. Use existing descriptive_title if set
    if vuln.get("descriptive_title"):
        return vuln["descriptive_title"]

    obs = vuln.get("parsed_observations") or []
    port = vuln.get("port", 0)

    # 2. If we have a template_id from Nuclei, use it
    template_id = vuln.get("template_id", "")
    if template_id:
        if template_id.upper().startswith("CVE-"):
            return f"Nuclei: {template_id.upper()}"
        nice_name = template_id.replace("-", " ").replace("_", " ").title()
        return f"Nuclei: {nice_name}"

    # 3. If we have CVE IDs, prioritize them
    cve_ids = vuln.get("cve_ids", [])
    if cve_ids and isinstance(cve_ids, list) and cve_ids[0]:
        return f"Known Vulnerability: {cve_ids[0].upper()}"

    # 4. Generate descriptive title based on observations
    for observation in obs:
        if not isinstance(observation, str):
            continue
        obs_lower = observation.lower()

        # Security headers
        if "missing hsts" in obs_lower or "strict-transport-security" in obs_lower:
            return "Missing HTTP Strict Transport Security Header"
        if "x-frame-options" in obs_lower and (
            "missing" in obs_lower or "not present" in obs_lower
        ):
            return "Missing X-Frame-Options Header (Clickjacking Risk)"
        if "x-content-type" in obs_lower and ("missing" in obs_lower or "not set" in obs_lower):
            return "Missing X-Content-Type-Options Header"

        # SSL/TLS issues
        if "ssl hostname mismatch" in obs_lower or "does not match certificate" in obs_lower:
            return "SSL Certificate Hostname Mismatch"
        if "certificate expired" in obs_lower or ("expired" in obs_lower and "ssl" in obs_lower):
            return "SSL Certificate Expired"
        if "self-signed" in obs_lower or "self signed" in obs_lower:
            return "Self-Signed SSL Certificate"
        if "beast" in obs_lower:
            return "BEAST Vulnerability (SSL/TLS)"
        if "poodle" in obs_lower:
            return "POODLE Vulnerability (SSL 3.0)"

        # CVE references in observations
        if "cve-" in obs_lower:
            match = re.search(r"(cve-\d{4}-\d+)", obs_lower)
            if match:
                return f"Known Vulnerability: {match.group(1).upper()}"

        # Information disclosure
        if "rfc-1918" in obs_lower or "private ip" in obs_lower:
            return "Internal IP Address Disclosed in Headers"
        if "server banner" in obs_lower and "no banner" not in obs_lower:
            return "Server Version Disclosed in Banner"
        if "directory listing" in obs_lower or "index of" in obs_lower:
            return "Directory Listing Enabled"
        if "etag" in obs_lower and "inode" in obs_lower:
            return "ETag Inode Disclosure"

        # HTTP methods
        if "put method" in obs_lower or "delete method" in obs_lower:
            return "Dangerous HTTP Methods Enabled"

    # 5. Fallback: first nikto finding (v4.6.20: backward compat with old html_reporter)
    nikto = vuln.get("nikto_findings") or []
    if nikto and isinstance(nikto, list):
        for finding in nikto:
            if not isinstance(finding, str):
                continue
            # Skip metadata lines
            finding_lower = finding.lower()
            if any(x in finding_lower for x in ["target ip:", "start time:", "end time:"]):
                continue
            if finding.strip():
                text = finding.strip()
                return text[:80] + ("..." if len(text) > 80 else "")

    # 6. Improved fallback based on available info
    source = vuln.get("source", "") or (vuln.get("original_severity", {}) or {}).get("tool", "")
    url = vuln.get("url", "")

    if source == "testssl":
        return f"SSL/TLS Configuration Issue on Port {port}"
    if source == "nikto" and url:
        return f"Web Security Finding on Port {port}"
    if url:
        return f"HTTP Service Finding on Port {port}"

    return f"Service Finding on Port {port}"


def generate_finding_id(
    asset_id: str, scanner: str, port: int, protocol: str, signature: str, title: str
) -> str:
    """
    Generate deterministic finding_id for deduplication across runs.

    v3.1: Enables correlation of findings between scans.

    Args:
        asset_id: Observable hash of the asset
        scanner: Tool that detected the finding (nikto, testssl, etc.)
        port: Port number
        protocol: Protocol (tcp/udp)
        signature: Unique identifier (CVE, plugin ID, or rule name)
        title: Normalized title of the finding

    Returns:
        SHA256 hash as finding_id
    """
    # Normalize title for consistent hashing
    title_normalized = re.sub(r"\s+", " ", title.lower().strip())[:100]

    fingerprint = f"{asset_id}|{scanner}|{protocol}:{port}|{signature}|{title_normalized}"
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def classify_finding_category(finding_text: str) -> str:
    """
    Classify a finding into a category based on its content.

    v3.1: Simple category classification without MITRE ATT&CK.

    Args:
        finding_text: The finding description text

    Returns:
        Category string: surface, misconfig, crypto, auth, info-leak, or vuln
    """
    if not finding_text:
        return "surface"

    text_lower = finding_text.lower()

    # Check categories in priority order (vuln first, surface last)
    for category in ["vuln", "auth", "crypto", "misconfig", "info-leak"]:
        for keyword in FINDING_CATEGORIES[category]:
            if keyword in text_lower:
                return category

    return "surface"


def calculate_severity(finding: str) -> str:
    """
    Calculate severity level from a vulnerability finding text.

    Args:
        finding: Vulnerability finding text

    Returns:
        Severity level string (critical/high/medium/low/info)
    """
    if not finding:
        return "info"

    finding_lower = finding.lower()

    # Ignore common Nikto metadata / non-findings that should not influence severity.
    benign_substrings = (
        "target ip:",
        "target hostname:",
        "target port:",
        "start time:",
        "end time:",
        "host(s) tested",
        "server: no banner retrieved",
        "scan terminated:",
        "no cgi directories found",
    )
    if any(s in finding_lower for s in benign_substrings):
        return "info"

    # v4.6.19: Check specific severity overrides FIRST (regex patterns)
    # These take precedence over generic keyword matching for common Nikto findings.
    for level in ["info", "low"]:  # Check info first, then low
        for pattern in SEVERITY_OVERRIDES.get(level, []):
            if re.search(pattern, finding_lower):
                return level

    def keyword_matches(keyword: str) -> bool:
        kw = (keyword or "").lower()
        if not kw:
            return False

        # Multi-word phrases are matched as substrings.
        if any(ch.isspace() for ch in kw):
            return kw in finding_lower

        # Prefix-like tokens (e.g., "cve-") are matched as substrings.
        if kw.endswith("-"):
            return kw in finding_lower

        # Short acronyms (e.g., RCE/XSS/SSL) must match as a standalone token to avoid
        # false positives like "fo[rce]".
        if len(kw) <= 3:
            return (
                re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", finding_lower) is not None
            )

        return kw in finding_lower

    for level in ["critical", "high", "medium", "low"]:
        for keyword in SEVERITY_KEYWORDS[level]:
            if keyword_matches(keyword):
                return level

    return "info"


def calculate_risk_score(host_record: Dict) -> int:
    """
    Calculate overall risk score (0-100) for a host using Weighted Maximum Gravity.

    v4.3: Refactored algorithm based on security audit recommendations.

    Formula:
    1. Base = max(CVSS_score, exploit_severity, insecure_service_score) * 10
    2. Density bonus = min(20, log10(num_vulns + 1) * 15)
    3. Exposure multiplier (1.15x) for common external-facing ports

    Score is based on:
    - Maximum CVSS score from CVE data (primary factor)
    - Presence of known exploits (high impact)
    - Insecure services (telnet, ftp, etc.)
    - Number of vulnerabilities (logarithmic density)
    - Port exposure (external-facing ports increase risk)

    Args:
        host_record: Host record dictionary

    Returns:
        Risk score 0-100
    """
    import math

    ports = host_record.get("ports", [])
    findings = host_record.get("findings", [])
    if not ports and not findings:
        return 0

    # v4.6.21: IoT lwIP false positive detection
    # lwIP TCP/IP stack (common in cheap IoT) responds SYN-ACK to all SYN probes,
    # making Nmap report many "open" ports that aren't real services.
    # Heuristic: IoT device with >20 ports is likely a false positive.
    asset_type = str(host_record.get("asset_type") or "").lower()
    os_detected = str(host_record.get("os_detected") or "").lower()
    is_iot = asset_type == "iot" or "lwip" in os_detected
    if is_iot and len(ports) > 20:
        # Cap risk score for IoT with suspiciously many ports
        return 30  # Low-medium risk, flag for manual review

    max_cvss = 0.0
    total_vulns = 0
    has_exposed_port = False

    # Common external-facing ports that increase exposure risk
    exposed_ports = {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        993,
        995,
        3306,
        3389,
        5432,
        8080,
        8443,
    }

    for port in ports:
        port_number = port.get("port", 0)

        # Check for exposed ports
        if port_number in exposed_ports:
            has_exposed_port = True

        # Extract CVSS scores from CVE data
        cves = port.get("cves", [])
        for cve in cves:
            cvss = cve.get("cvss_score")
            if cvss and isinstance(cvss, (int, float)) and cvss > max_cvss:
                max_cvss = float(cvss)
            total_vulns += 1

        # Count known exploits
        exploits = port.get("known_exploits", [])
        if exploits:
            # Known exploits are at least severity 8.0
            max_cvss = max(max_cvss, 8.0)
            total_vulns += len(exploits)

        # Insecure services bump minimum severity
        service = (port.get("service") or "").lower()
        if service in ("telnet", "rlogin", "rsh"):
            # Plaintext remote access = critical (9.0)
            max_cvss = max(max_cvss, 9.0)
            total_vulns += 1
        elif service == "ftp":
            # FTP = high risk (7.5)
            max_cvss = max(max_cvss, 7.5)
            total_vulns += 1
        elif "ssl" in service and port_number not in (443, 8443):
            # SSL on non-standard port = medium concern
            max_cvss = max(max_cvss, 5.0)

        # v4.6.20: Check for known backdoored services using service+version
        # nmap reports version in 'version' field, not just in banner text
        version = port.get("version") or ""
        product = port.get("product") or ""
        banner = port.get("banner") or ""
        # Build a combined string for pattern matching
        service_info = f"{service} {product} {version} {banner}".strip()
        if service_info:
            backdoors = detect_known_vulnerable_services(service_info)
            if backdoors:
                # Known backdoor = critical (10.0)
                max_cvss = max(max_cvss, 10.0)
                total_vulns += len(backdoors)
                # Store detected backdoors on the port for downstream use
                if "detected_backdoors" not in port:
                    port["detected_backdoors"] = []
                port["detected_backdoors"].extend(backdoors)

                # v4.6.22: Also inject CVE into port cves list for JSONL propagation
                if "cves" not in port:
                    port["cves"] = []
                for bd in backdoors:
                    cve_id = bd.get("cve_id", "")
                    # Only add if it's a real CVE and not already present
                    if cve_id.upper().startswith("CVE-"):
                        existing_cves = {c.get("cve_id", "").upper() for c in port["cves"]}
                        if cve_id.upper() not in existing_cves:
                            port["cves"].append(
                                {
                                    "cve_id": cve_id.upper(),
                                    "cvss_score": 9.8,
                                    "cvss_severity": "CRITICAL",
                                    "description": bd.get("description", ""),
                                    "source": "banner_analysis",
                                }
                            )

    # v4.3.1: Include vulnerabilities from Nikto/Nuclei finding dumps
    # These findings may not be attached to specific ports
    findings = host_record.get("findings", [])
    severity_map = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.0,
    }

    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        score = severity_map.get(severity, 0.0)

        # Override with explicit normalized_severity if available
        norm = finding.get("normalized_severity")
        if norm and isinstance(norm, (int, float)):
            score = float(norm)

        if score > 0:
            max_cvss = max(max_cvss, score)
            # Only count as 'vuln' for density if it adds risk (Med+)
            # otherwise we dilute density with 100 info findings
            if score >= 4.0:
                total_vulns += 1

    # 1. Base score from maximum CVSS (0-100 scale)
    base_score = max_cvss * 10

    # 2. Density bonus (logarithmic, max 20 points)
    # More vulnerabilities add risk but with diminishing returns
    density_bonus = 0.0
    if total_vulns > 0:
        density_bonus = min(20.0, math.log10(total_vulns + 1) * 15)

    # 3. Exposure multiplier for external-facing services
    exposure_multiplier = 1.15 if has_exposed_port else 1.0

    # Calculate final score
    final_score = (base_score + density_bonus) * exposure_multiplier

    # Cap at 100
    return min(100, round(final_score))


def calculate_risk_score_with_breakdown(host_record: Dict) -> Dict:
    """
    Calculate risk score with detailed breakdown for reporting.

    v4.3: Returns score plus breakdown components for HTML tooltips.

    Args:
        host_record: Host record dictionary

    Returns:
        Dict with 'score' and 'breakdown' containing:
        - max_cvss: Maximum CVSS score found
        - base_score: Base score (max_cvss * 10)
        - density_bonus: Logarithmic density bonus
        - exposure_multiplier: 1.0 or 1.15
        - total_vulns: Count of vulnerabilities
        - has_exposed_port: Boolean for external-facing ports
    """
    import math

    ports = host_record.get("ports", [])
    if not ports:
        return {
            "score": 0,
            "breakdown": {
                "max_cvss": 0.0,
                "base_score": 0.0,
                "density_bonus": 0.0,
                "exposure_multiplier": 1.0,
                "total_vulns": 0,
                "has_exposed_port": False,
            },
        }

    max_cvss = 0.0
    total_vulns = 0
    has_exposed_port = False

    exposed_ports = {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        993,
        995,
        3306,
        3389,
        5432,
        8080,
        8443,
    }

    for port in ports:
        port_number = port.get("port", 0)

        if port_number in exposed_ports:
            has_exposed_port = True

        cves = port.get("cves", [])
        for cve in cves:
            cvss = cve.get("cvss_score")
            if cvss and isinstance(cvss, (int, float)) and cvss > max_cvss:
                max_cvss = float(cvss)
            total_vulns += 1

        exploits = port.get("known_exploits", [])
        if exploits:
            max_cvss = max(max_cvss, 8.0)
            total_vulns += len(exploits)

        service = (port.get("service") or "").lower()
        if service in ("telnet", "rlogin", "rsh"):
            max_cvss = max(max_cvss, 9.0)
            total_vulns += 1
        elif service == "ftp":
            max_cvss = max(max_cvss, 7.5)
            total_vulns += 1
        elif "ssl" in service and port_number not in (443, 8443):
            max_cvss = max(max_cvss, 5.0)

    # v4.3.1: Include vulnerabilities from Nikto/Nuclei finding dumps (Fix M3)
    # Ensure findings logic matches calculate_risk_score()
    findings = host_record.get("findings", [])
    severity_map = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.0,
    }

    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        score = severity_map.get(severity, 0.0)

        # Override with explicit normalized_severity if available
        norm = finding.get("normalized_severity")
        if norm and isinstance(norm, (int, float)):
            score = float(norm)

        if score > 0:
            max_cvss = max(max_cvss, score)
            # Only count as 'vuln' for density if it adds risk (Med+)
            if score >= 4.0:
                total_vulns += 1

    base_score = max_cvss * 10
    density_bonus = 0.0
    if total_vulns > 0:
        density_bonus = min(20.0, math.log10(total_vulns + 1) * 15)

    exposure_multiplier = 1.15 if has_exposed_port else 1.0
    final_score = (base_score + density_bonus) * exposure_multiplier
    capped_score = min(100, round(final_score))

    return {
        "score": capped_score,
        "breakdown": {
            "max_cvss": round(max_cvss, 1),
            "base_score": round(base_score, 1),
            "density_bonus": round(density_bonus, 1),
            "exposure_multiplier": exposure_multiplier,
            "total_vulns": total_vulns,
            "has_exposed_port": has_exposed_port,
        },
    }


def generate_observable_hash(host_record: Dict) -> str:
    """
    Generate SHA256 hash for host record deduplication.

    Uses IP + ports + services as fingerprint.

    Args:
        host_record: Host record dictionary

    Returns:
        SHA256 hash string
    """
    # Build fingerprint from stable fields
    fingerprint = {
        "ip": host_record.get("ip", ""),
        "hostname": host_record.get("hostname", ""),
        "ports": sorted(
            [
                f"{p.get('port')}/{p.get('protocol')}/{p.get('service', '')}"
                for p in host_record.get("ports", [])
            ]
        ),
    }

    fingerprint_str = json.dumps(fingerprint, sort_keys=True)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def generate_host_tags(host_record: Dict, asset_type: Optional[str] = None) -> List[str]:
    """
    Generate tags array for a host based on its characteristics.

    Args:
        host_record: Host record dictionary
        asset_type: Optional pre-determined asset type

    Returns:
        List of tag strings
    """
    tags = set()

    # Add asset type tags
    if asset_type and asset_type in ASSET_TYPE_TAGS:
        tags.update(ASSET_TYPE_TAGS[asset_type])

    # Add service-based tags
    for port in host_record.get("ports", []):
        service = (port.get("service") or "").lower()
        if service in SERVICE_TAGS:
            tags.update(SERVICE_TAGS[service])

        # Web service tag
        if port.get("is_web_service"):
            tags.add("web")

    # Add web tag if web ports were detected but ports lack web flags
    if host_record.get("web_ports_count", 0) > 0:
        tags.add("web")

    # Add status-based tags
    status = host_record.get("status", "")
    if status == "filtered":
        tags.add("firewall-protected")

    # Add deep scan tags - v4.5.16: Only if deep scan was actually executed
    deep_scan = host_record.get("deep_scan", {})
    smart_scan = host_record.get("smart_scan", {})
    deep_executed = smart_scan.get("deep_scan_executed", False)
    if deep_scan and deep_executed:
        tags.add("deep-scanned")
        if deep_scan.get("mac_address"):
            tags.add("mac-identified")

    # Add vulnerability tags
    if host_record.get("known_exploits"):
        tags.add("exploitable")

    return sorted(list(tags))


def build_ecs_event(scan_mode: str, scan_duration: str = None) -> Dict:
    """
    Build ECS-compliant event object.

    Args:
        scan_mode: Scan mode (rapido/normal/completo)
        scan_duration: Optional duration string

    Returns:
        ECS event dictionary
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "enrichment",
            "category": ["network", "host"],
            "type": ["info"],
            "module": "redaudit",
            "dataset": "redaudit.scan",
            "outcome": "success",
            "action": f"network-scan-{scan_mode}",
            "duration": scan_duration,
        },
    }


def build_ecs_host(host_record: Dict) -> Dict:
    """
    Build ECS-compliant host object from host record.

    Args:
        host_record: Host record dictionary

    Returns:
        ECS host dictionary
    """
    ecs_host = {
        "ip": [host_record.get("ip")] if host_record.get("ip") else [],
    }

    if host_record.get("hostname"):
        ecs_host["name"] = host_record["hostname"]
        ecs_host["hostname"] = host_record["hostname"]

    deep_scan = host_record.get("deep_scan", {})
    if deep_scan.get("mac_address"):
        ecs_host["mac"] = [deep_scan["mac_address"]]

    if deep_scan.get("vendor"):
        ecs_host["vendor"] = deep_scan["vendor"]

    return ecs_host


def is_rfc1918_address(ip_str: str) -> bool:
    """
    Check if an IP address is in RFC-1918 private range.

    v3.1.4: Used for adjusting severity of internal IP disclosure findings.

    Args:
        ip_str: IP address string

    Returns:
        True if RFC-1918 private address
    """
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def detect_nikto_false_positives(vuln_record: Dict) -> List[str]:
    """
    Detect potential Nikto false positives by cross-validating with curl/wget headers.

    v3.1.4: Cross-validation to reduce false positives.

    Args:
        vuln_record: Vulnerability record with nikto_findings and headers

    Returns:
        List of potential false positive descriptions
    """
    false_positives = []

    # Get captured headers
    curl_headers = (vuln_record.get("curl_headers") or "").lower()
    wget_headers = (vuln_record.get("wget_headers") or "").lower()
    all_headers = curl_headers + wget_headers

    if not all_headers:
        return []

    nikto_findings = vuln_record.get("nikto_findings", [])

    for finding in nikto_findings:
        finding_lower = finding.lower()

        # Check X-Content-Type-Options
        if "x-content-type-options" in finding_lower and "not set" in finding_lower:
            if "x-content-type-options: nosniff" in all_headers:
                false_positives.append(
                    "X-Content-Type-Options: Header present in response but Nikto reports missing"
                )

        # Check X-Frame-Options
        if "x-frame-options" in finding_lower and "not present" in finding_lower:
            if "x-frame-options:" in all_headers:
                false_positives.append(
                    "X-Frame-Options: Header present in response but Nikto reports missing"
                )

        # Check HSTS
        if "strict-transport-security" in finding_lower and "not defined" in finding_lower:
            if "strict-transport-security:" in all_headers:
                false_positives.append("HSTS: Header present in response but Nikto reports missing")

    return false_positives


def enrich_vulnerability_severity(vuln_record: Dict, asset_id: str = "") -> Dict:
    """
    Enrich a vulnerability record with severity scoring, finding_id, and category.

    v3.1: Added finding_id for dedup, category for classification, normalized_severity.
    v3.1.4: Added RFC-1918 severity adjustment and cross-validation for false positives.

    Args:
        vuln_record: Vulnerability dictionary
        asset_id: Observable hash of the parent asset (for finding_id generation)

    Returns:
        Enriched vulnerability with severity fields, finding_id, and category
    """
    enriched = vuln_record.copy()

    # Calculate max severity from all findings
    max_severity = "info"
    max_score = 0
    all_categories = set()
    primary_finding = ""
    has_rfc1918_finding = False
    source = str(vuln_record.get("source") or "").strip().lower()
    explicit_severity = str(vuln_record.get("severity") or "").strip()
    has_tool_findings = bool(vuln_record.get("nikto_findings")) or bool(
        vuln_record.get("testssl_analysis")
    )

    if explicit_severity and not has_tool_findings:
        max_severity, max_score = _severity_from_label(explicit_severity)
        primary_finding = (
            vuln_record.get("name")
            or vuln_record.get("descriptive_title")
            or vuln_record.get("description")
            or vuln_record.get("url")
            or ""
        )
        if primary_finding:
            cat = classify_finding_category(primary_finding)
            if cat != "surface":
                all_categories.add(cat)
        if source == "nuclei":
            all_categories.add("vuln")

    # Check Nikto findings
    for finding in vuln_record.get("nikto_findings", []):
        severity = calculate_severity(finding)
        score = SEVERITY_LEVELS[severity]["score"] if severity in SEVERITY_LEVELS else 0
        if score > max_score:
            max_score = score
            max_severity = severity
            primary_finding = finding

        # Collect categories from all findings
        cat = classify_finding_category(finding)
        if cat != "surface":
            all_categories.add(cat)

        # Track RFC-1918 findings
        if "rfc-1918" in finding.lower() and "ip address found" in finding.lower():
            has_rfc1918_finding = True

    # Check TestSSL vulnerabilities
    testssl = vuln_record.get("testssl_analysis", {})
    if testssl.get("vulnerabilities"):
        # TestSSL vulnerabilities are typically high severity
        if max_score < 70:
            max_score = 70
            max_severity = "high"
        all_categories.add("crypto")
        if not primary_finding and testssl.get("vulnerabilities"):
            primary_finding = (
                str(testssl["vulnerabilities"][0]) if testssl["vulnerabilities"] else ""
            )

    if testssl.get("weak_ciphers"):
        if max_score < 50:
            max_score = 50
            max_severity = "medium"
        all_categories.add("crypto")

    # v3.1.4: Adjust severity for RFC-1918 findings on private networks
    url = vuln_record.get("url", "")
    if has_rfc1918_finding and url:
        try:
            from urllib.parse import urlparse

            host = urlparse(url).hostname
            if host and is_rfc1918_address(host):
                # Internal IP disclosure on internal network is informational, not high
                if max_score >= 50:
                    max_score = 30
                    max_severity = "low"
                enriched["severity_note"] = (
                    "RFC-1918 disclosure on private network (reduced severity)"
                )
        except Exception:
            pass

    # Set severity fields
    enriched["severity"] = max_severity
    enriched["severity_score"] = max_score

    # v3.1: Add normalized_severity (0.0-10.0 scale, CVSS-like)
    enriched["normalized_severity"] = round(max_score / 10, 1)

    # v3.1: Preserve original tool severity for traceability
    # v4.13.2: Improved source attribution with whatweb detection, 'redaudit' fallback
    tool_name = source or (
        "nikto"
        if vuln_record.get("nikto_findings")
        else "testssl" if testssl else "whatweb" if vuln_record.get("whatweb") else "redaudit"
    )
    enriched["original_severity"] = {
        "tool": tool_name,
        "value": max_severity.upper(),
        "score": max_score,
    }

    # v3.1: Determine primary category
    if all_categories:
        # Priority: vuln > auth > crypto > misconfig > info-leak
        for cat in ["vuln", "auth", "crypto", "misconfig", "info-leak"]:
            if cat in all_categories:
                enriched["category"] = cat
                break
    else:
        enriched["category"] = "surface"

    # v3.1.4: Detect potential false positives via cross-validation
    fps = detect_nikto_false_positives(vuln_record)
    if fps:
        enriched["potential_false_positives"] = fps
        # v3.6.1: Degrade severity when cross-validation proves finding is wrong
        # Only degrade if the primary issue was one of the validated headers
        header_fp_count = sum(
            1 for fp in fps if any(h in fp for h in ["X-Frame-Options", "X-Content-Type", "HSTS"])
        )
        if header_fp_count > 0:
            enriched["verified"] = False
            enriched["severity_note"] = (
                enriched.get("severity_note", "")
                + f" Cross-validation detected {header_fp_count} likely false positive(s)."
            ).strip()
            # Degrade to info if all significant findings were false positives
            # Check if primary finding was one of the FP'd headers
            primary_lower = primary_finding.lower()
            if any(x in primary_lower for x in ["x-frame-options", "x-content-type", "hsts"]):
                enriched["severity"] = "info"
                enriched["severity_score"] = 10
                enriched["normalized_severity"] = 1.0

    # v3.1: Generate finding_id for deduplication
    port = vuln_record.get("port", 0)

    # Extract signature from CVE, template ID, Nikto plugin ID, or URL
    signature = ""
    cve_ids = vuln_record.get("cve_ids") or []
    if isinstance(cve_ids, list) and cve_ids:
        signature = str(cve_ids[0]).upper()
    template_id = vuln_record.get("template_id")
    if not signature and template_id:
        signature = str(template_id)
    if "cve-" in primary_finding.lower():
        match = re.search(r"(cve-\d{4}-\d+)", primary_finding.lower())
        if match:
            signature = match.group(1).upper()

    if not signature:
        # Use first meaningful finding line as signature
        for finding in vuln_record.get("nikto_findings", [])[:3]:
            if not any(x in finding.lower() for x in ["target ip:", "start time:", "end time:"]):
                signature = finding[:50]
                break

    if not signature:
        signature = url or f"port-{port}"

    enriched["finding_id"] = generate_finding_id(
        asset_id=asset_id,
        scanner="nikto" if vuln_record.get("nikto_findings") else "testssl",
        port=port,
        protocol="tcp",
        signature=signature,
        title=primary_finding[:100] if primary_finding else url,
    )

    # v4.6.19: Add confirmed_exploitable flag for findings with CVE or Nuclei validation
    has_cve = bool(cve_ids) or "cve-" in primary_finding.lower()
    has_nuclei = source == "nuclei" or bool(template_id)
    has_known_exploit = bool(vuln_record.get("known_exploits"))
    enriched["confirmed_exploitable"] = has_cve or has_nuclei or has_known_exploit

    # v4.6.19: Calculate priority_score for finding ordering
    # Higher = more critical (0-100 scale)
    priority = enriched["severity_score"]  # Base from severity

    # Boost for confirmed exploitable findings
    if enriched["confirmed_exploitable"]:
        priority += 20

    # Boost for CVE findings (evidence of real vulnerability)
    if has_cve:
        priority += 10

    # Penalty for likely false positives
    if enriched.get("potential_false_positives"):
        priority -= 30

    # Penalty for low-value header findings
    if enriched.get("category") == "misconfig":
        priority -= 10

    enriched["priority_score"] = max(0, min(100, priority))

    # v4.6.19: Add confidence_score (0.0-1.0) for report quality
    # Higher = more confident the finding is real and actionable
    confidence = 0.5  # Base confidence

    # Boost for confirmed sources
    if enriched["confirmed_exploitable"]:
        confidence += 0.3
    if has_cve:
        confidence += 0.1
    if vuln_record.get("testssl_analysis"):
        confidence += 0.1  # TestSSL findings are high-confidence

    # Penalty for potential false positives
    if enriched.get("potential_false_positives"):
        confidence -= 0.4

    # Slight boost for cross-validated (not FP'd) findings
    if enriched.get("verified") is True:
        confidence += 0.1

    enriched["confidence_score"] = round(max(0.0, min(1.0, confidence)), 2)

    return enriched


def generate_cef_line(
    host_record: Dict, vendor: str = "RedAudit", product: str = "NetworkScanner"
) -> str:
    """
    Generate CEF (Common Event Format) line for ArcSight/McAfee integration.

    Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Args:
        host_record: Host record dictionary
        vendor: Vendor name
        product: Product name

    Returns:
        CEF formatted string
    """
    from redaudit.utils.constants import VERSION

    ip = host_record.get("ip", "unknown")
    port_count = len(host_record.get("ports", []))
    risk = calculate_risk_score(host_record)

    # Map risk score to CEF severity (0-10)
    cef_severity = min(risk // 10, 10)

    # Build extension fields
    extensions = [
        f"src={ip}",
        f"spt={port_count}",
        f"cs1={host_record.get('status', 'unknown')}",
        "cs1Label=HostStatus",
    ]

    if host_record.get("hostname"):
        extensions.append(f"shost={host_record['hostname']}")

    deep = host_record.get("deep_scan", {})
    if deep.get("mac_address"):
        extensions.append(f"smac={deep['mac_address']}")

    extension_str = " ".join(extensions)

    return (
        f"CEF:0|{vendor}|{product}|{VERSION}|scan.host|Host Scanned|{cef_severity}|{extension_str}"
    )


def enrich_report_for_siem(results: Dict, config: Dict) -> Dict:
    """
    Main entry point: Enrich a complete scan report with SIEM-compatible fields.

    Adds:
    - ECS compliance fields
    - Severity scoring for vulnerabilities
    - Tags for hosts
    - Observable hashes for deduplication
    - Risk scores

    Args:
        results: Complete scan results dictionary
        config: Scan configuration dictionary

    Returns:
        Enriched results dictionary
    """
    enriched = results.copy()

    # Add ECS event metadata
    scan_mode = config.get("scan_mode", "normal")
    duration = results.get("summary", {}).get("duration")
    ecs_event = build_ecs_event(scan_mode, duration)
    enriched.update(ecs_event)

    # Enrich each host
    for host in enriched.get("hosts", []):
        # Add ECS host format
        host["ecs_host"] = build_ecs_host(host)

        # Add risk score with breakdown for HTML tooltips (v4.3)
        risk_result = calculate_risk_score_with_breakdown(host)
        host["risk_score"] = risk_result["score"]
        host["risk_score_breakdown"] = risk_result["breakdown"]

        # Add observable hash
        host["observable_hash"] = generate_observable_hash(host)

        # Add tags
        host["tags"] = generate_host_tags(host)

        # Best-effort asset type classification (useful for SIEM/JSONL)
        try:
            from redaudit.core.entity_resolver import guess_asset_type

            host["asset_type"] = guess_asset_type(host)
        except Exception:
            pass

    # Enrich vulnerabilities with severity, finding_id, category, and observations
    # Build host IP to observable_hash mapping for finding_id generation
    host_hash_map = {h.get("ip"): h.get("observable_hash", "") for h in enriched.get("hosts", [])}

    # v3.1: Import evidence parser for parsed_observations
    try:
        from redaudit.core.evidence_parser import enrich_with_observations

        has_evidence_parser = True
    except ImportError:
        has_evidence_parser = False

    encryption_enabled = bool(config.get("encryption_enabled"))
    output_dir = config.get("_actual_output_dir") if not encryption_enabled else None

    for vuln_entry in enriched.get("vulnerabilities", []):
        host_ip = vuln_entry.get("host", "")
        asset_id = host_hash_map.get(host_ip, "")

        for vuln in vuln_entry.get("vulnerabilities", []):
            enriched_vuln = enrich_vulnerability_severity(vuln, asset_id=asset_id)
            vuln.update(enriched_vuln)

            # v3.1: Add parsed observations
            if has_evidence_parser:
                obs_enriched = enrich_with_observations(vuln, output_dir)
                vuln.update(obs_enriched)

            evidence_meta = _build_evidence_meta(vuln)
            if evidence_meta:
                existing = vuln.get("evidence")
                if isinstance(existing, dict):
                    merged = {**existing, **evidence_meta}
                else:
                    merged = evidence_meta
                vuln["evidence"] = merged

    # Add summary statistics for SIEM dashboards
    summary = enriched.get("summary", {})
    hosts = enriched.get("hosts", [])

    if hosts:
        risk_scores = [h.get("risk_score", 0) for h in hosts]
        summary["max_risk_score"] = max(risk_scores) if risk_scores else 0
        summary["avg_risk_score"] = (
            round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
        )
        summary["high_risk_hosts"] = sum(1 for r in risk_scores if r >= 70)

    # v3.6.1: Consolidate duplicate findings by (host, title)
    enriched["vulnerabilities"] = consolidate_findings(enriched.get("vulnerabilities", []))

    return enriched


def _build_evidence_meta(vuln_record: Dict[str, Any]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}

    source = (
        vuln_record.get("source")
        or (vuln_record.get("original_severity") or {}).get("tool")
        or "redaudit"
    )
    if source:
        meta["source_tool"] = source

    matched_at = vuln_record.get("matched_at") or vuln_record.get("url")
    if matched_at:
        meta["matched_at"] = matched_at

    template_id = vuln_record.get("template_id")
    if template_id:
        meta["template_id"] = template_id

    raw_hash = vuln_record.get("raw_tool_output_sha256")
    if raw_hash:
        meta["raw_output_sha256"] = raw_hash

    raw_ref = vuln_record.get("raw_tool_output_ref")
    if raw_ref:
        meta["raw_output_ref"] = raw_ref

    signals = []
    if vuln_record.get("template_id") or vuln_record.get("matched_at"):
        signals.append("nuclei")
    if vuln_record.get("nikto_findings"):
        signals.append("nikto")
    if vuln_record.get("testssl_analysis"):
        signals.append("testssl")
    if vuln_record.get("whatweb"):
        signals.append("whatweb")
    if vuln_record.get("extracted_results") or vuln_record.get("extracted-results"):
        signals.append("extracted_results")
    if vuln_record.get("curl_headers") or vuln_record.get("wget_headers"):
        signals.append("http_headers")

    if signals:
        meta["signals"] = sorted({s for s in signals if s})

    return meta


def consolidate_findings(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Group findings by (host, descriptive_title) and merge into single entries.

    v3.6.1: Reduces noise when same vulnerability appears on multiple ports.
    Example: "Missing X-Frame-Options" on ports 8182, 8183, 8184 -> one finding.

    Args:
        vulnerabilities: List of vulnerability entries (host + vulnerabilities list)

    Returns:
        Consolidated list with affected_ports arrays
    """
    if not vulnerabilities:
        return []

    # Group by (host, title)
    grouped: Dict[Tuple[str, str, str], List[Dict]] = {}
    host_order: List[str] = []  # Preserve original order

    for entry in vulnerabilities:
        host = entry.get("host", "")
        if host not in host_order:
            host_order.append(host)

        for vuln in entry.get("vulnerabilities", []):
            title = vuln.get("descriptive_title") or vuln.get("url", "")
            key = (host, title, "")
            if str(vuln.get("source") or "").lower() == "nuclei":
                key = (host, title, vuln.get("matched_at") or vuln.get("url") or "")
            grouped.setdefault(key, []).append(vuln)

    # Rebuild consolidated list
    consolidated: Dict[str, List[Dict]] = {}
    for (host, _title, _match), vulns in grouped.items():
        if host not in consolidated:
            consolidated[host] = []

        if len(vulns) == 1:
            # Single finding - keep as-is
            consolidated[host].append(vulns[0])
        else:
            # Multiple findings with same title - merge
            merged = max(vulns, key=lambda v: v.get("severity_score", 0) or 0).copy()
            ports_set = set()
            for v in vulns:
                port = v.get("port")
                if port:
                    ports_set.add(port)
                for affected in v.get("affected_ports", []) or []:
                    if affected:
                        ports_set.add(affected)
            ports = sorted(ports_set)

            def _merge_unique_list(base, extra, limit=None):
                if not extra:
                    return base
                seen = set(base)
                for item in extra:
                    if item in seen:
                        continue
                    base.append(item)
                    seen.add(item)
                if limit:
                    return base[:limit]
                return base

            for v in vulns:
                if v.get("nikto_findings"):
                    merged["nikto_findings"] = _merge_unique_list(
                        list(merged.get("nikto_findings", []) or []),
                        v.get("nikto_findings", []),
                        limit=20,
                    )
                if v.get("parsed_observations"):
                    merged["parsed_observations"] = _merge_unique_list(
                        list(merged.get("parsed_observations", []) or []),
                        v.get("parsed_observations", []),
                        limit=20,
                    )
                if v.get("testssl_analysis"):
                    if not merged.get("testssl_analysis"):
                        merged["testssl_analysis"] = v["testssl_analysis"]
                    else:
                        base = merged.get("testssl_analysis") or {}
                        extra = v.get("testssl_analysis") or {}
                        for field_name in ("vulnerabilities", "weak_ciphers", "protocols"):
                            base_list = list(base.get(field_name, []) or [])
                            extra_list = list(extra.get(field_name, []) or [])
                            merged_list = _merge_unique_list(base_list, extra_list)
                            if merged_list:
                                base[field_name] = merged_list
                        if extra.get("summary") and not base.get("summary"):
                            base["summary"] = extra.get("summary")
                        merged["testssl_analysis"] = base
            if ports:
                merged["affected_ports"] = ports
                merged["consolidated_count"] = len(vulns)
                # Update severity note
                existing_note = merged.get("severity_note", "")
                merged["severity_note"] = (
                    f"{existing_note} Consolidated from {len(vulns)} findings.".strip()
                )
            consolidated[host].append(merged)

    # Return in original host order
    return [
        {"host": host, "vulnerabilities": consolidated.get(host, [])}
        for host in host_order
        if host in consolidated
    ]


def get_top_critical_findings(findings: List[Dict], limit: int = 5) -> List[Dict]:
    """
    Get the top N most critical findings sorted by priority_score.

    v4.6.19: Used for "Top Critical Findings" summary in reports.

    Args:
        findings: List of enriched finding dictionaries
        limit: Maximum number of findings to return (default 5)

    Returns:
        List of top findings sorted by priority_score descending
    """
    if not findings:
        return []

    # Filter to only confirmed exploitable or high-severity findings
    critical = [
        f for f in findings if f.get("confirmed_exploitable") or f.get("severity_score", 0) >= 70
    ]

    # Sort by priority_score descending, then severity_score
    sorted_findings = sorted(
        critical,
        key=lambda f: (f.get("priority_score", 0), f.get("severity_score", 0)),
        reverse=True,
    )

    return sorted_findings[:limit]
