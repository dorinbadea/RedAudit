#!/usr/bin/env python3
"""
RedAudit - SIEM Enhancement Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v2.9: SIEM-compatible output enhancements for Splunk, Elastic, QRadar, ArcSight.
Implements ECS (Elastic Common Schema), severity scoring, and CEF format.
"""

import hashlib
import json
import re
from typing import Dict, List, Optional, Tuple, TypedDict


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

# Asset type to tags mapping
ASSET_TYPE_TAGS = {
    "router": ["network", "infrastructure", "gateway"],
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
    Calculate overall risk score (0-100) for a host.

    Score is based on:
    - Number of open ports
    - Presence of known exploits
    - Service types (insecure services add points)
    - Deep scan findings

    Args:
        host_record: Host record dictionary

    Returns:
        Risk score 0-100
    """
    score = 0

    ports = host_record.get("ports", [])

    # Base score from number of open ports (max 20 points)
    score += min(len(ports) * 2, 20)

    # Known exploits (high impact)
    for port in ports:
        if port.get("known_exploits"):
            score += len(port["known_exploits"]) * 15

        # Insecure services
        service = (port.get("service") or "").lower()
        if service in ("telnet", "ftp", "rlogin", "rsh"):
            score += 10
        if "ssl" in service and port.get("port") not in (443, 8443):
            score += 5

    # Cap at 100
    return min(score, 100)


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

    # Add status-based tags
    status = host_record.get("status", "")
    if status == "filtered":
        tags.add("firewall-protected")

    # Add deep scan tags
    if host_record.get("deep_scan"):
        tags.add("deep-scanned")
        if host_record["deep_scan"].get("mac_address"):
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
    tool_name = source or (
        "nikto" if vuln_record.get("nikto_findings") else "testssl" if testssl else "unknown"
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

        # Add risk score
        host["risk_score"] = calculate_risk_score(host)

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
            merged = vulns[0].copy()
            ports = sorted(set(v.get("port") for v in vulns if v.get("port")))
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
