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
from typing import Dict, List, Optional, Any
from datetime import datetime


# ECS Version for Elastic integration
ECS_VERSION = "8.11"

# Severity levels with numeric scores for SIEM correlation
SEVERITY_LEVELS = {
    "critical": {"score": 90, "color": "red"},
    "high": {"score": 70, "color": "orange"},
    "medium": {"score": 50, "color": "yellow"},
    "low": {"score": 30, "color": "blue"},
    "info": {"score": 10, "color": "gray"},
}

# Keywords to detect severity from findings
SEVERITY_KEYWORDS = {
    "critical": ["rce", "remote code execution", "unauthenticated", "critical", "backdoor", "rootkit"],
    "high": ["sql injection", "xss", "cross-site", "authentication bypass", "vulnerable", "exploit", "cve-"],
    "medium": ["information disclosure", "directory listing", "weak cipher", "ssl", "tls 1.0", "tls 1.1"],
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
            return re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", finding_lower) is not None

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
        "ports": sorted([
            f"{p.get('port')}/{p.get('protocol')}/{p.get('service', '')}"
            for p in host_record.get("ports", [])
        ])
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
        }
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


def enrich_vulnerability_severity(vuln_record: Dict) -> Dict:
    """
    Enrich a vulnerability record with severity scoring.
    
    Args:
        vuln_record: Vulnerability dictionary
        
    Returns:
        Enriched vulnerability with severity fields
    """
    enriched = vuln_record.copy()
    
    # Calculate max severity from all findings
    max_severity = "info"
    max_score = 0
    
    # Check Nikto findings
    for finding in vuln_record.get("nikto_findings", []):
        severity = calculate_severity(finding)
        score = SEVERITY_LEVELS.get(severity, {}).get("score", 0)
        if score > max_score:
            max_score = score
            max_severity = severity
    
    # Check TestSSL vulnerabilities
    testssl = vuln_record.get("testssl_analysis", {})
    if testssl.get("vulnerabilities"):
        # TestSSL vulnerabilities are typically high severity
        if max_score < 70:
            max_score = 70
            max_severity = "high"
    
    if testssl.get("weak_ciphers"):
        if max_score < 50:
            max_score = 50
            max_severity = "medium"
    
    enriched["severity"] = max_severity
    enriched["severity_score"] = max_score
    
    return enriched


def generate_cef_line(host_record: Dict, vendor: str = "RedAudit", product: str = "NetworkScanner") -> str:
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
        f"cs1Label=HostStatus",
    ]
    
    if host_record.get("hostname"):
        extensions.append(f"shost={host_record['hostname']}")
    
    deep = host_record.get("deep_scan", {})
    if deep.get("mac_address"):
        extensions.append(f"smac={deep['mac_address']}")
    
    extension_str = " ".join(extensions)
    
    return f"CEF:0|{vendor}|{product}|{VERSION}|scan.host|Host Scanned|{cef_severity}|{extension_str}"


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
    
    # Enrich vulnerabilities with severity
    for vuln_entry in enriched.get("vulnerabilities", []):
        for vuln in vuln_entry.get("vulnerabilities", []):
            enriched_vuln = enrich_vulnerability_severity(vuln)
            vuln.update(enriched_vuln)
    
    # Add summary statistics for SIEM dashboards
    summary = enriched.get("summary", {})
    hosts = enriched.get("hosts", [])
    
    if hosts:
        risk_scores = [h.get("risk_score", 0) for h in hosts]
        summary["max_risk_score"] = max(risk_scores) if risk_scores else 0
        summary["avg_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
        summary["high_risk_hosts"] = sum(1 for r in risk_scores if r >= 70)
    
    return enriched
