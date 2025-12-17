#!/usr/bin/env python3
"""
RedAudit - JSONL Exporter Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.1: Generate flat JSONL exports for SIEM/AI pipelines.
Creates findings.jsonl, assets.jsonl, and summary.json.
"""

import os
import json
from typing import Any, Dict
from datetime import datetime

from redaudit.utils.constants import SECURE_FILE_MODE


def export_findings_jsonl(results: Dict, output_path: str) -> int:
    """
    Export findings as JSONL (one finding per line).

    Args:
        results: Complete scan results dictionary
        output_path: Path to output file

    Returns:
        Number of findings exported
    """
    count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        for vuln_entry in results.get("vulnerabilities", []):
            host = vuln_entry.get("host", "")

            for vuln in vuln_entry.get("vulnerabilities", []):
                finding = {
                    "finding_id": vuln.get("finding_id", ""),
                    "asset_ip": host,
                    "port": vuln.get("port", 0),
                    "url": vuln.get("url", ""),
                    "severity": vuln.get("severity", "info"),
                    "normalized_severity": vuln.get("normalized_severity", 0.0),
                    "category": vuln.get("category", "surface"),
                    "title": _extract_title(vuln),
                    "parsed_observations": vuln.get("parsed_observations", [])[:5],
                    "timestamp": results.get("timestamp_end", ""),
                }

                f.write(json.dumps(finding, ensure_ascii=False) + "\n")
                count += 1

    try:
        os.chmod(output_path, SECURE_FILE_MODE)
    except Exception:
        pass

    return count


def export_assets_jsonl(results: Dict, output_path: str) -> int:
    """
    Export assets as JSONL (one asset per line).

    Args:
        results: Complete scan results dictionary
        output_path: Path to output file

    Returns:
        Number of assets exported
    """
    count = 0

    # Build finding count per host
    finding_counts: Dict[str, int] = {}
    for vuln_entry in results.get("vulnerabilities", []):
        host = vuln_entry.get("host", "")
        finding_counts[host] = finding_counts.get(host, 0) + len(
            vuln_entry.get("vulnerabilities", [])
        )

    with open(output_path, "w", encoding="utf-8") as f:
        for host in results.get("hosts", []):
            ip = host.get("ip", "")

            asset = {
                "asset_id": host.get("observable_hash", ""),
                "ip": ip,
                "hostname": host.get("hostname", ""),
                "status": host.get("status", "unknown"),
                "risk_score": host.get("risk_score", 0),
                "total_ports": host.get("total_ports_found", 0),
                "web_ports": host.get("web_ports_count", 0),
                "finding_count": finding_counts.get(ip, 0),
                "tags": host.get("tags", []),
                "timestamp": results.get("timestamp_end", ""),
            }

            # Add MAC if available
            ecs_host = host.get("ecs_host", {})
            if ecs_host.get("mac"):
                asset["mac"] = (
                    ecs_host["mac"][0] if isinstance(ecs_host["mac"], list) else ecs_host["mac"]
                )
            if ecs_host.get("vendor"):
                asset["vendor"] = ecs_host["vendor"]

            f.write(json.dumps(asset, ensure_ascii=False) + "\n")
            count += 1

    try:
        os.chmod(output_path, SECURE_FILE_MODE)
    except Exception:
        pass

    return count


def export_summary_json(results: Dict, output_path: str) -> Dict:
    """
    Export compact summary for dashboards.

    Args:
        results: Complete scan results dictionary
        output_path: Path to output file

    Returns:
        Summary dictionary
    """
    # Count severities
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts: Dict[str, int] = {}

    for vuln_entry in results.get("vulnerabilities", []):
        for vuln in vuln_entry.get("vulnerabilities", []):
            sev = vuln.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

            cat = vuln.get("category", "surface")
            category_counts[cat] = category_counts.get(cat, 0) + 1

    total_findings = sum(severity_counts.values())

    summary = {
        "schema_version": results.get("schema_version", "3.1"),
        "generated_at": results.get("generated_at", datetime.now().isoformat()),
        "session_id": results.get("session_id", ""),
        "scan_duration": results.get("summary", {}).get("duration", ""),
        "total_assets": len(results.get("hosts", [])),
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "max_risk_score": results.get("summary", {}).get("max_risk_score", 0),
        "high_risk_assets": results.get("summary", {}).get("high_risk_hosts", 0),
        "targets": results.get("targets", []),
        "scanner_versions": results.get("scanner_versions", {}),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    try:
        os.chmod(output_path, SECURE_FILE_MODE)
    except Exception:
        pass

    return summary


def export_all(results: Dict, output_dir: str) -> Dict[str, Any]:
    """
    Export all JSONL/JSON views.

    Args:
        results: Complete scan results dictionary
        output_dir: Directory for output files

    Returns:
        Dictionary with counts of exported items
    """
    os.makedirs(output_dir, exist_ok=True)

    findings_path = os.path.join(output_dir, "findings.jsonl")
    assets_path = os.path.join(output_dir, "assets.jsonl")
    summary_path = os.path.join(output_dir, "summary.json")

    findings_count = export_findings_jsonl(results, findings_path)
    assets_count = export_assets_jsonl(results, assets_path)
    export_summary_json(results, summary_path)

    return {
        "findings": findings_count,
        "assets": assets_count,
        "files": [findings_path, assets_path, summary_path],
    }


def _extract_title(vuln: Dict) -> str:
    """
    Extract a descriptive title from vulnerability record.

    v3.1.4: Generate human-readable titles based on finding type
    instead of generic "Finding on URL" messages.
    """
    import re

    obs = vuln.get("parsed_observations", [])

    # Generate descriptive title based on observations
    for observation in obs:
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

        # CVE references
        if "cve-" in obs_lower:
            match = re.search(r"(cve-\d{4}-\d+)", obs_lower)
            if match:
                return f"Known Vulnerability: {match.group(1).upper()}"

        # Information disclosure
        if "rfc-1918" in obs_lower or "private ip" in obs_lower:
            return "Internal IP Address Disclosed in Headers"
        if "server banner" in obs_lower and "no banner" not in obs_lower:
            return "Server Version Disclosed in Banner"

    # Fallback to URL-based title with port
    url = vuln.get("url", "")
    port = vuln.get("port", 0)

    if url:
        return f"Web Service Finding on Port {port}"

    return f"Service Finding on Port {port}"
