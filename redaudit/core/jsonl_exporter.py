#!/usr/bin/env python3
"""
RedAudit - JSONL Exporter Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.1: Generate flat JSONL exports for SIEM/AI pipelines.
Creates findings.jsonl, assets.jsonl, and summary.json.
"""

import os
import json
from typing import Any, Dict
from datetime import datetime

from redaudit.utils.constants import SECURE_FILE_MODE
from redaudit.core.siem import extract_finding_title


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

    session_id = results.get("session_id", "")
    schema_version = results.get("schema_version", "")
    scanner_versions = results.get("scanner_versions", {}) or {}
    redaudit_version = results.get("version") or scanner_versions.get("redaudit", "")
    scanner_info = results.get("scanner", {}) or {}
    scan_mode = scanner_info.get("mode") or scanner_info.get("mode_cli") or ""
    host_index = {
        h.get("ip"): h for h in results.get("hosts", []) if isinstance(h, dict) and h.get("ip")
    }

    with open(output_path, "w", encoding="utf-8") as f:
        for vuln_entry in results.get("vulnerabilities", []):
            host = vuln_entry.get("host", "")
            vulns = vuln_entry.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                continue
            host_info = host_index.get(host, {}) if host else {}
            asset_id = host_info.get("observable_hash", "")
            hostname = host_info.get("hostname", "")
            tags = host_info.get("tags", []) or []
            risk_score = host_info.get("risk_score", 0)
            status = host_info.get("status", "")

            for vuln in vulns:
                source = (
                    vuln.get("source") or (vuln.get("original_severity") or {}).get("tool") or ""
                )
                sources = []
                for candidate in (
                    source,
                    "nikto" if vuln.get("nikto_findings") else "",
                    "testssl" if vuln.get("testssl_analysis") else "",
                    "whatweb" if vuln.get("whatweb") else "",
                ):
                    if candidate and candidate not in sources:
                        sources.append(candidate)
                # v4.6.20: Use unified extract_finding_title from siem
                descriptive_title = extract_finding_title(vuln)
                finding = {
                    "finding_id": vuln.get("finding_id", ""),
                    "asset_id": asset_id,
                    "asset_ip": host,
                    "asset_hostname": hostname,
                    "asset_tags": tags,
                    "asset_risk_score": risk_score,
                    "asset_status": status,
                    "port": vuln.get("port", 0),
                    "url": vuln.get("url", ""),
                    "severity": vuln.get("severity", "info"),
                    "normalized_severity": vuln.get("normalized_severity", 0.0),
                    # v4.6.19: New quality fields
                    "confidence_score": vuln.get("confidence_score", 0.5),
                    "priority_score": vuln.get("priority_score", 0),
                    "confirmed_exploitable": vuln.get("confirmed_exploitable", False),
                    "category": vuln.get("category", "surface"),
                    # v4.6.20: Use descriptive_title for both fields for consistency with HTML
                    "title": descriptive_title,
                    "descriptive_title": descriptive_title,
                    "source": source,
                    "sources": sources,
                    "template_id": vuln.get("template_id", ""),
                    "cve_ids": vuln.get("cve_ids", []),
                    "matched_at": vuln.get("matched_at", ""),
                    "parsed_observations": vuln.get("parsed_observations", [])[:5],
                    "timestamp": results.get("timestamp_end", ""),
                    "scan_mode": scan_mode,
                    # Provenance: makes JSONL ingestion self-contained
                    "session_id": session_id,
                    "schema_version": schema_version,
                    "scanner": "RedAudit",
                    "scanner_version": redaudit_version,
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
    session_id = results.get("session_id", "")
    schema_version = results.get("schema_version", "")
    scanner_versions = results.get("scanner_versions", {}) or {}
    redaudit_version = results.get("version") or scanner_versions.get("redaudit", "")
    scanner_info = results.get("scanner", {}) or {}
    scan_mode = scanner_info.get("mode") or scanner_info.get("mode_cli") or ""

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
            deep = host.get("deep_scan", {}) or {}
            agentless = host.get("agentless_fingerprint", {}) or {}

            asset = {
                "asset_id": host.get("observable_hash", ""),
                "ip": ip,
                "hostname": host.get("hostname", ""),
                "status": host.get("status", "unknown"),
                "risk_score": host.get("risk_score", 0),
                "asset_type": host.get("asset_type", ""),
                "os_detected": host.get("os_detected") or deep.get("os_detected") or "",
                "total_ports": host.get("total_ports_found", 0),
                "web_ports": host.get("web_ports_count", 0),
                "finding_count": finding_counts.get(ip, 0),
                "tags": host.get("tags", []),
                "timestamp": results.get("timestamp_end", ""),
                "scan_mode": scan_mode,
                # Provenance: makes JSONL ingestion self-contained
                "session_id": session_id,
                "schema_version": schema_version,
                "scanner": "RedAudit",
                "scanner_version": redaudit_version,
            }

            # Add MAC if available
            ecs_host = host.get("ecs_host", {})
            if ecs_host.get("mac"):
                asset["mac"] = (
                    ecs_host["mac"][0] if isinstance(ecs_host["mac"], list) else ecs_host["mac"]
                )
            if ecs_host.get("vendor"):
                asset["vendor"] = ecs_host["vendor"]
            if agentless:
                filtered = {}
                for key in (
                    "domain",
                    "dns_domain_name",
                    "dns_computer_name",
                    "computer_name",
                    "os",
                    "http_title",
                    "http_server",
                    "smb_signing_required",
                    "smbv1_detected",
                    "product_version",
                    # v3.8.9: Device fingerprinting from HTTP title/server
                    "device_vendor",
                    "device_model",
                    "device_type",
                ):
                    if agentless.get(key) not in (None, ""):
                        filtered[key] = agentless.get(key)
                if filtered:
                    asset["agentless"] = filtered

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
    raw_total_findings = (results.get("summary", {}) or {}).get("vulns_found_raw")
    if raw_total_findings is None:
        raw_total_findings = total_findings

    config_snapshot = results.get("config_snapshot", {}) or {}
    scanner_meta = results.get("scanner", {}) or {}
    scan_mode = scanner_meta.get("mode") or config_snapshot.get("scan_mode")
    scan_mode_cli = (
        scanner_meta.get("mode_cli") or config_snapshot.get("scan_mode_cli") or scan_mode or ""
    )
    options = {
        "threads": config_snapshot.get("threads"),
        "udp_mode": config_snapshot.get("udp_mode"),
        "udp_top_ports": config_snapshot.get("udp_top_ports"),
        "topology_enabled": config_snapshot.get("topology_enabled"),
        "net_discovery_enabled": config_snapshot.get("net_discovery_enabled"),
        "net_discovery_redteam": config_snapshot.get("net_discovery_redteam"),
        "net_discovery_active_l2": config_snapshot.get("net_discovery_active_l2"),
        "scan_vulnerabilities": config_snapshot.get("scan_vulnerabilities"),
        "nuclei_enabled": config_snapshot.get("nuclei_enabled"),
        "nuclei_profile": config_snapshot.get("nuclei_profile"),
        "nuclei_full_coverage": config_snapshot.get("nuclei_full_coverage"),
        "cve_lookup_enabled": config_snapshot.get("cve_lookup_enabled"),
        "windows_verify_enabled": config_snapshot.get("windows_verify_enabled"),
    }
    options = {k: v for k, v in options.items() if v is not None}

    summary = {
        "schema_version": results.get("schema_version", "3.1"),
        "generated_at": results.get("generated_at", datetime.now().isoformat()),
        "session_id": results.get("session_id", ""),
        "scan_duration": results.get("summary", {}).get("duration", ""),
        "total_assets": len(results.get("hosts", [])),
        "total_findings": total_findings,
        "total_findings_raw": raw_total_findings,
        "severity_breakdown": severity_counts,
        "severity_counts": severity_counts,
        "category_breakdown": category_counts,
        "max_risk_score": results.get("summary", {}).get("max_risk_score", 0),
        "high_risk_assets": results.get("summary", {}).get("high_risk_hosts", 0),
        "targets": results.get("targets", []),
        "scanner_versions": results.get("scanner_versions", {}),
        "scan_mode": scan_mode or "",
        "scan_mode_cli": scan_mode_cli,
        "options": options,
        "pipeline": results.get("pipeline", {}),
        "smart_scan_summary": results.get("smart_scan_summary", {}),
        # Convenience: summary consumers frequently need RedAudit version
        "redaudit_version": results.get("version")
        or (results.get("scanner_versions", {}) or {}).get("redaudit", ""),
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


# v4.6.20: _extract_title moved to redaudit.core.siem.extract_finding_title
# for unified title generation across HTML and JSONL exporters
