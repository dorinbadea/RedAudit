#!/usr/bin/env python3
"""
RedAudit - HTML Report Generator
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.3: Generate interactive HTML reports with Bootstrap + Chart.js.
"""

import os
import re
import json
import xml.dom.minidom  # nosec B408
from datetime import datetime
from typing import Dict, Optional

from redaudit.utils.constants import SECURE_FILE_MODE, VERSION
from redaudit.utils.vendor_hints import get_best_vendor
from redaudit.core.siem import extract_finding_title


def _get_reverse_dns(host: Dict) -> str:
    """Extract first reverse DNS entry for hostname fallback."""
    # Source 1: dns.reverse (from enrich_host_with_dns)
    dns = host.get("dns", {})
    reverse = dns.get("reverse", [])
    if reverse and isinstance(reverse, list) and reverse[0]:
        return reverse[0].rstrip(".")
    # Source 2: phase0_enrichment.dns_reverse (from low_impact_enrichment)
    phase0 = host.get("phase0_enrichment", {})
    if isinstance(phase0, dict) and phase0.get("dns_reverse"):
        return str(phase0["dns_reverse"]).rstrip(".")
    return ""


def get_template_env():
    """
    Get Jinja2 environment configured for RedAudit templates.

    Returns:
        Configured Jinja2 Environment

    Raises:
        ImportError: If jinja2 is not installed
    """
    from jinja2 import Environment, PackageLoader, select_autoescape

    env = Environment(
        loader=PackageLoader("redaudit", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )

    # Custom filter for extracting filename from path
    def basename_filter(path):
        if not path:
            return ""
        return os.path.basename(str(path))

    env.filters["basename"] = basename_filter
    return env


def prepare_report_data(results: Dict, config: Dict, *, lang: str = "en") -> Dict:
    """
    Prepare data for HTML template rendering.

    Args:
        results: Full scan results dictionary
        config: Scan configuration dictionary

    Returns:
        Template-ready data dictionary
    """
    hosts = results.get("hosts", [])
    vulnerabilities = results.get("vulnerabilities", [])
    summary = results.get("summary", {})
    pipeline = results.get("pipeline", {}) or {}
    smart_scan_summary = results.get("smart_scan_summary", {}) or {}
    config_snapshot = results.get("config_snapshot", {}) or {}

    # Severity distribution for chart
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln_entry in vulnerabilities:
        for vuln in vuln_entry.get("vulnerabilities", []):
            sev = vuln.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # Top ports for chart
    port_counts: Dict[int, int] = {}
    for host in hosts:
        for port_info in host.get("ports", []):
            port = port_info.get("port")
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1

    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Host table data
    host_table = []
    # v3.10.2: Detect scanner's own IPs to mark as "Auditor Node"
    scanner_ips = {n.get("ip") for n in results.get("network_info", []) if n.get("ip")}
    for host in hosts:
        agentless = host.get("agentless_fingerprint", {}) or {}
        agentless_summary = (
            agentless.get("computer_name")
            or agentless.get("dns_computer_name")
            or agentless.get("http_title")
            or agentless.get("domain")
            or "-"
        )
        # v3.10.1: Get MAC from multiple sources, vendor with hostname fallback
        deep_scan = host.get("deep_scan", {}) or {}
        # v3.10.2: Fix MAC extraction - check both mac_address (canonical) and mac (legacy)
        mac_address = (
            deep_scan.get("mac_address") or host.get("mac_address") or host.get("mac") or ""
        )
        # v3.10.2: Mark scanner's own IPs as "Auditor Node" when MAC unavailable
        host_ip = host.get("ip", "")
        if not mac_address and host_ip in scanner_ips:
            mac_address = "(Auditor Node)" if lang != "es" else "(Nodo Auditor)"
        elif not mac_address:
            mac_address = "-"
        mac_vendor = deep_scan.get("vendor")
        hostname = host.get("hostname") or _get_reverse_dns(host) or "-"
        # Use vendor_hints for hostname-based fallback when MAC vendor missing
        display_vendor = get_best_vendor(mac_vendor, hostname, allow_guess=True) or "-"
        # v4.3: Extract identity_score and signals from smart_scan
        smart_scan = host.get("smart_scan", {}) or {}
        identity_score = smart_scan.get("identity_score", 0)
        identity_signals = smart_scan.get("identity_signals", [])
        host_table.append(
            {
                "ip": host.get("ip", ""),
                "hostname": hostname,
                "status": host.get("status", "up"),
                "ports_count": len(host.get("ports", [])),
                "risk_score": host.get("risk_score", 0),
                "risk_score_breakdown": host.get("risk_score_breakdown", {}),
                "identity_score": identity_score,
                "identity_signals": identity_signals,
                "mac": mac_address,
                "vendor": display_vendor,
                "os": host.get("os_detected")
                or deep_scan.get("os_detected")
                or agentless.get("os", "-"),
                "asset_type": host.get("asset_type", "-"),
                "tags": ", ".join(host.get("tags", [])),
                "agentless": agentless_summary,
            }
        )

    # Finding table data
    finding_table = []
    for vuln_entry in vulnerabilities:
        host_ip = vuln_entry.get("host", "")
        for vuln in vuln_entry.get("vulnerabilities", []):
            # v4.13.2: Changed fallback from 'unknown' to 'redaudit' for auto-generated findings
            source = (
                vuln.get("source")
                or (vuln.get("original_severity") or {}).get("tool")
                or "redaudit"
            )
            cve_ids = vuln.get("cve_ids") or []
            cve_txt = ", ".join(cve_ids[:3]) if isinstance(cve_ids, list) else ""
            # Extract observations for technical details
            observations = vuln.get("parsed_observations") or vuln.get("nikto_findings") or []
            if isinstance(observations, list):
                observations = [obs for obs in observations[:5] if obs]  # Limit to 5
            else:
                observations = []
            # v4.13.2: Fallback to description if no observations
            if not observations:
                desc_fallback = vuln.get("description") or vuln.get("info", {}).get(
                    "description", ""
                )
                if desc_fallback:
                    observations = [desc_fallback]

            title = _extract_finding_title(vuln)
            if lang:
                title = _translate_finding_title(title, lang)

            # v4.3.0: Extract rich details
            # v4.13.2: Fixed key mismatch - nuclei outputs "reference", not "references"
            description = vuln.get("description") or vuln.get("info", {}).get("description", "")
            references = (
                vuln.get("reference")
                or vuln.get("references")
                or vuln.get("info", {}).get("reference", [])
            )
            if not references and cve_ids:
                references = [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cve_ids]

            evidence = ""
            extracted_results = vuln.get("extracted_results") or vuln.get("extracted-results") or []
            if extracted_results:
                raw_evidence = "\n".join(str(r) for r in extracted_results)
                # Try to pretty print if it looks like XML
                if raw_evidence.strip().startswith("<") and raw_evidence.strip().endswith(">"):
                    try:
                        dom = xml.dom.minidom.parseString(raw_evidence)  # nosec B318
                        evidence = dom.toprettyxml()
                    except Exception:
                        evidence = raw_evidence
                # Try to pretty print if it looks like JSON
                elif raw_evidence.strip().startswith("{") and raw_evidence.strip().endswith("}"):
                    try:
                        obj = json.loads(raw_evidence)
                        evidence = json.dumps(obj, indent=2)
                    except Exception:
                        evidence = raw_evidence
                else:
                    evidence = raw_evidence

            finding_table.append(
                {
                    "host": host_ip,
                    "url": vuln.get("matched_at") or vuln.get("url", "-"),
                    "severity": vuln.get("severity", "info"),
                    "category": vuln.get("category", "-"),
                    "title": title,
                    "port": vuln.get("port", "-"),
                    "source": source,
                    "cve": cve_txt,
                    "observations": observations,
                    # v4.3.0: Rich details
                    "description": description,
                    "references": references,
                    "evidence": evidence,
                    "template_id": vuln.get("template_id"),
                }
            )

    # Extract smart scan reasons for display
    smart_scan_reasons = smart_scan_summary.get("reasons", {}) or {}

    # Extract topology data
    topology = pipeline.get("topology", {}) or {}
    topology_summary = {
        "default_gateway": topology.get("default_gateway", {}).get("ip", "-"),
        "interfaces": len(topology.get("interfaces", [])),
        "routes": len(topology.get("routes", [])),
        # v3.9.0: Include route details for explicit display
        "routes_list": [
            {
                "dst": r.get("dst", "-"),
                "via": r.get("via", "-"),
                "dev": r.get("dev", "-"),
            }
            for r in topology.get("routes", [])
        ],
    }

    # Extract playbooks from results
    playbooks = results.get("playbooks", []) or []

    # Extract artifacts/evidence
    artifacts = results.get("artifacts", []) or []
    pcaps = [a for a in artifacts if a.get("path", "").endswith(".pcap")]

    nuclei_data = results.get("nuclei") or {}
    suspected_items = nuclei_data.get("suspected") or []
    nuclei_suspected = []
    for item in suspected_items:
        if not isinstance(item, dict):
            continue
        nuclei_suspected.append(
            {
                "template_id": item.get("template_id") or "-",
                "matched_at": item.get("matched_at") or "-",
                "fp_reason": item.get("fp_reason") or "",
            }
        )

    return {
        "version": VERSION,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_timestamp": results.get("timestamp", "-"),
        "target": ", ".join(config.get("target_networks", [])) or "-",
        "scan_mode": config.get("scan_mode", "-"),
        "auditor_name": config.get("auditor_name") or "",
        "summary": summary,
        "host_count": len(hosts),
        "finding_count": len(finding_table),
        "severity_counts": severity_counts,
        "top_ports": top_ports,
        "host_table": host_table,
        "finding_table": finding_table,
        "pipeline": pipeline,
        "smart_scan": smart_scan_summary,
        "smart_scan_reasons": smart_scan_reasons,
        "config_snapshot": config_snapshot,
        "topology_summary": topology_summary,
        "playbooks": playbooks,
        "pcaps": pcaps,
        "nuclei_suspected": nuclei_suspected,
        "scan_duration": summary.get("duration", "-"),
    }


def _extract_finding_title(vuln: Dict) -> str:
    """
    Extract a readable title from a vulnerability finding.

    v4.6.20: Now delegates to unified extract_finding_title from siem.py.
    """
    # Use unified function from siem module
    return extract_finding_title(vuln)


def _translate_finding_title(title: str, lang: str) -> str:
    if not title or lang.lower() != "es":
        return title

    patterns = [
        (
            re.compile(r"^Missing X-Content-Type-Options Header$", re.IGNORECASE),
            "Falta la cabecera X-Content-Type-Options",
        ),
        (
            re.compile(
                r"^Missing X-Frame-Options Header(?: \(Clickjacking Risk\))?$",
                re.IGNORECASE,
            ),
            "Falta la cabecera X-Frame-Options (riesgo de clickjacking)",
        ),
        (
            re.compile(r"^Missing HTTP Strict Transport Security Header$", re.IGNORECASE),
            "Falta la cabecera HTTP Strict Transport Security (HSTS)",
        ),
        (
            re.compile(r"^Missing HSTS header$", re.IGNORECASE),
            "Falta la cabecera HSTS",
        ),
        (
            re.compile(r"^Internal IP Address Disclosed in Headers$", re.IGNORECASE),
            "Dirección IP interna expuesta en cabeceras",
        ),
        (
            re.compile(r"^Web Service Finding on Port (\d+)$", re.IGNORECASE),
            None,
        ),
    ]

    for pattern, replacement in patterns:
        match = pattern.match(title.strip())
        if not match:
            continue
        if replacement is None:
            return f"Hallazgo de servicio web en el puerto {match.group(1)}"
        return replacement

    return title


def generate_html_report(results: Dict, config: Dict, *, lang: str = "en") -> str:
    """
    Generate HTML report string from scan results.

    Args:
        results: Full scan results dictionary
        config: Scan configuration dictionary

    Returns:
        Rendered HTML string
    """
    env = get_template_env()
    template_name = "report_es.html.j2" if lang == "es" else "report.html.j2"
    template = env.get_template(template_name)

    data = prepare_report_data(results, config, lang=lang)
    return template.render(**data)


def save_html_report(
    results: Dict,
    config: Dict,
    output_dir: str,
    filename: str = "report.html",
    *,
    lang: str = "en",
) -> Optional[str]:
    """
    Generate and save HTML report to file.

    Args:
        results: Full scan results dictionary
        config: Scan configuration dictionary
        output_dir: Directory to save report
        filename: Output filename

    Returns:
        Path to saved file, or None on error
    """
    try:
        html_content = generate_html_report(results, config, lang=lang)

        output_path = os.path.join(output_dir, filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        try:
            os.chmod(output_path, SECURE_FILE_MODE)
        except Exception:
            pass

        return output_path
    except Exception as e:
        # Log error but don't crash
        import logging

        logging.getLogger(__name__).warning(f"Failed to generate HTML report: {e}")
        return None
