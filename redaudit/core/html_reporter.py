#!/usr/bin/env python3
"""
RedAudit - HTML Report Generator
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.3: Generate interactive HTML reports with Bootstrap + Chart.js.
"""

import os
import re
from datetime import datetime
from typing import Dict, Optional

from redaudit.utils.constants import SECURE_FILE_MODE, VERSION


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
    for host in hosts:
        agentless = host.get("agentless_fingerprint", {}) or {}
        agentless_summary = (
            agentless.get("computer_name")
            or agentless.get("dns_computer_name")
            or agentless.get("http_title")
            or agentless.get("domain")
            or "-"
        )
        host_table.append(
            {
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", "-"),
                "status": host.get("status", "up"),
                "ports_count": len(host.get("ports", [])),
                "risk_score": host.get("risk_score", 0),
                "mac": host.get("deep_scan", {}).get("mac_address", "-"),
                "vendor": host.get("deep_scan", {}).get("vendor", "-"),
                "os": host.get("os_detected")
                or host.get("deep_scan", {}).get("os_detected")
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
            source = (
                vuln.get("source") or (vuln.get("original_severity") or {}).get("tool") or "unknown"
            )
            cve_ids = vuln.get("cve_ids") or []
            cve_txt = ", ".join(cve_ids[:3]) if isinstance(cve_ids, list) else ""
            # Extract observations for technical details
            observations = vuln.get("parsed_observations") or vuln.get("nikto_findings") or []
            if isinstance(observations, list):
                observations = [obs for obs in observations[:5] if obs]  # Limit to 5
            else:
                observations = []

            title = _extract_finding_title(vuln)
            if lang:
                title = _translate_finding_title(title, lang)

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
        "scan_duration": summary.get("duration", "-"),
    }


def _extract_finding_title(vuln: Dict) -> str:
    """Extract a readable title from a vulnerability finding."""
    # Use descriptive_title if available (v3.1.4+)
    if vuln.get("descriptive_title"):
        return vuln["descriptive_title"]

    # Fallback: first nikto finding or URL
    nikto = vuln.get("nikto_findings", [])
    if nikto and isinstance(nikto, list) and len(nikto) > 0:
        first = nikto[0]
        # Skip metadata lines
        if not any(x in first.lower() for x in ["target ip:", "start time:", "end time:"]):
            return first[:80] + ("..." if len(first) > 80 else "")

    return vuln.get("url", "Finding")[:60]


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
                r"^Missing X-Frame-Options Header(?: \\(Clickjacking Risk\\))?$",
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
            re.compile(r"^Web Service Finding on Port (\\d+)$", re.IGNORECASE),
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
