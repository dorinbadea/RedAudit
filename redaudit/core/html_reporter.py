#!/usr/bin/env python3
"""
RedAudit - HTML Report Generator
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.3: Generate interactive HTML reports with Bootstrap + Chart.js.
"""

import os
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

    return Environment(
        loader=PackageLoader("redaudit", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )


def prepare_report_data(results: Dict, config: Dict) -> Dict:
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
        host_table.append(
            {
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", "-"),
                "status": host.get("status", "up"),
                "ports_count": len(host.get("ports", [])),
                "risk_score": host.get("risk_score", 0),
                "mac": host.get("deep_scan", {}).get("mac_address", "-"),
                "vendor": host.get("deep_scan", {}).get("vendor", "-"),
            }
        )

    # Finding table data
    finding_table = []
    for vuln_entry in vulnerabilities:
        host_ip = vuln_entry.get("host", "")
        for vuln in vuln_entry.get("vulnerabilities", []):
            finding_table.append(
                {
                    "host": host_ip,
                    "url": vuln.get("url", "-"),
                    "severity": vuln.get("severity", "info"),
                    "category": vuln.get("category", "-"),
                    "title": _extract_finding_title(vuln),
                    "port": vuln.get("port", "-"),
                }
            )

    return {
        "version": VERSION,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_timestamp": results.get("timestamp", "-"),
        "target": ", ".join(config.get("target_networks", [])) or "-",
        "scan_mode": config.get("scan_mode", "-"),
        "summary": summary,
        "host_count": len(hosts),
        "finding_count": len(finding_table),
        "severity_counts": severity_counts,
        "top_ports": top_ports,
        "host_table": host_table,
        "finding_table": finding_table,
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


def generate_html_report(results: Dict, config: Dict) -> str:
    """
    Generate HTML report string from scan results.

    Args:
        results: Full scan results dictionary
        config: Scan configuration dictionary

    Returns:
        Rendered HTML string
    """
    env = get_template_env()
    template = env.get_template("report.html.j2")

    data = prepare_report_data(results, config)
    return template.render(**data)


def save_html_report(
    results: Dict,
    config: Dict,
    output_dir: str,
    filename: str = "report.html",
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
        html_content = generate_html_report(results, config)

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
