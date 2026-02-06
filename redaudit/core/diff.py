#!/usr/bin/env python3
"""
RedAudit - Differential Analysis Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.0: Compare two JSON reports and generate delta analysis.
Identifies new hosts, removed hosts, new ports, closed ports, and new vulnerabilities.
"""

import json
import os
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

from redaudit.utils.constants import VERSION


def load_report(path: str) -> Optional[Dict]:
    """
    Load and validate a RedAudit JSON report.

    Args:
        path: Path to JSON report file

    Returns:
        Parsed report dict or None on error
    """
    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Validate it's a RedAudit report
        if "version" not in data or "hosts" not in data:
            return None

        return data
    except (json.JSONDecodeError, IOError):
        return None


def extract_host_index(report: Dict) -> Dict[str, Dict]:
    """
    Create an index of hosts by IP for fast lookup.

    Args:
        report: RedAudit report dict

    Returns:
        Dict mapping IP to host record
    """
    index = {}
    for host in report.get("hosts", []):
        ip = host.get("ip")
        if ip:
            index[ip] = host
    return index


def extract_ports_set(host: Dict) -> Set[Tuple[int, str]]:
    """
    Extract set of (port, service) tuples from a host.

    Args:
        host: Host record dict

    Returns:
        Set of (port, service) tuples
    """
    ports = set()
    for port_info in host.get("ports", []):
        port = port_info.get("port")
        service = port_info.get("service", "unknown")
        if port:
            ports.add((port, service))
    return ports


def extract_web_vulns_index(report: Dict) -> Dict[str, Dict]:
    """
    Extract web vulnerabilities by host from the vulnerabilities[] array.

    Args:
        report: Full scan report

    Returns:
        Dict mapping host IP to vulnerability counts by tool
    """
    vuln_index = {}
    for entry in report.get("vulnerabilities", []):
        host = entry.get("host", "")
        if not host:
            continue

        counts = {
            "nikto_count": 0,
            "whatweb_count": 0,
            "testssl_count": 0,
            "total_findings": 0,
        }

        for finding in entry.get("vulnerabilities", []):
            # Count Nikto findings
            nikto = finding.get("nikto_findings", [])
            counts["nikto_count"] += len(nikto) if isinstance(nikto, list) else 0

            # Count WhatWeb results
            whatweb = finding.get("whatweb", {})
            if whatweb and isinstance(whatweb, dict):
                counts["whatweb_count"] += 1

            # Count TestSSL vulnerabilities
            testssl = finding.get("testssl", {})
            if testssl:
                tssl_vulns = testssl.get("vulnerabilities", [])
                counts["testssl_count"] += len(tssl_vulns) if isinstance(tssl_vulns, list) else 0

        counts["total_findings"] = (
            counts["nikto_count"] + counts["whatweb_count"] + counts["testssl_count"]
        )

        vuln_index[host] = counts

    return vuln_index


def compare_hosts(old_report: Dict, new_report: Dict) -> Dict:
    """
    Compare two reports and identify host-level changes.

    Args:
        old_report: Previous scan report
        new_report: Current scan report

    Returns:
        Dict with new_hosts, removed_hosts lists
    """
    old_index = extract_host_index(old_report)
    new_index = extract_host_index(new_report)

    old_ips = set(old_index.keys())
    new_ips = set(new_index.keys())

    return {
        "new_hosts": list(new_ips - old_ips),
        "removed_hosts": list(old_ips - new_ips),
        "common_hosts": list(old_ips & new_ips),
    }


def compare_single_host(old_host: Dict, new_host: Dict) -> Dict:
    """
    Compare port/service changes for a single host.

    Args:
        old_host: Previous host record
        new_host: Current host record

    Returns:
        Dict with port changes
    """
    old_ports = extract_ports_set(old_host)
    new_ports = extract_ports_set(new_host)

    new_opened = new_ports - old_ports
    closed = old_ports - new_ports

    # Check for new vulnerabilities
    old_vulns = set()
    new_vulns = set()

    for port_info in old_host.get("ports", []):
        for exploit in port_info.get("known_exploits", []):
            old_vulns.add(exploit[:100])

    for port_info in new_host.get("ports", []):
        for exploit in port_info.get("known_exploits", []):
            new_vulns.add(exploit[:100])

    return {
        "new_ports": [{"port": p, "service": s} for p, s in sorted(new_opened)],
        "closed_ports": [{"port": p, "service": s} for p, s in sorted(closed)],
        "new_vulnerabilities": list(new_vulns - old_vulns),
        "resolved_vulnerabilities": list(old_vulns - new_vulns),
    }


def generate_diff_report(old_path: str, new_path: str) -> Optional[Dict]:
    """
    Generate comprehensive diff report between two scans.

    Args:
        old_path: Path to previous scan JSON
        new_path: Path to current scan JSON

    Returns:
        Diff report dict or None on error
    """
    old_report = load_report(old_path)
    new_report = load_report(new_path)

    if not old_report or not new_report:
        return None

    # Compare hosts
    host_comparison = compare_hosts(old_report, new_report)

    # Compare ports for common hosts
    old_index = extract_host_index(old_report)
    new_index = extract_host_index(new_report)

    changed_hosts = []
    for ip in host_comparison["common_hosts"]:
        changes = compare_single_host(old_index[ip], new_index[ip])
        if changes["new_ports"] or changes["closed_ports"] or changes["new_vulnerabilities"]:
            changes["ip"] = ip
            changes["hostname"] = new_index[ip].get("hostname", "")
            changed_hosts.append(changes)

    # Compare web vulnerabilities (v3.0.1)
    old_web_vulns = extract_web_vulns_index(old_report)
    new_web_vulns = extract_web_vulns_index(new_report)

    web_vuln_changes = []
    all_hosts = set(old_web_vulns.keys()) | set(new_web_vulns.keys())
    for host in all_hosts:
        old_counts = old_web_vulns.get(
            host, {"total_findings": 0, "nikto_count": 0, "whatweb_count": 0, "testssl_count": 0}
        )
        new_counts = new_web_vulns.get(
            host, {"total_findings": 0, "nikto_count": 0, "whatweb_count": 0, "testssl_count": 0}
        )

        delta = new_counts["total_findings"] - old_counts["total_findings"]
        if delta != 0:
            web_vuln_changes.append(
                {
                    "host": host,
                    "delta": delta,
                    "old_count": old_counts["total_findings"],
                    "new_count": new_counts["total_findings"],
                    "nikto_delta": new_counts["nikto_count"] - old_counts["nikto_count"],
                    "testssl_delta": new_counts["testssl_count"] - old_counts["testssl_count"],
                }
            )

    total_web_vuln_delta = sum(c["delta"] for c in web_vuln_changes)

    # Calculate summary statistics
    total_new_ports = sum(len(h["new_ports"]) for h in changed_hosts)
    total_closed_ports = sum(len(h["closed_ports"]) for h in changed_hosts)
    total_new_vulns = sum(len(h["new_vulnerabilities"]) for h in changed_hosts)

    return {
        "diff_version": VERSION,
        "generated_at": datetime.now().isoformat(),
        "old_report": {
            "path": os.path.basename(old_path),
            "timestamp": old_report.get("timestamp", "unknown"),
            "total_hosts": len(old_report.get("hosts", [])),
        },
        "new_report": {
            "path": os.path.basename(new_path),
            "timestamp": new_report.get("timestamp", "unknown"),
            "total_hosts": len(new_report.get("hosts", [])),
        },
        "changes": {
            "new_hosts": host_comparison["new_hosts"],
            "removed_hosts": host_comparison["removed_hosts"],
            "changed_hosts": changed_hosts,
            "web_vuln_changes": web_vuln_changes,  # v3.0.1: web findings diff
        },
        "summary": {
            "new_hosts_count": len(host_comparison["new_hosts"]),
            "removed_hosts_count": len(host_comparison["removed_hosts"]),
            "changed_hosts_count": len(changed_hosts),
            "total_new_ports": total_new_ports,
            "total_closed_ports": total_closed_ports,
            "total_new_vulnerabilities": total_new_vulns,
            "web_vuln_delta": total_web_vuln_delta,  # v3.0.1: net change in web findings
            "has_changes": bool(
                host_comparison["new_hosts"]
                or host_comparison["removed_hosts"]
                or changed_hosts
                or web_vuln_changes
            ),
        },
    }


def format_diff_text(diff: Dict) -> str:
    """
    Format diff report as human-readable text.

    Args:
        diff: Diff report dict

    Returns:
        Formatted text string
    """
    lines = []
    lines.append("=" * 60)
    lines.append("RedAudit Differential Analysis Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Generated: {diff['generated_at']}")
    lines.append(f"Old Report: {diff['old_report']['path']} ({diff['old_report']['timestamp']})")
    lines.append(f"New Report: {diff['new_report']['path']} ({diff['new_report']['timestamp']})")
    lines.append("")

    summary = diff["summary"]
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  New hosts discovered: {summary['new_hosts_count']}")
    lines.append(f"  Hosts removed/offline: {summary['removed_hosts_count']}")
    lines.append(f"  Hosts with changes: {summary['changed_hosts_count']}")
    lines.append(f"  New ports opened: {summary['total_new_ports']}")
    lines.append(f"  Ports closed: {summary['total_closed_ports']}")
    lines.append(f"  New vulnerabilities: {summary['total_new_vulnerabilities']}")
    web_delta = summary.get("web_vuln_delta", 0)
    if web_delta != 0:
        delta_str = f"+{web_delta}" if web_delta > 0 else str(web_delta)
        lines.append(f"  Web findings delta: {delta_str}")
    lines.append("")

    changes = diff["changes"]

    if changes["new_hosts"]:
        lines.append("NEW HOSTS")
        lines.append("-" * 40)
        for ip in changes["new_hosts"]:
            lines.append(f"  [+] {ip}")
        lines.append("")

    if changes["removed_hosts"]:
        lines.append("REMOVED HOSTS")
        lines.append("-" * 40)
        for ip in changes["removed_hosts"]:
            lines.append(f"  [-] {ip}")
        lines.append("")

    if changes["changed_hosts"]:
        lines.append("CHANGED HOSTS")
        lines.append("-" * 40)
        for host in changes["changed_hosts"]:
            ip = host["ip"]
            hostname = host.get("hostname", "")
            lines.append(f"  {ip}" + (f" ({hostname})" if hostname else ""))

            for port_info in host["new_ports"]:
                lines.append(f"    [+] Port {port_info['port']}/{port_info['service']}")

            for port_info in host["closed_ports"]:
                lines.append(f"    [-] Port {port_info['port']}/{port_info['service']}")

            for vuln in host["new_vulnerabilities"]:
                lines.append(f"    [!] New vuln: {vuln[:60]}...")

            lines.append("")

    # v3.0.1: Web vulnerability changes
    web_changes = changes.get("web_vuln_changes", [])
    if web_changes:
        lines.append("WEB VULNERABILITY CHANGES")
        lines.append("-" * 40)
        for wc in web_changes:
            delta_str = f"+{wc['delta']}" if wc["delta"] > 0 else str(wc["delta"])
            lines.append(
                f"  {wc['host']}: {delta_str} findings ({wc['old_count']} → {wc['new_count']})"
            )
            if wc["nikto_delta"] != 0:
                nd = f"+{wc['nikto_delta']}" if wc["nikto_delta"] > 0 else str(wc["nikto_delta"])
                lines.append(f"    Nikto: {nd}")
            if wc["testssl_delta"] != 0:
                td = (
                    f"+{wc['testssl_delta']}"
                    if wc["testssl_delta"] > 0
                    else str(wc["testssl_delta"])
                )
                lines.append(f"    TestSSL: {td}")
        lines.append("")

    if not summary["has_changes"]:
        lines.append("No changes detected between reports.")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_diff_markdown(diff: Dict) -> str:
    """
    Format diff report as Markdown.

    Args:
        diff: Diff report dict

    Returns:
        Markdown formatted string
    """
    lines = []
    lines.append("# RedAudit Differential Analysis Report")
    lines.append("")
    lines.append(f"**Generated**: {diff['generated_at']}")
    lines.append("")
    lines.append("## Reports Compared")
    lines.append("")
    lines.append("| Report | File | Timestamp | Hosts |")
    lines.append("|:---|:---|:---|:---:|")
    lines.append(
        f"| Old | {diff['old_report']['path']} | {diff['old_report']['timestamp']} | {diff['old_report']['total_hosts']} |"
    )
    lines.append(
        f"| New | {diff['new_report']['path']} | {diff['new_report']['timestamp']} | {diff['new_report']['total_hosts']} |"
    )
    lines.append("")

    summary = diff["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|:---|:---:|")
    lines.append(f"| New hosts | {summary['new_hosts_count']} |")
    lines.append(f"| Removed hosts | {summary['removed_hosts_count']} |")
    lines.append(f"| Changed hosts | {summary['changed_hosts_count']} |")
    lines.append(f"| New ports | {summary['total_new_ports']} |")
    lines.append(f"| Closed ports | {summary['total_closed_ports']} |")
    lines.append(f"| New vulnerabilities | {summary['total_new_vulnerabilities']} |")
    web_delta = summary.get("web_vuln_delta", 0)
    if web_delta != 0:
        delta_str = f"+{web_delta}" if web_delta > 0 else str(web_delta)
        lines.append(f"| Web findings delta | {delta_str} |")
    lines.append("")

    changes = diff["changes"]

    if changes["new_hosts"]:
        lines.append("## New Hosts")
        lines.append("")
        for ip in changes["new_hosts"]:
            lines.append(f"- `{ip}`")
        lines.append("")

    if changes["removed_hosts"]:
        lines.append("## Removed Hosts")
        lines.append("")
        for ip in changes["removed_hosts"]:
            lines.append(f"- `{ip}`")
        lines.append("")

    if changes["changed_hosts"]:
        lines.append("## Changed Hosts")
        lines.append("")
        for host in changes["changed_hosts"]:
            ip = host["ip"]
            hostname = host.get("hostname", "")
            lines.append(f"### {ip}" + (f" ({hostname})" if hostname else ""))
            lines.append("")

            if host["new_ports"]:
                lines.append("**New Ports:**")
                for port_info in host["new_ports"]:
                    lines.append(f"- Port {port_info['port']}/{port_info['service']}")
                lines.append("")

            if host["closed_ports"]:
                lines.append("**Closed Ports:**")
                for port_info in host["closed_ports"]:
                    lines.append(f"- Port {port_info['port']}/{port_info['service']}")
                lines.append("")

            if host["new_vulnerabilities"]:
                lines.append("**New Vulnerabilities:**")
                for vuln in host["new_vulnerabilities"]:
                    lines.append(f"- {vuln}")
                lines.append("")

    # v3.0.1: Web vulnerability changes section
    web_changes = changes.get("web_vuln_changes", [])
    if web_changes:
        lines.append("## Web Vulnerability Changes")
        lines.append("")
        lines.append("| Host | Delta | Old | New | Details |")
        lines.append("|:---|:---:|:---:|:---:|:---|")
        for wc in web_changes:
            delta_str = f"+{wc['delta']}" if wc["delta"] > 0 else str(wc["delta"])
            details = []
            if wc["nikto_delta"] != 0:
                nd = f"+{wc['nikto_delta']}" if wc["nikto_delta"] > 0 else str(wc["nikto_delta"])
                details.append(f"Nikto {nd}")
            if wc["testssl_delta"] != 0:
                td = (
                    f"+{wc['testssl_delta']}"
                    if wc["testssl_delta"] > 0
                    else str(wc["testssl_delta"])
                )
                details.append(f"TestSSL {td}")
            details_str = ", ".join(details) if details else "-"
            lines.append(
                f"| `{wc['host']}` | {delta_str} | {wc['old_count']} | {wc['new_count']} | {details_str} |"
            )
        lines.append("")

    if not summary["has_changes"]:
        lines.append("> No changes detected between the two reports.")
        lines.append("")

    return "\n".join(lines)


def format_diff_html(diff: Dict) -> str:
    """
    Format diff report as interactive HTML.

    v3.3: Uses Jinja2 template for visual diff with highlights.

    Args:
        diff: Diff report dict from generate_diff_report()

    Returns:
        HTML formatted string
    """
    try:
        from jinja2 import Environment, PackageLoader, select_autoescape

        env = Environment(
            loader=PackageLoader("redaudit", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("diff.html.j2")
        return template.render(**diff)
    except ImportError:
        # Fallback if Jinja2 not available
        return f"<html><body><pre>{format_diff_text(diff)}</pre></body></html>"
    except Exception as e:
        # Template error fallback
        return f"<html><body><h1>Error generating HTML diff</h1><pre>{e}</pre></body></html>"
