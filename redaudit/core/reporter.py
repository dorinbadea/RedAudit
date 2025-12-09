#!/usr/bin/env python3
"""
RedAudit - Reporter Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Report generation and saving functionality.
"""

import os
import json
import base64
import uuid
from datetime import datetime
from typing import Dict, Optional

from redaudit.utils.constants import VERSION, SECURE_FILE_MODE
from redaudit.core.crypto import encrypt_data


def generate_summary(
    results: Dict,
    config: Dict,
    all_hosts: list,
    scanned_results: list,
    scan_start_time: Optional[datetime]
) -> Dict:
    """
    Generate scan summary statistics.

    Args:
        results: Results dictionary
        config: Configuration dictionary
        all_hosts: All discovered hosts
        scanned_results: Scanned host results
        scan_start_time: Scan start timestamp

    Returns:
        Summary dictionary
    """
    duration = (
        datetime.now() - scan_start_time
        if scan_start_time is not None
        else None
    )
    total_vulns = sum(
        len(v.get("vulnerabilities", []))
        for v in results.get("vulnerabilities", [])
    )

    summary = {
        "networks": len(config.get("target_networks", [])),
        "hosts_found": len(all_hosts),
        "hosts_scanned": len(scanned_results),
        "vulns_found": total_vulns,
        "duration": str(duration).split(".")[0] if duration else None,
    }

    results["summary"] = summary

    # A5: SIEM-compatible fields (v2.7)
    results["schema_version"] = "2.0"
    results["event_type"] = "redaudit.scan.complete" if not duration else "redaudit.scan.complete"
    results["session_id"] = str(uuid.uuid4())
    results["timestamp_end"] = datetime.now().isoformat()
    results["scanner"] = {
        "name": "RedAudit",
        "version": VERSION,
        "mode": config.get("scan_mode", "normal")
    }
    results["targets"] = config.get("target_networks", [])

    return summary


def generate_text_report(results: Dict, partial: bool = False) -> str:
    """
    Generate human-readable text report.

    Args:
        results: Results dictionary
        partial: Whether this is a partial/interrupted report

    Returns:
        Text report string
    """
    lines = []
    status_txt = "PARTIAL/INTERRUPTED" if partial else "COMPLETED"

    lines.append(f"NETWORK AUDIT REPORT v{VERSION}\n")
    lines.append(f"Date: {datetime.now()}\n")
    lines.append(f"Status: {status_txt}\n\n")

    summ = results.get("summary", {})
    lines.append(f"Networks:      {summ.get('networks', 0)}\n")
    lines.append(f"Hosts Found:   {summ.get('hosts_found', 0)}\n")
    lines.append(f"Hosts Scanned: {summ.get('hosts_scanned', 0)}\n")
    lines.append(f"Web Vulns:     {summ.get('vulns_found', 0)}\n\n")

    for h in results.get("hosts", []):
        lines.append(f"Host: {h.get('ip')} ({h.get('hostname')})\n")
        lines.append(f"  Status: {h.get('status')}\n")
        lines.append(f"  Total Ports: {h.get('total_ports_found')}\n")

        for p in h.get("ports", []):
            lines.append(
                f"    - {p['port']}/{p['protocol']}  {p['service']}  {p['version']}\n"
            )
            # Show known exploits if found
            if p.get("known_exploits"):
                lines.append(f"      ⚠️  Known Exploits ({len(p['known_exploits'])}):\n")
                for exploit in p["known_exploits"][:3]:  # Max 3 for readability
                    lines.append(f"         - {exploit}\n")

        if h.get("dns", {}).get("reverse"):
            lines.append("  Reverse DNS:\n")
            for r in h["dns"]["reverse"]:
                lines.append(f"    {r}\n")

        if h.get("dns", {}).get("whois_summary"):
            lines.append("  Whois summary:\n")
            lines.append("    " + h["dns"]["whois_summary"].replace("\n", "\n    ") + "\n")

        if h.get("deep_scan"):
            lines.append("  Deep scan data present.\n")
            if h["deep_scan"].get("mac_address"):
                lines.append(f"    MAC: {h['deep_scan']['mac_address']}\n")
            if h["deep_scan"].get("vendor"):
                lines.append(f"    Vendor: {h['deep_scan']['vendor']}\n")

        lines.append("\n")

    if results.get("vulnerabilities"):
        lines.append("WEB VULNERABILITIES SUMMARY:\n")
        for v in results["vulnerabilities"]:
            lines.append(f"\nHost: {v['host']}\n")
            for item in v.get("vulnerabilities", []):
                lines.append(f"  URL: {item.get('url', '')}\n")
                if item.get("whatweb"):
                    lines.append(f"    WhatWeb: {item['whatweb'][:80]}...\n")
                if item.get("nikto_findings"):
                    lines.append(f"    Nikto: {len(item['nikto_findings'])} findings.\n")
                # TestSSL analysis results
                if item.get("testssl_analysis"):
                    tssl = item["testssl_analysis"]
                    lines.append(f"    TestSSL: {tssl.get('summary', 'analyzed')}\n")
                    if tssl.get("vulnerabilities"):
                        lines.append(f"      Vulnerabilities ({len(tssl['vulnerabilities'])}):\n")
                        for vuln in tssl["vulnerabilities"][:3]:
                            lines.append(f"        - {vuln}\n")

    return "".join(lines)


def save_results(
    results: Dict,
    config: Dict,
    encryption_enabled: bool = False,
    encryption_key: bytes = None,
    partial: bool = False,
    print_fn=None,
    t_fn=None,
    logger=None
) -> bool:
    """
    Save results to JSON and optionally TXT files.

    Args:
        results: Results dictionary
        config: Configuration dictionary
        encryption_enabled: Whether to encrypt reports
        encryption_key: Encryption key if enabled
        partial: Whether this is a partial save
        print_fn: Optional print function
        t_fn: Optional translation function
        logger: Optional logger

    Returns:
        True if save succeeded
    """
    prefix = "PARTIAL_" if partial else ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = config.get("output_dir", os.path.expanduser("~/RedAuditReports"))
    base = os.path.join(output_dir, f"{prefix}redaudit_{ts}")

    try:
        os.makedirs(os.path.dirname(base), exist_ok=True)

        # Save JSON report
        json_data = json.dumps(results, indent=2, default=str)
        if encryption_enabled and encryption_key:
            json_enc = encrypt_data(json_data, encryption_key)
            json_path = f"{base}.json.enc"
            with open(json_path, "wb") as f:
                f.write(json_enc)
        else:
            json_path = f"{base}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_data)

        os.chmod(json_path, SECURE_FILE_MODE)

        if print_fn and t_fn:
            print_fn(t_fn("json_report", json_path), "OKGREEN")

        # Save TXT report if enabled
        if config.get("save_txt_report"):
            txt_data = generate_text_report(results, partial=partial)
            if encryption_enabled and encryption_key:
                txt_enc = encrypt_data(txt_data, encryption_key)
                txt_path = f"{base}.txt.enc"
                with open(txt_path, "wb") as f:
                    f.write(txt_enc)
            else:
                txt_path = f"{base}.txt"
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(txt_data)

            os.chmod(txt_path, SECURE_FILE_MODE)

            if print_fn and t_fn:
                print_fn(t_fn("txt_report", txt_path), "OKGREEN")

        # Save salt file for encrypted reports
        if encryption_enabled and config.get("encryption_salt"):
            salt_bytes = base64.b64decode(config["encryption_salt"])
            salt_path = f"{base}.salt"
            with open(salt_path, "wb") as f:
                f.write(salt_bytes)
            os.chmod(salt_path, SECURE_FILE_MODE)

        return True

    except Exception as exc:
        if logger:
            logger.error("Save error: %s", exc, exc_info=True)
        if print_fn and t_fn:
            print_fn(t_fn("save_err", exc), "FAIL")
        return False


def show_config_summary(config: Dict, t_fn, colors: Dict) -> None:
    """
    Print configuration summary to console.

    Args:
        config: Configuration dictionary
        t_fn: Translation function
        colors: Color codes dictionary
    """
    print(f"\n{colors['HEADER']}{t_fn('exec_params')}{colors['ENDC']}")
    conf = {
        t_fn("targets"): config["target_networks"],
        t_fn("mode"): config["scan_mode"],
        t_fn("threads"): config["threads"],
        "Vulns": config.get("scan_vulnerabilities"),
        t_fn("output"): config["output_dir"],
    }
    for k, v in conf.items():
        print(f"  {k}: {v}")


def show_results_summary(results: Dict, t_fn, colors: Dict, output_dir: str) -> None:
    """
    Print final results summary to console.

    Args:
        results: Results dictionary
        t_fn: Translation function
        colors: Color codes dictionary
        output_dir: Output directory path
    """
    s = results.get("summary", {})
    print(f"\n{colors['HEADER']}{t_fn('final_summary')}{colors['ENDC']}")
    print(t_fn("nets", s.get("networks")))
    print(t_fn("hosts_up", s.get("hosts_found")))
    print(t_fn("hosts_full", s.get("hosts_scanned")))
    print(t_fn("vulns_web", s.get("vulns_found")))
    print(t_fn("duration", s.get("duration")))
    print(f"{colors['OKGREEN']}{t_fn('reports_gen', output_dir)}{colors['ENDC']}")
