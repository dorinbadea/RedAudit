#!/usr/bin/env python3
"""
RedAudit - Reporter Module
Copyright (C) 2025  Dorin Badea
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
from redaudit.core.entity_resolver import reconcile_assets
from redaudit.core.siem import enrich_report_for_siem
from redaudit.core.scanner_versions import get_scanner_versions



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

    # v3.1: Updated SIEM-compatible fields
    results["schema_version"] = "3.1"
    results["generated_at"] = datetime.now().isoformat()
    results["event_type"] = "redaudit.scan.complete"
    results["session_id"] = str(uuid.uuid4())
    results["timestamp_end"] = datetime.now().isoformat()
    
    # v3.1: Scanner versions for provenance tracking
    results["scanner_versions"] = get_scanner_versions()
    
    results["scanner"] = {
        "name": "RedAudit",
        "version": VERSION,
        "mode": config.get("scan_mode", "normal"),
        "mode_cli": config.get("scan_mode_cli", config.get("scan_mode", "normal")),
    }
    results["targets"] = config.get("target_networks", [])


    # v2.9: Entity Resolution - consolidate multi-interface hosts
    hosts = results.get("hosts", [])
    if hosts:
        unified = reconcile_assets(hosts)
        if unified:
            results["unified_assets"] = unified
            # Update summary with unified count
            multi_interface = sum(1 for a in unified if a.get("interface_count", 1) > 1)
            summary["unified_asset_count"] = len(unified)
            summary["multi_interface_devices"] = multi_interface

    # v2.9: SIEM Enhancement - ECS compliance, severity scoring, tags, risk scores
    enriched = enrich_report_for_siem(results, config)
    results.update(enriched)

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
        hostname = h.get("hostname") or "-"
        status = h.get("status") or "unknown"
        total_ports = h.get("total_ports_found") or 0
        risk_score = h.get("risk_score")

        lines.append(f"Host: {h.get('ip')} ({hostname})\n")
        lines.append(f"  Status: {status}\n")
        lines.append(f"  Total Ports: {total_ports}\n")
        if risk_score is not None:
            lines.append(f"  Risk Score: {risk_score}/100\n")

        for p in h.get("ports", []):
            service = p.get("service", "")
            version = p.get("version", "") or ""
            lines.append(
                f"    - {p['port']}/{p['protocol']}  {service}  {version}\n"
            )
            if p.get("cve_count"):
                max_sev = p.get("cve_max_severity") or "UNKNOWN"
                lines.append(f"      CVEs: {p['cve_count']} (max severity: {max_sev})\n")
            # Show known exploits if found
            if p.get("known_exploits"):
                lines.append(f"      ⚠️  Known Exploits ({len(p['known_exploits'])}):\n")
                for exploit in p["known_exploits"][:3]:  # Max 3 for readability
                    lines.append(f"         - {exploit}\n")

        if h.get("cve_summary"):
            cve_sum = h["cve_summary"]
            lines.append(
                "  CVE Summary: total {total} (critical {critical}, high {high})\n".format(
                    total=cve_sum.get("total", 0),
                    critical=cve_sum.get("critical", 0),
                    high=cve_sum.get("high", 0),
                )
            )

        if h.get("dns", {}).get("reverse"):
            lines.append("  Reverse DNS:\n")
            for r in h["dns"]["reverse"]:
                lines.append(f"    {r}\n")

        if h.get("dns", {}).get("whois_summary"):
            lines.append("  Whois summary:\n")
            lines.append("    " + h["dns"]["whois_summary"].replace("\n", "\n    ") + "\n")

        if h.get("deep_scan"):
            deep = h["deep_scan"] or {}
            lines.append("  Deep scan data present.\n")
            if deep.get("mac_address"):
                lines.append(f"    MAC: {deep['mac_address']}\n")
            if deep.get("vendor"):
                lines.append(f"    Vendor: {deep['vendor']}\n")
            commands = deep.get("commands") or []
            if commands:
                lines.append(f"    Commands: {len(commands)}\n")
            else:
                lines.append("    Commands: 0 (identity-only)\n")
            pcap = deep.get("pcap_capture") or {}
            pcap_file = pcap.get("pcap_file")
            if pcap_file:
                lines.append(f"    PCAP: {pcap_file}\n")

        lines.append("\n")

    if results.get("vulnerabilities"):
        lines.append("WEB VULNERABILITIES SUMMARY:\n")
        for v in results["vulnerabilities"]:
            lines.append(f"\nHost: {v['host']}\n")
            for item in v.get("vulnerabilities", []):
                lines.append(f"  URL: {item.get('url', '')}\n")
                if item.get("severity"):
                    score = item.get("severity_score")
                    if score is None:
                        lines.append(f"    Severity: {item['severity']}\n")
                    else:
                        lines.append(f"    Severity: {item['severity']} ({score})\n")
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

    v2.8.0: Reports are now saved in timestamped subfolders:
            RedAudit_YYYY-MM-DD_HH-MM-SS/

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
    
    # v2.8.1: Use pre-created folder if available (ensures PCAP files and reports are together)
    output_dir = config.get("_actual_output_dir")
    if not output_dir:
        # Fallback: create new timestamped folder
        ts_folder = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_base = config.get("output_dir", os.path.expanduser("~/Documents/RedAuditReports"))
        output_dir = os.path.join(output_base, f"RedAudit_{ts_folder}")
    
    base = os.path.join(output_dir, f"{prefix}redaudit_{ts}")

    try:
        os.makedirs(output_dir, exist_ok=True)

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
        # NOTE: The salt is NOT sensitive data - it is a public cryptographic parameter
        # that MUST be stored alongside encrypted data to allow decryption.
        # The password is derived using PBKDF2 with this salt, and storing the salt
        # is standard practice (see NIST SP 800-132). CodeQL flags this incorrectly.
        if encryption_enabled and config.get("encryption_salt"):
            salt_bytes = base64.b64decode(config["encryption_salt"])  # lgtm[py/clear-text-storage-sensitive-data]
            salt_path = f"{base}.salt"
            with open(salt_path, "wb") as f:
                f.write(salt_bytes)  # nosec B105 - salt is not sensitive, required for key derivation
            os.chmod(salt_path, SECURE_FILE_MODE)

        # Update config with actual output directory for display
        config["_actual_output_dir"] = output_dir

        # v3.3: Generate JSONL exports for SIEM/AI pipelines
        try:
            from redaudit.core.jsonl_exporter import export_all
            export_stats = export_all(results, output_dir)
            if print_fn and t_fn:
                print_fn(f"📊 JSONL exports: {export_stats['findings']} findings, {export_stats['assets']} assets", "OKGREEN")
        except Exception as jsonl_err:
            if logger:
                logger.warning("JSONL export failed: %s", jsonl_err)


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
        t_fn("web_vulns"): config.get("scan_vulnerabilities"),
        t_fn("cve_lookup"): config.get("cve_lookup_enabled"),
        t_fn("output"): config["output_dir"],
    }
    for k, v in conf.items():
        label = str(k).rstrip(":")
        print(f"  {label}: {v}")


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
    pcap_count = 0
    for h in results.get("hosts", []) or []:
        deep = h.get("deep_scan") or {}
        pcap = deep.get("pcap_capture") or {}
        if isinstance(pcap, dict) and pcap.get("pcap_file"):
            pcap_count += 1
    print(t_fn("pcaps", pcap_count))
    print(f"{colors['OKGREEN']}{t_fn('reports_gen', output_dir)}{colors['ENDC']}")
