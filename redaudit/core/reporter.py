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
import re
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional

from redaudit.utils.constants import (
    DEFAULT_IDENTITY_THRESHOLD,
    SCHEMA_VERSION,
    SECURE_FILE_MODE,
    VERSION,
)
from redaudit.utils.paths import get_default_reports_base_dir, maybe_chown_tree_to_invoking_user
from redaudit.core.crypto import encrypt_data
from redaudit.core.entity_resolver import reconcile_assets
from redaudit.core.siem import enrich_report_for_siem
from redaudit.core.scanner_versions import get_scanner_versions


def _build_config_snapshot(config: Dict) -> Dict[str, Any]:
    """Create a safe, minimal snapshot of the run configuration."""
    scan_mode = config.get("scan_mode")
    identity_threshold = config.get("identity_threshold")
    if not isinstance(identity_threshold, int) or identity_threshold < 0:
        identity_threshold = DEFAULT_IDENTITY_THRESHOLD
    if scan_mode in ("completo", "full") and identity_threshold < 4:
        identity_threshold = 4
    return {
        "targets": config.get("target_networks", []),
        "scan_mode": scan_mode,
        "scan_mode_cli": config.get("scan_mode_cli", scan_mode),
        "threads": config.get("threads"),
        "rate_limit_delay": config.get("rate_limit_delay", config.get("rate_limit")),
        "low_impact_enrichment": config.get("low_impact_enrichment"),
        "deep_scan_budget": config.get("deep_scan_budget"),
        "identity_threshold": identity_threshold,
        "udp_mode": config.get("udp_mode"),
        "udp_top_ports": config.get("udp_top_ports"),
        "topology_enabled": config.get("topology_enabled"),
        "topology_only": config.get("topology_only"),
        "net_discovery_enabled": config.get("net_discovery_enabled"),
        "net_discovery_redteam": config.get("net_discovery_redteam"),
        "net_discovery_active_l2": config.get("net_discovery_active_l2"),
        "net_discovery_kerberos_userenum": config.get("net_discovery_kerberos_userenum"),
        "windows_verify_enabled": config.get("windows_verify_enabled"),
        "windows_verify_max_targets": config.get("windows_verify_max_targets"),
        "scan_vulnerabilities": config.get("scan_vulnerabilities"),
        "nuclei_enabled": config.get("nuclei_enabled"),
        "cve_lookup_enabled": config.get("cve_lookup_enabled"),
        "dry_run": config.get("dry_run"),
        "prevent_sleep": config.get("prevent_sleep"),
        "auditor_name": config.get("auditor_name"),
    }


def _summarize_net_discovery(net_discovery: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(net_discovery, dict) or not net_discovery:
        return {"enabled": False}
    summary: Dict[str, Any] = {
        "enabled": bool(net_discovery.get("enabled", True)),
        "protocols_used": net_discovery.get("protocols_used", []),
        "redteam_enabled": bool(net_discovery.get("redteam_enabled", False)),
        "hyperscan_duration": net_discovery.get("hyperscan_duration", 0),
        "errors": (net_discovery.get("errors") or [])[:5],
    }
    summary["counts"] = {
        "dhcp_servers": len(net_discovery.get("dhcp_servers", []) or []),
        "alive_hosts": len(net_discovery.get("alive_hosts", []) or []),
        "netbios_hosts": len(net_discovery.get("netbios_hosts", []) or []),
        "arp_hosts": len(net_discovery.get("arp_hosts", []) or []),
        "mdns_services": len(net_discovery.get("mdns_services", []) or []),
        "upnp_devices": len(net_discovery.get("upnp_devices", []) or []),
        "candidate_vlans": len(net_discovery.get("candidate_vlans", []) or []),
        "hyperscan_tcp_hosts": len(net_discovery.get("hyperscan_tcp_hosts", {}) or {}),
        "potential_backdoors": len(net_discovery.get("potential_backdoors", []) or []),
    }

    redteam = net_discovery.get("redteam") or {}
    if isinstance(redteam, dict) and redteam:
        summary["redteam"] = {
            "targets_considered": redteam.get("targets_considered", 0),
            "masscan_open_ports": len((redteam.get("masscan") or {}).get("open_ports", []) or []),
            "snmp_hosts": len((redteam.get("snmp") or {}).get("hosts", []) or []),
            "smb_hosts": len((redteam.get("smb") or {}).get("hosts", []) or []),
            "rpc_hosts": len((redteam.get("rpc") or {}).get("hosts", []) or []),
            "ldap_hosts": len((redteam.get("ldap") or {}).get("hosts", []) or []),
            "kerberos_hosts": len((redteam.get("kerberos") or {}).get("hosts", []) or []),
            "vlan_ids": len((redteam.get("vlan_enum") or {}).get("vlan_ids", []) or []),
            "router_candidates": len(
                (redteam.get("router_discovery") or {}).get("router_candidates", []) or []
            ),
            "ipv6_neighbors": len((redteam.get("ipv6_discovery") or {}).get("neighbors", []) or []),
        }
    return summary


def _summarize_agentless(
    hosts: list, agentless_verify: Dict[str, Any], config: Dict[str, Any]
) -> Dict[str, Any]:
    # v3.8.5: Use config to determine if user enabled the feature,
    # not just whether results exist (fixes false "enabled: false" when no targets found)
    user_enabled = config.get("windows_verify_enabled", False)
    summary = {
        "enabled": bool(user_enabled),
        "targets": agentless_verify.get("targets", 0) if isinstance(agentless_verify, dict) else 0,
        "completed": (
            agentless_verify.get("completed", 0) if isinstance(agentless_verify, dict) else 0
        ),
        "signals": {},
        "domains": [],
    }
    if not hosts:
        return summary

    counts = {"smb": 0, "rdp": 0, "ldap": 0, "ssh": 0, "http": 0}
    domains = set()
    for host in hosts:
        probe = host.get("agentless_probe") or {}
        if probe.get("smb"):
            counts["smb"] += 1
        if probe.get("rdp"):
            counts["rdp"] += 1
        if probe.get("ldap"):
            counts["ldap"] += 1
        if probe.get("ssh"):
            counts["ssh"] += 1
        if probe.get("http"):
            counts["http"] += 1

        fp = host.get("agentless_fingerprint") or {}
        for key in ("domain", "dns_domain_name", "dns_domain"):
            val = fp.get(key)
            if isinstance(val, str) and val.strip():
                domains.add(val.strip())

    summary["signals"] = counts
    summary["domains"] = sorted(domains)[:10]
    return summary


def _summarize_smart_scan(hosts: list, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    hosts_count = 0
    deep_triggered = 0
    deep_executed = 0
    scores: List[int] = []
    signals: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    phase0_signals_collected = 0
    phase0_enabled = (
        bool(config.get("low_impact_enrichment", False)) if isinstance(config, dict) else False
    )

    for host in hosts or []:
        smart = host.get("smart_scan")
        if not isinstance(smart, dict):
            continue
        hosts_count += 1
        try:
            scores.append(int(smart.get("identity_score", 0)))
        except Exception:
            scores.append(0)
        if smart.get("trigger_deep"):
            deep_triggered += 1
        if smart.get("deep_scan_executed"):
            deep_executed += 1
        for sig in smart.get("signals", []) or []:
            signals[sig] = signals.get(sig, 0) + 1
        for reason in smart.get("reasons", []) or []:
            reasons[reason] = reasons.get(reason, 0) + 1
        if phase0_enabled:
            phase0 = host.get("phase0_enrichment") or {}
            if any(
                phase0.get(key)
                for key in (
                    "dns_reverse",
                    "mdns_name",
                    "snmp_sysDescr",
                )
            ):
                phase0_signals_collected += 1

    budget = 0
    if isinstance(config, dict):
        try:
            budget = int(config.get("deep_scan_budget", 0))
            if budget < 0:
                budget = 0
        except Exception:
            budget = 0
    skipped_by_budget = reasons.get("budget_exhausted", 0)

    return {
        "hosts": hosts_count,
        "identity_score_avg": round(sum(scores) / len(scores), 2) if scores else 0,
        "deep_scan_triggered": deep_triggered,
        "deep_scan_executed": deep_executed,
        "signals": signals,
        "reasons": reasons,
        "deep_scan_budget": budget,
        "deep_scan_budget_exhausted": bool(budget > 0 and skipped_by_budget > 0),
        "hosts_skipped_by_budget": skipped_by_budget,
        "phase0_enrichment_enabled": phase0_enabled,
        "phase0_signals_collected": phase0_signals_collected,
    }


def _infer_vuln_source(vuln: Dict[str, Any]) -> str:
    source = vuln.get("source") or (vuln.get("original_severity") or {}).get("tool") or ""
    if source:
        return source
    if vuln.get("template_id") or vuln.get("matched_at"):
        return "nuclei"
    if vuln.get("nikto_findings"):
        return "nikto"
    if vuln.get("testssl_analysis"):
        return "testssl"
    if vuln.get("whatweb"):
        return "whatweb"
    return "unknown"


def _summarize_vulnerabilities(vuln_entries: list) -> Dict[str, Any]:
    total = 0
    sources: Dict[str, int] = {}
    for entry in vuln_entries or []:
        if not entry:
            continue
        for vuln in entry.get("vulnerabilities", []) or []:
            total += 1
            source = _infer_vuln_source(vuln)
            sources[source] = sources.get(source, 0) + 1
    return {"total": total, "sources": sources}


def generate_summary(
    results: Dict,
    config: Dict,
    all_hosts: list,
    scanned_results: list,
    scan_start_time: Optional[datetime],
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
    duration = datetime.now() - scan_start_time if scan_start_time is not None else None
    raw_vulns = sum(
        len(v.get("vulnerabilities", [])) for v in results.get("vulnerabilities", []) if v
    )

    unique_hosts = {h for h in (all_hosts or []) if isinstance(h, str) and h.strip()}
    summary = {
        "networks": len(config.get("target_networks", [])),
        "hosts_found": len(unique_hosts),
        "hosts_scanned": len(scanned_results),
        "vulns_found": raw_vulns,
        "vulns_found_raw": raw_vulns,
        "duration": str(duration).split(".")[0] if duration else None,
    }

    results["summary"] = summary

    # Attach sanitized config snapshot + pipeline + smart scan summary for reporting.
    results["config_snapshot"] = _build_config_snapshot(config)
    results["smart_scan_summary"] = _summarize_smart_scan(results.get("hosts", []), config)
    raw_vuln_summary = _summarize_vulnerabilities(results.get("vulnerabilities", []))
    results["pipeline"] = {
        "topology": results.get("topology") or {},
        "net_discovery": _summarize_net_discovery(results.get("net_discovery") or {}),
        "host_scan": {
            "targets": len(unique_hosts),
            "scanned": len(scanned_results),
            "threads": config.get("threads"),
        },
        "agentless_verify": _summarize_agentless(
            results.get("hosts", []), results.get("agentless_verify") or {}, config
        ),
        "nuclei": results.get("nuclei") or {},
        "vulnerability_scan": raw_vuln_summary,
    }

    # v3.1+: Updated SIEM-compatible fields
    results["schema_version"] = SCHEMA_VERSION
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
        # Generic improvement: tag the default gateway as a router when topology is enabled.
        gateway_ip = ((results.get("topology") or {}).get("default_gateway") or {}).get("ip")

        # v3.9.6: Find gateway MAC for VPN interface detection (same MAC = VPN virtual IP)
        gateway_mac = None
        if gateway_ip:
            for host in hosts:
                if host.get("ip") == gateway_ip:
                    gateway_mac = (host.get("deep_scan") or {}).get("mac_address")
                    break

        if gateway_ip:
            for host in hosts:
                # Inject gateway info for VPN detection heuristic (entity_resolver uses these)
                host["_gateway_ip"] = gateway_ip
                if gateway_mac:
                    host["_gateway_mac"] = gateway_mac

                if host.get("ip") != gateway_ip:
                    continue
                host["is_default_gateway"] = True
                hints = host.get("device_type_hints")
                if not isinstance(hints, list):
                    hints = []
                normalized = {str(h).lower() for h in hints if h}
                if "router" not in normalized:
                    hints.append("router")
                host["device_type_hints"] = hints

        unified = reconcile_assets(hosts)
        if unified:
            results["unified_assets"] = unified
            # Update summary with unified count
            multi_interface = sum(1 for a in unified if a.get("interface_count", 1) > 1)
            summary["unified_asset_count"] = len(unified)
            summary["multi_interface_devices"] = multi_interface

    # v3.2.2b: Populate hidden_networks for SIEM/AI pipelines
    # This detects IPs leaked in headers/redirects outside target networks
    hidden_network_leaks = _detect_network_leaks(results, config)
    if hidden_network_leaks:
        results["hidden_networks"] = hidden_network_leaks
        summary["leaked_networks_detected"] = len(hidden_network_leaks)

    # v3.2.2b: Also extract scannable CIDRs for auto-pivot
    leaked_cidrs = extract_leaked_networks(results, config)
    if leaked_cidrs:
        results["leaked_networks_cidr"] = leaked_cidrs
        summary["pivot_candidates"] = len(leaked_cidrs)

    # v2.9: SIEM Enhancement - ECS compliance, severity scoring, tags, risk scores
    enriched = enrich_report_for_siem(results, config)
    results.update(enriched)
    consolidated_vulns = 0
    try:
        consolidated_vulns = _summarize_vulnerabilities(results.get("vulnerabilities", [])).get(
            "total", 0
        )
    except Exception:
        consolidated_vulns = raw_vulns
    summary["vulns_found"] = consolidated_vulns
    summary["vulns_found_raw"] = raw_vulns
    if results.get("pipeline", {}).get("vulnerability_scan") is not None:
        results["pipeline"]["vulnerability_scan"]["total_raw"] = raw_vulns
        results["pipeline"]["vulnerability_scan"]["total"] = consolidated_vulns

    return summary


def _detect_network_leaks(results: Dict, config: Dict) -> list:
    """
    Detect potential hidden networks by analyzing finding leaks (redirects, headers).

    Args:
        results: Results dictionary containing vulnerabilities
        config: Configuration dictionary with target networks

    Returns:
        List of strings describing detected leaks
    """
    leaks = set()
    targets = []
    for t in config.get("target_networks", []):
        try:
            targets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            pass

    # Regex for private IPv4 (fixed for full octet matching)
    ip_regex = re.compile(
        r"\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))\b"
    )

    # helper to check if IP is interesting (private + not in targets)
    def is_cand(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private or ip.is_loopback:
                return False
            # Check if in any target network
            for net in targets:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    for host_vuln in results.get("vulnerabilities", []) or []:
        if not host_vuln:
            continue
        host_ip = host_vuln.get("host")
        for finding in host_vuln.get("vulnerabilities", []):
            content_to_check = []

            # Check headers
            if finding.get("curl_headers"):
                content_to_check.append(finding["curl_headers"])
            if finding.get("wget_headers"):
                content_to_check.append(finding["wget_headers"])

            # Check redirects
            if finding.get("redirect_url"):
                content_to_check.append(finding["redirect_url"])

            # Check tool output
            if finding.get("nikto_findings"):
                content_to_check.extend(finding["nikto_findings"])

            for text in content_to_check:
                if not isinstance(text, str):
                    continue
                matches = ip_regex.findall(text)
                for m in matches:
                    if m != host_ip and is_cand(m):
                        # Infer subnet
                        try:
                            # Guess /24 for reporting context
                            ipaddress.ip_address(m)
                            net = ipaddress.ip_network(f"{m}/24", strict=False)
                            leaks.add(
                                f"Host {host_ip} leaks internal IP {m} (Potential Network: {net})"
                            )
                        except ValueError:
                            leaks.add(f"Host {host_ip} leaks internal IP {m}")

    return sorted(list(leaks))


def extract_leaked_networks(results: Dict, config: Dict) -> list:
    """
    Extract potential hidden networks as scannable CIDR ranges.

    v3.2.2b: For automatic pivot - returns /24 networks discovered via leaks.

    Args:
        results: Results dictionary containing vulnerabilities
        config: Configuration dictionary with target networks

    Returns:
        List of unique network CIDRs (e.g., ["192.168.10.0/24", "10.0.1.0/24"])
    """
    networks = set()
    targets = []
    for t in config.get("target_networks", []):
        try:
            targets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            pass

    # Regex for private IPv4 (fixed for full octet matching)
    ip_regex = re.compile(
        r"\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))\b"
    )

    def is_new_network(ip_str):
        """Check if IP is in a network not already being scanned."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private or ip.is_loopback:
                return False
            for net in targets:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    # Search vulnerabilities for leaked IPs
    for host_vuln in results.get("vulnerabilities", []) or []:
        if not host_vuln:
            continue
        for finding in host_vuln.get("vulnerabilities", []):
            content_to_check = []
            if finding.get("curl_headers"):
                content_to_check.append(finding["curl_headers"])
            if finding.get("wget_headers"):
                content_to_check.append(finding["wget_headers"])
            if finding.get("redirect_url"):
                content_to_check.append(finding["redirect_url"])
            if finding.get("nikto_findings"):
                content_to_check.extend(finding["nikto_findings"])

            for text in content_to_check:
                if not isinstance(text, str):
                    continue
                matches = ip_regex.findall(text)
                for m in matches:
                    if is_new_network(m):
                        try:
                            net = ipaddress.ip_network(f"{m}/24", strict=False)
                            networks.add(str(net))
                        except ValueError:
                            pass

    # Also check hidden_networks if already populated
    for leak_str in results.get("hidden_networks", []):
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", leak_str)
        if match:
            networks.add(match.group(1))

    return sorted(list(networks))


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
    auditor_name = (results.get("config_snapshot") or {}).get("auditor_name")
    if auditor_name:
        lines.append(f"Auditor: {auditor_name}\n\n")

    summ = results.get("summary", {})
    lines.append(f"Networks:      {summ.get('networks', 0)}\n")
    lines.append(f"Hosts Found:   {summ.get('hosts_found', 0)}\n")
    lines.append(f"Hosts Scanned: {summ.get('hosts_scanned', 0)}\n")
    lines.append(f"Web Vulns:     {summ.get('vulns_found', 0)}\n\n")

    pipeline = results.get("pipeline", {})
    smart = results.get("smart_scan_summary", {})
    if pipeline:
        lines.append("PIPELINE SUMMARY:\n")
        net_summary = pipeline.get("net_discovery") or {}
        if net_summary:
            counts = net_summary.get("counts") or {}
            lines.append(
                "  Net Discovery: enabled={enabled} (ARP {arp}, NetBIOS {nb}, UPNP {upnp})\n".format(
                    enabled=bool(net_summary.get("enabled")),
                    arp=counts.get("arp_hosts", 0),
                    nb=counts.get("netbios_hosts", 0),
                    upnp=counts.get("upnp_devices", 0),
                )
            )
        agentless = pipeline.get("agentless_verify") or {}
        if agentless:
            lines.append(
                "  Agentless verify: {completed}/{targets}\n".format(
                    completed=agentless.get("completed", 0),
                    targets=agentless.get("targets", 0),
                )
            )
        nuclei = pipeline.get("nuclei") or {}
        if nuclei:
            lines.append(
                "  Nuclei: {findings} finding(s) on {targets} targets\n".format(
                    findings=nuclei.get("findings", 0),
                    targets=nuclei.get("targets", 0),
                )
            )
        if smart:
            lines.append(
                "  SmartScan: deep executed {executed}, avg identity {avg}\n".format(
                    executed=smart.get("deep_scan_executed", 0),
                    avg=smart.get("identity_score_avg", 0),
                )
            )
        lines.append("\n")

    # v3.2.1: Check for network leaks (Guest Networks / Pivoting opportunities)
    # The user specifically requested techniques to discover "all networks here"
    network_leaks = _detect_network_leaks(results, results.get("config", {}))
    if network_leaks:
        lines.append("⚠️  POTENTIAL HIDDEN NETWORKS (LEAKS DETECTED):\n")
        lines.append(
            "   (Professional Pivot / Discovery Tip: These networks are referenced in headers/redirects but were not scanned)\n"
        )
        for leak in network_leaks:
            lines.append(f"   - {leak}\n")
        lines.append("\n")

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
            lines.append(f"    - {p['port']}/{p['protocol']}  {service}  {version}\n")
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

        agentless_fp = h.get("agentless_fingerprint") or {}
        if isinstance(agentless_fp, dict) and agentless_fp:
            lines.append("  Agentless fingerprint:\n")
            for label, key in (
                ("Computer", "computer_name"),
                ("Domain", "domain"),
                ("OS", "os"),
                ("SMB signing", "smb_signing_required"),
                ("SMBv1", "smbv1_detected"),
                ("RDP Version", "product_version"),
                ("HTTP title", "http_title"),
                ("HTTP server", "http_server"),
            ):
                if key in agentless_fp and agentless_fp.get(key) not in (None, ""):
                    lines.append(f"    {label}: {agentless_fp.get(key)}\n")
            ssh_keys = agentless_fp.get("ssh_hostkeys")
            if isinstance(ssh_keys, list) and ssh_keys:
                lines.append("    SSH hostkeys:\n")
                for key in ssh_keys[:3]:
                    lines.append(f"      - {key}\n")

        lines.append("\n")

    if results.get("vulnerabilities"):
        lines.append("WEB VULNERABILITIES SUMMARY:\n")
        for v in results["vulnerabilities"]:
            lines.append(f"\nHost: {v['host']}\n")
            for item in v.get("vulnerabilities", []):
                source = item.get("source")
                if source:
                    lines.append(f"  Source: {source}\n")
                url = item.get("matched_at") or item.get("url", "")
                lines.append(f"  URL: {url}\n")
                if item.get("severity"):
                    score = item.get("severity_score")
                    if score is None:
                        lines.append(f"    Severity: {item['severity']}\n")
                    else:
                        lines.append(f"    Severity: {item['severity']} ({score})\n")
                if item.get("template_id"):
                    lines.append(f"    Template: {item['template_id']}\n")
                if item.get("cve_ids"):
                    try:
                        cves = ", ".join(item.get("cve_ids")[:3])
                    except Exception:
                        cves = ""
                    if cves:
                        lines.append(f"    CVEs: {cves}\n")
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
                # v3.2.1: Show potential false positives for transparency
                if item.get("potential_false_positives"):
                    fps = item["potential_false_positives"]
                    lines.append(f"    ⚠️  Possible False Positives ({len(fps)}):\n")
                    for fp in fps[:3]:
                        lines.append(f"      - {fp}\n")

    return "".join(lines)


def save_results(
    results: Dict,
    config: Dict,
    encryption_enabled: bool = False,
    encryption_key: bytes = None,
    partial: bool = False,
    print_fn=None,
    t_fn=None,
    logger=None,
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
        output_base = config.get("output_dir") or get_default_reports_base_dir()
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
            salt_bytes = base64.b64decode(
                config["encryption_salt"]
            )  # lgtm[py/clear-text-storage-sensitive-data]
            salt_path = f"{base}.salt"
            with open(salt_path, "wb") as f:
                f.write(
                    salt_bytes
                )  # nosec B105 - salt is not sensitive, required for key derivation
            os.chmod(salt_path, SECURE_FILE_MODE)

        # Update config with actual output directory for display
        config["_actual_output_dir"] = output_dir

        # v3.1: Generate JSONL exports for SIEM/AI pipelines (skip when encryption is enabled)
        if not encryption_enabled:
            try:
                from redaudit.core.jsonl_exporter import export_all

                export_stats = export_all(results, output_dir)
                if print_fn and t_fn:
                    print_fn(
                        t_fn("jsonl_exports", export_stats["findings"], export_stats["assets"]),
                        "OKGREEN",
                    )
            except Exception as jsonl_err:
                if logger:
                    logger.warning("JSONL export failed: %s", jsonl_err)
        elif logger:
            logger.info("JSONL exports skipped (report encryption enabled)")

        # v3.9.0: Generate remediation playbooks BEFORE HTML report
        # This ensures playbook data is available for the HTML report
        if not encryption_enabled:
            try:
                from redaudit.core.playbook_generator import save_playbooks

                playbook_count, playbook_data = save_playbooks(results, output_dir, logger=logger)
                # Add playbooks to results for HTML report
                results["playbooks"] = playbook_data
                if playbook_count > 0 and print_fn and t_fn:
                    print_fn(t_fn("playbooks_generated", playbook_count), "OKGREEN")
            except Exception as pb_err:
                if logger:
                    logger.debug("Playbook generation failed: %s", pb_err)
                results["playbooks"] = []

        # v3.3: Generate HTML report if enabled
        # v3.3.1: Check both CLI key (html_report) and wizard key (save_html_report)
        html_enabled = config.get("html_report") or config.get("save_html_report")
        if html_enabled and not encryption_enabled:
            try:
                from redaudit.core.html_reporter import save_html_report

                html_path = save_html_report(
                    results,
                    config,
                    output_dir,
                    filename="report.html",
                    lang="en",
                )
                if html_path and print_fn and t_fn:
                    print_fn(t_fn("html_report", html_path), "OKGREEN")
                elif not html_path and print_fn:
                    print_fn("HTML report generation failed (check log)", "WARNING")

                if (config.get("lang") or "").lower() == "es":
                    html_es_path = save_html_report(
                        results,
                        config,
                        output_dir,
                        filename="report_es.html",
                        lang="es",
                    )
                    if html_es_path and print_fn and t_fn:
                        print_fn(t_fn("html_report_es", html_es_path), "OKGREEN")
            except Exception as html_err:
                if logger:
                    logger.warning("HTML report generation failed: %s", html_err)
                if print_fn:
                    print_fn(f"HTML report error: {html_err}", "FAIL")
        elif html_enabled and encryption_enabled:
            if logger:
                logger.info("HTML report skipped (report encryption enabled)")

        # v3.3: Send webhook alerts for high-severity findings
        webhook_url = config.get("webhook_url")
        if webhook_url:
            try:
                from redaudit.utils.webhook import process_findings_for_alerts

                alerts_sent = process_findings_for_alerts(results, webhook_url, config)
                if alerts_sent > 0 and print_fn and t_fn:
                    print_fn(f"Webhook alerts sent: {alerts_sent}", "OKGREEN")
            except Exception as webhook_err:
                if logger:
                    logger.warning("Webhook alerting failed: %s", webhook_err)

        # vNext: Write a run manifest to make output folders self-describing.
        # Skip in encrypted mode to avoid plaintext artifacts.
        if not encryption_enabled:
            try:
                manifest_path = _write_output_manifest(
                    output_dir=output_dir,
                    results=results,
                    config=config,
                    encryption_enabled=encryption_enabled,
                    partial=partial,
                    logger=logger,
                )
                if manifest_path and logger:
                    logger.debug("Wrote run manifest: %s", manifest_path)
            except Exception as manifest_err:
                if logger:
                    logger.debug("Run manifest generation failed: %s", manifest_err, exc_info=True)

        maybe_chown_tree_to_invoking_user(output_dir)
        return True

    except Exception as exc:
        if logger:
            logger.error("Save error: %s", exc, exc_info=True)
        if print_fn and t_fn:
            print_fn(t_fn("save_err", exc), "FAIL")
        return False


def _write_output_manifest(
    *,
    output_dir: str,
    results: Dict,
    config: Dict,
    encryption_enabled: bool,
    partial: bool,
    logger=None,
) -> Optional[str]:
    if not output_dir or not isinstance(output_dir, str):
        return None

    total_findings = 0
    for entry in results.get("vulnerabilities", []) or []:
        if isinstance(entry, dict):
            total_findings += len(entry.get("vulnerabilities", []) or [])

    pcap_count = 0
    for host in results.get("hosts", []) or []:
        if not isinstance(host, dict):
            continue
        deep = host.get("deep_scan") or {}
        if not isinstance(deep, dict):
            continue
        pcap = deep.get("pcap_capture") or {}
        if isinstance(pcap, dict) and pcap.get("pcap_file"):
            pcap_count += 1

    scanner_versions = results.get("scanner_versions", {}) or {}
    redaudit_version = results.get("version") or scanner_versions.get("redaudit", "")

    raw_findings = (results.get("summary", {}) or {}).get("vulns_found_raw")
    manifest: Dict[str, Any] = {
        "schema_version": results.get("schema_version", ""),
        "generated_at": results.get("generated_at", datetime.now().isoformat()),
        "timestamp": results.get("timestamp", ""),
        "timestamp_end": results.get("timestamp_end", ""),
        "session_id": results.get("session_id", ""),
        "partial": bool(partial),
        "encryption_enabled": bool(encryption_enabled),
        "redaudit_version": redaudit_version,
        "scanner_versions": scanner_versions,
        "targets": results.get("targets", []),
        "counts": {
            "hosts": len(results.get("hosts", []) or []),
            "findings": total_findings,
            "pcaps": pcap_count,
        },
        "artifacts": [],
    }
    if raw_findings is not None:
        manifest["counts"]["findings_raw"] = raw_findings

    artifacts = []
    try:
        for root, _dirs, files in os.walk(output_dir):
            for name in files:
                abs_path = os.path.join(root, name)
                try:
                    rel_path = os.path.relpath(abs_path, output_dir)
                except Exception:
                    rel_path = name
                try:
                    size_bytes = os.path.getsize(abs_path)
                except Exception:
                    size_bytes = None
                artifacts.append(
                    {
                        "path": rel_path.replace("\\", "/"),
                        "size_bytes": size_bytes,
                    }
                )
    except Exception:
        if logger:
            logger.debug("Failed to walk output directory for manifest", exc_info=True)

    artifacts.sort(key=lambda item: str(item.get("path", "")))
    manifest["artifacts"] = artifacts

    out_path = os.path.join(output_dir, "run_manifest.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(out_path, SECURE_FILE_MODE)
    except Exception:
        pass
    return out_path


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
    if config.get("windows_verify_enabled"):
        max_targets = config.get("windows_verify_max_targets")
        conf[t_fn("windows_verify")] = f"enabled (max {max_targets})" if max_targets else "enabled"
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
    raw_vulns = s.get("vulns_found_raw")
    total_vulns = s.get("vulns_found")
    if raw_vulns is not None and raw_vulns != total_vulns:
        print(t_fn("vulns_web_detail", total_vulns, raw_vulns))
    else:
        print(t_fn("vulns_web", total_vulns))
    print(t_fn("duration", s.get("duration")))
    pcap_count = 0
    for h in results.get("hosts", []) or []:
        deep = h.get("deep_scan") or {}
        pcap = deep.get("pcap_capture") or {}
        if isinstance(pcap, dict) and pcap.get("pcap_file"):
            pcap_count += 1
    print(t_fn("pcaps", pcap_count))
    print(f"{colors['OKGREEN']}{t_fn('reports_gen', output_dir)}{colors['ENDC']}")
