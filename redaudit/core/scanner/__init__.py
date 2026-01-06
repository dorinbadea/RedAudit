#!/usr/bin/env python3
"""
Scanner Module - RedAudit
Refactored into a package to improve maintainability.
"""

from redaudit.utils.constants import STATUS_UP

# Re-export all public symbols for backward compatibility
from redaudit.core.scanner.utils import (
    sanitize_ip,
    sanitize_hostname,
    is_ipv6,
    is_ipv6_network,
    is_web_service,
    is_suspicious_service,
    is_port_anomaly,
)

from redaudit.core.scanner.nmap import (
    get_nmap_arguments,
    get_nmap_arguments_for_target,
    run_nmap_command,
    _make_runner,
    _is_dry_run,  # Kept internal but exported if tested
)

from redaudit.core.scanner.traffic import (
    capture_traffic_snippet,
    start_background_capture,
    stop_background_capture,
    merge_pcap_files,
    organize_pcap_files,
    finalize_pcap_artifacts,
)

from redaudit.core.scanner.status import (
    finalize_host_status,
    output_has_identity,
    extract_vendor_mac,
    extract_os_detection,
)

from redaudit.core.scanner.enrichment import (
    enrich_host_with_dns,
    enrich_host_with_whois,
    http_enrichment,
    http_identity_probe,
    tls_enrichment,
    exploit_lookup,
    ssl_deep_analysis,
    banner_grab_fallback,
    _fetch_http_headers,  # Internal but may be used by tests
    _fetch_http_body,  # Internal but may be used by tests
    _extract_http_title,  # Internal but may be used by tests
    _extract_http_server,  # Internal but may be used by tests
    _clean_http_identity_text,  # Internal but may be used by tests
    _format_http_host,  # Internal but may be used by tests
)

__all__ = [
    "sanitize_ip",
    "sanitize_hostname",
    "is_ipv6",
    "is_ipv6_network",
    "is_web_service",
    "is_suspicious_service",
    "is_port_anomaly",
    "get_nmap_arguments",
    "get_nmap_arguments_for_target",
    "run_nmap_command",
    "_make_runner",
    "_is_dry_run",
    "capture_traffic_snippet",
    "start_background_capture",
    "stop_background_capture",
    "merge_pcap_files",
    "organize_pcap_files",
    "finalize_pcap_artifacts",
    "finalize_host_status",
    "output_has_identity",
    "extract_vendor_mac",
    "extract_os_detection",
    "enrich_host_with_dns",
    "enrich_host_with_whois",
    "http_enrichment",
    "http_identity_probe",
    "tls_enrichment",
    "exploit_lookup",
    "ssl_deep_analysis",
    "banner_grab_fallback",
    "_fetch_http_headers",
    "_fetch_http_body",
    "_extract_http_title",
    "_extract_http_server",
    "_clean_http_identity_text",
    "_format_http_host",
    "STATUS_UP",
]
