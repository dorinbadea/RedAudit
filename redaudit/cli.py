#!/usr/bin/env python3
"""
RedAudit - CLI Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Command-line interface and argument parsing.
"""

import os
import sys
import argparse

from redaudit.utils.constants import (
    VERSION,
    MAX_THREADS,
    MIN_THREADS,
    MAX_CIDR_LENGTH,
    DEFAULT_UDP_MODE,
    UDP_TOP_PORTS,
    DEFAULT_DEAD_HOST_RETRIES,
    DEFAULT_DEEP_SCAN_BUDGET,
    DEFAULT_IDENTITY_THRESHOLD,
    suggest_threads,
)
from redaudit.utils.i18n import TRANSLATIONS, detect_preferred_language
from redaudit.utils.paths import expand_user_path, get_default_reports_base_dir
from redaudit.utils.targets import parse_target_tokens


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """

    def _resolve_help_lang(argv):
        for idx, arg in enumerate(argv):
            if arg == "--lang" and idx + 1 < len(argv):
                return "es" if argv[idx + 1].lower() == "es" else "en"
            if arg.startswith("--lang="):
                return "es" if arg.split("=", 1)[1].lower() == "es" else "en"
        return "en"

    help_lang = _resolve_help_lang(sys.argv[1:])
    if help_lang == "es":
        help_low_impact = (
            "Habilita enriquecimiento de bajo impacto (DNS/mDNS/SNMP) antes del escaneo TCP. "
            "Timeouts cortos, ruido mínimo."
        )
        help_deep_budget = (
            "Máximo hosts que pueden ejecutar Deep Scan agresivo por ejecución (0 = sin límite)."
        )
        help_identity_threshold = (
            "Umbral mínimo de identity_score para omitir Deep Scan (0-100, defecto: 3)."
        )
        help_dead_host_retries = "Abandonar host tras N timeouts consecutivos (0 = sin límite)."
    else:
        help_low_impact = (
            "Enable low-impact enrichment (DNS/mDNS/SNMP) before TCP scanning. "
            "Short timeouts, minimal noise."
        )
        help_deep_budget = "Max hosts that can run aggressive Deep Scan per run (0 = unlimited)."
        help_identity_threshold = "Minimum identity_score to skip Deep Scan (0-100, default: 3)."
        help_dead_host_retries = "Abandon host after N consecutive timeouts (0 = unlimited)."

    parser = argparse.ArgumentParser(
        description=f"RedAudit v{VERSION} - Network Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  sudo redaudit

  # Non-interactive mode
  sudo redaudit --target 192.168.1.0/24 --mode normal --yes

  # With encryption
  sudo redaudit --target 192.168.1.0/24 --encrypt --encrypt-password "MyPass" --yes
""",
    )

    # Load persisted defaults (best-effort).
    persisted_defaults = {}
    try:
        from redaudit.utils.config import get_persistent_defaults

        persisted_defaults = get_persistent_defaults()
    except Exception:
        persisted_defaults = {}

    # Apply persisted defaults with safe validation/fallbacks.
    # Use suggest_threads() for dynamic detection if no valid persisted value.
    default_threads = persisted_defaults.get("threads")
    if not isinstance(default_threads, int) or not (MIN_THREADS <= default_threads <= MAX_THREADS):
        default_threads = suggest_threads()

    default_output = persisted_defaults.get("output_dir")
    if not isinstance(default_output, str) or not default_output.strip():
        default_output = None

    default_rate_limit = persisted_defaults.get("rate_limit")
    if not isinstance(default_rate_limit, (int, float)) or default_rate_limit < 0:
        default_rate_limit = 0.0

    default_udp_mode = persisted_defaults.get("udp_mode")
    if default_udp_mode not in ("quick", "full"):
        default_udp_mode = DEFAULT_UDP_MODE

    default_udp_top_ports = persisted_defaults.get("udp_top_ports")
    if not isinstance(default_udp_top_ports, int) or default_udp_top_ports <= 0:
        default_udp_top_ports = UDP_TOP_PORTS

    default_lang = persisted_defaults.get("lang")
    if default_lang not in ("en", "es"):
        default_lang = None

    default_topology_enabled = persisted_defaults.get("topology_enabled")
    if not isinstance(default_topology_enabled, bool):
        default_topology_enabled = False

    default_nuclei_enabled = persisted_defaults.get("nuclei_enabled")
    if not isinstance(default_nuclei_enabled, bool):
        default_nuclei_enabled = False

    default_nuclei_profile = persisted_defaults.get("nuclei_profile")
    if default_nuclei_profile not in ("fast", "balanced", "full"):
        default_nuclei_profile = "balanced"

    default_windows_verify_enabled = persisted_defaults.get("windows_verify_enabled")
    if not isinstance(default_windows_verify_enabled, bool):
        default_windows_verify_enabled = False

    default_windows_verify_max_targets = persisted_defaults.get("windows_verify_max_targets")
    if not isinstance(default_windows_verify_max_targets, int) or not (
        1 <= default_windows_verify_max_targets <= 200
    ):
        default_windows_verify_max_targets = 20

    parser.add_argument(
        "--target",
        "-t",
        type=str,
        metavar="TARGETS",
        help="Targets in CIDR/IP/range notation (comma-separated for multiple)",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["fast", "normal", "full"],
        default="normal",
        help="Scan mode: fast (discovery), normal (ports), full (all scans)",
    )
    parser.add_argument(
        "--threads",
        "-j",
        type=int,
        default=default_threads,
        choices=range(MIN_THREADS, MAX_THREADS + 1),
        metavar=f"{MIN_THREADS}-{MAX_THREADS}",
        help=f"Concurrent scanning threads (default: auto-detected, max {MAX_THREADS})",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=default_rate_limit,
        metavar="SECONDS",
        help="Delay between host scans in seconds (default: 0)",
    )
    parser.add_argument(
        "--encrypt", "-e", action="store_true", help="Encrypt reports with password"
    )
    parser.add_argument(
        "--encrypt-password",
        type=str,
        metavar="PASSWORD",
        help="Password for encryption (non-interactive mode). If --encrypt is used without this flag, a random password will be generated and displayed.",
    )
    parser.add_argument(
        "--no-vuln-scan", action="store_true", help="Disable web vulnerability scanning"
    )
    parser.add_argument(
        "--no-txt-report", action="store_true", help="Disable TXT report generation"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=default_output,
        help=f"Output directory for reports (default: {get_default_reports_base_dir()})",
    )
    parser.add_argument(
        "--max-hosts", type=int, help="Maximum number of hosts to scan (default: all)"
    )
    parser.add_argument("--no-deep-scan", action="store_true", help="Disable adaptive deep scan")
    parser.add_argument(
        "--low-impact-enrichment",
        action="store_true",
        help=help_low_impact,
    )
    parser.add_argument(
        "--deep-scan-budget",
        type=int,
        default=DEFAULT_DEEP_SCAN_BUDGET,
        metavar="N",
        help=help_deep_budget,
    )
    parser.add_argument(
        "--identity-threshold",
        type=int,
        default=DEFAULT_IDENTITY_THRESHOLD,
        metavar="N",
        help=help_identity_threshold,
    )
    parser.add_argument(
        "--dead-host-retries",
        type=int,
        default=DEFAULT_DEAD_HOST_RETRIES,
        metavar="N",
        help=help_dead_host_retries,
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip legal warning confirmation (use with caution)",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "es"],
        default=default_lang,
        help="Language: en (English) or es (Español)",
    )
    # v3.2.3: DX improvements
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (auto-detected for non-TTY)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands that would be executed without running them",
    )
    # v4.5.17: Verbose output
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging output",
    )
    parser.add_argument(
        "--no-prevent-sleep",
        action="store_true",
        help="Do not inhibit system/display sleep while a scan is running",
    )
    # v3.3: HTML report generation
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate interactive HTML report with charts and tables",
    )
    # v3.3: Webhook alerting
    parser.add_argument(
        "--webhook",
        type=str,
        metavar="URL",
        help="Webhook URL for real-time alerts on high/critical findings",
    )
    # v3.5.5: Nuclei template scanning (optional; requires nuclei installed)
    nuclei_group = parser.add_mutually_exclusive_group()
    nuclei_group.add_argument(
        "--nuclei",
        dest="nuclei",
        action="store_true",
        default=default_nuclei_enabled,
        help="Enable Nuclei template scanner (requires nuclei; runs in full mode only)",
    )
    nuclei_group.add_argument(
        "--no-nuclei",
        dest="nuclei",
        action="store_false",
        help="Disable Nuclei template scanner (override persisted defaults)",
    )
    # v4.6.20: Nuclei timeout (useful for Docker/slow networks)
    parser.add_argument(
        "--nuclei-timeout",
        type=int,
        default=300,
        help="Nuclei batch timeout in seconds (default: 300). Increase for slow networks.",
    )
    parser.add_argument(
        "--profile",
        dest="nuclei_profile",
        choices=["fast", "balanced", "full"],
        default=default_nuclei_profile,
        help="Set Nuclei scan intensity/speed (fast, balanced, full)",
    )
    windows_verify_group = parser.add_mutually_exclusive_group()
    windows_verify_group.add_argument(
        "--agentless-verify",
        dest="windows_verify",
        action="store_true",
        default=default_windows_verify_enabled,
        help="Enable agentless verification (SMB/RDP/LDAP/SSH/HTTP) for compatible targets",
    )
    windows_verify_group.add_argument(
        "--no-agentless-verify",
        dest="windows_verify",
        action="store_false",
        help="Disable agentless verification (override persisted defaults)",
    )
    parser.add_argument(
        "--agentless-verify-max-targets",
        type=int,
        default=default_windows_verify_max_targets,
        metavar="N",
        help="Max targets for agentless verification (1-200, default: 20)",
    )
    parser.add_argument("--version", "-V", action="version", version=f"RedAudit v{VERSION}")

    # v2.8.0 options
    parser.add_argument(
        "--udp-mode",
        choices=["quick", "full"],
        default=default_udp_mode,
        help="UDP scan mode: quick (priority ports) or full (all ports)",
    )
    parser.add_argument(
        "--udp-ports",
        type=int,
        default=default_udp_top_ports,
        metavar="N",
        help="Number of top UDP ports to scan in full UDP mode (default: 100)",
    )
    parser.add_argument(
        "--skip-update-check", action="store_true", help="Skip update check at startup"
    )

    # v3.0 options
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("OLD", "NEW"),
        help="Compare two JSON reports and show changes (no scan performed)",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        metavar="URL",
        help=(
            "SOCKS5 proxy for pivoting (requires proxychains4; TCP only; "
            "socks5://host:port or socks5://user:pass@host:port)"
        ),
    )
    parser.add_argument(
        "--ipv6", action="store_true", help="Enable IPv6-only mode (scan only IPv6 networks)"
    )
    parser.add_argument(
        "--nvd-key",
        type=str,
        metavar="KEY",
        help="NVD API key for CVE correlation (faster rate limits)",
    )
    parser.add_argument(
        "--cve-lookup",
        action="store_true",
        help="Enable CVE correlation via NVD API (slower, requires internet)",
    )
    parser.add_argument(
        "--allow-non-root",
        action="store_true",
        help="Allow running without root (limited features; some scans may fail)",
    )
    # v3.2.3: Stealth mode for enterprise networks
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Stealth mode: slow scanning for enterprise networks with IDS/rate limiters (T1 timing, 1 thread, 5s delay)",
    )

    # v3.1+: Topology discovery (ARP/VLAN/LLDP + gateway/routes)
    topology_group = parser.add_mutually_exclusive_group()
    topology_group.add_argument(
        "--topology",
        dest="topology",
        action="store_true",
        default=default_topology_enabled,
        help="Enable topology discovery (ARP/VLAN/LLDP + gateway/routes)",
    )
    topology_group.add_argument(
        "--no-topology",
        dest="topology",
        action="store_false",
        help="Disable topology discovery (override persisted defaults)",
    )
    topology_group.add_argument(
        "--topology-only",
        dest="topology_only",
        action="store_true",
        help="Run topology discovery only (skip host scanning)",
    )

    # v3.1+: Persist current CLI defaults to ~/.redaudit/config.json
    parser.add_argument(
        "--save-defaults",
        action="store_true",
        help="Save current CLI settings as persistent defaults (~/.redaudit/config.json)",
    )

    # v3.2.1+: Control whether persisted defaults are applied
    defaults_group = parser.add_mutually_exclusive_group()
    defaults_group.add_argument(
        "--defaults",
        choices=["ask", "use", "ignore"],
        default="ask",
        help="Persistent defaults behavior: ask (interactive), use, ignore",
    )
    defaults_group.add_argument(
        "--use-defaults",
        dest="defaults",
        action="store_const",
        const="use",
        help="Use persisted defaults without prompting",
    )
    defaults_group.add_argument(
        "--ignore-defaults",
        dest="defaults",
        action="store_const",
        const="ignore",
        help="Ignore persisted defaults (factory values for this run)",
    )

    # v4.6.0: Trust HyperScan Optimization
    parser.add_argument(
        "--trust-hyperscan",
        "--trust-discovery",
        dest="trust_hyperscan",
        action="store_true",
        help="Trust HyperScan/Discovery results for Deep Scan (scan found ports only, skip -p-)",
    )

    # v3.2+: Enhanced network discovery
    parser.add_argument(
        "--net-discovery",
        nargs="?",
        const="all",
        default=None,
        metavar="PROTOCOLS",
        help="Enable network discovery (all, or comma-separated: dhcp,netbios,mdns,upnp,arp,fping)",
    )
    parser.add_argument(
        "--scan-routed",
        action="store_true",
        help="Automatically include discovered routed networks (via local gateways) in scan scope",
    )
    parser.add_argument(
        "--follow-routes",
        action="store_true",
        help="Automatically include discovered remote networks (via SNMP/Routing Protocols) in scan scope",
    )
    parser.add_argument(
        "--redteam",
        action="store_true",
        help="Include Red Team discovery techniques (best-effort, slower/noisier)",
    )
    parser.add_argument(
        "--net-discovery-interface",
        type=str,
        metavar="IFACE",
        default=None,
        help="Network interface for net discovery and L2 captures (e.g., eth0)",
    )
    parser.add_argument(
        "--redteam-max-targets",
        type=int,
        metavar="N",
        default=50,
        help="Max target IPs sampled for redteam checks (1-500, default: 50)",
    )
    parser.add_argument(
        "--snmp-community",
        type=str,
        metavar="COMMUNITY",
        default="public",
        help="SNMP community for SNMP walking (default: public)",
    )
    parser.add_argument(
        "--dns-zone",
        type=str,
        metavar="ZONE",
        default=None,
        help="DNS zone for AXFR attempt (e.g., corp.local). If omitted, DHCP domain is used when available",
    )
    parser.add_argument(
        "--kerberos-realm",
        type=str,
        metavar="REALM",
        default=None,
        help="Kerberos realm hint (e.g., CORP.LOCAL). If omitted, attempts best-effort discovery",
    )
    parser.add_argument(
        "--kerberos-userlist",
        type=str,
        metavar="PATH",
        default=None,
        help="Optional userlist for Kerberos userenum (requires kerbrute; use only with authorization)",
    )
    parser.add_argument(
        "--redteam-active-l2",
        action="store_true",
        help="Enable additional L2-focused checks that may be noisier (bettercap/scapy sniff; requires root)",
    )

    # v4.0: Authenticated Scanning (Phase 4)
    auth_group = parser.add_argument_group("Authenticated Scanning")
    auth_group.add_argument(
        "--auth-provider",
        choices=["env", "keyring"],
        default="keyring",
        help="Credential provider backend: env (environment vars) or keyring (OS keychain)",
    )
    auth_group.add_argument(
        "--ssh-user",
        type=str,
        metavar="USER",
        help="Default SSH username for authenticated scanning",
    )
    auth_group.add_argument(
        "--ssh-key",
        type=str,
        metavar="PATH",
        help="Path to default SSH private key",
    )
    auth_group.add_argument(
        "--ssh-key-pass",
        type=str,
        metavar="PASSPHRASE",
        help="Passphrase for SSH private key (if encrypted)",
    )
    auth_group.add_argument(
        "--ssh-trust-keys",
        action="store_true",
        help="Auto-accept unknown SSH host keys (WARNING: susceptible to MITM)",
    )
    # Note: passwords should be passed via env vars or keyring for security
    auth_group.add_argument(
        "--smb-user",
        type=str,
        metavar="USER",
        help="Default SMB/Windows username (format: User or DOMAIN\\\\User)",
    )
    auth_group.add_argument(
        "--smb-pass",
        type=str,
        metavar="PASSWORD",
        help="Default SMB/Windows password",
    )
    auth_group.add_argument(
        "--smb-domain",
        type=str,
        metavar="DOMAIN",
        help="Default SMB/Windows domain (overrides DOMAIN\\\\User format)",
    )
    auth_group.add_argument(
        "--snmp-user",
        type=str,
        metavar="USER",
        help="Default SNMP v3 Username",
    )
    auth_group.add_argument(
        "--snmp-auth-proto",
        choices=["SHA", "MD5", "SHA224", "SHA256", "SHA384", "SHA512"],
        help="SNMP v3 Auth Protocol",
    )
    auth_group.add_argument(
        "--snmp-auth-pass",
        type=str,
        metavar="PASSWORD",
        help="SNMP v3 Auth Password",
    )
    auth_group.add_argument(
        "--snmp-priv-proto",
        choices=["AES", "DES", "AES192", "AES256", "3DES"],
        help="SNMP v3 Privacy Protocol",
    )
    auth_group.add_argument(
        "--snmp-priv-pass",
        type=str,
        metavar="PASSWORD",
        help="SNMP v3 Privacy Password",
    )
    auth_group.add_argument(
        "--snmp-topology",
        action="store_true",
        help="Enable deep SNMP topology queries (Routes, ARP) on authenticated devices",
    )

    # v4.3: Lynis Integration
    parser.add_argument(
        "--lynis",
        action="store_true",
        help="Enable Lynis hardening audit on authenticaticated Linux hosts (requires SSH)",
    )

    # v4.5.1: Multi-credential support
    parser.add_argument(
        "--credentials-file",
        type=str,
        metavar="PATH",
        help="JSON file with credentials list for universal auth (auto-detects protocol)",
    )
    parser.add_argument(
        "--generate-credentials-template",
        action="store_true",
        help="Generate empty credentials template (~/.redaudit/credentials.json) and exit",
    )

    # v4.3: HyperScan mode selection
    parser.add_argument(
        "--hyperscan-mode",
        choices=["auto", "connect", "syn"],
        default="auto",
        help="HyperScan method: auto (default, tries SYN if root), connect (no root), syn (requires root)",
    )

    return parser.parse_args()


def configure_from_args(app, args) -> bool:
    """
    Configure application from command-line arguments.

    Args:
        app: InteractiveNetworkAuditor instance
        args: Parsed arguments

    Returns:
        True if configuration succeeded
    """
    # Set language if specified
    if args.lang:
        if args.lang in TRANSLATIONS:
            app.lang = args.lang

    # Check dependencies
    if not app.check_dependencies():
        return False

    # Legal warning (unless --yes)
    if not args.yes:
        if not app.show_legal_warning():
            return False
    else:
        app.print_status(app.t("legal_warning_skipped"), "WARNING")

    # Parse targets
    final_targets = []

    if args.target:
        targets = [t.strip() for t in args.target.split(",") if t.strip()]
        valid_targets, invalid = parse_target_tokens(targets, MAX_CIDR_LENGTH)
        if invalid:
            for bad in invalid:
                if len(bad) > MAX_CIDR_LENGTH:
                    app.print_status(app.t("invalid_target_too_long", bad), "FAIL")
                else:
                    app.print_status(app.t("invalid_cidr_target", bad), "FAIL")
        if valid_targets:
            final_targets.extend(valid_targets)

    # v4.9: Auto-add routed networks if requested
    if getattr(args, "scan_routed", False):
        try:
            from redaudit.core.net_discovery import detect_routed_networks

            routed_res = detect_routed_networks(logger=app.logger)
            routed_nets = routed_res.get("networks", [])

            # Avoid duplications
            current_set = set(final_targets)
            added_count = 0
            for net in routed_nets:
                if net not in current_set:
                    final_targets.append(net)
                    current_set.add(net)
                    added_count += 1

            if added_count > 0:
                app.print_status(
                    f"Found and added {added_count} hidden routed networks to scope via --scan-routed",
                    "OKGREEN",
                )
        except ImportError:
            pass

    if final_targets:
        app.config["target_networks"] = final_targets
    else:
        app.print_status(app.t("target_required_non_interactive"), "FAIL")
        return False

    # Set scan mode
    mode_map = {"fast": "rapido", "normal": "normal", "full": "completo"}
    app.config["scan_mode"] = mode_map[args.mode]
    app.config["scan_mode_cli"] = args.mode  # Preserve CLI value for reports

    # Set threads
    app.config["threads"] = args.threads

    # Set rate limit
    app.rate_limit_delay = max(0.0, args.rate_limit)

    # Set output directory
    if args.output:
        app.config["output_dir"] = expand_user_path(args.output)

    # v3.5: Dry-run (print commands where supported)
    app.config["dry_run"] = bool(getattr(args, "dry_run", False))
    if app.config["dry_run"]:
        os.environ["REDAUDIT_DRY_RUN"] = "1"

    # v3.5: Prevent sleep while scanning (best-effort)
    app.config["prevent_sleep"] = not bool(getattr(args, "no_prevent_sleep", False))

    # Set max hosts
    if args.max_hosts:
        app.config["max_hosts_value"] = args.max_hosts
    else:
        app.config["max_hosts_value"] = "all"

    # Set vulnerability scanning
    app.config["scan_vulnerabilities"] = not args.no_vuln_scan

    # Set TXT report
    app.config["save_txt_report"] = not args.no_txt_report

    # v3.3: HTML report generation
    app.config["html_report"] = getattr(args, "html_report", False)

    # v3.3: Webhook alerting
    app.config["webhook_url"] = getattr(args, "webhook", None)

    # Set deep scan
    app.config["deep_id_scan"] = not args.no_deep_scan
    app.config["low_impact_enrichment"] = bool(getattr(args, "low_impact_enrichment", False))
    deep_scan_budget = getattr(args, "deep_scan_budget", DEFAULT_DEEP_SCAN_BUDGET)
    if not isinstance(deep_scan_budget, int) or deep_scan_budget < 0:
        deep_scan_budget = DEFAULT_DEEP_SCAN_BUDGET
    app.config["deep_scan_budget"] = deep_scan_budget
    identity_threshold = getattr(args, "identity_threshold", DEFAULT_IDENTITY_THRESHOLD)
    if (
        not isinstance(identity_threshold, int)
        or identity_threshold < 0
        or identity_threshold > 100
    ):
        identity_threshold = DEFAULT_IDENTITY_THRESHOLD
    app.config["identity_threshold"] = identity_threshold
    # v4.13: Dead host budget - abandon after N consecutive timeouts
    dead_host_retries = getattr(args, "dead_host_retries", DEFAULT_DEAD_HOST_RETRIES)
    if not isinstance(dead_host_retries, int) or dead_host_retries < 0:
        dead_host_retries = DEFAULT_DEAD_HOST_RETRIES
    app.config["dead_host_retries"] = dead_host_retries

    # Set UDP mode (v2.8.0)
    app.config["udp_mode"] = args.udp_mode
    if not isinstance(args.udp_ports, int) or not (50 <= args.udp_ports <= 500):
        app.print_status(app.t("val_out_of_range", 50, 500), "FAIL")
        return False
    app.config["udp_top_ports"] = args.udp_ports

    # v3.1+: Topology discovery
    app.config["topology_enabled"] = bool(args.topology or args.topology_only)
    app.config["topology_only"] = bool(args.topology_only)

    # v3.0: IPv6 mode
    app.config["ipv6_only"] = args.ipv6 if hasattr(args, "ipv6") else False

    # v3.0: CVE correlation
    app.config["cve_lookup_enabled"] = args.cve_lookup if hasattr(args, "cve_lookup") else False
    app.config["nvd_api_key"] = args.nvd_key if hasattr(args, "nvd_key") else None
    app.config["allow_non_root"] = args.allow_non_root

    # v3.2.3: Stealth mode for enterprise networks
    if getattr(args, "stealth", False):
        app.config["stealth_mode"] = True
        app.config["threads"] = 1  # Sequential scanning
        app.rate_limit_delay = max(app.rate_limit_delay, 5.0)  # Minimum 5s delay
        app.config["nmap_timing"] = "T1"  # Paranoid timing
        app.print_status("Stealth mode: T1 timing, 1 thread, 5s+ delay", "INFO")
    else:
        app.config["stealth_mode"] = False
        app.config["nmap_timing"] = "T4"  # Default aggressive

    # v3.2+: Enhanced network discovery
    if args.net_discovery:
        app.config["net_discovery_enabled"] = True
        if args.net_discovery != "all":
            protocols = [p.strip().lower() for p in args.net_discovery.split(",")]
            valid_protocols = ["dhcp", "netbios", "mdns", "upnp", "arp", "fping"]
            app.config["net_discovery_protocols"] = [p for p in protocols if p in valid_protocols]
        else:
            app.config["net_discovery_protocols"] = None  # All protocols
    app.config["net_discovery_redteam"] = args.redteam
    app.config["net_discovery_interface"] = (
        args.net_discovery_interface.strip() if args.net_discovery_interface else None
    )
    if isinstance(args.redteam_max_targets, int) and 1 <= args.redteam_max_targets <= 500:
        app.config["net_discovery_max_targets"] = args.redteam_max_targets
    app.config["net_discovery_snmp_community"] = args.snmp_community
    app.config["net_discovery_dns_zone"] = args.dns_zone
    app.config["net_discovery_kerberos_realm"] = args.kerberos_realm
    app.config["net_discovery_kerberos_userlist"] = args.kerberos_userlist
    app.config["net_discovery_active_l2"] = bool(args.redteam_active_l2)
    app.config["nuclei_enabled"] = bool(getattr(args, "nuclei", False))
    # v4.6.20: Nuclei timeout for slow/Docker networks
    nuclei_timeout = getattr(args, "nuclei_timeout", 300)
    if not isinstance(nuclei_timeout, int) or nuclei_timeout < 60:
        nuclei_timeout = 300  # Minimum 60s, default 300s
    app.config["nuclei_timeout"] = nuclei_timeout
    nuclei_profile = getattr(args, "nuclei_profile", "balanced")
    if nuclei_profile not in ("fast", "balanced", "full"):
        nuclei_profile = "balanced"
    app.config["nuclei_profile"] = nuclei_profile

    # v4.0: Authenticated Scanning
    app.config["auth_provider"] = getattr(args, "auth_provider", "keyring")
    app.config["auth_ssh_user"] = getattr(args, "ssh_user", None)
    app.config["auth_ssh_key"] = getattr(args, "ssh_key", None)
    app.config["auth_ssh_key_pass"] = getattr(args, "ssh_key_pass", None)
    app.config["auth_ssh_trust_keys"] = getattr(args, "ssh_trust_keys", False)

    # v4.2: SMB
    app.config["auth_smb_user"] = getattr(args, "smb_user", None)
    app.config["auth_smb_pass"] = getattr(args, "smb_pass", None)
    app.config["auth_smb_domain"] = getattr(args, "smb_domain", None)

    # v4.3: SNMP v3
    app.config["auth_snmp_user"] = getattr(args, "snmp_user", None)
    app.config["auth_snmp_auth_proto"] = getattr(args, "snmp_auth_proto", None)
    app.config["auth_snmp_auth_pass"] = getattr(args, "snmp_auth_pass", None)
    app.config["auth_snmp_priv_proto"] = getattr(args, "snmp_priv_proto", None)
    app.config["auth_snmp_priv_pass"] = getattr(args, "snmp_priv_pass", None)

    # v4.3: Lynis
    app.config["lynis_enabled"] = bool(getattr(args, "lynis", False))

    # v4.5.1: Multi-credential support
    credentials_file = getattr(args, "credentials_file", None)
    if credentials_file:
        try:
            from redaudit.core.credentials_manager import CredentialsManager

            creds_mgr = CredentialsManager()
            creds_mgr.load_from_file(expand_user_path(credentials_file))
            app.config["auth_credentials"] = [
                {"user": c.user, "pass": c.password} for c in creds_mgr.credentials
            ]
            app.config["auth_enabled"] = True
            app.print_status(f"Loaded {len(creds_mgr.credentials)} credentials", "OKGREEN")
        except FileNotFoundError:
            app.print_status(f"Credentials file not found: {credentials_file}", "FAIL")
            return False
        except Exception as e:
            app.print_status(f"Error loading credentials: {e}", "FAIL")
            return False

    # v4.3: HyperScan mode
    app.config["hyperscan_mode"] = getattr(args, "hyperscan_mode", "auto")
    if not isinstance(args.agentless_verify_max_targets, int) or not (
        1 <= args.agentless_verify_max_targets <= 200
    ):
        app.print_status(app.t("val_out_of_range", 1, 200), "FAIL")
        return False
    app.config["windows_verify_enabled"] = bool(getattr(args, "windows_verify", False))
    app.config["windows_verify_max_targets"] = args.agentless_verify_max_targets

    # Setup encryption if requested
    if args.encrypt:
        app.setup_encryption(non_interactive=True, password=args.encrypt_password)

    # v3.1+: Save defaults (best-effort; should never block execution)
    if args.save_defaults:
        try:
            from redaudit.utils.config import update_persistent_defaults

            update_persistent_defaults(
                threads=app.config.get("threads"),
                output_dir=app.config.get("output_dir"),
                rate_limit=app.rate_limit_delay,
                udp_mode=app.config.get("udp_mode"),
                udp_top_ports=app.config.get("udp_top_ports"),
                topology_enabled=app.config.get("topology_enabled"),
                nuclei_enabled=app.config.get("nuclei_enabled"),
                windows_verify_enabled=app.config.get("windows_verify_enabled"),
                windows_verify_max_targets=app.config.get("windows_verify_max_targets"),
                lang=app.lang,
            )
            app.print_status(app.t("defaults_saved"), "OKGREEN")
        except Exception:
            app.print_status(app.t("defaults_save_error"), "WARNING")

    return True


def main():
    """Main entry point for RedAudit CLI."""
    args = parse_arguments()

    # v3.2.3: Disable ANSI colors for non-TTY output or when explicitly requested.
    # Many modules import the COLORS dict directly, so we mutate it in-place to
    # propagate the setting globally.
    if getattr(args, "no_color", False) or not sys.stdout.isatty():
        from redaudit.utils.constants import COLORS

        for key in list(COLORS.keys()):
            COLORS[key] = ""

    # v4.5.1: Generate credentials template and exit
    if getattr(args, "generate_credentials_template", False):
        from redaudit.core.credentials_manager import CredentialsManager

        template_path = os.path.expanduser("~/.redaudit/credentials.json")
        CredentialsManager.generate_template(template_path)
        print(f"Credentials template generated: {template_path}")
        print("Edit this file with your credentials, then use --credentials-file to load.")
        sys.exit(0)

    # v3.0: Handle --diff mode (no scan, just comparison) - does not require root
    if args.diff:
        from redaudit.core.diff import (
            generate_diff_report,
            format_diff_text,
            format_diff_markdown,
            format_diff_html,
        )

        old_path, new_path = args.diff

        print(f"Comparing reports: {old_path} vs {new_path}")
        diff = generate_diff_report(old_path, new_path)

        if not diff:
            print("Error: Could not load or compare reports. Check file paths.")
            sys.exit(1)

        # Output both text and markdown
        print(format_diff_text(diff))

        # Save markdown version
        md_path = f"diff_report_{diff['generated_at'][:10]}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(format_diff_markdown(diff))
        try:
            from redaudit.utils.constants import SECURE_FILE_MODE

            os.chmod(md_path, SECURE_FILE_MODE)
        except Exception:
            pass
        print(f"\nMarkdown report saved: {md_path}")

        # v3.3: Save HTML version for visual diff
        html_path = f"diff_report_{diff['generated_at'][:10]}.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(format_diff_html(diff))
        try:
            from redaudit.utils.constants import SECURE_FILE_MODE

            os.chmod(html_path, SECURE_FILE_MODE)
        except Exception:
            pass
        print(f"HTML report saved: {html_path}")

        sys.exit(0)

    if os.geteuid() != 0 and not getattr(args, "allow_non_root", False):
        print(
            "Error: root privileges (sudo) required. Use --allow-non-root to proceed in limited mode."
        )
        sys.exit(1)
    elif os.geteuid() != 0:
        print("⚠  Running without root: some scans (OS detection, UDP, tcpdump) may fail.")

    # Import here to avoid circular imports
    from redaudit.core.auditor import InteractiveNetworkAuditor
    from redaudit.core.updater import interactive_update_check

    app = InteractiveNetworkAuditor()
    app.lang = detect_preferred_language(getattr(args, "lang", None))
    app.defaults_mode = getattr(args, "defaults", "ask")

    # Non-interactive mode: allow forcing "factory" values even if persisted defaults exist.
    if args.target and getattr(args, "defaults", None) == "ignore":
        argv = sys.argv[1:]

        def _has_any(flags):
            return any(f in argv for f in flags)

        if not _has_any(["--threads", "-j"]):
            args.threads = suggest_threads()
        if not _has_any(["--rate-limit"]):
            args.rate_limit = 0.0
        if not _has_any(["--output", "-o"]):
            args.output = None
        if not _has_any(["--udp-mode"]):
            args.udp_mode = DEFAULT_UDP_MODE
        if not _has_any(["--udp-ports"]):
            args.udp_ports = UDP_TOP_PORTS
        if not _has_any(["--topology", "--no-topology", "--topology-only"]):
            args.topology = False
            args.topology_only = False

    # v3.0: Configure proxy if specified
    if args.proxy:
        from redaudit.core.proxy import ProxyManager, is_proxychains_available

        proxy_manager = ProxyManager(args.proxy)
        if not proxy_manager.is_valid():
            app.print_status(app.t("invalid_proxy_url", args.proxy), "FAIL")
            sys.exit(1)
        success, msg = proxy_manager.test_connection()
        if success:
            app.print_status(app.t("proxy_configured", msg), "OKGREEN")
            if not is_proxychains_available():
                app.print_status(app.t("proxychains_missing"), "FAIL")
                sys.exit(1)
            app.proxy_manager = proxy_manager
        else:
            app.print_status(app.t("proxy_test_failed", msg), "FAIL")
            sys.exit(1)

    # Non-interactive mode if --target is provided
    if args.target:
        if configure_from_args(app, args):
            ok = app.run_complete_scan()
            sys.exit(0 if ok else 1)
        else:
            sys.exit(1)
    else:
        # Interactive mode with main menu (v3.2.2+)
        app.clear_screen()
        app.print_banner()

        # Update check before menu (respects --skip-update-check)
        if not args.skip_update_check and os.geteuid() == 0:
            if app.ask_yes_no(app.t("update_check_prompt"), default="no"):
                did_update = interactive_update_check(
                    print_fn=app.print_status,
                    ask_fn=app.ask_yes_no,
                    t_fn=app.t,
                    logger=app.logger,
                    lang=app.lang,
                )
                if did_update:
                    sys.exit(0)

        # Main menu loop
        while True:
            choice = app.show_main_menu()

            if choice == 0:  # Exit
                sys.exit(0)

            elif choice == 1:  # Start scan (wizard)
                try:
                    if app.interactive_setup():
                        ok = app.run_complete_scan()
                        sys.exit(0 if ok else 1)
                    else:
                        print(app.t("config_cancel"))
                        sys.exit(0)
                except KeyboardInterrupt:
                    print("\n")
                    app.print_status(app.t("config_cancel"), "WARNING")
                    sys.exit(0)

            elif choice == 2:  # Check for updates
                if os.geteuid() != 0:
                    app.print_status(app.t("update_requires_root"), "WARNING")
                else:
                    interactive_update_check(
                        print_fn=app.print_status,
                        ask_fn=app.ask_yes_no,
                        t_fn=app.t,
                        logger=app.logger,
                        lang=app.lang,
                    )

            elif choice == 3:  # Diff reports
                from redaudit.core.diff import (
                    generate_diff_report,
                    format_diff_text,
                    format_diff_markdown,
                )

                try:
                    old_path = input(
                        f"{app.COLORS['CYAN']}?{app.COLORS['ENDC']} {app.t('diff_enter_old_path')} "
                    ).strip()
                    new_path = input(
                        f"{app.COLORS['CYAN']}?{app.COLORS['ENDC']} {app.t('diff_enter_new_path')} "
                    ).strip()

                    if old_path and new_path:
                        diff = generate_diff_report(old_path, new_path)
                        if diff:
                            print(format_diff_text(diff))
                            md_path = f"diff_report_{diff['generated_at'][:10]}.md"
                            with open(md_path, "w") as f:
                                f.write(format_diff_markdown(diff))
                            app.print_status(f"Markdown report saved: {md_path}", "OKGREEN")
                        else:
                            app.print_status("Could not compare reports. Check file paths.", "FAIL")
                except KeyboardInterrupt:
                    print("")


if __name__ == "__main__":
    main()
