#!/usr/bin/env python3
"""
RedAudit - CLI Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Command-line interface and argument parsing.
"""

import os
import sys
import argparse
import ipaddress

from redaudit.utils.constants import (
    VERSION,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    MAX_CIDR_LENGTH,
    DEFAULT_UDP_MODE,
    UDP_TOP_PORTS,
)
from redaudit.utils.i18n import TRANSLATIONS, detect_preferred_language


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
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
    default_threads = persisted_defaults.get("threads")
    if not isinstance(default_threads, int) or not (MIN_THREADS <= default_threads <= MAX_THREADS):
        default_threads = DEFAULT_THREADS

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

    parser.add_argument(
        "--target",
        "-t",
        type=str,
        metavar="CIDR",
        help="Target network(s) in CIDR notation (comma-separated for multiple)",
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
        help=f"Concurrent scanning threads (default: {DEFAULT_THREADS})",
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
        help="Output directory for reports (default: ~/Documents/RedAuditReports)",
    )
    parser.add_argument(
        "--max-hosts", type=int, help="Maximum number of hosts to scan (default: all)"
    )
    parser.add_argument("--no-deep-scan", action="store_true", help="Disable adaptive deep scan")
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
    parser.add_argument("--version", "-V", action="version", version=f"RedAudit v{VERSION}")

    # Pre-scan options (v2.7)
    parser.add_argument(
        "--prescan", action="store_true", help="Enable fast asyncio pre-scan before nmap"
    )
    parser.add_argument(
        "--prescan-ports",
        type=str,
        default="1-1024",
        metavar="RANGE",
        help="Port range for pre-scan (default: 1-1024)",
    )
    parser.add_argument(
        "--prescan-timeout",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Pre-scan connection timeout (default: 0.5)",
    )

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
        help="SOCKS5 proxy for pivoting (socks5://host:port or socks5://user:pass@host:port)",
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
    if args.target:
        targets = [t.strip() for t in args.target.split(",")]
        valid_targets = []
        for t in targets:
            if len(t) > MAX_CIDR_LENGTH:
                app.print_status(app.t("invalid_target_too_long", t), "FAIL")
                continue
            try:
                ipaddress.ip_network(t, strict=False)
                valid_targets.append(t)
            except ValueError:
                app.print_status(app.t("invalid_cidr_target", t), "FAIL")
        if not valid_targets:
            app.print_status(app.t("no_valid_targets"), "FAIL")
            return False
        app.config["target_networks"] = valid_targets
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
        app.config["output_dir"] = os.path.expanduser(args.output)

    # Set max hosts
    if args.max_hosts:
        app.config["max_hosts_value"] = args.max_hosts
    else:
        app.config["max_hosts_value"] = "all"

    # Set vulnerability scanning
    app.config["scan_vulnerabilities"] = not args.no_vuln_scan

    # Set TXT report
    app.config["save_txt_report"] = not args.no_txt_report

    # Set deep scan
    app.config["deep_id_scan"] = not args.no_deep_scan

    # Set pre-scan configuration (v2.7)
    app.config["prescan_enabled"] = args.prescan
    app.config["prescan_ports"] = args.prescan_ports
    app.config["prescan_timeout"] = args.prescan_timeout

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
                lang=app.lang,
            )
            app.print_status(app.t("defaults_saved"), "OKGREEN")
        except Exception:
            app.print_status(app.t("defaults_save_error"), "WARNING")

    return True


def main():
    """Main entry point for RedAudit CLI."""
    args = parse_arguments()

    # v3.0: Handle --diff mode (no scan, just comparison) - does not require root
    if args.diff:
        from redaudit.core.diff import generate_diff_report, format_diff_text, format_diff_markdown

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
        with open(md_path, "w") as f:
            f.write(format_diff_markdown(diff))
        print(f"\nMarkdown report saved: {md_path}")

        sys.exit(0)

    if os.geteuid() != 0 and not getattr(args, "allow_non_root", False):
        print(
            "Error: root privileges (sudo) required. Use --allow-non-root to proceed in limited mode."
        )
        sys.exit(1)
    elif os.geteuid() != 0:
        print("⚠️  Running without root: some scans (OS detection, UDP, tcpdump) may fail.")

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
            args.threads = DEFAULT_THREADS
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
        from redaudit.core.proxy import ProxyManager

        proxy_manager = ProxyManager(args.proxy)
        if not proxy_manager.is_valid():
            app.print_status(app.t("invalid_proxy_url", args.proxy), "FAIL")
            sys.exit(1)
        success, msg = proxy_manager.test_connection()
        if success:
            app.print_status(app.t("proxy_configured", msg), "OKGREEN")
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
                if app.interactive_setup():
                    ok = app.run_complete_scan()
                    sys.exit(0 if ok else 1)
                else:
                    print(app.t("config_cancel"))
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
                from redaudit.core.diff import generate_diff_report, format_diff_text, format_diff_markdown

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
