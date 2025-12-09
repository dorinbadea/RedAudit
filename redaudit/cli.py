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
import ipaddress

from redaudit.utils.constants import (
    VERSION,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    MAX_CIDR_LENGTH,
)
from redaudit.utils.i18n import TRANSLATIONS


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
"""
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        metavar="CIDR",
        help="Target network(s) in CIDR notation (comma-separated for multiple)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["fast", "normal", "full"],
        default="normal",
        help="Scan mode: fast (discovery), normal (ports), full (all scans)"
    )
    parser.add_argument(
        "--threads", "-j",
        type=int,
        default=DEFAULT_THREADS,
        choices=range(MIN_THREADS, MAX_THREADS + 1),
        metavar=f"{MIN_THREADS}-{MAX_THREADS}",
        help=f"Concurrent scanning threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between host scans in seconds (default: 0)"
    )
    parser.add_argument(
        "--encrypt", "-e",
        action="store_true",
        help="Encrypt reports with password"
    )
    parser.add_argument(
        "--encrypt-password",
        type=str,
        metavar="PASSWORD",
        help="Password for encryption (non-interactive mode). If --encrypt is used without this flag, a random password will be generated and displayed."
    )
    parser.add_argument(
        "--no-vuln-scan",
        action="store_true",
        help="Disable web vulnerability scanning"
    )
    parser.add_argument(
        "--no-txt-report",
        action="store_true",
        help="Disable TXT report generation"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output directory for reports (default: ~/RedAuditReports)"
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        help="Maximum number of hosts to scan (default: all)"
    )
    parser.add_argument(
        "--no-deep-scan",
        action="store_true",
        help="Disable adaptive deep scan"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip legal warning confirmation (use with caution)"
    )
    parser.add_argument(
        "--lang",
        choices=["en", "es"],
        help="Language: en (English) or es (Español)"
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"RedAudit v{VERSION}"
    )

    # Pre-scan options (v2.7)
    parser.add_argument(
        "--prescan",
        action="store_true",
        help="Enable fast asyncio pre-scan before nmap (v2.7)"
    )
    parser.add_argument(
        "--prescan-ports",
        type=str,
        default="1-1024",
        metavar="RANGE",
        help="Port range for pre-scan (default: 1-1024)"
    )
    parser.add_argument(
        "--prescan-timeout",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Pre-scan connection timeout (default: 0.5)"
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
        app.print_status("⚠️  Legal warning skipped (--yes flag)", "WARNING")

    # Parse targets
    if args.target:
        targets = [t.strip() for t in args.target.split(",")]
        valid_targets = []
        for t in targets:
            if len(t) > MAX_CIDR_LENGTH:
                app.print_status(f"Invalid target (too long): {t}", "FAIL")
                continue
            try:
                ipaddress.ip_network(t, strict=False)
                valid_targets.append(t)
            except ValueError:
                app.print_status(f"Invalid CIDR: {t}", "FAIL")
        if not valid_targets:
            app.print_status("No valid targets provided", "FAIL")
            return False
        app.config["target_networks"] = valid_targets
    else:
        app.print_status("Error: --target is required in non-interactive mode", "FAIL")
        return False

    # Set scan mode
    mode_map = {"fast": "rapido", "normal": "normal", "full": "completo"}
    app.config["scan_mode"] = mode_map[args.mode]

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

    # Setup encryption if requested
    if args.encrypt:
        app.setup_encryption(non_interactive=True, password=args.encrypt_password)

    return True


def main():
    """Main entry point for RedAudit CLI."""
    if os.geteuid() != 0:
        print("Error: root privileges (sudo) required.")
        sys.exit(1)

    args = parse_arguments()

    # Import here to avoid circular imports
    from redaudit.core.auditor import InteractiveNetworkAuditor

    app = InteractiveNetworkAuditor()

    # Non-interactive mode if --target is provided
    if args.target:
        if configure_from_args(app, args):
            ok = app.run_complete_scan()
            sys.exit(0 if ok else 1)
        else:
            sys.exit(1)
    else:
        # Interactive mode
        if app.interactive_setup():
            ok = app.run_complete_scan()
            sys.exit(0 if ok else 1)
        else:
            print(app.t("config_cancel"))
            sys.exit(0)


if __name__ == "__main__":
    main()
