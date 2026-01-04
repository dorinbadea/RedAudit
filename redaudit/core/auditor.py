#!/usr/bin/env python3
"""
RedAudit - Main Auditor Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Main orchestrator class for network auditing operations.
"""

import math
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict

from redaudit.utils.constants import (
    COLORS,
    DEFAULT_LANG,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    suggest_threads,
    UDP_SCAN_MODE_FULL,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
    VERSION,
)
from redaudit.utils.paths import (
    expand_user_path,
    get_default_reports_base_dir,
    maybe_chown_to_invoking_user,
)
from redaudit.utils.i18n import TRANSLATIONS
from redaudit.core.auditor_components import _ActivityIndicator
from redaudit.core.auditor_runtime import AuditorRuntime
from redaudit.core.nuclei import (
    is_nuclei_available,
    run_nuclei_scan,
    get_http_targets_from_hosts,
)
from redaudit.core.crypto import is_crypto_available
from redaudit.core.reporter import (
    generate_summary,
    save_results,
    show_config_summary,
    show_results_summary,
)
from redaudit.core.config_context import ConfigurationContext
from redaudit.core.network_scanner import NetworkScanner


class InteractiveNetworkAuditor:
    """Main orchestrator for RedAudit scans."""

    def __getattr__(self, name: str):
        runtime = self.__dict__.get("_runtime")
        if runtime is not None and hasattr(runtime, name):
            return getattr(runtime, name)
        raise AttributeError(f"{self.__class__.__name__} has no attribute {name}")

    def __init__(self):
        self.lang = DEFAULT_LANG if DEFAULT_LANG in TRANSLATIONS else "en"
        # How to apply persisted defaults: ask/use/ignore (CLI may override).
        self.defaults_mode = "ask"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "network_info": [],
            "hosts": [],
            "vulnerabilities": [],
            "summary": {},
        }
        # v4.0: ConfigurationContext Composition
        self.cfg = ConfigurationContext()

        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = is_crypto_available()
        self.rate_limit_delay = 0.0
        self.extra_tools = {}

        # v3.0: Proxy manager (set by CLI if --proxy used)
        self.proxy_manager = None

        self.last_activity = datetime.now()
        self.activity_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._ui_progress_active = False
        self._ui_detail_lock = threading.Lock()
        self._ui_detail = ""
        self.heartbeat_stop = False
        self.heartbeat_thread = None
        self.current_phase = "init"
        self.interrupted = False
        self.scan_start_time = None

        # Subprocess tracking for cleanup on interruption (C1 fix)
        self._active_subprocesses = []
        self._subprocess_lock = threading.Lock()

        self.COLORS = COLORS

        self.logger = None
        self._runtime = AuditorRuntime(self)
        self._setup_logging()

        # v4.0: Direct Composition - UIManager
        from redaudit.core.ui_manager import UIManager

        self._ui_manager = UIManager(lang=self.lang, colors=self.COLORS, logger=self.logger)
        self.scanner = NetworkScanner(self.cfg, self._ui_manager, self.logger)

        signal.signal(signal.SIGINT, self.signal_handler)

    # v4.0: Adapter property for gradual migration to ConfigurationContext
    # v4.0: Adapter property for gradual migration to ConfigurationContext
    @property
    def config(self):
        """
        Backward compatibility proxy for self.cfg (ConfigurationContext).
        Allows access akin to self.config["key"].
        """
        return self.cfg

    @config.setter
    def config(self, value):
        # Handle re-assignment of self.config
        if isinstance(value, ConfigurationContext):
            self.cfg = value
        else:
            self.cfg = ConfigurationContext(value)

    # ---------- Reporting ----------

    def show_config_summary(self):
        """Display configuration summary."""
        show_config_summary(self.config, self.ui.t, self.ui.colors)

    def show_results(self):
        """Display final results summary."""
        show_results_summary(self.results, self.ui.t, self.ui.colors, self.config["output_dir"])

    def show_legal_warning(self):
        """Display legal warning and ask for confirmation."""
        print(f"{self.ui.colors['FAIL']}{self.ui.t('legal_warn')}{self.ui.colors['ENDC']}")
        return self.ask_yes_no(self.ui.t("legal_ask"), default="no")

    def save_results(self, partial=False):
        """Save results to files."""
        self.current_phase = "saving"
        if self.config.get("lang") is None:
            self.config["lang"] = self.lang
        save_results(
            self.results,
            self.config,
            self.encryption_enabled,
            self.encryption_key,
            partial,
            self.ui.print_status,
            self.ui.t,
            self.logger,
        )

    # ---------- Interactive flow (UI methods inherited from Wizard) ----------

    def interactive_setup(self):
        """Run interactive configuration setup."""
        # Apply persisted defaults early (language affects the banner/prompt text).
        persisted_defaults = {}
        try:
            from redaudit.utils.config import get_persistent_defaults

            persisted_defaults = get_persistent_defaults()
        except Exception:
            if self.logger:
                self.logger.debug("Failed to load persisted defaults", exc_info=True)
            persisted_defaults = {}

        default_lang = persisted_defaults.get("lang")
        if default_lang in TRANSLATIONS:
            self.lang = default_lang

        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies():
            return False
        if not self.show_legal_warning():
            return False

        # v3.2.1+: Give explicit control over persisted defaults.
        defaults_for_run = persisted_defaults
        should_skip_config = False
        auto_start = False
        scan_default_keys = (
            "target_networks",
            "threads",
            "output_dir",
            "rate_limit",
            "udp_mode",
            "udp_top_ports",
            "topology_enabled",
            "topology_only",
            "scan_mode",
            "scan_vulnerabilities",
            "nuclei_enabled",
            "cve_lookup_enabled",
            "generate_txt",
            "generate_html",
            "net_discovery_enabled",
            "net_discovery_redteam",
            "net_discovery_active_l2",
            "net_discovery_kerberos_userenum",
            "net_discovery_kerberos_realm",
            "net_discovery_kerberos_userlist",
        )
        has_scan_defaults = any(persisted_defaults.get(k) is not None for k in scan_default_keys)

        if has_scan_defaults:
            mode = getattr(self, "defaults_mode", "ask") or "ask"
            if mode == "ignore":
                defaults_for_run = {}
                self.ui.print_status(self.ui.t("defaults_ignore_confirm"), "INFO")
            elif mode == "ask":
                self.ui.print_status(self.ui.t("defaults_detected"), "INFO")
                options = [
                    self.ui.t("defaults_action_use"),
                    self.ui.t("defaults_action_review"),
                    self.ui.t("defaults_action_ignore"),
                ]
                choice = self.ask_choice(self.ui.t("defaults_action_q"), options, 0)
                if choice == 2:
                    defaults_for_run = {}
                    self.ui.print_status(self.ui.t("defaults_ignore_confirm"), "INFO")
                elif choice == 0:
                    # Use defaults and continue immediately (no re-asking scan parameters).
                    should_skip_config = True
                    auto_start = True
                elif choice == 1:
                    show_summary = self.ask_yes_no(
                        self.ui.t("defaults_show_summary_q"), default="no"
                    )
                    if show_summary:
                        self._show_defaults_summary(persisted_defaults)

        print(f"\n{self.ui.colors['HEADER']}{self.ui.t('scan_config')}{self.ui.colors['ENDC']}")
        print("=" * 60)

        # Targets: if the user chose to start immediately, prefer persisted targets when valid.
        target_networks = (
            defaults_for_run.get("target_networks") if isinstance(defaults_for_run, dict) else None
        )
        if (
            should_skip_config
            and isinstance(target_networks, list)
            and target_networks
            and all(isinstance(t, str) and t.strip() for t in target_networks)
        ):
            self.config["target_networks"] = [t.strip() for t in target_networks]
            self.ui.print_status(
                self.ui.t("defaults_targets_applied", len(self.config["target_networks"])), "INFO"
            )
        else:
            self.config["target_networks"] = self.ask_network_range()

        if should_skip_config:
            self._apply_run_defaults(defaults_for_run)
            self.encryption_enabled = False
        else:
            self._configure_scan_interactive(defaults_for_run)

        self.show_config_summary()

        if auto_start:
            return True

        # v3.1+: Save chosen settings as persistent defaults (optional).
        # v3.2.2+: Simplified - max 2 final prompts (save + start)
        wants_save_defaults = self.ask_yes_no(self.ui.t("save_defaults_q"), default="no")
        if wants_save_defaults:
            try:
                from redaudit.utils.config import update_persistent_defaults

                ok = update_persistent_defaults(
                    target_networks=self.config.get("target_networks"),
                    threads=self.config.get("threads"),
                    output_dir=self.config.get("output_dir"),
                    rate_limit=self.rate_limit_delay,
                    udp_mode=self.config.get("udp_mode"),
                    udp_top_ports=self.config.get("udp_top_ports"),
                    topology_enabled=self.config.get("topology_enabled"),
                    topology_only=self.config.get("topology_only"),
                    low_impact_enrichment=self.config.get("low_impact_enrichment"),
                    # v3.2.3+: New defaults
                    scan_mode=self.config.get("scan_mode"),
                    scan_vulnerabilities=self.config.get("scan_vulnerabilities"),
                    nuclei_enabled=self.config.get("nuclei_enabled"),
                    cve_lookup_enabled=self.config.get("cve_lookup_enabled"),
                    generate_txt=self.config.get("save_txt_report"),
                    generate_html=self.config.get("save_html_report"),
                    # v3.6.0+: Net discovery / red team
                    net_discovery_enabled=self.config.get("net_discovery_enabled"),
                    net_discovery_redteam=self.config.get("net_discovery_redteam"),
                    net_discovery_active_l2=self.config.get("net_discovery_active_l2"),
                    net_discovery_kerberos_userenum=self.config.get(
                        "net_discovery_kerberos_userenum"
                    ),
                    net_discovery_kerberos_realm=self.config.get("net_discovery_kerberos_realm"),
                    net_discovery_kerberos_userlist=self.config.get(
                        "net_discovery_kerberos_userlist"
                    ),
                    windows_verify_enabled=self.config.get("windows_verify_enabled"),
                    windows_verify_max_targets=self.config.get("windows_verify_max_targets"),
                    auditor_name=self.config.get("auditor_name"),
                    lang=self.lang,
                )
                self.ui.print_status(
                    self.ui.t("defaults_saved") if ok else self.ui.t("defaults_save_error"),
                    "OKGREEN" if ok else "WARNING",
                )
            except Exception:
                self.ui.print_status(self.ui.t("defaults_save_error"), "WARNING")
                if self.logger:
                    self.logger.debug("Failed to persist defaults", exc_info=True)

        return self.ask_yes_no(self.ui.t("start_audit"), default="yes")

    def run_complete_scan(self):
        """Execute the complete scan workflow."""
        self.scan_start_time = datetime.now()
        self.start_heartbeat()
        self._deep_executed_count = 0

        inhibitor = None
        if self.config.get("prevent_sleep", True):
            try:
                from redaudit.core.power import SleepInhibitor

                inhibitor = SleepInhibitor(logger=self.logger)
                inhibitor.start()
            except Exception:
                inhibitor = None

        try:
            # v2.8.1: Create timestamped output folder BEFORE scanning
            # This ensures PCAP files are saved inside the result folder
            ts_folder = self.scan_start_time.strftime("%Y-%m-%d_%H-%M-%S")
            output_base = self.config.get("output_dir", get_default_reports_base_dir())
            self.config["_actual_output_dir"] = os.path.join(output_base, f"RedAudit_{ts_folder}")
            os.makedirs(self.config["_actual_output_dir"], exist_ok=True)
            maybe_chown_to_invoking_user(self.config["_actual_output_dir"])

            # v3.7: Start session logging
            from redaudit.utils.session_log import start_session_log

            start_session_log(self.config["_actual_output_dir"], ts_folder)

            # Ensure network_info is populated for reports and topology discovery.
            if not self.results.get("network_info"):
                try:
                    # v4.0: Use Scanner
                    nets = self.scanner.detect_local_networks()
                    self.results["network_info"] = nets
                except Exception:
                    if self.logger:
                        self.logger.debug("Failed to detect local networks", exc_info=True)
                    pass

            # v3.1+: Optional topology discovery (best-effort)
            if self.config.get("topology_enabled") and not self.interrupted:
                try:
                    from redaudit.core.topology import discover_topology

                    self.current_phase = "topology"
                    self.ui.print_status(self.ui.t("topology_start"), "INFO")

                    # v3.2.3: Add spinner progress for topology phase
                    try:
                        from rich.progress import (
                            Progress,
                            SpinnerColumn,
                            TimeElapsedColumn,
                        )

                        with Progress(
                            SpinnerColumn(),
                            self._safe_text_column(
                                "[bold cyan]Topology[/bold cyan] {task.description}",
                                overflow="ellipsis",
                                no_wrap=True,
                            ),
                            TimeElapsedColumn(),
                            console=self._progress_console(),
                            transient=True,
                            refresh_per_second=4,
                        ) as progress:
                            task = progress.add_task("discovering...", total=None)
                            self.results["topology"] = discover_topology(
                                target_networks=self.config.get("target_networks", []),
                                network_info=self.results.get("network_info", []),
                                extra_tools=self.extra_tools,
                                logger=self.logger,
                            )
                            progress.update(task, description="complete")
                    except ImportError:
                        self.results["topology"] = discover_topology(
                            target_networks=self.config.get("target_networks", []),
                            network_info=self.results.get("network_info", []),
                            extra_tools=self.extra_tools,
                            logger=self.logger,
                        )
                except Exception as exc:
                    if self.logger:
                        self.logger.warning("Topology discovery failed: %s", exc)
                        self.logger.debug("Topology discovery exception details", exc_info=True)
                    self.results["topology"] = {"enabled": True, "error": str(exc)}

                if self.config.get("topology_only"):
                    self.config["rate_limit_delay"] = self.rate_limit_delay
                    generate_summary(self.results, self.config, [], [], self.scan_start_time)
                    self.save_results(partial=self.interrupted)
                    self.show_results()
                    return True

            # v3.2+: Enhanced network discovery (best-effort)
            # v3.2.1: Auto-enabled in 'completo' mode for complete network visibility
            # v3.2.3: Also auto-enabled when topology is enabled (intelligent discovery)
            net_discovery_auto = self.config.get("scan_mode") == "completo"
            topology_enabled = self.config.get("topology_enabled")
            net_discovery_setting = self.config.get("net_discovery_enabled")
            net_discovery_explicit = net_discovery_setting is True
            net_discovery_disabled = net_discovery_setting is False
            if (
                (not net_discovery_disabled)
                and (net_discovery_explicit or net_discovery_auto or topology_enabled)
            ) and not self.interrupted:
                try:
                    from redaudit.core.net_discovery import discover_networks

                    self.current_phase = "net_discovery"
                    self.ui.print_status(self.ui.t("net_discovery_start"), "INFO")

                    iface = self._select_net_discovery_interface()
                    redteam_options = {
                        "max_targets": self.config.get("net_discovery_max_targets", 50),
                        "snmp_community": self.config.get("net_discovery_snmp_community", "public"),
                        "dns_zone": self.config.get("net_discovery_dns_zone"),
                        "kerberos_realm": self.config.get("net_discovery_kerberos_realm"),
                        "kerberos_userlist": self.config.get("net_discovery_kerberos_userlist"),
                        "active_l2": bool(self.config.get("net_discovery_active_l2", False)),
                    }

                    # v3.2.3: Add spinner progress for net_discovery phase
                    try:
                        from rich.progress import (
                            BarColumn,
                            Progress,
                            SpinnerColumn,
                            TextColumn,
                            TimeElapsedColumn,
                        )

                        with self._progress_ui():
                            with Progress(
                                SpinnerColumn(),
                                self._safe_text_column(
                                    "[bold blue]Net Discovery[/bold blue] {task.description}",
                                    overflow="ellipsis",
                                    no_wrap=True,
                                ),
                                BarColumn(bar_width=20),
                                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                                TimeElapsedColumn(),
                                console=self._progress_console(),
                                transient=True,
                                refresh_per_second=4,
                            ) as progress:
                                # v3.8.1: Simplified progress - elapsed only, no ETA
                                task = progress.add_task(
                                    "initializing...",
                                    total=100,
                                )
                                nd_start_time = time.time()
                                nd_start_time = time.time()

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=self.config.get("net_discovery_redteam", False),
                                    redteam_options=redteam_options,
                                    extra_tools=self.extra_tools,
                                    progress_callback=lambda lbl, s, t: self._nd_progress_callback(
                                        lbl, s, t, progress, task, nd_start_time
                                    ),
                                    logger=self.logger,
                                )
                                progress.update(task, completed=100, description="complete")
                    except ImportError:
                        # Fallback without progress bar
                        with self._progress_ui():
                            with _ActivityIndicator(
                                label="Net Discovery",
                                touch_activity=self._touch_activity,
                            ) as indicator:

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=self.config.get("net_discovery_redteam", False),
                                    redteam_options=redteam_options,
                                    extra_tools=self.extra_tools,
                                    progress_callback=lambda lbl, s, t: indicator.update(
                                        f"{lbl} ({s}/{t})"
                                    ),
                                    logger=self.logger,
                                )

                    # Log discovered DHCP servers
                    dhcp_servers = self.results["net_discovery"].get("dhcp_servers", [])
                    if dhcp_servers:
                        self.ui.print_status(
                            self.ui.t("net_discovery_dhcp_found", len(dhcp_servers)),
                            "OKGREEN",
                        )
                    candidate_vlans = self.results["net_discovery"].get("candidate_vlans", [])
                    if candidate_vlans:
                        self.ui.print_status(
                            self.ui.t("net_discovery_vlans_found", len(candidate_vlans)),
                            "WARNING",
                        )

                    # v3.2.3: Visible CLI logging for HyperScan results
                    hyperscan_dur = self.results["net_discovery"].get("hyperscan_duration", 0)
                    if hyperscan_dur > 0:
                        arp_hosts = self.results["net_discovery"].get("arp_hosts", [])
                        upnp_devices = self.results["net_discovery"].get("upnp_devices", [])
                        tcp_hosts = self.results["net_discovery"].get("hyperscan_tcp_hosts", {})
                        self.ui.print_status(
                            f"✓ HyperScan: {len(arp_hosts)} ARP, {len(upnp_devices)} IoT/UPNP, {len(tcp_hosts)} TCP hosts ({hyperscan_dur:.1f}s)",
                            "OKGREEN",
                        )
                    backdoors = self.results["net_discovery"].get("potential_backdoors", [])
                    if backdoors:
                        self.ui.print_status(
                            f"⚠️  {len(backdoors)} puertos sospechosos (backdoor) detectados",
                            "WARNING",
                        )
                except Exception as exc:
                    if self.logger:
                        self.logger.warning("Net discovery failed: %s", exc)
                        self.logger.debug("Net discovery exception details", exc_info=True)
                    self.results["net_discovery"] = {"enabled": True, "error": str(exc)}

            discovery_hosts = self._collect_discovery_hosts(
                self.config.get("target_networks", []) or []
            )
            if discovery_hosts:
                self.ui.print_status(
                    self.ui.t("net_discovery_seed_hosts", len(discovery_hosts)),
                    "INFO",
                )

            all_hosts = []
            for network in self.config["target_networks"]:
                if self.interrupted:
                    break
                hosts = self.scan_network_discovery(network)
                all_hosts.extend(hosts)

            if discovery_hosts:
                before = set(all_hosts)
                all_hosts.extend(discovery_hosts)
                added = len(set(all_hosts) - before)
                if added > 0:
                    self.ui.print_status(
                        self.ui.t("net_discovery_seed_added", added),
                        "INFO",
                    )

            if not all_hosts:
                self.ui.print_status(self.ui.t("no_hosts"), "WARNING")
                self.stop_heartbeat()
                return False

            max_val = self.config["max_hosts_value"]
            if max_val != "all" and isinstance(max_val, int):
                all_hosts = all_hosts[:max_val]

            # v4.0: Pass Host objects to scanning engine
            host_targets = [self.scanner.get_or_create_host(ip) for ip in all_hosts]
            results = self.scan_hosts_concurrent(host_targets)

            # v3.8: Agentless Windows verification (SMB/RDP/LDAP) - opt-in
            if not self.interrupted:
                self.run_agentless_verification(results)

            # v3.0.1: CVE correlation via NVD (optional; can be slow)
            if self.config.get("cve_lookup_enabled") and not self.interrupted:
                try:
                    from redaudit.core.nvd import enrich_host_with_cves, get_api_key_from_config

                    # Ensure API key is loaded (from CLI, env, or config) without mislabeling the source.
                    if not self.config.get("nvd_api_key"):
                        self.setup_nvd_api_key(non_interactive=True)
                    api_key = self.config.get("nvd_api_key") or get_api_key_from_config()
                    for i, host_record in enumerate(results):
                        if self.interrupted:
                            break
                        results[i] = enrich_host_with_cves(
                            host_record, api_key=api_key, logger=self.logger
                        )
                    self.results["hosts"] = results
                except Exception:
                    # Best-effort: CVE enrichment should never break scans
                    if self.logger:
                        self.logger.debug("CVE enrichment failed (best-effort)", exc_info=True)
                    pass

            if self.config.get("scan_vulnerabilities") and not self.interrupted:
                self.scan_vulnerabilities_concurrent(results)

            # Nuclei template scanning (optional; full mode only, if installed and enabled)
            if (
                self.config.get("scan_vulnerabilities")
                and self.config.get("scan_mode") == "completo"
                and self.config.get("nuclei_enabled", False)
                and is_nuclei_available()
                and not self.interrupted
            ):
                self.ui.print_status(self.ui.t("nuclei_scan_start"), "INFO")
                try:
                    nuclei_targets = get_http_targets_from_hosts(results)
                    if nuclei_targets:
                        output_dir = (
                            self.config.get("_actual_output_dir")
                            or self.config.get("output_dir")
                            or get_default_reports_base_dir()
                        )

                        # Prefer a single Progress instance managed by the auditor to avoid
                        # competing Rich Live displays (which can cause flicker/no output).
                        nuclei_result = None
                        try:
                            from rich.progress import Progress

                            batch_size = 25
                            nuclei_timeout_s = 300
                            total_batches = max(1, int(math.ceil(len(nuclei_targets) / batch_size)))
                            progress_start_t = time.time()
                            with self._progress_ui():
                                with Progress(
                                    *self._progress_columns(
                                        show_detail=True,
                                        show_eta=True,
                                        show_elapsed=False,
                                    ),
                                    console=self._progress_console(),
                                    transient=False,
                                    refresh_per_second=4,
                                ) as progress:
                                    task = progress.add_task(
                                        f"[cyan]Nuclei (0/{total_batches})",
                                        total=total_batches,
                                        eta_upper=self._format_eta(
                                            total_batches * nuclei_timeout_s
                                        ),
                                        eta_est="",
                                        detail=f"{len(nuclei_targets)} targets",
                                    )

                                    def _nuclei_progress(
                                        completed: int, total: int, eta: str
                                    ) -> None:
                                        try:
                                            remaining = max(0, total - completed)
                                            elapsed_s = max(0.001, time.time() - progress_start_t)
                                            rate = completed / elapsed_s if completed else 0.0
                                            eta_est_val = (
                                                self._format_eta(remaining / rate)
                                                if rate > 0.0 and remaining
                                                else ""
                                            )
                                            progress.update(
                                                task,
                                                completed=completed,
                                                description=f"[cyan]Nuclei ({completed}/{total})",
                                                eta_upper=self._format_eta(
                                                    remaining * nuclei_timeout_s if remaining else 0
                                                ),
                                                eta_est=(
                                                    f"ETA≈ {eta_est_val}" if eta_est_val else ""
                                                ),
                                                detail=f"batch {completed}/{total}",
                                            )
                                        except Exception:
                                            pass

                                    nuclei_result = run_nuclei_scan(
                                        targets=nuclei_targets,
                                        output_dir=output_dir,
                                        severity="medium,high,critical",
                                        timeout=nuclei_timeout_s,
                                        batch_size=batch_size,
                                        progress_callback=lambda c, t, e: self._nuclei_progress_callback(
                                            c,
                                            t,
                                            e,
                                            progress,
                                            task,
                                            progress_start_t,
                                            nuclei_timeout_s,
                                        ),
                                        use_internal_progress=False,
                                        logger=self.logger,
                                        dry_run=bool(self.config.get("dry_run", False)),
                                        print_status=self.ui.print_status,
                                    )
                        except Exception:
                            nuclei_result = run_nuclei_scan(
                                targets=nuclei_targets,
                                output_dir=output_dir,
                                severity="medium,high,critical",
                                timeout=300,
                                logger=self.logger,
                                dry_run=bool(self.config.get("dry_run", False)),
                                print_status=self.ui.print_status,
                            )

                        findings = nuclei_result.get("findings") or []
                        suspected = []
                        if findings:
                            try:
                                from redaudit.core.verify_vuln import filter_nuclei_false_positives

                                host_agentless = {}
                                for host in self.results.get("hosts", []) or []:
                                    ip = host.get("ip")
                                    agentless = host.get("agentless_fingerprint") or {}
                                    if ip and agentless:
                                        host_agentless[ip] = agentless
                                findings, suspected = filter_nuclei_false_positives(
                                    findings, host_agentless, self.logger
                                )
                            except Exception as filter_err:
                                if self.logger:
                                    self.logger.warning(
                                        "Nuclei FP filter skipped: %s", filter_err, exc_info=True
                                    )
                        nuclei_summary = {
                            "enabled": True,
                            "targets": len(nuclei_targets),
                            "findings": len(findings),
                            "findings_total": len(nuclei_result.get("findings") or []),
                            "findings_suspected": len(suspected),
                            "success": bool(nuclei_result.get("success")),
                            "error": nuclei_result.get("error"),
                        }
                        if suspected:
                            nuclei_summary["suspected"] = [
                                {
                                    "template_id": f.get("template_id"),
                                    "matched_at": f.get("matched_at"),
                                    "fp_reason": f.get("fp_reason"),
                                }
                                for f in suspected[:25]
                                if isinstance(f, dict)
                            ]
                        raw_file = nuclei_result.get("raw_output_file")
                        if raw_file and isinstance(raw_file, str):
                            try:
                                nuclei_summary["output_file"] = os.path.relpath(
                                    raw_file, output_dir
                                )
                            except Exception:
                                nuclei_summary["output_file"] = raw_file
                        self.results["nuclei"] = nuclei_summary

                        merged = self._merge_nuclei_findings(findings)
                        if merged > 0:
                            self.ui.print_status(self.ui.t("nuclei_findings", merged), "OK")
                            if suspected:
                                self.ui.print_status(
                                    self.ui.t("nuclei_suspected", len(suspected)), "WARNING"
                                )
                        else:
                            self.ui.print_status(self.ui.t("nuclei_no_findings"), "INFO")
                except Exception as e:
                    if self.logger:
                        self.logger.warning("Nuclei scan failed: %s", e, exc_info=True)
                    self.ui.print_status(f"Nuclei: {e}", "WARNING")

            self.config["rate_limit_delay"] = self.rate_limit_delay
            generate_summary(self.results, self.config, all_hosts, results, self.scan_start_time)
            self.save_results(partial=self.interrupted)
            self.show_results()

        finally:
            # v3.7: Stop session logging
            from redaudit.utils.session_log import stop_session_log

            session_log_path = stop_session_log()
            if session_log_path and self.logger:
                self.logger.info("Session log saved: %s", session_log_path)

            if inhibitor is not None:
                try:
                    inhibitor.stop()
                except Exception:
                    pass
            self.stop_heartbeat()

        return not self.interrupted

    # ---------- Subprocess management (C1 fix) ----------

    def register_subprocess(self, proc: subprocess.Popen) -> None:
        """Register a subprocess for tracking and cleanup on interruption."""
        with self._subprocess_lock:
            self._active_subprocesses.append(proc)

    def unregister_subprocess(self, proc: subprocess.Popen) -> None:
        """Unregister a completed subprocess from tracking."""
        with self._subprocess_lock:
            if proc in self._active_subprocesses:
                self._active_subprocesses.remove(proc)

    def kill_all_subprocesses(self) -> None:
        """Terminate all tracked subprocesses (nmap, tcpdump, etc.)."""
        with self._subprocess_lock:
            for proc in self._active_subprocesses:
                try:
                    if proc.poll() is None:  # Still running
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                except Exception as exc:
                    if self.logger:
                        self.logger.debug("Error killing subprocess: %s", exc, exc_info=True)
            self._active_subprocesses.clear()

    def signal_handler(self, sig, frame):
        """Handle SIGINT (Ctrl+C) with proper cleanup."""
        try:
            ui = self.ui
        except AttributeError:
            ui = None

        def _status(msg_key: str, level: str) -> None:
            if ui:
                ui.print_status(ui.t(msg_key), level)
                return
            t_fn = getattr(self, "t", None)
            text = t_fn(msg_key) if callable(t_fn) else msg_key
            printer = getattr(self, "print_status", None)
            if callable(printer):
                printer(text, level)

        _status("interrupted", "WARNING")
        self.current_phase = "interrupted"
        self.interrupted = True

        # Kill all active subprocesses (nmap, tcpdump, etc.)
        if self._active_subprocesses:
            _status("terminating_scans", "WARNING")
            self.kill_all_subprocesses()

        # Stop heartbeat monitoring
        self.stop_heartbeat()

        # v2.8.1: If scan hasn't started yet, exit immediately
        if self.scan_start_time is None:
            sys.exit(0)

    def _apply_run_defaults(self, defaults_for_run: Dict) -> None:
        """Apply persisted defaults to self.config without prompts."""
        # 1. Scan Mode
        self.config["scan_mode"] = defaults_for_run.get("scan_mode", "normal")

        # 2. Max Hosts
        self.config["max_hosts_value"] = "all"

        # 3. Threads
        threads = defaults_for_run.get("threads")
        if isinstance(threads, int) and MIN_THREADS <= threads <= MAX_THREADS:
            self.config["threads"] = threads
        else:
            self.config["threads"] = DEFAULT_THREADS

        # 4. Rate Limit
        rate_limit = defaults_for_run.get("rate_limit")
        if isinstance(rate_limit, (int, float)) and rate_limit > 0:
            self.rate_limit_delay = float(min(max(rate_limit, 0), 60))
        else:
            self.rate_limit_delay = 0.0

        low_impact = defaults_for_run.get("low_impact_enrichment")
        self.config["low_impact_enrichment"] = (
            bool(low_impact) if isinstance(low_impact, bool) else False
        )

        # 5. Vulnerabilities
        self.config["scan_vulnerabilities"] = defaults_for_run.get("scan_vulnerabilities", True)
        self.config["nuclei_enabled"] = bool(defaults_for_run.get("nuclei_enabled", False))
        self.config["cve_lookup_enabled"] = defaults_for_run.get("cve_lookup_enabled", False)

        # 6. Output Dir
        out_dir = defaults_for_run.get("output_dir")
        if isinstance(out_dir, str) and out_dir.strip():
            self.config["output_dir"] = expand_user_path(out_dir.strip())
        else:
            self.config["output_dir"] = get_default_reports_base_dir()

        self.config["save_txt_report"] = defaults_for_run.get("generate_txt", True)
        self.config["save_html_report"] = defaults_for_run.get("generate_html", True)
        self.config["auditor_name"] = defaults_for_run.get("auditor_name")

        # 7. UDP Configuration
        self.config["udp_mode"] = defaults_for_run.get("udp_mode", UDP_SCAN_MODE_QUICK)
        self.config["udp_top_ports"] = defaults_for_run.get("udp_top_ports", UDP_TOP_PORTS)

        # 8. Topology
        self.config["topology_enabled"] = defaults_for_run.get("topology_enabled", False)
        self.config["topology_only"] = defaults_for_run.get("topology_only", False)

        # 9. Net discovery / Red team (wizard)
        self.config["net_discovery_enabled"] = bool(
            defaults_for_run.get("net_discovery_enabled", False)
        )
        self.config["net_discovery_redteam"] = bool(
            defaults_for_run.get("net_discovery_redteam", False)
        )
        self.config["net_discovery_active_l2"] = bool(
            defaults_for_run.get("net_discovery_active_l2", False)
        )
        self.config["net_discovery_kerberos_userenum"] = bool(
            defaults_for_run.get("net_discovery_kerberos_userenum", False)
        )
        self.config["net_discovery_kerberos_realm"] = defaults_for_run.get(
            "net_discovery_kerberos_realm"
        )
        userlist = defaults_for_run.get("net_discovery_kerberos_userlist")
        self.config["net_discovery_kerberos_userlist"] = (
            expand_user_path(userlist) if userlist else None
        )

        # 10. Agentless Windows verification
        self.config["windows_verify_enabled"] = bool(
            defaults_for_run.get("windows_verify_enabled", False)
        )
        max_targets = defaults_for_run.get("windows_verify_max_targets")
        if isinstance(max_targets, int) and 1 <= max_targets <= 200:
            self.config["windows_verify_max_targets"] = max_targets
        else:
            self.config["windows_verify_max_targets"] = 20

    def _ask_auditor_and_output_dir(self, defaults_for_run: Dict) -> None:
        """
        v3.9.0: Ask for auditor name and output directory.
        Used by automatic profiles (Express/Standard/Exhaustive) to ensure
        these prompts are not skipped.
        """
        # Auditor name
        auditor_default = defaults_for_run.get("auditor_name", "") if defaults_for_run else ""
        auditor_default = auditor_default or ""
        auditor_prompt = self.ui.t("auditor_name_q")
        auditor_name = input(
            f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {auditor_prompt} "
            f"[{auditor_default}]: "
        ).strip()
        if not auditor_name:
            auditor_name = auditor_default
        self.config["auditor_name"] = auditor_name.strip() if auditor_name else None

        # Output directory
        default_reports = get_default_reports_base_dir()
        persisted_output = defaults_for_run.get("output_dir") if defaults_for_run else None
        if isinstance(persisted_output, str) and persisted_output.strip():
            default_output = persisted_output
        else:
            default_output = default_reports

        output_prompt = self.ui.t("output_dir_q")
        output_dir = input(
            f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {output_prompt} "
            f"[{default_output}]: "
        ).strip()
        if not output_dir:
            output_dir = default_output
        self.config["output_dir"] = expand_user_path(output_dir)

    def _configure_scan_interactive(self, defaults_for_run: Dict) -> None:
        """
        v3.8.1: Interactive prompt sequence with step-by-step navigation.
        v3.9.0: Added profile selector (Express/Standard/Exhaustive/Custom).

        Uses a state machine pattern allowing users to go back to previous steps
        without restarting the entire wizard.
        """
        # v3.9.0: Profile selector - choose audit intensity
        from redaudit.utils.config import is_nvd_api_key_configured

        # Note: is_nuclei_available is already imported at module level from nuclei.py

        # v3.9.0: Loop for profile selection with back navigation from timing
        profile_choice = None
        timing_delay = 0.0
        timing_nmap_template = "T4"  # Default
        timing_threads_boost = False  # Aggressive mode boosts threads

        while profile_choice is None:
            profile_options = [
                self.ui.t("wizard_profile_express"),
                self.ui.t("wizard_profile_standard"),
                self.ui.t("wizard_profile_exhaustive"),
                self.ui.t("wizard_profile_custom"),
            ]
            profile_idx = self.ask_choice(self.ui.t("wizard_profile_q"), profile_options, default=1)

            # For profiles that ask timing, include a back option
            if profile_idx in (1, 2):  # Standard or Exhaustive
                timing_options = [
                    self.ui.t("timing_stealth"),
                    self.ui.t("timing_normal"),
                    self.ui.t("timing_aggressive"),
                    self.ui.t("go_back"),
                ]
                timing_choice = self.ask_choice(self.ui.t("timing_q"), timing_options, default=1)
                if timing_choice == 3:  # Go back
                    continue  # Re-show profile selector

                # v3.9.0: Real timing differences
                if timing_choice == 0:  # Stealth
                    timing_delay = 2.0
                    timing_nmap_template = "T1"  # Paranoid
                    timing_threads_boost = False
                elif timing_choice == 1:  # Normal
                    timing_delay = 0.0
                    timing_nmap_template = "T4"  # Aggressive (nmap default for speed)
                    timing_threads_boost = False
                elif timing_choice == 2:  # Aggressive
                    timing_delay = 0.0
                    timing_nmap_template = "T5"  # Insane
                    timing_threads_boost = True  # Will use MAX_THREADS

            profile_choice = profile_idx

        # PROFILE 0: Express - Fast scan with minimal config
        if profile_choice == 0:
            self.config["scan_mode"] = "rapido"
            self.config["max_hosts_value"] = "all"
            self.config["threads"] = DEFAULT_THREADS
            self.config["scan_vulnerabilities"] = False
            self.config["nuclei_enabled"] = False
            self.config["cve_lookup_enabled"] = False
            self.config["topology_enabled"] = True
            self.config["net_discovery_enabled"] = True
            self.config["net_discovery_redteam"] = False
            self.config["windows_verify_enabled"] = False
            self.config["save_txt_report"] = True
            self.config["save_html_report"] = True
            persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
            low_impact_default = "yes" if persisted_low_impact else "no"
            self.config["low_impact_enrichment"] = self.ask_yes_no(
                self.ui.t("low_impact_enrichment_q"), default=low_impact_default
            )
            # v3.9.0: Ask auditor name and output dir for all profiles
            self._ask_auditor_and_output_dir(defaults_for_run)
            self.rate_limit_delay = 0.0  # Express = always fast
            return

        # PROFILE 1: Standard - Balance (equivalent to old normal mode)
        if profile_choice == 1:
            self.config["scan_mode"] = "normal"
            self.config["max_hosts_value"] = "all"
            self.config["threads"] = DEFAULT_THREADS
            self.config["scan_vulnerabilities"] = True
            self.config["nuclei_enabled"] = False
            self.config["cve_lookup_enabled"] = False
            self.config["topology_enabled"] = True
            self.config["net_discovery_enabled"] = True
            self.config["net_discovery_redteam"] = False
            self.config["windows_verify_enabled"] = False
            self.config["save_txt_report"] = True
            self.config["save_html_report"] = True
            persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
            low_impact_default = "yes" if persisted_low_impact else "no"
            self.config["low_impact_enrichment"] = self.ask_yes_no(
                self.ui.t("low_impact_enrichment_q"), default=low_impact_default
            )
            # v3.9.0: Ask auditor name and output dir for all profiles
            self._ask_auditor_and_output_dir(defaults_for_run)
            # v3.9.0: Apply timing settings
            self.config["nmap_timing"] = timing_nmap_template
            if timing_threads_boost:
                self.config["threads"] = MAX_THREADS
            self.rate_limit_delay = timing_delay
            return

        # PROFILE 2: Exhaustive - Maximum discovery (auto-configures everything)
        if profile_choice == 2:
            self.ui.print_status(self.ui.t("exhaustive_mode_applying"), "INFO")

            # Core scan settings - maximum
            self.config["scan_mode"] = "completo"
            self.config["max_hosts_value"] = "all"
            # v3.9.0: Threads depend on timing choice
            # Stealth = reduced threads for IDS evasion, otherwise MAX
            if timing_nmap_template == "T1":  # Stealth
                self.config["threads"] = 2  # Very slow, IDS evasion
            else:
                self.config["threads"] = MAX_THREADS
            self.config["deep_id_scan"] = True
            # v3.9.0: Apply nmap timing template
            self.config["nmap_timing"] = timing_nmap_template

            # UDP - full scan
            self.config["udp_mode"] = UDP_SCAN_MODE_FULL
            self.config["udp_top_ports"] = 500  # ~98% coverage (was 200)

            # Vulnerability scanning - all enabled
            self.config["scan_vulnerabilities"] = True
            self.config["nuclei_enabled"] = is_nuclei_available()

            # NVD/CVE - enable if API key is configured, otherwise show reminder
            if is_nvd_api_key_configured():
                self.config["cve_lookup_enabled"] = True
                self.setup_nvd_api_key(non_interactive=True)
            else:
                self.config["cve_lookup_enabled"] = False
                self.ui.print_status(self.ui.t("nvd_not_configured_reminder"), "WARNING")
                print(
                    f"  {self.ui.colors['CYAN']}{self.ui.t('nvd_get_key_hint')}"
                    f"{self.ui.colors['ENDC']}"
                )

            # Discovery - all enabled
            self.config["topology_enabled"] = True
            self.config["topology_only"] = False
            self.config["net_discovery_enabled"] = True
            self.config["net_discovery_redteam"] = True
            self.config["net_discovery_active_l2"] = True
            self.config["net_discovery_kerberos_userenum"] = False  # Requires realm
            self.config["net_discovery_snmp_community"] = "public"
            self.config["net_discovery_dns_zone"] = ""
            self.config["net_discovery_max_targets"] = 100

            # Windows verification
            self.config["windows_verify_enabled"] = True
            self.config["windows_verify_max_targets"] = 50

            # Reports
            self.config["save_txt_report"] = True
            self.config["save_html_report"] = True
            self.config["output_dir"] = get_default_reports_base_dir()

            # Webhook off by default
            self.config["webhook_url"] = ""

            persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
            low_impact_default = "yes" if persisted_low_impact else "no"
            self.config["low_impact_enrichment"] = self.ask_yes_no(
                self.ui.t("low_impact_enrichment_q"), default=low_impact_default
            )

            # v3.9.0: Ask auditor name and output dir for all profiles
            self._ask_auditor_and_output_dir(defaults_for_run)

            # Rate limiting - already asked in profile selection loop
            self.rate_limit_delay = timing_delay
            return

        # PROFILE 3: Custom - Full wizard with 8 steps (original behavior)
        # v3.8.1: Wizard step machine for "< Volver" / "< Go Back" navigation
        TOTAL_STEPS = 8
        step = 1

        # Store choices for navigation (allows going back and reusing previous values)
        wizard_state: Dict = {}

        while step <= TOTAL_STEPS:
            # ═══════════════════════════════════════════════════════════════════
            # STEP 1: Scan Mode
            # ═══════════════════════════════════════════════════════════════════
            if step == 1:
                scan_modes = [
                    self.ui.t("mode_fast"),
                    self.ui.t("mode_normal"),
                    self.ui.t("mode_full"),
                ]
                modes_map = {0: "rapido", 1: "normal", 2: "completo"}
                persisted = defaults_for_run.get("scan_mode")
                default_idx = wizard_state.get(
                    "scan_mode_idx", {"rapido": 0, "normal": 1, "completo": 2}.get(persisted, 1)
                )

                choice = self.ask_choice_with_back(
                    self.ui.t("scan_mode"),
                    scan_modes,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    continue  # Can't go back from step 1

                wizard_state["scan_mode_idx"] = choice
                self.config["scan_mode"] = modes_map[choice]

                # Set max_hosts based on mode
                if self.config["scan_mode"] != "rapido":
                    limit = self.ask_number(self.ui.t("ask_num_limit"), default="all")
                    self.config["max_hosts_value"] = limit
                else:
                    self.config["max_hosts_value"] = "all"

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 2: Threads & Rate Limiting
            # ═══════════════════════════════════════════════════════════════════
            elif step == 2:
                # Show step header for UX
                self.ui.print_status(f"[{step}/{TOTAL_STEPS}] " + self.ui.t("threads"), "INFO")

                suggested_threads = suggest_threads()
                try:
                    cores = os.cpu_count()
                except Exception:
                    cores = None
                cores_display = str(cores) if isinstance(cores, int) and cores > 0 else "?"

                default_threads = wizard_state.get(
                    "threads",
                    (
                        defaults_for_run.get("threads")
                        if isinstance(defaults_for_run.get("threads"), int)
                        and MIN_THREADS <= defaults_for_run.get("threads") <= MAX_THREADS
                        else suggested_threads
                    ),
                )
                self.config["threads"] = self.ask_number(
                    self.ui.t("threads_suggested", suggested_threads, cores_display),
                    default=default_threads,
                    min_val=MIN_THREADS,
                    max_val=MAX_THREADS,
                )
                wizard_state["threads"] = self.config["threads"]

                # Rate limiting
                default_rate = defaults_for_run.get("rate_limit")
                if not isinstance(default_rate, (int, float)) or default_rate < 0:
                    default_rate = 0.0
                if self.ask_yes_no(
                    self.ui.t("rate_limiting"), default="yes" if default_rate > 0 else "no"
                ):
                    delay_default = int(default_rate) if default_rate > 0 else 1
                    delay_default = min(max(delay_default, 0), 60)
                    self.rate_limit_delay = float(
                        self.ask_number(
                            self.ui.t("rate_delay"), default=delay_default, min_val=0, max_val=60
                        )
                    )

                persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
                low_impact_default = "yes" if persisted_low_impact else "no"
                self.config["low_impact_enrichment"] = self.ask_yes_no(
                    self.ui.t("low_impact_enrichment_q"), default=low_impact_default
                )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 3: Vulnerability Scanning
            # ═══════════════════════════════════════════════════════════════════
            elif step == 3:
                vuln_options = [
                    self.ui.t("yes_option") + " — " + self.ui.t("vuln_scan_opt"),
                    self.ui.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("scan_vulnerabilities") is not False else 1
                default_idx = wizard_state.get("vuln_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.ui.t("vuln_scan_q"),
                    vuln_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["vuln_idx"] = choice
                self.config["scan_vulnerabilities"] = choice == 0

                # Nuclei (conditional)
                self.config["nuclei_enabled"] = False
                if (
                    self.config.get("scan_vulnerabilities")
                    and self.config.get("scan_mode") == "completo"
                    and is_nuclei_available()
                ):
                    self.config["nuclei_enabled"] = self.ask_yes_no(
                        self.ui.t("nuclei_q"),
                        default="yes" if defaults_for_run.get("nuclei_enabled") else "no",
                    )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 4: CVE Correlation
            # ═══════════════════════════════════════════════════════════════════
            elif step == 4:
                cve_options = [
                    self.ui.t("yes_option") + " — NVD API",
                    self.ui.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("cve_lookup_enabled") else 1
                default_idx = wizard_state.get("cve_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.ui.t("cve_lookup_q"),
                    cve_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["cve_idx"] = choice
                if choice == 0:
                    self.config["cve_lookup_enabled"] = True
                    self.setup_nvd_api_key()
                else:
                    self.config["cve_lookup_enabled"] = False

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 5: Output Directory
            # ═══════════════════════════════════════════════════════════════════
            elif step == 5:
                self.ui.print_status(f"[{step}/{TOTAL_STEPS}] " + self.ui.t("output_dir"), "INFO")

                auditor_default = wizard_state.get(
                    "auditor_name",
                    (
                        defaults_for_run.get("auditor_name")
                        if isinstance(defaults_for_run, dict)
                        else ""
                    ),
                )
                auditor_default = auditor_default or ""
                auditor_prompt = self.ui.t("auditor_name_q")
                auditor_name = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {auditor_prompt} "
                    f"[{auditor_default}]: "
                ).strip()
                if not auditor_name:
                    auditor_name = auditor_default
                auditor_name = auditor_name.strip()
                self.config["auditor_name"] = auditor_name if auditor_name else None
                wizard_state["auditor_name"] = self.config["auditor_name"] or ""

                default_reports = get_default_reports_base_dir()
                persisted_output = defaults_for_run.get("output_dir")
                if isinstance(persisted_output, str) and persisted_output.strip():
                    default_reports = expand_user_path(persisted_output.strip())

                out_dir = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('output_dir')} "
                    f"[{default_reports}]: "
                ).strip()
                if not out_dir:
                    out_dir = default_reports
                self.config["output_dir"] = expand_user_path(out_dir)

                # TXT and HTML always on
                self.config["save_txt_report"] = True
                self.config["save_html_report"] = True

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 6: UDP & Topology
            # ═══════════════════════════════════════════════════════════════════
            elif step == 6:
                # UDP configuration (only for non-rapido modes with deep scan)
                if self.config["scan_mode"] != "rapido" and self.config.get("deep_id_scan"):
                    udp_modes = [self.ui.t("udp_mode_quick"), self.ui.t("udp_mode_full")]
                    udp_map = {0: UDP_SCAN_MODE_QUICK, 1: UDP_SCAN_MODE_FULL}
                    persisted_udp = defaults_for_run.get("udp_mode")
                    default_idx = wizard_state.get(
                        "udp_idx", 1 if persisted_udp == UDP_SCAN_MODE_FULL else 0
                    )

                    choice = self.ask_choice_with_back(
                        self.ui.t("udp_mode_q"),
                        udp_modes,
                        default_idx,
                        step_num=step,
                        total_steps=TOTAL_STEPS,
                    )
                    if choice == self.WIZARD_BACK:
                        step -= 1
                        continue

                    wizard_state["udp_idx"] = choice
                    self.config["udp_mode"] = udp_map[choice]

                    # UDP ports profile
                    persisted_ports = defaults_for_run.get("udp_top_ports")
                    udp_ports_default = min(
                        max(
                            persisted_ports if isinstance(persisted_ports, int) else UDP_TOP_PORTS,
                            50,
                        ),
                        500,
                    )
                    self.config["udp_top_ports"] = udp_ports_default

                    if self.config["udp_mode"] == UDP_SCAN_MODE_FULL:
                        udp_profiles = [
                            (50, self.ui.t("udp_ports_profile_fast")),
                            (100, self.ui.t("udp_ports_profile_balanced")),
                            (200, self.ui.t("udp_ports_profile_thorough")),
                            (500, self.ui.t("udp_ports_profile_aggressive")),
                            ("custom", self.ui.t("udp_ports_profile_custom")),
                        ]
                        options = [label for _, label in udp_profiles]
                        profile_default = next(
                            (i for i, (v, _) in enumerate(udp_profiles) if v == udp_ports_default),
                            len(udp_profiles) - 1,
                        )
                        q = self.ui.t("udp_ports_profile_q")
                        selected_idx = self.ask_choice(q, options, profile_default)
                        selected = udp_profiles[selected_idx][0]
                        if selected == "custom":
                            self.config["udp_top_ports"] = self.ask_number(
                                self.ui.t("udp_ports_q"),
                                default=udp_ports_default,
                                min_val=50,
                                max_val=500,
                            )
                        else:
                            self.config["udp_top_ports"] = selected

                # Topology discovery
                topo_options = [
                    self.ui.t("topology_disabled"),
                    self.ui.t("topology_enabled_scan"),
                    self.ui.t("topology_only_mode"),
                ]
                persisted_topo = defaults_for_run.get("topology_enabled")
                persisted_only = defaults_for_run.get("topology_only")
                default_idx = 2 if persisted_only else (1 if persisted_topo else 0)
                default_idx = wizard_state.get("topo_idx", default_idx)

                topo_choice = self.ask_choice_with_back(
                    self.ui.t("topology_discovery_q"),
                    topo_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if topo_choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["topo_idx"] = topo_choice
                self.config["topology_enabled"] = topo_choice != 0
                self.config["topology_only"] = topo_choice == 2

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 7: Net Discovery & Red Team
            # ═══════════════════════════════════════════════════════════════════
            elif step == 7:
                nd_options = [
                    self.ui.t("yes_option") + " — DHCP/NetBIOS/mDNS/UPNP",
                    self.ui.t("no_option"),
                ]
                persisted_nd = defaults_for_run.get("net_discovery_enabled")
                nd_default = (
                    bool(persisted_nd)
                    if isinstance(persisted_nd, bool)
                    else bool(
                        self.config.get("topology_enabled")
                        or self.config.get("scan_mode") == "completo"
                    )
                )
                default_idx = 0 if nd_default else 1
                default_idx = wizard_state.get("nd_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.ui.t("net_discovery_q"),
                    nd_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["nd_idx"] = choice
                enable_net_discovery = choice == 0
                self.config["net_discovery_enabled"] = enable_net_discovery

                if enable_net_discovery:
                    # Red Team options
                    rt_options = [self.ui.t("redteam_mode_a"), self.ui.t("redteam_mode_b")]
                    rt_default = 1 if defaults_for_run.get("net_discovery_redteam") else 0
                    redteam_choice = self.ask_choice(
                        self.ui.t("redteam_mode_q"), rt_options, rt_default
                    )

                    wants_redteam = redteam_choice == 1
                    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
                    if wants_redteam and not is_root:
                        self.ui.print_status(self.ui.t("redteam_requires_root"), "WARNING")
                        wants_redteam = False

                    self.config["net_discovery_redteam"] = bool(wants_redteam)
                    self.config["net_discovery_active_l2"] = False
                    self.config["net_discovery_kerberos_userenum"] = False
                    self.config["net_discovery_kerberos_realm"] = None
                    self.config["net_discovery_kerberos_userlist"] = None

                    if self.config["net_discovery_redteam"]:
                        # L2 Active probing
                        persisted_l2 = defaults_for_run.get("net_discovery_active_l2")
                        self.config["net_discovery_active_l2"] = self.ask_yes_no(
                            self.ui.t("redteam_active_l2_q"),
                            default="yes" if persisted_l2 else "no",
                        )

                        # Kerberos enumeration
                        persisted_krb = defaults_for_run.get("net_discovery_kerberos_userenum")
                        enable_kerberos = self.ask_yes_no(
                            self.ui.t("redteam_kerberos_userenum_q"),
                            default="yes" if persisted_krb else "no",
                        )
                        self.config["net_discovery_kerberos_userenum"] = enable_kerberos

                        if enable_kerberos:
                            persisted_realm = (
                                defaults_for_run.get("net_discovery_kerberos_realm") or ""
                            )
                            realm = input(
                                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('kerberos_realm_q')} "
                                f"[{persisted_realm}]: "
                            ).strip()
                            self.config["net_discovery_kerberos_realm"] = (
                                realm or persisted_realm or None
                            )

                            persisted_userlist = (
                                defaults_for_run.get("net_discovery_kerberos_userlist") or ""
                            )
                            userlist = input(
                                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('kerberos_userlist_q')} "
                                f"[{persisted_userlist}]: "
                            ).strip()
                            self.config["net_discovery_kerberos_userlist"] = (
                                expand_user_path(userlist)
                                if userlist
                                else (
                                    expand_user_path(persisted_userlist)
                                    if persisted_userlist
                                    else None
                                )
                            )

                        # Advanced Net Discovery options
                        nd_settings = self.ask_net_discovery_options()
                        self.config["net_discovery_snmp_community"] = nd_settings.get(
                            "snmp_community", "public"
                        )
                        self.config["net_discovery_dns_zone"] = nd_settings.get("dns_zone", "")
                        self.config["net_discovery_max_targets"] = nd_settings.get(
                            "redteam_max_targets", 50
                        )

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 8: Windows Verification & Webhook
            # ═══════════════════════════════════════════════════════════════════
            elif step == 8:
                win_options = [
                    self.ui.t("yes_option") + " — SMB/RDP/LDAP/SSH/HTTP",
                    self.ui.t("no_option"),
                ]
                default_idx = 0 if defaults_for_run.get("windows_verify_enabled") else 1
                default_idx = wizard_state.get("win_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.ui.t("windows_verify_q"),
                    win_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["win_idx"] = choice
                if choice == 0:
                    self.config["windows_verify_enabled"] = True
                    persisted_max = defaults_for_run.get("windows_verify_max_targets")
                    max_default = (
                        persisted_max
                        if isinstance(persisted_max, int) and 1 <= persisted_max <= 200
                        else 20
                    )
                    self.config["windows_verify_max_targets"] = self.ask_number(
                        self.ui.t("windows_verify_max_q"),
                        default=max_default,
                        min_val=1,
                        max_val=200,
                    )
                else:
                    self.config["windows_verify_enabled"] = False

                # Webhook configuration
                webhook_url = self.ask_webhook_url()
                if webhook_url:
                    self.config["webhook_url"] = webhook_url

                step += 1
                continue

        # Final step: Encryption setup
        self.setup_encryption()

    def _show_defaults_summary(self, persisted_defaults: Dict) -> None:
        """Display summary of persisted defaults."""
        # v3.2.3: Display ALL saved defaults
        self.ui.print_status(self.ui.t("defaults_summary_title"), "INFO")

        def fmt_targets(val):
            if not isinstance(val, list) or not val:
                return "-"
            cleaned = [t.strip() for t in val if isinstance(t, str) and t.strip()]
            return ", ".join(cleaned) if cleaned else "-"

        # Helper to format boolean values
        def fmt_bool(val):
            if val is None:
                return "-"
            return self.ui.t("enabled") if val else self.ui.t("disabled")

        # Display all saved defaults
        fields = [
            ("defaults_summary_targets", fmt_targets(persisted_defaults.get("target_networks"))),
            ("defaults_summary_scan_mode", persisted_defaults.get("scan_mode")),
            ("defaults_summary_threads", persisted_defaults.get("threads")),
            ("defaults_summary_output", persisted_defaults.get("output_dir")),
            ("defaults_summary_rate_limit", persisted_defaults.get("rate_limit")),
            ("defaults_summary_udp_mode", persisted_defaults.get("udp_mode")),
            ("defaults_summary_udp_ports", persisted_defaults.get("udp_top_ports")),
            (
                "defaults_summary_topology",
                fmt_bool(persisted_defaults.get("topology_enabled")),
            ),
            (
                "defaults_summary_net_discovery",
                fmt_bool(persisted_defaults.get("net_discovery_enabled")),
            ),
            (
                "defaults_summary_redteam",
                fmt_bool(persisted_defaults.get("net_discovery_redteam")),
            ),
            (
                "defaults_summary_active_l2",
                fmt_bool(persisted_defaults.get("net_discovery_active_l2")),
            ),
            (
                "defaults_summary_kerbrute",
                fmt_bool(persisted_defaults.get("net_discovery_kerberos_userenum")),
            ),
            (
                "defaults_summary_web_vulns",
                fmt_bool(persisted_defaults.get("scan_vulnerabilities")),
            ),
            (
                "defaults_summary_nuclei",
                fmt_bool(persisted_defaults.get("nuclei_enabled")),
            ),
            (
                "defaults_summary_cve_lookup",
                fmt_bool(persisted_defaults.get("cve_lookup_enabled")),
            ),
            (
                "defaults_summary_txt_report",
                fmt_bool(persisted_defaults.get("generate_txt")),
            ),
            (
                "defaults_summary_html_report",
                fmt_bool(persisted_defaults.get("generate_html")),
            ),
            (
                "defaults_summary_windows_verify",
                fmt_bool(persisted_defaults.get("windows_verify_enabled")),
            ),
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.ui.print_status(f"- {self.ui.t(key)}: {display_val}", "INFO")

    # ---------- Progress Callbacks (v3.9.0 Refactor for Testability) ----------

    def _nd_progress_callback(
        self,
        label: str,
        step_index: int,
        step_total: int,
        progress: Any,
        task: Any,
        start_time: float,
    ) -> None:
        """Callback for Net Discovery progress updates."""
        try:
            pct = int((step_index / step_total) * 100) if step_total else 0
            if step_total and step_index >= step_total:
                pct = min(pct, 99)
            # v3.8.1: Truncate label to 35 chars for clean display
            lbl_s = label[:35] + "…" if len(label) > 35 else label
            progress.update(
                task,
                completed=pct,
                description=f"{lbl_s}",
            )
            # v3.8.1: Heartbeat every 30s for long phases
            now = time.time()
            if not hasattr(self, "_nd_last_heartbeat"):
                self._nd_last_heartbeat = start_time

            if now - self._nd_last_heartbeat >= 30.0:
                elapsed = int(now - start_time)
                mins, secs = divmod(elapsed, 60)
                msg = f"Net Discovery en progreso... ({mins}:{secs:02d} elapsed)"
                self.ui.print_status(msg, "INFO", force=True)
                self._nd_last_heartbeat = now
        except Exception:
            pass

    def _nuclei_progress_callback(
        self,
        completed: int,
        total: int,
        eta: str,
        progress: Any,
        task: Any,
        start_time: float,
        timeout: int,
    ) -> None:
        """Callback for Nuclei scan progress updates."""
        try:
            rem = max(0, total - completed)
            ela_s = max(0.001, time.time() - start_time)
            rate = completed / ela_s if completed else 0.0
            eta_est_v = self._format_eta(rem / rate) if rate > 0.0 and rem else ""
            progress.update(
                task,
                completed=completed,
                description=f"[cyan]Nuclei ({completed}/{total})",
                eta_upper=self._format_eta(rem * timeout if rem else 0),
                eta_est=f"ETA≈ {eta_est_v}" if eta_est_v else "",
                detail=f"batch {completed}/{total}",
            )
        except Exception:
            pass
