#!/usr/bin/env python3
"""
RedAudit - Main Auditor Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Main orchestrator class for network auditing operations.
"""

import ipaddress
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from redaudit.utils.constants import (
    COLORS,
    DEFAULT_IDENTITY_THRESHOLD,
    DEFAULT_LANG,
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
    normalize_nuclei_exclude,
    run_nuclei_scan,
    select_nuclei_targets,
)
from redaudit.core.scope_expansion import (
    build_leak_follow_targets,
    evaluate_leak_follow_candidates,
    extract_leak_follow_candidates,
)
from redaudit.core.iot_scope_probes import (
    IOT_PROBE_PACKS,
    normalize_iot_probe_packs,
    run_iot_scope_probes,
)
from redaudit.core.network import detect_all_networks
from redaudit.core.crypto import is_crypto_available
from redaudit.core.reporter import (
    generate_summary,
    save_results,
    show_config_summary,
    show_results_summary,
)
from redaudit.core.nvd import enrich_host_with_cves, get_api_key_from_config
from redaudit.core.config_context import ConfigurationContext
from redaudit.core.network_scanner import NetworkScanner
from redaudit.core.scan_wizard_flow import ScanWizardFlow
from redaudit.core.wizard import Wizard as WizardCompat


def _sync_scan_wizard_flow_compat() -> None:
    """Keep moved flow helpers patch-compatible with legacy auditor import paths."""
    import redaudit.core.scan_wizard_flow as scan_wizard_flow

    scan_wizard_flow.expand_user_path = expand_user_path
    scan_wizard_flow.get_default_reports_base_dir = get_default_reports_base_dir
    scan_wizard_flow.is_nuclei_available = is_nuclei_available
    scan_wizard_flow.normalize_nuclei_exclude = normalize_nuclei_exclude


class InteractiveNetworkAuditor:
    """Main orchestrator for RedAudit scans."""

    WIZARD_BACK = WizardCompat.WIZARD_BACK

    def __getattr__(self, name: str):
        runtime = self.__dict__.get("_runtime")
        if runtime is not None and hasattr(runtime, name):
            return getattr(runtime, name)
        scan_wizard_flow = self.__dict__.get("scan_wizard_flow")
        if scan_wizard_flow is not None and hasattr(type(scan_wizard_flow), name):
            return getattr(scan_wizard_flow, name)
        if hasattr(WizardCompat, name):
            attr = getattr(WizardCompat, name)
            if callable(attr):
                return attr.__get__(self, type(self))
            return attr
        raise AttributeError(f"{self.__class__.__name__} has no attribute {name}")

    @property
    def lang(self) -> str:
        return self._lang

    @lang.setter
    def lang(self, value: str) -> None:
        normalized = value if value in TRANSLATIONS else "en"
        self._lang = normalized
        if hasattr(self, "_ui_manager"):
            self._ui_manager.lang = normalized

    def __init__(self):
        self._lang = DEFAULT_LANG if DEFAULT_LANG in TRANSLATIONS else "en"
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
        self._proxy_manager = None

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
        self.wizard_service = WizardCompat(self)
        self.scan_wizard_flow = ScanWizardFlow(self)
        self._runtime = AuditorRuntime(self)
        self._setup_logging()

        # v4.0: Direct Composition - UIManager
        from redaudit.core.ui_manager import UIManager

        self._ui_manager = UIManager(
            lang=self.lang,
            colors=self.COLORS,
            logger=self.logger,
            progress_active_callback=lambda: self._ui_progress_active,
        )
        self.scanner = NetworkScanner(
            self.cfg,
            self._ui_manager,
            self.logger,
            proxy_manager=self._proxy_manager,
        )

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

    @property
    def proxy_manager(self):
        return self._proxy_manager

    @proxy_manager.setter
    def proxy_manager(self, value):
        self._proxy_manager = value
        scanner = getattr(self, "scanner", None)
        if scanner is not None:
            scanner.proxy_manager = value

    # ---------- Reporting ----------

    def show_config_summary(self):
        """Display configuration summary."""
        show_config_summary(self.config, self.ui.t, self.ui.colors)

    def _show_target_summary(self) -> None:
        targets = self.config.get("target_networks") or []
        if not isinstance(targets, list) or not targets:
            return
        summaries = []
        total_hosts = 0
        for token in targets:
            token_str = str(token).strip()
            if not token_str:
                continue
            try:
                net = ipaddress.ip_network(token_str, strict=False)
                count = int(net.num_addresses)
                total_hosts += count
                summaries.append(f"{token_str} (~{count})")
            except ValueError:
                summaries.append(token_str)
        if summaries:
            self.ui.print_status(
                self.ui.t("targets_normalized", ", ".join(summaries)),
                "INFO",
            )
            if total_hosts:
                self.ui.print_status(self.ui.t("targets_total", total_hosts), "INFO")

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

    # ---------- Interactive flow (wizard services via composition) ----------

    def _wizard_call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        override = self.__dict__.get(method_name)
        if callable(override):
            return override(*args, **kwargs)

        # Keep helper methods bound to the auditor so internal calls (ask_yes_no, etc.)
        # honor auditor-level overrides used throughout tests and runtime hooks.
        if method_name in {"ask_webhook_url", "ask_net_discovery_options", "ask_auth_config"}:
            method = getattr(WizardCompat, method_name)
            return method(self, *args, **kwargs)

        method = getattr(self.wizard_service, method_name)
        return method(*args, **kwargs)

    def _scan_wizard_flow_call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        _sync_scan_wizard_flow_compat()
        method = getattr(ScanWizardFlow, method_name)
        return method(self, *args, **kwargs)

    def clear_screen(self) -> None:
        self._wizard_call("clear_screen")

    def print_banner(self) -> None:
        self._wizard_call("print_banner")

    def show_main_menu(self) -> int:
        return self._wizard_call("show_main_menu")

    def ask_yes_no(self, question: str, default: str = "yes") -> bool:
        return self._wizard_call("ask_yes_no", question, default=default)

    def ask_yes_no_with_timeout(
        self,
        question: str,
        default: str = "yes",
        timeout: Optional[int] = 15,
        timeout_s: Optional[int] = None,
    ) -> bool:
        resolved_timeout = timeout_s if timeout_s is not None else timeout
        try:
            resolved_timeout_int = int(resolved_timeout) if resolved_timeout is not None else 15
        except Exception:
            resolved_timeout_int = 15
        return self._wizard_call(
            "ask_yes_no_with_timeout",
            question,
            default=default,
            timeout_s=resolved_timeout_int,
        )

    def ask_number(
        self,
        question: str,
        default: int = 10,
        min_val: int = 1,
        max_val: int = 1000,
    ) -> int:
        return self._wizard_call(
            "ask_number",
            question,
            default=default,
            min_val=min_val,
            max_val=max_val,
        )

    def ask_choice(self, question: str, options: List[str], default: int = 0) -> int:
        return self._wizard_call("ask_choice", question, options, default=default)

    def ask_choice_with_back(
        self,
        question: str,
        options: List[str],
        default: int = 0,
        *,
        step_num: int = 0,
        total_steps: int = 0,
    ) -> int:
        return self._wizard_call(
            "ask_choice_with_back",
            question,
            options,
            default=default,
            step_num=step_num,
            total_steps=total_steps,
        )

    def ask_manual_network(self) -> list[str]:
        return self._wizard_call("ask_manual_network")

    def ask_webhook_url(self) -> str:
        return self._wizard_call("ask_webhook_url")

    def ask_net_discovery_options(self) -> dict:
        return self._wizard_call("ask_net_discovery_options")

    def ask_auth_config(self, skip_intro: bool = False) -> dict:
        return self._wizard_call("ask_auth_config", skip_intro=skip_intro)

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
            "leak_follow_mode",
            "leak_follow_policy_pack",
            "leak_follow_allowlist",
            "leak_follow_allowlist_profiles",
            "leak_follow_denylist",
            "iot_probes_mode",
            "iot_probe_packs",
            "iot_probe_budget_seconds",
            "iot_probe_timeout_seconds",
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

        self._show_target_summary()
        self.show_config_summary()

        if self.config.get("nuclei_enabled"):
            self.ui.print_status(self.ui.t("long_scan_warning"), "WARNING")

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
                    nuclei_max_runtime=self.config.get("nuclei_max_runtime"),
                    leak_follow_mode=self.config.get("leak_follow_mode"),
                    leak_follow_policy_pack=self.config.get("leak_follow_policy_pack"),
                    leak_follow_allowlist=self.config.get("leak_follow_allowlist"),
                    leak_follow_allowlist_profiles=self.config.get(
                        "leak_follow_allowlist_profiles"
                    ),
                    leak_follow_denylist=self.config.get("leak_follow_denylist"),
                    iot_probes_mode=self.config.get("iot_probes_mode"),
                    iot_probe_packs=self.config.get("iot_probe_packs"),
                    iot_probe_budget_seconds=self.config.get("iot_probe_budget_seconds"),
                    iot_probe_timeout_seconds=self.config.get("iot_probe_timeout_seconds"),
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

    def _collect_auditor_ip_reasons(self) -> Dict[str, Set[str]]:
        """
        Collect auditor IPs with reasons without mutating host lists.
        Uses self.results['network_info'] as the source of truth.
        """
        network_info = self.results.get("network_info") or []
        auditor_ip_reasons: Dict[str, Set[str]] = {}

        def _add_reason(ip: str, reason: str) -> None:
            if not ip:
                return
            reasons = auditor_ip_reasons.setdefault(ip, set())
            reasons.add(reason)

        for entry in network_info:
            ip = entry.get("ip")
            iface = entry.get("interface")
            reason = f"network_info:{iface}" if iface else "network_info"
            _add_reason(ip, reason)

        topology = self.results.get("topology") or {}
        for route in topology.get("routes", []) or []:
            src_ip = route.get("src")
            if src_ip:
                dev = route.get("dev")
                reason = f"topology.route_src:{dev}" if dev else "topology.route_src"
                _add_reason(src_ip, reason)
        for iface in topology.get("interfaces", []) or []:
            iface_ip = iface.get("ip")
            if iface_ip:
                iface_name = iface.get("interface")
                reason = (
                    f"topology.interface_ip:{iface_name}" if iface_name else "topology.interface_ip"
                )
                _add_reason(iface_ip, reason)

        if not auditor_ip_reasons:
            try:
                fallback_nets = detect_all_networks(self.lang)
                for entry in fallback_nets:
                    ip = entry.get("ip")
                    iface = entry.get("interface")
                    reason = f"fallback.network_info:{iface}" if iface else "fallback.network_info"
                    _add_reason(ip, reason)
            except Exception:
                pass

        if not auditor_ip_reasons:
            try:
                hostname = socket.gethostname()
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    if ip and not ip.startswith("127."):
                        _add_reason(ip, "fallback.hostname")
            except Exception:
                pass

        if not auditor_ip_reasons:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect(("192.0.2.1", 80))
                ip = sock.getsockname()[0]
                if ip and not ip.startswith("127."):
                    _add_reason(ip, "fallback.udp_route")
            except Exception:
                pass
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

        return auditor_ip_reasons

    def _filter_auditor_ips(self, hosts: list) -> list:
        """
        Filter out auditor's own IPs from the host list.
        Uses self.results['network_info'] as the source of truth.
        """
        auditor_ip_reasons = self._collect_auditor_ip_reasons()
        auditor_ips = set(auditor_ip_reasons)
        if not auditor_ips:  # pragma: no cover
            self.results["auditor_exclusions"] = {"count": 0, "items": []}
            return hosts  # pragma: no cover

        filtered_hosts = [h for h in hosts if h not in auditor_ips]
        excluded_hosts = [h for h in hosts if h in auditor_ips]
        excluded_count = len(excluded_hosts)

        items = []
        if excluded_hosts:
            for ip in sorted(set(excluded_hosts)):
                reasons = sorted(auditor_ip_reasons.get(ip, set()))
                items.append({"ip": ip, "reasons": reasons})
        self.results["auditor_exclusions"] = {"count": excluded_count, "items": items}

        if excluded_count > 0:
            self.ui.print_status(
                self.ui.t("auditor_ip_excluded", excluded_count),
                "INFO",
            )
            if hasattr(self, "logger") and self.logger:
                self.logger.info(f"Excluded {excluded_count} self-IPs: {auditor_ips}")

        return filtered_hosts

    def run_complete_scan(self):
        """Execute the complete scan workflow."""
        self.scan_start_time = datetime.now()
        self.start_heartbeat()
        self._deep_executed_count = 0
        session_log_closed = False

        inhibitor = None
        if self.config.get("prevent_sleep", True):
            try:
                from redaudit.core.power import SleepInhibitor

                inhibitor = SleepInhibitor(logger=self.logger)
                inhibitor.start()
            except Exception:  # pragma: no cover
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

            if self.proxy_manager:
                proxy_cfg = getattr(self.proxy_manager, "proxy_config", None)
                proxy_label = "proxychains"
                if isinstance(proxy_cfg, dict):
                    host = proxy_cfg.get("host")
                    port = proxy_cfg.get("port")
                    if host and port:
                        proxy_label = f"{host}:{port}"
                self.ui.print_status(self.ui.t("proxy_in_use", proxy_label), "INFO")

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
                    except ImportError:  # pragma: no cover
                        self.results["topology"] = discover_topology(
                            target_networks=self.config.get("target_networks", []),
                            network_info=self.results.get("network_info", []),
                            extra_tools=self.extra_tools,
                            logger=self.logger,
                        )
                except Exception as exc:  # pragma: no cover
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
                    from redaudit.core.net_discovery import (
                        detect_default_route_interface,
                        discover_networks,
                    )

                    self.current_phase = "net_discovery"
                    self.ui.print_status(self.ui.t("net_discovery_start"), "INFO")

                    iface = self._select_net_discovery_interface()
                    scan_mode = str(self.config.get("scan_mode") or "").strip().lower()
                    full_dhcp = scan_mode in ("completo", "full", "exhaustive")
                    dhcp_timeout_s = 6 if full_dhcp else 10
                    dhcp_interfaces = None
                    if full_dhcp:
                        network_info = self.results.get("network_info", []) or []
                        iface_set = {
                            entry.get("interface")
                            for entry in network_info
                            if entry.get("interface") and entry.get("ip_version") == 4
                        }
                        if iface:
                            iface_set.add(iface)
                        dhcp_interfaces = sorted(i for i in iface_set if i)
                        if not dhcp_interfaces:
                            dhcp_interfaces = None
                    else:
                        default_iface = detect_default_route_interface(logger=self.logger)
                        if default_iface:  # pragma: no cover
                            dhcp_interfaces = [default_iface]
                    redteam_options = {
                        "max_targets": self.config.get("net_discovery_max_targets", 50),
                        "snmp_community": self.config.get("net_discovery_snmp_community", "public"),
                        "dns_zone": self.config.get("net_discovery_dns_zone"),
                        "kerberos_realm": self.config.get("net_discovery_kerberos_realm"),
                        "kerberos_userlist": self.config.get("net_discovery_kerberos_userlist"),
                        "active_l2": bool(self.config.get("net_discovery_active_l2", False)),
                        "use_masscan": self.config.get("net_discovery_masscan", True),
                    }
                    redteam_enabled = bool(self.config.get("net_discovery_redteam", False))
                    exclude_ips = None
                    if redteam_enabled:  # pragma: no cover
                        exclude_ips = set(self._collect_auditor_ip_reasons())

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

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    dhcp_interfaces=dhcp_interfaces,
                                    dhcp_timeout_s=dhcp_timeout_s,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=redteam_enabled,
                                    redteam_options=redteam_options,
                                    exclude_ips=exclude_ips,
                                    extra_tools=self.extra_tools,
                                    progress_callback=lambda lbl, s, t: self._nd_progress_callback(
                                        lbl, s, t, progress, task, nd_start_time
                                    ),
                                    logger=self.logger,
                                )
                                progress.update(task, completed=100, description="complete")
                    except ImportError:  # pragma: no cover
                        # Fallback without progress bar
                        with self._progress_ui():
                            with _ActivityIndicator(
                                label="Net Discovery",
                                touch_activity=self._touch_activity,
                            ) as indicator:

                                self.results["net_discovery"] = discover_networks(
                                    target_networks=self.config.get("target_networks", []),
                                    interface=iface,
                                    dhcp_interfaces=dhcp_interfaces,
                                    dhcp_timeout_s=dhcp_timeout_s,
                                    protocols=self.config.get("net_discovery_protocols"),
                                    redteam=redteam_enabled,
                                    redteam_options=redteam_options,
                                    exclude_ips=exclude_ips,
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
                            f"✔ HyperScan: {len(arp_hosts)} ARP, {len(upnp_devices)} IoT/UPNP, {len(tcp_hosts)} TCP hosts ({hyperscan_dur:.1f}s)",
                            "OKGREEN",
                        )
                    backdoors = self.results["net_discovery"].get("potential_backdoors", [])
                    if backdoors:
                        self.ui.print_status(
                            f"⚠  {len(backdoors)} puertos sospechosos (backdoor) detectados",
                            "WARNING",
                        )

                    # v4.6.32: L2 Warnings moved here for UI safety
                    l2_note = self.results["net_discovery"].get("l2_warning_note")
                    if l2_note:
                        self.ui.print_status(f"⚠  {l2_note}", "WARNING")
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

            # v4.2 Fix: Aggressive deduplication of all_hosts to prevent "ghost" duplicates
            # caused by invisible ANSI codes or whitespace from discovery tools
            import re

            ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            unique_map = {}
            cleaned_hosts = []

            for h in all_hosts:
                raw = str(h)
                clean = ansi_escape.sub("", raw).strip()
                if clean and clean not in unique_map:
                    unique_map[clean] = True
                    cleaned_hosts.append(clean)  # Use the clean version

            if len(cleaned_hosts) < len(all_hosts):
                diff = len(all_hosts) - len(cleaned_hosts)
                if self.logger:
                    self.logger.debug(f"Deduplicated {diff} ghost hosts from discovery list.")

            all_hosts = cleaned_hosts

            # v4.3: Auto-exclude Auditor IP
            all_hosts = self._filter_auditor_ips(all_hosts)

            max_val = self.config["max_hosts_value"]
            if max_val != "all" and isinstance(max_val, int):
                all_hosts = all_hosts[:max_val]

            # v4.0: Pass Host objects to scanning engine
            host_targets = [self.scanner.get_or_create_host(ip) for ip in all_hosts]

            # v4.9.2: Inject discovered IoT/UDP ports into Host objects
            udp_ports_map = self.results.get("net_discovery", {}).get("hyperscan_udp_ports", {})
            if udp_ports_map:
                for h in host_targets:
                    if h.ip in udp_ports_map:
                        # Append distinctive UDP ports
                        discovered_udp = set(udp_ports_map[h.ip])
                        current_udp = set(h.udp_ports if hasattr(h, "udp_ports") else [])
                        # Also check mixed ports list if legacy
                        current_mixed = set(h.ports)

                        new_ports = discovered_udp - current_udp - current_mixed
                        if new_ports:
                            # v4.11.0: Create Service objects for discovered UDP IoT ports
                            from redaudit.core.models import Service

                            # Get protocol name from upnp_devices if available
                            protocol_name = "iot"
                            upnp_devices = self.results.get("net_discovery", {}).get(
                                "upnp_devices", []
                            )
                            for device in upnp_devices:
                                if device.get("ip") == h.ip:
                                    proto = (
                                        device.get("device", "").replace("IoT (", "").rstrip(")")
                                    )
                                    if proto and proto != "unknown":
                                        protocol_name = f"iot-{proto.lower()}"
                                    break

                            for udp_port in new_ports:
                                svc = Service(
                                    port=udp_port,
                                    protocol="udp",
                                    name=protocol_name,
                                    state="open",
                                )
                                h.services.append(svc)

                            # Tag as IoT
                            if "iot" not in h.tags:
                                h.tags.add("iot")

            # v4.1: Run HyperScan-First sequentially BEFORE parallel nmap
            # This avoids file descriptor exhaustion by running one at a time
            if not self.interrupted:
                hyperscan_ports = self._run_hyperscan_discovery(all_hosts)
                if hyperscan_ports:
                    net_discovery = self.results.get("net_discovery")
                    if not isinstance(net_discovery, dict):
                        net_discovery = {}
                        self.results["net_discovery"] = net_discovery
                    net_discovery["hyperscan_first_tcp_hosts"] = hyperscan_ports

            results = self.scan_hosts_concurrent(host_targets)

            # v4.2: Decoupled Deep Scan Phase
            # We filter hosts that requested deep scan but haven't executed it yet.
            if not self.interrupted:
                deep_targets = [
                    h
                    for h in results
                    if hasattr(h, "smart_scan")
                    and h.smart_scan.get("trigger_deep")
                    and not h.smart_scan.get("deep_scan_executed")
                ]
                if deep_targets:
                    self.run_deep_scans_concurrent(deep_targets)

            # v3.8: Agentless Windows verification (SMB/RDP/LDAP) - opt-in
            if not self.interrupted:
                self.run_agentless_verification(results)

            # v4.1: CVE Lookup moved to AFTER Vuln Scan + Nuclei for complete version data

            # (see below, after Nuclei block)

            if self.config.get("scan_vulnerabilities") and not self.interrupted:
                self.scan_vulnerabilities_concurrent(results)

            # v5.x: Scope Expansion - protocol-specific IoT probes with strict guardrails.
            if not self.interrupted:
                iot_mode = self.config.get("iot_probes_mode", "off")
                scope_runtime = self.results.setdefault("scope_expansion_runtime", {})
                if isinstance(scope_runtime, dict):
                    try:
                        identity_threshold = self.config.get(
                            "identity_threshold", DEFAULT_IDENTITY_THRESHOLD
                        )
                        try:
                            identity_threshold = int(identity_threshold)
                        except Exception:
                            identity_threshold = DEFAULT_IDENTITY_THRESHOLD
                        if (
                            self.config.get("scan_mode") in ("completo", "full")
                            and identity_threshold < 4
                        ):
                            identity_threshold = 4

                        iot_runtime = run_iot_scope_probes(
                            results,
                            mode=iot_mode,
                            packs=self.config.get("iot_probe_packs")
                            or list(IOT_PROBE_PACKS.keys()),
                            budget_seconds=self.config.get("iot_probe_budget_seconds", 20),
                            timeout_seconds=self.config.get("iot_probe_timeout_seconds", 3),
                            identity_threshold=identity_threshold,
                        )
                    except Exception as iot_err:
                        if self.logger:
                            self.logger.warning(
                                "IoT scope probes failed: %s", iot_err, exc_info=True
                            )
                        iot_runtime = {
                            "mode": iot_mode if iot_mode in ("off", "safe") else "off",
                            "packs": normalize_iot_probe_packs(self.config.get("iot_probe_packs"))
                            or list(IOT_PROBE_PACKS.keys()),
                            "budget_seconds": self.config.get("iot_probe_budget_seconds", 20),
                            "timeout_seconds": self.config.get("iot_probe_timeout_seconds", 3),
                            "candidates": 0,
                            "executed_hosts": 0,
                            "probes_total": 0,
                            "probes_executed": 0,
                            "probes_responded": 0,
                            "budget_exceeded_hosts": 0,
                            "reasons": {"runtime_error": 1},
                            "hosts": [],
                            "evidence": [],
                        }
                    scope_runtime["iot_probes"] = iot_runtime
                    if iot_mode != "off":
                        self.ui.print_status(
                            self.ui.t(
                                "scope_iot_runtime",
                                int(iot_runtime.get("candidates", 0)),
                                int(iot_runtime.get("probes_executed", 0)),
                                int(iot_runtime.get("probes_responded", 0)),
                            ),
                            "INFO",
                        )

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
                    identity_threshold = self.config.get(
                        "identity_threshold", DEFAULT_IDENTITY_THRESHOLD
                    )
                    try:
                        identity_threshold = int(identity_threshold)
                    except Exception:  # pragma: no cover
                        identity_threshold = DEFAULT_IDENTITY_THRESHOLD
                    if (
                        self.config.get("scan_mode") in ("completo", "full")
                        and identity_threshold < 4
                    ):
                        identity_threshold = 4

                    nuclei_full_coverage = bool(self.config.get("nuclei_full_coverage", False))
                    priority_ports = None if nuclei_full_coverage else {80, 443, 8080, 8443}
                    max_targets_per_host = None if nuclei_full_coverage else 2

                    selection = select_nuclei_targets(
                        results,
                        identity_threshold=identity_threshold,
                        priority_ports=priority_ports,
                        max_targets_per_host=max_targets_per_host,
                        exclude_patterns=self.config.get("nuclei_exclude"),
                    )
                    nuclei_targets = selection.get("targets") or []
                    selected_targets_before_leak = len(nuclei_targets)
                    leak_follow_mode = self.config.get("leak_follow_mode", "off")
                    leak_follow_runtime = evaluate_leak_follow_candidates(
                        extract_leak_follow_candidates(self.results),
                        mode=leak_follow_mode,
                        target_networks=self.config.get("target_networks")
                        or self.config.get("targets")
                        or [],
                        allowlist=self.config.get("leak_follow_allowlist") or [],
                        policy_pack=self.config.get("leak_follow_policy_pack", "safe-default"),
                        allowlist_profiles=self.config.get("leak_follow_allowlist_profiles") or [],
                        denylist=self.config.get("leak_follow_denylist") or [],
                    )
                    leak_follow_targets = build_leak_follow_targets(
                        leak_follow_runtime.get("decisions") or [],
                        existing_targets=nuclei_targets,
                        max_targets=8,
                    )
                    if leak_follow_targets:
                        exclude_patterns = normalize_nuclei_exclude(
                            self.config.get("nuclei_exclude")
                        )
                        if exclude_patterns:
                            leak_follow_targets = [
                                t
                                for t in leak_follow_targets
                                if not any(pat in t for pat in exclude_patterns)
                            ]
                    if leak_follow_targets:
                        nuclei_targets = list(nuclei_targets) + leak_follow_targets
                        self.ui.print_status(
                            self.ui.t("scope_leak_targets_added", len(leak_follow_targets)),
                            "INFO",
                        )
                    leak_follow_runtime["followed"] = len(leak_follow_targets)
                    leak_follow_runtime["follow_targets"] = list(leak_follow_targets)
                    leak_follow_runtime["skipped"] = max(
                        0,
                        int(leak_follow_runtime.get("detected", 0))
                        - int(leak_follow_runtime.get("eligible", 0)),
                    )
                    scope_runtime = self.results.setdefault("scope_expansion_runtime", {})
                    if isinstance(scope_runtime, dict):
                        scope_runtime["leak_follow"] = leak_follow_runtime
                    if nuclei_targets:
                        output_dir = (
                            self.config.get("_actual_output_dir")
                            or self.config.get("output_dir")
                            or get_default_reports_base_dir()
                        )

                        # v4.15: Auto-detect multi-port hosts and switch to 'fast' profile
                        # Hosts with 3+ HTTP ports cause timeout issues with full template set
                        selected_profile = self.config.get("nuclei_profile", "balanced")
                        nuclei_profile = selected_profile
                        selected_by_host = selection.get("selected_by_host") or {}
                        host_port_count: Dict[str, int] = {}
                        for host, urls in selected_by_host.items():
                            try:
                                host_port_count[str(host)] = len(urls)
                            except Exception:  # pragma: no cover
                                host_port_count[str(host)] = 0

                        multi_port_hosts = [h for h, c in host_port_count.items() if c >= 3]
                        auto_switched = False
                        if (
                            multi_port_hosts
                            and nuclei_profile != "fast"
                            and not nuclei_full_coverage
                        ):
                            nuclei_profile = "fast"
                            auto_switched = True
                            if self.logger:
                                self.logger.info(
                                    "Auto-switching to 'fast' Nuclei profile: %d hosts with 3+ HTTP ports",
                                    len(multi_port_hosts),
                                )
                            self.ui.print_status(
                                f"Nuclei: auto-fast mode ({len(multi_port_hosts)} multi-port hosts)",
                                "INFO",
                            )
                        elif multi_port_hosts and nuclei_full_coverage:
                            if self.logger:
                                self.logger.info(
                                    "Auto-fast Nuclei profile skipped (full coverage enabled)"
                                )

                        try:
                            base_targets_total = int(
                                selection.get("targets_total") or selected_targets_before_leak
                            )
                        except (TypeError, ValueError):
                            base_targets_total = selected_targets_before_leak
                        targets_pre_optimization = max(
                            base_targets_total + len(leak_follow_targets),
                            len(nuclei_targets),
                        )
                        targets_total = len(nuclei_targets)
                        targets_exception = int(selection.get("targets_exception") or 0)
                        targets_optimized = int(selection.get("targets_optimized") or 0)
                        targets_excluded = int(selection.get("targets_excluded") or 0)
                        if targets_pre_optimization > targets_total:
                            if self.logger:
                                self.logger.info(
                                    "Nuclei targets optimized: %d -> %d (exceptions %d)",
                                    targets_pre_optimization,
                                    targets_total,
                                    targets_exception,
                                )
                            self.ui.print_status(
                                self.ui.t(
                                    "nuclei_targets_optimized",
                                    targets_total,
                                    targets_pre_optimization,
                                    targets_exception,
                                ),
                                "INFO",
                            )
                        if targets_excluded > 0:  # pragma: no cover
                            self.ui.print_status(
                                self.ui.t("nuclei_targets_excluded", targets_excluded),
                                "INFO",
                            )

                        # Prefer a single Progress instance managed by the auditor to avoid
                        # competing Rich Live displays (which can cause flicker/no output).
                        nuclei_result = None
                        nuclei_severity = "low,medium,high,critical"
                        nuclei_timeout_s = self.config.get("nuclei_timeout", 300)
                        nuclei_request_timeout_s = 10
                        nuclei_retries = 1
                        nuclei_max_runtime_minutes = self.config.get("nuclei_max_runtime", 0)
                        exception_targets = selection.get("exception_targets") or set()
                        nuclei_fatigue_limit = self.config.get("nuclei_fatigue_limit", 3)
                        try:
                            nuclei_fatigue_limit = int(nuclei_fatigue_limit)
                        except Exception:  # pragma: no cover
                            nuclei_fatigue_limit = 3
                        if nuclei_fatigue_limit < 0:  # pragma: no cover
                            nuclei_fatigue_limit = 0
                        try:
                            nuclei_max_runtime_minutes = int(nuclei_max_runtime_minutes)
                        except Exception:  # pragma: no cover
                            nuclei_max_runtime_minutes = 0
                        if nuclei_max_runtime_minutes < 0:  # pragma: no cover
                            nuclei_max_runtime_minutes = 0
                        nuclei_max_runtime_s = (
                            nuclei_max_runtime_minutes * 60 if nuclei_max_runtime_minutes else None
                        )
                        # v4.6.34: Smaller batches for faster parallel completion
                        batch_size = 10
                        try:
                            from rich.progress import Progress

                            total_targets = len(nuclei_targets)
                            try:
                                nuclei_timeout_s = int(nuclei_timeout_s)
                            except Exception:
                                nuclei_timeout_s = 300
                            if nuclei_timeout_s < 60:
                                nuclei_timeout_s = 300
                            if nuclei_full_coverage and nuclei_timeout_s < 900:
                                nuclei_timeout_s = 900
                                if self.logger:
                                    self.logger.info(
                                        "Nuclei timeout raised to %ss for full coverage (%d targets)",
                                        nuclei_timeout_s,
                                        total_targets,
                                    )
                            total_batches = max(1, int(math.ceil(total_targets / batch_size)))
                            progress_start_t = time.time()
                            self._nuclei_progress_state = {
                                "total_targets": int(total_targets),
                                "max_targets": 0,
                            }

                            # v4.4.4: Prevent UI duplication - Progress manages its own Live display
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
                                    f"[cyan]Nuclei (0/{total_targets})",
                                    total=total_targets,
                                    eta_upper=self._format_eta(total_batches * nuclei_timeout_s),
                                    eta_est="",
                                    detail=f"{total_targets} targets",
                                )

                                def _nuclei_progress(completed: int, total: int, eta: str) -> None:
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
                                            eta_est=(f"ETA≈ {eta_est_val}" if eta_est_val else ""),
                                            detail=f"batch {completed}/{total}",
                                        )
                                    except Exception:  # pragma: no cover
                                        pass

                                nuclei_result = run_nuclei_scan(
                                    targets=nuclei_targets,
                                    output_dir=output_dir,
                                    severity=nuclei_severity,
                                    timeout=nuclei_timeout_s,
                                    batch_size=batch_size,
                                    request_timeout=nuclei_request_timeout_s,
                                    retries=nuclei_retries,
                                    max_runtime_s=nuclei_max_runtime_s,
                                    exception_targets=exception_targets,
                                    fatigue_limit=nuclei_fatigue_limit,
                                    progress_callback=lambda c, t, e, d=None: self._nuclei_progress_callback(
                                        c,
                                        t,
                                        e,
                                        progress,
                                        task,
                                        progress_start_t,
                                        nuclei_timeout_s,
                                        total_targets,
                                        batch_size,
                                        detail=d,
                                    ),
                                    use_internal_progress=False,
                                    logger=self.logger,
                                    dry_run=bool(self.config.get("dry_run", False)),
                                    print_status=self.ui.print_status,
                                    proxy_manager=self.proxy_manager,
                                    profile=nuclei_profile,
                                    translate=self.ui.t,
                                )
                        except Exception:
                            nuclei_severity = "medium,high,critical"
                            nuclei_result = run_nuclei_scan(
                                targets=nuclei_targets,
                                output_dir=output_dir,
                                severity=nuclei_severity,
                                timeout=self.config.get("nuclei_timeout", 300),
                                request_timeout=10,
                                retries=1,
                                max_runtime_s=nuclei_max_runtime_s,
                                exception_targets=exception_targets,
                                fatigue_limit=nuclei_fatigue_limit,
                                logger=self.logger,
                                dry_run=bool(self.config.get("dry_run", False)),
                                print_status=self.ui.print_status,
                                proxy_manager=self.proxy_manager,
                                profile=nuclei_profile,
                                translate=self.ui.t,
                            )

                        findings = nuclei_result.get("findings") or []
                        suspected = []
                        if findings:
                            try:
                                from redaudit.core.verify_vuln import filter_nuclei_false_positives

                                host_agentless = {}
                                # v4.4.3 Fix: Use 'results' (local) instead of self.results['hosts'] (empty)
                                # and handle Host objects correctly
                                for host in results:
                                    if isinstance(host, dict):
                                        ip = host.get("ip")
                                        agentless = host.get("agentless_fingerprint") or {}
                                    else:
                                        ip = getattr(host, "ip", None)
                                        agentless = getattr(host, "agentless_fingerprint", {}) or {}

                                    if ip and agentless:
                                        host_agentless[ip] = agentless
                                findings, suspected = filter_nuclei_false_positives(
                                    findings,
                                    host_agentless,
                                    self.logger,
                                    host_records=results,  # v4.4.2: Pass host data for CPE validation
                                )
                            except Exception as filter_err:
                                if self.logger:
                                    self.logger.warning(
                                        "Nuclei FP filter skipped: %s", filter_err, exc_info=True
                                    )
                        nuclei_partial = bool(nuclei_result.get("partial"))
                        nuclei_error = nuclei_result.get("error")
                        nuclei_success = self._resolve_nuclei_success(
                            bool(nuclei_result.get("success")),
                            partial=nuclei_partial,
                            error=nuclei_error,
                        )
                        nuclei_summary = {
                            "enabled": True,
                            "profile": nuclei_profile,
                            "profile_selected": selected_profile,
                            "profile_effective": nuclei_profile,
                            "auto_switched": bool(auto_switched),
                            "full_coverage": bool(nuclei_full_coverage),
                            "targets": len(nuclei_targets),
                            "targets_total": targets_total,
                            "targets_pre_optimization": targets_pre_optimization,
                            "targets_exception": targets_exception,
                            "targets_optimized": targets_optimized,
                            "targets_excluded": targets_excluded,
                            "fatigue_limit": nuclei_fatigue_limit,
                            "leak_follow_mode": leak_follow_runtime.get("mode", "off"),
                            "leak_follow_detected": leak_follow_runtime.get("detected", 0),
                            "leak_follow_eligible": leak_follow_runtime.get("eligible", 0),
                            "leak_follow_followed": leak_follow_runtime.get("followed", 0),
                            "findings": len(findings),
                            "findings_total": len(nuclei_result.get("findings") or []),
                            "findings_suspected": len(suspected),
                            "success": nuclei_success,
                            "error": nuclei_error,
                        }
                        if nuclei_partial:
                            nuclei_summary["partial"] = True
                            timeout_batches = nuclei_result.get("timeout_batches") or []
                            failed_batches = nuclei_result.get("failed_batches") or []
                            if timeout_batches:
                                nuclei_summary["timeout_batches"] = timeout_batches
                            if failed_batches:
                                nuclei_summary["failed_batches"] = failed_batches
                        if nuclei_result.get("budget_exceeded"):
                            nuclei_summary["budget_exceeded"] = True
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
                        if auto_switched:
                            nuclei_summary["auto_switch_reason"] = "multi_port_hosts"
                            nuclei_summary["auto_switch_hosts"] = len(multi_port_hosts)
                        self.results["nuclei"] = nuclei_summary

                        merged = self._merge_nuclei_findings(findings)
                        suspected_count = len(suspected)
                        if merged > 0:
                            self.ui.print_status(self.ui.t("nuclei_findings", merged), "OK")
                            if suspected_count:
                                self.ui.print_status(
                                    self.ui.t("nuclei_suspected", suspected_count), "WARNING"
                                )
                        else:
                            if suspected_count:
                                self.ui.print_status(
                                    self.ui.t("nuclei_suspected_only", suspected_count), "WARNING"
                                )
                            elif nuclei_partial or nuclei_error:
                                self.ui.print_status(
                                    self.ui.t("nuclei_no_findings_partial"), "INFO"
                                )
                            else:
                                self.ui.print_status(self.ui.t("nuclei_no_findings"), "INFO")
                        if nuclei_result.get("budget_exceeded"):
                            self.ui.print_status(self.ui.t("nuclei_budget_exceeded"), "WARNING")
                        if nuclei_result.get("partial"):
                            timeout_batches = nuclei_result.get("timeout_batches") or []
                            failed_batches = nuclei_result.get("failed_batches") or []
                            if timeout_batches or failed_batches:
                                self.ui.print_status(
                                    self.ui.t(
                                        "nuclei_partial",
                                        len(timeout_batches),
                                        len(failed_batches),
                                    ),
                                    "WARNING",
                                )
                        pending_targets = nuclei_result.get("pending_targets") or []
                        if pending_targets:
                            resume_state = self._build_nuclei_resume_state(
                                output_dir=output_dir,
                                pending_targets=pending_targets,
                                total_targets=len(nuclei_targets),
                                profile=nuclei_profile,
                                profile_selected=selected_profile,
                                profile_effective=nuclei_profile,
                                full_coverage=bool(nuclei_full_coverage),
                                severity=nuclei_severity,
                                timeout_s=nuclei_timeout_s,
                                request_timeout_s=nuclei_request_timeout_s,
                                retries=nuclei_retries,
                                batch_size=batch_size,
                                max_runtime_minutes=nuclei_max_runtime_minutes,
                                fatigue_limit=nuclei_fatigue_limit,
                                output_file=nuclei_result.get("raw_output_file"),
                            )
                            resume_path = self._write_nuclei_resume_state(output_dir, resume_state)
                            if resume_path:
                                self.results["nuclei"]["resume_pending"] = len(pending_targets)
                                self.results["nuclei"]["resume_count"] = int(
                                    resume_state.get("resume_count") or 0
                                )
                                self.results["nuclei"]["last_resume_at"] = (
                                    resume_state.get("last_resume_at") or ""
                                )
                                try:
                                    self.results["nuclei"]["resume_state_file"] = os.path.relpath(
                                        resume_path, output_dir
                                    )
                                except Exception:
                                    self.results["nuclei"]["resume_state_file"] = resume_path
                                self.ui.print_status(
                                    self.ui.t("nuclei_resume_saved", resume_path), "WARNING"
                                )
                                resume_now = self.ask_yes_no_with_timeout(
                                    self.ui.t("nuclei_resume_prompt"),
                                    default="no",
                                    timeout_s=15,
                                )
                                if resume_now:
                                    self._resume_nuclei_from_state(
                                        resume_state=resume_state,
                                        resume_path=resume_path,
                                        output_dir=output_dir,
                                        use_existing_results=True,
                                        save_after=False,
                                        prompt_budget_override=True,
                                    )
                                else:
                                    self.ui.print_status(self.ui.t("nuclei_resume_skipped"), "INFO")
                except Exception as e:
                    if self.logger:
                        self.logger.warning("Nuclei scan failed: %s", e, exc_info=True)
                    self.ui.print_status(f"Nuclei: {e}", "WARNING")

            api_key = None
            # v4.1: CVE correlation moved here AFTER Vuln Scan + Nuclei
            # This ensures all version data from nikto/whatweb/testssl/nuclei is available
            if self.config.get("cve_lookup_enabled") and not self.interrupted:
                try:
                    self.ui.print_status(self.ui.t("running_cve_correlation"), "INFO")
                    # Ensure API key is loaded
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
                    if self.logger:
                        self.logger.debug("CVE enrichment failed (best-effort)", exc_info=True)

            # v4.5.0: Phase 4 - Authenticated Scanning (SSH/Lynis)
            if self.config.get("auth_enabled") and not self.interrupted:
                self._run_authenticated_scans(results)

                # v4.10: Process SNMP Topology (Routes/ARP) and optionally follow routes
                if self.config.get("snmp_topology") and not self.interrupted:
                    self._process_snmp_topology(results, api_key=api_key)

            # v4.3.1: Re-calculate risk scores with all findings (Nikto/Nuclei/Web)
            # This ensures risk_score reflects actual vulnerabilities found during scan
            try:
                from redaudit.core.siem import calculate_risk_score

                # Map findings to hosts by IP
                findings_map = {}
                vulns_data = self.results.get("vulnerabilities", [])
                for entry in vulns_data:
                    host_ip = entry.get("host")
                    if host_ip and entry.get("vulnerabilities"):
                        if host_ip not in findings_map:
                            findings_map[host_ip] = []
                        findings_map[host_ip].extend(entry["vulnerabilities"])

                # Update host records
                if isinstance(results, list):
                    for host in results:
                        # Ensure host is a dict (it might be a Pydantic model in some contexts, but usually dict here)
                        # If it's an object, we can't easily set findings unless we convert or use setattr
                        # Assuming dict based on usage in reporter.py
                        # Ensure we handle both dicts and Host objects
                        if isinstance(host, dict):
                            ip = host.get("ip")
                        else:
                            ip = getattr(host, "ip", None)

                        if ip and ip in findings_map:
                            if isinstance(host, dict):
                                host["findings"] = findings_map[ip]
                            else:
                                setattr(host, "findings", findings_map[ip])

                        # Recalculate and update
                        # This works because calculate_risk_score now looks at host["findings"]
                        host_record = host
                        if not isinstance(host, dict) and hasattr(host, "to_dict"):
                            host_record = host.to_dict()
                        new_risk = calculate_risk_score(host_record)

                        if isinstance(host, dict):
                            host["risk_score"] = new_risk
                        else:
                            setattr(host, "risk_score", new_risk)

            except Exception as e:
                if self.logger:
                    self.logger.warning("Risk score recalculation failed: %s", e)

            scope_runtime = self.results.get("scope_expansion_runtime") or {}
            if isinstance(scope_runtime, dict):
                self.results["scope_expansion_evidence"] = self._build_scope_expansion_evidence(
                    scope_runtime.get("leak_follow") or {},
                    scope_runtime.get("iot_probes") or {},
                )

            self.config["rate_limit_delay"] = self.rate_limit_delay
            generate_summary(self.results, self.config, all_hosts, results, self.scan_start_time)

            # v4.3: Finalize PCAP artifacts (merge and organize)
            output_dir = self.config.get("_actual_output_dir") or self.config.get("output_dir")
            if output_dir and not self.interrupted:
                try:
                    from redaudit.core.scanner.traffic import finalize_pcap_artifacts

                    session_id = ts_folder.replace("-", "").replace("_", "")
                    pcap_result = finalize_pcap_artifacts(
                        output_dir=output_dir,
                        session_id=session_id,
                        extra_tools=self.extra_tools,
                        logger=self.logger,
                        dry_run=self.config.get("dry_run"),
                    )
                    if pcap_result.get("merged_file"):
                        self.results["pcap_summary"] = {
                            "merged_file": os.path.basename(pcap_result["merged_file"]),
                            "raw_captures_dir": "raw_captures",
                            "individual_count": pcap_result.get("individual_count", 0),
                        }
                except Exception as pcap_err:
                    if self.logger:
                        self.logger.debug("PCAP finalization skipped: %s", pcap_err)

            # Close session log before saving reports so run_manifest captures
            # the final session log artifacts from this execution.
            from redaudit.utils.session_log import stop_session_log

            session_log_path = stop_session_log()
            session_log_closed = True
            if session_log_path and self.logger:
                self.logger.info("Session log saved: %s", session_log_path)

            self.save_results(partial=self.interrupted)
            self.show_results()

        finally:
            # v3.7: Stop session logging
            if not session_log_closed:
                from redaudit.utils.session_log import stop_session_log

                session_log_path = stop_session_log()
                if session_log_path and self.logger:
                    self.logger.info("Session log saved: %s", session_log_path)

            if self.proxy_manager:
                try:
                    self.proxy_manager.cleanup()
                except Exception:
                    pass

            if inhibitor is not None:
                try:
                    inhibitor.stop()
                except Exception:
                    pass
            self.stop_heartbeat()

        return not self.interrupted

    @staticmethod
    def _scope_evidence_entry(
        *,
        feature: str,
        classification: str,
        source: str,
        signal: str,
        decision: str,
        reason: str,
        host: str,
        raw_seed: str,
    ) -> Dict[str, Any]:
        allowed_classes = {"evidence", "heuristic", "hint"}
        normalized_class = classification if classification in allowed_classes else "hint"
        return {
            "feature": feature,
            "classification": normalized_class,
            "source": source or "unknown",
            "signal": signal or "",
            "decision": decision or "",
            "reason": reason or "",
            "host": host or "",
            "timestamp": datetime.now().isoformat(),
            "raw_ref": hashlib.sha256(raw_seed.encode("utf-8")).hexdigest(),
        }

    def _build_scope_expansion_evidence(
        self, leak_runtime: Dict[str, Any], iot_runtime: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        evidence: List[Dict[str, Any]] = []

        decisions = leak_runtime.get("decisions") if isinstance(leak_runtime, dict) else []
        if isinstance(decisions, list):
            for item in decisions:
                if not isinstance(item, dict):
                    continue
                candidate = str(item.get("candidate") or "").strip()
                source_host = str(item.get("source_host") or "").strip()
                source_field = str(item.get("source_field") or "").strip()
                reason = str(item.get("reason") or "").strip()
                eligible = bool(item.get("eligible"))
                if not candidate:
                    continue
                classification = "heuristic" if eligible else "hint"
                evidence.append(
                    self._scope_evidence_entry(
                        feature="leak_follow",
                        classification=classification,
                        source=f"leak_follow:{source_field or 'unknown'}",
                        signal=candidate,
                        decision="candidate_accepted" if eligible else "candidate_rejected",
                        reason=reason,
                        host=source_host,
                        raw_seed=f"leak|{source_host}|{source_field}|{candidate}|{reason}|{eligible}",
                    )
                )

        iot_evidence = iot_runtime.get("evidence") if isinstance(iot_runtime, dict) else []
        if isinstance(iot_evidence, list):
            for item in iot_evidence:
                if not isinstance(item, dict):
                    continue
                classification = str(item.get("classification") or "hint")
                # Promotion guardrail: only keep evidence class when explicitly corroborated.
                if classification == "evidence" and str(item.get("reason") or "") != "corroborated":
                    classification = "heuristic"
                source = str(item.get("source") or "unknown")
                signal = str(item.get("signal") or "")
                decision = str(item.get("decision") or "")
                reason = str(item.get("reason") or "")
                host = str(item.get("host") or "")
                evidence.append(
                    self._scope_evidence_entry(
                        feature="iot_probe",
                        classification=classification,
                        source=source,
                        signal=signal,
                        decision=decision,
                        reason=reason,
                        host=host,
                        raw_seed=f"iot|{host}|{source}|{signal}|{decision}|{reason}",
                    )
                )

        seen = set()
        deduped: List[Dict[str, Any]] = []
        for item in evidence:
            key = item.get("raw_ref")
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    # ---------- Phase 4: Authenticated Scanning (v4.5.0) ----------

    def _run_authenticated_scans(self, hosts: list) -> None:
        """
        Execute authenticated scans on eligible hosts using SSH/Lynis.

        Supports:
        - Universal credentials (auth_credentials list) via CredentialsManager
        - Legacy single credential (auth_ssh_user/pass/key)

        Args:
            hosts: List of host dictionaries from the scan results.
        """
        from redaudit.core.auth_ssh import SSHScanner, SSHConnectionError
        from redaudit.core.auth_lynis import LynisScanner
        from redaudit.core.credentials import Credential

        # v4.5.1: Check for universal credentials first
        auth_credentials = self.config.get("auth_credentials", [])
        use_multi_cred = bool(auth_credentials)

        # Legacy single credential fallback
        ssh_user = self.config.get("auth_ssh_user")
        ssh_pass = self.config.get("auth_ssh_pass")
        ssh_key = self.config.get("auth_ssh_key")
        ssh_key_pass = self.config.get("auth_ssh_key_pass")

        if not auth_credentials and not ssh_user:
            if self.logger:  # pragma: no cover
                self.logger.debug("Authenticated scan skipped: no credentials configured")
            return

        # Build credential list
        credentials: list = []

        if use_multi_cred:
            # v4.5.1: Universal credentials from wizard/CLI
            for cred_dict in auth_credentials:
                credentials.append(
                    Credential(
                        username=cred_dict.get("user", ""),
                        password=cred_dict.get("pass"),
                    )
                )
        else:
            # Legacy single credential
            credentials.append(
                Credential(
                    username=ssh_user,
                    password=ssh_pass,
                    private_key=ssh_key,
                    private_key_passphrase=ssh_key_pass,
                )
            )

        # Find hosts with SSH ports open (22 or non-standard where service is SSH)
        def get_ssh_port(host) -> Optional[int]:
            """Return SSH port for host if found (22 or service-based)."""
            # Get ports from dict or object
            if isinstance(host, dict):
                ports = host.get("ports", [])
                services = host.get("services", [])
            else:
                ports = getattr(host, "ports", []) or []
                services = getattr(host, "services", []) or []

            def _port_from_entry(entry) -> Optional[int]:
                if isinstance(entry, dict):
                    port = entry.get("port")
                    service = (entry.get("service") or entry.get("name") or "").lower()
                    product = (entry.get("product") or "").lower()
                    cpes = entry.get("cpe") or []
                    if service == "ssh" or "ssh" in product:
                        return int(port) if isinstance(port, int) else None
                    if isinstance(cpes, list) and any("openssh" in str(c).lower() for c in cpes):
                        return int(port) if isinstance(port, int) else None
                    if port == 22:
                        return 22
                elif hasattr(entry, "port"):
                    port = getattr(entry, "port", None)
                    service = getattr(entry, "service", None)
                    product = getattr(entry, "product", None)
                    cpes = getattr(entry, "cpe", None) or []
                    if str(service).lower() == "ssh" or "ssh" in str(product).lower():
                        return int(port) if isinstance(port, int) else None
                    if any("openssh" in str(c).lower() for c in cpes):
                        return int(port) if isinstance(port, int) else None
                    if port == 22:
                        return 22
                elif isinstance(entry, int) and entry == 22:
                    return 22
                return None

            # Prefer explicit SSH service entries
            if isinstance(ports, list):
                for p in ports:
                    port = _port_from_entry(p)
                    if port:
                        return port  # pragma: no cover

            # Fallback to services list if ports are missing service metadata
            if isinstance(services, list):
                for svc in services:
                    if not isinstance(svc, dict):
                        continue
                    name = (svc.get("name") or "").lower()
                    product = (svc.get("product") or "").lower()
                    port = svc.get("port")
                    if name == "ssh" or "ssh" in product:
                        return int(port) if isinstance(port, int) else None

            return None

        ssh_hosts = []
        for host in hosts:
            port = get_ssh_port(host)
            if port:
                ssh_hosts.append((host, port))

        if not ssh_hosts:
            self.ui.print_status(self.ui.t("auth_scan_no_hosts"), "INFO")
            return

        self.ui.print_status(self.ui.t("auth_scan_starting", len(ssh_hosts)), "INFO")

        auth_summary: Dict[str, Any] = {
            "enabled": True,
            "targets": len(ssh_hosts),
            "completed": 0,
            "ssh_success": 0,
            "lynis_success": 0,
            "errors": [],
        }

        for host, ssh_port in ssh_hosts:
            if self.interrupted:
                break

            # Safe handling for both Dict and Host objects
            if isinstance(host, dict):
                ip = host.get("ip")
            else:
                ip = getattr(host, "ip", None)

            if not ip:
                continue

            # Try each credential until one succeeds
            connected = False
            scanner = None
            working_cred = None

            for cred in credentials:
                try:
                    scanner = SSHScanner(cred, timeout=30, trust_unknown_keys=True)
                    scanner.connect(ip, port=int(ssh_port))
                    connected = True
                    working_cred = cred
                    break
                except SSHConnectionError:
                    continue
                except Exception:
                    continue

            if not connected or not scanner:
                auth_summary["errors"].append({"ip": ip, "error": "All credentials failed"})
                self.ui.print_status(f"[WARN] {ip}: SSH auth failed (all creds)", "WARNING")
                continue

            try:
                # Gather basic host info via SSH
                host_info = scanner.gather_host_info()

                auth_data = {
                    "os_name": host_info.os_name,
                    "os_version": host_info.os_version,
                    "kernel": host_info.kernel,
                    "hostname": host_info.hostname,
                    "packages_count": len(host_info.packages),
                    "services_count": len(host_info.services),
                    "users_count": len(host_info.users),
                    "credential_user": working_cred.username if working_cred else None,
                }

                if isinstance(host, dict):
                    host["auth_ssh"] = auth_data
                else:
                    # Host object (use auth_scan field)
                    if not hasattr(host, "auth_scan") or host.auth_scan is None:
                        host.auth_scan = {}
                    host.auth_scan["ssh"] = auth_data
                auth_summary["ssh_success"] += 1

                # Run Lynis audit if possible
                try:
                    lynis = LynisScanner(scanner)
                    lynis_result = lynis.run_audit(use_portable=True)
                    if lynis_result:
                        lynis_data = {
                            "hardening_index": lynis_result.hardening_index,
                            "warnings_count": len(lynis_result.warnings or []),
                            "suggestions_count": len(lynis_result.suggestions or []),
                            "tests_performed": lynis_result.tests_performed,
                        }
                        if isinstance(host, dict):
                            host["auth_lynis"] = lynis_data
                        else:
                            if not hasattr(host, "auth_scan") or host.auth_scan is None:
                                host.auth_scan = {}
                            host.auth_scan["lynis"] = lynis_data
                        auth_summary["lynis_success"] += 1
                except Exception as lynis_err:
                    if self.logger:
                        self.logger.debug("Lynis scan failed on %s: %s", ip, lynis_err)

                scanner.close()
                auth_summary["completed"] += 1
                self.ui.print_status(f"[OK] {ip}: SSH auth success", "OK")

            except SSHConnectionError as e:
                auth_summary["errors"].append({"ip": ip, "error": str(e)})
                self.ui.print_status(f"[WARN] {ip}: SSH failed - {e}", "WARNING")
                if self.logger:
                    self.logger.debug("SSH auth failed on %s: %s", ip, e)

            except Exception as e:
                auth_summary["errors"].append({"ip": ip, "error": str(e)})
                if self.logger:
                    self.logger.warning("Auth scan error on %s: %s", ip, e)

        self.results["auth_scan"] = auth_summary
        self.ui.print_status(
            self.ui.t(
                "auth_scan_complete",
                auth_summary["ssh_success"],
                auth_summary["lynis_success"],
            ),
            "OK",
        )

    # ---------- Subprocess management (C1 fix) ----------

    def _process_snmp_topology(self, hosts: list, api_key: Optional[str] = None) -> None:
        """
        Process discovered SNMP topology data (Routes) and optionally scan new networks.

        v4.10: Implements Advanced L2/L3 Discovery.
        Checks 'auth_scan.routes' for discovered subnets.
        If --follow-routes is enabled, triggers discovery and scanning on new subnets.
        """
        import ipaddress

        discovered_cidrs = set()
        router_map = {}  # subnet -> router_ip

        # 1. Collect Routes from authorized scans
        for host in hosts:
            # Handle both dict and Host objects
            if isinstance(host, dict):
                ip = host.get("ip")
                auth_data = host.get("auth_scan")
            else:
                ip = getattr(host, "ip", None)
                auth_data = getattr(host, "auth_scan", None)

            if not ip or not auth_data or not isinstance(auth_data, dict):
                continue

            routes = auth_data.get("routes")
            if not routes:
                continue

            for route in routes:
                dest = route.get("dest")
                mask = route.get("mask")
                if not dest or not mask:
                    continue

                # Convert Dest/Mask to CIDR
                try:
                    # Skip default routes (0.0.0.0) and loopbacks
                    if dest == "0.0.0.0" or dest.startswith("127."):  # nosec
                        continue

                    # Calculate netmask length
                    # Simple hack: use ipaddress.IPv4Network(f"{dest}/{mask}")
                    net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)

                    if net.is_global or net.is_private:
                        # Avoid /32 routes (host routes) unless requested?
                        # Usually we want subnets. /32 implies a single host.
                        if net.prefixlen == 32:
                            continue

                        cidr = str(net)
                        discovered_cidrs.add(cidr)
                        if cidr not in router_map:
                            router_map[cidr] = ip

                except Exception:
                    continue

        if not discovered_cidrs:
            return

        # 2. Filter against existing scope
        existing_scope = []
        for n in self.config.get("target_networks", []):
            try:
                existing_scope.append(ipaddress.IPv4Network(n, strict=False))
            except Exception:
                pass

        new_networks = []
        for cidr in discovered_cidrs:
            try:
                candidate = ipaddress.IPv4Network(cidr)
                # Check if already covered
                is_covered = False
                for existing in existing_scope:
                    # If candidate is subnet of existing, it's covered.
                    if candidate.subnet_of(existing):
                        is_covered = True
                        break

                    # Also check exact match
                    if candidate == existing:
                        is_covered = True
                        break

                if not is_covered:
                    new_networks.append(cidr)
            except Exception:
                pass

        if not new_networks:
            return

        # 3. Report Findings
        self.ui.print_status("Start SNMP Topology Analysis", "INFO")
        self.ui.print_status(f"Discovered {len(new_networks)} new routed networks:", "INFO")
        for subnet_cidr in new_networks:
            router = router_map.get(subnet_cidr, "unknown")
            self.ui.print_status(f"  - {subnet_cidr} (via {router})", "INFO")

        # 4. Follow Routes (if enabled)
        if self.config.get("follow_routes"):
            self.ui.print_status(
                f"Following routes: Scanning {len(new_networks)} new networks...", "INFO"
            )

            # Prevent infinite recursion: add to scope
            self.config["target_networks"].extend(new_networks)

            new_hosts_found = []

            # A) Ping Sweep (Net Discovery)
            with self._progress_ui():  # Wrap in progress if not already?
                for i, subnet_cidr in enumerate(new_networks):
                    if self.interrupted:
                        break
                    self.ui.print_status(
                        f"Scanning network {i + 1}/{len(new_networks)}: {subnet_cidr}", "INFO"
                    )
                    ips = self.scan_network_discovery(subnet_cidr)
                    new_hosts_found.extend(ips)

            # Deduplicate
            unique_ips = list(set(new_hosts_found))

            # Filter already scanned IPs
            scanned_ips = set()
            for h in hosts:
                if isinstance(h, dict):
                    scanned_ips.add(h.get("ip"))
                else:
                    scanned_ips.add(getattr(h, "ip", None))

            targets_to_scan = [ip for ip in unique_ips if ip not in scanned_ips]

            if targets_to_scan:
                self.ui.print_status(
                    self.ui.t("deep_scan_new_hosts", len(targets_to_scan)),
                    "INFO",
                )

                # B) Port Scan (Phase 2) using existing concurrency logic
                # Create Host objects
                new_host_objs = [self.scanner.get_or_create_host(ip) for ip in targets_to_scan]

                # Run Scan
                new_results = self.scan_hosts_concurrent(new_host_objs)

                # Merge Resuls
                if isinstance(hosts, list):
                    hosts.extend(new_results)

                # v4.10.1: Enrich new hosts with CVEs for consistency
                # Since these skipped the main loop, we must enrich them explicitly.
                if new_results:
                    self.ui.print_status(
                        self.ui.t("cve_enrich_new_hosts", len(new_results)),
                        "INFO",
                    )
                    for h in new_results:
                        try:
                            # enrich_host_with_cves is available in scope
                            enrich_host_with_cves(h, api_key=api_key, logger=self.logger)
                        except Exception:
                            pass
            else:
                self.ui.print_status("No new live hosts found in routed networks.", "INFO")
        else:
            self.ui.print_status(
                "Use --follow-routes to automatically scan these networks.", "INFO"
            )

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
        """Terminate all tracked subprocesses and ALL child processes (zombies)."""
        # 1. Kill tracked (registered) subprocesses
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

        # 2. Zombie Reaper: Kill ANY remaining child processes of this PID
        # This handles CommandRunner/NetworkScanner processes that weren't explicitly registered.
        # Works on Linux and macOS.
        try:
            current_pid = os.getpid()
            # pkill -P <PID> kills all children of PID
            if shutil.which("pkill"):
                subprocess.run(
                    ["pkill", "-P", str(current_pid)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception as exc:  # pragma: no cover
            if self.logger:  # pragma: no cover
                self.logger.debug("Zombie Reaper failed: %s", exc)

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

        if self.scan_start_time is not None:
            _status("interrupted_saving_progress", "WARNING")
        else:
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
        self._scan_wizard_flow_call("_apply_run_defaults", defaults_for_run)

    def _ask_auditor_and_output_dir(self, defaults_for_run: Dict) -> None:
        self._scan_wizard_flow_call("_ask_auditor_and_output_dir", defaults_for_run)

    @staticmethod
    def _normalize_csv_targets(raw_value: Any) -> List[str]:
        return ScanWizardFlow._normalize_csv_targets(raw_value)

    def _leak_follow_available_for_run(self) -> bool:
        return self._scan_wizard_flow_call("_leak_follow_available_for_run")

    def _apply_scope_expansion_profile_defaults(self, defaults_for_run: Dict, profile: str) -> None:
        self._scan_wizard_flow_call(
            "_apply_scope_expansion_profile_defaults",
            defaults_for_run,
            profile,
        )

    def _ask_scope_expansion_advanced(self) -> None:
        self._scan_wizard_flow_call("_ask_scope_expansion_advanced")

    def _ask_scope_expansion_quick(
        self,
        *,
        profile: str,
        step_num: Optional[int] = None,
        total_steps: Optional[int] = None,
    ) -> Optional[bool]:
        return self._scan_wizard_flow_call(
            "_ask_scope_expansion_quick",
            profile=profile,
            step_num=step_num,
            total_steps=total_steps,
        )

    def _configure_scan_interactive(self, defaults_for_run: Dict) -> None:
        self._scan_wizard_flow_call("_configure_scan_interactive", defaults_for_run)

    def _show_defaults_summary(self, persisted_defaults: Dict) -> None:
        self._scan_wizard_flow_call("_show_defaults_summary", persisted_defaults)

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
            # v4.4.4: Keep heartbeat alive during progress updates
            self._touch_activity()

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
                msg = self.ui.t("net_discovery_heartbeat", mins, secs)
                # v4.18: Use Text() to avoid Rich markup issues
                if hasattr(progress, "console"):
                    from rich.text import Text

                    heartbeat_msg = Text()
                    heartbeat_msg.append(msg, style="dim")
                    progress.console.print(heartbeat_msg)
                else:
                    self.ui.print_status(msg, "INFO", force=True)
                self._nd_last_heartbeat = now
        except Exception:
            pass

    def _nuclei_progress_callback(
        self,
        completed: float,
        total: int,
        eta: str,
        progress: Any,
        task: Any,
        start_time: float,
        timeout: int,
        total_targets: int,
        batch_size: int,
        *,
        detail: Optional[str] = None,
    ) -> None:
        """Callback for Nuclei scan progress updates."""
        try:
            # v4.4.4: Keep heartbeat alive during progress updates
            self._touch_activity()

            total_targets_i = max(0, int(total_targets))
            total_hint = max(0, int(total)) if total is not None else 0
            if total_targets_i <= 0:
                total_targets_i = total_hint
            use_batch_units = bool(total_targets_i and total_hint and total_hint != total_targets_i)
            if use_batch_units:
                approx_targets = int(round(float(completed) * max(1, int(batch_size))))
            else:
                approx_targets = int(round(float(completed)))
            approx_targets = max(0, min(total_targets_i, approx_targets))
            detail_text = detail or f"batch {completed}/{total}"
            if isinstance(detail_text, str):
                detail_lower = detail_text.lower()
            else:  # pragma: no cover
                detail_lower = ""
            is_running = any(token in detail_lower for token in ("running", "en curso"))
            if is_running and total_targets_i > 0:
                approx_targets = min(approx_targets, total_targets_i - 1)

            # Prevent regressions when batches are retried/split (timeouts can reset progress).
            state = getattr(self, "_nuclei_progress_state", None)
            if not isinstance(state, dict) or state.get("total_targets") != total_targets_i:
                state = {"total_targets": total_targets_i, "max_targets": 0}
                self._nuclei_progress_state = state
            max_seen = int(state.get("max_targets") or 0)
            if approx_targets < max_seen:
                approx_targets = max_seen
            else:
                state["max_targets"] = approx_targets
            if isinstance(detail_text, str) and detail_text:
                detail_text = f"[bright_blue]{detail_text}[/]"
            remaining_batches = max(0.0, float(total) - float(completed))
            remaining_targets = max(0, int(total_targets) - approx_targets)
            ela_s = max(0.001, time.time() - start_time)
            rate = approx_targets / ela_s if approx_targets else 0.0
            eta_est_v = (
                self._format_eta(remaining_targets / rate)
                if rate > 0.0 and remaining_targets
                else ""
            )
            progress.update(
                task,
                completed=approx_targets,
                description=f"[cyan]Nuclei ({approx_targets}/{total_targets})",
                eta_upper=self._format_eta(remaining_batches * timeout if remaining_batches else 0),
                eta_est=f"ETA≈ {eta_est_v}" if eta_est_v else "",
                detail=detail_text,
            )
        except Exception:  # pragma: no cover
            pass

    def _build_nuclei_resume_state(
        self,
        *,
        output_dir: str,
        pending_targets: List[str],
        total_targets: int,
        profile: str,
        profile_selected: Optional[str] = None,
        profile_effective: Optional[str] = None,
        full_coverage: bool,
        severity: str,
        timeout_s: int,
        request_timeout_s: int,
        retries: int,
        batch_size: int,
        max_runtime_minutes: int,
        fatigue_limit: Optional[int] = None,
        output_file: Optional[str],
    ) -> Dict[str, Any]:
        output_rel = "nuclei_output.json"
        if output_file and isinstance(output_file, str):
            try:
                output_rel = os.path.relpath(output_file, output_dir)
            except Exception:  # pragma: no cover
                output_rel = output_file
        return {
            "version": 1,
            "created_at": datetime.now().isoformat(),
            "output_dir": os.path.abspath(output_dir),
            "pending_targets": pending_targets,
            "total_targets": int(total_targets),
            "resume_count": 0,
            "last_resume_at": None,
            "profile_selected": profile_selected or profile,
            "profile_effective": profile_effective or profile,
            "output_file": output_rel,
            "nuclei": {
                "profile": profile,
                "full_coverage": bool(full_coverage),
                "severity": severity,
                "timeout_s": int(timeout_s),
                "request_timeout_s": int(request_timeout_s),
                "retries": int(retries),
                "batch_size": int(batch_size),
                "max_runtime_minutes": int(max_runtime_minutes),
                "fatigue_limit": fatigue_limit,
            },
        }

    def _write_nuclei_resume_state(
        self, output_dir: str, resume_state: Dict[str, Any]
    ) -> Optional[str]:
        try:
            pending_targets = resume_state.get("pending_targets") or []
            if not isinstance(pending_targets, list) or not pending_targets:
                return None
            resume_state["updated_at"] = datetime.now().isoformat()
            os.makedirs(output_dir, exist_ok=True)
            resume_path = os.path.join(output_dir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as handle:
                json.dump(resume_state, handle, indent=2)
            pending_path = os.path.join(output_dir, "nuclei_pending.txt")
            with open(pending_path, "w", encoding="utf-8") as handle:
                for target in pending_targets:
                    handle.write(f"{target}\n")
            return resume_path
        except Exception:  # pragma: no cover
            if self.logger:
                self.logger.debug("Failed to write nuclei resume state", exc_info=True)
            return None

    def _clear_nuclei_resume_state(self, resume_path: str, output_dir: str) -> None:
        for path in (
            resume_path,
            os.path.join(output_dir, "nuclei_pending.txt"),
        ):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:  # pragma: no cover
                if self.logger:
                    self.logger.debug("Failed to remove %s", path, exc_info=True)

    def _load_nuclei_resume_state(self, resume_path: str) -> Optional[Dict[str, Any]]:
        try:
            if not resume_path or not os.path.exists(resume_path):
                return None
            with open(resume_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            pending_targets = data.get("pending_targets") or []
            if not isinstance(pending_targets, list) or not pending_targets:
                return None
            output_dir = data.get("output_dir")
            if not output_dir:
                output_dir = os.path.dirname(resume_path)
                data["output_dir"] = output_dir
            if not isinstance(data.get("resume_count"), int):
                try:
                    data["resume_count"] = int(data.get("resume_count") or 0)
                except Exception:
                    data["resume_count"] = 0
            if data.get("last_resume_at") is None:
                data["last_resume_at"] = ""
            return data
        except Exception:  # pragma: no cover
            if self.logger:
                self.logger.debug("Failed to load nuclei resume state", exc_info=True)
            return None

    def _find_nuclei_resume_candidates(self, base_dir: str) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        if not base_dir or not os.path.isdir(base_dir):
            return candidates
        try:
            for entry in os.listdir(base_dir):
                scan_dir = os.path.join(base_dir, entry)
                if not os.path.isdir(scan_dir):  # pragma: no cover
                    continue
                resume_path = os.path.join(scan_dir, "nuclei_resume.json")
                if not os.path.exists(resume_path):  # pragma: no cover
                    continue
                state = self._load_nuclei_resume_state(resume_path)
                if not state:  # pragma: no cover
                    continue
                pending = state.get("pending_targets") or []
                created_at = state.get("created_at") or ""
                resume_count = state.get("resume_count") or 0
                try:
                    resume_count = int(resume_count)
                except Exception:  # pragma: no cover
                    resume_count = 0
                label = f"{entry} ({len(pending)} targets)"
                if resume_count > 0:
                    label = f"{label} | resumes: {resume_count}"
                candidates.append(
                    {
                        "path": resume_path,
                        "label": label,
                        "pending": len(pending),
                        "created_at": created_at,
                        "updated_at": state.get("updated_at") or "",
                        "output_dir": state.get("output_dir"),
                        "resume_count": resume_count,
                    }
                )
        except Exception:
            if self.logger:
                self.logger.debug("Failed to list nuclei resumes", exc_info=True)
        candidates.sort(
            key=lambda item: item.get("updated_at") or item.get("created_at") or "",
            reverse=True,
        )
        return candidates

    def _find_latest_report_json(self, output_dir: str) -> Optional[str]:
        if not output_dir or not os.path.isdir(output_dir):  # pragma: no cover
            return None
        candidates = []
        for name in os.listdir(output_dir):
            if not name.endswith(".json"):
                continue
            if not (
                name.startswith("redaudit_") or name.startswith("PARTIAL_redaudit_")
            ):  # pragma: no cover
                continue
            if name in ("run_manifest.json", "nuclei_resume.json"):  # pragma: no cover
                continue
            path = os.path.join(output_dir, name)
            if os.path.isfile(path):
                candidates.append(path)
        if not candidates:
            return None
        return max(candidates, key=lambda p: os.path.getmtime(p))

    def _detect_report_artifact(self, output_dir: str, suffixes: tuple[str, ...]) -> bool:
        if not output_dir or not os.path.isdir(output_dir):  # pragma: no cover
            return False
        for name in os.listdir(output_dir):
            if not name.endswith(suffixes):
                continue
            if (
                name.startswith("redaudit_")
                or name.startswith("PARTIAL_redaudit_")
                or name
                in ("report.html", "report_es.html", "report.html.enc", "report_es.html.enc")
            ):
                return True
        return False

    def _load_resume_context(self, output_dir: str) -> bool:
        report_path = self._find_latest_report_json(output_dir)
        if not report_path:
            self.ui.print_status(
                self.ui.t("nuclei_resume_failed", "missing JSON report"), "WARNING"
            )
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:  # pragma: no cover
            self.ui.print_status(
                self.ui.t("nuclei_resume_failed", "failed to read JSON report"), "WARNING"
            )
            return False
        if not isinstance(data, dict):  # pragma: no cover
            self.ui.print_status(self.ui.t("nuclei_resume_failed", "invalid report"), "WARNING")
            return False
        self.results = data
        snapshot = data.get("config_snapshot") or {}
        if not isinstance(snapshot, dict):  # pragma: no cover
            snapshot = {}
        self.config = snapshot.copy()
        if not self.config.get("target_networks"):
            resume_targets = self.config.get("targets") or data.get("targets") or []
            if isinstance(resume_targets, list) and resume_targets:
                self.config["target_networks"] = list(resume_targets)
        self.config["output_dir"] = output_dir
        self.config["_actual_output_dir"] = output_dir
        self.config["lang"] = self.config.get("lang") or self.lang
        self.config["save_txt_report"] = self._detect_report_artifact(
            output_dir, (".txt", ".txt.enc")
        )
        self.config["save_html_report"] = self._detect_report_artifact(
            output_dir, (".html", ".html.enc")
        )
        self.encryption_enabled = False
        self.encryption_key = None
        return True

    @staticmethod
    def _parse_duration_to_timedelta(value: Any) -> Optional[timedelta]:
        if isinstance(value, timedelta):  # pragma: no cover
            return value
        if isinstance(value, (int, float)):  # pragma: no cover
            return timedelta(seconds=int(value))
        if not isinstance(value, str):
            return None
        text = value.strip()
        if not text:  # pragma: no cover
            return None
        days = 0
        time_part = text
        day_match = re.match(r"^(\d+)\s+day[s]?,\s*(\d+:\d{2}:\d{2})$", text)
        if day_match:
            days = int(day_match.group(1))
            time_part = day_match.group(2)
        time_match = re.match(r"^(\d+):([0-5]\d):([0-5]\d)$", time_part)
        if not time_match:
            return None
        hours = int(time_match.group(1))
        minutes = int(time_match.group(2))
        seconds = int(time_match.group(3))
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    @staticmethod
    def _resolve_nuclei_success(success_flag: bool, *, partial: bool, error: Optional[str]) -> bool:
        if partial or error:
            return False
        return bool(success_flag)

    def _resume_scan_start_time(
        self, resume_finished_at: datetime, resume_elapsed: Optional[timedelta]
    ) -> Optional[datetime]:
        previous_duration = self._parse_duration_to_timedelta(
            (self.results.get("summary") or {}).get("duration")
        )
        total = None
        if previous_duration and resume_elapsed:
            total = previous_duration + resume_elapsed
        elif previous_duration:  # pragma: no cover
            total = previous_duration
        elif resume_elapsed:
            total = resume_elapsed
        if total is None:  # pragma: no cover
            return self.scan_start_time
        return resume_finished_at - total

    def _append_nuclei_output(self, source_path: str, dest_path: str) -> None:
        if not source_path or not os.path.exists(source_path):  # pragma: no cover
            return
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with (
            open(source_path, "r", encoding="utf-8", errors="ignore") as fin,
            open(dest_path, "a", encoding="utf-8") as fout,
        ):
            for line in fin:
                if not line.strip():  # pragma: no cover
                    continue
                fout.write(line if line.endswith("\n") else line + "\n")

    def _resume_nuclei_from_state(
        self,
        *,
        resume_state: Dict[str, Any],
        resume_path: str,
        output_dir: str,
        use_existing_results: bool,
        save_after: bool,
        override_max_runtime_minutes: Optional[int] = None,
        prompt_budget_override: bool = False,
    ) -> bool:
        if not use_existing_results:
            if not self._load_resume_context(output_dir):
                return False

        pending_targets = resume_state.get("pending_targets") or []
        if not isinstance(pending_targets, list) or not pending_targets:
            self.ui.print_status(self.ui.t("nuclei_resume_none"), "INFO")
            return False
        if not self.config.get("target_networks"):
            resume_targets = self.config.get("targets") or self.results.get("targets") or []
            if isinstance(resume_targets, list) and resume_targets:  # pragma: no cover
                self.config["target_networks"] = list(resume_targets)
        if not self.config.get("_actual_output_dir"):
            self.config["_actual_output_dir"] = output_dir
        if isinstance(resume_state, dict):
            try:
                resume_state["resume_count"] = int(resume_state.get("resume_count") or 0) + 1
            except Exception:  # pragma: no cover
                resume_state["resume_count"] = 1
            resume_state["last_resume_at"] = datetime.now().isoformat()
            self._write_nuclei_resume_state(output_dir, resume_state)

        inhibitor = None
        if self.config.get("prevent_sleep", True):
            try:
                from redaudit.core.power import SleepInhibitor

                inhibitor = SleepInhibitor(logger=self.logger)
                inhibitor.start()
            except Exception:  # pragma: no cover
                inhibitor = None

        nuclei_cfg = resume_state.get("nuclei") or {}
        profile = nuclei_cfg.get("profile") or "balanced"
        selected_profile = (
            resume_state.get("profile_selected") or self.config.get("nuclei_profile") or profile
        )
        effective_profile = resume_state.get("profile_effective") or profile
        auto_switched = bool(resume_state.get("auto_switched")) or (
            selected_profile != effective_profile
        )
        severity = nuclei_cfg.get("severity") or "low,medium,high,critical"
        timeout_s = nuclei_cfg.get("timeout_s") or 300
        request_timeout_s = nuclei_cfg.get("request_timeout_s") or 10
        retries = nuclei_cfg.get("retries") or 1
        batch_size = nuclei_cfg.get("batch_size") or 10
        max_runtime_minutes = nuclei_cfg.get("max_runtime_minutes") or 0
        fatigue_limit = nuclei_cfg.get("fatigue_limit")
        if fatigue_limit is None:
            fatigue_limit = self.config.get("nuclei_fatigue_limit", 3)
        try:
            fatigue_limit = int(fatigue_limit)
        except Exception:  # pragma: no cover
            fatigue_limit = 3
        if fatigue_limit < 0:  # pragma: no cover
            fatigue_limit = 0
        if fatigue_limit > 10:  # pragma: no cover
            fatigue_limit = 10
        if override_max_runtime_minutes is not None:
            try:
                max_runtime_minutes = int(override_max_runtime_minutes)
            except Exception:  # pragma: no cover
                max_runtime_minutes = int(nuclei_cfg.get("max_runtime_minutes") or 0)
        elif prompt_budget_override:
            saved_minutes = int(max_runtime_minutes) if str(max_runtime_minutes).isdigit() else 0
            if saved_minutes > 0:
                keep_budget = self.ask_yes_no(
                    self.ui.t("nuclei_resume_budget_keep", saved_minutes), default="yes"
                )
            else:
                keep_budget = self.ask_yes_no(
                    self.ui.t("nuclei_resume_budget_keep_unlimited"), default="yes"
                )
            if not keep_budget:
                new_minutes = self.ask_number(
                    self.ui.t("nuclei_resume_budget_prompt"),
                    default=saved_minutes,
                    min_val=0,
                    max_val=1440,
                )
                if isinstance(new_minutes, str):
                    max_runtime_minutes = 0
                else:
                    max_runtime_minutes = int(new_minutes)
        if max_runtime_minutes < 0:  # pragma: no cover
            max_runtime_minutes = 0
        if isinstance(resume_state, dict):
            nuclei_cfg["max_runtime_minutes"] = int(max_runtime_minutes)
            nuclei_cfg["fatigue_limit"] = int(fatigue_limit)
            resume_state["nuclei"] = nuclei_cfg
            resume_state["profile_selected"] = selected_profile
            resume_state["profile_effective"] = effective_profile
            resume_state["auto_switched"] = bool(auto_switched)
        max_runtime_s = max_runtime_minutes * 60 if max_runtime_minutes else None

        session_log_started = False
        session_log_closed = False
        try:
            try:
                from redaudit.utils.session_log import start_session_log

                resume_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                session_log_started = start_session_log(output_dir, f"resume_{resume_stamp}")
            except Exception:  # pragma: no cover
                if self.logger:
                    self.logger.debug("Failed to start resume session log", exc_info=True)

            self.ui.print_status(self.ui.t("nuclei_resume_running"), "INFO")
            resume_started_at = datetime.now()
            resume_output_file = os.path.join(output_dir, "nuclei_output_resume.json")
            if os.path.exists(resume_output_file):
                try:
                    os.remove(resume_output_file)
                except Exception:  # pragma: no cover
                    pass
            run_kwargs = {
                "targets": pending_targets,
                "output_dir": output_dir,
                "severity": severity,
                "timeout": timeout_s,
                "batch_size": batch_size,
                "request_timeout": request_timeout_s,
                "retries": retries,
                "max_runtime_s": max_runtime_s,
                "fatigue_limit": fatigue_limit,
                "output_file": resume_output_file,
                "append_output": False,
                "targets_file": os.path.join(output_dir, "nuclei_pending.txt"),
                "logger": self.logger,
                "dry_run": bool(self.config.get("dry_run", False)),
                "print_status": self.ui.print_status,
                "proxy_manager": self.proxy_manager,
                "profile": profile,
            }
            resume_result = None
            progress_console = self._progress_console()
            try:
                from rich.console import Console

                if not isinstance(progress_console, Console):
                    progress_console = None
            except ImportError:  # pragma: no cover
                progress_console = None
            if progress_console is not None:
                try:
                    from rich.progress import Progress

                    pending_total = len(pending_targets)
                    total_targets = pending_total
                    total_batches = max(1, int(math.ceil(pending_total / max(1, int(batch_size)))))
                    progress_start_t = time.time()
                    self._nuclei_progress_state = {
                        "total_targets": int(total_targets),
                        "max_targets": 0,
                    }
                    with Progress(
                        *self._progress_columns(
                            show_detail=True,
                            show_eta=True,
                            show_elapsed=False,
                        ),
                        console=progress_console,
                        transient=False,
                        refresh_per_second=4,
                    ) as progress:
                        task = progress.add_task(
                            f"[cyan]Nuclei (0/{total_targets})",
                            total=total_targets,
                            eta_upper=self._format_eta(total_batches * int(timeout_s)),
                            eta_est="",
                            detail=self.ui.t("nuclei_resume_pending", pending_total),
                        )
                        resume_result = run_nuclei_scan(
                            **run_kwargs,
                            progress_callback=lambda c, t, e, d=None: self._nuclei_progress_callback(
                                float(c),
                                total_targets,
                                e,
                                progress,
                                task,
                                progress_start_t,
                                int(timeout_s),
                                total_targets,
                                int(batch_size),
                                detail=d,
                            ),
                            use_internal_progress=False,
                            translate=self.ui.t,
                        )
                except Exception:  # pragma: no cover
                    resume_result = None
            if resume_result is None:
                resume_result = run_nuclei_scan(
                    **run_kwargs,
                    use_internal_progress=True,
                    translate=self.ui.t,
                )

            base_output_rel = resume_state.get("output_file") or "nuclei_output.json"
            base_output_path = (
                base_output_rel
                if os.path.isabs(base_output_rel)
                else os.path.join(output_dir, base_output_rel)
            )
            self._append_nuclei_output(resume_output_file, base_output_path)

            new_findings = resume_result.get("findings") or []
            suspected: List[Dict[str, Any]] = []
            if new_findings:
                try:
                    from redaudit.core.verify_vuln import filter_nuclei_false_positives

                    host_agentless = {}
                    for host in self.results.get("hosts", []) or []:
                        if isinstance(host, dict):
                            ip = host.get("ip")
                            agentless = host.get("agentless_fingerprint") or {}
                        else:
                            ip = getattr(host, "ip", None)
                            agentless = getattr(host, "agentless_fingerprint", {}) or {}
                        if ip and agentless:  # pragma: no cover
                            host_agentless[ip] = agentless
                    new_findings, suspected = filter_nuclei_false_positives(
                        new_findings,
                        host_agentless,
                        self.logger,
                        host_records=self.results.get("hosts", []),
                    )
                except Exception as filter_err:  # pragma: no cover
                    if self.logger:
                        self.logger.warning(
                            "Nuclei FP filter skipped on resume: %s", filter_err, exc_info=True
                        )

            merged = self._merge_nuclei_findings(new_findings)
            nuclei_summary = self.results.get("nuclei") or {}
            if not isinstance(nuclei_summary, dict):  # pragma: no cover
                nuclei_summary = {}
            nuclei_summary["findings"] = int(nuclei_summary.get("findings") or 0) + len(
                new_findings
            )
            nuclei_summary["findings_total"] = int(nuclei_summary.get("findings_total") or 0) + len(
                resume_result.get("findings") or []
            )
            nuclei_summary["findings_suspected"] = int(
                nuclei_summary.get("findings_suspected") or 0
            ) + len(suspected)
            combined_success = bool(nuclei_summary.get("success")) or bool(
                resume_result.get("success")
            )
            combined_error = nuclei_summary.get("error") or resume_result.get("error")
            if combined_error:
                nuclei_summary["error"] = combined_error
            if resume_result.get("budget_exceeded"):
                nuclei_summary["budget_exceeded"] = True
            nuclei_summary["profile"] = effective_profile
            nuclei_summary["profile_selected"] = selected_profile
            nuclei_summary["profile_effective"] = effective_profile
            nuclei_summary["auto_switched"] = bool(auto_switched)
            if base_output_path and isinstance(base_output_path, str):
                try:
                    nuclei_summary["output_file"] = os.path.relpath(base_output_path, output_dir)
                except Exception:  # pragma: no cover
                    nuclei_summary["output_file"] = base_output_path

            pending_after = resume_result.get("pending_targets") or []
            timeout_batches = resume_result.get("timeout_batches") or []
            failed_batches = resume_result.get("failed_batches") or []
            partial_flag = bool(resume_result.get("partial")) or bool(
                timeout_batches or failed_batches
            )

            if pending_after:
                partial_flag = True
                nuclei_summary["resume_pending"] = len(pending_after)
                resume_state["pending_targets"] = pending_after
                self._write_nuclei_resume_state(output_dir, resume_state)
            else:
                nuclei_summary.pop("resume_pending", None)
                self._clear_nuclei_resume_state(resume_path, output_dir)
            nuclei_summary["resume_count"] = int(resume_state.get("resume_count") or 0)
            nuclei_summary["last_resume_at"] = str(resume_state.get("last_resume_at") or "")
            nuclei_summary["resume_state_file"] = "nuclei_resume.json"

            if partial_flag:
                nuclei_summary["partial"] = True
                if timeout_batches:
                    existing_timeouts = nuclei_summary.get("timeout_batches") or []
                    nuclei_summary["timeout_batches"] = sorted(
                        set(existing_timeouts + list(timeout_batches))
                    )
                if failed_batches:
                    existing_failed = nuclei_summary.get("failed_batches") or []
                    nuclei_summary["failed_batches"] = sorted(
                        set(existing_failed + list(failed_batches))
                    )
            else:
                nuclei_summary.pop("partial", None)
                nuclei_summary.pop("timeout_batches", None)
                nuclei_summary.pop("failed_batches", None)

            nuclei_summary["success"] = self._resolve_nuclei_success(
                combined_success,
                partial=partial_flag,
                error=combined_error,
            )

            nuclei_summary["resume"] = {
                "added_findings": len(new_findings),
                "added_suspected": len(suspected),
                "pending_targets": len(pending_after),
            }
            self.results["nuclei"] = nuclei_summary

            if merged > 0:
                self.ui.print_status(self.ui.t("nuclei_resume_done", merged), "OK")
            else:
                self.ui.print_status(self.ui.t("nuclei_resume_done", 0), "INFO")

            if save_after:
                if session_log_started and not session_log_closed:
                    try:
                        from redaudit.utils.session_log import stop_session_log

                        session_log_path = stop_session_log()
                        session_log_closed = True
                        session_log_started = False
                        if session_log_path and self.logger:
                            self.logger.info("Session log saved: %s", session_log_path)
                    except Exception:  # pragma: no cover
                        if self.logger:
                            self.logger.debug("Failed to stop resume session log", exc_info=True)
                hosts = self.results.get("hosts") or []
                host_ips = []
                for host in hosts:
                    if isinstance(host, dict):
                        ip = host.get("ip")
                    else:
                        ip = getattr(host, "ip", None)
                    if ip:  # pragma: no cover
                        host_ips.append(ip)
                resume_finished_at = datetime.now()
                resume_elapsed = resume_finished_at - resume_started_at
                scan_start_time = self._resume_scan_start_time(resume_finished_at, resume_elapsed)
                generate_summary(self.results, self.config, host_ips, hosts, scan_start_time)
                self.save_results(partial=bool(resume_result.get("partial")))

            if resume_result.get("budget_exceeded"):
                self.ui.print_status(self.ui.t("nuclei_budget_exceeded"), "WARNING")
            timeout_batches = resume_result.get("timeout_batches") or []
            failed_batches = resume_result.get("failed_batches") or []
            if timeout_batches or failed_batches:
                self.ui.print_status(
                    self.ui.t("nuclei_partial", len(timeout_batches), len(failed_batches)),
                    "WARNING",
                )
            if pending_after:
                self.ui.print_status(self.ui.t("nuclei_resume_saved", resume_path), "WARNING")

            return bool(resume_result.get("success"))
        finally:
            if session_log_started and not session_log_closed:
                try:
                    from redaudit.utils.session_log import stop_session_log

                    session_log_path = stop_session_log()
                    if session_log_path and self.logger:
                        self.logger.info("Session log saved: %s", session_log_path)
                except Exception:  # pragma: no cover
                    if self.logger:
                        self.logger.debug("Failed to stop resume session log", exc_info=True)
            if inhibitor is not None:
                try:
                    inhibitor.stop()
                except Exception:  # pragma: no cover
                    pass

    def resume_nuclei_from_path(
        self,
        resume_path: str,
        *,
        override_max_runtime_minutes: Optional[int] = None,
        prompt_budget_override: bool = False,
    ) -> bool:
        try:
            if resume_path and os.path.isdir(resume_path):
                resume_path = os.path.join(resume_path, "nuclei_resume.json")
            resume_state = self._load_nuclei_resume_state(resume_path)
            if not resume_state:
                self.ui.print_status(self.ui.t("nuclei_resume_none"), "INFO")
                return False
            output_dir = resume_state.get("output_dir") or os.path.dirname(resume_path)
            return self._resume_nuclei_from_state(
                resume_state=resume_state,
                resume_path=resume_path,
                output_dir=output_dir,
                use_existing_results=False,
                save_after=True,
                override_max_runtime_minutes=override_max_runtime_minutes,
                prompt_budget_override=prompt_budget_override,
            )
        except KeyboardInterrupt:
            self.ui.print_status(self.ui.t("nuclei_resume_cancel"), "INFO")
            return False

    def resume_nuclei_interactive(self) -> bool:
        try:
            base_dir = get_default_reports_base_dir()
            while True:
                candidates = self._find_nuclei_resume_candidates(base_dir)
                if not candidates:
                    self.ui.print_status(self.ui.t("nuclei_resume_none"), "INFO")
                    return False

                options = [c["label"] for c in candidates]
                manage_idx = len(options)
                options.append(self.ui.t("nuclei_resume_manage"))
                back_idx = len(options)
                options.append(self.ui.t("wizard_go_back"))

                choice = self.ask_choice(self.ui.t("nuclei_resume_select"), options, default=0)
                if choice == back_idx:
                    self.ui.print_status(self.ui.t("nuclei_resume_cancel"), "INFO")
                    return False
                if choice == manage_idx:
                    manage_options = [
                        self.ui.t("nuclei_resume_delete_one"),
                        self.ui.t("nuclei_resume_delete_all"),
                        self.ui.t("wizard_go_back"),
                    ]
                    manage_choice = self.ask_choice(
                        self.ui.t("nuclei_resume_manage_select"), manage_options, default=0
                    )
                    if manage_choice == len(manage_options) - 1:
                        continue
                    if manage_choice == 0:
                        delete_options = [c["label"] for c in candidates]
                        delete_options.append(self.ui.t("wizard_go_back"))
                        delete_choice = self.ask_choice(
                            self.ui.t("nuclei_resume_delete_select"), delete_options, default=0
                        )
                        if delete_choice == len(delete_options) - 1:
                            continue
                        selected = candidates[delete_choice]
                        resume_path = str(selected.get("path") or "")
                        output_dir = selected.get("output_dir") or (
                            os.path.dirname(resume_path) if resume_path else ""
                        )
                        self._clear_nuclei_resume_state(resume_path, output_dir)
                        self.ui.print_status(
                            self.ui.t("nuclei_resume_deleted_one", selected.get("label") or ""),
                            "OK",
                        )
                        continue

                    confirm_delete_all = self.ask_yes_no(
                        self.ui.t("nuclei_resume_delete_all_confirm", len(candidates)),
                        default="no",
                    )
                    if not confirm_delete_all:
                        continue
                    deleted = 0
                    for candidate in candidates:
                        resume_path = str(candidate.get("path") or "")
                        output_dir = candidate.get("output_dir") or (
                            os.path.dirname(resume_path) if resume_path else ""
                        )
                        self._clear_nuclei_resume_state(resume_path, output_dir)
                        deleted += 1
                    self.ui.print_status(self.ui.t("nuclei_resume_deleted_all", deleted), "OK")
                    continue

                resume_path = candidates[choice]["path"]
                return self.resume_nuclei_from_path(resume_path, prompt_budget_override=True)
        except KeyboardInterrupt:
            self.ui.print_status(self.ui.t("nuclei_resume_cancel"), "INFO")
            return False
