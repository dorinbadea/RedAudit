#!/usr/bin/env python3
"""
RedAudit - Scan Wizard Flow Coordinator

Composition-first coordinator for interactive scan configuration flow.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Optional, Set

from redaudit.core.iot_scope_probes import IOT_PROBE_PACKS, normalize_iot_probe_packs
from redaudit.core.nuclei import is_nuclei_available, normalize_nuclei_exclude
from redaudit.core.scope_expansion import (
    LEAK_FOLLOW_ALLOWLIST_PROFILES,
    normalize_leak_follow_policy_pack,
    normalize_leak_follow_profiles,
)
from redaudit.core.wizard_service import WizardService
from redaudit.utils.constants import (
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    UDP_SCAN_MODE_FULL,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
    suggest_threads,
)
from redaudit.utils.paths import expand_user_path, get_default_reports_base_dir


class ScanWizardFlow:
    """Coordinator for interactive scan wizard steps and defaults handling."""

    WIZARD_BACK = WizardService.WIZARD_BACK

    def __init__(self, auditor: object) -> None:
        self._auditor = auditor

    def __getattr__(self, name: str):
        return getattr(self._auditor, name)

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
        nuclei_max_runtime = defaults_for_run.get("nuclei_max_runtime")
        if not isinstance(nuclei_max_runtime, int) or nuclei_max_runtime < 0:
            nuclei_max_runtime = 0
        self.config["nuclei_max_runtime"] = nuclei_max_runtime
        leak_follow_mode = defaults_for_run.get("leak_follow_mode")
        if leak_follow_mode not in ("off", "safe"):
            leak_follow_mode = "off"
        self.config["leak_follow_mode"] = leak_follow_mode
        leak_policy_pack = normalize_leak_follow_policy_pack(
            defaults_for_run.get("leak_follow_policy_pack")
        )
        self.config["leak_follow_policy_pack"] = leak_policy_pack
        leak_allowlist = defaults_for_run.get("leak_follow_allowlist")
        if isinstance(leak_allowlist, str):
            leak_allowlist = [leak_allowlist]
        if not isinstance(leak_allowlist, list):
            leak_allowlist = []
        self.config["leak_follow_allowlist"] = [
            str(item).strip() for item in leak_allowlist if str(item).strip()
        ]
        self.config["leak_follow_allowlist_profiles"] = normalize_leak_follow_profiles(
            defaults_for_run.get("leak_follow_allowlist_profiles")
        )
        leak_denylist = defaults_for_run.get("leak_follow_denylist")
        if isinstance(leak_denylist, str):
            leak_denylist = [leak_denylist]
        if not isinstance(leak_denylist, list):
            leak_denylist = []
        self.config["leak_follow_denylist"] = [
            str(item).strip() for item in leak_denylist if str(item).strip()
        ]
        iot_probes_mode = defaults_for_run.get("iot_probes_mode")
        if iot_probes_mode not in ("off", "safe"):
            iot_probes_mode = "off"
        self.config["iot_probes_mode"] = iot_probes_mode
        iot_probe_packs = normalize_iot_probe_packs(defaults_for_run.get("iot_probe_packs"))
        if not iot_probe_packs:
            iot_probe_packs = list(IOT_PROBE_PACKS.keys())
        self.config["iot_probe_packs"] = list(iot_probe_packs)
        iot_probe_budget = defaults_for_run.get("iot_probe_budget_seconds")
        if not isinstance(iot_probe_budget, int) or iot_probe_budget < 1 or iot_probe_budget > 300:
            iot_probe_budget = 20
        self.config["iot_probe_budget_seconds"] = iot_probe_budget
        iot_probe_timeout = defaults_for_run.get("iot_probe_timeout_seconds")
        if (
            not isinstance(iot_probe_timeout, int)
            or iot_probe_timeout < 1
            or iot_probe_timeout > 60
        ):
            iot_probe_timeout = 3
        self.config["iot_probe_timeout_seconds"] = iot_probe_timeout
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
        auditor_prompt = self._style_prompt_text(self.ui.t("auditor_name_q"))
        auditor_default_display = (
            self._style_default_value(auditor_default) if auditor_default else ""
        )
        auditor_name = input(f"{auditor_prompt} " f"[{auditor_default_display}]: ").strip()
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

        output_prompt = self._style_prompt_text(self.ui.t("output_dir_q"))
        default_output_display = self._style_default_value(default_output)
        output_dir = input(f"{output_prompt} " f"[{default_output_display}]: ").strip()
        if not output_dir:
            output_dir = default_output
        self.config["output_dir"] = expand_user_path(output_dir)

    @staticmethod
    def _normalize_csv_targets(raw_value: Any) -> List[str]:
        """Normalize comma-separated or list-based target values into a deduplicated list."""
        if raw_value is None:
            return []
        if isinstance(raw_value, str):
            raw_items = [raw_value]
        elif isinstance(raw_value, list):
            raw_items = raw_value
        else:
            return []

        normalized: List[str] = []
        seen: Set[str] = set()
        for chunk in raw_items:
            if chunk is None:
                continue
            for token in str(chunk).split(","):
                value = token.strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                normalized.append(value)
        return normalized

    def _leak_follow_available_for_run(self) -> bool:
        """Leak Following is only meaningful in full mode when Nuclei is enabled."""
        return bool(
            self.config.get("scan_vulnerabilities")
            and self.config.get("scan_mode") == "completo"
            and self.config.get("nuclei_enabled")
        )

    def _apply_scope_expansion_profile_defaults(self, defaults_for_run: Dict, profile: str) -> None:
        """Apply profile-aware defaults for scope expansion controls."""
        persisted_leak_mode = defaults_for_run.get("leak_follow_mode")
        if persisted_leak_mode not in ("off", "safe"):
            persisted_leak_mode = None

        persisted_iot_mode = defaults_for_run.get("iot_probes_mode")
        if persisted_iot_mode not in ("off", "safe"):
            persisted_iot_mode = None

        self.config["leak_follow_policy_pack"] = normalize_leak_follow_policy_pack(
            defaults_for_run.get("leak_follow_policy_pack")
        )
        self.config["leak_follow_allowlist_profiles"] = normalize_leak_follow_profiles(
            defaults_for_run.get("leak_follow_allowlist_profiles")
        )
        self.config["leak_follow_allowlist"] = self._normalize_csv_targets(
            defaults_for_run.get("leak_follow_allowlist")
        )
        self.config["leak_follow_denylist"] = self._normalize_csv_targets(
            defaults_for_run.get("leak_follow_denylist")
        )

        iot_packs = normalize_iot_probe_packs(defaults_for_run.get("iot_probe_packs"))
        self.config["iot_probe_packs"] = iot_packs or list(IOT_PROBE_PACKS.keys())

        iot_budget = defaults_for_run.get("iot_probe_budget_seconds")
        if not isinstance(iot_budget, int) or iot_budget < 1 or iot_budget > 300:
            iot_budget = 20
        self.config["iot_probe_budget_seconds"] = iot_budget

        iot_timeout = defaults_for_run.get("iot_probe_timeout_seconds")
        if not isinstance(iot_timeout, int) or iot_timeout < 1 or iot_timeout > 60:
            iot_timeout = 3
        self.config["iot_probe_timeout_seconds"] = iot_timeout

        if profile == "express":
            self.config["leak_follow_mode"] = "off"
            self.config["iot_probes_mode"] = "off"
            return

        if profile == "standard":
            self.config["leak_follow_mode"] = "off"
            self.config["iot_probes_mode"] = (
                persisted_iot_mode if persisted_iot_mode in ("off", "safe") else "off"
            )
            return

        if profile == "exhaustive":
            self.config["iot_probes_mode"] = (
                persisted_iot_mode if persisted_iot_mode in ("off", "safe") else "safe"
            )
            default_leak_mode = (
                persisted_leak_mode if persisted_leak_mode in ("off", "safe") else "safe"
            )
            self.config["leak_follow_mode"] = (
                default_leak_mode if self._leak_follow_available_for_run() else "off"
            )
            return

        # Custom profile keeps persisted modes with safe fallbacks.
        self.config["leak_follow_mode"] = (
            persisted_leak_mode if persisted_leak_mode in ("off", "safe") else "off"
        )
        self.config["iot_probes_mode"] = (
            persisted_iot_mode if persisted_iot_mode in ("off", "safe") else "off"
        )

    def _ask_scope_expansion_advanced(self) -> None:
        """Prompt optional advanced scope expansion settings."""
        policy_options = [
            ("safe-default", self.ui.t("scope_expansion_policy_pack_safe_default")),
            ("safe-strict", self.ui.t("scope_expansion_policy_pack_safe_strict")),
            ("safe-extended", self.ui.t("scope_expansion_policy_pack_safe_extended")),
        ]
        policy_values = [value for value, _label in policy_options]
        policy_labels = [label for _value, label in policy_options]
        current_pack = normalize_leak_follow_policy_pack(self.config.get("leak_follow_policy_pack"))
        default_policy_idx = (
            policy_values.index(current_pack) if current_pack in policy_values else 0
        )
        policy_choice = self.ask_choice(
            self.ui.t("scope_expansion_policy_pack_q"), policy_labels, default_policy_idx
        )
        self.config["leak_follow_policy_pack"] = policy_values[policy_choice]

        mode_options = [
            self.ui.t("scope_expansion_automatic_recommended"),
            self.ui.t("scope_expansion_manual_option"),
        ]
        default_allowlist_mode = (
            1
            if self.config.get("leak_follow_allowlist_profiles")
            or self.config.get("leak_follow_allowlist")
            else 0
        )
        allowlist_mode_choice = self.ask_choice(
            self.ui.t("scope_expansion_allowlist_mode_q"),
            mode_options,
            default_allowlist_mode,
        )
        if allowlist_mode_choice == 0:
            self.config["leak_follow_allowlist_profiles"] = []
            self.config["leak_follow_allowlist"] = []
            self.ui.print_status(self.ui.t("scope_expansion_auto_defaults_applied"), "INFO")
        else:
            profiles_prompt = self._style_prompt_text(
                self.ui.t("scope_expansion_allowlist_profiles_q")
            )
            profiles_hint = self.ui.t(
                "scope_expansion_allowlist_profiles_hint",
                ", ".join(LEAK_FOLLOW_ALLOWLIST_PROFILES),
            )
            profiles_input = input(f"{profiles_prompt} ({profiles_hint}): ").strip()
            if profiles_input:
                self.config["leak_follow_allowlist_profiles"] = normalize_leak_follow_profiles(
                    [profiles_input]
                )
            else:
                self.config["leak_follow_allowlist_profiles"] = []
                self.ui.print_status(self.ui.t("scope_expansion_empty_manual_fallback"), "INFO")

            allow_prompt = self._style_prompt_text(self.ui.t("scope_expansion_allowlist_q"))
            allow_hint = self.ui.t("scope_expansion_allowlist_hint")
            allow_input = input(f"{allow_prompt} ({allow_hint}): ").strip()
            if allow_input:
                self.config["leak_follow_allowlist"] = self._normalize_csv_targets(allow_input)
            else:
                self.config["leak_follow_allowlist"] = []
                self.ui.print_status(self.ui.t("scope_expansion_empty_manual_fallback"), "INFO")

        denylist_options = [self.ui.t("yes_option"), self.ui.t("no_default")]
        add_denylist_choice = self.ask_choice(
            self.ui.t("scope_expansion_add_denylist_q"),
            denylist_options,
            1,
        )
        if add_denylist_choice == 0:
            deny_prompt = self._style_prompt_text(self.ui.t("scope_expansion_denylist_q"))
            deny_hint = self.ui.t("scope_expansion_denylist_hint")
            deny_input = input(f"{deny_prompt} ({deny_hint}): ").strip()
            self.config["leak_follow_denylist"] = self._normalize_csv_targets(deny_input)
        else:
            self.config["leak_follow_denylist"] = []

        known_packs = list(IOT_PROBE_PACKS.keys())
        current_packs = normalize_iot_probe_packs(self.config.get("iot_probe_packs"))
        iot_mode_default = 0 if not current_packs or set(current_packs) == set(known_packs) else 1
        iot_packs_mode_choice = self.ask_choice(
            self.ui.t("scope_expansion_iot_packs_mode_q"),
            mode_options,
            iot_mode_default,
        )
        if iot_packs_mode_choice == 0:
            self.config["iot_probe_packs"] = known_packs
            self.ui.print_status(self.ui.t("scope_expansion_auto_defaults_applied"), "INFO")
        else:
            packs_prompt = self._style_prompt_text(self.ui.t("scope_expansion_iot_packs_q"))
            packs_hint = self.ui.t(
                "scope_expansion_iot_packs_hint",
                ", ".join(sorted(IOT_PROBE_PACKS.keys())),
            )
            packs_input = input(f"{packs_prompt} ({packs_hint}): ").strip()
            normalized_packs = normalize_iot_probe_packs([packs_input] if packs_input else [])
            if normalized_packs:
                self.config["iot_probe_packs"] = normalized_packs
            else:
                self.config["iot_probe_packs"] = known_packs
                self.ui.print_status(self.ui.t("scope_expansion_empty_manual_fallback"), "INFO")

        budget_default = self.config.get("iot_probe_budget_seconds", 20)
        if not isinstance(budget_default, int) or budget_default < 1 or budget_default > 300:
            budget_default = 20
        self.config["iot_probe_budget_seconds"] = self.ask_number(
            self.ui.t("scope_expansion_iot_budget_q"),
            default=budget_default,
            min_val=1,
            max_val=300,
        )

        timeout_default = self.config.get("iot_probe_timeout_seconds", 3)
        if not isinstance(timeout_default, int) or timeout_default < 1 or timeout_default > 60:
            timeout_default = 3
        self.config["iot_probe_timeout_seconds"] = self.ask_number(
            self.ui.t("scope_expansion_iot_timeout_q"),
            default=timeout_default,
            min_val=1,
            max_val=60,
        )

    def _ask_scope_expansion_quick(
        self,
        *,
        profile: str,
        step_num: Optional[int] = None,
        total_steps: Optional[int] = None,
    ) -> Optional[bool]:
        """Prompt quick scope expansion controls. Returns None when user chose back."""

        def _ask_toggle(
            question: str, yes_label: str, no_label: str, default_yes: bool
        ) -> Optional[bool]:
            options = [yes_label, no_label]
            default_idx = 0 if default_yes else 1
            if isinstance(step_num, int) and isinstance(total_steps, int):
                choice = self.ask_choice_with_back(
                    question,
                    options,
                    default_idx,
                    step_num=step_num,
                    total_steps=total_steps,
                )
                if choice == self.WIZARD_BACK:
                    return None
                return choice == 0
            choice = self.ask_choice(question, options, default_idx)
            return choice == 0

        no_label = self.ui.t("no_default")

        if profile == "standard":
            iot_enabled = _ask_toggle(
                self.ui.t("scope_expansion_quick_q_standard"),
                self.ui.t("scope_expansion_yes_iot"),
                no_label,
                default_yes=self.config.get("iot_probes_mode") == "safe",
            )
            if iot_enabled is None:
                return None
            self.config["iot_probes_mode"] = "safe" if iot_enabled else "off"
            self.config["leak_follow_mode"] = "off"
            self.ui.print_status(self.ui.t("scope_expansion_standard_leak_note"), "INFO")
            if not iot_enabled:
                return True
            advanced_enabled = _ask_toggle(
                self.ui.t("scope_expansion_advanced_q"),
                self.ui.t("yes_option"),
                no_label,
                default_yes=False,
            )
            if advanced_enabled is None:
                return None
            if advanced_enabled:
                self._ask_scope_expansion_advanced()
            else:
                self.ui.print_status(self.ui.t("scope_expansion_advanced_skipped_defaults"), "INFO")
            return True

        if profile == "exhaustive":
            default_enabled = (
                self.config.get("iot_probes_mode") == "safe"
                or self.config.get("leak_follow_mode") == "safe"
            )
            scope_enabled = _ask_toggle(
                self.ui.t("scope_expansion_quick_q_exhaustive"),
                self.ui.t("scope_expansion_yes_combined"),
                no_label,
                default_yes=default_enabled,
            )
            if scope_enabled is None:
                return None
            if not scope_enabled:
                self.config["iot_probes_mode"] = "off"
                self.config["leak_follow_mode"] = "off"
                return True
            self.config["iot_probes_mode"] = "safe"
            if self._leak_follow_available_for_run():
                self.config["leak_follow_mode"] = "safe"
            else:
                self.config["leak_follow_mode"] = "off"
                self.ui.print_status(self.ui.t("scope_expansion_leak_dependency_note"), "INFO")
            advanced_enabled = _ask_toggle(
                self.ui.t("scope_expansion_advanced_q"),
                self.ui.t("yes_option"),
                no_label,
                default_yes=False,
            )
            if advanced_enabled is None:
                return None
            if advanced_enabled:
                self._ask_scope_expansion_advanced()
            else:
                self.ui.print_status(self.ui.t("scope_expansion_advanced_skipped_defaults"), "INFO")
            return True

        # Custom profile: separate toggles for IoT and Leak Following.
        iot_enabled = _ask_toggle(
            self.ui.t("scope_expansion_iot_q"),
            self.ui.t("scope_expansion_yes_iot"),
            no_label,
            default_yes=self.config.get("iot_probes_mode") == "safe",
        )
        if iot_enabled is None:
            return None
        self.config["iot_probes_mode"] = "safe" if iot_enabled else "off"

        if self._leak_follow_available_for_run():
            leak_enabled = _ask_toggle(
                self.ui.t("scope_expansion_leak_q"),
                self.ui.t("scope_expansion_yes_leak"),
                no_label,
                default_yes=self.config.get("leak_follow_mode") == "safe",
            )
            if leak_enabled is None:
                return None
            self.config["leak_follow_mode"] = "safe" if leak_enabled else "off"
        else:
            self.config["leak_follow_mode"] = "off"
            self.ui.print_status(self.ui.t("scope_expansion_leak_dependency_note"), "INFO")

        if (
            self.config.get("iot_probes_mode") != "safe"
            and self.config.get("leak_follow_mode") != "safe"
        ):
            return True

        advanced_enabled = _ask_toggle(
            self.ui.t("scope_expansion_advanced_q"),
            self.ui.t("yes_option"),
            no_label,
            default_yes=False,
        )
        if advanced_enabled is None:
            return None
        if advanced_enabled:
            self._ask_scope_expansion_advanced()
        else:
            self.ui.print_status(self.ui.t("scope_expansion_advanced_skipped_defaults"), "INFO")
        return True

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

        def _ask_yes_no_with_back(question: str, default: str = "yes") -> Optional[bool]:
            default = default.lower()
            is_yes_default = default in ("yes", "y", "s", "si", "sí")
            options = [
                self.ui.t("yes_default") if is_yes_default else self.ui.t("yes_option"),
                self.ui.t("no_default") if not is_yes_default else self.ui.t("no_option"),
            ]
            default_idx = 0 if is_yes_default else 1
            choice = self.ask_choice_with_back(
                question,
                options,
                default_idx,
                step_num=2,
                total_steps=2,
            )
            if choice == self.WIZARD_BACK:
                return None
            return choice == 0

        def _ask_nuclei_coverage_with_back(
            *, default_full_coverage: bool, step_num: int, total_steps: int
        ) -> Optional[bool]:
            options = [
                self.ui.t("nuclei_coverage_adaptive"),
                self.ui.t("nuclei_coverage_full"),
            ]
            choice = self.ask_choice_with_back(
                self.ui.t("nuclei_coverage_mode_q"),
                options,
                default=1 if default_full_coverage else 0,
                step_num=step_num,
                total_steps=total_steps,
            )
            if choice == self.WIZARD_BACK:
                return None
            return choice == 1

        def _announce_nuclei_coverage_mode(full_coverage: bool) -> None:
            msg_key = (
                "nuclei_coverage_selected_full"
                if full_coverage
                else "nuclei_coverage_selected_adaptive"
            )
            self.ui.print_status(self.ui.t(msg_key), "INFO")

        # v3.9.0: Loop for profile selection with back navigation from timing
        while True:
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
                profile_idx = self.ask_choice(
                    self.ui.t("wizard_profile_q"), profile_options, default=1
                )

                # For profiles that ask timing, include a back option
                if profile_idx in (1, 2):  # Standard or Exhaustive
                    timing_options = [
                        self.ui.t("timing_stealth"),
                        self.ui.t("timing_normal"),
                        self.ui.t("timing_aggressive"),
                        self.ui.t("go_back"),
                    ]
                    timing_choice = self.ask_choice(
                        self.ui.t("timing_q"), timing_options, default=1
                    )
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
                self._apply_scope_expansion_profile_defaults(defaults_for_run, "express")
                persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
                low_impact_default = "yes" if persisted_low_impact else "no"
                low_impact = _ask_yes_no_with_back(
                    self.ui.t("low_impact_enrichment_q"), default=low_impact_default
                )
                if low_impact is None:
                    continue
                self.config["low_impact_enrichment"] = low_impact
                self.ui.print_status(self.ui.t("scope_expansion_express_forced_off"), "INFO")
                # v3.9.0: Ask auditor name and output dir for all profiles
                self._ask_auditor_and_output_dir(defaults_for_run)
                self.rate_limit_delay = 0.0  # Express = always fast
                self.config["hyperscan_mode"] = "auto"  # v4.3: Fast = auto-detect best mode
                self.config["trust_hyperscan"] = True  # v4.6.0: Max speed
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
                self._apply_scope_expansion_profile_defaults(defaults_for_run, "standard")
                persisted_low_impact = defaults_for_run.get("low_impact_enrichment")
                low_impact_default = "yes" if persisted_low_impact else "no"
                low_impact = _ask_yes_no_with_back(
                    self.ui.t("low_impact_enrichment_q"), default=low_impact_default
                )
                if low_impact is None:
                    continue
                self.config["low_impact_enrichment"] = low_impact
                if (
                    self._ask_scope_expansion_quick(profile="standard", step_num=2, total_steps=2)
                    is None
                ):
                    continue
                # v3.9.0: Ask auditor name and output dir for all profiles
                self._ask_auditor_and_output_dir(defaults_for_run)

                # v4.5.0: Ask for Authentication (Phase 4)
                auth_config = self.ask_auth_config()
                self.config.update(auth_config)

                # v3.9.0: Apply timing settings
                self.config["nmap_timing"] = timing_nmap_template
                if timing_threads_boost:
                    self.config["threads"] = MAX_THREADS
                self.rate_limit_delay = timing_delay
                # v4.3: HyperScan mode based on timing
                if timing_nmap_template == "T1":  # Stealth
                    self.config["hyperscan_mode"] = "connect"  # Connect is stealthier than SYN
                else:
                    self.config["hyperscan_mode"] = "auto"  # Let it auto-detect
                trust_hyperscan = _ask_yes_no_with_back(
                    self.ui.t("trust_hyperscan_q"),
                    default="yes",
                )
                if trust_hyperscan is None:
                    continue
                self.config["trust_hyperscan"] = trust_hyperscan
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

                # Vulnerability scanning - enabled (nikto, whatweb, etc.)
                self.config["scan_vulnerabilities"] = True

                # v4.8.0: Nuclei OFF by default (use --nuclei to enable)
                # Reason: Slow on web-dense networks, marginal value for network audits
                # v4.8.0: Nuclei OFF by default (use --nuclei to enable)
                # PROMPT: Ask usage for granular control in Exhaustive mode
                nuclei_enabled = _ask_yes_no_with_back(self.ui.t("nuclei_q"), default="no")
                if nuclei_enabled is None:
                    continue
                self.config["nuclei_enabled"] = nuclei_enabled
                fatigue_default = defaults_for_run.get("nuclei_fatigue_limit")
                if not isinstance(fatigue_default, int) or fatigue_default < 0:
                    fatigue_default = 3
                if fatigue_default > 10:
                    fatigue_default = 10
                # v4.11.0: Nuclei profile selector (full/balanced/fast)
                if self.config["nuclei_enabled"]:
                    profile_opts = [
                        self.ui.t("nuclei_full"),
                        self.ui.t("nuclei_balanced"),
                        self.ui.t("nuclei_fast"),
                    ]
                    profile_idx = self.ask_choice_with_back(
                        self.ui.t("nuclei_profile_q"),
                        profile_opts,
                        default=1,
                        step_num=2,
                        total_steps=2,
                    )
                    if profile_idx == self.WIZARD_BACK:
                        continue
                    self.config["nuclei_profile"] = ["full", "balanced", "fast"][profile_idx]
                    # v4.17: Full coverage option - default YES only when Nuclei profile is full
                    persisted_full_coverage = defaults_for_run.get("nuclei_full_coverage")
                    full_coverage_default = (
                        bool(persisted_full_coverage)
                        if isinstance(persisted_full_coverage, bool)
                        else self.config["nuclei_profile"] == "full"
                    )
                    full_coverage = _ask_nuclei_coverage_with_back(
                        default_full_coverage=full_coverage_default,
                        step_num=2,
                        total_steps=2,
                    )
                    if full_coverage is None:
                        continue
                    self.config["nuclei_full_coverage"] = full_coverage
                    _announce_nuclei_coverage_mode(full_coverage)
                    self.ui.print_status(self.ui.t("nuclei_optimization_note"), "INFO")
                    runtime_default = defaults_for_run.get("nuclei_max_runtime")
                    if not isinstance(runtime_default, int) or runtime_default < 0:
                        runtime_default = 0
                    self.config["nuclei_max_runtime"] = self.ask_number(
                        self.ui.t("nuclei_budget_q"),
                        default=runtime_default,
                        min_val=0,
                        max_val=1440,
                    )
                    self.config["nuclei_fatigue_limit"] = self.ask_number(
                        self.ui.t("nuclei_fatigue_q"),
                        default=fatigue_default,
                        min_val=0,
                        max_val=10,
                    )
                    exclude_default = defaults_for_run.get("nuclei_exclude")
                    if isinstance(exclude_default, list):
                        exclude_default = ", ".join([str(item) for item in exclude_default if item])
                    elif not isinstance(exclude_default, str):
                        exclude_default = ""
                    exclude_prompt = self._style_prompt_text(self.ui.t("nuclei_exclude_q"))
                    exclude_default_display = (
                        self._style_default_value(exclude_default) if exclude_default else ""
                    )
                    exclude_text = input(
                        f"{exclude_prompt} " f"[{exclude_default_display}]: "
                    ).strip()
                    if not exclude_text:
                        exclude_text = exclude_default
                    self.config["nuclei_exclude"] = normalize_nuclei_exclude(
                        [exclude_text] if exclude_text else []
                    )
                else:
                    self.config["nuclei_profile"] = "balanced"  # Default for non-interactive
                    self.config["nuclei_full_coverage"] = False
                    self.config["nuclei_max_runtime"] = 0
                    self.config["nuclei_fatigue_limit"] = fatigue_default
                    self.config["nuclei_exclude"] = normalize_nuclei_exclude(
                        [defaults_for_run.get("nuclei_exclude")]
                        if defaults_for_run.get("nuclei_exclude")
                        else []
                    )
                self._apply_scope_expansion_profile_defaults(defaults_for_run, "exhaustive")
                if (
                    self._ask_scope_expansion_quick(profile="exhaustive", step_num=2, total_steps=2)
                    is None
                ):
                    continue

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

                # v3.10.1: Auto-enable Phase 0 in Exhaustive mode (Goal: maximize information)
                self.config["low_impact_enrichment"] = True

                # v4.2: Enable web app security tools in Exhaustive (full assessment)
                if shutil.which("zap.sh"):
                    self.config["zap_enabled"] = True
                # SQLMap: level 3 = thorough, risk 2 = medium-high (risk 3 = destructive)
                self.config["sqlmap_level"] = 3
                self.config["sqlmap_risk"] = 2

                # v3.9.0: Ask auditor name and output dir for all profiles
                self._ask_auditor_and_output_dir(defaults_for_run)

                # v4.5.0: Ask for Authentication (Phase 4)
                auth_config = self.ask_auth_config()
                self.config.update(auth_config)

                # Rate limiting - already asked in profile selection loop
                self.rate_limit_delay = timing_delay
                # v4.3: HyperScan mode based on timing (Stealth = connect, else auto)
                if timing_nmap_template == "T1":  # Stealth
                    self.config["hyperscan_mode"] = "connect"
                else:
                    self.config["hyperscan_mode"] = "auto"
                trust_hyperscan = _ask_yes_no_with_back(
                    self.ui.t("trust_hyperscan_q"),
                    default="no",
                )
                if trust_hyperscan is None:
                    continue
                self.config["trust_hyperscan"] = trust_hyperscan
                return

            if profile_choice == 3:
                break

        # PROFILE 3: Custom - Full wizard with 10 steps
        # v3.8.1: Wizard step machine for "Cancel" navigation

        self._apply_scope_expansion_profile_defaults(defaults_for_run, "custom")
        TOTAL_STEPS = 10
        step = 1

        # Store choices for navigation (allows going back and reusing previous values)
        wizard_state: Dict = {}
        self.ui.print_status(self.ui.t("wizard_custom_intro"), "INFO")

        while step <= TOTAL_STEPS:  # pragma: no cover
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

                # v4.3: HyperScan mode selection
                hyperscan_options = [
                    self.ui.t("hyperscan_auto"),
                    self.ui.t("hyperscan_connect"),
                    self.ui.t("hyperscan_syn"),
                ]
                persisted_hyperscan = defaults_for_run.get("hyperscan_mode", "auto")
                hyperscan_idx_map = {"auto": 0, "connect": 1, "syn": 2}
                default_hs_idx = wizard_state.get(
                    "hyperscan_idx", hyperscan_idx_map.get(persisted_hyperscan, 0)
                )
                hs_choice = self.ask_choice_with_back(
                    self.ui.t("hyperscan_mode_q"),
                    hyperscan_options,
                    default_hs_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if hs_choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["hyperscan_idx"] = hs_choice
                self.config["hyperscan_mode"] = ["auto", "connect", "syn"][hs_choice]

                # v4.6.0: Trust HyperScan (optimization)
                # Ask if we should trust discovery results to speed up deep scans
                self.config["trust_hyperscan"] = self.ask_yes_no(
                    self.ui.t("trust_hyperscan_q"),
                    default="yes" if defaults_for_run.get("trust_hyperscan") else "no",
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

                # Nuclei (conditional) - v4.8.0: OFF by default due to slow scans
                self.config["nuclei_enabled"] = False
                self.config["nuclei_profile"] = "balanced"  # Default
                fatigue_default = defaults_for_run.get("nuclei_fatigue_limit")
                if not isinstance(fatigue_default, int) or fatigue_default < 0:
                    fatigue_default = 3
                if fatigue_default > 10:
                    fatigue_default = 10
                if (
                    self.config.get("scan_vulnerabilities")
                    and self.config.get("scan_mode") == "completo"
                    and is_nuclei_available()
                ):
                    # v4.8.0: Default to "no" - Nuclei is slow on web-dense networks
                    self.config["nuclei_enabled"] = self.ask_yes_no(
                        self.ui.t("nuclei_q"),
                        default="no",
                    )
                    # v4.11.0: Nuclei profile selector (full/balanced/fast)
                    if self.config["nuclei_enabled"]:
                        profile_opts = [
                            self.ui.t("nuclei_full"),
                            self.ui.t("nuclei_balanced"),
                            self.ui.t("nuclei_fast"),
                        ]
                        profile_idx = self.ask_choice(
                            self.ui.t("nuclei_profile_q"), profile_opts, default=1
                        )
                        self.config["nuclei_profile"] = ["full", "balanced", "fast"][profile_idx]
                        # v4.17: Full coverage option - default YES only when Nuclei profile is full
                        persisted_full_coverage = defaults_for_run.get("nuclei_full_coverage")
                        full_coverage_default = (
                            bool(persisted_full_coverage)
                            if isinstance(persisted_full_coverage, bool)
                            else self.config["nuclei_profile"] == "full"
                        )
                        full_coverage = _ask_nuclei_coverage_with_back(
                            default_full_coverage=full_coverage_default,
                            step_num=step,
                            total_steps=TOTAL_STEPS,
                        )
                        if full_coverage is None:
                            continue
                        self.config["nuclei_full_coverage"] = full_coverage
                        _announce_nuclei_coverage_mode(full_coverage)
                        self.ui.print_status(self.ui.t("nuclei_optimization_note"), "INFO")
                        runtime_default = defaults_for_run.get("nuclei_max_runtime")
                        if not isinstance(runtime_default, int) or runtime_default < 0:
                            runtime_default = 0
                        self.config["nuclei_max_runtime"] = self.ask_number(
                            self.ui.t("nuclei_budget_q"),
                            default=runtime_default,
                            min_val=0,
                            max_val=1440,
                        )
                        self.config["nuclei_fatigue_limit"] = self.ask_number(
                            self.ui.t("nuclei_fatigue_q"),
                            default=fatigue_default,
                            min_val=0,
                            max_val=10,
                        )
                        exclude_default = defaults_for_run.get("nuclei_exclude")
                        if isinstance(exclude_default, list):
                            exclude_default = ", ".join(
                                [str(item) for item in exclude_default if item]
                            )
                        elif not isinstance(exclude_default, str):
                            exclude_default = ""
                        exclude_prompt = self._style_prompt_text(self.ui.t("nuclei_exclude_q"))
                        exclude_default_display = (
                            self._style_default_value(exclude_default) if exclude_default else ""
                        )
                        exclude_text = input(
                            f"{exclude_prompt} " f"[{exclude_default_display}]: "
                        ).strip()
                        if not exclude_text:
                            exclude_text = exclude_default
                        self.config["nuclei_exclude"] = normalize_nuclei_exclude(
                            [exclude_text] if exclude_text else []
                        )
                    else:
                        self.config["nuclei_full_coverage"] = False
                        self.config["nuclei_max_runtime"] = 0
                        self.config["nuclei_fatigue_limit"] = fatigue_default
                        self.config["nuclei_exclude"] = normalize_nuclei_exclude(
                            [defaults_for_run.get("nuclei_exclude")]
                            if defaults_for_run.get("nuclei_exclude")
                            else []
                        )
                else:
                    self.config["nuclei_fatigue_limit"] = fatigue_default
                    self.config["nuclei_exclude"] = normalize_nuclei_exclude(
                        [defaults_for_run.get("nuclei_exclude")]
                        if defaults_for_run.get("nuclei_exclude")
                        else []
                    )
                # Only ask if vuln scan is enabled
                if self.config.get("scan_vulnerabilities"):
                    sql_opts = [
                        self.ui.t("sqlmap_l1"),
                        self.ui.t("sqlmap_l3"),
                        self.ui.t("sqlmap_risk"),
                        self.ui.t("sqlmap_extreme"),
                    ]
                    sql_map_vals = {
                        0: (1, 1),
                        1: (3, 1),
                        2: (3, 2),
                        3: (5, 3),
                    }
                    persisted_level = defaults_for_run.get("sqlmap_level", 1)
                    persisted_risk = defaults_for_run.get("sqlmap_risk", 1)

                    # Determine default index
                    def_sql_idx = 0
                    for idx, (l, r) in sql_map_vals.items():
                        if l == persisted_level and r == persisted_risk:
                            def_sql_idx = idx
                            break

                    def_sql_idx = wizard_state.get("sqlmap_idx", def_sql_idx)

                    sql_choice = self.ask_choice_with_back(
                        self.ui.t("sqlmap_config_q"),
                        sql_opts,
                        def_sql_idx,
                        step_num=step,
                        total_steps=TOTAL_STEPS,
                    )

                    if sql_choice == self.WIZARD_BACK:
                        # Re-run Step 3 logic (ask Vuln Scan again)
                        continue

                    wizard_state["sqlmap_idx"] = sql_choice
                    self.config["sqlmap_level"] = sql_map_vals[sql_choice][0]
                    self.config["sqlmap_risk"] = sql_map_vals[sql_choice][1]

                    # v4.2: OWASP ZAP (Custom profile)
                    zap_def_idx = wizard_state.get("zap_idx", 1)  # Default: No
                    zap_choice = self.ask_choice_with_back(
                        self.ui.t("zap_q"),
                        [self.ui.t("yes_option"), self.ui.t("no_option")],
                        zap_def_idx,
                        step_num=step,
                        total_steps=TOTAL_STEPS,
                    )

                    if zap_choice == self.WIZARD_BACK:
                        continue

                    wizard_state["zap_idx"] = zap_choice
                    self.config["zap_enabled"] = zap_choice == 0

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
            # STEP 5: UDP & Topology
            # ═══════════════════════════════════════════════════════════════════
            elif step == 5:
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
            # STEP 6: Net Discovery & Red Team
            # ═══════════════════════════════════════════════════════════════════
            elif step == 6:
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
                        # v3.10.1: Masscan strategy (if available)
                        if shutil.which("masscan"):
                            # Ask strategy
                            persisted_masscan = defaults_for_run.get("net_discovery_masscan")
                            default_mz = "yes" if persisted_masscan is not False else "no"
                            self.config["net_discovery_masscan"] = self.ask_yes_no(
                                self.ui.t("redteam_masscan_q"), default=default_mz
                            )
                        else:
                            self.config["net_discovery_masscan"] = False

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
                                f"{self.ui.t('kerberos_realm_q')} " f"[{persisted_realm}]: "
                            ).strip()
                            self.config["net_discovery_kerberos_realm"] = (
                                realm or persisted_realm or None
                            )

                            persisted_userlist = (
                                defaults_for_run.get("net_discovery_kerberos_userlist") or ""
                            )
                            userlist = input(
                                f"{self.ui.t('kerberos_userlist_q')} " f"[{persisted_userlist}]: "
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
            # STEP 7: Authenticated Scanning (Phase 4)
            # ═══════════════════════════════════════════════════════════════════
            elif step == 7:
                auth_options = [
                    self.ui.t("yes_option") + " — " + self.ui.t("auth_scan_opt"),
                    self.ui.t("no_option"),
                ]
                # Default: No, unless cli arg provided
                has_cli_auth = bool(
                    self.config.get("auth_ssh_user") or self.config.get("auth_ssh_key")
                )
                default_idx = 0 if has_cli_auth else 1
                default_idx = wizard_state.get("auth_idx", default_idx)

                choice = self.ask_choice_with_back(
                    self.ui.t("auth_scan_q"),
                    auth_options,
                    default_idx,
                    step_num=step,
                    total_steps=TOTAL_STEPS,
                )
                if choice == self.WIZARD_BACK:
                    step -= 1
                    continue

                wizard_state["auth_idx"] = choice

                if choice == 0:
                    # Yes - Configure Authentication via Wizard
                    # v4.5.1: Use shared wizard logic (Phase 4.1 Multi-Credential)
                    auth_cfg = self.ask_auth_config(skip_intro=True)

                    if not auth_cfg.get("auth_enabled"):
                        # User backed out of configuration details -> re-ask Step 7
                        continue

                    self.config.update(auth_cfg)

                else:
                    # Disabled
                    self.config["auth_enabled"] = False
                    self.config["auth_ssh_user"] = None
                    self.config["auth_credentials"] = []
                    if self.config.get("save_defaults_wizard"):
                        self._save_run_defaults(defaults_for_run)

                step += 1
                continue  # pragma: no cover

            # ═══════════════════════════════════════════════════════════════════
            # STEP 8: Windows Verification
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

                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 9: Scope Expansion
            # ═══════════════════════════════════════════════════════════════════
            elif step == 9:
                self.ui.print_status(
                    f"[{step}/{TOTAL_STEPS}] " + self.ui.t("scope_expansion_step_title"),
                    "INFO",
                )
                if (
                    self._ask_scope_expansion_quick(
                        profile="custom", step_num=step, total_steps=TOTAL_STEPS
                    )
                    is None
                ):
                    step -= 1
                    continue
                step += 1
                continue

            # ═══════════════════════════════════════════════════════════════════
            # STEP 10: Output Directory & Webhook
            # ═══════════════════════════════════════════════════════════════════
            elif step == 10:
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
                auditor_name = input(f"{auditor_prompt} " f"[{auditor_default}]: ").strip()
                if not auditor_name:
                    auditor_name = auditor_default
                auditor_name = auditor_name.strip()
                self.config["auditor_name"] = auditor_name if auditor_name else None
                wizard_state["auditor_name"] = self.config["auditor_name"] or ""

                default_reports = get_default_reports_base_dir()
                persisted_output = defaults_for_run.get("output_dir")
                if isinstance(persisted_output, str) and persisted_output.strip():
                    default_reports = expand_user_path(persisted_output.strip())

                out_dir = input(f"{self.ui.t('output_dir')} " f"[{default_reports}]: ").strip()
                if not out_dir:
                    out_dir = default_reports
                self.config["output_dir"] = expand_user_path(out_dir)

                # TXT and HTML always on
                self.config["save_txt_report"] = True
                self.config["save_html_report"] = True

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

        def fmt_runtime_minutes(val):
            if val is None:
                return "-"
            try:
                minutes = int(val)
            except Exception:
                return "-"
            if minutes < 0:
                minutes = 0
            return f"{minutes} min"

        def fmt_scope_mode(leak_mode: Any, iot_mode: Any) -> str:
            leak = leak_mode if leak_mode in ("off", "safe") else "off"
            iot = iot_mode if iot_mode in ("off", "safe") else "off"
            return (
                f"{self.ui.t('defaults_summary_leak_mode_label')}={leak}; "
                f"{self.ui.t('defaults_summary_iot_mode_label')}={iot}"
            )

        def fmt_policy(val: Any) -> str:
            normalized = normalize_leak_follow_policy_pack(val)
            labels = {
                "safe-default": self.ui.t("scope_expansion_policy_pack_safe_default"),
                "safe-strict": self.ui.t("scope_expansion_policy_pack_safe_strict"),
                "safe-extended": self.ui.t("scope_expansion_policy_pack_safe_extended"),
            }
            return labels.get(normalized, normalized)

        def fmt_packs(val: Any) -> str:
            packs = normalize_iot_probe_packs(val)
            if not packs:
                return "-"
            known_packs = list(IOT_PROBE_PACKS.keys())
            if set(packs) == set(known_packs):
                return self.ui.t("scope_expansion_automatic_all_packs")
            return ", ".join(packs)

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
                "defaults_summary_nuclei_runtime",
                fmt_runtime_minutes(persisted_defaults.get("nuclei_max_runtime")),
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
            (
                "defaults_summary_scope_expansion",
                fmt_scope_mode(
                    persisted_defaults.get("leak_follow_mode"),
                    persisted_defaults.get("iot_probes_mode"),
                ),
            ),
            (
                "defaults_summary_leak_follow",
                fmt_policy(persisted_defaults.get("leak_follow_policy_pack")),
            ),
            (
                "defaults_summary_iot_probes",
                (
                    f"packs={fmt_packs(persisted_defaults.get('iot_probe_packs'))}; "
                    f"budget={persisted_defaults.get('iot_probe_budget_seconds') or 20}s; "
                    f"timeout={persisted_defaults.get('iot_probe_timeout_seconds') or 3}s"
                ),
            ),
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.ui.print_status(f"- {self.ui.t(key)}: {display_val}", "INFO")
