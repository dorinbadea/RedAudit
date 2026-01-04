#!/usr/bin/env python3
# mypy: disable-error-code="attr-defined"
"""
RedAudit - Wizard UI Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.6: Extracted from auditor.py for better code organization.
Contains interactive UI methods: prompts, menus, input utilities.
"""

import os
import sys
import ipaddress
import platform
import re
import shutil
from typing import Dict, List

from redaudit.utils.constants import (
    VERSION,
    MAX_CIDR_LENGTH,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
)
from redaudit.utils.paths import expand_user_path, get_default_reports_base_dir
from redaudit.utils.dry_run import is_dry_run


class Wizard:
    """
    Mixin class containing interactive UI methods for RedAudit.

    Provides: input prompts, menus, banners, configuration wizards.
    Expects the inheriting class to have: lang, config, COLORS, t(), print_status().
    """

    # ---------- Screen utilities ----------

    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        if is_dry_run(self.config.get("dry_run")):
            return
        os.system("clear" if os.name == "posix" else "cls")

    def print_banner(self) -> None:
        """Print the RedAudit banner."""
        subtitle = self.ui.t("banner_subtitle", self._detect_os_banner_label())
        banner = f"""
{self.ui.colors['FAIL']}
 ____          _    {self.ui.colors['BOLD']}{self.ui.colors['HEADER']}_             _ _ _{self.ui.colors['ENDC']}{self.ui.colors['FAIL']}
|  _ \\ ___  __| |  {self.ui.colors['BOLD']}{self.ui.colors['HEADER']}/ \\  _   _  __| (_) |_{self.ui.colors['ENDC']}{self.ui.colors['FAIL']}
| |_) / _ \\/ _` | {self.ui.colors['BOLD']}{self.ui.colors['HEADER']}/ _ \\| | | |/ _` | | __|{self.ui.colors['ENDC']}{self.ui.colors['FAIL']}
|  _ <  __/ (_| |{self.ui.colors['BOLD']}{self.ui.colors['HEADER']}/ ___ \\ |_| | (_| | | |_{self.ui.colors['ENDC']}{self.ui.colors['FAIL']}
|_| \\_\\___|\\__,_|{self.ui.colors['BOLD']}{self.ui.colors['HEADER']}/_/   \\_\\__,_|\\__,_|_|\\__|{self.ui.colors['ENDC']}
                                     {self.ui.colors['CYAN']}v{VERSION}{self.ui.colors['ENDC']}
{self.ui.colors['OKBLUE']}══════════════════════════════════════════════════════{self.ui.colors['ENDC']}
{self.ui.colors['BOLD']}{subtitle}{self.ui.colors['ENDC']}
{self.ui.colors['OKBLUE']}══════════════════════════════════════════════════════{self.ui.colors['ENDC']}
"""
        print(banner)

    def _detect_os_banner_label(self) -> str:
        os_release = "/etc/os-release"
        label = ""
        data: Dict[str, str] = {}
        try:
            if os.path.exists(os_release):
                with open(os_release, "r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or "=" not in line:
                            continue
                        key, value = line.split("=", 1)
                        data[key.strip()] = value.strip().strip('"').strip("'")
        except Exception:
            data = {}

        label = data.get("NAME") or data.get("PRETTY_NAME") or data.get("ID") or ""
        if not label:
            system = platform.system().strip()
            if system == "Darwin":
                label = "macOS"
            else:
                label = system or "Linux"

        label = label.replace("GNU/Linux", "Linux")
        label = re.sub(r"[^A-Za-z0-9 _/+-]", "", label)
        label = re.sub(r"\s+", " ", label).strip().upper()
        if not label:
            label = "LINUX"
        if len(label) > 22:
            parts = label.split()
            if len(parts) >= 2:
                label = " ".join(parts[:2])
            elif parts:
                label = parts[0]
        if len(label) > 22:
            label = label[:22].rstrip()
        return label or "LINUX"

    # ---------- Menu utilities ----------

    def _use_arrow_menu(self) -> bool:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
        if os.environ.get("REDAUDIT_BASIC_PROMPTS", "").strip():
            return False
        return True

    def _read_key(self) -> str:
        if os.name == "nt":
            try:
                import msvcrt

                ch = msvcrt.getch()
                if ch in (b"\x00", b"\xe0"):
                    key = msvcrt.getch()
                    return {
                        b"H": "up",
                        b"P": "down",
                        b"K": "left",
                        b"M": "right",
                    }.get(key, "")
                if ch in (b"\r", b"\n"):
                    return "enter"
                if ch == b"\x03":
                    raise KeyboardInterrupt
                try:
                    return ch.decode("utf-8", errors="ignore")
                except Exception:
                    return ""
            except Exception:
                return ""

        try:
            import termios
            import tty

            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    seq = sys.stdin.read(2)
                    return {
                        "[A": "up",
                        "[B": "down",
                        "[C": "right",
                        "[D": "left",
                    }.get(seq, "esc")
                if ch in ("\r", "\n"):
                    return "enter"
                if ch == "\x03":
                    raise KeyboardInterrupt
                return ch
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            return ""

    def _clear_menu_lines(self, line_count: int) -> None:
        if line_count <= 0:
            return
        for i in range(line_count):
            sys.stdout.write("\r\x1b[2K")
            if i < line_count - 1:
                sys.stdout.write("\x1b[1A")
        sys.stdout.write("\r")
        sys.stdout.flush()

    def _menu_width(self) -> int:
        try:
            columns = shutil.get_terminal_size((80, 20)).columns
        except Exception:
            columns = 80
        if columns <= 2:
            return max(columns, 1)
        return columns - 1

    def _strip_ansi(self, text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _truncate_menu_text(self, text: str, width: int) -> str:
        if width <= 0:
            return ""
        plain = self._strip_ansi(text)
        if len(plain) <= width:
            return text
        if width <= 3:
            return plain[:width]
        target = width - 3
        out = []
        visible = 0
        idx = 0
        while idx < len(text) and visible < target:
            if text[idx] == "\x1b":
                match = re.match(r"\x1b\[[0-9;]*m", text[idx:])
                if match:
                    out.append(match.group(0))
                    idx += len(match.group(0))
                    continue
            out.append(text[idx])
            visible += 1
            idx += 1
        out.append("...")
        out.append(self.ui.colors["ENDC"])
        return "".join(out)

    def _arrow_menu(
        self,
        question: str,
        options: List[str],
        default: int = 0,
        *,
        header: str = "",
    ) -> int:
        if not options:
            return 0
        index = max(0, min(default, len(options) - 1)) if options else 0
        rendered_lines = 0
        width = self._menu_width()
        sep = "─" * min(60, width)

        while True:
            lines = [""]
            if header:
                lines.append(
                    self._truncate_menu_text(
                        f"{self.ui.colors['HEADER']}{header}{self.ui.colors['ENDC']}", width
                    )
                )
                lines.append(self._truncate_menu_text(sep, width))
            else:
                lines.append(
                    self._truncate_menu_text(
                        f"{self.ui.colors['OKBLUE']}{'—' * min(60, width)}{self.ui.colors['ENDC']}",
                        width,
                    )
                )
            lines.append(
                self._truncate_menu_text(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {question}", width
                )
            )
            for i, opt in enumerate(options):
                marker = f"{self.ui.colors['BOLD']}❯{self.ui.colors['ENDC']}" if i == index else " "
                opt_display = self._format_menu_option(opt)
                lines.append(self._truncate_menu_text(f"  {marker} {opt_display}", width))
            lines.append(
                self._truncate_menu_text(
                    f"{self.ui.colors['OKBLUE']}{self.ui.t('menu_nav_hint')}{self.ui.colors['ENDC']}",
                    width,
                )
            )

            if rendered_lines:
                self._clear_menu_lines(rendered_lines)
            sys.stdout.write("\n".join(lines))
            sys.stdout.flush()
            rendered_lines = len(lines)

            key = self._read_key()
            if not key:
                continue
            if key in ("up", "k", "left", "h"):
                index = (index - 1) % len(options)
                continue
            if key in ("down", "j", "right", "l"):
                index = (index + 1) % len(options)
                continue
            if key == "enter":
                print("")
                return index
            if key.isdigit():
                idx = int(key) - 1
                if 0 <= idx < len(options):
                    print("")
                    return idx
            if key in ("esc", "q"):
                print("")
                return index

    def _format_menu_option(self, option: str) -> str:
        if not option:
            return option
        if "\x1b[" in option:
            return option
        stripped = option.strip()
        labels = (
            (self.ui.t("yes_default"), "OKGREEN"),
            (self.ui.t("yes_option"), "OKGREEN"),
            (self.ui.t("no_default"), "FAIL"),
            (self.ui.t("no_option"), "FAIL"),
            (self.ui.t("wizard_go_back"), "OKBLUE"),
        )
        for label, color in labels:
            if label and stripped.startswith(label):
                return f"{self.ui.colors[color]}{option}{self.ui.colors['ENDC']}"
        return option

    def show_main_menu(self) -> int:
        """
        Display main menu and return user choice.

        Returns:
            int: 0=exit, 1=scan, 2=update, 3=diff
        """
        if self._use_arrow_menu():
            opts = [
                f"1) {self.ui.t('menu_option_scan')}",
                f"2) {self.ui.t('menu_option_update')}",
                f"3) {self.ui.t('menu_option_diff')}",
                f"0) {self.ui.t('menu_option_exit')}",
            ]
            choice = self._arrow_menu(
                self.ui.t("menu_prompt"),
                opts,
                0,
                header=f"RedAudit v{VERSION}",
            )
            return 0 if choice == 3 else choice + 1

        print(f"\n{self.ui.colors['HEADER']}RedAudit v{VERSION}{self.ui.colors['ENDC']}")
        print("─" * 60)
        print(
            f"  {self.ui.colors['CYAN']}1){self.ui.colors['ENDC']} {self.ui.t('menu_option_scan')}"
        )
        print(
            f"  {self.ui.colors['CYAN']}2){self.ui.colors['ENDC']} {self.ui.t('menu_option_update')}"
        )
        print(
            f"  {self.ui.colors['CYAN']}3){self.ui.colors['ENDC']} {self.ui.t('menu_option_diff')}"
        )
        print(
            f"  {self.ui.colors['CYAN']}0){self.ui.colors['ENDC']} {self.ui.t('menu_option_exit')}"
        )
        print("─" * 60)

        while True:
            try:
                ans = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('menu_prompt')} "
                ).strip()
                if ans in ("0", "1", "2", "3"):
                    return int(ans)
                self.ui.print_status(self.ui.t("menu_invalid_option"), "WARNING")
            except KeyboardInterrupt:
                print("")
                return 0

    def show_legal_warning(self) -> bool:
        """Display legal warning and ask for confirmation."""
        print(f"\n{self.ui.colors['WARNING']}{self.ui.t('legal_warning')}{self.ui.colors['ENDC']}")
        return self.ask_yes_no(self.ui.t("legal_accept"), default="no")

    # ---------- Input utilities ----------

    def ask_yes_no(self, question: str, default: str = "yes") -> bool:
        """Ask a yes/no question."""
        default = default.lower()
        if self._use_arrow_menu():
            default_idx = 0 if default in ("yes", "y", "s", "si", "sí") else 1
            is_yes_default = default_idx == 0
            options = [
                self.ui.t("yes_default") if is_yes_default else self.ui.t("yes_option"),
                self.ui.t("no_default") if not is_yes_default else self.ui.t("no_option"),
            ]
            try:
                return self._arrow_menu(question, options, default_idx) == 0
            except Exception:
                pass
        opts = (
            self.ui.t("ask_yes_no_opts")
            if default in ("yes", "y", "s", "si", "sí")
            else self.ui.t("ask_yes_no_opts_neg")
        )
        valid = {
            "yes": True,
            "y": True,
            "s": True,
            "si": True,
            "sí": True,
            "no": False,
            "n": False,
        }
        while True:
            try:
                print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
                ans = (
                    input(f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {question}{opts}: ")
                    .strip()
                    .lower()
                )
                if ans == "":
                    return valid.get(default, True)
                if ans in valid:
                    return valid[ans]
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_number(self, question: str, default=10, min_val: int = 1, max_val: int = 1000):
        """Ask for a number within a range."""
        default_return = default
        default_display = default
        if isinstance(default, str) and default.lower() in ("all", "todos", "todo"):
            default_return = "all"
            default_display = "todos" if self.lang == "es" else "all"
        while True:
            try:
                print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
                ans = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {question} [{default_display}]: "
                ).strip()
                if ans == "":
                    return default_return
                if ans.lower() in ("todos", "todo", "all"):
                    return "all"
                try:
                    num = int(ans)
                    if min_val <= num <= max_val:
                        return num
                    self.ui.print_status(self.ui.t("val_out_of_range", min_val, max_val), "WARNING")
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_choice(self, question: str, options: List[str], default: int = 0) -> int:
        """Ask to choose from a list of options."""
        if self._use_arrow_menu():
            try:
                return self._arrow_menu(question, options, default)
            except Exception:
                pass
        print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
        print(f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.ui.colors['BOLD']}>{self.ui.colors['ENDC']}" if i == default else " "
            print(f"  {marker} {i + 1}. {opt}")
        while True:
            try:
                ans = input(
                    f"\n{self.ui.t('select_opt')} [1-{len(options)}] ({default + 1}): "
                ).strip()
                if ans == "":
                    return default
                try:
                    idx = int(ans) - 1
                    if 0 <= idx < len(options):
                        return idx
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    # v3.8.1: Navigation-aware choice with "Go Back" option
    WIZARD_BACK = -1  # Sentinel value for "go back"

    def ask_choice_with_back(
        self,
        question: str,
        options: List[str],
        default: int = 0,
        *,
        step_num: int = 0,
        total_steps: int = 0,
    ) -> int:
        """
        Ask to choose from a list of options with a "< Volver" (Go Back) option.

        Returns:
            int: Selected index (0 to len(options)-1), or WIZARD_BACK (-1) if user chose to go back.
        """
        # Build header with step indicator if provided
        step_header = ""
        if step_num > 0 and total_steps > 0:
            step_header = f"[{step_num}/{total_steps}] "

        # Add "< Volver" / "< Go Back" as the last option (only if not first step)
        back_label = self.ui.t("wizard_go_back")
        show_back = step_num > 1  # Don't show back on first step
        display_options = list(options) + ([back_label] if show_back else [])

        if self._use_arrow_menu():
            try:
                result = self._arrow_menu(f"{step_header}{question}", display_options, default)
                if show_back and result == len(options):
                    return self.WIZARD_BACK
                return result
            except Exception:
                pass

        # Fallback text-based menu
        print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
        print(f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {step_header}{question}")
        for i, opt in enumerate(display_options):
            marker = f"{self.ui.colors['BOLD']}>{self.ui.colors['ENDC']}" if i == default else " "
            print(f"  {marker} {i + 1}. {opt}")

        while True:
            try:
                prompt_range = f"1-{len(display_options)}"
                ans = input(
                    f"\n{self.ui.t('select_opt')} [{prompt_range}] ({default + 1}): "
                ).strip()
                if ans == "":
                    return default
                # Support "0" or "b" or "back" for going back
                if show_back and ans.lower() in ("0", "b", "back", "volver", "<"):
                    return self.WIZARD_BACK
                try:
                    idx = int(ans) - 1
                    if 0 <= idx < len(options):
                        return idx
                    if show_back and idx == len(options):
                        return self.WIZARD_BACK
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_manual_network(self) -> str:
        """Ask for manual network CIDR input."""
        while True:
            try:
                net = input(
                    f"\n{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} CIDR (e.g. 192.168.1.0/24): "
                ).strip()
                if len(net) > MAX_CIDR_LENGTH:
                    self.ui.print_status(self.ui.t("invalid_cidr"), "WARNING")
                    continue
                try:
                    ipaddress.ip_network(net, strict=False)
                    return net
                except ValueError:
                    self.ui.print_status(self.ui.t("invalid_cidr"), "WARNING")
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    # ---------- Defaults summary ----------

    def _show_defaults_summary(self, persisted_defaults: Dict) -> None:
        """Display summary of persisted defaults."""
        self.ui.print_status(self.ui.t("defaults_summary_title"), "INFO")

        def fmt_targets(val):
            if not isinstance(val, list) or not val:
                return "-"
            cleaned = [t.strip() for t in val if isinstance(t, str) and t.strip()]
            return ", ".join(cleaned) if cleaned else "-"

        def fmt_bool(val):
            if val is None:
                return "-"
            return self.ui.t("enabled") if val else self.ui.t("disabled")

        fields = [
            ("defaults_summary_targets", fmt_targets(persisted_defaults.get("target_networks"))),
            ("defaults_summary_scan_mode", persisted_defaults.get("scan_mode")),
            ("defaults_summary_threads", persisted_defaults.get("threads")),
            ("defaults_summary_output", persisted_defaults.get("output_dir")),
            ("defaults_summary_rate_limit", persisted_defaults.get("rate_limit")),
            ("defaults_summary_udp_mode", persisted_defaults.get("udp_mode")),
            ("defaults_summary_udp_ports", persisted_defaults.get("udp_top_ports")),
            ("defaults_summary_topology", fmt_bool(persisted_defaults.get("topology_enabled"))),
            (
                "defaults_summary_web_vulns",
                fmt_bool(persisted_defaults.get("scan_vulnerabilities")),
            ),
            ("defaults_summary_cve_lookup", fmt_bool(persisted_defaults.get("cve_lookup_enabled"))),
            ("defaults_summary_txt_report", fmt_bool(persisted_defaults.get("generate_txt"))),
            ("defaults_summary_html_report", fmt_bool(persisted_defaults.get("generate_html"))),
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.ui.print_status(f"- {self.ui.t(key)}: {display_val}", "INFO")

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

        # 5. Vulnerabilities
        self.config["scan_vulnerabilities"] = defaults_for_run.get("scan_vulnerabilities", True)
        self.config["cve_lookup_enabled"] = defaults_for_run.get("cve_lookup_enabled", False)

        # 6. Output Dir
        out_dir = defaults_for_run.get("output_dir")
        if isinstance(out_dir, str) and out_dir.strip():
            self.config["output_dir"] = expand_user_path(out_dir.strip())
        else:
            self.config["output_dir"] = get_default_reports_base_dir()

        self.config["save_txt_report"] = defaults_for_run.get("generate_txt", True)
        self.config["save_html_report"] = defaults_for_run.get("generate_html", True)

        # 7. UDP Configuration
        self.config["udp_mode"] = defaults_for_run.get("udp_mode", UDP_SCAN_MODE_QUICK)
        self.config["udp_top_ports"] = defaults_for_run.get("udp_top_ports", UDP_TOP_PORTS)

        # 8. Topology
        self.config["topology_enabled"] = defaults_for_run.get("topology_enabled", False)
        self.config["topology_only"] = defaults_for_run.get("topology_only", False)

    # ---------- v3.7: Interactive Webhooks ----------

    def ask_webhook_url(self) -> str:
        """
        Prompt user for webhook URL configuration.

        Returns:
            Webhook URL or empty string if skipped
        """
        if not self.ask_yes_no(self.ui.t("webhook_q"), default="no"):
            return ""

        while True:
            try:
                print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
                # v3.8.0: Added hint with example URL formats
                hint = (
                    self.ui.colors["OKBLUE"]
                    + "(e.g. https://hooks.slack.com/services/... or https://outlook.office.com/webhook/...)"
                    + self.ui.colors["ENDC"]
                )
                print(f"  {hint}")
                url = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('webhook_url_prompt')} "
                ).strip()

                if not url:
                    return ""

                # Basic validation
                if not url.startswith("https://"):
                    self.ui.print_status(self.ui.t("webhook_invalid_url"), "WARNING")
                    continue

                self.ui.print_status(self.ui.t("webhook_configured", url[:50] + "..."), "OK")

                # Optional: test the webhook
                if self.ask_yes_no(self.ui.t("webhook_test_q"), default="no"):
                    self._test_webhook(url)

                return url

            except KeyboardInterrupt:
                print("")
                return ""

    def _test_webhook(self, url: str) -> bool:
        """Send a test webhook to verify configuration."""
        try:
            from redaudit.utils.webhook import send_webhook

            test_payload = {
                "type": "test",
                "message": "RedAudit webhook test",
                "source": "wizard",
            }
            if send_webhook(url, test_payload):
                self.ui.print_status(self.ui.t("webhook_test_success"), "OK")
                return True
            else:
                self.ui.print_status(
                    self.ui.t("webhook_test_failed", "Connection failed"), "WARNING"
                )
                return False
        except Exception as e:
            self.ui.print_status(self.ui.t("webhook_test_failed", str(e)), "WARNING")
            return False

    # ---------- v3.7: Advanced Net Discovery Options ----------

    def ask_net_discovery_options(self) -> dict:
        """
        Prompt for advanced Net Discovery configuration.

        Returns:
            Dict with snmp_community, dns_zone, max_targets
        """
        options = {
            "snmp_community": "public",
            "dns_zone": "",
            "redteam_max_targets": 50,
        }

        if not self.ask_yes_no(self.ui.t("net_discovery_advanced_q"), default="no"):
            return options

        try:
            # SNMP Community
            print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
            # v3.8.0: Added hint for SNMP community string
            hint = (
                self.ui.colors["OKBLUE"]
                + "(ENTER = 'public', or try 'private', 'community', etc.)"
                + self.ui.colors["ENDC"]
            )
            print(f"  {hint}")
            snmp = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('net_discovery_snmp_prompt')} "
                f"[{options['snmp_community']}]: "
            ).strip()
            if snmp:
                options["snmp_community"] = snmp[:64]  # Safety limit

            # DNS Zone
            print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
            # v3.8.0: Added hint for DNS zone with examples
            hint_dns = (
                self.ui.colors["OKBLUE"]
                + "(e.g. corp.local, example.com, internal.lan — ENTER to skip)"
                + self.ui.colors["ENDC"]
            )
            print(f"  {hint_dns}")
            dns_zone = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} {self.ui.t('net_discovery_dns_zone_prompt')} "
            ).strip()
            if dns_zone:
                options["dns_zone"] = dns_zone[:128]

            # Max targets
            max_tgt = self.ask_number(
                self.ui.t("net_discovery_max_targets_prompt"),
                default=50,
                min_val=1,
                max_val=500,
            )
            options["redteam_max_targets"] = max_tgt

            self.ui.print_status(self.ui.t("net_discovery_options_saved"), "OK")

        except KeyboardInterrupt:
            print("")

        return options
