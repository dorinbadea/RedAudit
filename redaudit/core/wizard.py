#!/usr/bin/env python3
# mypy: disable-error-code="attr-defined"
"""
RedAudit - Wizard UI Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.6: Extracted from auditor.py for better code organization.
Contains interactive UI methods: prompts, menus, input utilities.
"""

import os
import sys
import platform
import re
import shutil
from typing import Dict, List, Optional

from redaudit.utils.constants import (
    VERSION,
    MAX_CIDR_LENGTH,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
)
from redaudit.utils.paths import expand_user_path, get_default_reports_base_dir, get_invoking_user
from redaudit.utils.dry_run import is_dry_run
from redaudit.utils.targets import parse_target_tokens


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

    def _style_prompt_text(self, text: str) -> str:
        if not text:
            return text
        bold = self.ui.colors.get("BOLD", "")
        okblue = self.ui.colors.get("OKBLUE", "")
        endc = self.ui.colors.get("ENDC", "")
        if not (bold or okblue or endc):
            return text
        return f"{bold}{okblue}{text}{endc}"

    def _style_default_hint(self, text: str, color_key: str) -> str:
        if not text:
            return text
        color = self.ui.colors.get(color_key, "")
        bold = self.ui.colors.get("BOLD", "")
        endc = self.ui.colors.get("ENDC", "")
        if not (color or bold or endc):
            return text
        return f"{bold}{color}{text}{endc}"

    def _style_default_value(self, text: str) -> str:
        if not text:
            return text
        bold = self.ui.colors.get("BOLD", "")
        okgreen = self.ui.colors.get("OKGREEN", "")
        endc = self.ui.colors.get("ENDC", "")
        if not (bold or okgreen or endc):
            return text
        return f"{bold}{okgreen}{text}{endc}"

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
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(question)}",
                    width,
                )
            )
            for i, opt in enumerate(options):
                marker = f"{self.ui.colors['BOLD']}❯{self.ui.colors['ENDC']}" if i == index else " "
                # v4.14: Pass is_selected for enhanced color scheme
                opt_display = self._format_menu_option(opt, is_selected=(i == index))
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

    def _format_menu_option(self, option: str, is_selected: bool = False) -> str:
        """Format menu option with professional color scheme.

        v4.14: Enhanced colors for better visual hierarchy:
        - Selected option: Bold cyan
        - Yes/Si options: Green
        - No options: Dim red
        - Cancel/Back: Dim yellow
        """
        if not option:
            return option
        if "\x1b[" in option:
            return option
        stripped = option.strip()

        # Define label-color mappings
        labels = (
            (self.ui.t("yes_default"), "OKGREEN", True),
            (self.ui.t("yes_option"), "OKGREEN", False),
            (self.ui.t("no_default"), "FAIL", True),
            (self.ui.t("no_option"), "FAIL", False),
            (self.ui.t("wizard_go_back"), "WARNING", False),
            (self.ui.t("go_back"), "WARNING", False),
        )

        # Check for matching labels
        for label, color, is_default in labels:
            if label and stripped.startswith(label):
                dim = self.ui.colors.get("DIM", "")
                bold = self.ui.colors.get("BOLD", "")
                if color == "WARNING":
                    return f"{dim}{self.ui.colors.get(color, '')}{option}{self.ui.colors['ENDC']}"
                if is_default:
                    return f"{bold}{self.ui.colors.get(color, '')}{option}{self.ui.colors['ENDC']}"
                return f"{dim}{self.ui.colors.get(color, '')}{option}{self.ui.colors['ENDC']}"

        # v4.14: Selected option gets bold cyan for prominence
        if is_selected:
            return (
                f"{self.ui.colors['BOLD']}{self.ui.colors['CYAN']}"
                f"{option}{self.ui.colors['ENDC']}"
            )

        dim = self.ui.colors.get("DIM", "")
        accent = self.ui.colors.get("OKBLUE", "")
        if dim or accent:
            return f"{dim}{accent}{option}{self.ui.colors['ENDC']}"
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
            f"  {self.ui.colors['CYAN']}1){self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(self.ui.t('menu_option_scan'))}"
        )
        print(
            f"  {self.ui.colors['CYAN']}2){self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(self.ui.t('menu_option_update'))}"
        )
        print(
            f"  {self.ui.colors['CYAN']}3){self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(self.ui.t('menu_option_diff'))}"
        )
        print(
            f"  {self.ui.colors['CYAN']}0){self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(self.ui.t('menu_option_exit'))}"
        )
        print("─" * 60)

        while True:
            try:
                ans = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(self.ui.t('menu_prompt'))} "
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
        is_yes_default = default in ("yes", "y", "s", "si", "sí")
        opts_raw = (
            self.ui.t("ask_yes_no_opts") if is_yes_default else self.ui.t("ask_yes_no_opts_neg")
        )
        opts = self._style_default_hint(opts_raw, "OKGREEN" if is_yes_default else "FAIL")
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
                    input(
                        f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                        f"{self._style_prompt_text(question)}{opts}: "
                    )
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
        default_display = self._style_default_value(str(default_display))
        while True:
            try:
                print(f"\n{self.ui.colors['OKBLUE']}{'—' * 60}{self.ui.colors['ENDC']}")
                ans = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(question)} [{default_display}]: "
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
        print(
            f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(question)}"
        )
        for i, opt in enumerate(options):
            marker = f"{self.ui.colors['BOLD']}>{self.ui.colors['ENDC']}" if i == default else " "
            opt_display = self._format_menu_option(opt)
            print(f"  {marker} {i + 1}. {opt_display}")
        while True:
            try:
                default_choice = self._style_default_value(str(default + 1))
                ans = input(
                    f"\n{self.ui.t('select_opt')} [1-{len(options)}] ({default_choice}): "
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

    # v3.8.1: Navigation-aware choice with "Cancel" option
    WIZARD_BACK = -1  # Sentinel value for "go back"

    def _is_cancel_input(self, value: str) -> bool:
        if not value:
            return False
        return value.strip().lower() in {"cancel", "cancelar", "c"}

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
        Ask to choose from a list of options with a "Cancel" option.

        Returns:
            int: Selected index (0 to len(options)-1), or WIZARD_BACK (-1) if user chose to go back.
        """
        # Build header with step indicator if provided
        step_header = ""
        if step_num > 0 and total_steps > 0:
            step_header = f"[{step_num}/{total_steps}] "
        else:
            step_header = ""

        # Add "Cancel" as the last option (only if not first step)
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
        print(
            f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
            f"{self._style_prompt_text(f'{step_header}{question}')}"
        )
        for i, opt in enumerate(display_options):
            marker = f"{self.ui.colors['BOLD']}>{self.ui.colors['ENDC']}" if i == default else " "
            opt_display = self._format_menu_option(opt)
            print(f"  {marker} {i + 1}. {opt_display}")

        while True:
            try:
                prompt_range = f"1-{len(display_options)}"
                ans = input(
                    f"\n{self.ui.t('select_opt')} [{prompt_range}] ({default + 1}): "
                ).strip()
                if ans == "":
                    return default
                # Support common "back/cancel" inputs in text fallback
                if show_back and (
                    ans.lower() in ("0", "b", "back", "volver", "<") or self._is_cancel_input(ans)
                ):
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

    def ask_manual_network(self) -> list[str]:
        """Ask for one or more manual network CIDRs."""
        while True:
            try:
                raw = input(
                    f"\n{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(self.ui.t('manual_cidr_prompt'))}"
                ).strip()
                tokens = [token.strip() for token in raw.split(",") if token.strip()]
                if not tokens:
                    self.ui.print_status(self.ui.t("invalid_cidr"), "WARNING")
                    continue
                parsed, invalid = parse_target_tokens(tokens, MAX_CIDR_LENGTH)
                if invalid:
                    self.ui.print_status(self.ui.t("invalid_cidr_target", invalid[0]), "WARNING")
                    continue
                if not parsed:
                    self.ui.print_status(self.ui.t("invalid_cidr"), "WARNING")
                    continue
                return parsed
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
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(self.ui.t('webhook_url_prompt'))} "
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
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('net_discovery_snmp_prompt'))} "
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
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('net_discovery_dns_zone_prompt'))} "
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

    # ---------- v4.0: Authenticated Scanning ----------

    def ask_auth_config(self, skip_intro: bool = False) -> dict:
        """
        Interactive authentication setup for Phase 4.

        Refactored in Phase 4.1.1 to offer two modes:
        - Universal: Simple user/pass pairs, auto-detect protocol
        - Advanced: Per-protocol configuration (SSH key, SMB domain, SNMP v3)
        """
        auth_config: dict = {
            "auth_enabled": False,
            "auth_credentials": [],  # Universal credentials list
            "auth_ssh_user": None,
            "auth_ssh_key": None,
            "auth_ssh_pass": None,
            "auth_ssh_key_pass": None,
            "auth_smb_user": None,
            "auth_smb_pass": None,
            "auth_smb_domain": None,
            "auth_snmp_user": None,
            "auth_snmp_auth_proto": None,
            "auth_snmp_auth_pass": None,
            "auth_snmp_priv_proto": None,
            "auth_snmp_priv_pass": None,
            "auth_save_keyring": False,
        }

        if not skip_intro:
            # v4.5.17: Ask about auth scanning FIRST, before keyring access
            # This avoids unnecessary keyring password prompts when user doesn't want auth scanning
            if not self.ask_yes_no(self.ui.t("auth_scan_q"), default="no"):
                return auth_config

        # v4.5.3: Check for saved credentials in keyring (only if user wants auth)
        loaded_from_keyring = self._check_and_load_saved_credentials(auth_config)
        if loaded_from_keyring:
            # Credentials loaded from keyring, allow optional manual additions
            auth_config["auth_enabled"] = True
            if not self.ask_yes_no(self.ui.t("auth_add_more_q"), default="no"):
                return auth_config
        else:
            # v4.14: No credentials loaded - ask if user wants to configure manually
            # This fixes the bug where mode selection appeared after declining keyring load
            if not self.ask_yes_no(self.ui.t("auth_configure_manual_q"), default="no"):
                auth_config["auth_enabled"] = False
                return auth_config

        auth_config["auth_enabled"] = True

        # Mode selection: Universal vs Advanced
        mode_opts = [
            self.ui.t("auth_mode_universal"),
            self.ui.t("auth_mode_advanced"),
        ]
        # v4.5.1: Use back-aware menu to avoid trapping user
        mode_choice = self.ask_choice_with_back(
            self.ui.t("auth_mode_q"),
            mode_opts,
            0,
            step_num=2,  # Arbitrary step number to show "Back"
            total_steps=2,
        )

        if mode_choice == self.WIZARD_BACK:
            # User chose to go back -> disable auth unless keyring already loaded
            if loaded_from_keyring:
                return auth_config
            auth_config["auth_enabled"] = False
            return auth_config

        if mode_choice == 0:
            # Universal mode: collect simple user/pass pairs
            # Show protocol detection hint
            print(
                f"\n{self.ui.colors['OKBLUE']}"
                f"{self.ui.t('auth_protocol_hint')}"
                f"{self.ui.colors['ENDC']}"
            )
            existing_creds = list(auth_config.get("auth_credentials") or [])
            creds = self._collect_universal_credentials(start_index=len(existing_creds) + 1)
            if creds is None:
                if loaded_from_keyring:
                    return auth_config
                auth_config["auth_enabled"] = False
                return auth_config
            auth_config["auth_credentials"] = existing_creds + creds
        else:
            # Advanced mode: per-protocol configuration
            if self._collect_advanced_credentials(auth_config):
                if loaded_from_keyring:
                    return auth_config
                auth_config["auth_enabled"] = False
                return auth_config

        # Keyring option
        if (
            auth_config.get("auth_credentials")
            or auth_config.get("auth_ssh_pass")
            or auth_config.get("auth_smb_pass")
        ):
            if self.ask_yes_no(self.ui.t("auth_save_keyring_q"), default="no"):
                auth_config["auth_save_keyring"] = True

        # v4.10: SNMP Topology & Route Following (if auth enabled)
        if auth_config.get("auth_enabled"):
            if self.ask_yes_no(self.ui.t("snmp_topology_q"), default="no"):
                auth_config["snmp_topology"] = True
                if self.ask_yes_no(self.ui.t("follow_routes_q"), default="no"):
                    auth_config["follow_routes"] = True

        return auth_config

    def _load_keyring_from_invoking_user(self, invoking_user: str) -> Optional[dict]:
        if not invoking_user:
            return None
        if shutil.which("sudo") is None:
            return None

        try:
            import json
            import subprocess
            from pathlib import Path

            extra_env = {}
            try:
                import pwd

                user_info = pwd.getpwnam(invoking_user)
                runtime_dir = f"/run/user/{user_info.pw_uid}"
                bus_path = os.path.join(runtime_dir, "bus")
                if os.path.isdir(runtime_dir):
                    extra_env["XDG_RUNTIME_DIR"] = runtime_dir
                if os.path.exists(bus_path):
                    extra_env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
            except Exception:
                extra_env = {}

            package_root = Path(__file__).resolve().parents[1]
            script = (
                "import json, os, sys, logging\n"
                "logging.disable(logging.CRITICAL)\n"
                "root = os.environ.get('REDAUDIT_PYTHONPATH')\n"
                "if root:\n"
                "    sys.path.insert(0, root)\n"
                "from redaudit.core.credentials import KeyringCredentialProvider\n"
                "provider = KeyringCredentialProvider()\n"
                "summary = provider.get_saved_credential_summary()\n"
                "creds = []\n"
                "for item in summary:\n"
                "    protocol = item[0] if len(item) > 0 else ''\n"
                "    username = item[1] if len(item) > 1 else ''\n"
                "    cred = provider.get_credential('default', protocol.lower())\n"
                "    if not cred:\n"
                "        continue\n"
                "    creds.append({\n"
                "        'protocol': protocol,\n"
                "        'username': cred.username,\n"
                "        'password': cred.password,\n"
                "        'private_key': cred.private_key,\n"
                "        'private_key_passphrase': cred.private_key_passphrase,\n"
                "        'domain': cred.domain,\n"
                "        'snmp_auth_proto': cred.snmp_auth_proto,\n"
                "        'snmp_auth_pass': cred.snmp_auth_pass,\n"
                "        'snmp_priv_proto': cred.snmp_priv_proto,\n"
                "        'snmp_priv_pass': cred.snmp_priv_pass,\n"
                "    })\n"
                "payload = {'summary': summary, 'creds': creds}\n"
                "sys.stdout.write(json.dumps(payload))\n"
            )

            cmd = [
                "sudo",
                "-H",
                "-u",
                invoking_user,
                "env",
                f"REDAUDIT_PYTHONPATH={package_root}",
            ]
            for key, value in extra_env.items():
                cmd.append(f"{key}={value}")
            cmd += [
                sys.executable,
                "-c",
                script,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return None
            payload_raw = result.stdout.strip()
            if not payload_raw:
                return None
            payload = json.loads(payload_raw)
            if not isinstance(payload, dict):
                return None
            return payload
        except Exception:
            return None

    def _apply_keyring_credentials(self, auth_config: dict, credentials: list[dict]) -> int:
        loaded = 0
        for cred in credentials:
            if not isinstance(cred, dict):
                continue
            protocol = str(cred.get("protocol", "")).upper()
            if protocol == "SSH":
                auth_config["auth_ssh_user"] = cred.get("username")
                auth_config["auth_ssh_pass"] = cred.get("password")
                auth_config["auth_ssh_key"] = cred.get("private_key")
                auth_config["auth_ssh_key_pass"] = cred.get("private_key_passphrase")
                loaded += 1
            elif protocol == "SMB":
                auth_config["auth_smb_user"] = cred.get("username")
                auth_config["auth_smb_pass"] = cred.get("password")
                auth_config["auth_smb_domain"] = cred.get("domain")
                loaded += 1
            elif protocol == "SNMP":
                auth_config["auth_snmp_user"] = cred.get("username")
                auth_config["auth_snmp_auth_proto"] = cred.get("snmp_auth_proto")
                auth_config["auth_snmp_auth_pass"] = cred.get("snmp_auth_pass")
                auth_config["auth_snmp_priv_proto"] = cred.get("snmp_priv_proto")
                auth_config["auth_snmp_priv_pass"] = cred.get("snmp_priv_pass")
                loaded += 1
        return loaded

    def _check_and_load_saved_credentials(self, auth_config: dict) -> bool:
        """
        Check for saved credentials in keyring and offer to load them.

        v4.5.3: Implements B5 - Credential Loading for Future Scans

        Returns:
            True if credentials were loaded, False otherwise.
        """
        try:
            from redaudit.core.credentials import KeyringCredentialProvider

            provider = KeyringCredentialProvider()
            summary = provider.get_saved_credential_summary()
            invoking_user = get_invoking_user()
            invoking_payload = None
            using_invoking_user = False

            if not summary and invoking_user:
                invoking_payload = self._load_keyring_from_invoking_user(invoking_user)
                summary_raw = (
                    invoking_payload.get("summary", [])
                    if isinstance(invoking_payload, dict)
                    else []
                )
                summary = []
                for item in summary_raw:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        summary.append((item[0], item[1]))
                using_invoking_user = bool(summary)

            if not summary:
                return False

            # Show saved credentials
            found_msg = (
                self.ui.t("auth_saved_creds_found_invoking", invoking_user)
                if using_invoking_user
                else self.ui.t("auth_saved_creds_found")
            )
            print(f"\n{self.ui.colors['OKGREEN']}{found_msg}{self.ui.colors['ENDC']}")
            for item in summary:
                protocol = item[0] if len(item) > 0 else ""
                username = item[1] if len(item) > 1 else ""
                spray_count = item[2] if len(item) > 2 else 0
                spray_info = f" (+{spray_count} spray)" if spray_count > 0 else ""
                print(f"  - {protocol}: {username}{spray_info}")

            # Ask to load
            if self.ask_yes_no(self.ui.t("auth_load_saved_q"), default="yes"):
                loaded_count = 0
                if using_invoking_user and isinstance(invoking_payload, dict):
                    creds = invoking_payload.get("creds", [])
                    if isinstance(creds, list):
                        loaded_count = self._apply_keyring_credentials(auth_config, creds)
                else:
                    for item in summary:
                        protocol = item[0] if len(item) > 0 else ""
                        username = item[1] if len(item) > 1 else ""
                        cred = provider.get_credential("default", protocol.lower())
                        if cred:
                            if protocol == "SSH":
                                auth_config["auth_ssh_user"] = cred.username
                                auth_config["auth_ssh_pass"] = cred.password
                                auth_config["auth_ssh_key"] = cred.private_key
                                auth_config["auth_ssh_key_pass"] = cred.private_key_passphrase
                                loaded_count += 1
                            elif protocol == "SMB":
                                auth_config["auth_smb_user"] = cred.username
                                auth_config["auth_smb_pass"] = cred.password
                                auth_config["auth_smb_domain"] = cred.domain
                                loaded_count += 1
                            elif protocol == "SNMP":
                                auth_config["auth_snmp_user"] = cred.username
                                auth_config["auth_snmp_auth_proto"] = cred.snmp_auth_proto
                                auth_config["auth_snmp_auth_pass"] = cred.snmp_auth_pass
                                auth_config["auth_snmp_priv_proto"] = cred.snmp_priv_proto
                                auth_config["auth_snmp_priv_pass"] = cred.snmp_priv_pass
                                loaded_count += 1

                if loaded_count:
                    print(
                        f"{self.ui.colors['OKGREEN']}"
                        f"{self.ui.t('auth_loaded_creds').format(loaded_count)}"
                        f"{self.ui.colors['ENDC']}\n"
                    )
                    return True
                return False

            return False
        except Exception as e:
            # Keyring not available or other error - continue with manual setup
            import logging

            logging.getLogger(__name__).debug("Keyring check failed: %s", e)
            return False

    def _collect_universal_credentials(self, start_index: int = 1) -> Optional[list]:
        """Collect universal credentials (user/pass pairs)."""
        import getpass

        credentials: list = []
        cred_num = max(1, int(start_index))

        self.ui.print_status(self.ui.t("auth_cancel_hint"), "WARNING")
        print(
            f"\n{self.ui.colors['OKBLUE']}--- "
            f"{self.ui.t('auth_cred_number') % cred_num} "
            f"---{self.ui.colors['ENDC']}"
        )

        while True:
            user = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('auth_cred_user_prompt'))}: "
            ).strip()

            if self._is_cancel_input(user):
                self.ui.print_status(self.ui.t("config_cancel"), "WARNING")
                return None

            if not user:
                break

            try:
                password = getpass.getpass(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(self.ui.t('auth_cred_pass_prompt'))}: "
                )
            except Exception:
                password = ""  # nosec

            credentials.append({"user": user, "pass": password})

            if not self.ask_yes_no(self.ui.t("auth_add_another"), default="no"):
                break

            cred_num += 1
            print(
                f"\n{self.ui.colors['OKBLUE']}--- "
                f"{self.ui.t('auth_cred_number') % cred_num} "
                f"---{self.ui.colors['ENDC']}"
            )

        if credentials:
            print(
                f"\n{self.ui.colors['OKGREEN']}"
                f"{self.ui.t('auth_creds_summary') % len(credentials)}"
                f"{self.ui.colors['ENDC']}"
            )

        return credentials

    def _collect_advanced_credentials(self, auth_config: Dict) -> bool:
        """Collect advanced credentials."""
        import getpass

        self.ui.print_status(self.ui.t("auth_cancel_hint"), "WARNING")

        # 1. SSH
        if self.ask_yes_no(self.ui.t("auth_ssh_configure_q"), default="yes"):
            print(f"\n{self.ui.colors['OKBLUE']}--- SSH ---{self.ui.colors['ENDC']}")
            default_user = "root"
            u = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('auth_ssh_user_prompt'))} "
                f"[{default_user}]: "
            ).strip()
            if self._is_cancel_input(u):
                self.ui.print_status(self.ui.t("config_cancel"), "WARNING")
                return True
            auth_config["auth_ssh_user"] = u if u else default_user

            method_opts = [
                self.ui.t("auth_method_key"),
                self.ui.t("auth_method_pass"),
            ]
            choice = self.ask_choice(self.ui.t("auth_method_q"), method_opts, 0)

            if choice == 0:
                default_key = "~/.ssh/id_rsa"
                k = input(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text(self.ui.t('auth_ssh_key_prompt'))} "
                    f"[{default_key}]: "
                ).strip()
                auth_config["auth_ssh_key"] = expand_user_path(k if k else default_key)
            else:
                print(
                    f"{self.ui.colors['OKBLUE']}"
                    f"{self.ui.t('auth_ssh_pass_hint')}:{self.ui.colors['ENDC']}"
                )
                try:
                    pwd = getpass.getpass(
                        f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                        f"{self._style_prompt_text('Password: ')}"
                    )
                    auth_config["auth_ssh_pass"] = pwd
                except Exception:
                    pass

        # 2. SMB
        if self.ask_yes_no(self.ui.t("auth_smb_configure_q"), default="no"):
            print(f"\n{self.ui.colors['OKBLUE']}--- SMB ---{self.ui.colors['ENDC']}")
            default_user = "Administrator"
            u = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('auth_smb_user_prompt'))} "
                f"[{default_user}]: "
            ).strip()
            if self._is_cancel_input(u):
                self.ui.print_status(self.ui.t("config_cancel"), "WARNING")
                return True
            auth_config["auth_smb_user"] = u if u else default_user

            d = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('auth_smb_domain_prompt'))} []: "
            ).strip()
            auth_config["auth_smb_domain"] = d if d else None

            print(
                f"{self.ui.colors['OKBLUE']}"
                f"{self.ui.t('auth_smb_pass_hint')}:{self.ui.colors['ENDC']}"
            )
            try:
                pwd = getpass.getpass(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text('Password: ')}"
                )
                auth_config["auth_smb_pass"] = pwd
            except Exception:
                pass

        # 3. SNMP v3
        if self.ask_yes_no(self.ui.t("auth_snmp_configure_q"), default="no"):
            print(f"\n{self.ui.colors['OKBLUE']}--- SNMP v3 ---{self.ui.colors['ENDC']}")
            u = input(
                f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                f"{self._style_prompt_text(self.ui.t('auth_snmp_user_prompt'))}: "
            ).strip()
            if self._is_cancel_input(u):
                self.ui.print_status(self.ui.t("config_cancel"), "WARNING")
                return True
            auth_config["auth_snmp_user"] = u

            auth_protos = ["SHA", "MD5", "SHA224", "SHA256", "SHA384", "SHA512"]
            a_idx = self.ask_choice(self.ui.t("auth_snmp_auth_proto_q"), auth_protos, 0)
            auth_config["auth_snmp_auth_proto"] = auth_protos[a_idx]

            try:
                auth_pass = getpass.getpass(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text('Auth Key: ')}"
                )
                auth_config["auth_snmp_auth_pass"] = auth_pass
            except Exception:
                pass

            priv_protos = ["AES", "DES", "AES192", "AES256", "3DES"]
            p_idx = self.ask_choice(self.ui.t("auth_snmp_priv_proto_q"), priv_protos, 0)
            auth_config["auth_snmp_priv_proto"] = priv_protos[p_idx]

            try:
                priv_pass = getpass.getpass(
                    f"{self.ui.colors['CYAN']}?{self.ui.colors['ENDC']} "
                    f"{self._style_prompt_text('Priv Key: ')}"
                )
                auth_config["auth_snmp_priv_pass"] = priv_pass
            except Exception:
                pass
        return False
