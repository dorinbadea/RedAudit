#!/usr/bin/env python3
"""
RedAudit - Wizard Compatibility Facade
Copyright (C) 2026  Dorin Badea
GPLv3 License

Compatibility layer preserving the legacy Wizard import path while the
implementation lives in wizard_service.py.
"""

from redaudit.core import wizard_service
from redaudit.core.wizard_service import WizardService

# Re-export legacy module symbols used by tests/patches.
os = wizard_service.os
sys = wizard_service.sys
platform = wizard_service.platform
re = wizard_service.re
shutil = wizard_service.shutil
subprocess = wizard_service.subprocess
time = wizard_service.time
parse_target_tokens = wizard_service.parse_target_tokens
expand_user_path = wizard_service.expand_user_path
get_default_reports_base_dir = wizard_service.get_default_reports_base_dir
get_invoking_user = wizard_service.get_invoking_user
is_dry_run = wizard_service.is_dry_run
MAX_CIDR_LENGTH = wizard_service.MAX_CIDR_LENGTH
DEFAULT_THREADS = wizard_service.DEFAULT_THREADS
MAX_THREADS = wizard_service.MAX_THREADS
MIN_THREADS = wizard_service.MIN_THREADS
UDP_SCAN_MODE_QUICK = wizard_service.UDP_SCAN_MODE_QUICK
UDP_TOP_PORTS = wizard_service.UDP_TOP_PORTS
VERSION = wizard_service.VERSION


def _sync_compat_globals() -> None:
    """Keep wizard_service globals aligned with this compatibility module."""
    wizard_service.os = os
    wizard_service.sys = sys
    wizard_service.platform = platform
    wizard_service.re = re
    wizard_service.shutil = shutil
    wizard_service.subprocess = subprocess
    wizard_service.time = time
    wizard_service.parse_target_tokens = parse_target_tokens
    wizard_service.expand_user_path = expand_user_path
    wizard_service.get_default_reports_base_dir = get_default_reports_base_dir
    wizard_service.get_invoking_user = get_invoking_user
    wizard_service.is_dry_run = is_dry_run


class Wizard(WizardService):
    """Backward-compatible alias for legacy imports."""

    def __getattribute__(self, name: str):
        _sync_compat_globals()
        return super().__getattribute__(name)


__all__ = [name for name in globals() if not name.startswith("_")]
