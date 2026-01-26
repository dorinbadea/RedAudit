#!/usr/bin/env python3
"""
Coverage for applying persisted defaults in auditor.
"""

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.utils.constants import DEFAULT_THREADS, MAX_THREADS, MIN_THREADS


def _make_auditor():
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor.config = {"threads": DEFAULT_THREADS}
    auditor.rate_limit_delay = 0.0
    return auditor


def test_apply_run_defaults_valid():
    auditor = _make_auditor()
    defaults = {
        "scan_mode": "full",
        "threads": MIN_THREADS + 1,
        "rate_limit": 2.5,
        "scan_vulnerabilities": False,
        "nuclei_enabled": True,
        "nuclei_max_runtime": 30,
        "cve_lookup_enabled": True,
    }

    InteractiveNetworkAuditor._apply_run_defaults(auditor, defaults)

    assert auditor.config["scan_mode"] == "full"
    assert auditor.config["threads"] == MIN_THREADS + 1
    assert auditor.rate_limit_delay == 2.5
    assert auditor.config["scan_vulnerabilities"] is False
    assert auditor.config["nuclei_enabled"] is True
    assert auditor.config["nuclei_max_runtime"] == 30
    assert auditor.config["cve_lookup_enabled"] is True


def test_apply_run_defaults_invalid_values():
    auditor = _make_auditor()
    defaults = {
        "threads": MAX_THREADS + 100,
        "rate_limit": -1,
        "nuclei_max_runtime": -5,
    }

    InteractiveNetworkAuditor._apply_run_defaults(auditor, defaults)

    assert auditor.config["threads"] == DEFAULT_THREADS
    assert auditor.rate_limit_delay == 0.0
    assert auditor.config["nuclei_max_runtime"] == 0
