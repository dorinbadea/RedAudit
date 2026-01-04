"""
Centralized pytest fixtures for RedAudit test suite.

This module provides shared mock objects and fixtures to eliminate
duplication across test files.
"""

import logging
import pytest
from unittest.mock import MagicMock, patch

from redaudit.core.config_context import ConfigurationContext
from redaudit.core.network_scanner import NetworkScanner


# ==============================================================================
# Mock Classes for Mixin Testing
# ==============================================================================


class MockAuditorBase:
    """Base mock auditor with common attributes required by all mixins."""

    def __init__(self, config=None):
        self.config = config or {
            "scan_mode": "default",
            "output_dir": "/tmp",
            "lang": "en",
            "dry_run": False,
            "timing_mode": "balanced",
            "max_threads": 4,
            "deep_scan_enabled": True,
            "windows_verify_enabled": False,
            "udp_mode": "quick",
        }
        self.cfg = ConfigurationContext(self.config)

        self.logger = MagicMock(spec=logging.Logger)
        self.results = {}
        self.extra_tools = {"nmap": "/usr/bin/nmap"}
        self.rate_limit_delay = 0.0
        self.interrupted = False
        self.lang = self.config.get("lang", "en")
        self.COLORS = {
            "HEADER": "",
            "OKGREEN": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
        }
        self.cryptography_available = True
        self.console = MagicMock()

        # v4.0 Compatibility: Mock UI Manager
        self.ui = MagicMock()
        self.ui.colors = self.COLORS
        self.ui.t.side_effect = self.t
        self.ui.print_status = MagicMock()

        # v4.0 Scanner Composition
        self.scanner = NetworkScanner(self.cfg, self.ui, self.logger)

    def print_status(self, msg, status_type="info", **kwargs):
        pass

    def t(self, key, *args):
        """Translation stub."""
        return f"{key}_{'_'.join(map(str, args))}" if args else key

    def ask_choice(self, question, options):
        return 0

    def ask_choice_with_back(self, question, options):
        return 0

    def ask_text(self, prompt, default=""):
        return default

    def ask_yes_no(self, question, default=True):
        return default

    def ask_manual_network(self):
        return "192.168.1.0/24"

    def _set_ui_detail(self, detail):
        pass

    def _get_ui_detail(self):
        return ""

    def _progress_ui(self):
        return MagicMock()

    def _progress_console(self):
        return MagicMock()

    def _progress_columns(self, **kwargs):
        return []

    def _safe_text_column(self, *args, **kwargs):
        return MagicMock()

    def _format_eta(self, seconds):
        return "00:00"

    def _touch_activity(self):
        pass

    def _coerce_text(self, value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value) if value is not None else ""


# ==============================================================================
# Pytest Fixtures
# ==============================================================================


@pytest.fixture
def mock_auditor():
    """Provides a basic MockAuditorBase instance."""
    return MockAuditorBase()


@pytest.fixture
def mock_auditor_with_config():
    """Factory fixture for MockAuditorBase with custom config."""

    def _factory(config=None):
        return MockAuditorBase(config=config)

    return _factory


@pytest.fixture
def mock_nmap_module():
    """Mock for python-nmap module."""
    mock_module = MagicMock()
    mock_scanner = MagicMock()
    mock_module.PortScanner.return_value = mock_scanner
    mock_scanner.all_hosts.return_value = []
    return mock_module, mock_scanner


@pytest.fixture
def mock_logger():
    """Mock logger instance."""
    return MagicMock(spec=logging.Logger)


@pytest.fixture
def sample_host_result():
    """Sample host scan result for testing reporters."""
    return {
        "ip": "192.168.1.100",
        "hostname": "test-host.local",
        "status": "up",
        "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "Test Vendor",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.0",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "Apache 2.4",
            },
        ],
        "os_detection": "Linux 5.x",
        "smart_scan": {
            "identity_score": 85,
            "classification": "server",
        },
    }


@pytest.fixture
def sample_network_info():
    """Sample network detection result."""
    return [
        {
            "network": "192.168.1.0/24",
            "interface": "eth0",
            "gateway": "192.168.1.1",
            "hosts_estimated": 254,
        }
    ]


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability finding."""
    return {
        "host": "192.168.1.100",
        "port": 80,
        "template_id": "CVE-2021-12345",
        "name": "Test Vulnerability",
        "severity": "high",
        "description": "Test description",
        "reference": "https://example.com/cve",
        "matcher_name": "test-matcher",
    }


# ==============================================================================
# Context Manager Fixtures
# ==============================================================================


@pytest.fixture
def patch_shutil_which():
    """Patch shutil.which to return specified path or None."""

    def _patcher(return_value="/usr/bin/nmap"):
        return patch("shutil.which", return_value=return_value)

    return _patcher


@pytest.fixture
def patch_subprocess_run():
    """Patch subprocess.run for command testing."""

    def _patcher(return_value=None):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = return_value or ""
        mock_result.stderr = ""
        return patch("subprocess.run", return_value=mock_result)

    return _patcher


# ==============================================================================
# Test Data Constants
# ==============================================================================

SAMPLE_IPS = [
    "192.168.1.1",
    "192.168.1.10",
    "192.168.1.100",
    "10.0.0.1",
    "172.16.0.1",
]

SAMPLE_MACS = [
    "AA:BB:CC:DD:EE:FF",
    "00:11:22:33:44:55",
    "DE:AD:BE:EF:CA:FE",
]

SAMPLE_PORTS = [22, 80, 443, 3389, 445, 8080, 8443]

VPN_VENDOR_OUIS = [
    "00:1B:17",  # Palo Alto
    "00:09:0F",  # Fortinet
    "00:00:0C",  # Cisco
]
