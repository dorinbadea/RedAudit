"""Tests for auditor.py to push coverage to 95%+
Targets main orchestrator logic, subprocess management, and interactive configuration.
"""

import os
import signal
import subprocess
import threading
from unittest.mock import patch, MagicMock
import pytest
from redaudit.core.auditor import InteractiveNetworkAuditor


def test_auditor_init_with_env():
    """Test InteractiveNetworkAuditor init with environment variables (lines 73-161)."""
    with patch("redaudit.core.auditor.DEFAULT_LANG", "es"):
        auditor = InteractiveNetworkAuditor()
        assert auditor.lang == "es"


def test_auditor_subprocess_management():
    """Test register/unregister/kill subprocesses (lines 866-892)."""
    auditor = InteractiveNetworkAuditor()
    mock_proc = MagicMock(spec=subprocess.Popen)
    # Ensure poll() returns None so it's considered active
    mock_proc.poll.return_value = None

    auditor.register_subprocess(mock_proc)
    assert mock_proc in auditor._active_subprocesses

    auditor.unregister_subprocess(mock_proc)
    assert mock_proc not in auditor._active_subprocesses

    auditor.register_subprocess(mock_proc)
    auditor.kill_all_subprocesses()
    assert mock_proc.terminate.called


def test_auditor_signal_handler():
    """Test signal handler for SIGINT (lines 894-910)."""
    auditor = InteractiveNetworkAuditor()
    # Patch the instance method directly
    auditor.kill_all_subprocesses = MagicMock()
    auditor.stop_heartbeat = MagicMock()
    # Must have active subprocesses to call kill_all_subprocesses
    auditor._active_subprocesses.append(MagicMock())

    with pytest.raises(SystemExit):
        auditor.signal_handler(signal.SIGINT, None)

    assert auditor.interrupted is True
    assert auditor.kill_all_subprocesses.called
    assert auditor.stop_heartbeat.called


def test_auditor_apply_run_defaults():
    """Test _apply_run_defaults with varied config (lines 912-987)."""
    auditor = InteractiveNetworkAuditor()
    defaults = {
        "auditor_name": "Test",
        "output_dir": "/tmp/test",
        "scan_mode": "full",
        "target_networks": ["1.1.1.0/24"],
        "threads": 4,
        "deep_id_scan": True,
        "tcp_scan": True,
        "udp_scan": False,
        "vuln_scan": True,
        "nikto_enabled": False,
        "nuclei_enabled": True,
    }
    auditor._apply_run_defaults(defaults)
    assert auditor.config["auditor_name"] == "Test"
    assert auditor.config["threads"] == 4


def test_auditor_ask_auditor_non_interactive():
    """Test _ask_auditor_and_output_dir in non-interactive (lines 989-1021)."""
    auditor = InteractiveNetworkAuditor()
    defaults = {"auditor_name": "Admin", "output_dir": "/tmp"}
    with patch("builtins.input", side_effect=["", ""]):  # Use defaults
        auditor._ask_auditor_and_output_dir(defaults)
    assert auditor.config["auditor_name"] == "Admin"


def test_auditor_show_defaults_summary():
    """Test _show_defaults_summary formatting (lines 1646-1720)."""
    auditor = InteractiveNetworkAuditor()
    defaults = {
        "target_networks": ["1.1.1.0/24", "2.2.2.0/24"],
        "tcp_scan": True,
        "udp_scan": False,
    }
    # Simply covering the print logic
    with patch("builtins.print"):
        auditor._show_defaults_summary(defaults)


def test_run_complete_scan_short_circuit(tmp_path):
    """Test run_complete_scan with interrupted state (line 360)."""
    auditor = InteractiveNetworkAuditor()
    auditor.config["output_dir"] = str(tmp_path)
    auditor.interrupted = True
    assert auditor.run_complete_scan() is False


def test_run_complete_scan_no_setup(tmp_path):
    """Test run_complete_scan with quick profile (lines 430, 647)."""
    auditor = InteractiveNetworkAuditor()
    auditor.config["output_dir"] = str(tmp_path)
    auditor.config["target_networks"] = ["1.1.1.0/24"]

    # Mock all heavy dependencies
    with patch(
        "redaudit.core.net_discovery.discover_networks", return_value={"alive_hosts": ["1.1.1.1"]}
    ):
        with patch.object(auditor, "scan_network_discovery", return_value=["1.1.1.1"]):
            with patch.object(auditor, "scan_hosts_concurrent", return_value=[{"ip": "1.1.1.1"}]):
                with patch.object(auditor, "save_results"):
                    with patch.object(auditor, "detect_all_networks"):
                        # Ensure net_discovery is enabled to reach that path
                        auditor.config["net_discovery_enabled"] = True
                        # Completo mode triggers discover_networks
                        auditor.config["scan_mode"] = "completo"
                        auditor.run_complete_scan()
                        assert "net_discovery" in auditor.results
                        assert auditor.results["net_discovery"]["alive_hosts"] == ["1.1.1.1"]
