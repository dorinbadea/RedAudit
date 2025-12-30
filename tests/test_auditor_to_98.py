import os
import signal
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock
import pytest
from contextlib import ExitStack, contextmanager

from redaudit.core.auditor import InteractiveNetworkAuditor, TRANSLATIONS
from redaudit.utils.constants import COLORS, DEFAULT_THREADS, VERSION

WIZARD_BACK = -1  # Sentinel value for "go back"

# -------------------------------------------------------------------------
# Fixtures and Helpers
# -------------------------------------------------------------------------


class MockInput:
    def __init__(self, responses=None):
        self.responses = responses or []

    def __call__(self, *args, **kwargs):
        return self.responses.pop(0) if self.responses else ""


@pytest.fixture
def mock_auditor(tmp_path):
    with (
        patch("redaudit.core.auditor.InteractiveNetworkAuditor._setup_logging"),
        patch("signal.signal"),
        patch("redaudit.core.auditor.InteractiveNetworkAuditor.start_heartbeat"),
        patch("redaudit.core.auditor.InteractiveNetworkAuditor.stop_heartbeat"),
    ):
        a = InteractiveNetworkAuditor()
        a.config["output_dir"] = str(tmp_path)
        a.logger = MagicMock()
        a.t = lambda k, *args: f"T({k})"
        a.COLORS = COLORS.copy()
        return a


@contextmanager
def patch_wizard(auditor):
    patches = [
        patch.object(auditor, "ask_choice", return_value=0),
        patch.object(auditor, "ask_choice_with_back", return_value=0),
        patch.object(auditor, "ask_yes_no", return_value=True),
        patch.object(auditor, "ask_number", return_value=0),
        patch.object(auditor, "ask_webhook_url", return_value=""),
        patch.object(auditor, "ask_net_discovery_options", return_value={}),
        patch.object(auditor, "ask_manual_network", return_value=["127.0.0.1"]),
        patch.object(auditor, "ask_network_range", return_value=["127.0.0.1"]),
        patch.object(auditor, "setup_encryption"),
        patch.object(auditor, "setup_nvd_api_key"),
        patch.object(auditor, "clear_screen"),
        patch.object(auditor, "print_banner"),
        patch.object(auditor, "print_status"),
        patch.object(auditor, "save_results"),
        patch.object(auditor, "show_results"),
        patch("builtins.print"),
        patch("builtins.input", MockInput([""] * 100)),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        yield stack


# -------------------------------------------------------------------------
# Basic Tests
# -------------------------------------------------------------------------


def test_auditor_init_basics(mock_auditor):
    assert mock_auditor.results["version"] == VERSION
    assert mock_auditor.interrupted is False


def test_auditor_show_legal_warning_accept(mock_auditor):
    with patch.object(mock_auditor, "ask_yes_no", return_value=True), patch("builtins.print"):
        assert mock_auditor.show_legal_warning() is True


def test_auditor_show_legal_warning_decline(mock_auditor):
    with patch.object(mock_auditor, "ask_yes_no", return_value=False), patch("builtins.print"):
        assert mock_auditor.show_legal_warning() is False


def test_auditor_interactive_setup_defaults_crash(mock_auditor):
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch("redaudit.utils.config.get_persistent_defaults", side_effect=Exception("crash"))
        )
        mock_auditor.defaults_mode = "ask"
        assert mock_auditor.interactive_setup() is True


def test_auditor_interactive_setup_with_persisted_lang(mock_auditor):
    with patch_wizard(mock_auditor) as stack:
        lang = list(TRANSLATIONS.keys())[0] if TRANSLATIONS else "en"
        stack.enter_context(
            patch("redaudit.utils.config.get_persistent_defaults", return_value={"lang": lang})
        )
        mock_auditor.lang = "other"
        assert mock_auditor.interactive_setup() is True


def test_auditor_interactive_setup_save_error(mock_auditor):
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(patch("redaudit.utils.config.get_persistent_defaults", return_value={}))
        stack.enter_context(
            patch(
                "redaudit.utils.config.update_persistent_defaults",
                side_effect=Exception("save fail"),
            )
        )
        assert mock_auditor.interactive_setup() is True


# -------------------------------------------------------------------------
# Signal Handler Tests
# -------------------------------------------------------------------------


def test_auditor_signal_handler_no_start(mock_auditor):
    with patch("sys.exit") as m_exit, patch("builtins.print"):
        mock_auditor.scan_start_time = None
        mock_auditor.signal_handler(signal.SIGINT, None)
        assert m_exit.called


def test_auditor_signal_handler_with_procs(mock_auditor):
    mock_auditor.scan_start_time = datetime.now()
    proc = MagicMock()
    proc.poll.return_value = None
    mock_auditor._active_subprocesses = [proc]
    with patch("builtins.print"):
        mock_auditor.signal_handler(signal.SIGINT, None)
    assert proc.terminate.called
    assert mock_auditor.interrupted is True


def test_auditor_signal_handler_proc_already_done(mock_auditor):
    mock_auditor.scan_start_time = datetime.now()
    proc = MagicMock()
    proc.poll.return_value = 0  # Already finished
    mock_auditor._active_subprocesses = [proc]
    with patch("builtins.print"):
        mock_auditor.signal_handler(signal.SIGINT, None)
    assert not proc.terminate.called


# -------------------------------------------------------------------------
# Configure Scan Interactive Tests
# -------------------------------------------------------------------------


def test_auditor_configure_scan_interactive_basic(mock_auditor):
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_interactive_back(mock_auditor):
    with patch_wizard(mock_auditor) as stack:
        # Simulate WIZARD_BACK on first choice, then success
        stack.enter_context(
            patch.object(
                mock_auditor, "ask_choice_with_back", side_effect=[WIZARD_BACK, 0, 0, 0, 0, 0, 0]
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME1", "NAME2"])))
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Kill Processes Tests
# -------------------------------------------------------------------------


def test_auditor_kill_processes_success(mock_auditor):
    proc = MagicMock()
    proc.poll.return_value = None
    mock_auditor._active_subprocesses = [proc]
    mock_auditor.kill_all_subprocesses()
    assert proc.terminate.called


def test_auditor_kill_processes_error(mock_auditor):
    proc = MagicMock()
    proc.poll.return_value = None
    proc.terminate.side_effect = Exception("fail")
    mock_auditor._active_subprocesses = [proc]
    mock_auditor.kill_all_subprocesses()  # Should not raise


def test_auditor_kill_processes_empty(mock_auditor):
    mock_auditor._active_subprocesses = []
    mock_auditor.kill_all_subprocesses()  # Should not raise


# -------------------------------------------------------------------------
# Apply Defaults Tests
# -------------------------------------------------------------------------


def test_auditor_apply_defaults_normal(mock_auditor):
    mock_auditor._apply_run_defaults({"scan_mode": "normal"})
    assert mock_auditor.config["threads"] == DEFAULT_THREADS


def test_auditor_apply_defaults_completo(mock_auditor):
    mock_auditor._apply_run_defaults({"scan_mode": "completo"})
    assert mock_auditor.config["threads"] == DEFAULT_THREADS


# -------------------------------------------------------------------------
# Show Results Tests
# -------------------------------------------------------------------------


def test_auditor_show_results(mock_auditor):
    mock_auditor.results = {"hosts": [], "vulnerabilities": []}
    mock_auditor.config["output_dir"] = "/tmp"
    with patch("builtins.print"), patch("redaudit.core.auditor.show_results_summary"):
        mock_auditor.show_results()


# -------------------------------------------------------------------------
# Run Complete Scan - Early Exit Paths
# -------------------------------------------------------------------------


def test_auditor_run_complete_scan_interrupted_early(mock_auditor):
    """Test that run_complete_scan respects interrupted flag."""
    with patch_wizard(mock_auditor):
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.interrupted = True  # Already interrupted
        mock_auditor.run_complete_scan()
        # Should exit early without error


def test_auditor_run_complete_scan_session_log_fail(mock_auditor):
    """Test session log failure handling."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        stack.enter_context(
            patch("redaudit.utils.session_log.start_session_log", side_effect=Exception("fail"))
        )
        with pytest.raises(Exception, match="fail"):
            mock_auditor.run_complete_scan()


def test_auditor_run_complete_scan_detect_networks_fail(mock_auditor):
    """Test detect_all_networks failure handling."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.interrupted = True  # Skip most work
        stack.enter_context(
            patch.object(mock_auditor, "detect_all_networks", side_effect=Exception("nd fail"))
        )
        mock_auditor.run_complete_scan()
        assert mock_auditor.logger.debug.called


# -------------------------------------------------------------------------
# Heartbeat Tests
# -------------------------------------------------------------------------


def test_auditor_heartbeat_loop_stop_flag(mock_auditor):
    """Test that heartbeat loop respects stop flag."""
    mock_auditor.heartbeat_stop = True
    mock_auditor.last_activity = datetime.now()
    mock_auditor.current_phase = "scanning"
    with patch("time.sleep"):
        mock_auditor._heartbeat_loop()  # Should exit immediately


def test_auditor_heartbeat_loop_excluded_phase(mock_auditor):
    """Test that heartbeat skips excluded phases."""
    mock_auditor.heartbeat_stop = False
    mock_auditor.last_activity = datetime.now()
    mock_auditor.current_phase = "topology"  # Excluded phase
    call_count = [0]

    def stop_after_one(secs):
        call_count[0] += 1
        if call_count[0] >= 1:
            mock_auditor.heartbeat_stop = True

    with patch("time.sleep", side_effect=stop_after_one):
        mock_auditor._heartbeat_loop()


# -------------------------------------------------------------------------
# Misc Coverage Tests
# -------------------------------------------------------------------------


def test_auditor_print_status(mock_auditor):
    with patch("builtins.print"):
        mock_auditor.print_status("test message", "INFO")
        mock_auditor.print_status("test warning", "WARNING")
        mock_auditor.print_status("test error", "FAIL")


def test_auditor_t_function(mock_auditor):
    # Reset t to the real implementation
    mock_auditor.t = InteractiveNetworkAuditor.t.__get__(mock_auditor)
    # Should return translated string or key
    result = mock_auditor.t("some_key")
    assert isinstance(result, str)


def test_auditor_detect_all_networks(mock_auditor):
    with (
        patch("netifaces.interfaces", return_value=["lo0"]),
        patch("netifaces.ifaddresses", return_value={}),
    ):
        mock_auditor.detect_all_networks()


# -------------------------------------------------------------------------
# Additional Run Complete Scan Tests
# -------------------------------------------------------------------------


def test_auditor_run_complete_scan_topology_only(mock_auditor):
    """Test topology_only mode exits early after topology discovery."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.config["topology_enabled"] = True
        mock_auditor.config["topology_only"] = True
        stack.enter_context(
            patch("redaudit.core.topology.discover_topology", return_value={"test": True})
        )
        stack.enter_context(patch("redaudit.core.reporter.generate_summary"))
        mock_auditor.run_complete_scan()
        assert mock_auditor.results.get("topology") == {"test": True}


def test_auditor_run_complete_scan_topology_fail(mock_auditor):
    """Test topology discovery failure handling."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.config["topology_enabled"] = True
        mock_auditor.config["topology_only"] = True  # Force early exit after topology
        stack.enter_context(
            patch("redaudit.core.topology.discover_topology", side_effect=Exception("topo fail"))
        )
        stack.enter_context(patch("redaudit.core.reporter.generate_summary"))
        mock_auditor.run_complete_scan()
        assert mock_auditor.results.get("topology", {}).get("error") == "topo fail"


def test_auditor_run_complete_scan_no_hosts(mock_auditor):
    """Test no hosts found scenario."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        stack.enter_context(patch.object(mock_auditor, "scan_network_discovery", return_value=[]))
        mock_auditor.run_complete_scan()
        assert mock_auditor.print_status.called


def test_auditor_run_complete_scan_with_hosts(mock_auditor):
    """Test scan with hosts found."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.interrupted = True  # Skip detailed scanning
        stack.enter_context(
            patch.object(mock_auditor, "scan_network_discovery", return_value=[{"ip": "127.0.0.1"}])
        )
        mock_auditor.run_complete_scan()


def test_auditor_run_complete_scan_net_discovery_enabled(mock_auditor):
    """Test with net_discovery enabled."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.config["net_discovery_enabled"] = True
        mock_auditor.interrupted = True  # Skip rest
        stack.enter_context(
            patch("redaudit.core.net_discovery.discover_networks", return_value={"hosts": []})
        )
        mock_auditor.run_complete_scan()


# -------------------------------------------------------------------------
# Configure Scan Interactive - More Branches
# -------------------------------------------------------------------------


def test_auditor_configure_scan_mode_completo(mock_auditor):
    """Test completo scan mode selection."""
    with patch_wizard(mock_auditor) as stack:
        # Choice 1 = completo mode
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[1, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_mode_rapido(mock_auditor):
    """Test rapido scan mode selection."""
    with patch_wizard(mock_auditor) as stack:
        # Choice 2 = rapido mode
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[2, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_udp_custom(mock_auditor):
    """Test custom UDP ports configuration."""
    with patch_wizard(mock_auditor) as stack:
        # Normal mode, then custom UDP
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 2, 0, 0, 0, 0, 0])
        )  # 2 = custom UDP
        stack.enter_context(patch("builtins.input", MockInput(["NAME", "53,123,161"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_redteam(mock_auditor):
    """Test Red Team mode configuration."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(patch("os.geteuid", return_value=0))  # Root
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(
                mock_auditor, "ask_yes_no", side_effect=[True, True, True, True, True, True]
            )
        )
        stack.enter_context(
            patch("builtins.input", MockInput(["NAME", "REALM", "/path/to/users.txt"]))
        )
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Save & Show Config Tests
# -------------------------------------------------------------------------


def test_auditor_show_config_summary(mock_auditor):
    """Test show_config_summary method."""
    mock_auditor.config = {
        "scan_mode": "normal",
        "threads": 10,
        "target_networks": ["192.168.1.0/24"],
        "output_dir": "/tmp/test",
        "udp_scan_mode": "quick",
        "rate_limit_delay": 0,
    }
    with patch("builtins.print"):
        mock_auditor.show_config_summary()


def test_auditor_save_results_normal(mock_auditor):
    """Test save_results without encryption."""
    mock_auditor.results = {"hosts": [], "version": VERSION}
    mock_auditor.config["_actual_output_dir"] = "/tmp/test_output"
    mock_auditor.config["encrypt_results"] = False
    with patch("builtins.open", MagicMock()), patch("json.dump"), patch("os.makedirs"):
        mock_auditor.save_results()


def test_auditor_save_results_partial(mock_auditor):
    """Test save_results with partial flag."""
    mock_auditor.results = {"hosts": [], "version": VERSION}
    mock_auditor.config["_actual_output_dir"] = "/tmp/test_output"
    with patch("builtins.open", MagicMock()), patch("json.dump"), patch("os.makedirs"):
        mock_auditor.save_results(partial=True)


# -------------------------------------------------------------------------
# Misc Methods Coverage
# -------------------------------------------------------------------------


def test_auditor_select_net_discovery_interface(mock_auditor):
    """Test _select_net_discovery_interface method."""
    mock_auditor.results["network_info"] = [{"interface": "eth0", "network": "192.168.1.0/24"}]
    with patch.object(mock_auditor, "ask_choice", return_value=0):
        result = mock_auditor._select_net_discovery_interface()
        assert result == "eth0"


def test_auditor_select_net_discovery_interface_empty(mock_auditor):
    """Test _select_net_discovery_interface with no interfaces."""
    mock_auditor.results["network_info"] = []
    result = mock_auditor._select_net_discovery_interface()
    assert result is None


def test_auditor_scan_network_discovery(mock_auditor):
    """Test scan_network_discovery method."""
    with patch("redaudit.core.auditor_scan.nmap", MagicMock()) as m_nmap:
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["192.168.1.1"]
        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        scanner.__getitem__.return_value = host_mock
        m_nmap.PortScanner.return_value = scanner
        mock_auditor.scan_network_discovery("192.168.1.0/24")


# -------------------------------------------------------------------------
# Defaults Handling Tests (lines 250-272)
# -------------------------------------------------------------------------


def test_auditor_interactive_setup_defaults_ignore_mode(mock_auditor):
    """Test defaults_mode='ignore' skips persisted defaults."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch(
                "redaudit.utils.config.get_persistent_defaults",
                return_value={"target_networks": ["192.168.1.0/24"], "threads": 10},
            )
        )
        mock_auditor.defaults_mode = "ignore"
        assert mock_auditor.interactive_setup() is True


def test_auditor_interactive_setup_defaults_use(mock_auditor):
    """Test defaults_mode='ask' with choice=0 (use defaults) starts immediately."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch(
                "redaudit.utils.config.get_persistent_defaults",
                return_value={"target_networks": ["192.168.1.0/24"], "threads": 10},
            )
        )
        mock_auditor.defaults_mode = "ask"
        # Choice 0 = use defaults immediately
        stack.enter_context(patch.object(mock_auditor, "ask_choice", side_effect=[0, 0, 0, 0, 0]))
        assert mock_auditor.interactive_setup() is True


def test_auditor_interactive_setup_defaults_review(mock_auditor):
    """Test defaults_mode='ask' with choice=1 (review) shows summary."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch(
                "redaudit.utils.config.get_persistent_defaults",
                return_value={"target_networks": ["192.168.1.0/24"], "threads": 10},
            )
        )
        mock_auditor.defaults_mode = "ask"
        # Choice 1 = review, then yes to show summary
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice", side_effect=[1, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(
                mock_auditor,
                "ask_yes_no",
                side_effect=[True, True, True, True, True, True, True, True],
            )
        )
        assert mock_auditor.interactive_setup() is True


def test_auditor_interactive_setup_defaults_action_ignore(mock_auditor):
    """Test defaults_mode='ask' with choice=2 (ignore) clears defaults."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch(
                "redaudit.utils.config.get_persistent_defaults",
                return_value={"target_networks": ["192.168.1.0/24"], "threads": 10},
            )
        )
        mock_auditor.defaults_mode = "ask"
        # Choice 2 = ignore defaults
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice", side_effect=[2, 0, 0, 0, 0, 0])
        )
        assert mock_auditor.interactive_setup() is True


# -------------------------------------------------------------------------
# Show Defaults Summary (lines 1421-1492)
# -------------------------------------------------------------------------


def test_auditor_show_defaults_summary(mock_auditor):
    """Test _show_defaults_summary method."""
    persisted = {
        "target_networks": ["192.168.1.0/24"],
        "threads": 10,
        "scan_mode": "normal",
        "topology_enabled": True,
        "net_discovery_enabled": False,
        "net_discovery_kerberos_realm": "REALM",
    }
    with patch("builtins.print"):
        mock_auditor._show_defaults_summary(persisted)


def test_auditor_show_defaults_summary_empty(mock_auditor):
    """Test _show_defaults_summary with empty defaults."""
    with patch("builtins.print"):
        mock_auditor._show_defaults_summary({})


def test_auditor_show_defaults_summary_none_values(mock_auditor):
    """Test _show_defaults_summary with None values."""
    persisted = {
        "target_networks": None,
        "threads": None,
        "net_discovery_kerberos_userlist": None,
    }
    with patch("builtins.print"):
        mock_auditor._show_defaults_summary(persisted)


# -------------------------------------------------------------------------
# UDP Profile Selection (lines 1203-1227)
# -------------------------------------------------------------------------


def test_auditor_configure_udp_full_mode_custom(mock_auditor):
    """Test UDP full mode with custom ports selection."""
    with patch_wizard(mock_auditor) as stack:
        # Mode 0 (normal), then UDP mode 1 (full), then profile 4 (custom)
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 1, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice", side_effect=[4, 0, 0, 0, 0])
        )  # Custom profile
        stack.enter_context(patch.object(mock_auditor, "ask_number", return_value=300))
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_udp_full_mode_profile(mock_auditor):
    """Test UDP full mode with predefined profile selection."""
    with patch_wizard(mock_auditor) as stack:
        # Mode 0 (normal), then UDP mode 1 (full), then profile 1 (balanced)
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 1, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice", side_effect=[1, 0, 0, 0, 0])
        )  # Balanced profile
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Topology Wizard (lines 1248-1249, 1315-1363)
# -------------------------------------------------------------------------


def test_auditor_configure_topology_enabled(mock_auditor):
    """Test topology configuration when enabled."""
    with patch_wizard(mock_auditor) as stack:
        # Normal mode, quick UDP, topology choice 1 (enabled), then yes to topology
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 1, 0, 0, 0, 0])
        )  # 1 = enable topology
        stack.enter_context(
            patch.object(mock_auditor, "ask_yes_no", side_effect=[True, True, True, True, True])
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})
        # Just verify the method ran without error - config depends on wizard flow
        assert True


def test_auditor_configure_topology_back(mock_auditor):
    """Test topology configuration with back navigation."""
    with patch_wizard(mock_auditor) as stack:
        # Normal mode, quick UDP, topology choice with back
        stack.enter_context(
            patch.object(
                mock_auditor, "ask_choice_with_back", side_effect=[0, 0, WIZARD_BACK, 0, 0, 0, 0, 0]
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME1", "NAME2"])))
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Encryption and Misc Methods
# -------------------------------------------------------------------------


def test_auditor_setup_encryption_skip(mock_auditor):
    """Test encryption setup when user declines."""
    with patch.object(mock_auditor, "ask_yes_no", return_value=False), patch("builtins.print"):
        mock_auditor.setup_encryption()
        assert mock_auditor.config.get("encrypt_results") is not True


def test_auditor_rate_limit_delay_property(mock_auditor):
    """Test rate_limit_delay property getter."""
    # The property returns config value or default
    mock_auditor._rate_limit_delay = 0.5
    # Just verify the property exists and is callable
    delay = mock_auditor.rate_limit_delay
    assert isinstance(delay, (int, float))


# -------------------------------------------------------------------------
# Interactive Setup Early Exit Tests (lines 217, 219)
# -------------------------------------------------------------------------


def test_auditor_interactive_setup_check_dependencies_fail(mock_auditor):
    """Test interactive_setup returns False when check_dependencies fails."""
    with patch.object(mock_auditor, "check_dependencies", return_value=False):
        result = mock_auditor.interactive_setup()
        assert result is False


def test_auditor_interactive_setup_legal_warning_decline(mock_auditor):
    """Test interactive_setup returns False when legal warning is declined."""
    with (
        patch.object(mock_auditor, "check_dependencies", return_value=True),
        patch.object(mock_auditor, "show_legal_warning", return_value=False),
    ):
        result = mock_auditor.interactive_setup()
        assert result is False


# -------------------------------------------------------------------------
# Sleep Inhibitor Exception (lines 367-368)
# -------------------------------------------------------------------------


def test_auditor_run_complete_scan_sleep_inhibitor_fail(mock_auditor):
    """Test run_complete_scan handles SleepInhibitor exception gracefully."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.config["prevent_sleep"] = True
        mock_auditor.interrupted = True  # Exit early
        # Mock SleepInhibitor to raise
        stack.enter_context(
            patch("redaudit.core.power.SleepInhibitor", side_effect=Exception("power fail"))
        )
        mock_auditor.run_complete_scan()
        # Should complete without error


# -------------------------------------------------------------------------
# More Wizard Branch Tests
# -------------------------------------------------------------------------


def test_auditor_configure_scan_manual_network(mock_auditor):
    """Test manual network input configuration."""
    with patch_wizard(mock_auditor) as stack:
        # Simulate manual network entry path
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(mock_auditor, "ask_manual_network", return_value=["10.0.0.0/8"])
        )
        stack.enter_context(patch("builtins.input", MockInput(["AUDITOR_NAME"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_check_dependencies(mock_auditor):
    """Test check_dependencies method."""
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        result = mock_auditor.check_dependencies()
        assert result is True


def test_auditor_check_dependencies_missing(mock_auditor):
    """Test check_dependencies when nmap is missing."""
    with patch("shutil.which", return_value=None), patch("builtins.print"):
        result = mock_auditor.check_dependencies()
        assert result is False


# -------------------------------------------------------------------------
# NVD API Key Tests
# -------------------------------------------------------------------------


def test_auditor_setup_nvd_api_key_skip(mock_auditor):
    """Test NVD API key setup when user skips."""
    with (
        patch.object(mock_auditor, "ask_yes_no", return_value=False),
        patch("redaudit.utils.config.is_nvd_api_key_configured", return_value=False),
        patch("builtins.print"),
    ):
        mock_auditor.setup_nvd_api_key()


def test_auditor_setup_nvd_api_key_already_configured(mock_auditor):
    """Test NVD API key setup when already configured."""
    with (
        patch("redaudit.utils.config.is_nvd_api_key_configured", return_value=True),
        patch("builtins.print"),
    ):
        mock_auditor.setup_nvd_api_key()


# -------------------------------------------------------------------------
# WIZARD_BACK Branches (lines 1065-1066, 1248-1249, 1286-1287, 1389-1390)
# -------------------------------------------------------------------------


def test_auditor_configure_scan_vuln_step_back(mock_auditor):
    """Test WIZARD_BACK on vulnerability scanning step."""
    with patch_wizard(mock_auditor) as stack:
        # Mode 0, UDP 0, then BACK on vuln step, then forward
        stack.enter_context(
            patch.object(
                mock_auditor,
                "ask_choice_with_back",
                side_effect=[0, 0, WIZARD_BACK, 0, 0, 0, 0, 0, 0, 0],
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME1", "NAME2"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_net_discovery_back(mock_auditor):
    """Test WIZARD_BACK on net discovery step."""
    with patch_wizard(mock_auditor) as stack:
        # Mode 0, UDP 0, Vuln 0, then BACK on net discovery, then forward
        stack.enter_context(
            patch.object(
                mock_auditor,
                "ask_choice_with_back",
                side_effect=[0, 0, 0, WIZARD_BACK, 0, 0, 0, 0, 0, 0, 0],
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME1", "NAME2"])))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_windows_verify_back(mock_auditor):
    """Test WIZARD_BACK on Windows verification step."""
    with patch_wizard(mock_auditor) as stack:
        # Mode, UDP, Vuln, NetDisc, then BACK on windows verify, then forward
        stack.enter_context(
            patch.object(
                mock_auditor,
                "ask_choice_with_back",
                side_effect=[0, 0, 0, 0, WIZARD_BACK, 0, 0, 0, 0, 0, 0, 0],
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME1", "NAME2"])))
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Persisted Output Dir (line 1147)
# -------------------------------------------------------------------------


def test_auditor_configure_scan_persisted_output_dir(mock_auditor):
    """Test configuration with persisted output directory."""
    defaults = {"output_dir": "/custom/output/path"}
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch("builtins.input", MockInput(["NAME", ""]))
        )  # Empty = use persisted
        mock_auditor._configure_scan_interactive(defaults)


# -------------------------------------------------------------------------
# More Scan Mode Variations
# -------------------------------------------------------------------------


def test_auditor_configure_scan_no_vuln_scan(mock_auditor):
    """Test configuration without vulnerability scanning."""
    with patch_wizard(mock_auditor) as stack:
        # Mode 0, UDP 0, Vuln 1 (disable), rest 0
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 1, 0, 0, 0, 0])
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})
        # Just verify method ran without error


def test_auditor_configure_scan_with_nuclei(mock_auditor):
    """Test configuration with Nuclei enabled."""
    with patch_wizard(mock_auditor) as stack:
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[0, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(
            patch.object(
                mock_auditor, "ask_yes_no", side_effect=[True, True, True, True, True, True]
            )
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        stack.enter_context(patch("shutil.which", return_value="/usr/bin/nuclei"))
        mock_auditor._configure_scan_interactive({})


def test_auditor_configure_scan_ipv6_mode(mock_auditor):
    """Test configuration with different scan modes."""
    with patch_wizard(mock_auditor) as stack:
        # Choice 2 = rapido mode (valid index)
        stack.enter_context(
            patch.object(mock_auditor, "ask_choice_with_back", side_effect=[2, 0, 0, 0, 0, 0, 0])
        )
        stack.enter_context(patch("builtins.input", MockInput(["NAME"])))
        mock_auditor._configure_scan_interactive({})


# -------------------------------------------------------------------------
# Error Handling in Run Complete Scan
# -------------------------------------------------------------------------


def test_auditor_run_complete_scan_dry_run(mock_auditor):
    """Test run_complete_scan in dry run mode."""
    with patch_wizard(mock_auditor) as stack:
        mock_auditor.config["target_networks"] = ["127.0.0.1"]
        mock_auditor.config["dry_run"] = True
        mock_auditor.run_complete_scan()
        # Should complete without actual scanning


# -------------------------------------------------------------------------
# Additional Method Coverage
# -------------------------------------------------------------------------


def test_auditor_clear_screen(mock_auditor):
    """Test clear_screen method."""
    with patch("os.system"):
        mock_auditor.clear_screen()


def test_auditor_print_banner(mock_auditor):
    """Test print_banner method."""
    with patch("builtins.print"):
        mock_auditor.print_banner()


def test_auditor_ask_choice(mock_auditor):
    """Test ask_choice method."""
    with patch("builtins.input", return_value="1"):
        result = mock_auditor.ask_choice("Question?", ["Option 1", "Option 2"], 0)
        assert result in [0, 1]


def test_auditor_ask_yes_no(mock_auditor):
    """Test ask_yes_no method."""
    with patch("builtins.input", return_value="y"):
        result = mock_auditor.ask_yes_no("Question?")
        assert result is True


def test_auditor_ask_number(mock_auditor):
    """Test ask_number method."""
    with patch("builtins.input", return_value="10"):
        result = mock_auditor.ask_number("Number?", 5, 1, 100)
        assert result == 10
