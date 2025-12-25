"""
Tests for proxy.py edge cases and missing coverage lines.
Target: Push proxy.py from 78% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
import socket


class TestParseProxyUrlEdgeCases:
    """Tests for parse_proxy_url edge cases (lines 36-57)."""

    def test_parse_proxy_url_empty_string(self):
        """Test empty URL returns None (line 36-37)."""
        from redaudit.core.proxy import parse_proxy_url

        result = parse_proxy_url("")
        assert result is None

    def test_parse_proxy_url_none(self):
        """Test None URL returns None."""
        from redaudit.core.proxy import parse_proxy_url

        result = parse_proxy_url(None)
        assert result is None

    def test_parse_proxy_url_host_port_only(self):
        """Test host:port format without scheme (line 40-41)."""
        from redaudit.core.proxy import parse_proxy_url

        result = parse_proxy_url("10.0.0.1:1080")

        assert result is not None
        assert result["type"] == "socks5"
        assert result["host"] == "10.0.0.1"
        assert result["port"] == 1080

    def test_parse_proxy_url_invalid_format(self):
        """Test invalid URL returns None (line 46-47)."""
        from redaudit.core.proxy import parse_proxy_url

        result = parse_proxy_url("not-a-valid-url")
        assert result is None

    def test_parse_proxy_url_exception(self):
        """Test exception handling returns None (lines 56-57)."""
        from redaudit.core.proxy import parse_proxy_url

        with patch("redaudit.core.proxy.urlparse") as mock_urlparse:
            mock_urlparse.side_effect = ValueError("Parse error")
            result = parse_proxy_url("socks5://10.0.0.1:1080")

        assert result is None


class TestTestProxyConnection:
    """Tests for test_proxy_connection function (lines 60-118)."""

    def test_test_proxy_connection_invalid_proxy(self):
        """Test None proxy returns False (lines 75-76)."""
        from redaudit.core.proxy import test_proxy_connection

        result = test_proxy_connection(None)

        assert result[0] is False
        assert "Invalid" in result[1]

    def test_test_proxy_connection_socket_fallback_success(self):
        """Test socket fallback when nc not available (lines 84-93)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 80, "type": "socks5"}

        with patch("shutil.which", return_value=None):  # No nc
            with patch("socket.socket") as mock_socket_class:
                mock_sock = MagicMock()
                mock_socket_class.return_value = mock_sock
                mock_sock.connect.return_value = None  # Success

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is True
        assert "reachable" in result[1]

    def test_test_proxy_connection_socket_fallback_failure(self):
        """Test socket fallback failure (lines 94-95)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 12345, "type": "socks5"}

        with patch("shutil.which", return_value=None):  # No nc
            with patch("socket.socket") as mock_socket_class:
                mock_sock = MagicMock()
                mock_socket_class.return_value = mock_sock
                mock_sock.connect.side_effect = socket.error("Connection refused")

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is False
        assert "failed" in result[1]

    def test_test_proxy_connection_nc_success(self):
        """Test nc success path (lines 110-111)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 1080, "type": "socks5"}

        with patch("shutil.which", return_value="/usr/bin/nc"):
            with patch("redaudit.core.proxy.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_runner.run.return_value = mock_result

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is True
        assert "reachable" in result[1]

    def test_test_proxy_connection_nc_failure(self):
        """Test nc failure path (lines 112-113)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 1080, "type": "socks5"}

        with patch("shutil.which", return_value="/usr/bin/nc"):
            with patch("redaudit.core.proxy.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_result = MagicMock()
                mock_result.returncode = 1  # Failure
                mock_runner.run.return_value = mock_result

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is False
        assert "not responding" in result[1]

    def test_test_proxy_connection_exception_timeout(self):
        """Test exception with timeout message (lines 114-117)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 1080, "type": "socks5"}

        with patch("shutil.which", return_value="/usr/bin/nc"):
            with patch("redaudit.core.proxy.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_runner.run.side_effect = Exception("Connection timed out")

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is False
        assert "timeout" in result[1].lower()

    def test_test_proxy_connection_exception_generic(self):
        """Test generic exception handling (line 118)."""
        from redaudit.core.proxy import test_proxy_connection

        proxy = {"host": "127.0.0.1", "port": 1080, "type": "socks5"}

        with patch("shutil.which", return_value="/usr/bin/nc"):
            with patch("redaudit.core.proxy.CommandRunner") as mock_runner_class:
                mock_runner = MagicMock()
                mock_runner_class.return_value = mock_runner
                mock_runner.run.side_effect = Exception("Unknown error")

                result = test_proxy_connection(proxy, timeout=5)

        assert result[0] is False
        assert "error" in result[1].lower()


class TestGenerateProxychainsConfig:
    """Tests for generate_proxychains_config (lines 121-155)."""

    def test_generate_config_with_auth(self):
        """Test config generation with user/password (lines 150-151)."""
        from redaudit.core.proxy import generate_proxychains_config

        proxy = {
            "type": "socks5",
            "host": "10.0.0.1",
            "port": 1080,
            "user": "admin",
            "password": "secret",
        }

        result = generate_proxychains_config(proxy)

        assert "socks5 10.0.0.1 1080 admin secret" in result

    def test_generate_config_without_auth(self):
        """Test config generation without auth (lines 152-153)."""
        from redaudit.core.proxy import generate_proxychains_config

        proxy = {
            "type": "socks5",
            "host": "10.0.0.1",
            "port": 1080,
            "user": None,
            "password": None,
        }

        result = generate_proxychains_config(proxy)

        assert "socks5 10.0.0.1 1080\n" in result or result.endswith("socks5 10.0.0.1 1080")


class TestCreateTempProxychainsConfig:
    """Tests for create_temp_proxychains_config (lines 158-178)."""

    def test_create_temp_config_success(self):
        """Test successful temp config creation (lines 168-176)."""
        from redaudit.core.proxy import create_temp_proxychains_config, cleanup_temp_config
        import os

        proxy = {"type": "socks5", "host": "10.0.0.1", "port": 1080}

        result = create_temp_proxychains_config(proxy)

        assert result is not None
        assert os.path.exists(result)
        assert "redaudit_proxy_" in result

        # Cleanup
        cleanup_temp_config(result)

    def test_create_temp_config_exception(self):
        """Test exception returns None (lines 177-178)."""
        from redaudit.core.proxy import create_temp_proxychains_config

        proxy = {"type": "socks5", "host": "10.0.0.1", "port": 1080}

        with patch("tempfile.mkstemp") as mock_mkstemp:
            mock_mkstemp.side_effect = OSError("Disk full")
            result = create_temp_proxychains_config(proxy)

        assert result is None


class TestCleanupTempConfig:
    """Tests for cleanup_temp_config (lines 181-192)."""

    def test_cleanup_existing_file(self, tmp_path):
        """Test cleanup removes existing file (lines 188-190)."""
        from redaudit.core.proxy import cleanup_temp_config
        import os

        test_file = tmp_path / "test.conf"
        test_file.write_text("config content")

        cleanup_temp_config(str(test_file))

        assert not os.path.exists(test_file)

    def test_cleanup_nonexistent_file(self):
        """Test cleanup handles non-existent file (line 189)."""
        from redaudit.core.proxy import cleanup_temp_config

        # Should not raise
        cleanup_temp_config("/nonexistent/path.conf")

    def test_cleanup_exception_silenced(self, tmp_path):
        """Test cleanup silences exceptions (lines 191-192)."""
        from redaudit.core.proxy import cleanup_temp_config

        test_file = tmp_path / "test.conf"
        test_file.write_text("content")

        with patch("os.remove") as mock_remove:
            mock_remove.side_effect = PermissionError("Access denied")
            # Should not raise
            cleanup_temp_config(str(test_file))


class TestWrapCommandWithProxychains:
    """Tests for wrap_command_with_proxychains (lines 195-225)."""

    def test_wrap_command_no_proxychains(self):
        """Test when proxychains not available (lines 213-215)."""
        from redaudit.core.proxy import wrap_command_with_proxychains

        proxy = {"type": "socks5", "host": "10.0.0.1", "port": 1080}
        cmd = ["nmap", "-sV", "target"]

        with patch("shutil.which", return_value=None):
            result_cmd, config_path = wrap_command_with_proxychains(cmd, proxy)

        assert result_cmd == cmd
        assert config_path is None

    def test_wrap_command_config_creation_fails(self):
        """Test when config creation fails (lines 219-220)."""
        from redaudit.core.proxy import wrap_command_with_proxychains

        proxy = {"type": "socks5", "host": "10.0.0.1", "port": 1080}
        cmd = ["nmap", "-sV", "target"]

        with patch("shutil.which", return_value="/usr/bin/proxychains4"):
            with patch("redaudit.core.proxy.create_temp_proxychains_config", return_value=None):
                result_cmd, config_path = wrap_command_with_proxychains(cmd, proxy)

        assert result_cmd == cmd
        assert config_path is None


class TestGetNmapProxyArgs:
    """Tests for get_nmap_proxy_args (lines 228-254)."""

    def test_get_nmap_proxy_args_none(self):
        """Test None proxy returns empty (lines 241-242)."""
        from redaudit.core.proxy import get_nmap_proxy_args

        result = get_nmap_proxy_args(None)
        assert result == ""

    def test_get_nmap_proxy_args_socks4(self):
        """Test socks4 proxy returns args (lines 248-251)."""
        from redaudit.core.proxy import get_nmap_proxy_args

        proxy = {"type": "socks4", "host": "10.0.0.1", "port": 1080}

        result = get_nmap_proxy_args(proxy)

        assert result == "--proxies socks4://10.0.0.1:1080"

    def test_get_nmap_proxy_args_socks5(self):
        """Test socks5 returns empty (use proxychains) (lines 253-254)."""
        from redaudit.core.proxy import get_nmap_proxy_args

        proxy = {"type": "socks5", "host": "10.0.0.1", "port": 1080}

        result = get_nmap_proxy_args(proxy)

        assert result == ""


class TestIsProxychainsAvailable:
    """Tests for is_proxychains_available (lines 257-270)."""

    def test_is_proxychains_available_true(self):
        """Test when proxychains4 is available (lines 264-270)."""
        from redaudit.core.proxy import is_proxychains_available

        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: (
                "/usr/bin/proxychains4" if x == "proxychains4" else None
            )
            result = is_proxychains_available()

        assert result is True

    def test_is_proxychains_available_false(self):
        """Test when no proxychains available."""
        from redaudit.core.proxy import is_proxychains_available

        with patch("shutil.which", return_value=None):
            result = is_proxychains_available()

        assert result is False


class TestProxyManager:
    """Tests for ProxyManager class (lines 273-336)."""

    def test_proxy_manager_no_url(self):
        """Test ProxyManager with no URL."""
        from redaudit.core.proxy import ProxyManager

        manager = ProxyManager()

        assert manager.is_valid() is False

    def test_proxy_manager_test_connection_no_proxy(self):
        """Test test_connection returns False when no proxy (lines 298-299)."""
        from redaudit.core.proxy import ProxyManager

        manager = ProxyManager()

        result = manager.test_connection()

        assert result[0] is False
        assert "No proxy" in result[1]

    def test_proxy_manager_test_connection_with_proxy(self):
        """Test test_connection calls test_proxy_connection (lines 301-303)."""
        from redaudit.core.proxy import ProxyManager

        manager = ProxyManager("socks5://10.0.0.1:1080")

        with patch("redaudit.core.proxy.test_proxy_connection") as mock_test:
            mock_test.return_value = (True, "OK")
            result = manager.test_connection()

        assert result[0] is True
        mock_test.assert_called_once()

    def test_proxy_manager_wrap_command_no_proxy(self):
        """Test wrap_command returns original when no proxy (lines 315-316)."""
        from redaudit.core.proxy import ProxyManager

        manager = ProxyManager()
        cmd = ["nmap", "-sV", "target"]

        result = manager.wrap_command(cmd)

        assert result == cmd

    def test_proxy_manager_cleanup(self, tmp_path):
        """Test cleanup removes temp configs (lines 325-329)."""
        from redaudit.core.proxy import ProxyManager
        import os

        manager = ProxyManager("socks5://10.0.0.1:1080")

        # Add a temp config
        test_file = tmp_path / "test.conf"
        test_file.write_text("config")
        manager.temp_configs.append(str(test_file))

        manager.cleanup()

        assert not os.path.exists(test_file)
        assert len(manager.temp_configs) == 0

    def test_proxy_manager_context_manager(self):
        """Test context manager protocol (lines 331-336)."""
        from redaudit.core.proxy import ProxyManager

        with ProxyManager("socks5://10.0.0.1:1080") as manager:
            assert manager.is_valid() is True
            manager.temp_configs.append("/tmp/fake.conf")

        # After exit, cleanup should have been called
        assert len(manager.temp_configs) == 0 or not any(manager.temp_configs)  # cleanup was called
