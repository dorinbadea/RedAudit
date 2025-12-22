#!/usr/bin/env python3
"""
RedAudit - Tests for proxy helpers.
"""

from types import SimpleNamespace
from unittest.mock import patch

from redaudit.core import proxy


def test_parse_proxy_url_variants():
    parsed = proxy.parse_proxy_url("socks5://user:pass@localhost:1080")
    assert parsed["type"] == "socks5"
    assert parsed["host"] == "localhost"
    assert parsed["port"] == 1080
    assert parsed["user"] == "user"
    assert parsed["password"] == "pass"

    parsed = proxy.parse_proxy_url("10.0.0.1:9050")
    assert parsed["type"] == "socks5"
    assert parsed["host"] == "10.0.0.1"
    assert parsed["port"] == 9050

    assert proxy.parse_proxy_url("") is None
    assert proxy.parse_proxy_url("bad") is None


def test_generate_proxychains_config_includes_auth():
    config = proxy.generate_proxychains_config(
        {"type": "socks5", "host": "127.0.0.1", "port": 1080, "user": "u", "password": "p"}
    )
    assert "socks5 127.0.0.1 1080 u p" in config


def test_temp_config_lifecycle(tmp_path):
    config_path = proxy.create_temp_proxychains_config(
        {"type": "socks5", "host": "127.0.0.1", "port": 1080}
    )
    assert config_path is not None
    assert "proxychains configuration" in open(config_path, "r", encoding="utf-8").read()
    proxy.cleanup_temp_config(config_path)


def test_get_nmap_proxy_args():
    assert proxy.get_nmap_proxy_args({"type": "socks4", "host": "h", "port": 1080}) == (
        "--proxies socks4://h:1080"
    )
    assert proxy.get_nmap_proxy_args({"type": "socks5", "host": "h", "port": 1080}) == ""


def test_wrap_command_with_proxychains_absent():
    with patch("redaudit.core.proxy.shutil.which", return_value=None):
        wrapped, path = proxy.wrap_command_with_proxychains(["nmap", "x"], {"host": "h", "port": 1})
    assert wrapped == ["nmap", "x"]
    assert path is None


def test_wrap_command_with_proxychains_present(tmp_path):
    with patch("redaudit.core.proxy.shutil.which", return_value="/usr/bin/proxychains"):
        with patch(
            "redaudit.core.proxy.create_temp_proxychains_config",
            return_value=str(tmp_path / "proxy.conf"),
        ):
            wrapped, path = proxy.wrap_command_with_proxychains(
                ["nmap", "x"], {"host": "h", "port": 1}
            )
    assert wrapped[:3] == ["/usr/bin/proxychains", "-q", "-f"]
    assert path == str(tmp_path / "proxy.conf")


def test_proxy_manager_wrap_and_cleanup(tmp_path):
    manager = proxy.ProxyManager("socks5://10.0.0.1:1080")
    assert manager.is_valid() is True

    with patch(
        "redaudit.core.proxy.wrap_command_with_proxychains",
        return_value=(["proxychains", "cmd"], str(tmp_path / "x.conf")),
    ):
        wrapped = manager.wrap_command(["cmd"])
    assert wrapped == ["proxychains", "cmd"]
    manager.cleanup()
    assert manager.temp_configs == []


def test_proxy_connection_socket_fallback():
    class _Socket:
        def settimeout(self, _timeout):
            return None

        def connect(self, _addr):
            return None

        def close(self):
            return None

    with patch("redaudit.core.proxy.shutil.which", return_value=None):
        with patch("socket.socket", return_value=_Socket()):
            ok, msg = proxy.test_proxy_connection({"host": "h", "port": 1})
    assert ok is True
    assert "reachable" in msg


def test_proxy_connection_with_nc_failure():
    result = SimpleNamespace(returncode=1)
    with patch("redaudit.core.proxy.shutil.which", return_value="/usr/bin/nc"):
        with patch("redaudit.core.proxy.CommandRunner.run", return_value=result):
            ok, msg = proxy.test_proxy_connection({"host": "h", "port": 1})
    assert ok is False
    assert "not responding" in msg
