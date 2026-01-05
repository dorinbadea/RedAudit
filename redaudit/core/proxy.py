#!/usr/bin/env python3
"""
RedAudit - Proxy Support Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.0: SOCKS5 proxy integration for pivoting and internal network scanning.
Supports both proxychains wrapper and native nmap --proxies option.
"""

import os
import shutil
import tempfile
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run


def parse_proxy_url(url: str) -> Optional[Dict]:
    """
    Parse a SOCKS5 proxy URL into components.

    Supported formats:
    - socks5://host:port
    - socks5://user:pass@host:port
    - host:port (assumes socks5)

    Args:
        url: Proxy URL string

    Returns:
        Dict with type, host, port, user, password or None on error
    """
    if not url:
        return None

    # Add scheme if missing
    if not url.startswith(("socks5://", "socks4://", "http://")):
        url = f"socks5://{url}"

    try:
        parsed = urlparse(url)

        if not parsed.hostname or not parsed.port:
            return None

        return {
            "type": parsed.scheme or "socks5",
            "host": parsed.hostname,
            "port": parsed.port,
            "user": parsed.username,
            "password": parsed.password,
        }
    except Exception:
        return None


def test_proxy_connection(proxy: Dict, timeout: int = 10) -> Tuple[bool, str]:
    """
    Test if a proxy is reachable via TCP.

    Note: This only verifies TCP connectivity to the proxy port, not full
    SOCKS5 protocol compatibility. Actual proxy functionality is validated
    when proxychains executes the scan commands.

    Args:
        proxy: Parsed proxy dict from parse_proxy_url
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (success, message)
    """
    if not proxy:
        return False, "Invalid proxy configuration"

    # Try to connect through the proxy
    host = proxy["host"]
    port = proxy["port"]

    # Use nc (netcat) to test basic TCP connectivity to proxy
    nc_path = shutil.which("nc") or shutil.which("netcat")
    if not nc_path:
        # Fallback: try Python socket
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True, f"Proxy {host}:{port} is reachable"
        except socket.error as e:
            return False, f"Proxy connection failed: {e}"

    try:
        runner = CommandRunner(
            dry_run=is_dry_run(),
            default_timeout=float(timeout + 5),
            default_retries=0,
            backoff_base_s=0.0,
        )
        result = runner.run(
            [nc_path, "-z", "-w", str(timeout), host, str(port)],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        if result.returncode == 0:
            return True, f"Proxy {host}:{port} is reachable"
        else:
            return False, f"Proxy {host}:{port} not responding"
    except Exception as e:
        msg = str(e)
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            return False, f"Proxy connection timeout ({timeout}s)"
        return False, f"Proxy test error: {e}"


def generate_proxychains_config(proxy: Dict) -> str:
    """
    Generate proxychains configuration content.

    Args:
        proxy: Parsed proxy dict

    Returns:
        Proxychains config file content
    """
    proxy_type = proxy.get("type", "socks5")
    host = proxy["host"]
    port = proxy["port"]
    user = proxy.get("user", "")
    password = proxy.get("password", "")

    config_lines = [
        "# RedAudit generated proxychains configuration",
        "# v3.0",
        "",
        "strict_chain",
        "proxy_dns",
        "remote_dns_subnet 224",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "",
        "[ProxyList]",
    ]

    if user and password:
        config_lines.append(f"{proxy_type} {host} {port} {user} {password}")
    else:
        config_lines.append(f"{proxy_type} {host} {port}")

    return "\n".join(config_lines)


def create_temp_proxychains_config(proxy: Dict) -> Optional[str]:
    """
    Create a temporary proxychains configuration file.

    Args:
        proxy: Parsed proxy dict

    Returns:
        Path to temp config file or None on error
    """
    try:
        config_content = generate_proxychains_config(proxy)

        # Create temp file that persists after close
        fd, path = tempfile.mkstemp(prefix="redaudit_proxy_", suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write(config_content)

        return path
    except Exception:
        return None


def cleanup_temp_config(path: str) -> None:
    """
    Remove temporary proxychains config file.

    Args:
        path: Path to temp config file
    """
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


def wrap_command_with_proxychains(cmd: List[str], proxy: Dict) -> Tuple[List[str], Optional[str]]:
    """
    Wrap a command with proxychains for SOCKS5 proxying.

    Args:
        cmd: Original command list
        proxy: Parsed proxy dict

    Returns:
        Tuple of (wrapped command, temp config path or None)
    """
    # Check if proxychains is available
    proxychains_path = (
        shutil.which("proxychains4")
        or shutil.which("proxychains")
        or shutil.which("proxychains-ng")
    )

    if not proxychains_path:
        # Fallback: return original command with warning
        return cmd, None

    # Create temp config
    config_path = create_temp_proxychains_config(proxy)
    if not config_path:
        return cmd, None

    # Wrap command with proxychains
    wrapped = [proxychains_path, "-q", "-f", config_path] + cmd

    return wrapped, config_path


def get_nmap_proxy_args(proxy: Dict) -> str:
    """
    Generate nmap --proxies argument string.

    Note: nmap --proxies only supports CONNECT proxies (HTTP),
    not full SOCKS5. Use proxychains for better compatibility.

    Args:
        proxy: Parsed proxy dict

    Returns:
        Nmap proxy argument string (may be empty)
    """
    if not proxy:
        return ""

    # nmap only supports socks4 natively via --proxies
    # For socks5, we need proxychains
    proxy_type = proxy.get("type", "socks5")

    if proxy_type == "socks4":
        host = proxy["host"]
        port = proxy["port"]
        return f"--proxies socks4://{host}:{port}"

    # For socks5 and http, return empty (use proxychains instead)
    return ""


def is_proxychains_available() -> bool:
    """
    Check if proxychains is installed.

    Returns:
        True if proxychains is available
    """
    return any(
        [
            shutil.which("proxychains4"),
            shutil.which("proxychains"),
            shutil.which("proxychains-ng"),
        ]
    )


def get_proxy_command_wrapper(
    proxy_manager: Optional[object],
) -> Optional[Callable[[Sequence[str]], Sequence[str]]]:
    """
    Return a command wrapper for proxy routing when available.
    """
    if proxy_manager is None:
        return None
    wrapper = getattr(proxy_manager, "wrap_command", None)
    if callable(wrapper):
        return wrapper
    return None


class ProxyManager:
    """
    Manages proxy configuration for a scan session.

    Usage:
        manager = ProxyManager("socks5://10.0.0.1:1080")
        if manager.is_valid():
            wrapped_cmd = manager.wrap_command(["nmap", "-sV", "target"])
            # ... run wrapped_cmd ...
        manager.cleanup()
    """

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url
        self.proxy_config = parse_proxy_url(proxy_url) if proxy_url else None
        self.temp_configs: List[str] = []
        self._tested = False
        self._test_result = (False, "Not tested")

    def is_valid(self) -> bool:
        """Check if proxy configuration is valid."""
        return self.proxy_config is not None

    def test_connection(self, timeout: int = 10) -> Tuple[bool, str]:
        """Test proxy connectivity."""
        if not self.is_valid():
            return False, "No proxy configured"

        self._tested = True
        self._test_result = test_proxy_connection(self.proxy_config, timeout)
        return self._test_result

    def wrap_command(self, cmd: List[str]) -> List[str]:
        """
        Wrap a command with proxy support.

        Args:
            cmd: Original command list

        Returns:
            Wrapped command (or original if no proxy)
        """
        if not self.is_valid():
            return cmd

        wrapped, config_path = wrap_command_with_proxychains(cmd, self.proxy_config)

        if config_path:
            self.temp_configs.append(config_path)

        return wrapped

    def cleanup(self) -> None:
        """Clean up any temporary files."""
        for path in self.temp_configs:
            cleanup_temp_config(path)
        self.temp_configs.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
