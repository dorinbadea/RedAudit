"""
SSH-based authenticated scanning module.

This module provides SSH-based host auditing capabilities using Paramiko.
It enables secure remote command execution for Linux/Unix system auditing.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from redaudit.core.credentials import Credential

logger = logging.getLogger(__name__)


@dataclass
class SSHHostInfo:
    """Information gathered from an SSH-authenticated host."""

    os_name: str = ""
    os_version: str = ""
    kernel: str = ""
    hostname: str = ""
    uptime: str = ""
    architecture: str = ""
    packages: List[Dict[str, str]] = field(default_factory=list)
    services: List[Dict[str, str]] = field(default_factory=list)
    users: List[Dict[str, Any]] = field(default_factory=list)
    firewall_rules: str = ""


class SSHConnectionError(Exception):
    """Raised when SSH connection fails."""

    pass


class SSHCommandError(Exception):
    """Raised when SSH command execution fails."""

    pass


class SSHScanner:
    """
    Authenticated SSH-based host scanner.

    Uses Paramiko for SSH connections and command execution.
    Supports both key-based and password authentication.
    """

    def __init__(self, credential: Credential, timeout: int = 30, trust_unknown_keys: bool = False):
        """
        Initialize SSH scanner with credentials.

        Args:
            credential: Credential object with SSH authentication details.
            timeout: Connection and command timeout in seconds.
            trust_unknown_keys: If True, auto-accept unknown host keys (AutoAddPolicy).
                                If False, reject unknown keys (RejectPolicy). Default: False.
        """
        self.credential = credential
        self.timeout = timeout
        self.trust_unknown_keys = trust_unknown_keys
        self._client = None
        self._connected = False
        self._paramiko = None

        # Lazy import paramiko
        try:
            import paramiko  # type: ignore[import-untyped]

            self._paramiko = paramiko
        except ImportError:
            logger.error("paramiko package not installed. Install with: pip install paramiko")
            raise ImportError(
                "paramiko is required for SSH scanning. "
                "Install with: pip install 'redaudit[auth]'"
            )

    def connect(self, host: str, port: int = 22) -> bool:
        """
        Establish SSH connection to host.

        Args:
            host: Target hostname or IP address.
            port: SSH port (default: 22).

        Returns:
            True if connection successful.

        Raises:
            SSHConnectionError: If connection fails.
        """
        if self._connected:
            self.close()

        self._client = self._paramiko.SSHClient()  # type: ignore
        self._client.load_system_host_keys()  # type: ignore

        assert self._client is not None
        if self.trust_unknown_keys:
            # v4.5.14: Use custom policy to avoid "not found in known_hosts" errors
            # which occur if AutoAddPolicy fails to save keys (e.g. permission denied)
            # or if strict checking logic interferes.
            class PermissivePolicy(self._paramiko.MissingHostKeyPolicy):  # type: ignore
                def missing_host_key(self, client, hostname, key):
                    # Add key to memory only (transient trust)
                    client.get_host_keys().add(hostname, key.get_name(), key)
                    # We do NOT save to file to prevent read-only filesystem errors

            self._client.set_missing_host_key_policy(PermissivePolicy())
        else:
            self._client.set_missing_host_key_policy(self._paramiko.RejectPolicy())  # type: ignore

        try:
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": self.credential.username,
                "timeout": self.timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if self.credential.private_key:
                # Key-based authentication
                logger.debug("Connecting to %s:%d with SSH key", host, port)
                key = self._load_private_key()
                connect_kwargs["pkey"] = key
            elif self.credential.password:
                # Password authentication
                logger.debug("Connecting to %s:%d with password", host, port)
                connect_kwargs["password"] = self.credential.password
            else:
                raise SSHConnectionError(
                    "No authentication method provided (need password or private_key)"
                )

            self._client.connect(**connect_kwargs)  # type: ignore
            self._connected = True
            logger.info("SSH connection established to %s:%d", host, port)
            return True

        except self._paramiko.AuthenticationException as e:
            logger.error("SSH authentication failed for %s: %s", host, e)
            raise SSHConnectionError(f"Authentication failed: {e}")
        except self._paramiko.SSHException as e:
            logger.error("SSH error connecting to %s: %s", host, e)
            raise SSHConnectionError(f"SSH error: {e}")
        except Exception as e:
            logger.error("Failed to connect to %s: %s", host, e)
            raise SSHConnectionError(f"Connection failed: {e}")

    def _load_private_key(self):
        """Load SSH private key from file."""
        key_path = self.credential.private_key
        passphrase = self.credential.private_key_passphrase

        # Try different key types
        key_types = [
            self._paramiko.RSAKey,
            self._paramiko.Ed25519Key,
            self._paramiko.ECDSAKey,
            self._paramiko.DSSKey,
        ]

        for key_class in key_types:
            try:
                return key_class.from_private_key_file(key_path, password=passphrase)
            except self._paramiko.SSHException:
                continue

        raise SSHConnectionError(f"Unable to load private key from {key_path}")

    def close(self):
        """Close SSH connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._connected = False
            self._client = None
            logger.debug("SSH connection closed")

    def run_command(self, command: str, timeout: Optional[int] = None) -> Tuple[str, str, int]:
        """
        Execute command on remote host.

        Args:
            command: Command to execute.
            timeout: Command timeout (uses instance timeout if not specified).

        Returns:
            Tuple of (stdout, stderr, exit_code).

        Raises:
            SSHCommandError: If command execution fails.
        """
        if not self._connected:
            raise SSHCommandError("Not connected to any host")

        cmd_timeout = timeout or self.timeout

        assert self._client is not None
        try:
            stdin, stdout, stderr = self._client.exec_command(  # nosec B601
                command, timeout=cmd_timeout
            )
            exit_code = stdout.channel.recv_exit_status()
            stdout_str = stdout.read().decode("utf-8", errors="replace")
            stderr_str = stderr.read().decode("utf-8", errors="replace")

            logger.debug(
                "Command '%s' completed with exit code %d",
                command[:50] + "..." if len(command) > 50 else command,
                exit_code,
            )

            return stdout_str, stderr_str, exit_code

        except Exception as e:
            logger.error("Command execution failed: %s", e)
            raise SSHCommandError(f"Command failed: {e}")

    def get_os_info(self) -> Dict[str, str]:
        """
        Retrieve OS information from remote host.

        Returns:
            Dictionary with OS details (name, version, kernel, architecture).
        """
        info = {}

        # Try /etc/os-release first (modern Linux)
        stdout, _, code = self.run_command("cat /etc/os-release 2>/dev/null")
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if "=" in line:
                    key, _, value = line.partition("=")
                    info[key.lower()] = value.strip('"')

        # Get kernel info
        stdout, _, _ = self.run_command("uname -r")
        info["kernel"] = stdout.strip()

        # Get architecture
        stdout, _, _ = self.run_command("uname -m")
        info["architecture"] = stdout.strip()

        # Get hostname
        stdout, _, _ = self.run_command("hostname")
        info["hostname"] = stdout.strip()

        return info

    def get_installed_packages(self) -> List[Dict[str, str]]:
        """
        Get list of installed packages.

        Detects package manager and queries accordingly.

        Returns:
            List of dictionaries with package info (name, version).
        """
        packages = []

        # Try dpkg (Debian/Ubuntu)
        stdout, _, code = self.run_command(
            "dpkg-query -W -f='${Package}|${Version}\\n' 2>/dev/null | head -500"
        )
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if "|" in line:
                    name, version = line.split("|", 1)
                    packages.append({"name": name, "version": version, "manager": "dpkg"})
            return packages

        # Try rpm (RHEL/CentOS/Fedora)
        stdout, _, code = self.run_command(
            "rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -500"
        )
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if "|" in line:
                    name, version = line.split("|", 1)
                    packages.append({"name": name, "version": version, "manager": "rpm"})
            return packages

        # Try apk (Alpine)
        stdout, _, code = self.run_command("apk list --installed 2>/dev/null | head -500")
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                parts = line.split()
                if parts:
                    # Format: "package-version info"
                    name_version = parts[0]
                    packages.append({"name": name_version, "version": "", "manager": "apk"})
            return packages

        logger.warning("Could not detect package manager")
        return packages

    def get_running_services(self) -> List[Dict[str, str]]:
        """
        Get list of running services.

        Returns:
            List of dictionaries with service info (name, status).
        """
        services = []

        # Try systemctl (systemd)
        stdout, _, code = self.run_command(
            "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null"
        )
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0].replace(".service", "")
                    status = parts[2]  # LOAD / ACTIVE / SUB
                    services.append({"name": name, "status": status, "manager": "systemd"})
            return services

        # Try service (SysV init)
        stdout, _, code = self.run_command("service --status-all 2>/dev/null")
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if "[ + ]" in line:
                    name = line.replace("[ + ]", "").strip()
                    services.append({"name": name, "status": "running", "manager": "sysv"})
            return services

        return services

    def get_users(self) -> List[Dict[str, Any]]:
        """
        Get list of user accounts.

        Returns:
            List of dictionaries with user info (username, uid, gid, home, shell).
        """
        users = []

        stdout, _, code = self.run_command("cat /etc/passwd")
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 7:
                    users.append(
                        {
                            "username": parts[0],
                            "uid": int(parts[2]) if parts[2].isdigit() else parts[2],
                            "gid": int(parts[3]) if parts[3].isdigit() else parts[3],
                            "home": parts[5],
                            "shell": parts[6],
                        }
                    )

        return users

    def get_firewall_rules(self) -> str:
        """
        Get firewall configuration.

        Returns:
            String with firewall rules.
        """
        # Try iptables
        stdout, _, code = self.run_command(
            "sudo iptables -L -n 2>/dev/null || iptables -L -n 2>/dev/null"
        )
        if code == 0 and stdout and "Chain" in stdout:
            return f"# iptables\n{stdout}"

        # Try nftables
        stdout, _, code = self.run_command(
            "sudo nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null"
        )
        if code == 0 and stdout:
            return f"# nftables\n{stdout}"

        # Try firewalld
        stdout, _, code = self.run_command("firewall-cmd --list-all 2>/dev/null")
        if code == 0 and stdout:
            return f"# firewalld\n{stdout}"

        # Try ufw
        stdout, _, code = self.run_command("ufw status verbose 2>/dev/null")
        if code == 0 and stdout:
            return f"# ufw\n{stdout}"

        return "No firewall detected or insufficient permissions"

    def gather_host_info(self) -> SSHHostInfo:
        """
        Gather comprehensive host information.

        Returns:
            SSHHostInfo object with all gathered data.
        """
        info = SSHHostInfo()

        # Get OS info
        os_data = self.get_os_info()
        info.os_name = os_data.get("name", os_data.get("id", ""))
        info.os_version = os_data.get("version_id", os_data.get("version", ""))
        info.kernel = os_data.get("kernel", "")
        info.hostname = os_data.get("hostname", "")
        info.architecture = os_data.get("architecture", "")

        # Get packages (limited to first 500)
        info.packages = self.get_installed_packages()

        # Get services
        info.services = self.get_running_services()

        # Get users
        info.users = self.get_users()

        # Get firewall
        info.firewall_rules = self.get_firewall_rules()

        return info

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False
