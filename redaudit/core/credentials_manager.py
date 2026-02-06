#!/usr/bin/env python3
"""
Credentials Manager for Phase 4.1 Multi-Credential Support.

Manages multiple credentials with automatic protocol detection
based on open ports, and credential spraying across hosts.
"""

import json
import logging
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Port to protocol mapping
PORT_PROTOCOL_MAP: Dict[int, str] = {
    22: "ssh",
    23: "telnet",
    139: "smb",
    445: "smb",
    161: "snmp",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
}


@dataclass
class UniversalCredential:
    """
    A credential that can be used across multiple protocols.

    Unlike the protocol-specific Credential class, this is protocol-agnostic
    and will be tried against any compatible service.
    """

    user: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    domain: Optional[str] = None  # For SMB/Windows
    # SNMP v3 fields (optional)
    auth_protocol: Optional[str] = None  # SHA, MD5
    priv_protocol: Optional[str] = None  # AES, DES
    priv_password: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict) -> "UniversalCredential":
        """Create from dictionary."""
        return cls(
            user=data.get("user", ""),
            password=data.get("pass") or data.get("password"),
            private_key=data.get("key") or data.get("private_key"),
            private_key_passphrase=data.get("key_pass") or data.get("private_key_passphrase"),
            domain=data.get("domain"),
            auth_protocol=data.get("auth_protocol"),
            priv_protocol=data.get("priv_protocol"),
            priv_password=data.get("priv_pass") or data.get("priv_password"),
        )


@dataclass
class CredentialResult:
    """Result of a credential attempt."""

    host: str
    port: int
    protocol: str
    credential: UniversalCredential
    success: bool
    error: Optional[str] = None


class CredentialsManager:
    """
    Manages multiple credentials for authenticated scanning.

    Supports:
    - Loading/saving credentials from JSON file
    - Auto-detection of protocol based on port
    - Credential spraying with rate limiting
    - Tracking which credentials succeeded per host
    """

    MAX_ATTEMPTS_PER_HOST = 3
    TIMEOUT_SECONDS = 3

    def __init__(self, credentials: Optional[List[Dict]] = None):
        """
        Initialize with optional list of credential dictionaries.

        Args:
            credentials: List of dicts with user/pass/key fields
        """
        self.credentials: List[UniversalCredential] = []
        self.results: Dict[str, CredentialResult] = {}  # host:port -> result
        self._failed_attempts: Dict[str, int] = {}  # host -> count

        if credentials:
            for cred_dict in credentials:
                self.add_credential(UniversalCredential.from_dict(cred_dict))

    def add_credential(self, credential: UniversalCredential) -> None:
        """Add a credential to the manager."""
        self.credentials.append(credential)
        logger.debug("Added credential for user: %s", credential.user)

    def load_from_file(self, path: str) -> None:
        """
        Load credentials from a JSON file.

        Args:
            path: Path to credentials JSON file

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file is invalid JSON
        """
        file_path = Path(path).expanduser()

        if not file_path.exists():
            raise FileNotFoundError(f"Credentials file not found: {path}")

        # Check permissions (should be 0600 for security)
        mode = file_path.stat().st_mode & 0o777
        if mode != 0o600:
            logger.warning("Credentials file has insecure permissions: %o (should be 600)", mode)

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cred_list = data.get("credentials", [])
        for cred_dict in cred_list:
            self.add_credential(UniversalCredential.from_dict(cred_dict))

        logger.info("Loaded %d credentials from %s", len(cred_list), path)

    def save_to_file(self, path: str) -> None:
        """
        Save credentials to a JSON file with secure permissions.

        Args:
            path: Path to save credentials JSON file
        """
        file_path = Path(path).expanduser()
        file_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "credentials": [
                {
                    "user": c.user,
                    **({"pass": c.password} if c.password else {}),
                    **({"key": c.private_key} if c.private_key else {}),
                    **({"domain": c.domain} if c.domain else {}),
                }
                for c in self.credentials
            ]
        }

        # Write with secure permissions
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        os.chmod(file_path, 0o600)
        logger.info("Saved %d credentials to %s", len(self.credentials), path)

    def get_protocol_for_port(self, port: int) -> Optional[str]:
        """
        Get the protocol name for a given port.

        Args:
            port: Port number

        Returns:
            Protocol name (ssh, smb, snmp, etc.) or None
        """
        return PORT_PROTOCOL_MAP.get(port)

    def get_credentials_for_protocol(self, protocol: str) -> List[UniversalCredential]:
        """
        Get all credentials applicable for a given protocol.

        For now, returns all credentials (universal approach).
        Future: Could filter based on credential fields.

        Args:
            protocol: Protocol name (ssh, smb, snmp)

        Returns:
            List of applicable credentials
        """
        # Universal approach: try all credentials
        # SNMP v3 needs auth_protocol, but we still try
        return self.credentials

    def can_attempt(self, host: str) -> bool:
        """
        Check if we can still attempt credentials on this host.

        Args:
            host: Target host IP/hostname

        Returns:
            True if under MAX_ATTEMPTS_PER_HOST failures
        """
        return self._failed_attempts.get(host, 0) < self.MAX_ATTEMPTS_PER_HOST

    def record_attempt(self, host: str, success: bool) -> None:
        """
        Record a credential attempt result.

        Args:
            host: Target host
            success: Whether the attempt succeeded
        """
        if not success:
            self._failed_attempts[host] = self._failed_attempts.get(host, 0) + 1

    def try_credentials(
        self,
        host: str,
        port: int,
        connect_func,
    ) -> Optional[Tuple[UniversalCredential, object]]:
        """
        Try all credentials against a host/port until one succeeds.

        Args:
            host: Target host IP
            port: Target port
            connect_func: Function(credential, host, port) -> (success, result/error)

        Returns:
            Tuple of (successful credential, connection result) or None
        """
        protocol = self.get_protocol_for_port(port)
        if not protocol:
            logger.debug("No protocol mapping for port %d", port)
            return None

        credentials = self.get_credentials_for_protocol(protocol)
        if not credentials:
            logger.debug("No credentials available for protocol %s", protocol)
            return None

        for cred in credentials:
            if not self.can_attempt(host):
                logger.warning("Max attempts reached for %s, skipping", host)
                break

            try:
                success, result = connect_func(cred, host, port)
                self.record_attempt(host, success)

                if success:
                    self.results[f"{host}:{port}"] = CredentialResult(
                        host=host,
                        port=port,
                        protocol=protocol,
                        credential=cred,
                        success=True,
                    )
                    logger.info(
                        "Credential successful: %s@%s:%d (%s)",
                        cred.user,
                        host,
                        port,
                        protocol,
                    )
                    return (cred, result)

            except Exception as e:
                self.record_attempt(host, False)
                logger.debug(
                    "Credential failed: %s@%s:%d - %s",
                    cred.user,
                    host,
                    port,
                    str(e),
                )

        return None

    def get_successful_credentials(self) -> Dict[str, CredentialResult]:
        """Get all successful credential results."""
        return {k: v for k, v in self.results.items() if v.success}

    @staticmethod
    def generate_template(path: str) -> None:
        """
        Generate an empty credentials template file.

        Args:
            path: Path to save template
        """
        template = {
            "credentials": [
                {"user": "admin", "pass": "changeme"},
                {"user": "root", "pass": "toor"},
                {"user": "administrator", "pass": "P@ssw0rd", "domain": "WORKGROUP"},
            ]
        }

        file_path = Path(path).expanduser()
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=2)

        os.chmod(file_path, 0o600)
        logger.info("Generated credentials template: %s", path)
