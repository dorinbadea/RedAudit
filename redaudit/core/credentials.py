"""
Credential management for authenticated scanning.

This module provides secure credential storage and retrieval for SSH, SMB, and SNMP
authentication. Credentials are NEVER stored in plaintext on disk.

Supported backends:
- Environment variables (for CI/CD pipelines)
- OS Keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import os
import logging

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """
    Represents a credential for authenticated scanning.

    Attributes:
        username: The username for authentication.
        password: The password (optional if using key-based auth).
        private_key: Path to SSH private key file (optional).
        private_key_passphrase: Passphrase for encrypted private key (optional).
        domain: Windows domain for SMB/WMI authentication (optional).
    """

    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    domain: Optional[str] = None

    def __repr__(self) -> str:
        """Redact sensitive fields in repr."""
        return (
            f"Credential(username={self.username!r}, "
            f"password={'***' if self.password else None}, "
            f"private_key={self.private_key!r}, "
            f"domain={self.domain!r})"
        )


class CredentialProvider(ABC):
    """Abstract base class for credential providers."""

    @abstractmethod
    def get_credential(self, target: str, protocol: str) -> Optional[Credential]:
        """
        Retrieve credential for a target/protocol combination.

        Args:
            target: The target host (IP or hostname).
            protocol: The protocol (ssh, smb, snmp).

        Returns:
            Credential object if found, None otherwise.
        """
        pass

    @abstractmethod
    def store_credential(self, target: str, protocol: str, credential: Credential) -> bool:
        """
        Store a credential for a target/protocol combination.

        Args:
            target: The target host (IP or hostname).
            protocol: The protocol (ssh, smb, snmp).
            credential: The credential to store.

        Returns:
            True if stored successfully, False otherwise.
        """
        pass


class EnvironmentCredentialProvider(CredentialProvider):
    """
    Reads credentials from environment variables.

    Environment variable naming convention:
        REDAUDIT_<PROTOCOL>_USER - Username
        REDAUDIT_<PROTOCOL>_PASS - Password
        REDAUDIT_<PROTOCOL>_KEY  - Path to private key (SSH only)
        REDAUDIT_<PROTOCOL>_DOMAIN - Domain (SMB only)

    Example:
        export REDAUDIT_SSH_USER=auditor
        export REDAUDIT_SSH_KEY=/home/user/.ssh/audit_key
    """

    def get_credential(self, target: str, protocol: str) -> Optional[Credential]:
        """Get credential from environment variables."""
        prefix = f"REDAUDIT_{protocol.upper()}"

        username = os.environ.get(f"{prefix}_USER")
        if not username:
            logger.debug("No %s_USER environment variable found", prefix)
            return None

        password = os.environ.get(f"{prefix}_PASS")
        private_key = os.environ.get(f"{prefix}_KEY")
        private_key_passphrase = os.environ.get(f"{prefix}_KEY_PASS")
        domain = os.environ.get(f"{prefix}_DOMAIN")

        logger.debug("Found %s credentials for user %s", protocol.upper(), username)

        return Credential(
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            domain=domain,
        )

    def store_credential(self, target: str, protocol: str, credential: Credential) -> bool:
        """Environment provider does not support storing credentials."""
        logger.warning("EnvironmentCredentialProvider does not support store_credential")
        return False


class KeyringCredentialProvider(CredentialProvider):
    """
    Uses OS keyring for secure credential storage.

    Requires the 'keyring' package to be installed.
    Falls back to environment provider if keyring is unavailable.
    """

    def __init__(self):
        self._keyring_available = False
        try:
            import keyring

            self._keyring = keyring
            self._keyring_available = True
            logger.debug("Keyring backend: %s", keyring.get_keyring())
        except ImportError:
            logger.warning("keyring package not installed, falling back to environment")
            self._fallback = EnvironmentCredentialProvider()

    def get_credential(self, target: str, protocol: str) -> Optional[Credential]:
        """Get credential from OS keyring."""
        if not self._keyring_available:
            return self._fallback.get_credential(target, protocol)

        service_name = f"redaudit-{protocol}"

        # Try target-specific credential first
        username = self._keyring.get_password(service_name, f"{target}:username")
        if not username:
            # Fall back to global credential for protocol
            username = self._keyring.get_password(service_name, "default:username")

        if not username:
            logger.debug("No keyring credential found for %s/%s", protocol, target)
            return None

        # Get associated password/key
        password = self._keyring.get_password(service_name, f"{target}:password")
        if not password:
            password = self._keyring.get_password(service_name, "default:password")

        private_key = self._keyring.get_password(service_name, f"{target}:key")
        if not private_key:
            private_key = self._keyring.get_password(service_name, "default:key")

        domain = self._keyring.get_password(service_name, f"{target}:domain")
        if not domain:
            domain = self._keyring.get_password(service_name, "default:domain")

        logger.debug("Found keyring credential for %s/%s", protocol, target)

        return Credential(
            username=username,
            password=password,
            private_key=private_key,
            domain=domain,
        )

    def store_credential(self, target: str, protocol: str, credential: Credential) -> bool:
        """Store credential in OS keyring."""
        if not self._keyring_available:
            return False

        service_name = f"redaudit-{protocol}"
        key_prefix = target if target else "default"

        try:
            self._keyring.set_password(service_name, f"{key_prefix}:username", credential.username)

            if credential.password:
                self._keyring.set_password(
                    service_name, f"{key_prefix}:password", credential.password
                )

            if credential.private_key:
                self._keyring.set_password(
                    service_name, f"{key_prefix}:key", credential.private_key
                )

            if credential.domain:
                self._keyring.set_password(service_name, f"{key_prefix}:domain", credential.domain)

            logger.info("Stored credential for %s/%s in keyring", protocol, target)
            return True

        except Exception as e:
            logger.error("Failed to store credential in keyring: %s", e)
            return False


def get_credential_provider(provider_type: str = "keyring") -> CredentialProvider:
    """
    Factory function to get a credential provider.

    Args:
        provider_type: Type of provider ('env', 'keyring').

    Returns:
        CredentialProvider instance.

    Raises:
        ValueError: If provider_type is unknown.
    """
    providers = {
        "env": EnvironmentCredentialProvider,
        "environment": EnvironmentCredentialProvider,
        "keyring": KeyringCredentialProvider,
    }

    if provider_type.lower() not in providers:
        raise ValueError(
            f"Unknown credential provider: {provider_type}. "
            f"Valid options: {list(providers.keys())}"
        )

    return providers[provider_type.lower()]()
