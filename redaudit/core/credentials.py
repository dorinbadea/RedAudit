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
import json

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
    domain: Optional[str] = None  # For SMB/Windows

    # SNMP v3 Fields
    snmp_auth_proto: Optional[str] = None  # SHA, MD5, etc.
    snmp_auth_pass: Optional[str] = None  # Auth Key
    snmp_priv_proto: Optional[str] = None  # AES, DES, etc.
    snmp_priv_pass: Optional[str] = None  # Privacy Key

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
            from keyring.errors import NoKeyringError

            try:
                # Test backend availability
                current_backend = keyring.get_keyring()
                # If backend is 'fail' check if we can switch to alt
                if "fail" in str(current_backend).lower():
                    raise NoKeyringError("Backend is 'fail'")

                self._keyring = keyring
                self._keyring_available = True
                logger.debug("Keyring backend: %s", current_backend)

            except (NoKeyringError, ImportError, Exception):
                # Fallback to PlaintextKeyring (common for root/headless)
                try:
                    import keyrings.alt.file

                    keyring.set_keyring(keyrings.alt.file.PlaintextKeyring())
                    logger.info("Using PlaintextKeyring (headless/root mode)")
                    self._keyring = keyring
                    self._keyring_available = True
                except ImportError:
                    logger.warning(
                        "keyring/keyrings.alt not fully available, falling back to environment"
                    )
                    self._fallback = EnvironmentCredentialProvider()
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

        # Get associated data (stored as JSON blob in password field for v4.1+)
        # For backward compatibility, we check if it's JSON; if not, treat as password.

        # We use a single 'secret' entry for all fields to handle passphrase properly.
        secret_blob = self._keyring.get_password(service_name, f"{target}:secret")
        if not secret_blob:
            secret_blob = self._keyring.get_password(service_name, "default:secret")

        # Legacy fallback (v4.0 MVP stored fields separately, but password was just password)
        legacy_password = None
        if not secret_blob:
            legacy_password = self._keyring.get_password(service_name, f"{target}:password")
            if not legacy_password:
                legacy_password = self._keyring.get_password(service_name, "default:password")

        # Parse secret
        password = legacy_password
        key_passphrase = None

        if secret_blob:
            try:
                data = json.loads(secret_blob)
                if isinstance(data, dict):
                    password = data.get("password")
                    key_passphrase = data.get("key_passphrase")
                    # We can also store other fields here if needed
            except json.JSONDecodeError:
                # If not JSON, assume it's a raw password (migration)
                password = secret_blob

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
            private_key_passphrase=key_passphrase,
            domain=domain,
        )

    def has_saved_credentials(self) -> dict:
        """
        Check if there are any saved credentials in keyring.

        Returns:
            dict with protocol names as keys and bool as values indicating
            if credentials exist for that protocol.
            Example: {"ssh": True, "smb": False, "snmp": False}
        """
        if not self._keyring_available:
            return {"ssh": False, "smb": False, "snmp": False}

        result = {}
        for protocol in ["ssh", "smb", "snmp"]:
            service_name = f"redaudit-{protocol}"
            try:
                username = self._keyring.get_password(service_name, "default:username")
                result[protocol] = username is not None
            except Exception:
                result[protocol] = False

        return result

    def get_saved_credential_summary(self) -> list:
        """
        Get a summary of saved credentials for display.

        v4.6.19: Now includes spray list count.

        Returns:
            List of tuples (protocol, username, spray_count) for each saved credential.
            spray_count is 0 if only default credential, >0 if spray list exists.
        """
        if not self._keyring_available:
            return []

        summary = []
        for protocol in ["ssh", "smb", "snmp"]:
            service_name = f"redaudit-{protocol}"
            try:
                username = self._keyring.get_password(service_name, "default:username")
                spray_count = 0

                # Check for spray list
                try:
                    spray_json = self._keyring.get_password(service_name, "spray:list")
                    if spray_json:
                        spray_list = json.loads(spray_json)
                        if isinstance(spray_list, list):
                            spray_count = len(spray_list)
                except (json.JSONDecodeError, Exception):
                    pass

                if username or spray_count > 0:
                    display_user = username or "(spray only)"
                    summary.append((protocol.upper(), display_user, spray_count))
            except Exception:
                pass

        return summary

    def get_all_credentials(self, protocol: str) -> list:
        """
        Get all credentials for a protocol, including spray list.

        Returns list with default credential first, then any spray list entries.
        This enables credential spraying across hosts with different auth.

        Args:
            protocol: Protocol name (ssh, smb, snmp)

        Returns:
            List of Credential objects. Empty list if none found.
        """
        from typing import List

        credentials: List[Credential] = []

        if not self._keyring_available:
            # Fallback: try to get single credential from env
            cred = self._fallback.get_credential("", protocol)
            if cred:
                credentials.append(cred)
            return credentials

        service_name = f"redaudit-{protocol}"

        # First, try to read spray list (JSON array)
        try:
            spray_json = self._keyring.get_password(service_name, "spray:list")
            if spray_json:
                spray_list = json.loads(spray_json)
                for entry in spray_list:
                    if isinstance(entry, dict):
                        user = entry.get("user", "")
                        password = entry.get("pass", "")
                        domain = entry.get("domain")
                        hint = entry.get("hint", "")
                        if user:
                            cred = Credential(
                                username=user,
                                password=password,
                                domain=domain,
                            )
                            credentials.append(cred)
                            logger.debug("Loaded spray credential: %s (%s)", user, hint)
        except (json.JSONDecodeError, Exception) as e:
            logger.debug("Failed to parse spray list for %s: %s", protocol, e)

        # If no spray list, fall back to default credential
        if not credentials:
            default_cred = self.get_credential("", protocol)
            if default_cred:
                credentials.append(default_cred)

        return credentials

    def store_credential(self, target: str, protocol: str, credential: Credential) -> bool:
        """Store credential in OS keyring."""
        if not self._keyring_available:
            return False

        service_name = f"redaudit-{protocol}"
        key_prefix = target if target else "default"

        try:
            self._keyring.set_password(service_name, f"{key_prefix}:username", credential.username)

            # Store secret data as JSON
            secret_data = {}
            if credential.password:
                secret_data["password"] = credential.password
            if credential.private_key_passphrase:
                secret_data["key_passphrase"] = credential.private_key_passphrase

            if secret_data:
                secret_blob = json.dumps(secret_data)
                self._keyring.set_password(service_name, f"{key_prefix}:secret", secret_blob)
                # v4.1: Also set legacy password for compatibility if needed? No, Phase 4 is new.
                # But to avoid confusion, maybe clear old password field if exists to prefer secret.
                # For now just set secret.

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
