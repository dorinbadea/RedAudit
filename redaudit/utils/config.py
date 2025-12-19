#!/usr/bin/env python3
"""
RedAudit - Configuration Management Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.0.1: Persistent configuration for NVD API key and other settings.
"""

import os
import json
import stat
import copy
import logging

try:
    import pwd  # Unix-only
except ImportError:  # pragma: no cover
    pwd = None
from typing import Dict, Optional, Any

from redaudit.utils.paths import get_default_reports_base_dir, get_invoking_user

# Config version
CONFIG_VERSION = "3.6.0"

# Environment variable names
ENV_NVD_API_KEY = "NVD_API_KEY"

# Default config structure
DEFAULT_CONFIG: Dict[str, Any] = {
    "version": CONFIG_VERSION,
    "nvd_api_key": None,
    "nvd_api_key_storage": None,  # "config", "env", or None
    # v3.1+: Persistent defaults for common CLI/interactive settings.
    # v3.2.3: Expanded to cover all scan parameters
    "defaults": {
        # v3.4.4: Persist last selected targets for "start immediately" wizard flow.
        "target_networks": None,  # list[str] of CIDRs (e.g., ["192.168.1.0/24"])
        "threads": None,
        "output_dir": None,
        "rate_limit": None,
        "udp_mode": None,
        "udp_top_ports": None,
        "topology_enabled": None,
        "topology_only": None,  # v3.2.2+
        "lang": None,
        # v3.2.3: Additional scan parameters
        "scan_mode": None,  # "rapido", "normal", "completo"
        "scan_vulnerabilities": None,  # True/False
        "cve_lookup_enabled": None,  # True/False
        "generate_txt": None,  # True/False
        "generate_html": None,  # True/False
        # v3.6.0+: Optional template scanner toggle (if nuclei is installed)
        "nuclei_enabled": None,  # True/False
        # v3.6.0+: Net Discovery / Red Team defaults (wizard)
        "net_discovery_enabled": None,  # True/False
        "net_discovery_redteam": None,  # True/False
        "net_discovery_active_l2": None,  # True/False
        "net_discovery_kerberos_userenum": None,  # True/False
        "net_discovery_kerberos_realm": None,  # str | None
        "net_discovery_kerberos_userlist": None,  # str | None
        # v3.8: Agentless verification (SMB/RDP/LDAP)
        "windows_verify_enabled": None,  # True/False
        "windows_verify_max_targets": None,  # int | None
    },
}

# Backwards-compatible constants (do not rely on these for path resolution).
# Real path resolution happens via get_config_paths(), which handles sudo.
CONFIG_DIR = os.path.expanduser("~/.redaudit")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

logger = logging.getLogger("RedAudit")


def _resolve_config_owner() -> Optional[tuple[int, int]]:
    """
    Resolve the intended config owner (uid, gid).

    When running under sudo, RedAudit should store and read configuration from
    the invoking user’s home directory, not root’s. In that scenario we also
    prefer config files owned by the invoking user, not root.
    """
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user and pwd is not None:
                pw = pwd.getpwnam(sudo_user)
                return pw.pw_uid, pw.pw_gid
    except Exception:
        logger.debug("Failed to resolve config owner", exc_info=True)
        pass
    return None


def get_config_paths() -> tuple[str, str]:
    """
    Get the config directory and file path.

    - Normal execution: use the current user’s home (~/.redaudit/config.json)
    - sudo execution: use the invoking user’s home (~SUDO_USER/.redaudit/config.json)
    """
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                home_dir = os.path.expanduser(f"~{sudo_user}")
            else:
                home_dir = os.path.expanduser("~")
        else:
            home_dir = os.path.expanduser("~")
    except Exception:
        logger.debug("Failed to resolve config paths; using fallback home directory", exc_info=True)
        home_dir = os.path.expanduser("~")

    config_dir = os.path.join(home_dir, ".redaudit")
    config_file = os.path.join(config_dir, "config.json")
    return config_dir, config_file


def _maybe_chown(path: str) -> None:
    owner = _resolve_config_owner()
    if not owner:
        return
    uid, gid = owner
    try:
        os.chown(path, uid, gid)
    except Exception:
        logger.debug("Failed to chown config path: %s", path, exc_info=True)
        pass


def ensure_config_dir() -> str:
    """
    Create config directory if it doesn't exist.

    Returns:
        Path to config directory
    """
    config_dir, _ = get_config_paths()
    if not os.path.isdir(config_dir):
        os.makedirs(config_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except Exception:
        logger.debug("Failed to chmod config dir: %s", config_dir, exc_info=True)
        pass
    _maybe_chown(config_dir)
    return config_dir


def load_config() -> Dict[str, Any]:
    """
    Load configuration from file.

    Returns:
        Configuration dictionary (defaults if file doesn't exist)
    """
    ensure_config_dir()

    _, config_file = get_config_paths()
    if not os.path.isfile(config_file):
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Merge with defaults for any missing keys
        merged = copy.deepcopy(DEFAULT_CONFIG)
        merged.update(config)
        return merged

    except (json.JSONDecodeError, IOError):
        logger.debug("Failed to load config file; using defaults", exc_info=True)
        return copy.deepcopy(DEFAULT_CONFIG)


def save_config(config: Dict[str, Any]) -> bool:
    """
    Save configuration to file with secure permissions.

    Args:
        config: Configuration dictionary to save

    Returns:
        True if save succeeded
    """
    ensure_config_dir()
    config_dir, config_file = get_config_paths()

    # Ensure version is current
    config["version"] = CONFIG_VERSION

    try:
        # Write to temp file first then rename (atomic)
        temp_file = config_file + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        # Set secure permissions (owner read/write only)
        os.chmod(temp_file, stat.S_IRUSR | stat.S_IWUSR)

        # Atomic rename
        os.replace(temp_file, config_file)
        _maybe_chown(config_dir)
        _maybe_chown(config_file)
        return True

    except (IOError, OSError):
        logger.debug("Failed to save config file", exc_info=True)
        return False


def get_nvd_api_key() -> Optional[str]:
    """
    Get NVD API key from config file or environment variable.

    Priority:
    1. Environment variable NVD_API_KEY
    2. Config file ~/.redaudit/config.json

    Returns:
        API key string or None if not configured
    """
    # Check environment variable first
    env_key = os.environ.get(ENV_NVD_API_KEY)
    if env_key and env_key.strip():
        return env_key.strip()

    # Then check config file
    config = load_config()
    file_key = config.get("nvd_api_key")
    if file_key and file_key.strip():
        return file_key.strip()

    return None


def set_nvd_api_key(api_key: str, storage: str = "config") -> bool:
    """
    Store NVD API key in config file.

    Args:
        api_key: The API key to store
        storage: Storage method ("config" for file)

    Returns:
        True if save succeeded
    """
    config = load_config()
    config["nvd_api_key"] = api_key.strip() if api_key else None
    config["nvd_api_key_storage"] = storage
    return save_config(config)


def clear_nvd_api_key() -> bool:
    """
    Remove NVD API key from config file.

    Returns:
        True if save succeeded
    """
    config = load_config()
    config["nvd_api_key"] = None
    config["nvd_api_key_storage"] = None
    return save_config(config)


def is_nvd_api_key_configured() -> bool:
    """
    Check if NVD API key is configured (either env or config).

    Returns:
        True if API key is available
    """
    return get_nvd_api_key() is not None


def validate_nvd_api_key(api_key: str) -> bool:
    """
    Validate NVD API key format.

    NVD API keys are UUIDs: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    Args:
        api_key: The API key to validate

    Returns:
        True if format appears valid
    """
    if not api_key:
        return False

    key = api_key.strip()

    # UUID format: 8-4-4-4-12 hex characters
    parts = key.split("-")
    if len(parts) != 5:
        return False

    expected_lengths = [8, 4, 4, 4, 12]
    for i, part in enumerate(parts):
        if len(part) != expected_lengths[i]:
            return False
        if not all(c in "0123456789abcdefABCDEF" for c in part):
            return False

    return True


def get_config_summary() -> Dict[str, Any]:
    """
    Get a summary of current configuration status.

    Returns:
        Dictionary with config status info
    """
    config = load_config()
    _, config_file = get_config_paths()

    has_env_key = bool(os.environ.get(ENV_NVD_API_KEY))
    has_file_key = bool(config.get("nvd_api_key"))

    return {
        "config_file": config_file,
        "config_exists": os.path.isfile(config_file),
        "nvd_key_source": "env" if has_env_key else ("config" if has_file_key else None),
        "nvd_key_configured": has_env_key or has_file_key,
    }


def get_persistent_defaults() -> Dict[str, Any]:
    """
    Get persisted defaults from config file.

    Returns:
        Dict with default keys; values may be None if not configured.
    """
    config = load_config()
    raw = config.get("defaults")
    defaults = DEFAULT_CONFIG.get("defaults", {}).copy()
    if isinstance(raw, dict):
        defaults.update(raw)

    # v3.4.2+ hotfix: Old versions could persist /root paths when running under sudo
    # (because ~ expanded to /root). Also, some environments run RedAudit directly as
    # root (no sudo) but still expect artifacts to land under /home/<user> when a single
    # "human" user exists. If we detect the legacy default under /root, rewrite to the
    # preferred Documents folder.
    output_dir = defaults.get("output_dir")
    if isinstance(output_dir, str):
        normalized = output_dir.strip()
        legacy_root_defaults = {
            "/root/RedAuditReports",
            "/root/Documents/RedAuditReports",
            "/root/Documentos/RedAuditReports",
        }
        if normalized in legacy_root_defaults:
            preferred_default = get_default_reports_base_dir()
            if preferred_default and preferred_default != normalized:
                defaults["output_dir"] = preferred_default
        elif get_invoking_user() and normalized == "/root":
            defaults["output_dir"] = get_default_reports_base_dir()

    return defaults


def update_persistent_defaults(**kwargs: Any) -> bool:
    """
    Update persisted defaults in config file.

    Any keys not present in DEFAULT_CONFIG["defaults"] are ignored.

    Returns:
        True if save succeeded
    """
    config = load_config()
    existing = config.get("defaults")
    defaults = existing if isinstance(existing, dict) else {}

    allowed = set(DEFAULT_CONFIG.get("defaults", {}).keys())
    for key, value in kwargs.items():
        if key in allowed:
            defaults[key] = value

    config["defaults"] = defaults
    return save_config(config)
