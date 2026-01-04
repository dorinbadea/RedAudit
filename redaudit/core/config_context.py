"""
RedAudit - Configuration Context (Extracted from InteractiveNetworkAuditor)

This module provides a typed wrapper around the config dictionary,
enabling better testability and IDE support.

Part of v4.0 Architecture Refactoring - Phase 2.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any, Dict, Iterator, List, Optional

from redaudit.utils.constants import (
    DEFAULT_DEEP_SCAN_BUDGET,
    DEFAULT_IDENTITY_THRESHOLD,
    DEFAULT_THREADS,
    DEFAULT_UDP_MODE,
    UDP_TOP_PORTS,
)
from redaudit.utils.paths import get_default_reports_base_dir


class ConfigurationContext(MutableMapping):
    """
    Typed wrapper for RedAudit scan configuration.

    Provides type-safe access to configuration values with defaults,
    enabling easier testing and IDE autocompletion.
    """

    def __init__(self, raw_config: Optional[Dict[str, Any]] = None):
        """
        Initialize configuration context.

        Args:
            raw_config: Optional raw config dict. If None, uses defaults.
        """
        if raw_config is None:
            self._config = self._defaults()
        else:
            self._config = self._defaults()
            self._config.update(raw_config)

    @staticmethod
    def _defaults() -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "target_networks": [],
            "max_hosts": "all",
            "max_hosts_value": "all",
            "scan_mode": "normal",
            "threads": DEFAULT_THREADS,
            "output_dir": get_default_reports_base_dir(),
            "dry_run": False,
            "prevent_sleep": True,
            "scan_vulnerabilities": True,
            "save_txt_report": True,
            "save_html_report": True,
            "encryption_salt": None,
            "udp_mode": DEFAULT_UDP_MODE,
            "udp_top_ports": UDP_TOP_PORTS,
            "ipv6_only": False,
            "cve_lookup_enabled": False,
            "nvd_api_key": None,
            "deep_id_scan": True,
            "low_impact_enrichment": False,
            "deep_scan_budget": DEFAULT_DEEP_SCAN_BUDGET,
            "identity_threshold": DEFAULT_IDENTITY_THRESHOLD,
            "topology_enabled": False,
            "topology_only": False,
            "net_discovery_enabled": None,
            "net_discovery_protocols": None,
            "net_discovery_redteam": False,
            "net_discovery_interface": None,
            "net_discovery_max_targets": 50,
            "net_discovery_snmp_community": "public",
            "net_discovery_dns_zone": None,
            "net_discovery_kerberos_realm": None,
            "net_discovery_kerberos_userlist": None,
            "net_discovery_active_l2": False,
            "windows_verify_enabled": False,
            "windows_verify_max_targets": 20,
            "nuclei_enabled": False,
        }

    # -------------------------------------------------------------------------
    # Raw dict access (for backward compatibility)
    # -------------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value with default fallback."""
        return self._config.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-like access."""
        return self._config[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-like set."""
        self._config[key] = value

    def __delitem__(self, key: str) -> None:
        """Dict-like delete."""
        del self._config[key]

    def __iter__(self) -> Iterator[str]:
        """Dict-like iterator."""
        return iter(self._config)

    def __len__(self) -> int:
        """Dict-like length."""
        return len(self._config)

    def __contains__(self, key: object) -> bool:
        """Dict-like contains check."""
        return key in self._config

    def setdefault(self, key: str, default: Any = None) -> Any:
        """Dict-like setdefault."""
        return self._config.setdefault(key, default)

    @property
    def raw(self) -> Dict[str, Any]:
        """Get underlying raw config dict."""
        return self._config

    # -------------------------------------------------------------------------
    # Typed Properties - Scan Settings
    # -------------------------------------------------------------------------

    @property
    def target_networks(self) -> List[str]:
        """Get target network CIDRs."""
        return self._config.get("target_networks", []) or []

    @target_networks.setter
    def target_networks(self, value: List[str]) -> None:
        self._config["target_networks"] = value

    @property
    def scan_mode(self) -> str:
        """Get scan mode (normal, rapido, completo)."""
        return self._config.get("scan_mode", "normal") or "normal"

    @scan_mode.setter
    def scan_mode(self, value: str) -> None:
        self._config["scan_mode"] = value

    @property
    def threads(self) -> int:
        """Get number of threads."""
        return int(self._config.get("threads", DEFAULT_THREADS) or DEFAULT_THREADS)

    @threads.setter
    def threads(self, value: int) -> None:
        self._config["threads"] = max(1, int(value))

    @property
    def output_dir(self) -> str:
        """Get output directory path."""
        return self._config.get("output_dir", "") or get_default_reports_base_dir()

    @output_dir.setter
    def output_dir(self, value: str) -> None:
        self._config["output_dir"] = value

    @property
    def dry_run(self) -> bool:
        """Check if dry run mode is enabled."""
        return bool(self._config.get("dry_run", False))

    @property
    def prevent_sleep(self) -> bool:
        """Check if sleep prevention is enabled."""
        return bool(self._config.get("prevent_sleep", True))

    # -------------------------------------------------------------------------
    # Typed Properties - Feature Flags
    # -------------------------------------------------------------------------

    @property
    def scan_vulnerabilities(self) -> bool:
        """Check if vulnerability scanning is enabled."""
        return bool(self._config.get("scan_vulnerabilities", True))

    @property
    def cve_lookup_enabled(self) -> bool:
        """Check if CVE lookup is enabled."""
        return bool(self._config.get("cve_lookup_enabled", False))

    @property
    def nuclei_enabled(self) -> bool:
        """Check if Nuclei scanning is enabled."""
        return bool(self._config.get("nuclei_enabled", False))

    @property
    def deep_id_scan(self) -> bool:
        """Check if deep identity scan is enabled."""
        return bool(self._config.get("deep_id_scan", True))

    @property
    def topology_enabled(self) -> bool:
        """Check if topology discovery is enabled."""
        return bool(self._config.get("topology_enabled", False))

    @property
    def topology_only(self) -> bool:
        """Check if topology-only mode is enabled."""
        return bool(self._config.get("topology_only", False))

    @property
    def windows_verify_enabled(self) -> bool:
        """Check if Windows agentless verification is enabled."""
        return bool(self._config.get("windows_verify_enabled", False))

    @property
    def net_discovery_enabled(self) -> Optional[bool]:
        """Check if net discovery is enabled (None = auto)."""
        val = self._config.get("net_discovery_enabled")
        return None if val is None else bool(val)

    @property
    def net_discovery_redteam(self) -> bool:
        """Check if red team net discovery is enabled."""
        return bool(self._config.get("net_discovery_redteam", False))

    # -------------------------------------------------------------------------
    # Typed Properties - Thresholds & Limits
    # -------------------------------------------------------------------------

    @property
    def identity_threshold(self) -> int:
        """Get identity score threshold for deep scan."""
        return int(
            self._config.get("identity_threshold", DEFAULT_IDENTITY_THRESHOLD)
            or DEFAULT_IDENTITY_THRESHOLD
        )

    @property
    def deep_scan_budget(self) -> int:
        """Get deep scan budget (max hosts)."""
        return int(
            self._config.get("deep_scan_budget", DEFAULT_DEEP_SCAN_BUDGET)
            or DEFAULT_DEEP_SCAN_BUDGET
        )

    @property
    def windows_verify_max_targets(self) -> int:
        """Get max targets for Windows verification."""
        return int(self._config.get("windows_verify_max_targets", 20) or 20)

    # -------------------------------------------------------------------------
    # Convenience Methods
    # -------------------------------------------------------------------------

    def is_full_mode(self) -> bool:
        """Check if running in full/exhaustive scan mode."""
        return self.scan_mode in ("completo", "full")

    def is_stealth_mode(self) -> bool:
        """Check if stealth/slow mode is enabled."""
        return bool(self._config.get("stealth_mode", False))

    def copy(self) -> "ConfigurationContext":
        """Create a copy of this configuration."""
        return ConfigurationContext(dict(self._config))


def create_config_context(raw_config: Optional[Dict[str, Any]] = None) -> ConfigurationContext:
    """Factory function to create ConfigurationContext."""
    return ConfigurationContext(raw_config)
