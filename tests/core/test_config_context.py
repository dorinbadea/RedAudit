#!/usr/bin/env python3
"""
Tests for ConfigurationContext - Phase 2 Architecture Refactoring.

These tests verify that ConfigurationContext works independently.
"""

import pytest

from redaudit.core.config_context import ConfigurationContext, create_config_context
from redaudit.utils.constants import DEFAULT_THREADS


class TestConfigurationContextCreation:
    """Test ConfigurationContext instantiation."""

    def test_default_creation(self):
        """Test ConfigurationContext with defaults."""
        cfg = ConfigurationContext()
        assert cfg.scan_mode == "normal"
        assert cfg.threads == DEFAULT_THREADS
        assert cfg.dry_run is False

    def test_custom_config(self):
        """Test ConfigurationContext with custom config."""
        raw = {"scan_mode": "completo", "threads": 16}
        cfg = ConfigurationContext(raw)
        assert cfg.scan_mode == "completo"
        assert cfg.threads == 16

    def test_factory_function(self):
        """Test create_config_context factory."""
        cfg = create_config_context({"dry_run": True})
        assert isinstance(cfg, ConfigurationContext)
        assert cfg.dry_run is True


class TestDictCompatibility:
    """Test dict-like access for backward compatibility."""

    def test_get_method(self):
        """Test get() method."""
        cfg = ConfigurationContext({"key": "value"})
        assert cfg.get("key") == "value"
        assert cfg.get("missing", "default") == "default"

    def test_bracket_access(self):
        """Test __getitem__ and __setitem__."""
        cfg = ConfigurationContext({"x": 1})
        assert cfg["x"] == 1
        cfg["y"] = 2
        assert cfg["y"] == 2

    def test_contains(self):
        """Test __contains__."""
        cfg = ConfigurationContext({"exists": True})
        assert "exists" in cfg
        assert "missing" not in cfg

    def test_setdefault(self):
        """Test setdefault()."""
        cfg = ConfigurationContext({})
        result = cfg.setdefault("new_key", "default_val")
        assert result == "default_val"
        assert cfg["new_key"] == "default_val"

    def test_raw_property(self):
        """Test raw dict access."""
        raw = {"a": 1, "b": 2}
        cfg = ConfigurationContext(raw)
        assert cfg.raw["a"] == 1
        assert cfg.raw["b"] == 2


class TestTypedProperties:
    """Test typed property access."""

    def test_target_networks(self):
        """Test target_networks property."""
        cfg = ConfigurationContext()
        assert cfg.target_networks == []

        cfg.target_networks = ["10.0.0.0/24"]
        assert cfg.target_networks == ["10.0.0.0/24"]

    def test_scan_mode(self):
        """Test scan_mode property."""
        cfg = ConfigurationContext({"scan_mode": "rapido"})
        assert cfg.scan_mode == "rapido"

        cfg.scan_mode = "completo"
        assert cfg.scan_mode == "completo"

    def test_threads(self):
        """Test threads property with validation."""
        cfg = ConfigurationContext({"threads": 8})
        assert cfg.threads == 8

        cfg.threads = -1  # Should enforce minimum of 1
        assert cfg.threads >= 1

    def test_output_dir(self):
        """Test output_dir property."""
        cfg = ConfigurationContext({"output_dir": "/custom/path"})
        assert cfg.output_dir == "/custom/path"

        cfg.output_dir = "/new/path"
        assert cfg.output_dir == "/new/path"

    def test_boolean_properties(self):
        """Test boolean flag properties."""
        cfg = ConfigurationContext(
            {
                "dry_run": True,
                "scan_vulnerabilities": False,
                "cve_lookup_enabled": True,
                "nuclei_enabled": True,
                "deep_id_scan": False,
                "topology_enabled": True,
                "windows_verify_enabled": True,
            }
        )

        assert cfg.dry_run is True
        assert cfg.scan_vulnerabilities is False
        assert cfg.cve_lookup_enabled is True
        assert cfg.nuclei_enabled is True
        assert cfg.deep_id_scan is False
        assert cfg.topology_enabled is True
        assert cfg.windows_verify_enabled is True

    def test_nuclei_timeout_default(self):
        cfg = ConfigurationContext()
        assert cfg.nuclei_timeout == 300

        cfg = ConfigurationContext({"nuclei_timeout": 450})
        assert cfg.nuclei_timeout == 450

    def test_prevent_sleep_default(self):
        """Test prevent_sleep defaults to True."""
        cfg = ConfigurationContext({})
        assert cfg.prevent_sleep is True


class TestThresholdProperties:
    """Test threshold/limit properties."""

    def test_identity_threshold(self):
        """Test identity_threshold property."""
        cfg = ConfigurationContext({"identity_threshold": 75})
        assert cfg.identity_threshold == 75

    def test_deep_scan_budget(self):
        """Test deep_scan_budget property."""
        cfg = ConfigurationContext({"deep_scan_budget": 10})
        assert cfg.deep_scan_budget == 10

    def test_windows_verify_max_targets(self):
        """Test windows_verify_max_targets property."""
        cfg = ConfigurationContext({"windows_verify_max_targets": 50})
        assert cfg.windows_verify_max_targets == 50


class TestConvenienceMethods:
    """Test convenience methods."""

    def test_is_full_mode(self):
        """Test is_full_mode() method."""
        cfg = ConfigurationContext({"scan_mode": "completo"})
        assert cfg.is_full_mode() is True

        cfg.scan_mode = "full"
        assert cfg.is_full_mode() is True

        cfg.scan_mode = "normal"
        assert cfg.is_full_mode() is False

    def test_is_stealth_mode(self):
        """Test is_stealth_mode() method."""
        cfg = ConfigurationContext({"stealth_mode": True})
        assert cfg.is_stealth_mode() is True

        cfg2 = ConfigurationContext({})
        assert cfg2.is_stealth_mode() is False

    def test_copy(self):
        """Test copy() creates independent copy."""
        original = ConfigurationContext({"scan_mode": "normal"})
        copied = original.copy()

        copied.scan_mode = "completo"

        assert original.scan_mode == "normal"
        assert copied.scan_mode == "completo"


class TestNetDiscoveryProperties:
    """Test net discovery specific properties."""

    def test_net_discovery_enabled_none(self):
        """Test net_discovery_enabled with None (auto)."""
        cfg = ConfigurationContext({"net_discovery_enabled": None})
        assert cfg.net_discovery_enabled is None

    def test_net_discovery_enabled_explicit(self):
        """Test net_discovery_enabled with explicit value."""
        cfg = ConfigurationContext({"net_discovery_enabled": True})
        assert cfg.net_discovery_enabled is True

        cfg2 = ConfigurationContext({"net_discovery_enabled": False})
        assert cfg2.net_discovery_enabled is False

    def test_net_discovery_redteam(self):
        """Test net_discovery_redteam property."""
        cfg = ConfigurationContext({"net_discovery_redteam": True})
        assert cfg.net_discovery_redteam is True

    def test_topology_only(self):
        """Test topology_only property."""
        cfg = ConfigurationContext({"topology_only": True})
        assert cfg.topology_only is True
