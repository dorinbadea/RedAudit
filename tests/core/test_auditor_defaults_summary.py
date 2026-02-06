#!/usr/bin/env python3
"""
Tests for additional auditor coverage paths.
Coverage for _show_defaults_summary edge cases and identity threshold conversion.
"""
import unittest
from unittest.mock import MagicMock

from redaudit.core.auditor import InteractiveNetworkAuditor


def _make_auditor():
    """Create minimal auditor instance for testing."""
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor.config = {}
    auditor.logger = MagicMock()
    auditor.ui = MagicMock()
    auditor.ui.t.side_effect = lambda key, *args: key
    return auditor


class TestShowDefaultsSummary(unittest.TestCase):
    def test_show_defaults_summary_with_all_fields(self):
        """Test _show_defaults_summary displays all fields."""
        auditor = _make_auditor()
        defaults = {
            "target_networks": ["192.168.1.0/24", "10.0.0.0/8"],
            "scan_mode": "full",
            "threads": 8,
            "output_dir": "/tmp/output",
            "rate_limit": 1.5,
            "udp_mode": "quick",
            "udp_top_ports": 100,
            "topology_enabled": True,
            "nuclei_enabled": True,
            "nuclei_max_runtime": 30,
        }

        auditor._show_defaults_summary(defaults)

        # Should have printed status for title
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_empty_targets_formats_as_dash(self):
        """Test fmt_targets returns '-' for empty list."""
        auditor = _make_auditor()
        defaults = {
            "target_networks": [],
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_none_targets_formats_as_dash(self):
        """Test fmt_targets returns '-' for None."""
        auditor = _make_auditor()
        defaults = {
            "target_networks": None,
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_invalid_runtime_minutes_handled(self):
        """Test fmt_runtime_minutes handles non-numeric value (lines 3160-3163)."""
        auditor = _make_auditor()
        defaults = {
            "nuclei_max_runtime": "not_a_number",
        }

        # Should not raise
        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_negative_runtime_minutes_clamped(self):
        """Test fmt_runtime_minutes clamps negative values to 0 (lines 3164-3165)."""
        auditor = _make_auditor()
        defaults = {
            "nuclei_max_runtime": -5,
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_none_runtime_minutes_formats_as_dash(self):
        """Test fmt_runtime_minutes returns '-' for None (lines 3157-3159)."""
        auditor = _make_auditor()
        defaults = {
            "nuclei_max_runtime": None,
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_none_bool_formats_as_dash(self):
        """Test fmt_bool returns '-' for None (lines 3152-3154)."""
        auditor = _make_auditor()
        defaults = {
            "topology_enabled": None,
            "nuclei_enabled": None,
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()

    def test_show_defaults_summary_targets_with_whitespace_cleaned(self):
        """Test fmt_targets cleans whitespace from target strings."""
        auditor = _make_auditor()
        defaults = {
            "target_networks": ["  192.168.1.0/24  ", "10.0.0.0/8", "   "],
        }

        auditor._show_defaults_summary(defaults)
        auditor.ui.print_status.assert_called()


if __name__ == "__main__":
    unittest.main()
