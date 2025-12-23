#!/usr/bin/env python3
"""
RedAudit - Tests for HTML reporter edge cases and error handling.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock

from redaudit.core import html_reporter


def test_get_template_env_import_error():
    """Test line 27: ImportError when jinja2 not available."""
    with patch.dict("sys.modules", {"jinja2": None}):
        try:
            html_reporter.get_template_env()
            assert False, "Should have raised ImportError"
        except (ImportError, AttributeError):
            pass  # Expected


def test_save_html_report_chmod_error():
    """Test lines 208-209: chmod failure (non-critical)."""
    results = {
        "hosts": [],
        "vulnerabilities": [],
        "summary": {},
        "timestamp": "2025-01-01",
        "pipeline": {},
        "smart_scan_summary": {},
        "config_snapshot": {},
    }
    config = {"target_networks": ["192.168.1.0/24"], "scan_mode": "smart"}

    # Mock template rendering
    class _Template:
        def render(self, **kwargs):
            return "<html>test</html>"

    class _Env:
        def get_template(self, _name):
            return _Template()

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.html_reporter.get_template_env", return_value=_Env()):
            # Mock os.chmod to raise an exception
            with patch("os.chmod", side_effect=PermissionError("Mock chmod error")):
                # Should still succeed (chmod error is suppressed)
                output_path = html_reporter.save_html_report(results, config, tmpdir)
                assert output_path is not None
                assert os.path.exists(output_path)


def test_save_html_report_generation_error():
    """Test lines 212, 214, 216-217: Exception during report generation."""
    results = {"hosts": [], "vulnerabilities": []}
    config = {}

    # Mock generate_html_report to raise an exception
    with patch(
        "redaudit.core.html_reporter.generate_html_report", side_effect=RuntimeError("Mock error")
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = html_reporter.save_html_report(results, config, tmpdir)
            # Should return None on error
            assert output_path is None
