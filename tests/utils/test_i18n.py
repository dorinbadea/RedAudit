#!/usr/bin/env python3
"""
RedAudit - i18n Tests
Unit tests for language detection helpers.
"""

import os
import sys
import unittest
from unittest.mock import patch

# Add parent directory to path for CI compatibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.utils.i18n import detect_preferred_language, get_text


class TestDetectPreferredLanguage(unittest.TestCase):
    def test_prefers_explicit_value(self):
        self.assertEqual(detect_preferred_language("es"), "es")
        self.assertEqual(detect_preferred_language("en"), "en")

    def test_detects_from_env_lang(self):
        with patch.dict(os.environ, {"LANG": "es_ES.UTF-8"}, clear=True):
            self.assertEqual(detect_preferred_language(None), "es")

    def test_falls_back_to_en_for_unknown(self):
        with (
            patch.dict(os.environ, {"LANG": "C.UTF-8"}, clear=True),
            patch("locale.getlocale", return_value=(None, None)),
            patch("locale.getdefaultlocale", return_value=(None, None)),
        ):
            self.assertEqual(detect_preferred_language(None), "en")


if __name__ == "__main__":
    unittest.main()


def test_i18n_missing_key():
    """Test get_text with missing key (line 718)."""
    result = get_text("nonexistent_key_12345", "en")
    assert "nonexistent_key_12345" in result


def test_i18n_missing_key_es():
    """Test get_text with missing key in Spanish (line 740)."""
    result = get_text("nonexistent_key_67890", "es")
    assert "nonexistent_key_67890" in result


def test_detect_preferred_language_ignores_blank_env_and_uses_locale():
    """Test whitespace env var is ignored and locale is used."""
    with (
        patch.dict(os.environ, {"LC_ALL": "   "}, clear=True),
        patch("locale.getlocale", return_value=("es_ES", "UTF-8")),
    ):
        assert detect_preferred_language(None) == "es"


def test_detect_preferred_language_defaultlocale_on_getlocale_error():
    """Test defaultlocale path when getlocale raises."""
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("locale.getlocale", side_effect=RuntimeError("boom")),
        patch("locale.getdefaultlocale", return_value=("es_ES", "UTF-8")),
    ):
        assert detect_preferred_language(None) == "es"


def test_detect_preferred_language_defaultlocale_exception():
    """Test fallback to en when defaultlocale raises."""
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("locale.getlocale", side_effect=RuntimeError("boom")),
        patch("locale.getdefaultlocale", side_effect=RuntimeError("boom")),
    ):
        assert detect_preferred_language(None) == "en"


def test_hyperscan_start_sequential_key_en():
    """v4.15: Test hyperscan_start_sequential key exists in English."""
    result = get_text("hyperscan_start_sequential", "en")
    assert "SYN mode" in result
    assert "sequential" in result
    assert "{}" in result  # placeholder for host count


def test_hyperscan_start_sequential_key_es():
    """v4.15: Test hyperscan_start_sequential key exists in Spanish."""
    result = get_text("hyperscan_start_sequential", "es")
    assert "SYN" in result
    assert "secuencial" in result
    assert "{}" in result  # placeholder for host count


def test_deep_scan_heartbeat_key_en():
    """Ensure deep scan heartbeat formats in English."""
    result = get_text("deep_scan_heartbeat", "en", 1, 2, 3, 4)
    assert "DeepScan" in result
    assert "1/2" in result
    assert "3:04" in result


def test_deep_scan_heartbeat_key_es():
    """Ensure deep scan heartbeat formats in Spanish."""
    result = get_text("deep_scan_heartbeat", "es", 1, 2, 3, 4)
    assert "DeepScan" in result
    assert "1/2" in result
    assert "3:04" in result


def test_deep_scan_progress_key():
    """Ensure deep scan progress formats consistently."""
    result_en = get_text("deep_scan_progress", "en", 1, 2)
    result_es = get_text("deep_scan_progress", "es", 1, 2)
    assert "DeepScan" in result_en
    assert "1/2" in result_en
    assert "DeepScan" in result_es
    assert "1/2" in result_es


def test_auth_scan_connected_formats_protocol():
    """Ensure auth_scan_connected formats protocol label."""
    result_en = get_text("auth_scan_connected", "en", "SSH")
    result_es = get_text("auth_scan_connected", "es", "SMB")
    assert "SSH" in result_en
    assert "SMB" in result_es
    assert "{" not in result_en
    assert "{" not in result_es


def test_scan_error_host_format():
    """Ensure scan_error_host formats host and error."""
    result_en = get_text("scan_error_host", "en", "10.0.0.1", "boom")
    result_es = get_text("scan_error_host", "es", "10.0.0.1", "boom")
    assert "10.0.0.1" in result_en
    assert "boom" in result_en
    assert "10.0.0.1" in result_es
    assert "boom" in result_es


def test_deep_scan_new_hosts_format():
    """Ensure deep_scan_new_hosts formats count."""
    result_en = get_text("deep_scan_new_hosts", "en", 2)
    result_es = get_text("deep_scan_new_hosts", "es", 2)
    assert "2" in result_en
    assert "2" in result_es


def test_cve_enrich_new_hosts_format():
    """Ensure cve_enrich_new_hosts formats count."""
    result_en = get_text("cve_enrich_new_hosts", "en", 3)
    result_es = get_text("cve_enrich_new_hosts", "es", 3)
    assert "3" in result_en
    assert "3" in result_es


def test_auth_failed_all_formats():
    """Ensure auth failed messages format IP."""
    result_en = get_text("ssh_auth_failed_all", "en", "10.0.0.2")
    result_es = get_text("smb_auth_failed_all", "es", "10.0.0.2")
    assert "10.0.0.2" in result_en
    assert "10.0.0.2" in result_es


def test_dependency_i18n_keys_exist():
    """Ensure dependency status keys are present in both languages."""
    assert "Impacket" in get_text("impacket_available", "en")
    assert "Impacket" in get_text("impacket_available", "es")
    assert "PySNMP" in get_text("pysnmp_available", "en")
    assert "PySNMP" in get_text("pysnmp_available", "es")
