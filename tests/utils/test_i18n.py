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


def test_new_progress_i18n_keys_formatting():
    """Ensure new progress-related keys format correctly in both languages."""
    en = get_text("scanning_hosts_heartbeat", "en", 1, 2, 3, 4)
    es = get_text("scanning_hosts_heartbeat", "es", 1, 2, 3, 4)
    assert "1/2" in en
    assert "1/2" in es
    assert "3:04" in en
    assert "3:04" in es

    en = get_text("progress_elapsed", "en", 1, 2, 3, 4)
    es = get_text("progress_elapsed", "es", 1, 2, 3, 4)
    assert "1/2" in en
    assert "1/2" in es
    assert "3:04" in en
    assert "3:04" in es

    en = get_text("net_discovery_heartbeat", "en", 3, 4)
    es = get_text("net_discovery_heartbeat", "es", 3, 4)
    assert "3:04" in en
    assert "3:04" in es


def test_new_nuclei_i18n_keys_formatting():
    """Ensure new Nuclei keys format correctly in both languages."""
    en = get_text("nuclei_scanning_batches", "en", 3, 4)
    es = get_text("nuclei_scanning_batches", "es", 3, 4)
    assert "3" in en and "4" in en
    assert "3" in es and "4" in es

    en = get_text("nuclei_detail_parallel_running", "en", 1, 2, "0:10")
    es = get_text("nuclei_detail_parallel_running", "es", 1, 2, "0:10")
    assert "1/2" in en
    assert "1/2" in es
    assert "0:10" in en
    assert "0:10" in es
    assert "sub-batch" in en
    assert "sub-lote" in es

    en_split = get_text("nuclei_detail_split", "en", 3, 10)
    es_split = get_text("nuclei_detail_split", "es", 3, 10)
    assert "split depth" in en_split
    assert "profundidad" in es_split

    en = get_text("nuclei_resume_pending", "en", 5)
    es = get_text("nuclei_resume_pending", "es", 5)
    assert "5" in en
    assert "5" in es

    en = get_text("nuclei_no_findings_partial", "en")
    es = get_text("nuclei_no_findings_partial", "es")
    assert "Nuclei" in en
    assert "Nuclei" in es

    en = get_text("nuclei_targets_optimized", "en", 1, 2, 3)
    es = get_text("nuclei_targets_optimized", "es", 1, 2, 3)
    assert "1" in en and "2" in en and "3" in en
    assert "1" in es and "2" in es and "3" in es

    en = get_text("nuclei_optimization_note", "en")
    es = get_text("nuclei_optimization_note", "es")
    assert "identity" in en
    assert "identidad" in es

    en = get_text("nuclei_fatigue_q", "en")
    es = get_text("nuclei_fatigue_q", "es")
    assert "fatigue" in en
    assert "fatiga" in es

    en = get_text("nuclei_exclude_q", "en")
    es = get_text("nuclei_exclude_q", "es")
    assert "exclude" in en
    assert "exclusion" in es or "exclu" in es

    en = get_text("nuclei_detail_retry", "en", 2)
    es = get_text("nuclei_detail_retry", "es", 2)
    assert "2" in en
    assert "2" in es

    en = get_text("nuclei_detail_split", "en", 1, 3)
    es = get_text("nuclei_detail_split", "es", 1, 3)
    assert "1" in en and "3" in en
    assert "1" in es and "3" in es

    en = get_text("nuclei_timeout_detail", "en", 1, 4, "hosts 1; ports 80")
    es = get_text("nuclei_timeout_detail", "es", 1, 4, "hosts 1; ports 80")
    assert "1/4" in en
    assert "1/4" in es

    en = get_text("nuclei_progress_compact", "en", "batch 1/1", "5:00")
    es = get_text("nuclei_progress_compact", "es", "lote 1/1", "5:00")
    assert "5:00" in en
    assert "5:00" in es
    assert "total" in en.lower()
    assert "total" in es.lower()

    en = get_text("nuclei_completed_in", "en", "28:30")
    es = get_text("nuclei_completed_in", "es", "28:30")
    assert "28:30" in en
    assert "28:30" in es

    en = get_text("nuclei_resume_completed_in", "en", "15:01")
    es = get_text("nuclei_resume_completed_in", "es", "15:01")
    assert "15:01" in en
    assert "15:01" in es

    en = get_text("scope_iot_runtime", "en", 3, 7, 0)
    es = get_text("scope_iot_runtime", "es", 3, 7, 0)
    assert "3" in en and "7" in en
    assert "3" in es and "7" in es

    en = get_text("scope_leak_targets_added", "en", 2)
    es = get_text("scope_leak_targets_added", "es", 2)
    assert "2" in en
    assert "2" in es

    en = get_text("nuclei_timeout_targets", "en", "1.2.3.4(2)", "80,443")
    es = get_text("nuclei_timeout_targets", "es", "1.2.3.4(2)", "80,443")
    assert "1.2.3.4" in en
    assert "1.2.3.4" in es

    en = get_text("nuclei_suspected_only", "en", 2)
    es = get_text("nuclei_suspected_only", "es", 2)
    assert "2" in en
    assert "2" in es

    en = get_text("output_dir_q", "en")
    es = get_text("output_dir_q", "es")
    assert "Output" in en
    assert "Directorio" in es

    en = get_text("running_cve_correlation", "en")
    es = get_text("running_cve_correlation", "es")
    assert "CVE" in en
    assert "CVE" in es
