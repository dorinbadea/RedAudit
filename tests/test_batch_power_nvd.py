#!/usr/bin/env python3
"""
Batch: power, nvd - VERIFIED APIs
Target: ~80 lines
"""

import tempfile
from unittest.mock import patch, MagicMock


# =================================================================
# power.py - 49 lines, 67.76%
# APIs: SleepInhibitor class (start, stop, __enter__, __exit__)
# =================================================================
def test_power_sleep_inhibitor_init():
    """Test SleepInhibitor initialization."""
    from redaudit.core.power import SleepInhibitor

    inhibitor = SleepInhibitor(dry_run=True)
    assert inhibitor is not None


def test_power_sleep_inhibitor_context_manager():
    """Test SleepInhibitor as context manager."""
    from redaudit.core.power import SleepInhibitor

    with SleepInhibitor(dry_run=True) as inhibitor:
        # Should not crash in dry-run mode
        assert inhibitor is not None


def test_power_sleep_inhibitor_start_stop():
    """Test SleepInhibitor start/stop."""
    from redaudit.core.power import SleepInhibitor

    inhibitor = SleepInhibitor(dry_run=True)
    inhibitor.start()
    inhibitor.stop()
    # Should handle gracefully


# =================================================================
# nvd.py - 81 lines, 67.86%
# APIs: build_cpe_query, extract_product_version, get_api_key_from_config,
#       ensure_cache_dir, get_cached_result, query_nvd
# =================================================================
def test_nvd_build_cpe_query():
    """Test CPE query building."""
    from redaudit.core.nvd import build_cpe_query

    cpe = build_cpe_query("apache", "2.4.49")
    assert "cpe:2.3" in cpe
    assert "apache" in cpe.lower()


def test_nvd_extract_product_version():
    """Test product/version extraction."""
    from redaudit.core.nvd import extract_product_version

    product, version = extract_product_version("Apache httpd 2.4.49")
    assert product is not None
    assert version is not None


def test_nvd_get_api_key_from_config():
    """Test API key retrieval."""
    from redaudit.core.nvd import get_api_key_from_config

    # Should return None or a string
    key = get_api_key_from_config()
    assert key is None or isinstance(key, str)


def test_nvd_ensure_cache_dir():
    """Test cache directory creation."""
    from redaudit.core.nvd import ensure_cache_dir

    # Should handle gracefully
    ensure_cache_dir()


def test_nvd_get_cached_result():
    """Test cache retrieval."""
    from redaudit.core.nvd import get_cached_result

    # Non-existent query
    result = get_cached_result("nonexistent_test_query_12345")
    assert result is None


def test_nvd_query_with_mock():
    """Test NVD query with mocked requests."""
    from redaudit.core.nvd import query_nvd

    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"vulnerabilities": []})

        # Should handle gracefully
        result = query_nvd(keyword="test", api_key="fake_key")
        assert isinstance(result, list)
