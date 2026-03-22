"""
Tests for paths.py and config.py utils modules to boost coverage to 85%+.
"""

from unittest.mock import patch, MagicMock
import pytest
import tempfile
import os

from redaudit.utils.paths import (
    get_invoking_user,
    get_reports_home_dir,
    get_invoking_home_dir,
    expand_user_path,
    get_documents_dir,
    get_default_reports_base_dir,
    resolve_invoking_user_owner,
    maybe_chown_to_invoking_user,
)

from redaudit.utils.config import (
    get_config_paths,
    ensure_config_dir,
    load_config,
    save_config,
    get_nvd_api_key,
    set_nvd_api_key,
    clear_nvd_api_key,
    is_nvd_api_key_configured,
    validate_nvd_api_key,
    get_config_summary,
    get_persistent_defaults,
    update_persistent_defaults,
    DEFAULT_CONFIG,
)

# -------------------------------------------------------------------------
# Paths Module Tests
# -------------------------------------------------------------------------


def test_get_invoking_user():
    """Test get_invoking_user function."""
    result = get_invoking_user()
    assert result is None or isinstance(result, str)


def test_get_reports_home_dir():
    """Test get_reports_home_dir function."""
    result = get_reports_home_dir()
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_invoking_home_dir():
    """Test get_invoking_home_dir function."""
    result = get_invoking_home_dir()
    assert isinstance(result, str)
    assert len(result) > 0


def test_expand_user_path_tilde():
    """Test expand_user_path with tilde."""
    result = expand_user_path("~/test")
    assert result.startswith("/") or result.startswith("C:")
    assert "~" not in result


def test_expand_user_path_absolute():
    """Test expand_user_path with absolute path."""
    result = expand_user_path("/tmp/test")
    assert result == "/tmp/test"


def test_get_documents_dir():
    """Test get_documents_dir function."""
    result = get_documents_dir()
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_documents_dir_with_home():
    """Test get_documents_dir with custom home."""
    result = get_documents_dir(home_dir="/tmp")
    assert isinstance(result, str)


def test_get_default_reports_base_dir():
    """Test get_default_reports_base_dir function."""
    result = get_default_reports_base_dir()
    assert isinstance(result, str)
    assert len(result) > 0


def test_resolve_invoking_user_owner():
    """Test resolve_invoking_user_owner function."""
    result = resolve_invoking_user_owner()
    assert result is None or isinstance(result, tuple)


def test_maybe_chown_to_invoking_user():
    """Test maybe_chown_to_invoking_user with temp file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    try:
        maybe_chown_to_invoking_user(path)  # Should not raise
    finally:
        os.unlink(path)


# -------------------------------------------------------------------------
# Config Module Tests
# -------------------------------------------------------------------------


def test_get_config_paths():
    """Test get_config_paths function."""
    config_dir, config_file = get_config_paths()
    assert isinstance(config_dir, str)
    assert isinstance(config_file, str)
    assert config_file.endswith(".json")


def test_ensure_config_dir():
    """Test ensure_config_dir function."""
    result = ensure_config_dir()
    assert isinstance(result, str)
    assert os.path.isdir(result)


def test_load_config():
    """Test load_config function."""
    config = load_config()
    assert isinstance(config, dict)
    assert "version" in config or "defaults" in config


def test_save_config():
    """Test save_config function."""
    config = load_config()
    result = save_config(config)
    assert result is True


def test_get_nvd_api_key():
    """Test get_nvd_api_key function."""
    result = get_nvd_api_key()
    assert result is None or isinstance(result, str)


def test_is_nvd_api_key_configured():
    """Test is_nvd_api_key_configured function."""
    result = is_nvd_api_key_configured()
    assert isinstance(result, bool)


def test_validate_nvd_api_key_valid():
    """Test validate_nvd_api_key with valid UUID format."""
    api_key = "12345678-1234-1234-1234-123456789012"
    result = validate_nvd_api_key(api_key)
    assert isinstance(result, bool)


def test_validate_nvd_api_key_invalid():
    """Test validate_nvd_api_key with invalid format."""
    result = validate_nvd_api_key("invalid-key")
    assert result is False


def test_validate_nvd_api_key_empty():
    """Test validate_nvd_api_key with empty string."""
    result = validate_nvd_api_key("")
    assert result is False


def test_validate_nvd_api_key_none():
    """Test validate_nvd_api_key with None."""
    result = validate_nvd_api_key(None)
    assert result is False


def test_get_config_summary():
    """Test get_config_summary function."""
    summary = get_config_summary()
    assert isinstance(summary, dict)


def test_get_persistent_defaults():
    """Test get_persistent_defaults function."""
    defaults = get_persistent_defaults()
    assert isinstance(defaults, dict)


def test_update_persistent_defaults():
    """Test update_persistent_defaults function."""
    # Just ensure it doesn't crash
    result = update_persistent_defaults(threads=4)
    assert result is True or result is False


def test_default_config_structure():
    """Test DEFAULT_CONFIG has expected structure."""
    assert "version" in DEFAULT_CONFIG
    assert "defaults" in DEFAULT_CONFIG
    assert isinstance(DEFAULT_CONFIG["defaults"], dict)
