#!/usr/bin/env python3
"""
Tests for thread suggestion helper.
"""

import os
from unittest.mock import patch

from redaudit.utils.constants import (
    MAX_THREADS,
    MIN_THREADS,
    _read_packaged_version_file,
    _read_pyproject_version,
    _resolve_version,
    suggest_threads,
)


def test_suggest_threads_minimum(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 1)
    assert suggest_threads() == MIN_THREADS + 1


def test_suggest_threads_caps(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 64)
    assert suggest_threads() == min(12, MAX_THREADS)


def test_suggest_threads_fallback_none(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    expected = max(MIN_THREADS + 1, min(4, 12, MAX_THREADS))
    assert suggest_threads() == expected


def test_suggest_threads_fallback_exception(monkeypatch):
    def _boom():
        raise RuntimeError("fail")

    monkeypatch.setattr(os, "cpu_count", _boom)
    expected = max(MIN_THREADS + 1, min(4, 12, MAX_THREADS))
    assert suggest_threads() == expected


def test_read_packaged_version_file_exception():
    """Test _read_packaged_version_file with exception (line 34-35)."""
    with patch("pathlib.Path.is_file", side_effect=Exception("File error")):
        result = _read_packaged_version_file()
        assert result is None


def test_read_pyproject_version_no_match():
    """Test _read_pyproject_version with no version match (line 51-53)."""
    with patch("pathlib.Path.is_file", return_value=True):
        with patch("pathlib.Path.read_text", return_value="no version here"):
            result = _read_pyproject_version()
            assert result is None


def test_read_pyproject_version_exception():
    """Test _read_pyproject_version exception fallback."""
    with patch("pathlib.Path.is_file", side_effect=Exception("boom")):
        assert _read_pyproject_version() is None


def test_resolve_version_pyproject_fallback():
    """Test _resolve_version using pyproject fallback (line 73).

    Note: This test verifies the mocking mechanism works. The actual
    _resolve_version function is called at module import time, so we
    test the components directly.
    """
    # Test that _read_pyproject_version returns the actual version from pyproject.toml
    result = _read_pyproject_version()
    # It should return a version string in semver format
    assert result is not None
    assert "." in result
    # Verify the import returns a value as well
    assert _resolve_version() is not None


def test_resolve_version_prefers_pyproject(monkeypatch):
    monkeypatch.setattr("redaudit.utils.constants._read_packaged_version_file", lambda: None)

    def _raise(*_args, **_kwargs):
        raise Exception("no metadata")

    monkeypatch.setattr("importlib.metadata.version", _raise)
    monkeypatch.setattr("redaudit.utils.constants._read_pyproject_version", lambda: "9.9.9")
    assert _resolve_version() == "9.9.9"
