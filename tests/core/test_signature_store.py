#!/usr/bin/env python3
"""
Tests for signature_store data loaders.
"""

from unittest.mock import patch

from redaudit.core import signature_store
from redaudit.core.signature_store import (
    DEFAULT_NUCLEI_TEMPLATE_VENDORS,
    load_device_hostname_hints,
    load_device_vendor_hints,
    load_nuclei_template_vendors,
    _load_json,
    _sanitize_device_vendor_hints,
)


def test_load_device_vendor_hints_has_router():
    hints = load_device_vendor_hints()
    assert isinstance(hints, list)
    assert any(h.get("device_type") == "router" for h in hints)


def test_load_nuclei_template_vendors_baseline():
    templates = load_nuclei_template_vendors()
    assert "CVE-2022-26143" in templates
    assert "expected_vendors" in templates["CVE-2022-26143"]


def test_load_device_hostname_hints_has_mobile():
    hints = load_device_hostname_hints()
    assert isinstance(hints, list)
    assert any(h.get("device_type") == "mobile" for h in hints)


def test_load_json_missing_returns_none(tmp_path):
    with patch.object(signature_store, "_data_path", return_value=tmp_path / "missing.json"):
        assert _load_json("missing.json") is None


def test_sanitize_device_vendor_hints_invalid_types():
    assert _sanitize_device_vendor_hints("bad") == []


def test_sanitize_device_vendor_hints_skips_invalid_entries():
    data = [
        "bad",
        {"device_type": None},
        {"device_type": "router"},
    ]
    assert _sanitize_device_vendor_hints(data) == []


def test_load_device_hostname_hints_fallback():
    signature_store.load_device_hostname_hints.cache_clear()
    with patch.object(signature_store, "_load_device_hints", return_value=[]):
        hints = load_device_hostname_hints()
    assert hints


def test_load_nuclei_template_vendors_fallback():
    signature_store.load_nuclei_template_vendors.cache_clear()
    with patch.object(signature_store, "_load_json", return_value={}):
        data = load_nuclei_template_vendors()
    assert data == DEFAULT_NUCLEI_TEMPLATE_VENDORS
