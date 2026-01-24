#!/usr/bin/env python3
"""
Tests for signature_store data loaders.
"""

from redaudit.core.signature_store import (
    load_device_vendor_hints,
    load_nuclei_template_vendors,
)


def test_load_device_vendor_hints_has_router():
    hints = load_device_vendor_hints()
    assert isinstance(hints, list)
    assert any(h.get("device_type") == "router" for h in hints)


def test_load_nuclei_template_vendors_baseline():
    templates = load_nuclei_template_vendors()
    assert "CVE-2022-26143" in templates
    assert "expected_vendors" in templates["CVE-2022-26143"]
