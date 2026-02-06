#!/usr/bin/env python3
"""Tests for hostname-based vendor hints."""

from redaudit.utils.vendor_hints import infer_vendor_from_hostname


def test_infer_vendor_from_hostname_detects_explicit_fritz_label():
    assert infer_vendor_from_hostname("fritz-box") == "AVM (guess)"


def test_infer_vendor_from_hostname_ignores_generic_fritz_domain_suffix():
    assert infer_vendor_from_hostname("android.fritz.box") is None


def test_infer_vendor_from_hostname_detects_synology():
    assert infer_vendor_from_hostname("diskstation-synology") == "Synology (guess)"
