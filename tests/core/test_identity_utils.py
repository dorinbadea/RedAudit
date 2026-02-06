#!/usr/bin/env python3
"""
RedAudit - Identity Utils Tests
"""

from redaudit.core.identity_utils import is_infra_identity


def test_is_infra_identity_device_type():
    assert is_infra_identity(device_type="router") == (True, "device_type")


def test_is_infra_identity_hint():
    assert is_infra_identity(device_type_hints=["switch"]) == (True, "device_type_hint")


def test_is_infra_identity_keyword():
    ok, reason = is_infra_identity(text="Netgear Router")
    assert ok is True
    assert reason.startswith("keyword:")
