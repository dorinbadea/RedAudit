#!/usr/bin/env python3
"""
Coverage for auditor mixin encryption and NVD setup flows.
"""

from __future__ import annotations

import base64

from redaudit.core.auditor_mixins import AuditorCryptoMixin, AuditorNVDMixin


class _DummyAuditor(AuditorCryptoMixin, AuditorNVDMixin):
    def __init__(self):
        self.config = {"cve_lookup_enabled": True}
        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = True
        self.lang = "en"
        self.COLORS = {"WARNING": "", "ENDC": "", "CYAN": ""}
        self.printed = []

    def t(self, key, *_args):
        return key

    def print_status(self, message, status="INFO", *_args, **_kwargs):
        self.printed.append((message, status))

    def ask_yes_no(self, *_args, **_kwargs):
        return True

    def ask_choice(self, *_args, **_kwargs):
        return 0


def test_setup_encryption_non_interactive_generates_password(monkeypatch):
    auditor = _DummyAuditor()

    monkeypatch.setattr("redaudit.core.auditor_mixins.generate_random_password", lambda: "pw")
    monkeypatch.setattr(
        "redaudit.core.auditor_mixins.derive_key_from_password",
        lambda _pw: (b"key", b"salt"),
    )

    auditor.setup_encryption(non_interactive=True, password=None)

    assert auditor.encryption_enabled is True
    assert auditor.encryption_key == b"key"
    assert auditor.config["encryption_enabled"] is True
    assert auditor.config["encryption_salt"] == base64.b64encode(b"salt").decode()


def test_setup_encryption_non_interactive_missing_crypto():
    auditor = _DummyAuditor()
    auditor.cryptography_available = False

    auditor.setup_encryption(non_interactive=True, password="pw")

    assert ("cryptography_required", "FAIL") in auditor.printed


def test_setup_nvd_api_key_cli_valid(monkeypatch):
    auditor = _DummyAuditor()

    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: True)

    auditor.setup_nvd_api_key(api_key="abc")

    assert auditor.config["nvd_api_key"] == "abc"
    assert ("nvd_key_set_cli", "OKGREEN") in auditor.printed


def test_setup_nvd_api_key_cli_invalid(monkeypatch):
    auditor = _DummyAuditor()

    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: False)

    auditor.setup_nvd_api_key(api_key="bad")

    assert auditor.config.get("nvd_api_key") is None
    assert ("nvd_key_invalid", "WARNING") in auditor.printed


def test_setup_nvd_api_key_non_interactive_without_key(monkeypatch):
    auditor = _DummyAuditor()

    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)

    auditor.setup_nvd_api_key(non_interactive=True, api_key=None)

    assert ("nvd_key_not_configured", "WARNING") in auditor.printed
