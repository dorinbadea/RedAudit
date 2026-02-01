#!/usr/bin/env python3
"""
Tests for scripts/seed_keyring.py
"""

import runpy
from types import SimpleNamespace
from unittest.mock import patch


def _load_script():
    return runpy.run_path("scripts/seed_keyring.py")


def test_seed_keyring_main_sets_credentials():
    calls = []

    class _Keyring:
        def get_keyring(self):
            return object()

        def set_keyring(self, _backend):
            return None

        def set_password(self, service, key, value):
            calls.append((service, key, value))

    fake_keyring = _Keyring()
    fake_errors = SimpleNamespace(NoKeyringError=RuntimeError)

    with patch.dict("sys.modules", {"keyring": fake_keyring, "keyring.errors": fake_errors}):
        with patch("os.geteuid", return_value=0):
            mod = _load_script()
            mod["main"]()

    # Ensure SSH and SMB spray lists are written.
    assert any(call[0] == "redaudit-ssh" and call[1] == "spray:list" for call in calls)
    assert any(call[0] == "redaudit-smb" and call[1] == "spray:list" for call in calls)
    # Ensure SNMP credentials are stored.
    assert any(call[0] == "redaudit-snmp" and call[1] == "default:secret" for call in calls)
