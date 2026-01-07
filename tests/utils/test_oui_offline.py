#!/usr/bin/env python3
"""
RedAudit - Tests for offline OUI database logic.
"""

import time
from redaudit.utils import oui_lookup


def test_load_offline_db_success(tmp_path, monkeypatch):
    """Test loading OUI database from local file."""
    # Create mock structure: data/manuf
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    manuf_file = data_dir / "manuf"
    manuf_file.write_text(
        "AA:BB:CC\tShort\tLong Name Inc\n# Comment\n112233\tOther\tOther Inc\n", encoding="utf-8"
    )

    # Mock module location to allow relative path "utils/../data/manuf"
    utils_dir = tmp_path / "utils"
    utils_dir.mkdir()
    fake_module_file = utils_dir / "oui_lookup.py"

    monkeypatch.setattr(oui_lookup, "__file__", str(fake_module_file))

    # Reset cache before load
    oui_lookup._OFFLINE_CACHE = {}

    oui_lookup._load_offline_db()

    assert "AABBCC" in oui_lookup._OFFLINE_CACHE
    assert oui_lookup._OFFLINE_CACHE["AABBCC"] == "Long Name Inc"
    assert "112233" in oui_lookup._OFFLINE_CACHE
    assert oui_lookup._OFFLINE_CACHE["112233"] == "Other Inc"


def test_lookup_vendor_online_uses_offline_fallback(monkeypatch):
    """Test lookup_vendor_online checks offline cache first."""
    # Setup offline cache
    oui_lookup._OFFLINE_CACHE = {"AABBCC": "Offline Vendor"}
    oui_lookup._VENDOR_CACHE = {}
    oui_lookup._LAST_REQUEST_TIME = 0.0

    # Ensure requests is NOT used
    def _fail(*args, **kwargs):
        raise AssertionError("Should not make network request")

    monkeypatch.setattr(time, "sleep", lambda x: None)

    # We rely on the fact that if it tried to import requests, it would fail or use real network?
    # We patch requests to be sure
    import sys

    monkeypatch.setitem(sys.modules, "requests", None)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:11:22:33")
    assert vendor == "Offline Vendor"
