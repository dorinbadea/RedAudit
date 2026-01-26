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
        "AA:BB:CC\tShort\tLong Name Inc\n"
        "AA:BB:CC:1/28\tShort\tNibble Vendor\n"
        "11:22:33:44:5/36\tShort\tNine Vendor\n"
        "# Comment\n"
        "112233\tOther\tOther Inc\n",
        encoding="utf-8",
    )

    # Mock module location to allow relative path "utils/../data/manuf"
    utils_dir = tmp_path / "utils"
    utils_dir.mkdir()
    fake_module_file = utils_dir / "oui_lookup.py"

    monkeypatch.setattr(oui_lookup, "__file__", str(fake_module_file))

    # Reset cache before load
    oui_lookup._OFFLINE_CACHE = {}
    oui_lookup._OFFLINE_CACHE_EXT = {}

    oui_lookup._load_offline_db()

    assert "AABBCC" in oui_lookup._OFFLINE_CACHE
    assert oui_lookup._OFFLINE_CACHE["AABBCC"] == "Long Name Inc"
    assert "112233" in oui_lookup._OFFLINE_CACHE
    assert oui_lookup._OFFLINE_CACHE["112233"] == "Other Inc"
    assert 28 in oui_lookup._OFFLINE_CACHE_EXT
    assert oui_lookup._OFFLINE_CACHE_EXT[28]["AABBCC1"] == "Nibble Vendor"
    assert 36 in oui_lookup._OFFLINE_CACHE_EXT
    assert oui_lookup._OFFLINE_CACHE_EXT[36]["112233445"] == "Nine Vendor"


def test_lookup_vendor_online_uses_offline_fallback(monkeypatch):
    """Test lookup_vendor_online checks offline cache first."""
    # Setup offline cache
    oui_lookup._OFFLINE_CACHE = {"AABBCC": "Offline Vendor"}
    oui_lookup._OFFLINE_CACHE_EXT = {}
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


def test_load_offline_db_missing_file(monkeypatch):
    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE", {})
    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE_EXT", {})
    monkeypatch.setattr(oui_lookup, "__file__", "/tmp/redaudit/utils/oui_lookup.py")
    monkeypatch.setattr("os.path.exists", lambda _p: False)
    oui_lookup._load_offline_db()
    assert oui_lookup._OFFLINE_CACHE == {}


def test_load_offline_db_read_error(monkeypatch):
    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE", {})
    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE_EXT", {})
    monkeypatch.setattr(oui_lookup, "__file__", "/tmp/redaudit/utils/oui_lookup.py")
    monkeypatch.setattr("os.path.exists", lambda _p: True)

    def _boom(*_args, **_kwargs):
        raise OSError("nope")

    monkeypatch.setattr("builtins.open", _boom)
    oui_lookup._load_offline_db()


def test_load_offline_db_skips_invalid_prefixes(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    manuf_file = data_dir / "manuf"
    manuf_file.write_text(
        "AA:BB:CC/25\tShort\tBad Bits\n"
        "AA:BB:CC/ZZ\tShort\tBad Parse\n"
        "AA:BB:CC:DD/36\tShort\tToo Short\n",
        encoding="utf-8",
    )

    utils_dir = tmp_path / "utils"
    utils_dir.mkdir()
    fake_module_file = utils_dir / "oui_lookup.py"
    monkeypatch.setattr(oui_lookup, "__file__", str(fake_module_file))

    oui_lookup._OFFLINE_CACHE = {}
    oui_lookup._OFFLINE_CACHE_EXT = {}
    oui_lookup._load_offline_db()

    assert oui_lookup._OFFLINE_CACHE == {}
    assert oui_lookup._OFFLINE_CACHE_EXT == {}


def test_lookup_vendor_online_prefers_longest_prefix(monkeypatch):
    oui_lookup._OFFLINE_CACHE = {}
    oui_lookup._OFFLINE_CACHE_EXT = {
        28: {"AABBCC1": "Nibble Vendor"},
        36: {"AABBCCDDE": "Nine Vendor"},
    }
    oui_lookup._VENDOR_CACHE = {}
    oui_lookup._LAST_REQUEST_TIME = 0.0

    import sys

    monkeypatch.setitem(sys.modules, "requests", None)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor == "Nine Vendor"


def test_lookup_vendor_online_matches_28(monkeypatch):
    oui_lookup._OFFLINE_CACHE = {}
    oui_lookup._OFFLINE_CACHE_EXT = {28: {"AABBCC1": "Nibble Vendor"}}
    oui_lookup._VENDOR_CACHE = {}
    oui_lookup._LAST_REQUEST_TIME = 0.0

    import sys

    monkeypatch.setitem(sys.modules, "requests", None)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:1f:00:00")
    assert vendor == "Nibble Vendor"
