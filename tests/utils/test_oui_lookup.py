#!/usr/bin/env python3
"""
RedAudit - Tests for OUI lookup helpers.
"""

import builtins
import sys
import time
import types

from redaudit.utils import oui_lookup


def test_normalize_oui_formats():
    assert oui_lookup.normalize_oui("aa:bb:cc:dd:ee:ff") == "AABBCC"
    assert oui_lookup.normalize_oui("AA-BB-CC-11-22-33") == "AABBCC"
    assert oui_lookup.normalize_oui("aabb.ccdd.eeff") == "AABBCC"


def test_get_vendor_with_fallback_prefers_local(monkeypatch):
    def _fail(*_args, **_kwargs):
        raise AssertionError("online lookup should not be called")

    monkeypatch.setattr(oui_lookup, "lookup_vendor_online", _fail)
    assert oui_lookup.get_vendor_with_fallback("00:11:22:33:44:55", local_vendor="Acme") == "Acme"


def test_lookup_vendor_online_caches_success(monkeypatch):
    class _Response:
        status_code = 200
        text = "Acme Corp"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    times = iter([1000.0, 1000.0])
    monkeypatch.setattr(time, "time", lambda: next(times))
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor == "Acme Corp"
    assert oui_lookup._VENDOR_CACHE["AABBCC"] == "Acme Corp"


def test_lookup_vendor_online_caches_miss(monkeypatch):
    class _Response:
        status_code = 404
        text = "Not found"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor is None
    assert "AABBCC" in oui_lookup._VENDOR_CACHE
    assert oui_lookup._VENDOR_CACHE["AABBCC"] is None


def test_lookup_vendor_online_short_mac(monkeypatch):
    oui_lookup.clear_cache()
    assert oui_lookup.lookup_vendor_online("aa:bb") is None


def test_lookup_vendor_online_ext_prefix_longer_than_mac(monkeypatch):
    class _Response:
        status_code = 404
        text = "Not found"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE", {})
    monkeypatch.setattr(oui_lookup, "_OFFLINE_CACHE_EXT", {36: {"AABBCCDDE": "Vendor"}})

    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd")
    assert vendor is None


def test_lookup_vendor_online_request_exception(monkeypatch):
    class _Requests:
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    monkeypatch.setitem(sys.modules, "requests", _Requests())
    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor is None


def test_lookup_vendor_online_empty_mac():
    """Test line 51: return None for empty MAC."""
    assert oui_lookup.lookup_vendor_online("") is None
    assert oui_lookup.lookup_vendor_online(None) is None


def test_lookup_vendor_online_cache_hit(monkeypatch):
    """Test line 59: return cached result without making request."""
    oui_lookup.clear_cache()
    oui_lookup._VENDOR_CACHE["AABBCC"] = "Cached Vendor"

    # Should not make any request
    def _fail(*_args, **_kwargs):
        raise AssertionError("Should not make request when cached")

    monkeypatch.setattr(time, "time", _fail)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor == "Cached Vendor"


def test_lookup_vendor_online_rate_limiting(monkeypatch):
    """Test line 64: rate limiting with sleep."""

    class _Response:
        status_code = 200
        text = "Vendor1"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 1000.5  # Recent request

    # Current time is 1000.8, so delta is 0.3s < 1.0s
    times = iter([1000.8, 1000.8, 1001.0])  # time(), time() in sleep check, updated time()
    sleep_called = []

    monkeypatch.setattr(time, "time", lambda: next(times))
    monkeypatch.setattr(time, "sleep", lambda x: sleep_called.append(x))

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    oui_lookup.lookup_vendor_online("11:22:33:44:55:66")

    # Should have slept for 0.7 seconds (1.0 - 0.3)
    assert len(sleep_called) == 1
    assert abs(sleep_called[0] - 0.7) < 0.01


def test_lookup_vendor_online_import_error(monkeypatch):
    """Test line 89: handle missing requests library."""
    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    monkeypatch.setattr(time, "time", lambda: 1000.0)

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "requests":
            raise ImportError("requests not available")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor is None


def test_get_vendor_with_fallback_online_disabled():
    """Test lines 115-118: online_fallback=False returns None."""
    result = oui_lookup.get_vendor_with_fallback(
        "00:11:22:33:44:55", local_vendor=None, online_fallback=False
    )
    assert result is None


def test_get_vendor_with_fallback_empty_mac():
    """Test line 118: empty MAC returns None even with online_fallback."""
    result = oui_lookup.get_vendor_with_fallback("", local_vendor=None, online_fallback=True)
    assert result is None


def test_is_locally_administered_true():
    # x2 (0010)
    assert oui_lookup.is_locally_administered("02:00:00:00:00:00")
    # x6 (0110)
    assert oui_lookup.is_locally_administered("06:12:34:56:78:90")
    # xA (1010) - e.g. randomized
    assert oui_lookup.is_locally_administered("0A-00-00-00-00-00")
    # xE (1110)
    assert oui_lookup.is_locally_administered("0E00.0000.0000")

    # Mixed case
    assert oui_lookup.is_locally_administered("0a:00:00:00:00:00")


def test_is_locally_administered_false():
    # 00 (0000)
    assert not oui_lookup.is_locally_administered("00:50:56:C0:00:01")  # VMware
    # 01 (0001) - Multicast but not LAA
    assert not oui_lookup.is_locally_administered("01:00:5E:00:00:01")
    # 04 (0100)
    assert not oui_lookup.is_locally_administered("04:00:00:00:00:00")
    # Empty
    assert not oui_lookup.is_locally_administered("")
    assert not oui_lookup.is_locally_administered(None)
    assert not oui_lookup.is_locally_administered("ZZ:00:00:00:00:00")
    assert not oui_lookup.is_locally_administered("0")


def test_get_vendor_returns_private_label():
    # LAA MAC shoud return specific label, ignoring local/online
    label = "(MAC privado)"

    # Even if local_vendor is provided?
    # Logic: implementation checks LAA first.
    assert oui_lookup.get_vendor_with_fallback("02:00:00:00:00:00", local_vendor="Unknown") == label

    # Even if we have a "fake" local vendor?
    # Usually we want the truth (Private) over a guess.
    assert (
        oui_lookup.get_vendor_with_fallback("06:00:00:00:00:00", local_vendor="SomeVendor") == label
    )

    # Verify normal MAC still works
    assert (
        oui_lookup.get_vendor_with_fallback("00:50:56:00:00:01", local_vendor="VMware") == "VMware"
    )


def test_get_vendor_with_fallback_online(monkeypatch):
    monkeypatch.setattr(oui_lookup, "lookup_vendor_online", lambda _m: "OnlineVendor")
    result = oui_lookup.get_vendor_with_fallback("00:11:22:33:44:55", local_vendor=None)
    assert result == "OnlineVendor"
