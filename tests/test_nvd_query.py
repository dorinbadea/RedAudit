#!/usr/bin/env python3
"""
Additional coverage for NVD query/caching helpers.
"""

import json
import os
import time
from urllib.error import HTTPError

from redaudit.core import nvd


def test_get_api_key_from_env(monkeypatch):
    monkeypatch.setattr(nvd, "CONFIG_AVAILABLE", False)
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    assert nvd.get_api_key_from_config() == "env-key"


def test_get_cached_result_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    cache_file = tmp_path / f"{nvd.get_cache_key('query')}.json"
    cache_file.write_text(json.dumps({"cves": ["x"]}), encoding="utf-8")

    old_time = time.time() - (nvd.NVD_CACHE_TTL + 10)
    os.utime(cache_file, (old_time, old_time))

    assert nvd.get_cached_result("query") is None
    assert not cache_file.exists()


def test_query_nvd_uses_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    nvd.save_to_cache("cached", {"cves": [{"cve_id": "CVE-1"}]})

    def _fail_urlopen(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called for cache hits")

    monkeypatch.setattr(nvd, "urlopen", _fail_urlopen)
    cached = nvd.query_nvd(keyword="cached")
    assert cached == [{"cve_id": "CVE-1"}]


def test_query_nvd_parses_response(monkeypatch):
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "urlopen", lambda *_args, **_kwargs: _Response())

    result = nvd.query_nvd(keyword="apache", api_key=None, logger=None)
    assert result[0]["cve_id"] == "CVE-2024-0001"
    assert result[0]["cvss_score"] == 9.8
    assert result[0]["cvss_severity"] == "CRITICAL"


def test_query_nvd_handles_http_error(monkeypatch):
    def _raise_http(*_args, **_kwargs):
        raise HTTPError("url", 404, "not found", hdrs=None, fp=None)

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "urlopen", _raise_http)
    monkeypatch.setattr(nvd.time, "sleep", lambda *_args, **_kwargs: None)

    result = nvd.query_nvd(keyword="apache", api_key=None, logger=None)
    assert result == []


def test_clear_cache_removes_files(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    cache_file = tmp_path / "test.json"
    cache_file.write_text("{}", encoding="utf-8")
    assert nvd.clear_cache() == 1
    assert not cache_file.exists()
