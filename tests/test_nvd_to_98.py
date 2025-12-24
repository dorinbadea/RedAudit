import os
import json
import time
import pytest
from unittest.mock import MagicMock, patch, mock_open
from urllib.error import HTTPError, URLError
from redaudit.core import nvd


@pytest.fixture
def clean_nvd_cache(tmp_path):
    # Mock NVD_CACHE_DIR to a temporary directory
    cache_dir = tmp_path / "nvd_cache"
    with patch("redaudit.core.nvd.NVD_CACHE_DIR", str(cache_dir)):
        yield cache_dir


# -------------------------------------------------------------------------
# Test API Key Logic
# -------------------------------------------------------------------------


def test_get_api_key_logic():
    # Case 1: Config available
    with (
        patch("redaudit.core.nvd.CONFIG_AVAILABLE", True),
        patch("redaudit.core.nvd.config_get_nvd_api_key", return_value="config-key"),
    ):
        assert nvd.get_api_key_from_config() == "config-key"

    # Case 2: Config not available, fallback to env
    with (
        patch("redaudit.core.nvd.CONFIG_AVAILABLE", False),
        patch.dict(os.environ, {"NVD_API_KEY": "env-key"}),
    ):
        assert nvd.get_api_key_from_config() == "env-key"

    # Case 3: Neither
    with patch("redaudit.core.nvd.CONFIG_AVAILABLE", False), patch.dict(os.environ, {}, clear=True):
        assert nvd.get_api_key_from_config() is None


# -------------------------------------------------------------------------
# Test Cache Logic
# -------------------------------------------------------------------------


def test_cache_dir_creation(clean_nvd_cache):
    with patch("os.makedirs") as mock_makedirs, patch("os.chmod") as mock_chmod:
        nvd.ensure_cache_dir()
        mock_makedirs.assert_called_once()
        mock_chmod.assert_called_once()

    # Test chmod failure
    with patch("os.makedirs"), patch("os.chmod", side_effect=Exception("Perm error")):
        # Should not crash
        nvd.ensure_cache_dir()


def test_cache_get_and_save(clean_nvd_cache):
    query = "test_query"
    data = {"cves": [{"id": "CVE-1"}]}

    # Not in cache
    assert nvd.get_cached_result(query) is None

    # Save to cache
    nvd.save_to_cache(query, data)

    # Get from cache
    cached = nvd.get_cached_result(query)
    assert cached == data

    # Test expired cache
    with patch("os.path.getmtime", return_value=time.time() - 9999999):
        assert nvd.get_cached_result(query) is None
        assert not os.path.exists(
            os.path.join(str(clean_nvd_cache), f"{nvd.get_cache_key(query)}.json")
        )


def test_cache_error_handling(clean_nvd_cache):
    query = "bad_cache"
    cache_file = os.path.join(str(clean_nvd_cache), f"{nvd.get_cache_key(query)}.json")
    os.makedirs(clean_nvd_cache, exist_ok=True)

    # Corrupt JSON
    with open(cache_file, "w") as f:
        f.write("{invalid json}")
    assert nvd.get_cached_result(query) is None

    # Exception during save
    with patch("builtins.open", side_effect=Exception("Disk full")):
        nvd.save_to_cache("anything", {"a": 1})  # Should not crash


# -------------------------------------------------------------------------
# Test Query Building and Parsing
# -------------------------------------------------------------------------


def test_build_cpe_query():
    # Sanitization
    cpe = nvd.build_cpe_query("Apache HTTPD!", "2.4.49 (beta)", "The Vendor")
    assert "apachehttpd" in cpe
    assert "2.4.49beta" in cpe
    assert "thevendor" in cpe
    assert cpe.startswith("cpe:2.3:a:")


def test_extract_product_version():
    assert nvd.extract_product_version("Apache httpd 2.4.49") == ("Apache", "2.4.49")
    assert nvd.extract_product_version("OpenSSH 7.9p1") == ("OpenSSH", "7.9p1")
    assert nvd.extract_product_version("nginx/1.18.0") == ("nginx", "1.18.0")
    # "Unknown service 1.0" matches (\w+)\s+(\d+\.\d...) -> ('service', '1.0')
    assert nvd.extract_product_version("Unknown service 1.0") == ("service", "1.0")
    assert nvd.extract_product_version(None) == (None, None)


# -------------------------------------------------------------------------
# Test NVD API Query
# -------------------------------------------------------------------------


@patch("redaudit.core.nvd.urlopen")
def test_query_nvd_success(mock_url, clean_nvd_cache):
    # Mock NIST response
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                    "descriptions": [{"lang": "en", "value": "A description"}],
                    "published": "2021-10-05T00:00Z",
                }
            }
        ]
    }
    mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_url.return_value.__enter__.return_value = mock_resp

    # Test adding apiKey header
    nvd.query_nvd(keyword="apache", api_key="test-key")
    args = mock_url.call_args[0][0]
    assert args.get_header("Apikey") == "test-key"

    # Test cache hit with logger
    logger = MagicMock()
    # Results should be in cache now
    res = nvd.query_nvd(keyword="apache", logger=logger)
    assert len(res) == 1
    logger.debug.assert_called()


def test_query_nvd_no_params():
    assert nvd.query_nvd() == []


@patch("redaudit.core.nvd.urlopen")
def test_query_nvd_retries_and_errors(mock_url, clean_nvd_cache):
    # Simulate 429 (Too Many Requests) then success
    mock_err = HTTPError("http://nvd", 429, "Too Many Requests", {}, None)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"vulnerabilities": []}'

    mock_url.side_effect = [mock_err, mock_resp, mock_resp]

    with patch("time.sleep"):
        res = nvd.query_nvd(cpe_name="cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", logger=MagicMock())
        assert res == []
        assert mock_url.call_count >= 2

    # URLError (Network down)
    mock_url.side_effect = URLError("Network unreachable")
    mock_url.reset_mock()
    res = nvd.query_nvd(keyword="test_network_fail")
    assert res == []
    assert mock_url.call_count == 3

    # Status != 200 (e.g. 404 - non-retryable)
    mock_url.side_effect = HTTPError("url", 404, "Not Found", {}, None)
    mock_url.reset_mock()
    res = nvd.query_nvd(keyword="test_404")
    assert res == []
    assert mock_url.call_count == 1


@patch("redaudit.core.nvd.urlopen")
def test_query_nvd_generic_exception(mock_url, clean_nvd_cache):
    mock_url.side_effect = Exception("Unknown failure")
    logger = MagicMock()
    res = nvd.query_nvd(keyword="test", logger=logger)
    assert res == []
    logger.debug.assert_called()


# -------------------------------------------------------------------------
# Test Enrichment logic
# -------------------------------------------------------------------------


@patch("redaudit.core.nvd.query_nvd")
def test_enrich_port_with_cves(mock_query):
    mock_query.return_value = [
        {"cve_id": "C1", "cvss_score": 9.8},
        {"cve_id": "C2", "cvss_score": 5.0},
    ]

    port = {"service": "http", "product": "Apache", "version": "2.4.49"}
    # Mock sleep to avoid delay
    with patch("time.sleep"):
        enriched = nvd.enrich_port_with_cves(port)

    assert enriched["cve_count"] == 2
    assert enriched["cve_max_severity"] == "CRITICAL"
    assert "cves" in enriched


def test_enrich_port_cpe_translation():
    # Test CPE 2.2 to 2.3 translation
    port = {"service": "ssh", "cpe": "cpe:/a:openbsd:openssh:7.9"}
    with patch("redaudit.core.nvd.query_nvd", return_value=[]) as mock_query, patch("time.sleep"):
        nvd.enrich_port_with_cves(port)
        # Check if query_nvd was called with the translated CPE
        args, kwargs = mock_query.call_args
        assert kwargs["cpe_name"] == "cpe:2.3:a:openbsd:openssh:7.9:*:*:*:*:*:*:*"


def test_enrich_port_cpe_list():
    # Test list of CPEs
    port = {"service": "ssh", "cpe": ["cpe:/a:x:y:1.0", "cpe:/a:a:b:2.0"]}
    with patch("redaudit.core.nvd.query_nvd", return_value=[]) as mock_query, patch("time.sleep"):
        nvd.enrich_port_with_cves(port)
        assert mock_query.called


def test_enrich_port_wildcards():
    # cpe_version in (*, -, "")
    # case 1: no version in port_info
    port = {"service": "test", "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*"}
    assert nvd.enrich_port_with_cves(port) == port

    # case 2: version results in empty sanitized version
    port = {"service": "test", "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*", "version": "!!!"}
    assert nvd.enrich_port_with_cves(port) == port


def test_enrich_port_wildcard_version_filling():
    # CPE with wildcard version but port_info has version
    port = {"service": "test", "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*", "version": "1.2.3"}
    with patch("redaudit.core.nvd.query_nvd", return_value=[]) as mock_query, patch("time.sleep"):
        nvd.enrich_port_with_cves(port)
        kwargs = mock_query.call_args[1]
        assert "1.2.3" in kwargs["cpe_name"]


def test_enrich_port_fallbacks():
    # No version, no product, just service
    port = {"service": "apache"}
    with patch("redaudit.core.nvd.query_nvd", return_value=[]) as mock_query, patch("time.sleep"):
        # Should not crash, returns input
        nvd.enrich_port_with_cves(port)

    # Product extraction success
    port = {"service": "http", "extrainfo": "Apache 2.4"}
    with patch("redaudit.core.nvd.query_nvd", return_value=[]) as mock_query, patch("time.sleep"):
        nvd.enrich_port_with_cves(port)


@patch("redaudit.core.nvd.enrich_port_with_cves")
def test_enrich_host(mock_enrich_port):
    mock_enrich_port.side_effect = lambda p, *args, **kwargs: {
        **p,
        "cve_count": 1,
        "cve_max_severity": "HIGH",
    }

    host = {
        "ports": [
            {"service": "http", "version": "1.0"},
            {"service": "ssh", "cpe": "cpe:/a:x:y:z"},
            {"service": "no-info"},  # Should be skipped
        ]
    }

    res = nvd.enrich_host_with_cves(host)
    assert res["cve_summary"]["total"] == 2  # 2 ports enriched
    assert res["cve_summary"]["high"] == 2
    assert mock_enrich_port.call_count == 2


@patch("redaudit.core.nvd.enrich_port_with_cves")
def test_enrich_host_list_cpe(mock_enrich_port):
    mock_enrich_port.side_effect = lambda p, *args, **kwargs: {**p, "cve_count": 0}
    host = {"ports": [{"service": "http", "cpe": ["cpe:/a:x:y:1.0"]}]}
    nvd.enrich_host_with_cves(host)
    assert mock_enrich_port.called


def test_clear_cache(clean_nvd_cache):
    os.makedirs(clean_nvd_cache, exist_ok=True)
    f = open(os.path.join(str(clean_nvd_cache), "test.json"), "w")
    f.close()

    # Should remove 1 file
    assert nvd.clear_cache() == 1
    assert len(os.listdir(clean_nvd_cache)) == 0

    # Chmod failure or other exception in clear_cache
    with patch("os.listdir", side_effect=Exception("error")):
        assert nvd.clear_cache() == 0


def test_severity_mapping():
    def get_enriched(scores):
        cves = [{"cvss_score": s} for s in scores]
        with patch("redaudit.core.nvd.query_nvd", return_value=cves), patch("time.sleep"):
            return nvd.enrich_port_with_cves({"product": "p", "version": "v"})

    assert get_enriched([9.1])["cve_max_severity"] == "CRITICAL"
    assert get_enriched([7.5])["cve_max_severity"] == "HIGH"
    assert get_enriched([4.5])["cve_max_severity"] == "MEDIUM"
    assert get_enriched([1.0])["cve_max_severity"] == "LOW"
    assert "cve_max_severity" not in get_enriched([0])
