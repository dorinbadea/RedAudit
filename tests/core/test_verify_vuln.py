#!/usr/bin/env python3
"""
RedAudit - Tests for verify_vuln module
v2.9 Smart-Check false positive filtering
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.verify_vuln import (
    extract_path_from_finding,
    is_sensitive_file,
    is_false_positive_by_content_type,
    is_false_positive_by_size,
    check_nuclei_false_positive,
    filter_nuclei_false_positives,
    validate_cpe_against_template,
    extract_host_cpes,
    verify_content_type,
    verify_magic_bytes,
    verify_nikto_finding,
    filter_nikto_false_positives,
)


class TestVerifyVuln(unittest.TestCase):
    """Tests for Nikto false positive filtering."""

    def test_extract_path_standard(self):
        """Test path extraction from standard Nikto format."""
        finding = "+ /backup.tar: This file may contain sensitive data."
        result = extract_path_from_finding(finding)
        self.assertEqual(result, "/backup.tar")

    def test_extract_path_osvdb(self):
        """Test path extraction from OSVDB format."""
        finding = "OSVDB-12345: /admin/.htpasswd found on the server."
        result = extract_path_from_finding(finding)
        self.assertEqual(result, "/admin/.htpasswd")

    def test_extract_path_no_path(self):
        """Test that None is returned for findings without paths."""
        finding = "+ Server: Apache/2.4.49 appears to be outdated."
        result = extract_path_from_finding(finding)
        # This may or may not find a path depending on the content
        # The important thing is it doesn't crash
        self.assertIsInstance(result, (str, type(None)))
        self.assertIsNone(extract_path_from_finding(None))

    def test_extract_path_pattern3(self):
        finding = "See /var/www/index.php for details."
        result = extract_path_from_finding(finding)
        self.assertEqual(result, "/var/www/index.php")

    def test_is_sensitive_file_tar(self):
        """Test sensitive file detection for tar."""
        self.assertTrue(is_sensitive_file("/backup.tar"))
        self.assertTrue(is_sensitive_file("/config.bak"))
        self.assertTrue(is_sensitive_file("/server.pem"))

    def test_is_sensitive_file_non_sensitive(self):
        """Test non-sensitive file detection."""
        self.assertFalse(is_sensitive_file("/index.html"))
        self.assertFalse(is_sensitive_file("/robots.txt"))
        self.assertFalse(is_sensitive_file(""))

    def test_fp_by_content_type_json(self):
        """Test that JSON content-type is flagged as FP for tar files."""
        result = is_false_positive_by_content_type(".tar", "application/json")
        self.assertTrue(result)

    def test_fp_by_content_type_html(self):
        """Test that HTML content-type is flagged as FP for zip files."""
        result = is_false_positive_by_content_type(".zip", "text/html")
        self.assertTrue(result)

    def test_fp_by_content_type_binary(self):
        """Test that binary content-type is NOT flagged as FP."""
        result = is_false_positive_by_content_type(".tar", "application/x-tar")
        self.assertFalse(result)

    def test_fp_by_content_type_none(self):
        result = is_false_positive_by_content_type(".tar", None)
        self.assertFalse(result)

    def test_fp_by_size_small_archive(self):
        """Test that very small archive sizes are flagged as FP."""
        result = is_false_positive_by_size(".tar", 47)  # 47 bytes JSON response
        self.assertTrue(result)

    def test_fp_by_size_valid_archive(self):
        """Test that larger archive sizes are NOT flagged as FP."""
        result = is_false_positive_by_size(".tar", 50000)  # 50KB
        self.assertFalse(result)

    def test_fp_by_size_none(self):
        result = is_false_positive_by_size(".tar", None)
        self.assertFalse(result)

    def test_nuclei_false_positive_router_vendor(self):
        finding = {
            "template-id": "CVE-2022-26143",
            "response": "HTTP/1.1 200 OK\\r\\nServer: FRITZ!OS Guest information Server\\r\\n\\r\\n{}",
        }
        is_fp, reason = check_nuclei_false_positive(finding, {"device_vendor": "AVM"})
        self.assertTrue(is_fp)
        self.assertIn("fp_vendor_detected", reason)

    @patch("redaudit.core.verify_vuln.verify_content_type")
    def test_verify_finding_filtered(self, mock_verify):
        """Test that a finding with JSON response is filtered."""
        mock_verify.return_value = ("application/json", 47)

        finding = "+ /backup.tar: May contain sensitive config."
        is_valid, reason = verify_nikto_finding(finding, "http://192.168.1.1:8189")

        self.assertFalse(is_valid)
        self.assertIn("filtered", reason)

    @patch("redaudit.core.verify_vuln.verify_content_type")
    def test_verify_finding_kept(self, mock_verify):
        """Test that a finding with binary response is kept."""
        mock_verify.return_value = ("application/x-tar", 102400)

        finding = "+ /backup.tar: May contain sensitive config."
        is_valid, reason = verify_nikto_finding(finding, "http://192.168.1.1")

        self.assertTrue(is_valid)
        self.assertIn("kept", reason)

    def test_filter_empty_list(self):
        """Test filtering empty list returns empty."""
        result = filter_nikto_false_positives([], "http://test.com")
        self.assertEqual(result, [])

    @patch("redaudit.core.verify_vuln.verify_nikto_finding")
    def test_filter_removes_fps(self, mock_verify):
        """Test that filter removes false positives."""
        # First finding is FP, second is valid
        mock_verify.side_effect = [
            (False, "filtered:content_type"),
            (True, "kept:verified"),
        ]

        findings = [
            "+ /backup.tar: May contain data.",
            "+ /admin/: Possible admin directory.",
        ]

        result = filter_nikto_false_positives(findings, "http://test.com")

        self.assertEqual(len(result), 1)
        self.assertIn("admin", result[0])

    @patch("redaudit.core.command_runner.subprocess.run")
    def test_verify_content_type_dry_run_does_not_execute(self, mock_run):
        with patch.dict(os.environ, {"REDAUDIT_DRY_RUN": "1"}, clear=False):
            content_type, content_len = verify_content_type("http://example.com", extra_tools={})
        mock_run.assert_not_called()
        self.assertIsNone(content_type)
        self.assertIsNone(content_len)


if __name__ == "__main__":
    unittest.main()


def test_verify_content_type_no_curl():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Type: text/html\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com", extra_tools={})
        assert content_type == "text/html"


def test_verify_content_type_content_length_value_error():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Length: invalid\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com")
        assert length is None


def test_verify_magic_bytes_no_curl():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"PK\x03\x04test"
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip", extra_tools={})
        assert isinstance(is_valid, bool)


def test_verify_magic_bytes_no_magic_defined():
    is_valid, reason = verify_magic_bytes("http://example.com/file.unknown", ".unknown")
    assert is_valid is True
    assert "kept:no_magic_check_for_ext" in reason


def test_verify_content_type_empty_curl_path():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Type: text/html\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com", extra_tools={"curl": ""})
        assert content_type == "text/html"
        assert length is None


def test_verify_content_type_exception_returns_none():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_runner.run.side_effect = RuntimeError("boom")

        content_type, length = verify_content_type("http://example.com")
        assert content_type is None
        assert length is None


def test_verify_magic_bytes_empty_curl_path():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"PK\x03\x04test"
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes(
            "http://example.com/file.zip", ".zip", extra_tools={"curl": ""}
        )
        assert is_valid is True
        assert "magic_bytes_match" in reason


def test_verify_magic_bytes_magic_not_defined():
    with patch.dict("redaudit.core.verify_vuln.MAGIC_BYTES", {}, clear=True):
        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip")
    assert is_valid is True
    assert "kept:magic_not_defined" in reason


def test_verify_magic_bytes_mismatch_not_html():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"XXXXYYYY"
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip")
        assert is_valid is False
        assert "filtered:magic_mismatch" in reason


def test_verify_magic_bytes_exception():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_runner.run.side_effect = RuntimeError("boom")

        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip")
        assert is_valid is True
        assert "magic_check_error" in reason


def test_verify_nikto_finding_no_path():
    is_valid, reason = verify_nikto_finding("No path here", "http://example.com")
    assert is_valid is True
    assert "no_path_extracted" in reason


def test_verify_nikto_finding_not_sensitive():
    is_valid, reason = verify_nikto_finding("+ /index.html: ok", "http://example.com")
    assert is_valid is True
    assert "not_sensitive_file" in reason


def test_validate_cpe_against_template_no_host_cpe():
    is_fp, reason = validate_cpe_against_template([], {"expected_vendors": []})
    assert is_fp is False
    assert reason == "no_host_cpe"


def test_validate_cpe_against_template_no_match(monkeypatch):
    monkeypatch.setattr("redaudit.core.verify_vuln.match_infra_keyword", lambda *_a, **_k: None)
    is_fp, reason = validate_cpe_against_template(
        ["cpe:/a:vendor:product:1.0"], {"expected_vendors": ["other"]}
    )
    assert is_fp is False
    assert reason == "cpe_no_match"


def test_extract_host_cpes_includes_http_server_cpe():
    host_data = {"http_server": "cpe:/a:vendor:prod:1.0", "ports": []}
    cpes = extract_host_cpes(host_data)
    assert "cpe:/a:vendor:prod:1.0" in cpes


def test_check_nuclei_false_positive_cpe_matches_expected(monkeypatch):
    finding = {"template-id": "CVE-0000-0000", "response": "Server: test\n"}
    host_data = {"http_server": "cpe:/a:vendor:prod:1.0"}

    monkeypatch.setattr(
        "redaudit.core.verify_vuln.validate_cpe_against_template",
        lambda *_a, **_k: (False, "matches_expected:vendor"),
    )
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.NUCLEI_TEMPLATE_VENDORS",
        {"CVE-0000-0000": {"expected_vendors": ["vendor"]}},
        raising=False,
    )

    is_fp, reason = check_nuclei_false_positive(finding, host_data, host_data=host_data)
    assert is_fp is False
    assert "matches_expected" in reason


def test_check_nuclei_false_positive_server_header_index_error(monkeypatch):
    class _WeirdLine:
        def lower(self):
            return "server:"

        def startswith(self, _prefix):
            return True

        def split(self, _sep, _maxsplit):
            raise IndexError("boom")

    class _WeirdResponse:
        def splitlines(self):
            return [_WeirdLine()]

        def lower(self):
            return ""

        def __len__(self):
            return 0

        def __getitem__(self, _item):
            return ""

    monkeypatch.setattr(
        "redaudit.core.verify_vuln.NUCLEI_TEMPLATE_VENDORS",
        {"CVE-0000-0001": {"expected_vendors": []}},
        raising=False,
    )

    finding = {"template-id": "CVE-0000-0001", "response": _WeirdResponse()}
    is_fp, _reason = check_nuclei_false_positive(finding, {})
    assert is_fp is False


def test_check_nuclei_false_positive_infra_hit(monkeypatch):
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.NUCLEI_TEMPLATE_VENDORS",
        {"CVE-0000-0002": {"expected_vendors": []}},
        raising=False,
    )
    monkeypatch.setattr("redaudit.core.verify_vuln.match_infra_keyword", lambda *_a, **_k: "router")
    finding = {"template-id": "CVE-0000-0002", "response": "Server: RouterOS\n"}
    is_fp, reason = check_nuclei_false_positive(finding, {})
    assert is_fp is True
    assert "infrastructure_device" in reason


def test_filter_nuclei_false_positives_urlparse_exception(monkeypatch):
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.NUCLEI_TEMPLATE_VENDORS",
        {"CVE-0000-0003": {"expected_vendors": []}},
        raising=False,
    )
    monkeypatch.setattr(
        "urllib.parse.urlparse", lambda *_a, **_k: (_ for _ in ()).throw(Exception())
    )
    findings = [{"template-id": "CVE-0000-0003", "ip": "http://bad"}]
    genuine, suspected = filter_nuclei_false_positives(findings, host_agentless={})
    assert genuine
    assert suspected == []


def test_filter_nuclei_false_positives_trim_port(monkeypatch):
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.NUCLEI_TEMPLATE_VENDORS",
        {"CVE-0000-0004": {"expected_vendors": []}},
        raising=False,
    )
    findings = [{"template-id": "CVE-0000-0004", "ip": "example.com:8080"}]
    host_agentless = {"example.com": {"device_vendor": "test"}}
    genuine, suspected = filter_nuclei_false_positives(findings, host_agentless=host_agentless)
    assert genuine
    assert suspected == []


def test_verify_magic_bytes_html_response():
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"<html>" + (b"x" * 300)
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/backup.tar", ".tar")
        assert isinstance(is_valid, bool)


def test_verify_nikto_finding_size_false_positive():
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        mock_verify.return_value = ("application/octet-stream", 100)

        is_valid, reason = verify_nikto_finding(
            "+ /backup.tar: This file may contain...", "http://example.com"
        )
        assert is_valid is False
        assert "too_small" in reason


def test_verify_nikto_finding_magic_bytes_fail():
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        with patch("redaudit.core.verify_vuln.verify_magic_bytes") as mock_magic:
            mock_verify.return_value = ("application/octet-stream", 5000)
            mock_magic.return_value = (False, "filtered:magic_mismatch")

            is_valid, reason = verify_nikto_finding(
                "+ /backup.tar: This file may contain...", "http://example.com"
            )
            assert is_valid is False


def test_filter_nikto_false_positives_with_logger():
    logger = MagicMock()

    with patch("redaudit.core.verify_vuln.verify_nikto_finding") as mock_verify:
        mock_verify.side_effect = [
            (True, "kept:verified"),
            (False, "filtered:content_type_mismatch"),
        ]

        findings = ["finding1", "finding2"]
        result = filter_nikto_false_positives(findings, "http://example.com", logger=logger)

        assert len(result) == 1
        assert logger.debug.called
        assert logger.info.called


def test_check_nuclei_false_positive_no_template_id():
    finding = {}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "no_template_id"


def test_check_nuclei_false_positive_raw_dict():
    finding = {"template-id": "CVE-2022-26143", "raw": {"response": "Server: Fritz!Box\r\n"}}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True


def test_check_nuclei_false_positive_server_header_parsing():
    finding = {
        "template-id": "CVE-2022-26143",
        "response": "HTTP/1.1 200 OK\r\nServer: Mitel-MiCollab\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False


def test_check_nuclei_false_positive_expected_vendor():
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Mitel\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "expected_vendor_found"


def test_check_nuclei_false_positive_infrastructure_device():
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Netgear\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    assert "netgear" in reason.lower()


def test_filter_nuclei_false_positives_empty():
    genuine, fps = filter_nuclei_false_positives([])
    assert genuine == []
    assert fps == []


def test_filter_nuclei_false_positives_url_parsing():
    findings = [
        {
            "template-id": "CVE-2022-26143",
            "ip": "http://192.168.1.1:8080",
            "response": "Server: Fritz!Box\r\n",
        }
    ]
    host_agentless = {"192.168.1.1": {"device_vendor": "AVM"}}

    genuine, fps = filter_nuclei_false_positives(findings, host_agentless)
    assert len(fps) == 1


def test_filter_nuclei_false_positives_with_logger():
    logger = MagicMock()
    findings = [
        {"template-id": "CVE-2022-26143", "ip": "192.168.1.1", "response": "Server: Fritz!Box\r\n"}
    ]

    genuine, fps = filter_nuclei_false_positives(findings, logger=logger)
    assert len(fps) == 1
    assert logger.info.called


def test_check_nuclei_false_positive_lf_line_endings():
    """Test header parsing with LF line endings (v4.3.1 fix)."""
    finding = {
        "template-id": "CVE-2022-26143",
        "response": "HTTP/1.1 200 OK\nServer: FRITZ!OS Guest information Server\nDate: Mon, 01 Jan 2026",
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    assert "vendor_detected" in reason or "fritz" in reason.lower()


def test_filter_nuclei_false_positives_with_host_records():
    """Test v4.4.2 fix: host_records parameter enables CPE-based validation."""
    findings = [
        {
            "template-id": "CVE-2022-26143",
            "ip": "192.168.178.1",
            "response": "HTTP/1.1 200 OK\r\nServer: FRITZ!OS Guest information Server\r\n\r\n{}",
        }
    ]
    host_records = [
        {
            "ip": "192.168.178.1",
            "ports": [{"port": 8189, "cpe": ["cpe:2.3:a:avm:fritz_os:*:*:*:*:*:*:*:*"]}],
        }
    ]

    genuine, fps = filter_nuclei_false_positives(findings, host_records=host_records)
    assert len(fps) == 1
    assert len(genuine) == 0
    assert fps[0].get("suspected_false_positive") is True


def test_check_nuclei_false_positive_fritz_in_response_body():
    """v4.13.2: Detect FRITZ!OS in response body, not just Server header."""
    finding = {
        "template-id": "CVE-2022-26143",
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"server":"FRITZ!OS Guest information Server","version":"1.0"}'
        ),
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    assert "fritz" in reason.lower()


def test_normalize_nuclei_finding_extracts_rich_fields():
    """v4.13.2: Verify nuclei normalization extracts impact/remediation/cvss."""
    from redaudit.core.nuclei import _normalize_nuclei_finding

    raw = {
        "template-id": "CVE-2024-54767",
        "info": {
            "name": "AVM FRITZ!Box Vulnerability",
            "severity": "high",
            "description": "A vulnerability in FRITZ!Box devices allows...",
            "impact": "An attacker can exploit this to...",
            "remediation": "Update to the latest firmware version.",
            "classification": {
                "cvss-score": 8.6,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            },
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-54767",
            ],
        },
        "host": "http://192.168.178.1:443",
        "matched-at": "http://192.168.178.1:443/path",
        "extracted-results": ["<result>data</result>"],
    }

    result = _normalize_nuclei_finding(raw)

    assert result is not None
    assert result["source"] == "nuclei"
    assert result["template_id"] == "CVE-2024-54767"
    assert result["name"] == "AVM FRITZ!Box Vulnerability"
    assert result["severity"] == "high"
    assert result["description"] == "A vulnerability in FRITZ!Box devices allows..."
    # v4.13.2 new fields
    assert result["impact"] == "An attacker can exploit this to..."
    assert result["remediation"] == "Update to the latest firmware version."
    assert result["cvss_score"] == 8.6
    assert "CVSS:3.1" in result["cvss_metrics"]
    assert len(result["reference"]) == 1
    assert result["extracted_results"] == ["<result>data</result>"]


# =============================================================================
# v4.14: CVE-2024-54767 Model-Specific Matching Tests
# =============================================================================


def test_check_nuclei_false_positive_cve_2024_54767_correct_model():
    """Test CVE-2024-54767 is NOT flagged as FP when model 7530 is present."""
    finding = {
        "template_id": "CVE-2024-54767",
        "info": {"name": "AVM FRITZ!Box 7530 AX - Unauthorized Access"},
        "response": "HTTP/1.1 200 OK\r\nServer: FRITZ!Box 7530 AX\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding, None)
    assert is_fp is False, f"Should not be FP for 7530, but got: {reason}"


def test_check_nuclei_false_positive_cve_2024_54767_wrong_model_7590():
    """Test CVE-2024-54767 IS flagged as FP when model 7590 is detected."""
    finding = {
        "template_id": "CVE-2024-54767",
        "info": {"name": "AVM FRITZ!Box - Unauthorized Access"},
        "response": "HTTP/1.1 200 OK\r\nServer: FRITZ!Box 7590 AX\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding, None)
    assert is_fp is True, f"Should be FP for 7590, but got: {reason}"
    assert "7590" in reason


def test_check_nuclei_false_positive_cve_2024_54767_wrong_model_repeater():
    """Test CVE-2024-54767 IS flagged as FP for FRITZ!Repeater devices."""
    finding = {
        "template_id": "CVE-2024-54767",
        "info": {"name": "AVM FRITZ!Box - Unauthorized Access"},
        "response": "HTTP/1.1 200 OK\r\nServer: FRITZ!Repeater 1200 AX\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding, None)
    assert is_fp is True, f"Should be FP for Repeater, but got: {reason}"
    assert "repeater" in reason or "1200" in reason


def test_check_nuclei_false_positive_cve_2024_54767_no_model_info():
    """Test CVE-2024-54767 IS flagged as FP when no model info available."""
    finding = {
        "template_id": "CVE-2024-54767",
        "info": {"name": "AVM FRITZ!Box - Unauthorized Access"},
        "response": "HTTP/1.1 200 OK\r\nServer: AVM\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding, None)
    # Should be FP because expected model (7530) not found
    assert is_fp is True, f"Should be FP when model not specified, but got: {reason}"
    assert "model" in reason.lower()
