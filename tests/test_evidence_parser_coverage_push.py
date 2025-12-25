"""
Tests for evidence_parser.py edge cases and missing coverage lines.
Target: Push evidence_parser.py from 93% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock
import os


class TestDeriveDescriptiveTitle:
    """Tests for _derive_descriptive_title function."""

    def test_derive_title_empty_observations(self):
        """Test returns None for empty observations (line 76)."""
        from redaudit.core.evidence_parser import _derive_descriptive_title

        result = _derive_descriptive_title([])
        assert result is None

    def test_derive_title_non_string_observations(self):
        """Test handles mixed observations with valid strings (lines 91-92, 114-115)."""
        from redaudit.core.evidence_parser import _derive_descriptive_title

        # Test with valid strings that get skipped because they're metadata
        result = _derive_descriptive_title(
            ["Server banner: Apache", "Technology: PHP", "valid vulnerability text"]
        )
        # Should return the valid vulnerability text (not metadata)
        assert result == "valid vulnerability text"

    def test_derive_title_empty_string_observation(self):
        """Test handles empty string observation (lines 117-118)."""
        from redaudit.core.evidence_parser import _derive_descriptive_title

        result = _derive_descriptive_title(["", "   ", "valid observation text"])
        assert result == "valid observation text"

    def test_derive_title_cve_pattern(self):
        """Test CVE pattern extraction."""
        from redaudit.core.evidence_parser import _derive_descriptive_title

        result = _derive_descriptive_title(["Some issue with CVE-2021-12345"])
        assert result == "CVE-2021-12345"

    def test_derive_title_missing_header(self):
        """Test missing header pattern."""
        from redaudit.core.evidence_parser import _derive_descriptive_title

        result = _derive_descriptive_title(["Missing X-Frame-Options header"])
        assert "Missing" in result


class TestParseTestsslOutput:
    """Tests for parse_testssl_output function."""

    def test_parse_testssl_sslv2_enabled(self):
        """Test SSLv2 enabled detection (line 216)."""
        from redaudit.core.evidence_parser import parse_testssl_output

        data = {"protocols": {"SSLv2": True}}
        result = parse_testssl_output(data)

        assert "SSLv2 enabled" in result

    def test_parse_testssl_tls11_enabled(self):
        """Test TLS 1.1 enabled detection (line 222)."""
        from redaudit.core.evidence_parser import parse_testssl_output

        data = {"protocols": {"TLS1.1": True}}
        result = parse_testssl_output(data)

        assert "TLS 1.1 enabled" in result

    def test_parse_testssl_all_protocols(self):
        """Test all protocol detections."""
        from redaudit.core.evidence_parser import parse_testssl_output

        data = {
            "protocols": {
                "SSLv2": True,
                "SSLv3": True,
                "TLS1.0": True,
                "TLS1.1": True,
            }
        }
        result = parse_testssl_output(data)

        assert "SSLv2 enabled" in result
        assert "SSLv3 enabled" in result
        assert "TLS 1.0 enabled" in result
        assert "TLS 1.1 enabled" in result


class TestSaveRawOutput:
    """Tests for save_raw_output exception handling (lines 293-294, 305-306)."""

    def test_save_raw_output_chmod_exception(self, tmp_path):
        """Test chmod exception is handled silently (lines 293-294, 305-306)."""
        from redaudit.core.evidence_parser import save_raw_output

        # Create output with mocked chmod to raise exception
        with patch("os.chmod") as mock_chmod:
            mock_chmod.side_effect = PermissionError("Permission denied")

            result = save_raw_output("test raw output", str(tmp_path), "192.168.1.1", 443)

        assert result == "evidence/raw_192_168_1_1_443.txt"
        assert os.path.exists(tmp_path / "evidence" / "raw_192_168_1_1_443.txt")

    def test_save_raw_output_success(self, tmp_path):
        """Test successful raw output saving."""
        from redaudit.core.evidence_parser import save_raw_output

        result = save_raw_output("raw output content here", str(tmp_path), "10.0.0.1", 80)

        assert "evidence/raw_10_0_0_1_80.txt" in result


class TestParseNiktoFindings:
    """Tests for parse_nikto_findings edge cases."""

    def test_parse_nikto_pattern_with_groups(self):
        """Test pattern matching with capture groups."""
        from redaudit.core.evidence_parser import parse_nikto_findings

        findings = ["Server: Apache/2.4.41", "Retrieved x-powered-by header: PHP/7.4"]
        result = parse_nikto_findings(findings)

        assert any("Server banner:" in obs for obs in result)
        assert any("X-Powered-By disclosure:" in obs for obs in result)

    def test_parse_nikto_truncation(self):
        """Test long observations are truncated."""
        from redaudit.core.evidence_parser import parse_nikto_findings

        long_line = "+ " + "A" * 200
        result = parse_nikto_findings([long_line])

        assert len(result[0]) <= 100


class TestEnrichWithObservations:
    """Tests for enrich_with_observations function."""

    def test_enrich_with_large_output_externalized(self, tmp_path):
        """Test large output is saved to external file."""
        from redaudit.core.evidence_parser import enrich_with_observations

        # Create vuln record with large output
        large_output = "x" * 5000  # > 4KB threshold
        vuln_record = {
            "url": "https://192.168.1.1:443/test",
            "port": 443,
            "nikto_findings": [large_output],
        }

        result = enrich_with_observations(vuln_record, str(tmp_path))

        assert "raw_tool_output_sha256" in result

    def test_enrich_adds_descriptive_title(self):
        """Test descriptive title is derived from observations."""
        from redaudit.core.evidence_parser import enrich_with_observations

        vuln_record = {
            # Use pattern that matches NIKTO_OBSERVATION_PATTERNS
            "nikto_findings": ["The anti-clickjacking X-Frame-Options header is not present"],
        }

        result = enrich_with_observations(vuln_record)

        # Check parsed observations were extracted
        assert "parsed_observations" in result
        assert any("X-Frame-Options" in obs for obs in result["parsed_observations"])
