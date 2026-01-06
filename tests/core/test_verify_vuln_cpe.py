#!/usr/bin/env python3
"""
Tests for Smart-Check Nuclei CPE validation functions.

v4.3: Tests for parse_cpe_components, validate_cpe_against_template, extract_host_cpes.
"""

import unittest
from redaudit.core.verify_vuln import (
    parse_cpe_components,
    validate_cpe_against_template,
    extract_host_cpes,
    check_nuclei_false_positive,
    NUCLEI_TEMPLATE_VENDORS,
)


class TestParseCpeComponents(unittest.TestCase):
    """Tests for parse_cpe_components function."""

    def test_parse_cpe_23_format(self):
        """Should parse CPE 2.3 format correctly."""
        cpe = "cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*"
        result = parse_cpe_components(cpe)
        self.assertEqual(result["vendor"], "apache")
        self.assertEqual(result["product"], "httpd")
        self.assertEqual(result["version"], "2.4.50")

    def test_parse_cpe_22_format(self):
        """Should parse CPE 2.2 format correctly."""
        cpe = "cpe:/a:apache:httpd:2.4.50"
        result = parse_cpe_components(cpe)
        self.assertEqual(result["vendor"], "apache")
        self.assertEqual(result["product"], "httpd")
        self.assertEqual(result["version"], "2.4.50")

    def test_parse_cpe_empty_string(self):
        """Should return empty dict for empty input."""
        result = parse_cpe_components("")
        self.assertEqual(result, {"vendor": "", "product": "", "version": ""})

    def test_parse_cpe_none(self):
        """Should return empty dict for None."""
        result = parse_cpe_components(None)
        self.assertEqual(result, {"vendor": "", "product": "", "version": ""})

    def test_parse_cpe_wildcard_version(self):
        """Should handle wildcard version."""
        cpe = "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*"
        result = parse_cpe_components(cpe)
        self.assertEqual(result["vendor"], "microsoft")
        self.assertEqual(result["product"], "iis")
        self.assertEqual(result["version"], "")  # Wildcard should become empty


class TestValidateCpeAgainstTemplate(unittest.TestCase):
    """Tests for validate_cpe_against_template function."""

    def test_validate_cpe_matches_expected(self):
        """Should not flag as FP when CPE matches expected vendor."""
        template_config = {
            "expected_vendors": ["mitel", "micollab"],
            "false_positive_vendors": ["fritz", "avm"],
        }
        cpes = ["cpe:2.3:a:mitel:micollab:9.0:*:*:*:*:*:*:*"]
        is_fp, reason = validate_cpe_against_template(cpes, template_config)
        self.assertFalse(is_fp)
        self.assertIn("matches_expected", reason)

    def test_validate_cpe_matches_fp_vendor(self):
        """Should flag as FP when CPE matches FP vendor."""
        template_config = {
            "expected_vendors": ["mitel", "micollab"],
            "false_positive_vendors": ["fritz", "avm"],
        }
        cpes = ["cpe:2.3:a:avm:fritzbox:7.50:*:*:*:*:*:*:*"]
        is_fp, reason = validate_cpe_against_template(cpes, template_config)
        self.assertTrue(is_fp)
        self.assertIn("fp_vendor", reason)

    def test_validate_cpe_infrastructure(self):
        """Should flag as FP when CPE matches infrastructure device."""
        template_config = {
            "expected_vendors": ["mitel"],
            "false_positive_vendors": [],
        }
        cpes = ["cpe:2.3:a:synology:diskstation_manager:7.0:*:*:*:*:*:*:*"]
        is_fp, reason = validate_cpe_against_template(cpes, template_config)
        self.assertTrue(is_fp)
        self.assertIn("infrastructure", reason)


class TestExtractHostCpes(unittest.TestCase):
    """Tests for extract_host_cpes function."""

    def test_extract_from_ports(self):
        """Should extract CPE from ports data."""
        host_data = {
            "ports": [
                {"port": 80, "cpe": "cpe:/a:apache:httpd:2.4.50"},
                {"port": 443, "cpe": ["cpe:/a:openssl:openssl:1.1.1k"]},
            ]
        }
        cpes = extract_host_cpes(host_data)
        self.assertEqual(len(cpes), 2)
        self.assertIn("cpe:/a:apache:httpd:2.4.50", cpes)

    def test_extract_empty_host(self):
        """Should return empty list for host without CPE."""
        host_data = {"ports": [{"port": 80, "service": "http"}]}
        cpes = extract_host_cpes(host_data)
        self.assertEqual(cpes, [])


class TestCheckNucleiWithCpe(unittest.TestCase):
    """Tests for check_nuclei_false_positive with CPE validation."""

    def test_cpe_blocks_fp_vendor(self):
        """Should detect FP when host CPE is an infrastructure device."""
        finding = {
            "template-id": "CVE-2022-26143",
            "ip": "192.168.1.1",
        }
        host_data = {"ports": [{"port": 80, "cpe": "cpe:2.3:a:avm:fritzbox:7.50:*:*:*:*:*:*:*"}]}
        is_fp, reason = check_nuclei_false_positive(
            finding,
            agentless_data=None,
            host_data=host_data,
        )
        self.assertTrue(is_fp)
        self.assertIn("fp", reason.lower())


if __name__ == "__main__":
    unittest.main()
