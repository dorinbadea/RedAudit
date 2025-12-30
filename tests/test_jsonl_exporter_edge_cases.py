"""Tests for jsonl_exporter.py to push coverage to 95%+
Targets lines: 286-287, 341, 343, 347, 349, 351, 361
"""

from unittest.mock import patch
import tempfile
import os

from redaudit.core.jsonl_exporter import (
    export_summary_json,
    _extract_title,
)


def test_export_summary_chmod_exception():
    """Test export_summary_json with chmod exception (lines 286-287)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "summary.json")
        results = {
            "schema_version": "3.1",
            "session_id": "test",
            "summary": {},
            "hosts": [],
            "vulnerabilities": [],
        }

        with patch("os.chmod", side_effect=PermissionError("Access denied")):
            summary = export_summary_json(results, output_path)
            assert summary is not None


def test_extract_title_x_frame_options():
    """Test _extract_title with X-Frame-Options (line 341)."""
    vuln = {"parsed_observations": ["X-Frame-Options header missing"]}
    title = _extract_title(vuln)
    assert "X-Frame-Options" in title


def test_extract_title_x_content_type():
    """Test _extract_title with X-Content-Type (line 343)."""
    vuln = {"parsed_observations": ["X-Content-Type-Options header missing"]}
    title = _extract_title(vuln)
    assert "X-Content-Type" in title


def test_extract_title_cert_expired():
    """Test _extract_title with expired cert (line 349)."""
    vuln = {"parsed_observations": ["SSL certificate expired"]}
    title = _extract_title(vuln)
    assert "Expired" in title


def test_extract_title_self_signed():
    """Test _extract_title with self-signed cert (line 351)."""
    vuln = {"parsed_observations": ["Self-signed certificate detected"]}
    title = _extract_title(vuln)
    assert "Self-Signed" in title


def test_extract_title_server_banner():
    """Test _extract_title with server banner (line 363)."""
    vuln = {"parsed_observations": ["Server banner: Apache/2.4.41"]}
    title = _extract_title(vuln)
    assert "Server Version" in title or "Banner" in title


def test_extract_title_fallback_no_url():
    """Test _extract_title fallback without URL (line 372)."""
    vuln = {"port": 8080}
    title = _extract_title(vuln)
    assert "8080" in title
