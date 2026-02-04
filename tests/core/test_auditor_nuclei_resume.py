#!/usr/bin/env python3
"""
Tests for Nuclei Resume State functions in InteractiveNetworkAuditor.
Coverage for _write_nuclei_resume_state, _load_nuclei_resume_state,
_clear_nuclei_resume_state, and _find_nuclei_resume_candidates.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from redaudit.core.auditor import InteractiveNetworkAuditor


def _make_auditor():
    """Create minimal auditor instance for testing."""
    auditor = InteractiveNetworkAuditor.__new__(InteractiveNetworkAuditor)
    auditor.config = {}
    auditor.logger = MagicMock()
    auditor.ui = MagicMock()
    return auditor


class TestNucleiResumeState(unittest.TestCase):
    def test_write_nuclei_resume_state_success(self):
        """Test successful write of resume state."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_state = {
                "pending_targets": ["http://t1", "http://t2"],
                "output_dir": tmpdir,
            }
            result = auditor._write_nuclei_resume_state(tmpdir, resume_state)

            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(result))
            with open(result, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["pending_targets"], ["http://t1", "http://t2"])
            self.assertIn("updated_at", saved)

            pending_path = os.path.join(tmpdir, "nuclei_pending.txt")
            self.assertTrue(os.path.exists(pending_path))
            with open(pending_path, "r", encoding="utf-8") as f:
                lines = f.read().strip().split("\n")
            self.assertEqual(lines, ["http://t1", "http://t2"])

    def test_write_nuclei_resume_state_empty_targets_returns_none(self):
        """Test that empty pending_targets returns None (lines 3403-3404)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = auditor._write_nuclei_resume_state(tmpdir, {"pending_targets": []})
            self.assertIsNone(result)

    def test_write_nuclei_resume_state_none_targets_returns_none(self):
        """Test that None pending_targets returns None."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = auditor._write_nuclei_resume_state(tmpdir, {"pending_targets": None})
            self.assertIsNone(result)

    def test_write_nuclei_resume_state_exception_logs_and_returns_none(self):
        """Test exception path logs and returns None (lines 3415-3418)."""
        auditor = _make_auditor()
        with patch("builtins.open", side_effect=IOError("disk full")):
            result = auditor._write_nuclei_resume_state("/fake/dir", {"pending_targets": ["t1"]})
        self.assertIsNone(result)
        auditor.logger.debug.assert_called()

    def test_clear_nuclei_resume_state_removes_files(self):
        """Test successful removal of resume files."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            pending_path = os.path.join(tmpdir, "nuclei_pending.txt")
            with open(resume_path, "w") as f:
                f.write("{}")
            with open(pending_path, "w") as f:
                f.write("t1\n")

            auditor._clear_nuclei_resume_state(resume_path, tmpdir)

            self.assertFalse(os.path.exists(resume_path))
            self.assertFalse(os.path.exists(pending_path))

    def test_clear_nuclei_resume_state_exception_logged(self):
        """Test exception during removal is logged (lines 3428-3430)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w") as f:
                f.write("{}")

            with patch("os.remove", side_effect=OSError("permission denied")):
                auditor._clear_nuclei_resume_state(resume_path, tmpdir)
            auditor.logger.debug.assert_called()

    def test_load_nuclei_resume_state_success(self):
        """Test successful loading of resume state."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            state = {
                "pending_targets": ["http://t1"],
                "output_dir": tmpdir,
                "resume_count": 2,
            }
            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump(state, f)

            result = auditor._load_nuclei_resume_state(resume_path)

            self.assertIsNotNone(result)
            self.assertEqual(result["pending_targets"], ["http://t1"])
            self.assertEqual(result["resume_count"], 2)

    def test_load_nuclei_resume_state_empty_path_returns_none(self):
        """Test empty path returns None (line 3434)."""
        auditor = _make_auditor()
        result = auditor._load_nuclei_resume_state("")
        self.assertIsNone(result)

    def test_load_nuclei_resume_state_nonexistent_returns_none(self):
        """Test nonexistent path returns None."""
        auditor = _make_auditor()
        result = auditor._load_nuclei_resume_state("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_load_nuclei_resume_state_empty_pending_returns_none(self):
        """Test empty pending_targets returns None (lines 3438-3440)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump({"pending_targets": []}, f)

            result = auditor._load_nuclei_resume_state(resume_path)
            self.assertIsNone(result)

    def test_load_nuclei_resume_state_missing_output_dir_uses_dirname(self):
        """Test missing output_dir falls back to resume file dirname (lines 3441-3444)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump({"pending_targets": ["http://t1"]}, f)

            result = auditor._load_nuclei_resume_state(resume_path)

            self.assertEqual(result["output_dir"], tmpdir)

    def test_load_nuclei_resume_state_invalid_resume_count_defaults_to_zero(self):
        """Test invalid resume_count converts to 0 (lines 3445-3449)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump({"pending_targets": ["http://t1"], "resume_count": "not_a_number"}, f)

            result = auditor._load_nuclei_resume_state(resume_path)

            self.assertEqual(result["resume_count"], 0)

    def test_load_nuclei_resume_state_sets_missing_last_resume_at(self):
        """Test missing last_resume_at gets set to empty string (lines 3450-3451)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump({"pending_targets": ["http://t1"]}, f)

            result = auditor._load_nuclei_resume_state(resume_path)

            self.assertEqual(result["last_resume_at"], "")

    def test_load_nuclei_resume_state_exception_returns_none(self):
        """Test exception during load returns None (lines 3453-3456)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w", encoding="utf-8") as f:
                f.write("invalid json{{{")

            result = auditor._load_nuclei_resume_state(resume_path)

            self.assertIsNone(result)
            auditor.logger.debug.assert_called()

    def test_find_nuclei_resume_candidates_returns_sorted_list(self):
        """Test finding candidates returns properly sorted list."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two scan directories with resume states
            scan1_dir = os.path.join(tmpdir, "scan_2024_01_01")
            scan2_dir = os.path.join(tmpdir, "scan_2024_02_01")
            os.makedirs(scan1_dir)
            os.makedirs(scan2_dir)

            with open(os.path.join(scan1_dir, "nuclei_resume.json"), "w") as f:
                json.dump(
                    {
                        "pending_targets": ["http://t1"],
                        "created_at": "2024-01-01T00:00:00",
                        "updated_at": "2024-01-01T00:00:00",
                        "resume_count": 0,
                    },
                    f,
                )

            with open(os.path.join(scan2_dir, "nuclei_resume.json"), "w") as f:
                json.dump(
                    {
                        "pending_targets": ["http://t2", "http://t3"],
                        "created_at": "2024-02-01T00:00:00",
                        "updated_at": "2024-02-01T00:00:00",
                        "resume_count": 1,
                    },
                    f,
                )

            candidates = auditor._find_nuclei_resume_candidates(tmpdir)

            self.assertEqual(len(candidates), 2)
            # Most recent should be first
            self.assertIn("scan_2024_02_01", candidates[0]["label"])
            self.assertIn("2 targets", candidates[0]["label"])
            self.assertIn("resumes: 1", candidates[0]["label"])

    def test_find_nuclei_resume_candidates_empty_base_dir(self):
        """Test empty base_dir returns empty list (line 3460-3461)."""
        auditor = _make_auditor()
        result = auditor._find_nuclei_resume_candidates("")
        self.assertEqual(result, [])

    def test_find_nuclei_resume_candidates_nonexistent_dir(self):
        """Test nonexistent dir returns empty list."""
        auditor = _make_auditor()
        result = auditor._find_nuclei_resume_candidates("/nonexistent/dir")
        self.assertEqual(result, [])

    def test_find_nuclei_resume_candidates_exception_logged(self):
        """Test exception during listing is logged (lines 3494-3496)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("os.listdir", side_effect=OSError("access denied")):
                result = auditor._find_nuclei_resume_candidates(tmpdir)
            self.assertEqual(result, [])
            auditor.logger.debug.assert_called()

    def test_find_nuclei_resume_candidates_invalid_resume_count_handled(self):
        """Test invalid resume_count in candidate is handled (lines 3476-3479)."""
        auditor = _make_auditor()
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = os.path.join(tmpdir, "scan_test")
            os.makedirs(scan_dir)

            with open(os.path.join(scan_dir, "nuclei_resume.json"), "w") as f:
                json.dump(
                    {
                        "pending_targets": ["http://t1"],
                        "resume_count": "invalid",
                    },
                    f,
                )

            candidates = auditor._find_nuclei_resume_candidates(tmpdir)

            self.assertEqual(len(candidates), 1)
            # Should have handled the invalid resume_count
            self.assertEqual(candidates[0]["resume_count"], 0)


if __name__ == "__main__":
    unittest.main()
