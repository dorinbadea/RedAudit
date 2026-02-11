"""Tests for nuclei resume state, scope evidence, delegation wrappers, and static helpers."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from redaudit.core.auditor import InteractiveNetworkAuditor


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestAuditorNucleiResume(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()

    # --- Scope Evidence ---

    def test_scope_evidence_entry_normal(self, *args):
        """Test _scope_evidence_entry with valid classification."""
        entry = InteractiveNetworkAuditor._scope_evidence_entry(
            feature="leak_follow",
            classification="evidence",
            source="leak_follow:redirect",
            signal="https://example.com",
            decision="candidate_accepted",
            reason="domain match",
            host="192.168.1.1",
            raw_seed="test_seed_data",
        )
        self.assertEqual(entry["feature"], "leak_follow")
        self.assertEqual(entry["classification"], "evidence")
        self.assertIn("timestamp", entry)
        self.assertIn("raw_ref", entry)
        self.assertEqual(len(entry["raw_ref"]), 64)  # SHA-256 hex

    def test_scope_evidence_entry_unknown_classification(self, *args):
        """Test _scope_evidence_entry normalizes unknown classifications."""
        entry = InteractiveNetworkAuditor._scope_evidence_entry(
            feature="iot_probe",
            classification="invalid_class",
            source="",
            signal="",
            decision="",
            reason="",
            host="",
            raw_seed="seed",
        )
        self.assertEqual(entry["classification"], "hint")
        self.assertEqual(entry["source"], "unknown")

    def test_build_scope_expansion_evidence_leak(self, *args):
        """Test building scope evidence from leak follow decisions."""
        leak_runtime = {
            "decisions": [
                {
                    "candidate": "https://evil.com",
                    "source_host": "192.168.1.1",
                    "source_field": "redirect",
                    "reason": "domain match",
                    "eligible": True,
                },
                {
                    "candidate": "https://safe.com",
                    "source_host": "192.168.1.2",
                    "source_field": "link",
                    "reason": "out of scope",
                    "eligible": False,
                },
            ]
        }
        evidence = self.auditor._build_scope_expansion_evidence(leak_runtime, {})
        self.assertEqual(len(evidence), 2)
        self.assertEqual(evidence[0]["classification"], "heuristic")
        self.assertEqual(evidence[1]["classification"], "hint")

    def test_build_scope_expansion_evidence_iot(self, *args):
        """Test building scope evidence from IoT probe evidence."""
        iot_runtime = {
            "evidence": [
                {
                    "classification": "heuristic",
                    "source": "mdns",
                    "signal": "camera._tcp",
                    "decision": "identified",
                    "reason": "protocol match",
                    "host": "192.168.1.5",
                },
                {
                    "classification": "evidence",
                    "source": "upnp",
                    "signal": "device",
                    "decision": "confirmed",
                    "reason": "corroborated",
                    "host": "192.168.1.6",
                },
            ]
        }
        evidence = self.auditor._build_scope_expansion_evidence({}, iot_runtime)
        self.assertEqual(len(evidence), 2)
        self.assertEqual(evidence[1]["classification"], "evidence")

    def test_build_scope_expansion_evidence_promotion_guardrail(self, *args):
        """Test evidence class is demoted if not corroborated."""
        iot_runtime = {
            "evidence": [
                {
                    "classification": "evidence",
                    "source": "upnp",
                    "signal": "dev",
                    "decision": "maybe",
                    "reason": "not corroborated",
                    "host": "10.0.0.1",
                },
            ]
        }
        evidence = self.auditor._build_scope_expansion_evidence({}, iot_runtime)
        self.assertEqual(evidence[0]["classification"], "heuristic")

    def test_build_scope_expansion_evidence_dedup(self, *args):
        """Test deduplication of scope evidence entries."""
        leak_runtime = {
            "decisions": [
                {
                    "candidate": "https://dup.com",
                    "source_host": "10.0.0.1",
                    "source_field": "link",
                    "reason": "match",
                    "eligible": True,
                },
                {
                    "candidate": "https://dup.com",
                    "source_host": "10.0.0.1",
                    "source_field": "link",
                    "reason": "match",
                    "eligible": True,
                },
            ]
        }
        evidence = self.auditor._build_scope_expansion_evidence(leak_runtime, {})
        self.assertEqual(len(evidence), 1)

    def test_build_scope_expansion_evidence_empty(self, *args):
        """Test with empty/None inputs."""
        evidence = self.auditor._build_scope_expansion_evidence({}, {})
        self.assertEqual(evidence, [])

        evidence2 = self.auditor._build_scope_expansion_evidence(None, None)
        self.assertEqual(evidence2, [])

    def test_build_scope_expansion_evidence_bad_items(self, *args):
        """Test with non-dict items in decisions."""
        leak_runtime = {"decisions": ["bad_string", 42, None]}
        evidence = self.auditor._build_scope_expansion_evidence(leak_runtime, {})
        self.assertEqual(evidence, [])

    # --- Nuclei Resume State ---

    def test_build_nuclei_resume_state(self, *args):
        """Test building nuclei resume state dict."""
        state = self.auditor._build_nuclei_resume_state(
            output_dir="/tmp/test_output",
            pending_targets=["http://a.com", "http://b.com"],
            total_targets=10,
            profile="balanced",
            full_coverage=True,
            severity="high,critical",
            timeout_s=300,
            request_timeout_s=10,
            retries=2,
            batch_size=10,
            max_runtime_minutes=60,
            fatigue_limit=3,
            output_file="/tmp/test_output/nuclei_output.json",
        )
        self.assertEqual(state["version"], 1)
        self.assertEqual(len(state["pending_targets"]), 2)
        self.assertEqual(state["total_targets"], 10)
        self.assertEqual(state["nuclei"]["profile"], "balanced")
        self.assertTrue(state["nuclei"]["full_coverage"])
        self.assertEqual(state["nuclei"]["fatigue_limit"], 3)

    def test_write_nuclei_resume_state(self, *args):
        """Test writing nuclei resume state to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {
                "pending_targets": ["http://a.com"],
                "total_targets": 5,
            }
            path = self.auditor._write_nuclei_resume_state(tmpdir, state)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.exists(path))

            with open(path) as f:
                data = json.load(f)
            self.assertIn("updated_at", data)

            pending_path = os.path.join(tmpdir, "nuclei_pending.txt")
            self.assertTrue(os.path.exists(pending_path))

    def test_write_nuclei_resume_state_empty_targets(self, *args):
        """Test write returns None when no pending targets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {"pending_targets": []}
            result = self.auditor._write_nuclei_resume_state(tmpdir, state)
            self.assertIsNone(result)

    def test_write_nuclei_resume_state_none_targets(self, *args):
        """Test write returns None when pending_targets is None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {"pending_targets": None}
            result = self.auditor._write_nuclei_resume_state(tmpdir, state)
            self.assertIsNone(result)

    def test_load_nuclei_resume_state(self, *args):
        """Test loading nuclei resume state from disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            state = {
                "pending_targets": ["http://a.com"],
                "output_dir": tmpdir,
                "resume_count": 0,
                "last_resume_at": None,
            }
            with open(resume_path, "w") as f:
                json.dump(state, f)

            loaded = self.auditor._load_nuclei_resume_state(resume_path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["pending_targets"], ["http://a.com"])
            self.assertEqual(loaded["last_resume_at"], "")

    def test_load_nuclei_resume_state_no_file(self, *args):
        """Test loading with nonexistent file."""
        result = self.auditor._load_nuclei_resume_state("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_load_nuclei_resume_state_empty_file(self, *args):
        """Test loading with empty pending targets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            with open(resume_path, "w") as f:
                json.dump({"pending_targets": []}, f)

            result = self.auditor._load_nuclei_resume_state(resume_path)
            self.assertIsNone(result)

    def test_load_nuclei_resume_state_no_output_dir(self, *args):
        """Test loading infers output_dir from path when missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            state = {"pending_targets": ["http://a.com"], "resume_count": "bad"}
            with open(resume_path, "w") as f:
                json.dump(state, f)

            loaded = self.auditor._load_nuclei_resume_state(resume_path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["output_dir"], tmpdir)
            self.assertEqual(loaded["resume_count"], 0)

    def test_clear_nuclei_resume_state(self, *args):
        """Test clearing nuclei resume state files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resume_path = os.path.join(tmpdir, "nuclei_resume.json")
            pending_path = os.path.join(tmpdir, "nuclei_pending.txt")
            for path in (resume_path, pending_path):
                with open(path, "w") as f:
                    f.write("test")

            self.auditor._clear_nuclei_resume_state(resume_path, tmpdir)
            self.assertFalse(os.path.exists(resume_path))
            self.assertFalse(os.path.exists(pending_path))

    def test_clear_nuclei_resume_state_missing(self, *args):
        """Test clearing non-existent files doesn't raise."""
        self.auditor._clear_nuclei_resume_state("/nonexistent", "/nonexistent")

    # --- Report Detection ---

    def test_find_latest_report_json(self, *args):
        """Test finding the latest report JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["redaudit_2026-01-01.json", "redaudit_2026-01-02.json", "random.json"]:
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write("{}")

            result = self.auditor._find_latest_report_json(tmpdir)
            self.assertIsNotNone(result)
            self.assertIn("redaudit_", os.path.basename(result))

    def test_find_latest_report_json_partial(self, *args):
        """Test finding PARTIAL report files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "PARTIAL_redaudit_test.json"), "w") as f:
                f.write("{}")

            result = self.auditor._find_latest_report_json(tmpdir)
            self.assertIsNotNone(result)

    def test_find_latest_report_json_empty(self, *args):
        """Test with no matching report files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.auditor._find_latest_report_json(tmpdir)
            self.assertIsNone(result)

    def test_detect_report_artifact_txt(self, *args):
        """Test detecting a text report artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "redaudit_report.txt"), "w") as f:
                f.write("report")

            self.assertTrue(self.auditor._detect_report_artifact(tmpdir, (".txt",)))

    def test_detect_report_artifact_html(self, *args):
        """Test detecting an HTML report artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "report.html"), "w") as f:
                f.write("<html>")

            self.assertTrue(self.auditor._detect_report_artifact(tmpdir, (".html",)))

    def test_detect_report_artifact_none(self, *args):
        """Test no report artifact found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertFalse(self.auditor._detect_report_artifact(tmpdir, (".txt",)))

    # --- Load Resume Context ---

    def test_load_resume_context_success(self, *args):
        """Test loading resume context from a JSON report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "redaudit_test.json")
            report_data = {
                "config_snapshot": {
                    "target_networks": ["192.168.1.0/24"],
                    "lang": "en",
                },
                "hosts": [],
            }
            with open(report_path, "w") as f:
                json.dump(report_data, f)

            result = self.auditor._load_resume_context(tmpdir)
            self.assertTrue(result)
            self.assertEqual(self.auditor.config["target_networks"], ["192.168.1.0/24"])

    def test_load_resume_context_no_report(self, *args):
        """Test resume context fails when no report found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.auditor._load_resume_context(tmpdir)
            self.assertFalse(result)

    # --- Static Helpers ---

    def test_parse_duration_to_timedelta_hms(self, *args):
        """Test parsing H:MM:SS format."""
        result = InteractiveNetworkAuditor._parse_duration_to_timedelta("1:30:45")
        self.assertEqual(result, timedelta(hours=1, minutes=30, seconds=45))

    def test_parse_duration_to_timedelta_days(self, *args):
        """Test parsing 'N day(s), H:MM:SS' format."""
        result = InteractiveNetworkAuditor._parse_duration_to_timedelta("2 days, 3:15:00")
        self.assertEqual(result, timedelta(days=2, hours=3, minutes=15))

    def test_parse_duration_to_timedelta_invalid(self, *args):
        """Test parsing invalid format returns None."""
        result = InteractiveNetworkAuditor._parse_duration_to_timedelta("invalid")
        self.assertIsNone(result)

    def test_parse_duration_to_timedelta_none(self, *args):
        """Test parsing None returns None."""
        result = InteractiveNetworkAuditor._parse_duration_to_timedelta(None)
        self.assertIsNone(result)

    def test_parse_duration_to_timedelta_not_string(self, *args):
        """Test parsing non-string returns None."""
        result = InteractiveNetworkAuditor._parse_duration_to_timedelta([1, 2, 3])
        self.assertIsNone(result)

    def test_resolve_nuclei_success_true(self, *args):
        """Test nuclei success resolution."""
        self.assertTrue(
            InteractiveNetworkAuditor._resolve_nuclei_success(True, partial=False, error=None)
        )

    def test_resolve_nuclei_success_partial(self, *args):
        """Test nuclei success with partial flag."""
        self.assertFalse(
            InteractiveNetworkAuditor._resolve_nuclei_success(True, partial=True, error=None)
        )

    def test_resolve_nuclei_success_error(self, *args):
        """Test nuclei success with error."""
        self.assertFalse(
            InteractiveNetworkAuditor._resolve_nuclei_success(True, partial=False, error="timeout")
        )

    def test_resolve_nuclei_success_false(self, *args):
        """Test nuclei success with false flag."""
        self.assertFalse(
            InteractiveNetworkAuditor._resolve_nuclei_success(False, partial=False, error=None)
        )

    def test_resume_scan_start_time(self, *args):
        """Test resume start time calculation."""
        self.auditor.results = {"summary": {"duration": "0:10:00"}}
        self.auditor.scan_start_time = datetime(2026, 1, 1, 12, 0, 0)
        finished = datetime(2026, 1, 1, 12, 30, 0)
        elapsed = timedelta(minutes=20)

        result = self.auditor._resume_scan_start_time(finished, elapsed)
        self.assertIsNotNone(result)

    def test_resume_scan_start_time_no_elapsed(self, *args):
        """Test resume start time with no elapsed time."""
        self.auditor.results = {"summary": {"duration": "0:10:00"}}
        finished = datetime(2026, 1, 1, 12, 30, 0)
        result = self.auditor._resume_scan_start_time(finished, None)
        expected = finished - timedelta(minutes=10)
        self.assertEqual(result, expected)

    # --- Delegation Wrappers ---

    def test_apply_run_defaults_delegates(self, *args):
        """Test _apply_run_defaults delegates to ScanWizardFlow."""
        defaults = {"scan_mode": "normal"}
        self.auditor._apply_run_defaults(defaults)
        # Should call _scan_wizard_flow_call
        self.mock_runtime_cls.return_value._scan_wizard_flow_call = MagicMock()

    def test_normalize_csv_targets(self, *args):
        """Test static _normalize_csv_targets."""
        from redaudit.core.scan_wizard_flow import ScanWizardFlow

        result = ScanWizardFlow._normalize_csv_targets("a,b,c")
        self.assertEqual(result, ["a", "b", "c"])

    def test_normalize_csv_targets_none(self, *args):
        """Test _normalize_csv_targets with None."""
        from redaudit.core.scan_wizard_flow import ScanWizardFlow

        result = ScanWizardFlow._normalize_csv_targets(None)
        self.assertEqual(result, [])

    def test_show_defaults_summary_delegates(self, *args):
        """Test _show_defaults_summary delegates."""
        self.auditor._show_defaults_summary({"key": "value"})

    def test_configure_scan_interactive_delegates(self, *args):
        """Test _configure_scan_interactive delegates."""
        self.auditor._configure_scan_interactive({"scan_mode": "normal"})

    # --- Append Nuclei Output ---

    def test_append_nuclei_output(self, *args):
        """Test appending nuclei output to destination file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.json")
            with open(src, "w") as f:
                f.write('{"finding": "xss"}\n{"finding": "sqli"}\n')

            dest = os.path.join(tmpdir, "dest.json")
            self.auditor._append_nuclei_output(src, dest)

            with open(dest) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)

    # --- Find Nuclei Resume Candidates ---

    def test_find_nuclei_resume_candidates(self, *args):
        """Test finding nuclei resume candidates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "RedAudit_2026-01-01")
            os.makedirs(subdir)
            resume_path = os.path.join(subdir, "nuclei_resume.json")
            state = {
                "pending_targets": ["http://a.com"],
                "output_dir": subdir,
                "created_at": "2026-01-01T00:00:00",
            }
            with open(resume_path, "w") as f:
                json.dump(state, f)

            candidates = self.auditor._find_nuclei_resume_candidates(tmpdir)
            self.assertGreaterEqual(len(candidates), 1)

    def test_find_nuclei_resume_candidates_empty(self, *args):
        """Test finding candidates in empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            candidates = self.auditor._find_nuclei_resume_candidates(tmpdir)
            self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()
