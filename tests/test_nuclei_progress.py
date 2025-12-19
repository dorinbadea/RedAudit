#!/usr/bin/env python3
"""
Tests for nuclei integration progress plumbing.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch


class _FakeRunResult:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""


class _FakeCommandRunner:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, cmd, *args, **kwargs):
        # Locate the nuclei output path ("-o <path>") and write a JSONL finding to it.
        out_path = None
        try:
            if "-o" in cmd:
                out_path = cmd[cmd.index("-o") + 1]
        except Exception:
            out_path = None

        if out_path:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            payload = {
                "template-id": "unit-test-template",
                "info": {"name": "Unit Test Finding", "severity": "high"},
                "host": "http://127.0.0.1:80",
                "matched-at": "http://127.0.0.1:80/",
            }
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")

        return _FakeRunResult()


class TestNucleiProgress(unittest.TestCase):
    def test_progress_callback_called_per_batch(self):
        from redaudit.core.nuclei import run_nuclei_scan

        calls = []

        def cb(completed, total, eta):
            calls.append((completed, total, eta))

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
                    res = run_nuclei_scan(
                        targets=[
                            "http://127.0.0.1:80",
                            "http://127.0.0.2:80",
                            "http://127.0.0.3:80",
                        ],
                        output_dir=tmpdir,
                        batch_size=2,
                        progress_callback=cb,
                        use_internal_progress=False,
                        print_status=None,
                    )

        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("raw_output_file"))
        self.assertGreaterEqual(len(res.get("findings") or []), 1)

        # 3 targets with batch_size=2 => 2 batches
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1][0], calls[-1][1])
        self.assertTrue(str(calls[-1][2]).startswith("ETA≈ "))
