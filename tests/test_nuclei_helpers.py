#!/usr/bin/env python3
"""
RedAudit - Tests for nuclei helper utilities and error paths.
"""

import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def _fake_runner(stdout, returncode=0):
    def _run(*_args, **_kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    return SimpleNamespace(run=_run)


def test_get_nuclei_version_parses_output():
    from redaudit.core import nuclei

    version_output = "Nuclei Engine Version: v3.2.1\n"
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch("redaudit.core.nuclei.CommandRunner", lambda *_a, **_k: _fake_runner(version_output)):
            assert nuclei.get_nuclei_version() == "Nuclei Engine Version: v3.2.1"


def test_run_nuclei_scan_errors_when_missing_binary():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value=None):
            res = run_nuclei_scan(["http://127.0.0.1:80"], output_dir=tmpdir)

    assert res["success"] is False
    assert res["error"] == "nuclei not installed"


def test_run_nuclei_scan_no_targets():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            res = run_nuclei_scan([], output_dir=tmpdir)

    assert res["success"] is False
    assert res["error"] == "no targets provided"


def test_run_nuclei_scan_dry_run_short_circuit():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            res = run_nuclei_scan(["http://127.0.0.1:80"], output_dir=tmpdir, dry_run=True)

    assert res["success"] is True
    assert res["error"] == "dry-run mode"


def test_parse_nuclei_output_skips_invalid_lines():
    from redaudit.core.nuclei import _parse_nuclei_output

    payload = {
        "template-id": "unit-test-template",
        "info": {"name": "Unit Test Finding", "severity": "high"},
        "host": "http://127.0.0.1:80",
        "matched-at": "http://127.0.0.1:80/",
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        path = f"{tmpdir}/nuclei.json"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
            handle.write("{not valid json}\n")

        findings = _parse_nuclei_output(path)

    assert len(findings) == 1
    assert findings[0]["template_id"] == "unit-test-template"


def test_extract_cve_ids_from_tags_and_classification():
    from redaudit.core.nuclei import _extract_cve_ids

    info = {
        "classification": {"cve-id": ["CVE-2023-0001"]},
        "tags": ["cve-2023-0002", "misc"],
    }
    cves = _extract_cve_ids(info)
    assert set(cves) == {"CVE-2023-0001", "CVE-2023-0002"}


def test_get_http_targets_from_hosts_dedupes_and_schemes():
    from redaudit.core.nuclei import get_http_targets_from_hosts

    hosts = [
        {
            "ip": "10.0.0.1",
            "ports": [
                {"port": 80, "service": "http", "is_web_service": True},
                {"port": 443, "service": "https", "is_web_service": True},
                {"port": 22, "service": "ssh", "is_web_service": False},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert "http://10.0.0.1:80" in targets
    assert "https://10.0.0.1:443" in targets


def test_run_nuclei_scan_internal_progress(tmp_path):
    import sys
    from types import SimpleNamespace

    from redaudit.core.nuclei import run_nuclei_scan

    class _DummyColumn:
        def __init__(self, *args, **kwargs):
            pass

    class _DummyProgress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def add_task(self, *_args, **_kwargs):
            return 1

        def update(self, *_args, **_kwargs):
            return None

    class _DummyConsole:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeRunResult:
        def __init__(self):
            self.returncode = 0
            self.stdout = ""
            self.stderr = ""

    class _FakeCommandRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            out_path = None
            try:
                if "-o" in cmd:
                    out_path = cmd[cmd.index("-o") + 1]
            except Exception:
                out_path = None

            if out_path:
                payload = {
                    "template-id": "unit-test-template",
                    "info": {"name": "Unit Test Finding", "severity": "high"},
                    "host": "http://127.0.0.1:80",
                    "matched-at": "http://127.0.0.1:80/",
                }
                with open(out_path, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload) + "\n")

            return _FakeRunResult()

    progress_module = SimpleNamespace(
        Progress=_DummyProgress,
        SpinnerColumn=_DummyColumn,
        BarColumn=_DummyColumn,
        TextColumn=_DummyColumn,
        TimeElapsedColumn=_DummyColumn,
    )
    console_module = SimpleNamespace(Console=_DummyConsole)

    prev_progress = sys.modules.get("rich.progress")
    prev_console = sys.modules.get("rich.console")
    sys.modules["rich.progress"] = progress_module
    sys.modules["rich.console"] = console_module
    try:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
                res = run_nuclei_scan(
                    targets=["http://127.0.0.1:80"],
                    output_dir=str(tmp_path),
                    batch_size=1,
                    use_internal_progress=True,
                )
    finally:
        if prev_progress is None:
            sys.modules.pop("rich.progress", None)
        else:
            sys.modules["rich.progress"] = prev_progress
        if prev_console is None:
            sys.modules.pop("rich.console", None)
        else:
            sys.modules["rich.console"] = prev_console

    assert res["success"] is True
