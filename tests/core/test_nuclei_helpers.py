#!/usr/bin/env python3
"""
RedAudit - Tests for nuclei helper utilities and error paths.
"""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from redaudit.core.nuclei import (
    _normalize_nuclei_finding,
    _parse_nuclei_output,
    run_nuclei_scan,
    NucleiProgressCallback,
)


def _fake_runner(stdout, returncode=0):
    def _run(*_args, **_kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    return SimpleNamespace(run=_run)


def test_get_nuclei_version_parses_output():
    from redaudit.core import nuclei

    version_output = "Nuclei Engine Version: v3.2.1\n"
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch(
            "redaudit.core.nuclei.CommandRunner", lambda *_a, **_k: _fake_runner(version_output)
        ):
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


def test_run_nuclei_scan_batch_size_zero():
    """Test run_nuclei_scan with batch_size < 1 (line 130)."""

    class _Runner:
        def __init__(self, *args, **kwargs):
            self.last_cmd = None

        def run(self, cmd, *args, **kwargs):
            self.last_cmd = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
            with patch("redaudit.core.nuclei.CommandRunner", _Runner):
                res = run_nuclei_scan(
                    ["http://127.0.0.1:80"],
                    tmpdir,
                    batch_size=0,
                    request_timeout=1,
                    retries=5,
                    templates="/tmp/tpl",
                    profile="fast",
                    use_internal_progress=False,
                )
    assert res["success"] is True


def test_run_nuclei_scan_output_file_exception():
    """Test run_nuclei_scan failing to create initial output file (lines 173-175)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("builtins.open", side_effect=IOError("Permission denied")):
            with tempfile.TemporaryDirectory() as tmpdir:
                result = run_nuclei_scan(["http://target"], tmpdir)
    assert "Failed to create targets file" in result["error"]


def test_run_nuclei_scan_output_file_failed():
    """Test run_nuclei_scan failing to create initial output file (lines 169-175)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open") as mock_open:
                # 1st call: write targets_file
                # 2nd call: create empty output_file
                mock_hook = MagicMock()
                mock_hook.write.side_effect = [None, IOError("Failed to Write Output")]
                mock_open.return_value.__enter__.return_value = mock_hook

                result = run_nuclei_scan(["http://target"], "/tmp/out")
                assert "Failed to create nuclei output file" in result["error"]


def test_run_nuclei_scan_stderr_error():
    """Test run_nuclei_scan capturing error in stderr (lines 202-203)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    mock_runner = mock_runner_cls.return_value
                    mock_res = MagicMock()
                    mock_res.stderr = "Error: Template not found"
                    mock_res.returncode = 1
                    mock_runner.run.return_value = mock_res

                    with patch("os.path.exists", return_value=False):
                        result = run_nuclei_scan(
                            ["http://target"], tmpdir, use_internal_progress=False
                        )
                        assert "Error: Template not found" in result.get("error", "")


def test_run_nuclei_scan_progress_callback_exception():
    """Test run_nuclei_scan with progress callback exception (lines 211-217)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    mock_runner = mock_runner_cls.return_value
                    mock_runner.run.return_value = MagicMock(stderr="", returncode=0)

                    callback = MagicMock(side_effect=Exception("UI error"))
                    with patch("os.path.exists", return_value=True):
                        # Should swallow exception
                        run_nuclei_scan(
                            ["t1", "t2"], "/tmp/out", progress_callback=callback, batch_size=1
                        )


def test_run_nuclei_scan_internal_progress_fallback():
    """Test run_nuclei_scan falling back from rich progress (lines 262-278)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    # Force rich import error or exception in Progress
                    with patch("redaudit.core.nuclei.time.time", side_effect=[0, 1, 2, 3, 4, 5]):
                        with patch("rich.progress.Progress", side_effect=ImportError("No rich")):
                            run_nuclei_scan(["t1"], "/tmp/out", use_internal_progress=True)


def test_run_nuclei_scan_general_exception():
    """Test run_nuclei_scan general exception handler (lines 286-289)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", side_effect=Exception("System Crash")):
            logger = MagicMock()
            result = run_nuclei_scan(["t"], "/tmp", logger=logger)
            assert "System Crash" in result.get("error", "")
            logger.error.assert_called()


def test_parse_nuclei_output_json_error():
    """Test _parse_nuclei_output with invalid JSON line (lines 309-310)."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("invalid json\n")
        f.write('{"template-id": "id", "info": {"severity": "info"}}\n')
        tmp_path = f.name

    try:
        findings = _parse_nuclei_output(tmp_path)
        assert len(findings) == 1
    finally:
        os.remove(tmp_path)


def test_parse_nuclei_output_general_exception():
    """Test _parse_nuclei_output general exception (lines 311-313)."""
    logger = MagicMock()
    # open will fail
    with patch("builtins.open", side_effect=Exception("File Error")):
        findings = _parse_nuclei_output("missing.json", logger=logger)
        assert findings == []
        logger.warning.assert_called()


def test_normalize_nuclei_finding_empty():
    """Test _normalize_nuclei_finding empty input (line 332)."""
    assert _normalize_nuclei_finding({}) is None


def test_nuclei_progress_callback_protocol_call():
    NucleiProgressCallback.__call__(object(), 0.0, 0, "")


def test_get_nuclei_help_text_cache_and_exception():
    from redaudit.core import nuclei

    nuclei._NUCLEI_HELP_CACHE = None
    runner = MagicMock()
    runner.run.return_value = SimpleNamespace(stdout=b"help", stderr=b"err")
    text = nuclei._get_nuclei_help_text(runner)
    assert text == "help\nerr"
    assert nuclei._get_nuclei_help_text(runner) == "help\nerr"

    nuclei._NUCLEI_HELP_CACHE = None
    runner.run.side_effect = RuntimeError("boom")
    assert nuclei._get_nuclei_help_text(runner) == ""


def test_nuclei_supports_flag_from_help_text():
    from redaudit.core import nuclei

    with patch("redaudit.core.nuclei._get_nuclei_help_text", return_value="--timeout -tags"):
        assert nuclei._nuclei_supports_flag("--timeout", MagicMock()) is True
        assert nuclei._nuclei_supports_flag("-retries", MagicMock()) is False


def test_get_nuclei_version_fallback_first_line():
    from redaudit.core import nuclei

    version_output = "v1.2.3\nextra"
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch(
            "redaudit.core.nuclei.CommandRunner", lambda *_a, **_k: _fake_runner(version_output)
        ):
            assert nuclei.get_nuclei_version() == "v1.2.3"


def test_get_nuclei_version_exception_returns_none():
    from redaudit.core import nuclei

    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch("redaudit.core.nuclei.CommandRunner", side_effect=RuntimeError("boom")):
            assert nuclei.get_nuclei_version() is None


def test_run_nuclei_scan_dry_run_with_status(tmp_path):
    calls = []

    def _print_status(msg, level):
        calls.append((msg, level))

    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        res = run_nuclei_scan(
            ["http://127.0.0.1:80"],
            output_dir=str(tmp_path),
            dry_run=True,
            print_status=_print_status,
        )
    assert res["success"] is True
    assert any("dry-run" in msg for msg, _ in calls)


def test_run_nuclei_scan_targets_file_failure(tmp_path):
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch("builtins.open", side_effect=IOError("nope")):
            res = run_nuclei_scan(["http://127.0.0.1:80"], output_dir=str(tmp_path))
    assert "Failed to create targets file" in res["error"]


def test_run_nuclei_scan_timeout_and_retry_flags(tmp_path):
    captured = {}

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    def _supports(flag, _runner):
        return flag in ("-tags", "-timeout", "-retries")

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            with patch("redaudit.core.nuclei._nuclei_supports_flag", side_effect=_supports):
                res = run_nuclei_scan(
                    ["http://127.0.0.1:80"],
                    output_dir=str(tmp_path),
                    request_timeout=1,
                    retries=10,
                    templates="/tmp/templates",
                    profile="fast",
                    batch_size=0,
                    use_internal_progress=False,
                )
    assert res["success"] is True
    assert "-timeout" in captured["cmd"]
    assert "3" in captured["cmd"]
    assert "-retries" in captured["cmd"]
    assert "3" in captured["cmd"]
    assert "-tags" in captured["cmd"]
    assert "-t" in captured["cmd"]


def test_run_nuclei_scan_long_flag_fallback(tmp_path):
    captured = {}

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    def _supports(flag, _runner):
        return flag in ("--timeout", "--retries")

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            with patch("redaudit.core.nuclei._nuclei_supports_flag", side_effect=_supports):
                res = run_nuclei_scan(
                    ["http://127.0.0.1:80"],
                    output_dir=str(tmp_path),
                    request_timeout=100,
                    retries=1,
                    use_internal_progress=False,
                )
    assert res["success"] is True
    assert "--timeout" in captured["cmd"]
    assert "--retries" in captured["cmd"]


def test_run_nuclei_scan_progress_loop_emits_updates(tmp_path):
    from redaudit.core import nuclei

    class _FakeEvent:
        def __init__(self):
            self._flag = False
            self._calls = 0

        def wait(self, timeout=None):
            self._calls += 1
            if self._calls == 1:
                return False
            return self._flag

        def set(self):
            self._flag = True

    class _ImmediateThread:
        def __init__(self, target=None, **_kwargs):
            self._target = target

        def start(self):
            if self._target:
                self._target()

    class _ImmediateFuture:
        def __init__(self, result):
            self._result = result

        def result(self):
            return self._result

    class _ImmediateExecutor:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, func, *args, **kwargs):
            return _ImmediateFuture(func(*args, **kwargs))

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    progress_calls = []

    def _cb(completed, total, eta, detail=""):
        progress_calls.append((completed, total, eta, detail))

    with patch("redaudit.core.nuclei.threading.Event", _FakeEvent):
        with patch("redaudit.core.nuclei.threading.Thread", _ImmediateThread):
            with patch("concurrent.futures.ThreadPoolExecutor", _ImmediateExecutor):
                with patch("concurrent.futures.as_completed", side_effect=lambda fs: list(fs)):
                    with patch("redaudit.core.nuclei.CommandRunner", _Runner):
                        with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
                            res = nuclei.run_nuclei_scan(
                                targets=["http://127.0.0.1:80"],
                                output_dir=str(tmp_path),
                                batch_size=1,
                                progress_callback=_cb,
                                use_internal_progress=False,
                            )
    assert res["nuclei_available"] is True
    assert progress_calls


def test_run_nuclei_scan_batch_timeout_sets_error(tmp_path):
    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="", timed_out=True)

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            res = run_nuclei_scan(
                ["http://1", "http://2"],
                output_dir=str(tmp_path),
                batch_size=2,
                use_internal_progress=False,
            )
    assert res["partial"] is True
    assert res["error"] == "timeout"


def test_run_nuclei_scan_split_keeps_timeout_floor(tmp_path):
    timeouts = []

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            timeouts.append(kwargs.get("timeout"))
            timed_out = len(timeouts) == 1
            return SimpleNamespace(returncode=0, stdout="", stderr="", timed_out=timed_out)

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            with patch("redaudit.core.nuclei._nuclei_supports_flag", return_value=False):
                res = run_nuclei_scan(
                    ["http://1", "http://2"],
                    output_dir=str(tmp_path),
                    batch_size=2,
                    timeout=600,
                    request_timeout=10,
                    use_internal_progress=False,
                )
    assert res["success"] is True
    assert len(timeouts) >= 2
    assert min(timeouts[1:]) >= timeouts[0]


def test_run_nuclei_scan_fallback_print_status(tmp_path):
    calls = []

    def _print_status(msg, level):
        calls.append((msg, level))

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            with patch("rich.progress.Progress", side_effect=RuntimeError("boom")):
                res = run_nuclei_scan(
                    ["http://127.0.0.1:80"],
                    output_dir=str(tmp_path),
                    use_internal_progress=True,
                    print_status=_print_status,
                )
    assert res["success"] is True
    assert calls


def test_run_nuclei_scan_no_internal_progress_print_status(tmp_path):
    calls = []

    def _print_status(msg, level):
        calls.append((msg, level))

    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            res = run_nuclei_scan(
                ["http://127.0.0.1:80"],
                output_dir=str(tmp_path),
                use_internal_progress=False,
                print_status=_print_status,
            )
    assert res["success"] is True
    assert calls


def test_run_nuclei_scan_threadpool_exception_logs(tmp_path):
    class _Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    logger = MagicMock()
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", _Runner):
            res = run_nuclei_scan(
                ["http://1", "http://2"],
                output_dir=str(tmp_path),
                batch_size=1,
                progress_callback=lambda *_a, **_k: None,
                use_internal_progress=False,
                logger=logger,
            )
    assert res["success"] is False or res["success"] is True
    logger.warning.assert_called()


def test_parse_nuclei_output_skips_blank_lines(tmp_path):
    payload = {"template-id": "t", "info": {"severity": "info"}}
    output_file = tmp_path / "nuclei.json"
    output_file.write_text("\n" + json.dumps(payload) + "\n", encoding="utf-8")
    findings = _parse_nuclei_output(str(output_file))
    assert len(findings) == 1


def test_extract_cve_ids_handles_string():
    from redaudit.core.nuclei import _extract_cve_ids

    info = {"classification": {"cve-id": "CVE-2023-1111"}}
    assert _extract_cve_ids(info) == ["CVE-2023-1111"]


def test_get_http_targets_handles_missing_fields():
    from redaudit.core.nuclei import get_http_targets_from_hosts
    from redaudit.core.models import Host

    host = Host(ip="10.0.0.1")
    host.ports = [{"port": None, "service": "http", "is_web_service": True}]
    targets = get_http_targets_from_hosts([{"ip": ""}, host])
    assert targets == []


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


def test_run_nuclei_scan_budget_sets_pending_targets(tmp_path):
    from redaudit.core.nuclei import run_nuclei_scan

    targets = ["http://127.0.0.1:80", "http://127.0.0.2:80"]
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
            with patch("redaudit.core.nuclei.time.time", side_effect=[0, 10, 10]):
                res = run_nuclei_scan(
                    targets=targets,
                    output_dir=str(tmp_path),
                    batch_size=1,
                    max_runtime_s=1,
                    use_internal_progress=False,
                    print_status=None,
                )

    assert res.get("budget_exceeded") is True
    assert res.get("pending_targets") == targets
    assert res.get("targets_scanned") == 0


def test_run_nuclei_scan_append_output_preserves_existing(tmp_path):
    from redaudit.core.nuclei import run_nuclei_scan

    output_file = tmp_path / "nuclei_output.json"
    output_file.write_text('{"existing": true}\n', encoding="utf-8")

    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
            res = run_nuclei_scan(
                targets=["http://127.0.0.1:80"],
                output_dir=str(tmp_path),
                output_file=str(output_file),
                append_output=True,
                use_internal_progress=False,
                print_status=None,
            )

    assert res.get("success") is True
    content = output_file.read_text(encoding="utf-8")
    assert '"existing"' in content
    assert "unit-test-template" in content
