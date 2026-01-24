#!/usr/bin/env python3
"""
RedAudit - Tests for updater helper functions.
"""

import hashlib
import os
import time
from unittest.mock import patch

from redaudit.core import updater


def test_version_parsing_and_compare():
    # Now returns 4-tuple: (major, minor, patch, suffix)
    assert updater.parse_version("1.2.3") == (1, 2, 3, "")
    assert updater.parse_version("1.2.3a") == (1, 2, 3, "a")
    assert updater.parse_version("1.2.3b") == (1, 2, 3, "b")
    assert updater.parse_version("bad") == (0, 0, 0, "")

    # Basic version comparison
    assert updater.compare_versions("1.0.0", "1.0.1") == -1
    assert updater.compare_versions("2.0.0", "1.9.9") == 1
    assert updater.compare_versions("1.2.3", "1.2.3") == 0

    # Letter suffix comparison (3.9.5a > 3.9.5)
    assert updater.compare_versions("3.9.5", "3.9.5a") == -1  # 3.9.5 < 3.9.5a
    assert updater.compare_versions("3.9.5a", "3.9.5") == 1  # 3.9.5a > 3.9.5
    assert updater.compare_versions("3.9.5a", "3.9.5a") == 0
    assert updater.compare_versions("3.9.5a", "3.9.5b") == -1  # a < b


def test_release_dates_and_type():
    assert updater._parse_published_date("2025-01-02T00:00:00Z") == "2025-01-02"
    assert updater._parse_published_date("") is None

    notes = "## [1.2.3] - 2025-02-01\n- Added x"
    assert updater._extract_release_date_from_notes(notes, "1.2.3") == "2025-02-01"

    assert updater._classify_release_type("1.2.3", "2.0.0") == "Major"
    assert updater._classify_release_type("1.2.3", "1.3.0") == "Minor"
    assert updater._classify_release_type("1.2.3", "1.2.4") == "Patch"


def test_extract_release_items_and_strip_markdown():
    notes = """
## Added
- New feature
## Breaking Changes
- This breaks
## Fixed
- Bug fix
"""
    extracted = updater._extract_release_items(notes)
    assert "New feature" in extracted["highlights"]
    assert "Bug fix" in extracted["highlights"]
    assert extracted["breaking"] == ["This breaks"]

    stripped = updater._strip_markdown_inline("**Bold** [Link](https://example.com)")
    assert stripped == "Bold Link"


def test_format_release_notes_for_cli_and_summary():
    notes = "## Added\n- Feature A\n- Feature B\n"
    formatted = updater.format_release_notes_for_cli(notes, width=60, max_lines=10)
    assert "Feature A" in formatted

    def _t(key, *args):
        return f"{key}:{','.join(str(a) for a in args)}" if args else key

    summary = updater.render_update_summary_for_cli(
        current_version="1.0.0",
        latest_version="1.1.0",
        release_notes=notes,
        release_url="https://example.com",
        published_at="2025-01-02T00:00:00Z",
        lang="en",
        t_fn=_t,
        notes_lang="en",
        max_items=2,
        max_breaking=1,
    )
    assert "update_release_date:2025-01-02" in summary
    assert "update_release_type:Minor" in summary
    assert "update_release_url:https://example.com" in summary


def test_compute_file_hash_and_iter_files(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("hello", encoding="utf-8")
    expected = hashlib.sha256(b"hello").hexdigest()

    assert updater.compute_file_hash(str(target)) == expected

    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "skip.pyc").write_bytes(b"")

    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "file.txt").write_text("data", encoding="utf-8")

    rel_paths = updater._iter_files(str(tmp_path))
    assert "sample.txt" in rel_paths
    assert os.path.join("nested", "file.txt") in rel_paths
    assert os.path.join("__pycache__", "skip.pyc") not in rel_paths


def test_inject_default_lang_updates_and_appends(tmp_path):
    constants = tmp_path / "constants.py"
    constants.write_text('DEFAULT_LANG = "en"\n', encoding="utf-8")

    assert updater._inject_default_lang(str(constants), "es") is True
    assert 'DEFAULT_LANG = "es"' in constants.read_text(encoding="utf-8")

    constants.write_text("OTHER = 1\n", encoding="utf-8")
    assert updater._inject_default_lang(str(constants), "en") is True
    assert 'DEFAULT_LANG = "en"' in constants.read_text(encoding="utf-8")


def test_restart_terminal_notice_and_pause(monkeypatch, capsys):
    def _t(key, *args):
        return f"{key}:{','.join(str(a) for a in args)}" if args else key

    monkeypatch.setattr(updater, "_suggest_restart_command", lambda: "exec $SHELL -l")
    monkeypatch.setattr(updater.sys.stdout, "isatty", lambda: True)
    updater._show_restart_terminal_notice(t_fn=_t, lang="en")
    output = capsys.readouterr().out
    assert "update_restart_terminal_title" in output
    assert "exec $SHELL -l" in output

    monkeypatch.setattr(updater.sys.stdin, "isatty", lambda: False)
    called = {}

    def _fake_sleep(value):
        called["sleep"] = value

    monkeypatch.setattr(time, "sleep", _fake_sleep)
    updater._pause_for_restart_terminal(t_fn=_t)
    assert called["sleep"] == 1.0


def test_pause_for_restart_terminal_tty(monkeypatch):
    monkeypatch.setattr(updater.sys.stdin, "isatty", lambda: True)
    called = {}

    def _fake_input(_prompt):
        called["input"] = True
        return ""

    monkeypatch.setattr("builtins.input", _fake_input)
    updater._pause_for_restart_terminal(t_fn=lambda key: key)
    assert called["input"] is True


class _SyncRunner:
    def __init__(self, branch="main", dirty=False, status_error=False):
        self.branch = branch
        self.dirty = dirty
        self.status_error = status_error

    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/dorinbadea/RedAudit\n"
        if cmd[:3] == ["git", "status", "--porcelain"]:
            if self.status_error:
                raise RuntimeError("status fail")
            return " M file\n" if self.dirty else ""
        if cmd[:2] == ["git", "fetch"]:
            return ""
        if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"]:
            return f"{self.branch}\n"
        if cmd[:2] == ["git", "pull"]:
            return ""
        raise AssertionError(f"Unexpected command: {cmd}")


def test_maybe_sync_local_repo_main_branch(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    messages = []

    def _t(key, *args):
        return f"{key}:{','.join(args)}" if args else key

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_SyncRunner(branch="main"),
        print_fn=lambda msg, *_a: messages.append(msg),
        t_fn=_t,
    )
    assert any("update_repo_sync_ok" in msg for msg in messages)


def test_maybe_sync_local_repo_branch_skip(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    messages = []

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_SyncRunner(branch="feature"),
        print_fn=lambda msg, *_a: messages.append(msg),
        t_fn=lambda key, *args: f"{key}:{','.join(args)}" if args else key,
    )
    assert any("update_repo_sync_branch_skip" in msg for msg in messages)


def test_maybe_sync_local_repo_dirty_skips(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    messages = []

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_SyncRunner(branch="main", dirty=True),
        print_fn=lambda msg, *_a: messages.append(msg),
        t_fn=lambda key, *args: f"{key}:{','.join(args)}" if args else key,
    )
    assert any("update_repo_sync_skip_dirty" in msg for msg in messages)


def test_maybe_sync_local_repo_status_error_logs(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    logger = type("Logger", (), {"debug": lambda *args, **_k: None})()

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_SyncRunner(status_error=True),
        print_fn=lambda *_a, **_k: None,
        t_fn=lambda key, *args: key,
        logger=logger,
    )


def test_maybe_sync_local_repo_empty_cwd():
    updater._maybe_sync_local_repo(
        cwd_path="",
        home_redaudit_path="/tmp",
        target_ref="v1.2.3",
        runner=_SyncRunner(),
        print_fn=lambda *_a, **_k: None,
        t_fn=lambda key, *args: key,
    )


class _FetchFailRunner(_SyncRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:2] == ["git", "fetch"]:
            raise RuntimeError("fetch fail")
        return super().check_output(args, **_kwargs)


def test_maybe_sync_local_repo_fetch_failure(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    messages = []

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_FetchFailRunner(branch="main"),
        print_fn=lambda msg, *_a: messages.append(msg),
        t_fn=lambda key, *args: f"{key}:{','.join(args)}" if args else key,
    )
    assert any("update_repo_sync_fetch_failed" in msg for msg in messages)


class _PullFailRunner(_SyncRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:2] == ["git", "pull"]:
            raise RuntimeError("pull fail")
        return super().check_output(args, **_kwargs)


def test_maybe_sync_local_repo_pull_failure(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()
    messages = []

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_PullFailRunner(branch="main"),
        print_fn=lambda msg, *_a: messages.append(msg),
        t_fn=lambda key, *args: f"{key}:{','.join(args)}" if args else key,
    )
    assert any("update_repo_sync_pull_failed" in msg for msg in messages)


def test_maybe_sync_local_repo_branch_lookup_error(tmp_path):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    (cwd / ".git").mkdir(parents=True)
    home.mkdir()

    class _BranchFailRunner(_SyncRunner):
        def check_output(self, args, **_kwargs):
            cmd = list(args)
            if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"]:
                raise RuntimeError("branch fail")
            return super().check_output(args, **_kwargs)

    updater._maybe_sync_local_repo(
        cwd_path=str(cwd),
        home_redaudit_path=str(home),
        target_ref="v1.2.3",
        runner=_BranchFailRunner(branch="main"),
        print_fn=lambda *_a, **_k: None,
        t_fn=lambda key, *args: key,
    )


def test_render_update_summary_width_fallback_and_lang_es():
    notes = "## Added\n- Something\n"

    with patch("shutil.get_terminal_size", side_effect=OSError("no tty")):
        res = updater.render_update_summary_for_cli(
            current_version="1.0.0",
            latest_version="1.0.1",
            release_notes=notes,
            release_url=None,
            published_at=None,
            lang="en",
            notes_lang="es",
            t_fn=lambda key, *args: key,
        )
    assert "update_notes_fallback_es" in res


def test_render_update_summary_terminal_exception():
    notes = "## Added\n- Something\n"
    with (
        patch.object(updater.sys.stdout, "isatty", lambda: True),
        patch("shutil.get_terminal_size", side_effect=OSError("no tty")),
    ):
        res = updater.render_update_summary_for_cli(
            current_version="1.0.0",
            latest_version="1.0.1",
            release_notes=notes,
            release_url=None,
            published_at=None,
            lang="en",
            notes_lang="en",
            t_fn=lambda key, *args: key,
        )
    assert "update_release_type" in res


def test_format_release_notes_empty_and_width_fallback():
    assert updater.format_release_notes_for_cli("") == ""
    with patch("shutil.get_terminal_size", side_effect=OSError("no tty")):
        res = updater.format_release_notes_for_cli("## Added\n- Item\n", width=10)
    assert "Added" in res


def test_format_release_notes_spanish_heading_and_trim():
    notes = "\n\n## Cambiado\n- Ajuste\n\n"
    result = updater.format_release_notes_for_cli(notes, width=80)
    assert "Cambiado:" in result


def test_format_release_notes_only_noise_returns_empty():
    notes = "[![badge](url)](url)\n---\n"
    assert updater.format_release_notes_for_cli(notes) == ""


def test_restart_self_empty_argv():
    with patch.object(updater.sys, "argv", []):
        assert updater.restart_self(logger=None) is False


def test_compute_tree_diff_handles_compare_error(tmp_path):
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    (old_dir / "file.txt").write_text("a", encoding="utf-8")
    (new_dir / "file.txt").write_text("b", encoding="utf-8")
    with patch("os.path.getsize", side_effect=OSError("boom")):
        diff = updater.compute_tree_diff(str(old_dir), str(new_dir))
    assert "file.txt" in diff["modified"]


def test_iter_files_skips_pyc_outside_cache(tmp_path):
    (tmp_path / "skip.pyc").write_bytes(b"")
    (tmp_path / "keep.txt").write_text("ok", encoding="utf-8")
    rel_paths = updater._iter_files(str(tmp_path))
    assert "keep.txt" in rel_paths
    assert "skip.pyc" not in rel_paths


def test_ensure_version_file_prints_and_logger(tmp_path):
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    version_path = package_dir / "VERSION"
    version_path.write_text("1.0.0\n", encoding="utf-8")
    logs = []

    class _Logger:
        def warning(self, *_a):
            logs.append("warn")

    messages = []
    ok = updater._ensure_version_file(
        str(package_dir),
        "1.0.1",
        print_fn=lambda msg, *_a: messages.append(msg),
        logger=_Logger(),
    )
    assert ok is True
    assert messages
    assert logs


def test_ensure_version_file_write_error(tmp_path):
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    logger = type("Logger", (), {"warning": lambda *args, **_k: None})()

    with patch("pathlib.Path.write_text", side_effect=OSError("boom")):
        ok = updater._ensure_version_file(str(package_dir), "1.0.1", logger=logger)
    assert ok is False


def test_perform_git_update_requires_root_for_system_install(tmp_path):
    class _Runner:
        def __init__(self, **_kwargs):
            return None

    with (
        patch.object(updater, "CommandRunner", _Runner),
        patch.object(updater, "is_dry_run", return_value=False),
        patch.object(updater.os, "geteuid", return_value=1000),
        patch.object(updater.sys, "argv", ["redaudit"]),
        patch("shutil.which", return_value="/usr/local/bin/redaudit"),
    ):
        ok, msg = updater.perform_git_update(
            repo_path=str(tmp_path),
            lang="en",
            t_fn=lambda key, *args: key,
        )
    assert ok is False
    assert "update_requires_root_install" in msg


def test_perform_git_update_sudo_lookup_failure(tmp_path):
    class _Runner:
        def __init__(self, **_kwargs):
            return None

    with (
        patch.dict(os.environ, {"SUDO_USER": "ghost"}),
        patch.object(updater, "CommandRunner", _Runner),
        patch.object(updater, "is_dry_run", return_value=True),
        patch.object(updater.os, "geteuid", return_value=0),
        patch("pwd.getpwnam", side_effect=KeyError("missing")),
    ):
        ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")
    assert ok is True
    assert "Dry-run" in msg


def test_show_restart_terminal_notice_fallback_and_print_error():
    with (
        patch.object(updater, "_suggest_restart_command", return_value="exec $SHELL -l"),
        patch.object(updater.sys.stdout, "isatty", return_value=False),
        patch("shutil.get_terminal_size", side_effect=OSError("fail")),
        patch("builtins.print", side_effect=RuntimeError("print fail")),
    ):
        updater._show_restart_terminal_notice(t_fn=lambda key, *args: key, lang="en")


def test_pause_for_restart_terminal_exception(monkeypatch):
    def _raise():
        raise RuntimeError("boom")

    monkeypatch.setattr(updater.sys.stdin, "isatty", _raise)
    updater._pause_for_restart_terminal(t_fn=lambda key: key)
