#!/usr/bin/env python3
"""
RedAudit - Tests for updater helper functions.
"""

import hashlib
import os
import time

from redaudit.core import updater


def test_version_parsing_and_compare():
    assert updater.parse_version("1.2.3") == (1, 2, 3)
    assert updater.parse_version("bad") == (0, 0, 0)
    assert updater.compare_versions("1.0.0", "1.0.1") == -1
    assert updater.compare_versions("2.0.0", "1.9.9") == 1
    assert updater.compare_versions("1.2.3", "1.2.3") == 0


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
