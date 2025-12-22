#!/usr/bin/env python3
"""
Coverage for perform_git_update success path without system install.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

from redaudit.core import updater


class _DummyRunner:
    def __init__(self, **_kwargs):
        return None

    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:2] == ["git", "ls-remote"]:
            ref = cmd[-1]
            if ref.endswith("^{}"):
                return "deadbeef\trefs/tags/v3.8.4^{}\n"
            return "deadbeef\trefs/tags/v3.8.4\n"
        if cmd[:2] == ["git", "rev-parse"]:
            return "deadbeef\n"
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return ""
        raise AssertionError(f"Unexpected command: {cmd}")

    def run(self, *_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class _DummyPopen:
    def __init__(self, args, **_kwargs):
        self._args = args
        self._returncode = 0
        self._done = False
        self._lines = iter(
            [
                "Cloning into 'RedAudit'...\n",
                "Receiving objects: 100% (1/1), done.\n",
                "Resolving deltas: 100% (1/1), done.\n",
            ]
        )
        self.stdout = self
        clone_path = args[-1]
        os.makedirs(os.path.join(clone_path, "redaudit", "core"), exist_ok=True)
        os.makedirs(os.path.join(clone_path, "redaudit", "utils"), exist_ok=True)
        with open(os.path.join(clone_path, "redaudit", "__init__.py"), "w", encoding="utf-8"):
            pass
        with open(os.path.join(clone_path, "redaudit", "cli.py"), "w", encoding="utf-8"):
            pass
        with open(
            os.path.join(clone_path, "redaudit", "core", "auditor.py"),
            "w",
            encoding="utf-8",
        ):
            pass
        with open(
            os.path.join(clone_path, "redaudit", "utils", "constants.py"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write('DEFAULT_LANG = "en"\n')
        with open(os.path.join(clone_path, "redaudit_install.sh"), "w", encoding="utf-8"):
            pass

    def readline(self):
        try:
            return next(self._lines)
        except StopIteration:
            self._done = True
            return ""

    def poll(self):
        return self._returncode if self._done else None

    def wait(self):
        return self._returncode

    def kill(self):
        self._returncode = 1


class _FallbackRunner(_DummyRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:2] == ["git", "ls-remote"] and cmd[-1].endswith("^{}"):
            return ""
        return super().check_output(args, **_kwargs)


class _MismatchRunner(_DummyRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:2] == ["git", "rev-parse"]:
            return "badc0de\n"
        return super().check_output(args, **_kwargs)


class _FailingPopen:
    def __init__(self, *_args, **_kwargs):
        self._returncode = 1
        self._done = True
        self.stdout = self

    def readline(self):
        return ""

    def poll(self):
        return self._returncode

    def wait(self):
        return self._returncode

    def kill(self):
        self._returncode = 1


class _InstallFailRunner(_DummyRunner):
    def run(self, *_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")


def test_perform_git_update_non_root_success(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"
    assert (home_dir / "RedAudit" / "redaudit" / "__init__.py").exists()


def test_perform_git_update_fallback_tag_resolution(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _FallbackRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"


def test_perform_git_update_clone_failure(tmp_path, monkeypatch):
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _FailingPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is False
    assert "Git clone failed" in msg


def test_perform_git_update_clone_mismatch(tmp_path, monkeypatch):
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _MismatchRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is False
    assert "Clone verification failed" in msg


def test_perform_git_update_aborts_on_dirty_home_repo(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    red_repo = home_dir / "RedAudit"
    (red_repo / ".git").mkdir(parents=True)
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    class _DirtyRunner(_DummyRunner):
        def check_output(self, args, **_kwargs):
            cmd = list(args)
            if cmd[:3] == ["git", "status", "--porcelain"]:
                return " M core.py\n"
            return super().check_output(args, **_kwargs)

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DirtyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is False
    assert "update_home_changes_detected_abort" in msg


def test_perform_git_update_dry_run_uses_sudo_user(monkeypatch, tmp_path):
    called = {"pwd": False}

    class _PwdEntry:
        pw_dir = str(tmp_path / "root_home")
        pw_uid = 1000
        pw_gid = 1000

    def _fake_getpwnam(_name):
        called["pwd"] = True
        return _PwdEntry()

    monkeypatch.setenv("SUDO_USER", "root")
    monkeypatch.setenv("REDAUDIT_DRY_RUN", "1")
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    import pwd

    monkeypatch.setattr(pwd, "getpwnam", _fake_getpwnam)

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert called["pwd"] is True
    assert ok is True
    assert "Dry-run" in msg


def test_perform_git_update_install_script_failure(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _InstallFailRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile
    install_path = "/usr/local/lib/redaudit"

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return False
        if path == install_path:
            return True
        return orig_isdir(path)

    def _isfile(path):
        if path.startswith(install_path):
            return True
        return orig_isfile(path)

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"
