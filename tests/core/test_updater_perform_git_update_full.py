#!/usr/bin/env python3
"""
Coverage for perform_git_update success path without system install.
"""

from __future__ import annotations

import os
import shutil
from unittest.mock import MagicMock
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


class _DirtyHomeRunner(_DummyRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return " M core.py\n"
        return super().check_output(args, **_kwargs)


class _StatusErrorRunner(_DummyRunner):
    def check_output(self, args, **_kwargs):
        cmd = list(args)
        if cmd[:3] == ["git", "status", "--porcelain"]:
            raise RuntimeError("status failed")
        return super().check_output(args, **_kwargs)


class _SeederFailRunner(_DummyRunner):
    def run(self, *_args, **_kwargs):
        raise RuntimeError("seeder failed")


def _setup_root_update(monkeypatch, tmp_path, runner_cls):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", runner_cls)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(
        updater, "compute_tree_diff", lambda *_a, **_k: {"added": [], "modified": [], "removed": []}
    )
    monkeypatch.setattr(updater.os, "walk", lambda *_a, **_k: [("/tmp", ["d1"], ["f1"])])
    monkeypatch.setattr(updater.os, "chmod", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    return home_dir, temp_root


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


def test_perform_git_update_clone_timeout(tmp_path, monkeypatch):
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    class _HangPopen:
        def __init__(self, *_args, **_kwargs):
            self._returncode = 0
            self.stdout = self

        def readline(self):
            return ""

        def poll(self):
            return None

        def wait(self):
            return self._returncode

        def kill(self):
            self._returncode = 1

    times = iter([0.0, 121.0, 121.0])

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _HangPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setattr("time.time", lambda: next(times))
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "timed out" in msg.lower()


def test_perform_git_update_system_swap_failure(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

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
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(
        updater, "compute_tree_diff", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(updater.os, "walk", lambda *_a, **_k: [("/tmp", ["d1"], ["f1"])])
    monkeypatch.setattr(updater.os, "chmod", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr(
        updater.os, "rename", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("swap"))
    )

    install_path = "/usr/local/lib/redaudit"

    def _isdir(_path):
        return True

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        return True

    def _exists(path):
        if path.endswith(".old"):
            return True
        if path == install_path:
            return False
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en", logger=MagicMock())

    assert ok is False
    assert "System install swap failed" in msg


def test_perform_git_update_home_copy_verification_failure(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "testuser")
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(updater.os, "walk", lambda *_a, **_k: [("/tmp", ["d1"], ["f1"])])
    monkeypatch.setattr(updater.os, "chmod", lambda *_a, **_k: None)
    monkeypatch.setattr(
        updater.os, "chown", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr("time.time", lambda: 123)

    dummy_user = type("Dummy", (), {"pw_dir": str(home_dir), "pw_uid": 1000, "pw_gid": 1000})
    monkeypatch.setattr("pwd.getpwnam", lambda _u: dummy_user)

    install_path = "/usr/local/lib/redaudit"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    backup_path = f"{home_redaudit_path}_backup_123"

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return False
        return False

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path == os.path.join(staged_home_path, "redaudit", "__init__.py"):
            return True
        if path.startswith(f"{install_path}.new{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}") and path.endswith("core/auditor.py"):
            return False
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        if path.startswith(f"{home_redaudit_path}{os.sep}"):
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        return False

    def _exists(path):
        if path == home_redaudit_path:
            return True
        if path == backup_path:
            return True
        if path.endswith(".old"):
            return True
        if path == install_path:
            return True
        if path == staged_home_path:
            return False
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en", logger=MagicMock())

    assert ok is False
    assert "verification failed" in msg.lower()


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


def test_perform_git_update_dirty_home_repo_backed_up_when_system_updated(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    red_repo = home_dir / "RedAudit"
    (red_repo / ".git").mkdir(parents=True)
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"
    source_module = clone_path / "redaudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    staged_home_path = f"{red_repo}.new"

    class _DirtyHomeRunner(_DummyRunner):
        def check_output(self, args, **kwargs):
            cmd = list(args)
            if cmd[:3] == ["git", "status", "--porcelain"]:
                if kwargs.get("cwd") == str(red_repo):
                    return " M core.py\n"
                return ""
            return super().check_output(args, **kwargs)

    messages = []

    def _capture(msg, _status=None):
        messages.append(msg)

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DirtyHomeRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "testuser")
    dummy_user = type("Dummy", (), {"pw_dir": str(home_dir), "pw_uid": 1000, "pw_gid": 1000})
    monkeypatch.setattr("pwd.getpwnam", lambda _u: dummy_user)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(
        updater,
        "compute_tree_diff",
        lambda *_a, **_k: {"added": [], "modified": [], "removed": []},
    )
    monkeypatch.setattr(updater, "_maybe_sync_local_repo", lambda **_k: None)
    monkeypatch.setattr(updater.os, "walk", lambda *_a, **_k: [("/tmp", [], [])])
    monkeypatch.setattr(updater.os, "chmod", lambda *_a, **_k: None)
    monkeypatch.setattr(updater.os, "chown", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)

    def _isdir(path):
        if path in (
            str(clone_path),
            str(source_module),
            str(red_repo),
            str(red_repo / ".git"),
            install_path,
        ):
            return True
        return False

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        return True

    def _exists(path):
        if path in (str(red_repo), install_path, staged_install_path, staged_home_path):
            return True
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path),
        lang="en",
        print_fn=_capture,
        t_fn=lambda key, *_args: key,
    )

    assert ok is True, msg
    assert any("update_home_changes_detected_backup" in m for m in messages)


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


def test_perform_git_update_dirty_home_repo_backed_up_after_system_update(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _DirtyHomeRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    old_install_path = f"{install_path}.old"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path):
            return True
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return True
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{home_redaudit_path}.new{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path in {staged_install_path, old_install_path}:
            return False
        if path == install_path:
            return False
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(updater, "_maybe_sync_local_repo", lambda **_k: None)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is True, msg
    assert msg == "UPDATE_SUCCESS_RESTART"


def test_perform_git_update_status_check_exception_backed_up(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _StatusErrorRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    old_install_path = f"{install_path}.old"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path):
            return True
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return True
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{home_redaudit_path}.new{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path in {staged_install_path, old_install_path}:
            return False
        if path == install_path:
            return False
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(updater, "_maybe_sync_local_repo", lambda **_k: None)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is True, msg
    assert msg == "UPDATE_SUCCESS_RESTART"


def test_perform_git_update_staged_home_copy_missing_key_files(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    staged_key_file = os.path.join(staged_home_path, "redaudit", "__init__.py")

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        return orig_isdir(path)

    def _isfile(path):
        if path == staged_key_file:
            return False
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        return orig_isfile(path)

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "Staged home copy missing key files" in msg


def test_perform_git_update_home_swap_failure_rolls_back(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr("time.time", lambda: 123)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    backup_path = f"{home_redaudit_path}_backup_123"
    staged_key_file = os.path.join(staged_home_path, "redaudit", "__init__.py")

    state = {"home_exists": True, "backup_exists": False}

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path == staged_key_file:
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path == home_redaudit_path:
            return state["home_exists"]
        if path == backup_path:
            return state["backup_exists"]
        return False

    def _rename(src, dst):
        if src == home_redaudit_path and dst == backup_path:
            state["home_exists"] = False
            state["backup_exists"] = True
            return None
        if src == staged_home_path and dst == home_redaudit_path:
            raise RuntimeError("swap failed")
        if src == backup_path and dst == home_redaudit_path:
            state["home_exists"] = True
            return None
        return None

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(updater.os, "rename", _rename)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "Home folder swap failed" in msg


def test_perform_git_update_chown_failure_logs_warning(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _DummyRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"

    monkeypatch.setenv("SUDO_USER", "testuser")
    dummy_user = type("Dummy", (), {"pw_dir": str(home_dir), "pw_uid": 1000, "pw_gid": 1000})
    monkeypatch.setattr("pwd.getpwnam", lambda _u: dummy_user)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(
        updater.os, "chown", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("chown"))
    )

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)

    logger = MagicMock()
    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=logger, print_fn=lambda *_a, **_k: None
    )

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"
    assert logger.warning.called


def test_perform_git_update_verification_failure_rolls_back(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _DummyRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    old_install_path = f"{install_path}.old"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    backup_path = f"{home_redaudit_path}_backup_123"

    monkeypatch.setattr("time.time", lambda: 123)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(updater, "_maybe_sync_local_repo", lambda **_k: None)

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return False
        if path == home_redaudit_path:
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path in {home_redaudit_path, backup_path, old_install_path, install_path}:
            return True
        return False

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "Installation verification failed" in msg


def test_perform_git_update_home_swap_failure_backup_restore_exception(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    clone_path = temp_root / "RedAudit"

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(updater, "_ensure_version_file", lambda *_a, **_k: True)
    monkeypatch.setattr(updater, "_inject_default_lang", lambda *_a, **_k: True)
    monkeypatch.setattr(shutil, "copytree", lambda *_a, **_k: None)
    monkeypatch.setattr(shutil, "rmtree", lambda *_a, **_k: None)
    monkeypatch.setattr("time.time", lambda: 123)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    backup_path = f"{home_redaudit_path}_backup_123"
    staged_key_file = os.path.join(staged_home_path, "redaudit", "__init__.py")

    state = {"home_exists": True, "backup_exists": False}

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path == staged_key_file:
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path == home_redaudit_path:
            return state["home_exists"]
        if path == backup_path:
            return state["backup_exists"]
        return False

    def _rename(src, dst):
        if src == home_redaudit_path and dst == backup_path:
            state["home_exists"] = False
            state["backup_exists"] = True
            return None
        if src == staged_home_path and dst == home_redaudit_path:
            raise RuntimeError("swap failed")
        if src == backup_path and dst == home_redaudit_path:
            raise RuntimeError("restore failed")
        return None

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(updater.os, "rename", _rename)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "Home folder swap failed" in msg


def test_perform_git_update_chown_dirs_and_files(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _DummyRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"

    monkeypatch.setenv("SUDO_USER", "testuser")
    dummy_user = type("Dummy", (), {"pw_dir": str(home_dir), "pw_uid": 1000, "pw_gid": 1000})
    monkeypatch.setattr("pwd.getpwnam", lambda _u: dummy_user)
    monkeypatch.setattr(updater.os, "rename", lambda *_a, **_k: None)
    monkeypatch.setattr(updater.os, "chown", lambda *_a, **_k: None)

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        return orig_isfile(path)

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", lambda *_a, **_k: False)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"


def test_perform_git_update_verification_missing_key_file_rolls_back(tmp_path, monkeypatch):
    home_dir, temp_root = _setup_root_update(monkeypatch, tmp_path, _DummyRunner)
    clone_path = temp_root / "RedAudit"
    install_path = "/usr/local/lib/redaudit"
    staged_install_path = f"{install_path}.new"
    old_install_path = f"{install_path}.old"
    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    staged_home_path = f"{home_redaudit_path}.new"
    backup_path = f"{home_redaudit_path}_backup_123"

    monkeypatch.setattr("time.time", lambda: 123)
    monkeypatch.setattr(updater, "_maybe_sync_local_repo", lambda **_k: None)

    orig_isdir = updater.os.path.isdir
    orig_isfile = updater.os.path.isfile

    def _isdir(path):
        if path == str(clone_path / "redaudit"):
            return True
        if path == install_path:
            return True
        if path == home_redaudit_path:
            return True
        if path == os.path.join(home_redaudit_path, ".git"):
            return False
        return orig_isdir(path)

    def _isfile(path):
        if path.endswith("core/auditor.py") and path.startswith(f"{install_path}{os.sep}"):
            return False
        if path.endswith("redaudit_install.sh"):
            return True
        if path.startswith(f"{staged_install_path}{os.sep}"):
            return True
        if path.startswith(f"{staged_home_path}{os.sep}"):
            return True
        if path.startswith(f"{install_path}{os.sep}"):
            return True
        return orig_isfile(path)

    def _exists(path):
        if path in {home_redaudit_path, backup_path, old_install_path, install_path}:
            return True
        return False

    def _rename(src, dst):
        if src in {old_install_path, backup_path}:
            raise RuntimeError("rollback failed")
        return None

    monkeypatch.setattr(updater.os.path, "isdir", _isdir)
    monkeypatch.setattr(updater.os.path, "isfile", _isfile)
    monkeypatch.setattr(updater.os.path, "exists", _exists)
    monkeypatch.setattr(updater.os, "rename", _rename)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is False
    assert "Installation verification failed" in msg


def test_perform_git_update_keyring_seed_success(tmp_path, monkeypatch):
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

    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    seeder_script = os.path.join(home_redaudit_path, "scripts", "seed_keyring.py")

    orig_isfile = updater.os.path.isfile

    def _isfile(path):
        if path == seeder_script:
            return True
        return orig_isfile(path)

    monkeypatch.setattr(updater.os.path, "isfile", _isfile)

    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=MagicMock(), print_fn=lambda *_a, **_k: None
    )

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"


def test_perform_git_update_keyring_seed_failure_logs_debug(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _SeederFailRunner)
    monkeypatch.setattr(updater.subprocess, "Popen", _DummyPopen)
    monkeypatch.setattr(updater.tempfile, "mkdtemp", lambda **_k: str(temp_root))
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        updater.os.path,
        "expanduser",
        lambda path: str(home_dir) if path == "~" else os.path.expanduser(path),
    )

    home_redaudit_path = os.path.join(str(home_dir), "RedAudit")
    seeder_script = os.path.join(home_redaudit_path, "scripts", "seed_keyring.py")

    orig_isfile = updater.os.path.isfile

    def _isfile(path):
        if path == seeder_script:
            return True
        return orig_isfile(path)

    monkeypatch.setattr(updater.os.path, "isfile", _isfile)

    logger = MagicMock()
    ok, msg = updater.perform_git_update(
        repo_path=str(tmp_path), lang="en", logger=logger, print_fn=lambda *_a, **_k: None
    )

    assert ok is True
    assert msg == "UPDATE_SUCCESS_RESTART"
    assert logger.debug.called


def test_perform_git_update_timeout_error(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)

    def _raise_timeout(**_kwargs):
        raise subprocess.TimeoutExpired(cmd="mkdtemp", timeout=1)

    monkeypatch.setattr(updater.tempfile, "mkdtemp", _raise_timeout)

    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en")

    assert ok is False
    assert "timed out" in msg.lower()


def test_perform_git_update_unexpected_error_logs(tmp_path, monkeypatch):
    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)

    def _raise_error(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(updater.tempfile, "mkdtemp", _raise_error)

    logger = MagicMock()
    ok, msg = updater.perform_git_update(repo_path=str(tmp_path), lang="en", logger=logger)

    assert ok is False
    assert "Update failed" in msg
    assert logger.error.called
