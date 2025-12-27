#!/usr/bin/env python3
"""
Additional tests for constants version resolution.
"""

from pathlib import Path


def _make_fake_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    (repo_root / "redaudit" / "utils").mkdir(parents=True)
    constants_path = repo_root / "redaudit" / "utils" / "constants.py"
    constants_path.write_text("# placeholder\n", encoding="utf-8")
    return constants_path


def test_read_packaged_version_file_invalid(tmp_path, monkeypatch):
    constants_path = _make_fake_repo(tmp_path)
    version_path = constants_path.parents[1] / "VERSION"
    version_path.write_text("bad-version", encoding="utf-8")

    import redaudit.utils.constants as constants

    monkeypatch.setattr(constants, "__file__", str(constants_path))
    assert constants._read_packaged_version_file() is None


def test_read_packaged_version_file_empty(tmp_path, monkeypatch):
    constants_path = _make_fake_repo(tmp_path)
    version_path = constants_path.parents[1] / "VERSION"
    version_path.write_text("", encoding="utf-8")

    import redaudit.utils.constants as constants

    monkeypatch.setattr(constants, "__file__", str(constants_path))
    assert constants._read_packaged_version_file() is None


def test_read_packaged_version_file_accepts_letter_suffix(tmp_path, monkeypatch):
    constants_path = _make_fake_repo(tmp_path)
    version_path = constants_path.parents[1] / "VERSION"
    version_path.write_text("3.9.1a", encoding="utf-8")

    import redaudit.utils.constants as constants

    monkeypatch.setattr(constants, "__file__", str(constants_path))
    assert constants._read_packaged_version_file() == "3.9.1a"


def test_read_pyproject_version_missing(tmp_path, monkeypatch):
    constants_path = _make_fake_repo(tmp_path)

    import redaudit.utils.constants as constants

    monkeypatch.setattr(constants, "__file__", str(constants_path))
    assert constants._read_pyproject_version() is None


def test_resolve_version_falls_back_to_dev(tmp_path, monkeypatch):
    constants_path = _make_fake_repo(tmp_path)
    pyproject = constants_path.parents[2] / "pyproject.toml"
    pyproject.write_text('name = "redaudit"\n', encoding="utf-8")

    import importlib.metadata
    import redaudit.utils.constants as constants

    def _raise_version(_: str) -> str:
        raise Exception("no metadata")

    monkeypatch.setattr(importlib.metadata, "version", _raise_version)
    monkeypatch.setattr(constants, "__file__", str(constants_path))

    assert constants._resolve_version() == "0.0.0-dev"
