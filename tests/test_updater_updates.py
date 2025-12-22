#!/usr/bin/env python3
"""
Additional updater coverage for update checks and changelog fetching.
"""

import json
from urllib.error import HTTPError

from redaudit.core import updater


def test_fetch_latest_version_success(monkeypatch):
    payload = {
        "tag_name": "v9.9.9",
        "name": "Release 9.9.9",
        "body": "Notes",
        "published_at": "2025-01-01",
        "html_url": "https://example.com/release",
    }

    class _Response:
        status = 200

        def read(self):
            return json.dumps(payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(updater, "urlopen", lambda *_args, **_kwargs: _Response())
    result = updater.fetch_latest_version(logger=None)
    assert result["tag_name"] == "9.9.9"


def test_fetch_latest_version_http_error(monkeypatch):
    def _raise_http(*_args, **_kwargs):
        raise HTTPError("url", 403, "forbidden", hdrs=None, fp=None)

    monkeypatch.setattr(updater, "urlopen", _raise_http)
    assert updater.fetch_latest_version(logger=None) is None


def test_fetch_changelog_snippet_extracts_section(monkeypatch):
    changelog = "\n".join(
        [
            "# Changelog",
            "## [3.0.0] - 2024-01-01",
            "- Old",
            "## [9.9.9] - 2025-01-01",
            "- Added feature",
            "- Fixed bug",
            "## [9.9.8] - 2024-12-01",
            "- Previous",
        ]
    )

    class _Response:
        status = 200

        def read(self):
            return changelog.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(updater, "urlopen", lambda *_args, **_kwargs: _Response())
    snippet = updater.fetch_changelog_snippet("9.9.9", logger=None, lang="en")
    assert snippet is not None
    assert "Added feature" in snippet[0]


def test_check_for_updates_available(monkeypatch):
    monkeypatch.setattr(
        updater,
        "fetch_latest_version",
        lambda _logger=None: {
            "tag_name": "9.9.9",
            "body": "Release notes",
            "html_url": "https://example.com",
            "published_at": "2025-01-01",
        },
    )
    monkeypatch.setattr(updater, "fetch_changelog_snippet", lambda *_args, **_kwargs: ("Notes", "en"))

    update = updater.check_for_updates(logger=None, lang="en")
    assert update[0] is True
    assert update[1] == "9.9.9"
    assert update[2] == "Notes"


def test_check_for_updates_no_update(monkeypatch):
    monkeypatch.setattr(
        updater,
        "fetch_latest_version",
        lambda _logger=None: {
            "tag_name": updater.VERSION,
            "body": "Release notes",
            "html_url": "https://example.com",
            "published_at": "2025-01-01",
        },
    )
    update = updater.check_for_updates(logger=None, lang="en")
    assert update[0] is False
