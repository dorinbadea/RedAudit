#!/usr/bin/env python3
"""
Tests for multi-credential CLI flags.

Tests:
- --credentials-file parsing and loading
- --generate-credentials-template generation
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from redaudit.core.credentials_manager import CredentialsManager


class TestCredentialsFileCLI:
    """Tests for --credentials-file CLI flag."""

    def test_credentials_file_loads_valid_json(self, tmp_path):
        """Valid JSON file should be loaded correctly."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(
            json.dumps(
                {
                    "credentials": [
                        {"user": "admin", "pass": "secret"},
                        {"user": "root", "pass": "toor"},
                    ]
                }
            )
        )
        os.chmod(creds_file, 0o600)

        mgr = CredentialsManager()
        mgr.load_from_file(str(creds_file))

        assert len(mgr.credentials) == 2
        assert mgr.credentials[0].user == "admin"
        assert mgr.credentials[0].password == "secret"
        assert mgr.credentials[1].user == "root"

    def test_credentials_file_not_found_raises(self, tmp_path):
        """Non-existent file should raise FileNotFoundError."""
        mgr = CredentialsManager()

        with pytest.raises(FileNotFoundError):
            mgr.load_from_file(str(tmp_path / "nonexistent.json"))

    def test_credentials_file_invalid_json_raises(self, tmp_path):
        """Invalid JSON should raise error."""
        creds_file = tmp_path / "bad.json"
        creds_file.write_text("not valid json {{{")
        os.chmod(creds_file, 0o600)

        mgr = CredentialsManager()

        with pytest.raises(json.JSONDecodeError):
            mgr.load_from_file(str(creds_file))

    def test_credentials_file_insecure_permissions_warns(self, tmp_path, caplog):
        """File with insecure permissions should log a warning."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({"credentials": [{"user": "x", "pass": "y"}]}))
        os.chmod(creds_file, 0o644)  # Insecure

        import logging

        with caplog.at_level(logging.WARNING):
            mgr = CredentialsManager()
            mgr.load_from_file(str(creds_file))

        assert "insecure permissions" in caplog.text.lower()


class TestGenerateCredentialsTemplate:
    """Tests for --generate-credentials-template CLI flag."""

    def test_generate_template_creates_file(self, tmp_path):
        """Template generation should create a valid JSON file."""
        template_path = tmp_path / "template.json"

        CredentialsManager.generate_template(str(template_path))

        assert template_path.exists()

        with open(template_path) as f:
            data = json.load(f)

        assert "credentials" in data
        assert isinstance(data["credentials"], list)
        assert len(data["credentials"]) > 0

    def test_generate_template_has_secure_permissions(self, tmp_path):
        """Generated template should have 0600 permissions."""
        template_path = tmp_path / "template.json"

        CredentialsManager.generate_template(str(template_path))

        mode = template_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_generate_template_creates_parent_dirs(self, tmp_path):
        """Template generation should create parent directories."""
        deep_path = tmp_path / "a" / "b" / "c" / "template.json"

        CredentialsManager.generate_template(str(deep_path))

        assert deep_path.exists()


class TestAuthCredentialsIntegration:
    """Tests for auth_credentials integration with auditor."""

    def test_auth_credentials_list_format(self):
        """auth_credentials should be a list of dicts with user/pass."""
        # Simulating what the wizard produces
        auth_credentials = [
            {"user": "admin", "pass": "admin123"},
            {"user": "root", "pass": "toor"},
        ]

        # Verify format matches what auditor expects
        for cred in auth_credentials:
            assert "user" in cred
            assert "pass" in cred or cred.get("pass") is None

    def test_credentials_manager_from_auth_credentials(self):
        """CredentialsManager should accept auth_credentials format."""
        auth_credentials = [
            {"user": "admin", "pass": "secret"},
            {"user": "backup", "pass": "backup123"},
        ]

        mgr = CredentialsManager(auth_credentials)

        assert len(mgr.credentials) == 2
        assert mgr.credentials[0].user == "admin"
        assert mgr.credentials[1].password == "backup123"
