#!/usr/bin/env python3
"""
Tests for CredentialsManager - Phase 4.1 Multi-Credential Support.
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from redaudit.core.credentials_manager import (
    CredentialsManager,
    UniversalCredential,
    CredentialResult,
    PORT_PROTOCOL_MAP,
)


class TestUniversalCredential:
    """Tests for UniversalCredential dataclass."""

    def test_from_dict_basic(self):
        """Test creating credential from basic dict."""
        data = {"user": "admin", "pass": "secret"}
        cred = UniversalCredential.from_dict(data)

        assert cred.user == "admin"
        assert cred.password == "secret"
        assert cred.private_key is None

    def test_from_dict_with_key(self):
        """Test creating credential with SSH key."""
        data = {"user": "deploy", "key": "~/.ssh/id_rsa", "key_pass": "keypass"}
        cred = UniversalCredential.from_dict(data)

        assert cred.user == "deploy"
        assert cred.private_key == "~/.ssh/id_rsa"
        assert cred.private_key_passphrase == "keypass"

    def test_from_dict_with_domain(self):
        """Test creating credential with Windows domain."""
        data = {"user": "Administrator", "pass": "P@ss", "domain": "CORP"}
        cred = UniversalCredential.from_dict(data)

        assert cred.user == "Administrator"
        assert cred.domain == "CORP"

    def test_to_dict_excludes_none(self):
        """Test to_dict excludes None values."""
        cred = UniversalCredential(user="admin", password="secret")
        d = cred.to_dict()

        assert "user" in d
        assert "password" in d
        assert "private_key" not in d
        assert "domain" not in d


class TestCredentialsManager:
    """Tests for CredentialsManager class."""

    def test_init_empty(self):
        """Test initialization without credentials."""
        mgr = CredentialsManager()
        assert len(mgr.credentials) == 0

    def test_init_with_credentials(self):
        """Test initialization with credentials list."""
        creds = [
            {"user": "admin", "pass": "admin"},
            {"user": "root", "pass": "toor"},
        ]
        mgr = CredentialsManager(creds)

        assert len(mgr.credentials) == 2
        assert mgr.credentials[0].user == "admin"
        assert mgr.credentials[1].user == "root"

    def test_add_credential(self):
        """Test adding credentials."""
        mgr = CredentialsManager()
        cred = UniversalCredential(user="test", password="pass")
        mgr.add_credential(cred)

        assert len(mgr.credentials) == 1
        assert mgr.credentials[0].user == "test"

    def test_get_protocol_for_port(self):
        """Test port to protocol mapping."""
        mgr = CredentialsManager()

        assert mgr.get_protocol_for_port(22) == "ssh"
        assert mgr.get_protocol_for_port(445) == "smb"
        assert mgr.get_protocol_for_port(139) == "smb"
        assert mgr.get_protocol_for_port(161) == "snmp"
        assert mgr.get_protocol_for_port(3389) == "rdp"
        assert mgr.get_protocol_for_port(9999) is None

    def test_can_attempt_initial(self):
        """Test can_attempt returns True initially."""
        mgr = CredentialsManager()
        assert mgr.can_attempt("192.168.1.1") is True

    def test_can_attempt_after_failures(self):
        """Test can_attempt returns False after max failures."""
        mgr = CredentialsManager()
        host = "192.168.1.1"

        # Record failures up to limit
        for _ in range(mgr.MAX_ATTEMPTS_PER_HOST):
            mgr.record_attempt(host, success=False)

        assert mgr.can_attempt(host) is False

    def test_record_attempt_success_no_increment(self):
        """Test successful attempts don't increment failure count."""
        mgr = CredentialsManager()
        host = "192.168.1.1"

        mgr.record_attempt(host, success=True)
        mgr.record_attempt(host, success=True)

        assert mgr._failed_attempts.get(host, 0) == 0

    def test_try_credentials_success(self):
        """Test try_credentials returns on first success."""
        mgr = CredentialsManager(
            [
                {"user": "wrong", "pass": "wrong"},
                {"user": "correct", "pass": "correct"},
                {"user": "alsocorrect", "pass": "alsocorrect"},
            ]
        )

        def connect_func(cred, host, port):
            if cred.user == "correct":
                return (True, {"connected": True})
            return (False, None)

        result = mgr.try_credentials("192.168.1.1", 22, connect_func)

        assert result is not None
        cred, data = result
        assert cred.user == "correct"
        assert data["connected"] is True

    def test_try_credentials_all_fail(self):
        """Test try_credentials returns None when all fail."""
        mgr = CredentialsManager(
            [
                {"user": "wrong1", "pass": "wrong"},
                {"user": "wrong2", "pass": "wrong"},
            ]
        )

        def connect_func(cred, host, port):
            return (False, None)

        result = mgr.try_credentials("192.168.1.1", 22, connect_func)
        assert result is None

    def test_try_credentials_unknown_port(self):
        """Test try_credentials returns None for unknown port."""
        mgr = CredentialsManager([{"user": "admin", "pass": "admin"}])

        def connect_func(cred, host, port):
            return (True, {})

        result = mgr.try_credentials("192.168.1.1", 9999, connect_func)
        assert result is None

    def test_try_credentials_respects_max_attempts(self):
        """Test try_credentials stops after max failures."""
        mgr = CredentialsManager([{"user": f"user{i}", "pass": "pass"} for i in range(10)])

        attempts = []

        def connect_func(cred, host, port):
            attempts.append(cred.user)
            return (False, None)

        mgr.try_credentials("192.168.1.1", 22, connect_func)

        # Should stop after MAX_ATTEMPTS_PER_HOST
        assert len(attempts) == mgr.MAX_ATTEMPTS_PER_HOST

    def test_get_successful_credentials(self):
        """Test retrieving successful credentials."""
        mgr = CredentialsManager([{"user": "admin", "pass": "admin"}])

        def connect_func(cred, host, port):
            return (True, {})

        mgr.try_credentials("192.168.1.1", 22, connect_func)
        mgr.try_credentials("192.168.1.2", 445, connect_func)

        successful = mgr.get_successful_credentials()
        assert len(successful) == 2
        assert "192.168.1.1:22" in successful
        assert "192.168.1.2:445" in successful


class TestCredentialsManagerFile:
    """Tests for file load/save operations."""

    def test_load_from_file(self, tmp_path):
        """Test loading credentials from JSON file."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(
            json.dumps(
                {
                    "credentials": [
                        {"user": "admin", "pass": "admin"},
                        {"user": "root", "pass": "toor"},
                    ]
                }
            )
        )
        os.chmod(creds_file, 0o600)

        mgr = CredentialsManager()
        mgr.load_from_file(str(creds_file))

        assert len(mgr.credentials) == 2

    def test_load_from_file_not_found(self):
        """Test FileNotFoundError for missing file."""
        mgr = CredentialsManager()

        with pytest.raises(FileNotFoundError):
            mgr.load_from_file("/nonexistent/path.json")

    def test_save_to_file(self, tmp_path):
        """Test saving credentials to JSON file."""
        mgr = CredentialsManager(
            [
                {"user": "admin", "pass": "secret"},
            ]
        )

        creds_file = tmp_path / "saved_creds.json"
        mgr.save_to_file(str(creds_file))

        assert creds_file.exists()

        # Check permissions
        mode = creds_file.stat().st_mode & 0o777
        assert mode == 0o600

        # Check content
        with open(creds_file) as f:
            data = json.load(f)
        assert len(data["credentials"]) == 1
        assert data["credentials"][0]["user"] == "admin"

    def test_generate_template(self, tmp_path):
        """Test generating credentials template."""
        template_file = tmp_path / "template.json"
        CredentialsManager.generate_template(str(template_file))

        assert template_file.exists()

        with open(template_file) as f:
            data = json.load(f)

        assert "credentials" in data
        assert len(data["credentials"]) >= 1

        # Check permissions
        mode = template_file.stat().st_mode & 0o777
        assert mode == 0o600
