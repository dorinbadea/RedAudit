#!/usr/bin/env python3
"""
RedAudit - Encryption Tests
Tests for encryption/decryption functionality.
"""

import sys
import os
import base64

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None
    PBKDF2HMAC = None
    hashes = None

from redaudit.core.crypto import (
    is_crypto_available,
    derive_key_from_password,
    encrypt_data,
    generate_random_password,
)


def test_key_derivation():
    """Test PBKDF2 key derivation."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping: cryptography not available")
        return

    password = "test_password_123"
    salt = os.urandom(16)

    key1, salt1 = derive_key_from_password(password, salt)
    key2, salt2 = derive_key_from_password(password, salt)

    assert key1 == key2, "Same password and salt should produce same key"
    assert salt1 == salt, "Salt should be preserved"
    assert len(key1) == 44, "Fernet key should be 44 bytes (base64 encoded)"

    # Different salt should produce different key
    salt3 = os.urandom(16)
    key3, _ = derive_key_from_password(password, salt3)
    assert key1 != key3, "Different salt should produce different key"

    print("✅ Key derivation tests passed")


def test_encryption_decryption():
    """Test encryption and decryption of data."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping: cryptography not available")
        return

    password = "test_password_123"

    # Derive key
    key, salt = derive_key_from_password(password)

    # Test data
    test_data = "This is a test report with sensitive data"

    # Encrypt
    encrypted = encrypt_data(test_data, key)
    assert encrypted != test_data, "Encrypted data should be different"
    assert isinstance(encrypted, bytes), "Encrypted data should be bytes"

    # Decrypt
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted).decode("utf-8")
    assert decrypted == test_data, "Decrypted data should match original"

    print("✅ Encryption/decryption tests passed")


def test_encryption_without_crypto():
    """Test that encryption degrades gracefully without cryptography."""
    # Import the crypto module to mock it
    import redaudit.core.crypto as crypto_module

    original_fernet = crypto_module.Fernet
    crypto_module.Fernet = None

    try:
        # Test encrypt_data returns original when Fernet is None
        result = encrypt_data("test", None)
        assert result == "test", "Should return original data if encryption unavailable"

        print("✅ Graceful degradation test passed")
    finally:
        crypto_module.Fernet = original_fernet


def test_password_validation():
    """Test password validation in ask_password_twice."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping: cryptography not available")
        return

    # Verify the crypto module functions exist
    from redaudit.core import crypto as crypto_module

    assert hasattr(
        crypto_module, "ask_password_twice"
    ), "ask_password_twice function should exist in crypto module"
    assert hasattr(
        crypto_module, "derive_key_from_password"
    ), "derive_key_from_password function should exist in crypto module"
    assert callable(crypto_module.ask_password_twice), "ask_password_twice should be callable"
    assert callable(
        crypto_module.derive_key_from_password
    ), "derive_key_from_password should be callable"

    print("✅ Password validation structure test passed")


def test_validate_password_strength_and_prompt(monkeypatch):
    if not CRYPTO_AVAILABLE:
        return

    from redaudit.core.crypto import validate_password_strength, ask_password_twice

    ok, msg = validate_password_strength("Short1", lang="en")
    assert ok is False
    assert "at least" in msg

    inputs = iter(["short", "StrongPass123", "StrongPass123"])
    monkeypatch.setattr("getpass.getpass", lambda *_args, **_kwargs: next(inputs))
    assert ask_password_twice(prompt="Password", lang="en") == "StrongPass123"


def test_generate_random_password_length():
    pw = generate_random_password(24)
    assert len(pw) == 24


if __name__ == "__main__":
    print("Running encryption tests...\n")

    test_key_derivation()
    test_encryption_decryption()
    test_encryption_without_crypto()
    test_password_validation()

    print("\n🎉 All encryption tests passed!")
