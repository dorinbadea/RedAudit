#!/usr/bin/env python3
"""
RedAudit - Crypto module compatibility tests without cryptography installed.
"""

import base64


def test_derive_key_with_fake_kdf(monkeypatch):
    import redaudit.core.crypto as crypto

    class _DummyHashes:
        class SHA256:
            pass

    class _DummyKDF:
        def __init__(self, algorithm, length, salt, iterations):
            self.length = length
            self.salt = salt

        def derive(self, _password_bytes):
            return b"a" * self.length

    monkeypatch.setattr(crypto, "PBKDF2HMAC", _DummyKDF)
    monkeypatch.setattr(crypto, "hashes", _DummyHashes)

    key, salt = crypto.derive_key_from_password("password", salt=b"\x00" * 16)
    assert salt == b"\x00" * 16
    assert len(key) == len(base64.urlsafe_b64encode(b"a" * 32))


def test_encrypt_and_decrypt_with_fake_fernet(monkeypatch):
    import redaudit.core.crypto as crypto

    class _DummyFernet:
        def __init__(self, _key):
            pass

        def encrypt(self, data):
            return b"enc:" + data

        def decrypt(self, data):
            return data.replace(b"enc:", b"", 1)

    monkeypatch.setattr(crypto, "Fernet", _DummyFernet)

    key = b"dummy"
    encrypted = crypto.encrypt_data("secret", key)
    assert encrypted.startswith(b"enc:")
    decrypted = crypto.decrypt_data(encrypted, key)
    assert decrypted == b"secret"


def test_validate_password_strength_spanish():
    from redaudit.core.crypto import validate_password_strength

    ok, msg = validate_password_strength("Short1", lang="es")
    assert ok is False
    assert "contraseña" in msg.lower()


def test_ask_password_twice_spanish_mismatch(monkeypatch):
    from redaudit.core.crypto import ask_password_twice

    inputs = iter(["StrongPass123", "Mismatch123", "StrongPass123", "StrongPass123"])
    monkeypatch.setattr("getpass.getpass", lambda *_args, **_kwargs: next(inputs))

    assert ask_password_twice(prompt="Clave", lang="es") == "StrongPass123"
