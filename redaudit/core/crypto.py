#!/usr/bin/env python3
"""
RedAudit - Cryptography Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

Handles encryption, decryption, and key derivation for report security.
"""

import os
import base64
import getpass

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    Fernet = None
    PBKDF2HMAC = None
    hashes = None
    CRYPTO_AVAILABLE = False

from redaudit.utils.constants import (
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    MIN_PASSWORD_LENGTH,
    COLORS,
)


def is_crypto_available() -> bool:
    """Check if cryptography library is available."""
    return CRYPTO_AVAILABLE


def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """
    Derive encryption key from password using PBKDF2.

    Args:
        password: User password
        salt: Optional salt bytes. If None, generates random salt.

    Returns:
        Tuple of (key_bytes, salt_bytes)

    Raises:
        RuntimeError: If cryptography library is not available
    """
    if PBKDF2HMAC is None:
        raise RuntimeError("cryptography not available")

    if salt is None:
        salt = os.urandom(SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_data(data, encryption_key: bytes = None):
    """
    Encrypt data using Fernet (AES-128-CBC + HMAC-SHA256).

    Args:
        data: String or bytes to encrypt
        encryption_key: Fernet-compatible key

    Returns:
        Encrypted bytes, or original data if encryption unavailable
    """
    if not encryption_key or Fernet is None:
        return data

    try:
        f = Fernet(encryption_key)
        if isinstance(data, str):
            data = data.encode()
        return f.encrypt(data)
    except Exception:  # pragma: no cover
        return data


def decrypt_data(encrypted_data: bytes, encryption_key: bytes) -> bytes:
    """
    Decrypt data using Fernet.

    Args:
        encrypted_data: Encrypted bytes
        encryption_key: Fernet-compatible key

    Returns:
        Decrypted bytes

    Raises:
        Exception: If decryption fails
    """
    if Fernet is None:
        raise RuntimeError("cryptography not available")

    f = Fernet(encryption_key)
    return f.decrypt(encrypted_data)


def ask_password_twice(prompt: str = "Password", lang: str = "en") -> str:
    """
    Prompt user for password twice with validation.

    Args:
        prompt: Prompt text
        lang: Language for error messages

    Returns:
        Validated password string
    """
    while True:
        p1 = getpass.getpass(f"{COLORS['CYAN']}?{COLORS['ENDC']} {prompt}: ")

        if len(p1) < MIN_PASSWORD_LENGTH:
            msg = "Password must be at least 8 characters"
            if lang == "es":
                msg = "La contraseña debe tener al menos 8 caracteres"
            print(f"{COLORS['WARNING']}[WARNING]{COLORS['ENDC']} {msg}")
            continue

        p2 = getpass.getpass(f"{COLORS['CYAN']}?{COLORS['ENDC']} Confirm: ")

        if p1 == p2:
            return p1

        msg = "Passwords don't match"
        if lang == "es":
            msg = "Las contraseñas no coinciden"
        print(f"{COLORS['WARNING']}[WARNING]{COLORS['ENDC']} {msg}")


def generate_random_password(length: int = 32) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length

    Returns:
        Random password string
    """
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))
