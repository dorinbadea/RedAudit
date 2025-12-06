#!/usr/bin/env python3
"""RedAudit Report Decryptor"""

import sys
import base64
import getpass
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

def derive_key_from_password(password, salt):
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def decrypt_report(encrypted_file):
    try:
        if not os.path.exists(encrypted_file):
            print(f"❌ File not found: {encrypted_file}")
            return False

        # Read encrypted data
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()

        # Try to find the salt file
        # Expected formats: base.json.enc -> base.salt, base.txt.enc -> base.salt
        salt_file = encrypted_file.replace('.json.enc', '.salt').replace('.txt.enc', '.salt')
        
        # Fallback if extension logic fails (e.g. user renamed file but kept .enc)
        if not os.path.exists(salt_file):
             # Try assuming it's in the same dir with .salt extension matching the base name
             base_name = os.path.splitext(os.path.splitext(encrypted_file)[0])[0] # remove .json.enc or .txt.enc
             salt_file = base_name + ".salt"

        if not os.path.exists(salt_file):
             print(f"❌ Salt file not found. Expected: {salt_file}")
             return False

        with open(salt_file, 'rb') as f:
            salt = f.read()

        password = getpass.getpass("Decryption password: ")
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted_data)

        output_file = encrypted_file.replace('.enc', '')
        # Prevent overwriting existing files without .enc extension if they happen to match
        if output_file == encrypted_file:
            output_file += ".decrypted"

        with open(output_file, 'wb') as f:
            f.write(decrypted)

        print(f"✓ Decrypted successfully: {output_file}")
        return True

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: redaudit_decrypt.py <encrypted_file.(json|txt).enc>")
        sys.exit(1)

    ok = decrypt_report(sys.argv[1])
    sys.exit(0 if ok else 1)
