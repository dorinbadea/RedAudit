#!/usr/bin/env python3
"""
RedAudit Keyring Credential Seeder - Lab Seguridad
---------------------------------------------------
Run this script ONCE on your Ubuntu/MSI system to pre-populate the keyring
with lab credentials. After running, the wizard will detect and offer
to load them automatically.

Usage:
    python3 scripts/seed_keyring.py

Lab Network: 172.20.0.0/24 (lab_seguridad Docker network)
"""

import json
import sys

# ============================================================================
# LAB CREDENTIALS - RedAudit Docker Lab (Phase 4)
# ============================================================================

# SSH Credentials (target-ssh-lynis @ 172.20.0.20)
SSH_USER = "auditor"
SSH_PASS = "redaudit"
SSH_KEY = None
SSH_KEY_PASS = None

# SMB/Windows Credentials (samba-ad @ 172.20.0.60, REDAUDIT.LOCAL domain)
SMB_USER = "Administrator"
SMB_PASS = "P@ssw0rd123"
SMB_DOMAIN = "REDAUDIT"

# SNMP v3 Credentials (target-snmp @ 172.20.0.40)
SNMP_USER = "admin-snmp"
SNMP_AUTH_PROTO = "SHA"
SNMP_AUTH_PASS = "auth_pass_123"
SNMP_PRIV_PROTO = "AES"
SNMP_PRIV_PASS = "priv_pass_456"

# ============================================================================
# DO NOT EDIT BELOW THIS LINE
# ============================================================================


def main():
    try:
        import keyring
    except ImportError:
        print("[ERROR] keyring package not installed.")
        print("Run: pip3 install keyring")
        sys.exit(1)

    print("RedAudit Keyring Credential Seeder - Lab Seguridad")
    print("=" * 50)

    count = 0

    # SSH
    if SSH_USER:
        keyring.set_password("redaudit-ssh", "default:username", SSH_USER)
        secret_data = {}
        if SSH_PASS:
            secret_data["password"] = SSH_PASS
        if SSH_KEY_PASS:
            secret_data["key_passphrase"] = SSH_KEY_PASS
        if secret_data:
            keyring.set_password("redaudit-ssh", "default:secret", json.dumps(secret_data))
        if SSH_KEY:
            keyring.set_password("redaudit-ssh", "default:key", SSH_KEY)
        print(f"[OK] SSH: {SSH_USER} (for 172.20.0.20 target-ssh-lynis)")
        count += 1

    # SMB
    if SMB_USER:
        keyring.set_password("redaudit-smb", "default:username", SMB_USER)
        secret_data = {}
        if SMB_PASS:
            secret_data["password"] = SMB_PASS
        if secret_data:
            keyring.set_password("redaudit-smb", "default:secret", json.dumps(secret_data))
        if SMB_DOMAIN:
            keyring.set_password("redaudit-smb", "default:domain", SMB_DOMAIN)
        print(f"[OK] SMB: {SMB_USER}@{SMB_DOMAIN} (for 172.20.0.60 samba-ad)")
        count += 1

    # SNMP v3
    if SNMP_USER:
        keyring.set_password("redaudit-snmp", "default:username", SNMP_USER)
        # Store SNMP auth/priv in secret blob
        snmp_secret = {}
        if SNMP_AUTH_PASS:
            snmp_secret["auth_pass"] = SNMP_AUTH_PASS
            snmp_secret["auth_proto"] = SNMP_AUTH_PROTO
        if SNMP_PRIV_PASS:
            snmp_secret["priv_pass"] = SNMP_PRIV_PASS
            snmp_secret["priv_proto"] = SNMP_PRIV_PROTO
        if snmp_secret:
            keyring.set_password("redaudit-snmp", "default:secret", json.dumps(snmp_secret))
        print(f"[OK] SNMP: {SNMP_USER} ({SNMP_AUTH_PROTO}/{SNMP_PRIV_PROTO}) (for 172.20.0.40)")
        count += 1

    print("=" * 50)
    print(f"Stored {count} credential(s) in system keyring.")
    print("")
    print("Credentials ready for:")
    print("  - SSH:  172.20.0.20 (target-ssh-lynis) -> auditor:redaudit")
    print("  - SMB:  172.20.0.60 (samba-ad)         -> Administrator@REDAUDIT")
    print("  - SNMP: 172.20.0.40 (target-snmp)      -> admin-snmp (SHA/AES)")
    print("")
    print("Next: Start a scan and the wizard will offer to load these.")


if __name__ == "__main__":
    main()
