#!/usr/bin/env python3
"""
RedAudit Keyring Credential Seeder - Lab Seguridad (Spray Mode)
----------------------------------------------------------------
Run this script ONCE on your Ubuntu/MSI system to pre-populate the keyring
with ALL lab credentials. RedAudit will spray these credentials across targets.

Usage:
    python3 scripts/seed_keyring.py

Lab Network: 172.20.0.0/24 (lab_seguridad Docker network)
"""

import json
import sys

# ============================================================================
# ALL LAB CREDENTIALS - RedAudit Docker Lab (Phase 4)
# Format: (username, password, domain, target_hint)
# ============================================================================

# SSH Credentials (spray list)
SSH_CREDENTIALS = [
    ("auditor", "redaudit", "172.20.0.20 target-ssh-lynis"),  # nosec
    ("msfadmin", "msfadmin", "172.20.0.11 metasploitable"),  # nosec
    ("openplc", "openplc", "172.20.0.50 openplc-scada"),  # nosec
]

# SMB/Windows Credentials (spray list)
SMB_CREDENTIALS = [
    ("Administrator", "P@ssw0rd123", "REDAUDITAD.LABORATORIO.LAN", "172.20.0.60 samba-ad"),  # nosec
    ("docker", "password123", None, "172.20.0.30 target-windows"),
    ("msfadmin", "msfadmin", None, "172.20.0.11 metasploitable"),  # nosec
]

# SNMP v3 Credentials
SNMP_USER = "admin-snmp"
SNMP_AUTH_PROTO = "SHA"
SNMP_AUTH_PASS = "auth_pass_123"  # nosec
SNMP_PRIV_PROTO = "AES"
SNMP_PRIV_PASS = "priv_pass_456"  # nosec

# Web/HTTP Credentials (for reference - not stored in keyring)
WEB_CREDENTIALS = [
    ("admin@juice-sh.op", "pwned", "172.20.0.10 juiceshop"),
    ("admin", "password", "172.20.0.12 dvwa"),
    ("guest", "guest", "172.20.0.13 webgoat"),
    ("admin", "admin", "172.20.0.14 hackazon"),
    ("bee", "bug", "172.20.0.15 bwapp"),
    ("admin", "admin", "172.20.0.70 iot-camera"),
    ("admin", "password", "172.20.0.71 iot-router"),
]

# ============================================================================
# DO NOT EDIT BELOW THIS LINE
# ============================================================================


def main():
    try:
        import keyring
        from keyring.errors import NoKeyringError

        # v4.5.8: Configure backend fallback for root/headless
        try:
            # Check if default backend is usable
            backend = keyring.get_keyring()
            if "fail" in str(backend).lower():
                raise NoKeyringError("Backend is 'fail'")
        except (NoKeyringError, Exception):
            # Fallback to PlaintextKeyring
            try:
                import keyrings.alt.file

                keyring.set_keyring(keyrings.alt.file.PlaintextKeyring())
                print(
                    "[INFO] No desktop keyring found. Using PlaintextKeyring (headless/root mode)."
                )
            except ImportError:
                # If keyrings.alt is missing, we can't do much but warn
                print(
                    "[WARN] 'keyrings.alt' not found. Credentials may not persist if no backend is available."
                )
                pass
    except ImportError:
        print("[ERROR] keyring package not installed.")
        print("Run: pip3 install keyring keyrings.alt")
        sys.exit(1)

    # v4.5.7: Warn if not running as root, because RedAudit usually runs as root
    import os

    if os.geteuid() != 0:
        print("[WARN] You are running this script as a NON-ROOT user.")
        print("       If you run RedAudit with 'sudo', it cannot see these credentials.")
        print("       Recommended: sudo python3 scripts/seed_keyring.py")
        print("       (Continuing anyway...)")
        print("-" * 65)

    print("RedAudit Keyring Credential Seeder - Lab Seguridad (Spray Mode)")
    print("=" * 65)

    count = 0

    # SSH - Store as spray list in JSON
    if SSH_CREDENTIALS:
        # Primary credential (default)
        primary = SSH_CREDENTIALS[0]
        keyring.set_password("redaudit-ssh", "default:username", primary[0])
        secret_data = {"password": primary[1]}
        keyring.set_password("redaudit-ssh", "default:secret", json.dumps(secret_data))

        # Store full spray list
        spray_list = [{"user": u, "pass": p, "hint": h} for u, p, h in SSH_CREDENTIALS]
        keyring.set_password("redaudit-ssh", "spray:list", json.dumps(spray_list))

        print(f"[OK] SSH Primary: {primary[0]} ({primary[2]})")
        for u, p, h in SSH_CREDENTIALS[1:]:
            print(f"     SSH Spray:   {u} ({h})")
        count += len(SSH_CREDENTIALS)

    # SMB - Store as spray list in JSON
    if SMB_CREDENTIALS:
        # Primary credential (default)
        primary = SMB_CREDENTIALS[0]
        keyring.set_password("redaudit-smb", "default:username", primary[0])
        secret_data = {"password": primary[1]}
        keyring.set_password("redaudit-smb", "default:secret", json.dumps(secret_data))
        if primary[2]:
            keyring.set_password("redaudit-smb", "default:domain", primary[2])

        # Store full spray list
        spray_list = [
            {"user": u, "pass": p, "domain": d, "hint": h} for u, p, d, h in SMB_CREDENTIALS
        ]
        keyring.set_password("redaudit-smb", "spray:list", json.dumps(spray_list))

        domain_str = f"@{primary[2]}" if primary[2] else ""
        print(f"[OK] SMB Primary: {primary[0]}{domain_str} ({primary[3]})")
        for u, p, d, h in SMB_CREDENTIALS[1:]:
            domain_str = f"@{d}" if d else ""
            print(f"     SMB Spray:   {u}{domain_str} ({h})")
        count += len(SMB_CREDENTIALS)

    # SNMP v3
    if SNMP_USER:
        keyring.set_password("redaudit-snmp", "default:username", SNMP_USER)
        snmp_secret = {
            "auth_pass": SNMP_AUTH_PASS,
            "auth_proto": SNMP_AUTH_PROTO,
            "priv_pass": SNMP_PRIV_PASS,
            "priv_proto": SNMP_PRIV_PROTO,
        }
        keyring.set_password("redaudit-snmp", "default:secret", json.dumps(snmp_secret))
        print(f"[OK] SNMP: {SNMP_USER} ({SNMP_AUTH_PROTO}/{SNMP_PRIV_PROTO})")
        count += 1

    print("=" * 65)
    print(f"Stored {count} credential(s) in system keyring.")
    print("")
    print("Spray Mode Enabled:")
    print(f"  - SSH:  {len(SSH_CREDENTIALS)} credentials")
    print(f"  - SMB:  {len(SMB_CREDENTIALS)} credentials")
    print("  - SNMP: 1 credential")
    print("")
    print("Web credentials (reference only - not in keyring):")
    for u, p, h in WEB_CREDENTIALS:
        print(f"  - {h}: {u}")
    print("")
    print("Next: Start a scan and the wizard will offer to load these.")


if __name__ == "__main__":
    main()
