# Improvement Proposals (Non-Binding)

This document collects architectural suggestions for future versions, without altering the current core (v2.5).
*Note: Any proposals implemented must comply with the GPLv3 license.*

## 1. Decoupling Python Code
**Current State**: `redaudit_install.sh` embeds the entire Python source code within a `cat << 'EOF'` block.
**Proposal**: Split into two files:
- `install.sh`: Installation logic only (apt, aliases, copy).
- `src/redaudit.py`: The clean Python source code.
**Benefit**: Facilitates linting, testing, and code review without regenerating the installer.

## 2. Decryptor Tests
**Current State**: `redaudit_decrypt.py` is tested manually.
**Proposal**: Add `tests/test_decrypt.py` that:
1. Generates a dummy key and salt.
2. Encrypts a string.
3. Invokes `redaudit_decrypt.py` (or its imported functions) to verify the round-trip.

## 3. Python Version Validation
**Current State**: Assumes `python3` (typically 3.10+ on Kali).
**Proposal**: Add an explicit version check (>= 3.8) in the installer to avoid syntax errors on older distros.

## 4. CI/CD Integration
**Proposal**: Include a `.github/workflows/verify.yml` file to validate PRs automatically without running actual scans.

```yaml
name: Verify RedAudit
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y nmap python3-nmap python3-cryptography
      - name: Run Verification Script
        run: bash redaudit_verify.sh
        continue-on-error: true # Expect failure on binary path but check syntax
      - name: Syntax Check
        run: |
          bash -n redaudit_install.sh
          python3 -m py_compile redaudit_decrypt.py
      - name: Run Sanitization Tests
        run: python3 tests/test_sanitization.py
```
