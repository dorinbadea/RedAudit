# Architectural Proposals

This document collects architectural suggestions for future versions, focusing on modularity and testing.

## 1. Source Decoupling strategy
**Current State**: `redaudit_install.sh` acts as a self-extracting archive containing the Python source.
**Proposal**: Split the distribution into:
- `bin/redaudit`: Entry point script.
- `lib/redaudit/`: Python package structure.
**Benefit**: Enables standard Python tooling (pip, pylint, pytest) to function without extraction steps.

## 2. Decryption Verification Suite
**Current State**: Decryption logic is manually verified.
**Proposal**: Implement automated regression tests `tests/test_crypto_roundtrip.py`:
1. Generate ephemeral key/salt.
2. Encrypt payload.
3. Decrypt and assert equality.

## 3. Runtime Environment Validation
**Proposal**: Add a `pre_flight_check()` routine that verifies:
- Python version >= 3.8.
- Nmap binary presence and version >= 7.0.
- Write permissions in output directory.

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
