# Architectural Proposals

[![Ver en español](https://img.shields.io/badge/Ver%20en%20español-red?style=flat-square)](PROPOSALS_ES.md)

This document collects architectural suggestions for future versions, focusing on modularity and testing.

## 1. Source Decoupling Strategy

**Status**: COMPLETED in v2.6
**Implementation**: RedAudit is now a Python package:

- `redaudit/core/`: Core modules (auditor, scanner, crypto, reporter, network)
- `redaudit/utils/`: Utilities (constants, i18n)
- Original `redaudit.py` preserved as backward-compatible wrapper
**Benefit**: Standard Python tooling (pip, pylint, pytest) now works seamlessly.

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

**Status**: COMPLETED in v2.6
**Implementation**: `.github/workflows/tests.yml` provides:

- Automated testing on Python 3.9, 3.10, 3.11, 3.12
- Codecov integration for coverage reporting
- Flake8 linting

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
