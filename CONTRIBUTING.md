# Contributing Guidelines

[![Ver en español](https://img.shields.io/badge/Ver%20en%20español-red?style=flat-square)](CONTRIBUTING_ES.md)

## Overview

RedAudit adheres to strict coding and commit standards to maintain auditability and reliability.

## Code Standards

### Python

- **Format**: PEP 8 compliant
- **Type Hinting**: Function signatures must include type hints
- **Security**: No `shell=True` in subprocess calls. All user input must be sanitized
- **Concurrency**: Network I/O operations must be thread-safe

### Package Structure (v2.6)

The codebase is organized as a Python package:

- `redaudit/core/`: Core functionality (auditor, scanner, crypto, reporter, network)
- `redaudit/utils/`: Utilities (constants, i18n)
- `tests/`: Test suites

### Testing

- **Local Validation**: Run `python3 -m pytest tests/` before submitting PRs
- **Verification Script**: Run `bash redaudit_verify.sh` for environment checks
- **CI/CD**: GitHub Actions runs tests automatically on PRs

## Pull Request Process

1. **Branching**: Create feature branches from `main`
   - Naming: `feature/short-description` or `fix/issue-id`
2. **Commits**: Use semantic commit messages
   - `feat: add ssl inspection`
   - `fix: logic error in thread pool`
3. **Documentation**: Update `README.md` and `docs/` files for architectural changes
4. **Tests**: Include test coverage for new functionality

## Reporting Issues

- **Bug Reports**: Provide steps to reproduce, OS version, and sanitized logs
- **Security**: Report vulnerabilities via private channel with label `security`

## Code Style

- Keep code clean and commented
- Follow PEP 8 for Python
- Shell scripts: POSIX compliant or clearly Bash-specific

## License

By contributing to RedAudit, you agree that your contributions will be licensed under the **GNU General Public License v3.0 (GPLv3)**.
