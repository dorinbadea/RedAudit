# Contributing Guidelines

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](CONTRIBUTING_ES.md)

## Welcome

Thank you for considering contributing to RedAudit! This document outlines the development process and standards for contributing.

## Development Setup

### Engineering Workflow (Recommended)

For a clean timeline and consistent releases, see `AGENTS.md` (branching, commit grouping, pre-commit hooks, CI checks, release checklist).

### Prerequisites

- **OS**: Kali Linux, Debian 11+, Ubuntu 20.04+, or Parrot OS
- **Python**: 3.9 or higher
- **Git**: Latest stable version
- **Tools**: nmap, tcpdump, curl, wget (see `redaudit_install.sh` for full list)

### Getting Started

1. **Fork and Clone**

   ```bash
   git clone https://github.com/YOUR_USERNAME/RedAudit.git
   cd RedAudit
   ```

2. **Create Virtual Environment** (Optional but recommended)

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Linux/Mac
   ```

3. **Install Dependencies**

   ```bash
   # Core dependencies
   pip3 install -r requirements.txt

   # Development dependencies (optional)
   pip3 install -e ".[dev]"
   ```

4. **Install System Dependencies**

   ```bash
   sudo bash redaudit_install.sh
   ```

5. **Verify Installation**

   ```bash
   bash redaudit_verify.sh
   ```

### Running Tests

```bash
# Run all tests
python3 -m unittest discover tests/

# Run specific test file
python3 -m unittest tests/test_network.py

# Run with coverage
pip3 install coverage
coverage run -m unittest discover tests/
coverage report
```

### Code Quality Checks

```bash
# Format code (if black is installed)
black redaudit/ tests/

# Lint code
flake8 redaudit/ tests/ --max-line-length=100
```

---

## Code Standards

### Python

- **Format**: PEP 8 compliant (100 character line limit)
- **Type Hinting**: Function signatures must include type hints
- **Security**: No `shell=True` in subprocess calls. All user input must be sanitized
- **Concurrency**: Network I/O operations must be thread-safe
- **Documentation**: Docstrings for all public functions and classes

### Package Structure

The codebase is organized as a Python package:

- `redaudit/core/`: Core functionality (auditor, scanner, net_discovery, crypto, reporter, network, nvd, diff, proxy)
- `redaudit/utils/`: Utilities (constants, i18n, config)
- `tests/`: Test suites with unittest

### Testing Requirements

- **Coverage**: New features must include tests
- **Local Validation**: Run `python3 -m unittest discover tests/` before submitting PRs
- **Verification Script**: Run `bash redaudit_verify.sh` for environment checks
- **CI/CD**: GitHub Actions runs tests automatically on PRs (Python 3.9-3.12)

---

## Pull Request Process

### 1. Branching Strategy

- Create feature branches from `main`
- Naming conventions:
  - `feature/short-description` (new features)
  - `fix/issue-number` or `fix/brief-description` (bug fixes)
  - `docs/topic` (documentation updates)
  - `refactor/component` (code refactoring)

### 2. Commit Messages

Use semantic commit messages:

```
feat: add IPv6 scanning support
fix: correct thread pool size validation
docs: update MANUAL_EN.md with v3.0 options
refactor: modularize scanner.py
test: add unit tests for diff module
chore: update dependencies
```

### 3. Pull Request Guidelines

- **Title**: Clear, descriptive summary
- **Description**:
  - What changes were made?
  - Why were they made?
  - How were they tested?
- **Documentation**: Update README.md and docs/ for architectural changes
- **Tests**: Include test coverage for new functionality
- **Commits**: Keep commits atomic and well-described

### 4. Review Process

- All PRs require at least one review
- CI/CD must pass (tests, linting, security checks)
- Address reviewer feedback promptly
- Squash commits before merge (if requested)

---

## Reporting Issues

### Bug Reports

Include:

- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment**: OS version, Python version, RedAudit version
- **Logs**: Sanitized logs from `~/.redaudit/logs/` (remove sensitive data!)
- **Screenshots**: If applicable

### Feature Requests

Include:

- **Use case**: What problem does it solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about

### Security Issues

**Do not report security vulnerabilities via public issues!**

Email: `security@dorinbadea.com`

See [SECURITY.md](../docs/SECURITY.en.md) for our vulnerability disclosure policy.

---

## Code Style

### Python Conventions

- **Imports**: Group stdlib, third-party, local imports separately
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes
- **Comments**: Use `#` for inline comments, docstrings for functions
- **Line Length**: Maximum 100 characters

### Shell Scripts

- **Compatibility**: POSIX compliant or clearly Bash-specific (use `#!/usr/bin/env bash`)
- **Error Handling**: Check exit codes, use `set -e` when appropriate
- **Quoting**: Always quote variables: `"${VAR}"`

---

## Documentation

### When to Update Docs

- **New features**: Update README.md, USAGE.md, MANUAL_EN/ES.md
- **CLI changes**: Update --help text and all documentation
- **API changes**: Update REPORT_SCHEMA.md if JSON structure changes
- **Breaking changes**: Update CHANGELOG.md and migration guide

### Documentation Style

- **Clear and concise**
- **Examples**: Include practical examples
- **Bilingual**: Update both EN and ES versions when possible

---

## License

By contributing to RedAudit, you agree that your contributions will be licensed under the **GNU General Public License v3.0 (GPLv3)**.

See [LICENSE](../LICENSE) for details.

---

## Questions?

- **Issues**: Use [GitHub Issues](https://github.com/dorinbadea/RedAudit/issues) for bugs/features
- **Contact**: See README.md for contact information

Thank you for contributing to RedAudit!
