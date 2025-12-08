# Contributing Guidelines

## Overview
This project adheres to strict coding and commit standards to maintain auditability and reliability. Contributions that do not follow these guidelines will be rejected.

## Code Standards

### Python
- **Format**: Code must be compliant with PEP 8.
- **Type Hinting**: All function signatures must include type hints.
- **Security**: No usage of `shell=True` in subprocess calls. All user input must be sanitized before execution.
- **Concurrency**: Operations involving network I/O must be thread-safe.

### Testing
- **Local Validation**: Run the `redaudit_verify.sh` script before submitting PRs.
- **Unit Tests**: New modules must be accompanied by relevant test cases (where applicable).

## Pull Request Process

1.  **Branching**: Create feature branches from `main`. Naming convention: `feature/short-description` or `fix/issue-id`.
2.  **Commits**: Use semantic commit messages (e.g., `feat: add ssl inspection`, `fix: logic error in thread pool`).
3.  **Documentation**: Update `README.md` and relevant `docs/` files if architectural changes are made.

## Reporting Issues
- **Bug Reports**: Provide steps to reproduce, OS version, and sanitized logs.
- **Security**: Report critical vulnerabilities via private channel or issue tracker with the label `security`.

## License
By contributing to RedAudit, you agree that your contributions will be licensed under the **GNU General Public License v3.0**.
works with the core dependencies. See [README.md](README.md#security-features) for the full list of required and recommended tools.

You can verify your environment and installation integrity by running:
```bash
bash redaudit_verify.sh
## Code Style

*   Keep the code clean and commented.
*   Follow PEP 8 for Python code where possible.
*   Shell scripts should be POSIX compliant where possible or clearly Bash-specific.

## License

By contributing to RedAudit, you agree that your contributions will be licensed under the  
**GNU General Public License v3.0 (GPLv3)**, the same license as the project.
