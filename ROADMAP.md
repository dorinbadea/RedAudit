# RedAudit Project Roadmap

This document outlines the future development phases for the RedAudit framework.

## 🚀 Upcoming Phases (Post v4.3)

### Phase 4: Authenticated Scanning (Long Term)

Goal: Enable deeper audits by logging into target systems via SSH/SMB/SNMP.

- [ ] **4.1 Secrets Management Architectur**e
  - Design integration with system keyring or HashiCorp Vault.
  - Avoid storing plain-text credentials in config files.

- [ ] **4.2 SSH Credential Support**
  - Implement Paramiko or native SSH client integration.
  - Support key-based authentication (RSA/Ed25519).
  - Support interactive password authentication.

- [ ] **4.3 SMB/WMI Credential Support**
  - Investigate Impacket integration for Windows auditing.
  - Support NTLM/Kerberos auth.

- [ ] **4.4 SNMP Community String Support**
  - Support SNMP v1/v2c (community strings).
  - Support SNMP v3 (AuthPriv/NoAuthNoPriv).

- [ ] **4.5 Remote Linux Auditing**
  - Integrate with tools like `lynis` or `osquery` on remote hosts via SSH.

### Phase 5: DevOps & reproducibility

Goal: Ensure deterministic builds and secure dependency management.

- [ ] **5.1 Dependency Locking**
  - Generate `requirements.lock` or `poetry.lock`.
  - Evaluate `pip-tools` vs `poetry` for the project ecosystem.

- [ ] **5.2 CI/CD Hardening**
  - Update GitHub Actions to use locked dependencies.
  - Ensure reproducible builds across environments (Dev/Prod/CI).

- [ ] **5.3 Dependency Maintenance**
  - Document process for updating and auditing dependencies (Dependabot/Renovate).
