# Phase 4: Authenticated Scanning - Design Document

**Version**: 1.0 (Draft)
**Status**: Proposed
**Author**: RedAudit Development
**Date**: 2026-01-09

---

## 1. Executive Summary

Phase 4 transforms RedAudit from a **network-level auditing tool** into a **complete internal audit platform** by adding credential-based enumeration. This enables:

- **Deep configuration audits** (not just port/banner detection)
- **Compliance verification** (CIS benchmarks, NIST, ISO 27001)
- **Accurate vulnerability confirmation** (patch verification vs inference)
- **Complete asset inventory** (installed software, users, services)

---

## 2. Architecture Overview

```
                    +------------------+
                    |   Credentials    |
                    |    Provider      |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
    +----v----+        +-----v-----+       +-----v-----+
    |  SSH    |        |  SMB/WMI  |       | SNMP v3   |
    | Module  |        |  Module   |       | Module    |
    +---------+        +-----------+       +-----------+
         |                   |                   |
         +-------------------+-------------------+
                             |
                    +--------v---------+
                    |   Authenticated  |
                    |    Scanner       |
                    +--------+---------+
                             |
                    +--------v---------+
                    |     Lynis        |
                    |   Integration    |
                    +------------------+
```

---

## 3. Components

### 3.1 Secrets Management (P4.1)

**Goal**: Never store credentials in plaintext. Provide multiple secure backends.

#### Supported Backends

| Backend | Use Case | Priority |
|---------|----------|----------|
| **Environment Variables** | CI/CD pipelines | P0 (MVP) |
| **Keyring (OS)** | Interactive desktop use | P0 (MVP) |
| **HashiCorp Vault** | Enterprise environments | P1 |
| **Pass (GPG)** | Linux power users | P2 |

#### Interface

```python
# redaudit/core/credentials.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

@dataclass
class Credential:
    """Represents a credential for authenticated scanning."""
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None  # Path to key file
    private_key_passphrase: Optional[str] = None
    domain: Optional[str] = None  # For Windows/SMB

class CredentialProvider(ABC):
    """Abstract credential provider interface."""

    @abstractmethod
    def get_credential(self, target: str, protocol: str) -> Optional[Credential]:
        """Retrieve credential for target/protocol combination."""
        pass

class EnvironmentCredentialProvider(CredentialProvider):
    """Reads credentials from environment variables."""
    # REDAUDIT_SSH_USER, REDAUDIT_SSH_KEY, etc.

class KeyringCredentialProvider(CredentialProvider):
    """Uses OS keyring (macOS Keychain, Windows Credential Manager, etc.)."""

class VaultCredentialProvider(CredentialProvider):
    """Integrates with HashiCorp Vault."""
```

#### CLI Flags

```
--auth-provider {env|keyring|vault}   Credential backend (default: keyring)
--vault-addr URL                       Vault server address
--vault-token TOKEN                    Vault authentication token
--ssh-user USER                        Default SSH username
--ssh-key PATH                         Default SSH private key
--smb-user DOMAIN\\USER                Default SMB username
```

#### Security Considerations

- Credentials NEVER written to disk (except encrypted keyring)
- Credentials NEVER logged (redacted in session logs)
- Memory cleared after use (where possible)
- Audit log of credential access attempts

---

### 3.2 SSH Credential Support (P4.2)

**Goal**: Enable remote Linux/Unix auditing via SSH.

#### Implementation

```python
# redaudit/core/auth_ssh.py

import paramiko
from typing import List, Dict, Any

class SSHScanner:
    """Authenticated SSH-based host scanning."""

    def __init__(self, credential: Credential, timeout: int = 30):
        self.credential = credential
        self.timeout = timeout
        self.client = None

    def connect(self, host: str, port: int = 22) -> bool:
        """Establish SSH connection."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.credential.private_key:
            key = paramiko.RSAKey.from_private_key_file(
                self.credential.private_key,
                password=self.credential.private_key_passphrase
            )
            self.client.connect(host, port, username=self.credential.username, pkey=key)
        else:
            self.client.connect(host, port,
                username=self.credential.username,
                password=self.credential.password)
        return True

    def run_command(self, command: str) -> tuple[str, str, int]:
        """Execute command and return (stdout, stderr, exit_code)."""
        stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
        return stdout.read().decode(), stderr.read().decode(), stdout.channel.recv_exit_status()

    def get_os_info(self) -> Dict[str, str]:
        """Retrieve OS information."""
        out, _, _ = self.run_command("cat /etc/os-release 2>/dev/null || uname -a")
        # Parse output...

    def get_installed_packages(self) -> List[Dict[str, str]]:
        """Get list of installed packages with versions."""
        # Detect package manager and query
        out, _, _ = self.run_command("dpkg -l 2>/dev/null || rpm -qa 2>/dev/null")
        # Parse output...

    def get_running_services(self) -> List[str]:
        """List running services."""
        out, _, _ = self.run_command("systemctl list-units --type=service --state=running")
        # Parse output...

    def get_users(self) -> List[Dict[str, Any]]:
        """Get user accounts."""
        out, _, _ = self.run_command("cat /etc/passwd")
        # Parse output...

    def get_firewall_rules(self) -> str:
        """Get firewall configuration."""
        out, _, _ = self.run_command("iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null")
        return out
```

#### Data Model Extension

```python
@dataclass
class AuthenticatedHostData:
    """Extended host data from authenticated scanning."""
    os_info: Dict[str, str]
    installed_packages: List[Dict[str, str]]
    running_services: List[str]
    users: List[Dict[str, Any]]
    firewall_rules: str
    ssh_config: Dict[str, str]
    cron_jobs: List[str]
    # ... more fields
```

---

### 3.3 SMB/WMI Credential Support (P4.3)

**Goal**: Enable authenticated Windows enumeration.

#### Implementation

```python
# redaudit/core/auth_smb.py

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import wmi, dcom

class SMBScanner:
    """Authenticated SMB/WMI-based Windows scanning."""

    def __init__(self, credential: Credential):
        self.credential = credential
        self.smb = None

    def connect(self, host: str, port: int = 445) -> bool:
        """Establish SMB connection."""
        self.smb = SMBConnection(host, host, sess_port=port)
        if self.credential.domain:
            self.smb.login(self.credential.username, self.credential.password,
                          domain=self.credential.domain)
        else:
            self.smb.login(self.credential.username, self.credential.password)
        return True

    def get_shares(self) -> List[Dict[str, str]]:
        """Enumerate SMB shares."""
        return self.smb.listShares()

    def get_installed_software(self) -> List[Dict[str, str]]:
        """Query installed software via WMI."""
        # WMI query: SELECT * FROM Win32_Product

    def get_hotfixes(self) -> List[Dict[str, str]]:
        """Query installed hotfixes/patches."""
        # WMI query: SELECT * FROM Win32_QuickFixEngineering

    def get_services(self) -> List[Dict[str, str]]:
        """Query Windows services."""
        # WMI query: SELECT * FROM Win32_Service

    def get_local_users(self) -> List[Dict[str, str]]:
        """Enumerate local users."""
        # Net API or WMI query
```

#### Dependencies

```toml
# pyproject.toml additions
[project.optional-dependencies]
auth = [
    "paramiko>=3.0.0",
    "impacket>=0.11.0",
    "pysnmp>=6.0.0",
]
```

---

### 3.4 SNMP v3 Support (P4.4)

**Goal**: Authenticated SNMP queries for network device auditing.

#### Implementation

```python
# redaudit/core/auth_snmp.py

from pysnmp.hlapi import *
from dataclasses import dataclass

@dataclass
class SNMPv3Credential:
    """SNMP v3 authentication parameters."""
    username: str
    auth_protocol: str = "SHA"  # MD5, SHA, SHA224, SHA256, SHA384, SHA512
    auth_password: Optional[str] = None
    priv_protocol: str = "AES"  # DES, 3DES, AES, AES192, AES256
    priv_password: Optional[str] = None
    security_level: str = "authPriv"  # noAuthNoPriv, authNoPriv, authPriv

class SNMPv3Scanner:
    """Authenticated SNMP v3 scanner."""

    def __init__(self, credential: SNMPv3Credential):
        self.credential = credential

    def get_system_info(self, host: str) -> Dict[str, str]:
        """Query system MIB."""
        # sysDescr, sysName, sysUpTime, sysContact, sysLocation

    def get_interfaces(self, host: str) -> List[Dict[str, Any]]:
        """Query interface table."""
        # IF-MIB::ifTable

    def get_routing_table(self, host: str) -> List[Dict[str, str]]:
        """Query IP routing table."""
        # IP-MIB::ipRouteTable

    def get_arp_table(self, host: str) -> List[Dict[str, str]]:
        """Query ARP cache."""
        # IP-MIB::ipNetToMediaTable
```

---

### 3.5 Lynis Integration (P4.5)

**Goal**: Run CIS hardening checks on remote Linux hosts.

#### Implementation

```python
# redaudit/core/auth_lynis.py

class LynisScanner:
    """Remote Lynis execution via SSH."""

    def __init__(self, ssh_scanner: SSHScanner):
        self.ssh = ssh_scanner

    def check_lynis_available(self) -> bool:
        """Verify Lynis is installed on target."""
        _, _, code = self.ssh.run_command("which lynis")
        return code == 0

    def install_lynis_temp(self) -> bool:
        """Download Lynis to temp directory for one-time use."""
        cmd = "cd /tmp && git clone --depth 1 https://github.com/CISOfy/lynis.git"
        _, _, code = self.ssh.run_command(cmd)
        return code == 0

    def run_audit(self, profile: str = "default") -> Dict[str, Any]:
        """Execute Lynis audit and parse results."""
        cmd = "cd /tmp/lynis && ./lynis audit system --no-colors --quick"
        out, _, code = self.ssh.run_command(cmd)
        return self._parse_lynis_output(out)

    def _parse_lynis_output(self, output: str) -> Dict[str, Any]:
        """Parse Lynis text output into structured data."""
        # Parse warnings, suggestions, hardening index
```

#### Output Integration

Lynis findings integrate into existing RedAudit reporting:

```python
@dataclass
class LynisResult:
    hardening_index: int  # 0-100
    warnings: List[str]
    suggestions: List[str]
    tests_performed: int
    tests_skipped: int
```

---

## 4. Wizard Integration

New wizard prompts for authenticated scanning:

```
┌──────────────────────────────────────┐
│  Authenticated Scanning              │
├──────────────────────────────────────┤
│                                      │
│  Do you have credentials for         │
│  internal host auditing?             │
│                                      │
│  > No (network-only scan)            │
│    Yes, SSH keys/passwords           │
│    Yes, Windows domain credentials   │
│    Yes, SNMP v3 credentials          │
│                                      │
└──────────────────────────────────────┘
```

---

## 5. Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Credential theft from memory | Clear after use, no global storage |
| Credential logging | Redaction in all log paths |
| Man-in-the-middle | SSH host key verification, TLS for Vault |
| Privilege escalation | Minimal sudo commands, audit logging |
| Lateral movement | Scope credentials to audit targets only |

### Audit Trail

All authenticated actions logged:

```json
{
  "timestamp": "2026-01-09T15:30:00Z",
  "action": "ssh_connect",
  "target": "192.168.1.10",
  "username": "auditor",
  "auth_method": "key",
  "success": true,
  "commands_executed": 12
}
```

---

## 6. Implementation Phases

### Phase 4.0 (MVP) - 2 weeks

- [ ] P4.1 Secrets Management (env + keyring only)
- [ ] P4.2 SSH basic (key auth, command execution)
- [ ] CLI flags for credentials
- [ ] Basic reporting integration

### Phase 4.1 - 2 weeks

- [ ] P4.2 SSH complete (package/service/user enumeration)
- [ ] P4.5 Lynis integration
- [ ] Wizard integration

### Phase 4.2 - 2 weeks

- [ ] P4.3 SMB/WMI support
- [ ] Windows-specific checks

### Phase 4.3 - 1 week

- [ ] P4.4 SNMP v3 support
- [ ] Network device auditing

### Phase 4.4 - 1 week

- [ ] P4.1 Vault integration
- [ ] Enterprise features

---

## 7. Dependencies

```toml
[project.optional-dependencies]
auth = [
    "paramiko>=3.0.0",      # SSH client
    "impacket>=0.11.0",     # SMB/WMI
    "pysnmp>=6.0.0",        # SNMP v3
    "keyring>=24.0.0",      # OS keyring
    "hvac>=2.0.0",          # HashiCorp Vault
]
```

---

## 8. Testing Strategy

- Unit tests with mocked SSH/SMB/SNMP connections
- Integration tests against Docker containers (SSH server, Samba, SNMP daemon)
- Security testing (credential handling, no plaintext leaks)
- Performance testing (connection pooling, parallel audits)

---

## 9. Open Questions

1. **Scope of sudo commands**: Should we support `sudo` for privileged checks, or require root SSH?
2. **Connection pooling**: Reuse SSH connections across multiple checks?
3. **Credential scope**: Per-host credentials vs global credentials?
4. **Offline mode**: Cache authenticated data for offline analysis?

---

## 10. References

- [Paramiko Documentation](https://docs.paramiko.org/)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
