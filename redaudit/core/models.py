"""
RedAudit - Core Data Models
Copyright (C) 2026 Dorin Badea
GPLv3 License

This module defines the canonical data structures used throughout the application.
Replacing raw dictionaries with typed dataclasses eliminates class-of-bugs related
to key mismatches (e.g., 'mac' vs 'mac_address').
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class Service:
    """Represents a network service running on a port."""

    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    state: str = "open"
    reason: str = ""
    tunnel: str = ""  # ssl/tls if applicable
    cpe: List[str] = field(default_factory=list)
    script_output: Dict[str, str] = field(default_factory=dict)

    @property
    def is_encrypted(self) -> bool:
        """Check if service uses SSL/TLS."""
        return self.tunnel in ("ssl", "tls") or self.name in ("https", "ssl", "tls", "rdp")


@dataclass
class Vulnerability:
    """Represents a security finding or vulnerability."""

    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str = ""
    evidence: str = ""
    solution: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    tool_source: str = "redaudit"
    affected_ports: List[int] = field(default_factory=list)

    # Metadata for report grouping
    category: str = "vuln"
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict:
        """Serialize for JSON reports compatibility."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "solution": self.solution,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "tool_source": self.tool_source,
            "affected_ports": self.affected_ports,
        }


@dataclass
class Host:
    """Represents a networked asset."""

    ip: str
    mac_address: str = ""  # Canonical field for MAC
    hostname: str = ""
    vendor: str = ""
    os_detected: str = ""
    device_type: str = "unknown"

    # Collections
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    ports: List[Dict] = field(default_factory=list)

    web_ports_count: int = 0
    total_ports_found: int = 0

    # Metadata
    tags: Set[str] = field(default_factory=set)
    device_type_hints: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    status: str = "up"

    is_auditor_node: bool = False

    # Extended Data
    deep_scan: Dict = field(default_factory=dict)
    agentless_fingerprint: Dict = field(default_factory=dict)
    agentless_probe: Dict = field(default_factory=dict)
    phase0_enrichment: Dict = field(default_factory=dict)
    dns: Dict = field(default_factory=dict)
    cve_summary: Dict = field(default_factory=dict)
    smart_scan: Dict = field(default_factory=dict)
    red_team_findings: Dict = field(default_factory=dict)
    # v4.0: Authenticated Scanning Results (Phase 4)
    auth_scan: Dict = field(default_factory=dict)

    # Raw data preservation (for transition)
    raw_nmap_data: Dict = field(default_factory=dict)

    # v4.3.1: Raw finding bucket for risk scoring and JSON export
    findings: List[Dict] = field(default_factory=list)

    @property
    def mac(self) -> str:
        """Alias for backward compatibility during migration."""
        return self.mac_address

    def add_service(self, service: Service) -> None:
        """Add a service to the host."""
        self.services.append(service)

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the host."""
        self.vulnerabilities.append(vuln)
        # Recalculate risk score logic could go here

    def to_dict(self) -> Dict:
        """Serialize for JSON reports compatibility."""
        if self.ports:
            ports = [dict(p) for p in self.ports]
        else:
            ports = []
            for svc in self.services:
                ports.append(
                    {
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "service": svc.name,
                        "product": svc.product,
                        "version": svc.version,
                        "extrainfo": svc.extrainfo,
                        "state": svc.state,
                        "reason": svc.reason,
                        "tunnel": svc.tunnel,
                        "cpe": svc.cpe,
                        "script_output": svc.script_output,
                    }
                )
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "mac": self.mac_address,  # Dual keys for compatibility
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_detected": self.os_detected,
            "device_type": self.device_type,
            "services": [s.__dict__ for s in self.services],
            "ports": ports,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "findings": self.findings,  # v4.3.1: Export raw findings
            "tags": list(self.tags),
            "device_type_hints": list(self.device_type_hints),
            "risk_score": self.risk_score,
            "status": self.status,
            "web_ports_count": self.web_ports_count,
            "total_ports_found": self.total_ports_found,
            "is_auditor_node": self.is_auditor_node,
            # Extended fields
            "deep_scan": self.deep_scan,
            "agentless_fingerprint": self.agentless_fingerprint,
            "agentless_probe": self.agentless_probe,
            "phase0_enrichment": self.phase0_enrichment,
            "dns": self.dns,
            "cve_summary": self.cve_summary,
            "smart_scan": self.smart_scan,
            "red_team_findings": self.red_team_findings,
            "auth_scan": self.auth_scan,
        }
