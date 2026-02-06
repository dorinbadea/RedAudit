#!/usr/bin/env python3
"""
RedAudit - Playbook Generator Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.4: Generate actionable remediation playbooks per finding type.
"""

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from redaudit.utils.constants import SECURE_FILE_MODE, VERSION

# Playbook categories based on finding patterns
PLAYBOOK_PATTERNS = {
    "tls_hardening": [
        r"weak.?cipher",
        r"ssl|tls",
        r"certificate",
        r"heartbleed",
        r"poodle",
        r"beast",
        r"freak",
        r"logjam",
        r"drown",
        r"rc4",
        r"sha1",
        r"md5.?signature",
    ],
    "http_headers": [
        r"hsts",
        r"strict-transport",
        r"x-frame-options",
        r"x-content-type",
        r"content-security-policy",
        r"x-xss-protection",
        r"missing.?header",
    ],
    "cve_remediation": [
        r"cve-\d{4}-\d+",
    ],
    "web_hardening": [
        r"nikto",
        r"directory.?listing",
        r"server.?banner",
        r"phpinfo",
        r"backup.?file",
        r"default.?page",
        r"admin.?panel",
    ],
    "port_hardening": [
        r"telnet",
        r"ftp",
        r"rsh|rlogin|rexec",
        r"smb.?v1",
        r"netbios",
        r"ldap.?anonymous",
        r"snmp.?public",
    ],
}

# v4.14: Device-aware remediation templates
# Commands and steps vary based on device type/vendor
DEVICE_REMEDIATION_TEMPLATES = {
    "embedded_device": {
        "vendors": [
            "avm",
            "fritz",
            "mikrotik",
            "ubiquiti",
            "netgear",
            "tp-link",
            "asus",
            "sercomm",
            "vodafone",
        ],
        "steps": [
            "Access device web interface at http://{host}",
            "Navigate to System/Administration > Firmware Update",
            "Check for available firmware updates",
            "Download latest firmware from vendor website if manual update needed",
            "Apply update and verify device restarts correctly",
        ],
        "commands": [
            "# Embedded devices do not use apt/yum",
            "# Update via web interface or vendor tool:",
            "# - AVM FRITZ: http://{host} > System > Update",
            "# - MikroTik: /system package update check-for-updates",
            "# - Ubiquiti: Web UI > Settings > Firmware",
        ],
    },
    "network_device": {
        "vendors": ["cisco", "juniper", "arista", "huawei", "fortinet", "paloalto"],
        "steps": [
            "Identify current firmware/IOS version",
            "Check vendor security advisories",
            "Download patched firmware from vendor portal",
            "Schedule maintenance window for update",
            "Backup configuration before applying",
            "Apply update and verify connectivity",
        ],
        "commands": [
            "# Network device update (vendor-specific):",
            "# Cisco IOS: copy tftp flash && reload",
            "# Juniper: request system software add",
            "# Check running version: show version",
        ],
    },
    "linux_server": {
        "vendors": ["linux", "ubuntu", "debian", "rhel", "centos", "rocky", "fedora"],
        "steps": [
            "Identify affected packages",
            "Check vendor advisories for patches",
            "Apply security updates",
            "Verify fix with vulnerability scanner",
            "Document remediation in change log",
        ],
        "commands": [
            "# Debian/Ubuntu: apt update && apt upgrade",
            "# RHEL/CentOS: yum update",
            "# Check version: dpkg -l | grep <package>",
        ],
    },
    "windows": {
        "vendors": ["windows", "microsoft"],
        "steps": [
            "Check Windows Update for security patches",
            "Apply pending updates",
            "Restart if required",
            "Verify with vulnerability scanner",
        ],
        "commands": [
            "# Windows Update: Settings > Update & Security",
            "# PowerShell: Get-WindowsUpdate",
            "# wmic qfe list brief",
        ],
    },
}

# Compiled patterns for efficiency
COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {}
for category, patterns in PLAYBOOK_PATTERNS.items():
    COMPILED_PATTERNS[category] = [re.compile(p, re.IGNORECASE) for p in patterns]

_PORT_PATTERNS = [
    re.compile(r"\bport\s*(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE),
]


def _coerce_port(value: Any) -> Optional[int]:
    if isinstance(value, int):
        port = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw.isdigit():
            return None
        port = int(raw)
    else:
        return None

    return port if 0 < port < 65536 else None


def _extract_port(finding: Dict) -> Optional[int]:
    port = _coerce_port(finding.get("port"))
    if port is not None:
        return port

    url = finding.get("url")
    if isinstance(url, str):
        match = re.search(r":(\d{1,5})(?:/|$)", url)
        if match:
            port = _coerce_port(match.group(1))
            if port is not None:
                return port

    candidate_texts: List[str] = []
    for key in ("descriptive_title", "category"):
        val = finding.get(key)
        if isinstance(val, str):
            candidate_texts.append(val)

    nikto = finding.get("nikto_findings", [])
    if isinstance(nikto, list):
        candidate_texts.extend(line for line in nikto[:10] if isinstance(line, str))

    obs = finding.get("parsed_observations", [])
    if isinstance(obs, list):
        candidate_texts.extend(line for line in obs[:10] if isinstance(line, str))

    for text in candidate_texts:
        for pattern in _PORT_PATTERNS:
            match = pattern.search(text)
            if match:
                port = _coerce_port(match.group(1))
                if port is not None:
                    return port

    return None


def _is_experimental_testssl(finding: Dict) -> bool:
    testssl = finding.get("testssl_analysis", {})
    if not isinstance(testssl, dict):
        return False
    vulns = testssl.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return False
    for vuln in vulns:
        text = str(vuln).lower()
        if "experimental" in text or "potentially vulnerable" in text:
            return True
    return False


def _should_skip_playbook(finding: Dict) -> bool:
    fps = finding.get("potential_false_positives") or []
    if fps:
        return True
    source = finding.get("source") or (finding.get("original_severity") or {}).get("tool")
    confidence = finding.get("confidence_score")
    if source == "testssl":
        if _is_experimental_testssl(finding):
            return True
        if isinstance(confidence, (int, float)) and confidence < 0.6:
            return True
    return False


def _detect_device_type(vendor: Optional[str], device_type: Optional[str]) -> str:
    """
    Detect remediation template type based on vendor and device type.
    """
    # Type safety: vendor and device_type must be strings
    vendor_lower = vendor.lower() if isinstance(vendor, str) else ""

    # Check templates for vendor match
    if vendor_lower:
        for template_name, template in DEVICE_REMEDIATION_TEMPLATES.items():
            if any(v in vendor_lower for v in template["vendors"]):
                return template_name

    # Check generic device types
    if device_type and isinstance(device_type, str):
        dt_lower = device_type.lower()
        if "routeros" in dt_lower or "switch" in dt_lower or "firewall" in dt_lower:
            return "network_device"
        if any(x in dt_lower for x in ("router", "gateway", "modem", "ont", "cpe")):
            enterprise = DEVICE_REMEDIATION_TEMPLATES.get("network_device", {}).get("vendors", [])
            if any(v in vendor_lower for v in enterprise):
                return "network_device"
            return "embedded_device"
        if any(x in dt_lower for x in ("embedded", "iot", "printer", "smart_tv", "camera")):
            return "embedded_device"
        if "windows" in dt_lower:
            return "windows"

    return "linux_server"


def _select_device_type(
    device_type: Optional[str], device_type_hints: Optional[List[str]]
) -> Optional[str]:
    if isinstance(device_type, str):
        value = device_type.strip().lower()
        if value and value != "unknown":
            return value

    hints = []
    if isinstance(device_type_hints, list):
        hints = [str(h).strip().lower() for h in device_type_hints if h]

    if not hints:
        return None

    for preferred in (
        "router",
        "firewall",
        "gateway",
        "vpn",
        "printer",
        "smart_tv",
        "iot",
    ):
        if preferred in hints:
            return preferred

    return hints[0] if hints else None


def classify_finding(finding: Dict) -> Optional[str]:
    """
    Classify a finding into a playbook category.

    Args:
        finding: Vulnerability finding dictionary

    Returns:
        Playbook category name or None
    """
    # Build searchable text from all relevant finding fields
    search_texts = []

    # Basic text fields
    for key in ("title", "descriptive_title", "description", "url", "severity", "category"):
        val = finding.get(key)
        if isinstance(val, str):
            search_texts.append(val)

    # Check CVE IDs first (highest priority)
    cve_ids = finding.get("cve_ids", [])
    if isinstance(cve_ids, list) and cve_ids:
        return "cve_remediation"

    # Check nikto findings
    nikto = finding.get("nikto_findings", [])
    if isinstance(nikto, list):
        for line in nikto[:10]:
            if isinstance(line, str):
                search_texts.append(line)

    # Check testssl analysis
    testssl = finding.get("testssl_analysis", {})
    if isinstance(testssl, dict):
        summary = testssl.get("summary", "")
        if isinstance(summary, str) and summary:
            search_texts.append(summary)
        vulns = testssl.get("vulnerabilities", [])
        if isinstance(vulns, list):
            search_texts.extend(v for v in vulns[:10] if isinstance(v, str))
        weak = testssl.get("weak_ciphers", [])
        if isinstance(weak, list):
            search_texts.extend(c for c in weak[:5] if isinstance(c, str))

    # Check parsed observations
    obs = finding.get("parsed_observations", [])
    if isinstance(obs, list):
        search_texts.extend(o for o in obs[:10] if isinstance(o, str))

    combined = " ".join(search_texts).lower()

    # Match against patterns (order matters - more specific first)
    for category in [
        "cve_remediation",
        "tls_hardening",
        "http_headers",
        "web_hardening",
        "port_hardening",
    ]:
        for pattern in COMPILED_PATTERNS.get(category, []):
            if pattern.search(combined):
                return category

    return None


def generate_playbook(
    finding: Dict,
    host: str,
    category: str,
    vendor: Optional[str] = None,
    device_type: Optional[str] = None,
) -> Dict:
    """
    Generate a playbook structure for a finding.

    Args:
        finding: Vulnerability finding dictionary
        host: Host IP address
        category: Playbook category
        vendor: Detected vendor (for device-aware remediation)
        device_type: Detected device type (for device-aware remediation)

    Returns:
        Playbook dictionary with title, steps, references
    """
    descriptive_title = finding.get("descriptive_title")
    url = finding.get("url")
    # v4.14: Prefer 'title' field over URL if descriptive_title absent
    raw_title = finding.get("title")

    # v4.14: Check if raw_title is not a URL (URLs are not real titles)
    is_valid_title = (
        isinstance(raw_title, str)
        and raw_title.strip()
        and raw_title.lower() != "untitled"
        and not raw_title.startswith(("http://", "https://", "/"))
    )

    title = (
        descriptive_title
        if isinstance(descriptive_title, str) and descriptive_title.strip()
        else (
            raw_title
            if is_valid_title
            else url if isinstance(url, str) and url.strip() else f"Finding on {host}"
        )
    )

    severity_val = finding.get("severity", "info")
    severity = severity_val.upper() if isinstance(severity_val, str) else str(severity_val).upper()
    port = _extract_port(finding)

    playbook = {
        "title": title,
        "host": host,
        "port": port,
        "severity": severity,
        "category": category,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "steps": [],
        "commands": [],
        "references": [],
        "vendor": vendor,  # Meta info
        "device_type": device_type,  # Meta info
    }

    # Detect remediation profile
    profile_name = _detect_device_type(vendor, device_type)
    profile = DEVICE_REMEDIATION_TEMPLATES.get(
        profile_name, DEVICE_REMEDIATION_TEMPLATES["linux_server"]
    )

    # Category-specific content
    if category == "tls_hardening":
        playbook["steps"] = [
            "Verify TLS version: ensure TLS 1.2+ only",
            "Review cipher suite configuration",
            "Replace weak or self-signed certificates",
            "Enable HSTS with long max-age",
            "Test with testssl.sh or SSL Labs",
        ]
        playbook["commands"] = [
            f"openssl s_client -connect {host}:{port or 443} -tls1_2",
            f"testssl.sh --fast {host}:{port or 443}",
            "# Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
            "# Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
        ]
        playbook["references"] = [
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
            "https://ssl-config.mozilla.org/",
        ]

    elif category == "http_headers":
        playbook["steps"] = [
            "Add missing security headers to web server config",
            "Enable HSTS with includeSubDomains",
            "Configure Content-Security-Policy",
            "Set X-Frame-Options to DENY or SAMEORIGIN",
            "Add X-Content-Type-Options: nosniff",
        ]
        playbook["commands"] = [
            "# Apache .htaccess:",
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            'Header always set X-Frame-Options "DENY"',
            'Header always set X-Content-Type-Options "nosniff"',
            "# Nginx:",
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        ]
        playbook["references"] = [
            "https://owasp.org/www-project-secure-headers/",
            "https://securityheaders.com/",
        ]

    elif category == "cve_remediation":
        cves = finding.get("cve_ids", [])
        if cves:
            # v4.14: Use device-aware steps for CVEs
            if profile_name in ("embedded_device", "network_device"):
                raw_steps = [
                    f"Research CVE details: {', '.join(cves[:3])}",
                    "Check vendor advisories for firmware updates",
                ] + profile["steps"]
            else:
                raw_steps = [
                    f"Research CVE details: {', '.join(cves[:3])}",
                    "Check vendor advisories for patches",
                    "Apply security updates or upgrade software",
                    "Verify fix with vulnerability scanner",
                    "Document remediation in change log",
                ]
            # Replace {host} placeholder in steps
            playbook["steps"] = [step.replace("{host}", host) for step in raw_steps]
            playbook["references"] = [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves[:3]]
        else:
            # v4.14: Use device-aware generic steps (also replace {host})
            playbook["steps"] = [step.replace("{host}", host) for step in profile["steps"]]

        # v4.14: Use device-aware commands (replace {host})
        playbook["commands"] = [cmd.replace("{host}", host) for cmd in profile["commands"]]

    elif category == "web_hardening":
        playbook["steps"] = [
            "Disable directory listing",
            "Remove server version from banners",
            "Delete default/test pages",
            "Restrict access to admin panels",
            "Review file permissions",
        ]
        playbook["commands"] = [
            "# Apache: Options -Indexes",
            "# Apache: ServerTokens Prod",
            "# Nginx: server_tokens off;",
            "# Nginx: autoindex off;",
        ]
        playbook["references"] = [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ]

    elif category == "port_hardening":
        playbook["steps"] = [
            "Identify if service is required",
            "If not needed: disable or block port",
            "If needed: restrict to trusted IPs",
            "Replace insecure protocols (telnet→SSH, FTP→SFTP)",
            "Enable encryption where possible",
        ]
        if port is not None:
            playbook["commands"] = [
                f"# Check service: netstat -tlnp | grep :{port}",
                f"# Block port: iptables -A INPUT -p tcp --dport {port} -j DROP",
                "# Disable service: systemctl disable <service>",
                f"# UFW: ufw deny {port}/tcp",  # v4.14
            ]
        else:
            playbook["commands"] = [
                "# Identify listening services: netstat -tlnp",
                "# Block port (replace <port>): iptables -A INPUT -p tcp --dport <port> -j DROP",
                "# Disable service: systemctl disable <service>",
            ]
        playbook["references"] = [
            "https://www.cisecurity.org/cis-benchmarks/",
        ]

    return playbook


def get_playbooks_for_results(results: Dict) -> List[Dict]:
    """
    Generate playbooks for all findings in scan results.

    v4.14: Now extracts host vendor/device_type for device-aware remediation.

    Args:
        results: Complete scan results dictionary

    Returns:
        List of playbook dictionaries
    """
    playbooks = []
    seen_categories: Dict[str, set] = {}  # host -> set of categories

    # v4.14: Build host info lookup for vendor/device_type
    host_info: Dict[str, Dict] = {}
    for host_entry in results.get("hosts", []):
        # Type safety: host_entry must be a dict
        if not isinstance(host_entry, dict):
            continue
        ip = host_entry.get("ip")
        if ip:
            deep_scan = host_entry.get("deep_scan", {}) or {}
            identity = host_entry.get("identity", {}) or {}
            # Ensure nested dicts are actually dicts
            if not isinstance(deep_scan, dict):
                deep_scan = {}
            if not isinstance(identity, dict):
                identity = {}
            selected_type = _select_device_type(
                identity.get("device_type") or host_entry.get("device_type"),
                host_entry.get("device_type_hints"),
            )
            host_info[ip] = {
                "vendor": deep_scan.get("vendor")
                or identity.get("vendor")
                or host_entry.get("vendor"),
                "device_type": selected_type,
            }

    for vuln_entry in results.get("vulnerabilities", []):
        # Type safety: vuln_entry must be a dict
        if not isinstance(vuln_entry, dict):
            continue
        host = vuln_entry.get("host", "unknown")

        if host not in seen_categories:
            seen_categories[host] = set()

        # v4.14: Get vendor info for this host
        info = host_info.get(host, {})
        vendor = info.get("vendor")
        device_type = info.get("device_type")

        for vuln in vuln_entry.get("vulnerabilities", []):
            # Type safety: vuln must be a dict for classify_finding
            if not isinstance(vuln, dict):
                continue
            if _should_skip_playbook(vuln):
                continue
            category = classify_finding(vuln)
            if not category:
                continue

            # Deduplicate: one playbook per category per host
            if category in seen_categories[host]:
                continue

            seen_categories[host].add(category)
            # v4.14: Pass vendor/device_type for device-aware remediation
            playbook = generate_playbook(vuln, host, category, vendor, device_type)
            playbooks.append(playbook)

    return playbooks


def render_playbook_markdown(playbook: Dict) -> str:
    """
    Render a playbook dictionary as Markdown.

    Args:
        playbook: Playbook dictionary

    Returns:
        Markdown string
    """
    lines = [
        f"# {playbook['title']}",
        "",
        f"**Host**: {playbook['host']}",
        f"**Port**: {playbook['port']}" if playbook.get("port") else "",
        f"**Severity**: {playbook['severity']}",
        f"**Category**: {playbook['category'].replace('_', ' ').title()}",
        f"**Generated**: {playbook['generated_at']}",
        "",
        "---",
        "",
        "## Remediation Steps",
        "",
    ]

    for i, step in enumerate(playbook.get("steps", []), 1):
        lines.append(f"{i}. {step}")

    if playbook.get("commands"):
        lines.extend(
            [
                "",
                "## Suggested Commands",
                "",
                "```bash",
            ]
        )
        lines.extend(playbook["commands"])
        lines.append("```")

    if playbook.get("references"):
        lines.extend(
            [
                "",
                "## References",
                "",
            ]
        )
        for ref in playbook["references"]:
            lines.append(f"- {ref}")

    lines.extend(
        [
            "",
            "---",
            f"*Generated by RedAudit v{VERSION}*",
        ]
    )

    return "\n".join(lines)


def save_playbooks(results: Dict, output_dir: str, *, logger=None) -> tuple[int, list]:
    """
    Save remediation playbooks to output directory.

    v3.9.0: Now returns (count, playbook_data) for HTML report integration.

    Args:
        results: Complete scan results dictionary
        output_dir: Directory to save playbooks

    Returns:
        Tuple of (number of playbooks generated, list of playbook metadata)
    """
    playbooks = get_playbooks_for_results(results)
    if not playbooks:
        return 0, []

    playbooks_dir = os.path.join(output_dir, "playbooks")
    try:
        os.makedirs(playbooks_dir, exist_ok=True)
    except Exception as exc:
        if logger:
            logger.warning("Could not create playbooks directory %s: %s", playbooks_dir, exc)
        return 0, []

    count = 0
    playbook_data = []  # v3.9.0: Collect for HTML report
    for playbook in playbooks:
        host_safe = playbook["host"].replace(".", "_")
        category = playbook["category"]
        filename = f"{host_safe}_{category}.md"
        filepath = os.path.join(playbooks_dir, filename)

        try:
            markdown = render_playbook_markdown(playbook)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(markdown)
            try:
                os.chmod(filepath, SECURE_FILE_MODE)
            except Exception as chmod_err:
                if logger:
                    logger.debug("Could not chmod playbook %s: %s", filepath, chmod_err)
            count += 1
            # v3.9.0: Add to data for HTML report
            playbook_data.append(
                {
                    "host": playbook["host"],
                    "category": category,
                    "title": playbook.get("title", category),
                    "path": filepath,
                    "filename": filename,
                    # v4.3.0: Include full content for HTML display
                    "steps": playbook.get("steps", []),
                    "commands": playbook.get("commands", []),
                    "references": playbook.get("references", []),
                    "severity": playbook.get("severity", "INFO"),
                }
            )
        except Exception as exc:
            if logger:
                logger.debug("Failed to write playbook %s: %s", filepath, exc)
            continue

    return count, playbook_data
