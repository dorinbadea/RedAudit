#!/usr/bin/env python3
"""
RedAudit - Playbook Generator Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.4: Generate actionable remediation playbooks per finding type.
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Optional

try:
    from jinja2 import Environment, PackageLoader, select_autoescape
except ImportError:
    Environment = None  # type: ignore

from redaudit.utils.constants import VERSION

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

# Compiled patterns for efficiency
COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {}
for category, patterns in PLAYBOOK_PATTERNS.items():
    COMPILED_PATTERNS[category] = [re.compile(p, re.IGNORECASE) for p in patterns]


def classify_finding(finding: Dict) -> Optional[str]:
    """
    Classify a finding into a playbook category.

    Args:
        finding: Vulnerability finding dictionary

    Returns:
        Playbook category name or None
    """
    # Build searchable text from finding fields
    search_texts = []

    for key in ("descriptive_title", "url", "severity", "category"):
        val = finding.get(key)
        if isinstance(val, str):
            search_texts.append(val)

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
        if summary:
            search_texts.append(summary)
        vulns = testssl.get("vulnerabilities", [])
        if isinstance(vulns, list):
            search_texts.extend(v for v in vulns[:10] if isinstance(v, str))
        weak = testssl.get("weak_ciphers", [])
        if isinstance(weak, list):
            search_texts.extend(c for c in weak[:5] if isinstance(c, str))

    # Check CVEs
    cves = finding.get("cve_ids", [])
    if isinstance(cves, list):
        search_texts.extend(c for c in cves if isinstance(c, str))

    # Check parsed observations
    obs = finding.get("parsed_observations", [])
    if isinstance(obs, list):
        search_texts.extend(o for o in obs[:10] if isinstance(o, str))

    combined = " ".join(search_texts).lower()

    # Match against patterns (order matters - more specific first)
    for category in ["cve_remediation", "tls_hardening", "http_headers", "web_hardening", "port_hardening"]:
        for pattern in COMPILED_PATTERNS.get(category, []):
            if pattern.search(combined):
                return category

    return None


def generate_playbook(finding: Dict, host: str, category: str) -> Dict:
    """
    Generate a playbook structure for a finding.

    Args:
        finding: Vulnerability finding dictionary
        host: Host IP address
        category: Playbook category

    Returns:
        Playbook dictionary with title, steps, references
    """
    title = finding.get("descriptive_title") or finding.get("url") or f"Finding on {host}"
    severity = finding.get("severity", "info").upper()
    port = finding.get("port", "")

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
    }

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
            playbook["steps"] = [
                f"Research CVE details: {', '.join(cves[:3])}",
                "Check vendor advisories for patches",
                "Apply security updates or upgrade software",
                "Verify fix with vulnerability scanner",
                "Document remediation in change log",
            ]
            playbook["references"] = [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves[:3]]
        else:
            playbook["steps"] = [
                "Identify affected software version",
                "Search NVD for known vulnerabilities",
                "Apply vendor patches",
                "Retest after remediation",
            ]
        playbook["commands"] = [
            "# Debian/Ubuntu: apt update && apt upgrade",
            "# RHEL/CentOS: yum update",
            "# Check version: dpkg -l | grep <package>",
        ]

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
        playbook["commands"] = [
            f"# Check service: netstat -tlnp | grep :{port}",
            f"# Block port: iptables -A INPUT -p tcp --dport {port} -j DROP",
            "# Disable service: systemctl disable <service>",
        ]
        playbook["references"] = [
            "https://www.cisecurity.org/cis-benchmarks/",
        ]

    return playbook


def get_playbooks_for_results(results: Dict) -> List[Dict]:
    """
    Generate playbooks for all findings in scan results.

    Args:
        results: Complete scan results dictionary

    Returns:
        List of playbook dictionaries
    """
    playbooks = []
    seen_categories: Dict[str, set] = {}  # host -> set of categories

    for vuln_entry in results.get("vulnerabilities", []):
        host = vuln_entry.get("host", "unknown")

        if host not in seen_categories:
            seen_categories[host] = set()

        for vuln in vuln_entry.get("vulnerabilities", []):
            category = classify_finding(vuln)
            if not category:
                continue

            # Deduplicate: one playbook per category per host
            category_key = f"{host}:{category}"
            if category in seen_categories[host]:
                continue

            seen_categories[host].add(category)
            playbook = generate_playbook(vuln, host, category)
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
        lines.extend([
            "",
            "## Suggested Commands",
            "",
            "```bash",
        ])
        lines.extend(playbook["commands"])
        lines.append("```")

    if playbook.get("references"):
        lines.extend([
            "",
            "## References",
            "",
        ])
        for ref in playbook["references"]:
            lines.append(f"- {ref}")

    lines.extend([
        "",
        "---",
        f"*Generated by RedAudit v{VERSION}*",
    ])

    return "\n".join(lines)


def save_playbooks(results: Dict, output_dir: str) -> int:
    """
    Generate and save playbooks for all findings.

    Args:
        results: Complete scan results dictionary
        output_dir: Directory to save playbooks

    Returns:
        Number of playbooks generated
    """
    playbooks = get_playbooks_for_results(results)
    if not playbooks:
        return 0

    playbooks_dir = os.path.join(output_dir, "playbooks")
    os.makedirs(playbooks_dir, exist_ok=True)

    count = 0
    for playbook in playbooks:
        host_safe = playbook["host"].replace(".", "_")
        category = playbook["category"]
        filename = f"{host_safe}_{category}.md"
        filepath = os.path.join(playbooks_dir, filename)

        try:
            markdown = render_playbook_markdown(playbook)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(markdown)
            count += 1
        except Exception:
            continue

    return count
