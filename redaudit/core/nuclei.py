#!/usr/bin/env python3
"""
RedAudit - Nuclei Integration Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.6: Nuclei template scanner integration for enhanced vulnerability detection.
"""

import os
import json
import shutil
from typing import Any, Dict, List, Optional

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run


def is_nuclei_available() -> bool:
    """Check if nuclei is installed and available."""
    return shutil.which("nuclei") is not None


def get_nuclei_version() -> Optional[str]:
    """Get nuclei version string."""
    if not is_nuclei_available():
        return None
    try:
        runner = CommandRunner(default_timeout=10.0)
        result = runner.run(["nuclei", "-version"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            stdout_str = (
                result.stdout.decode("utf-8", errors="replace")
                if isinstance(result.stdout, bytes)
                else str(result.stdout)
            )
            # Parse "Nuclei Engine Version: vX.X.X" or similar
            for line in stdout_str.splitlines():
                if "version" in line.lower():
                    return line.strip()
            return stdout_str.strip().split("\n")[0]
    except Exception:
        pass
    return None


def run_nuclei_scan(
    targets: List[str],
    output_dir: str,
    *,
    severity: str = "medium,high,critical",
    templates: Optional[str] = None,
    rate_limit: int = 150,
    timeout: int = 300,
    logger=None,
    dry_run: bool = False,
    print_status=None,
) -> Dict[str, Any]:
    """
    Run Nuclei scan against HTTP/HTTPS targets.

    Args:
        targets: List of URLs (e.g., ["http://192.168.1.1:80", "https://192.168.1.1:443"])
        output_dir: Directory to save nuclei JSON output
        severity: Comma-separated severity levels (default: medium,high,critical)
        templates: Path to custom templates directory (optional)
        rate_limit: Requests per second (default: 150)
        timeout: Scan timeout in seconds (default: 300)
        logger: Optional logger
        dry_run: If True, print command but don't execute
        print_status: Optional status print function

    Returns:
        Dict with scan results and findings
    """
    result = {
        "success": False,
        "nuclei_available": is_nuclei_available(),
        "targets_scanned": len(targets),
        "findings": [],
        "raw_output_file": None,
        "error": None,
    }

    if not result["nuclei_available"]:
        result["error"] = "nuclei not installed"
        return result

    if not targets:
        result["error"] = "no targets provided"
        return result

    if dry_run or is_dry_run():
        if print_status:
            print_status("[dry-run] nuclei scan skipped", "INFO")
        result["success"] = True
        result["error"] = "dry-run mode"
        return result

    # Create targets file for nuclei
    os.makedirs(output_dir, exist_ok=True)
    targets_file = os.path.join(output_dir, "nuclei_targets.txt")
    output_file = os.path.join(output_dir, "nuclei_output.json")

    try:
        with open(targets_file, "w") as f:
            for target in targets:
                f.write(f"{target}\n")
    except Exception as e:
        result["error"] = f"Failed to create targets file: {e}"
        return result

    # Build nuclei command
    cmd = [
        "nuclei",
        "-l",
        targets_file,
        "-o",
        output_file,
        "-jsonl",  # JSON Lines format
        "-severity",
        severity,
        "-rate-limit",
        str(rate_limit),
        "-silent",  # Reduce noise
        "-nc",  # No color
    ]

    if templates:
        cmd.extend(["-t", templates])

    if print_status:
        print_status(f"Running nuclei scan on {len(targets)} targets...", "INFO")

    try:
        runner = CommandRunner(
            logger=logger,
            default_timeout=float(timeout),
            dry_run=dry_run,
        )

        # v3.7: Add spinner progress for Nuclei scan
        try:
            from rich.progress import (
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
            )
            from rich.console import Console

            console = Console()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Nuclei scanning {len(targets)} targets...", total=None
                )
                res = runner.run(cmd, capture_output=True, text=True, timeout=float(timeout))
                progress.update(task, completed=True)

        except ImportError:
            # Fallback if rich not available
            res = runner.run(cmd, capture_output=True, text=True, timeout=float(timeout))

        result["success"] = res.returncode == 0 or os.path.exists(output_file)
        result["raw_output_file"] = output_file if os.path.exists(output_file) else None

        # Parse JSONL output
        if os.path.exists(output_file):
            result["findings"] = _parse_nuclei_output(output_file, logger)

        if res.stderr and "error" in res.stderr.lower():
            result["error"] = res.stderr[:500]

    except Exception as e:
        result["error"] = str(e)
        if logger:
            logger.error("Nuclei scan failed: %s", e, exc_info=True)

    return result


def _parse_nuclei_output(output_file: str, logger=None) -> List[Dict[str, Any]]:
    """Parse nuclei JSONL output into findings list."""
    findings = []

    try:
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    normalized = _normalize_nuclei_finding(finding)
                    if normalized:
                        findings.append(normalized)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        if logger:
            logger.warning("Failed to parse nuclei output: %s", e)

    return findings


def _normalize_nuclei_finding(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalize nuclei finding to RedAudit vulnerability format.

    Nuclei output format:
    {
        "template-id": "cve-2021-44228",
        "info": {"name": "...", "severity": "critical", ...},
        "host": "http://target:port",
        "matched-at": "http://target:port/path",
        ...
    }
    """
    if not raw:
        return None

    info = raw.get("info", {})
    template_id = raw.get("template-id", raw.get("templateID", "unknown"))

    # Map nuclei severity to RedAudit severity
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    severity = severity_map.get(info.get("severity", "").lower(), "medium")

    return {
        "source": "nuclei",
        "template_id": template_id,
        "name": info.get("name", template_id),
        "severity": severity,
        "description": info.get("description", ""),
        "host": raw.get("host", ""),
        "matched_at": raw.get("matched-at", raw.get("matchedAt", "")),
        "matcher_name": raw.get("matcher-name", raw.get("matcherName", "")),
        "curl_command": raw.get("curl-command", ""),
        "reference": info.get("reference", []),
        "tags": info.get("tags", []),
        "cve_ids": _extract_cve_ids(info),
        "raw": raw,
    }


def _extract_cve_ids(info: Dict) -> List[str]:
    """Extract CVE IDs from nuclei finding info."""
    cves = []

    # Check classification
    classification = info.get("classification", {})
    if isinstance(classification, dict):
        cve_id = classification.get("cve-id", classification.get("cveId", []))
        if isinstance(cve_id, list):
            cves.extend(cve_id)
        elif isinstance(cve_id, str) and cve_id:
            cves.append(cve_id)

    # Check tags for CVE patterns
    tags = info.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                cves.append(tag.upper())

    return list(set(cves))


def get_http_targets_from_hosts(hosts: List[Dict]) -> List[str]:
    """
    Extract HTTP/HTTPS URLs from RedAudit host results.

    Args:
        hosts: List of host result dicts from RedAudit scan

    Returns:
        List of URLs for nuclei scanning

    v3.6.1: Fixed bug where state check was skipping all ports (RedAudit
    ports don't have a 'state' field). Now uses is_web_service flag.
    """
    # Common HTTPS ports beyond 443
    HTTPS_PORTS = {443, 8443, 4443, 9443, 49443}

    targets = []

    for host in hosts:
        ip = host.get("ip", "")
        if not ip:
            continue

        ports = host.get("ports", [])
        for port_info in ports:
            port = port_info.get("port")
            if not port:
                continue

            service = port_info.get("service", "").lower()

            # Only target web services (RedAudit already marks these)
            if not port_info.get("is_web_service"):
                continue

            # Determine if HTTP or HTTPS
            if port in HTTPS_PORTS or "https" in service or "ssl" in service:
                targets.append(f"https://{ip}:{port}")
            else:
                targets.append(f"http://{ip}:{port}")

    return list(set(targets))
