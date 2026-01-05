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
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.utils.dry_run import is_dry_run
from redaudit.core.verify_vuln import check_nuclei_false_positive


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
    batch_size: int = 25,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    use_internal_progress: bool = True,
    logger=None,
    dry_run: bool = False,
    print_status=None,
    proxy_manager=None,
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
    try:
        runner = CommandRunner(
            logger=logger,
            default_timeout=float(timeout),
            dry_run=dry_run,
            command_wrapper=get_proxy_command_wrapper(proxy_manager),
        )

        # Run in batches to provide real progress/ETA on long scans.
        size = int(batch_size) if isinstance(batch_size, int) else 25
        if size < 1:
            size = 25
        batches = [targets[i : i + size] for i in range(0, len(targets), size)]
        total_batches = len(batches)

        def _build_cmd(targets_path: str, out_path: str) -> List[str]:
            cmd = [
                "nuclei",
                "-l",
                targets_path,
                "-o",
                out_path,
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
            return cmd

        def _format_eta(seconds: float) -> str:
            try:
                sec = int(max(0, round(float(seconds))))
            except Exception:
                return "--:--"
            h = sec // 3600
            m = (sec % 3600) // 60
            s = sec % 60
            return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"

        if print_status:
            print_status(
                f"[nuclei] scanning {len(targets)} targets in {total_batches} batch(es)...",
                "INFO",
            )

        # Ensure output_file exists and is empty before appending batch outputs.
        try:
            with open(output_file, "w", encoding="utf-8") as f_out:
                f_out.write("")
        except Exception as e:
            result["error"] = f"Failed to create nuclei output file: {e}"
            return result

        batch_durations: List[float] = []

        def _run_one_batch(batch_idx: int, batch_targets: List[str]) -> None:
            batch_start = time.time()
            with tempfile.TemporaryDirectory(prefix="nuclei_tmp_", dir=output_dir) as tmpdir:
                batch_targets_file = os.path.join(tmpdir, f"targets_{batch_idx}.txt")
                batch_output_file = os.path.join(tmpdir, f"output_{batch_idx}.json")

                with open(batch_targets_file, "w", encoding="utf-8") as f_targets:
                    for t in batch_targets:
                        f_targets.write(f"{t}\n")

                cmd = _build_cmd(batch_targets_file, batch_output_file)
                res = runner.run(cmd, capture_output=True, text=True, timeout=float(timeout))

                # Append JSONL output to the consolidated file, if present.
                if os.path.exists(batch_output_file):
                    with (
                        open(batch_output_file, "r", encoding="utf-8", errors="ignore") as fin,
                        open(output_file, "a", encoding="utf-8") as fout,
                    ):
                        for line in fin:
                            if line.strip():
                                fout.write(line if line.endswith("\n") else line + "\n")

                if res.stderr and "error" in str(res.stderr).lower() and not result["error"]:
                    result["error"] = str(res.stderr)[:500]

            batch_durations.append(time.time() - batch_start)

        if progress_callback is not None:
            # External progress management (preferred when another rich Live/Progress is active).
            for idx, batch in enumerate(batches, start=1):
                _run_one_batch(idx, batch)
                avg = (sum(batch_durations) / len(batch_durations)) if batch_durations else 0.0
                remaining = max(0, total_batches - idx)
                eta = _format_eta(avg * remaining) if avg > 0 else "--:--"
                try:
                    progress_callback(idx, total_batches, f"ETA≈ {eta}")
                except Exception:
                    pass
        elif use_internal_progress:
            # Rich progress UI (best-effort)
            try:
                from rich.progress import (
                    Progress,
                    SpinnerColumn,
                    BarColumn,
                    TextColumn,
                    TimeElapsedColumn,
                )
                from rich.console import Console

                console = Console()
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    TextColumn("{task.fields[eta]}", justify="right"),
                    console=console,
                    transient=False,
                    refresh_per_second=4,
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]Nuclei (0/{total_batches})",
                        total=total_batches,
                        eta="ETA≈ --:--",
                    )
                    for idx, batch in enumerate(batches, start=1):
                        _run_one_batch(idx, batch)
                        avg = (
                            (sum(batch_durations) / len(batch_durations))
                            if batch_durations
                            else 0.0
                        )
                        remaining = max(0, total_batches - idx)
                        eta = _format_eta(avg * remaining) if avg > 0 else "--:--"
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]Nuclei ({idx}/{total_batches})",
                            eta=f"ETA≈ {eta}",
                        )
            except Exception:
                # Fallback: batch-by-batch status
                for idx, batch in enumerate(batches, start=1):
                    if print_status:
                        print_status(
                            f"[nuclei] batch {idx}/{total_batches} ({len(batch)} targets)",
                            "INFO",
                        )
                    _run_one_batch(idx, batch)
        else:
            # No internal UI: batch-by-batch status
            for idx, batch in enumerate(batches, start=1):
                if print_status:
                    print_status(
                        f"[nuclei] batch {idx}/{total_batches} ({len(batch)} targets)", "INFO"
                    )
                _run_one_batch(idx, batch)

        result["success"] = os.path.exists(output_file)
        result["raw_output_file"] = output_file if os.path.exists(output_file) else None

        if os.path.exists(output_file):
            result["findings"] = _parse_nuclei_output(output_file, logger)

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

    # v3.9.0: Check for false positives using response analysis
    is_fp, fp_reason = check_nuclei_false_positive(raw)

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
        # v3.9.0: FP detection
        "suspected_false_positive": is_fp,
        "fp_reason": fp_reason if is_fp else None,
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

    from redaudit.core.models import Host

    for host in hosts:
        if isinstance(host, Host):
            host = host.to_dict()
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
