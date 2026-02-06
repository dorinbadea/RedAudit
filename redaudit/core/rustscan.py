#!/usr/bin/env python3
"""
RedAudit - RustScan Integration Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v4.8.0: RustScan as primary fast port scanner with nmap fallback.
Provides ~5s faster scans than nmap -p- -A alone.
"""

import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run

_REDAUDIT_REDACT_ENV_KEYS = {"NVD_API_KEY", "GITHUB_TOKEN"}


def _make_runner(
    *, logger=None, dry_run: Optional[bool] = None, timeout: Optional[float] = None
) -> CommandRunner:
    """Create a CommandRunner instance."""
    return CommandRunner(
        logger=logger,
        dry_run=is_dry_run(dry_run),
        default_timeout=timeout,
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys=_REDAUDIT_REDACT_ENV_KEYS,
    )


def is_rustscan_available() -> bool:
    """Check if RustScan is installed and available."""
    return shutil.which("rustscan") is not None


def get_rustscan_version() -> Optional[str]:
    """Get RustScan version string."""
    if not is_rustscan_available():
        return None
    try:
        result = subprocess.run(
            ["rustscan", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Output is like "RustScan 2.3.0"
            return result.stdout.strip().split()[-1] if result.stdout else None
    except Exception:
        pass
    return None


def run_rustscan(
    target: str,
    *,
    ports: Optional[List[int]] = None,
    nmap_args: str = "-A",
    ulimit: int = 5000,
    timeout: float = 600.0,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Run RustScan on a target with integrated nmap fingerprinting.

    Args:
        target: IP address or hostname to scan
        ports: Optional list of ports to scan (e.g. [80, 443])
        nmap_args: Arguments to pass to nmap after discovery (default: -A)
        ulimit: File descriptor limit for RustScan (default: 5000)
        timeout: Maximum time for the scan in seconds (default: 600)
        logger: Optional logger instance
        dry_run: If True, don't actually run the command

    Returns:
        Dict with keys:
            - success: bool
            - stdout: str
            - stderr: str
            - returncode: int
            - duration: float
            - ports: List[int] (discovered ports)
            - error: Optional[str]
    """
    result: Dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "returncode": -1,
        "duration": 0.0,
        "ports": [],
        "error": None,
    }

    if not is_rustscan_available():
        result["error"] = "RustScan not installed"
        return result

    # Build command
    cmd = [
        "rustscan",
        "-a",
        target,
        "--ulimit",
        str(ulimit),
    ]

    if ports:
        port_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_str])

    cmd.append("--")

    # Add nmap arguments
    if nmap_args:
        cmd.extend(nmap_args.split())

    runner = _make_runner(logger=logger, dry_run=dry_run, timeout=timeout)

    import time

    start = time.time()

    try:
        res = runner.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            check=False,
            text=True,
        )

        result["duration"] = time.time() - start
        result["returncode"] = res.returncode
        result["stdout"] = res.stdout or ""
        result["stderr"] = res.stderr or ""
        result["success"] = res.returncode == 0

        # Parse discovered ports from output
        result["ports"] = _parse_rustscan_ports(result["stdout"])

        if res.timed_out:
            result["error"] = f"Timeout after {timeout}s"
            result["success"] = False

    except Exception as e:
        result["error"] = str(e)
        result["duration"] = time.time() - start

    return result


def run_rustscan_discovery_only(
    target: str,
    *,
    ports: Optional[List[int]] = None,
    port_range: Optional[str] = None,
    ulimit: int = 5000,
    timeout: float = 120.0,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Tuple[List[int], Optional[str]]:
    """
    Run RustScan for port discovery only (no nmap fingerprinting).

    Args:
        target: IP address or hostname to scan
        ports: Optional list of ports to scan
        port_range: Optional port range string (e.g. "1-65535")
        ulimit: File descriptor limit for RustScan
        timeout: Maximum time for discovery in seconds
        logger: Optional logger instance
        dry_run: If True, don't actually run the command

    Returns:
        Tuple of (list of open ports, error message or None)
    """
    if not is_rustscan_available():
        return [], "RustScan not installed"

    cmd = [
        "rustscan",
        "-a",
        target,
        "--ulimit",
        str(ulimit),
    ]

    if ports:
        port_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_str])
    elif port_range:
        cmd.extend(["-r", port_range])

    cmd.append("-g")  # Greppable output (just ports)

    runner = _make_runner(logger=logger, dry_run=dry_run, timeout=timeout)

    try:
        res = runner.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            check=False,
            text=True,
        )

        if res.returncode != 0:
            stderr = (res.stderr or "").strip()
            # mypy fix
            stderr_str = (
                stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
            )
            return [], f"RustScan failed: {stderr_str[:200]}"

        if res.timed_out:
            return [], f"RustScan timeout after {timeout}s"

        # Parse greppable output: "192.168.1.1 -> [80,443,8080]"
        stdout_val = res.stdout or ""
        if isinstance(stdout_val, bytes):
            stdout_val = stdout_val.decode("utf-8", errors="replace")
        ports = _parse_rustscan_greppable(stdout_val)
        return ports, None

    except Exception as e:
        return [], str(e)


def _parse_rustscan_ports(stdout: str) -> List[int]:
    """
    Parse open ports from RustScan output.

    Looks for lines like: "Open 192.168.178.1:80"
    """
    ports = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Open ") and ":" in line:
            try:
                port_str = line.split(":")[-1]
                ports.append(int(port_str))
            except ValueError:
                continue
    return sorted(set(ports))


def _parse_rustscan_greppable(stdout: str) -> List[int]:
    """
    Parse greppable output format from RustScan.

    Format: "192.168.1.1 -> [80,443,8080]"
    Returns a flat list of all unique ports found across all hosts.
    """
    ports = []
    for line in stdout.splitlines():
        if "->" in line and "[" in line:
            try:
                # Extract the port list between brackets
                bracket_start = line.index("[")
                bracket_end = line.index("]")
                port_str = line[bracket_start + 1 : bracket_end]
                for p in port_str.split(","):
                    p = p.strip()
                    if p.isdigit():
                        ports.append(int(p))
            except (ValueError, IndexError):
                continue
    return sorted(set(ports))


def _parse_rustscan_greppable_map(stdout: str) -> Dict[str, List[int]]:
    """
    Parse greppable output into a map of IP -> Ports.

    Format: "192.168.1.1 -> [80,443]"
    """
    result: Dict[str, List[int]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "->" in line and "[" in line:
            try:
                # Split "IP -> [ports]"
                parts = line.split("->")
                ip_str = parts[0].strip()

                # Extract ports
                bracket_start = line.index("[")
                bracket_end = line.index("]")
                port_str = line[bracket_start + 1 : bracket_end]

                host_ports = []
                for p in port_str.split(","):
                    p = p.strip()
                    if p.isdigit():
                        host_ports.append(int(p))

                if host_ports:
                    result[ip_str] = sorted(list(set(host_ports)))
            except (ValueError, IndexError):
                continue
    return result


def run_rustscan_multi(
    targets: List[str],
    *,
    ports: Optional[List[int]] = None,
    ulimit: int = 5000,
    timeout: float = 120.0,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Tuple[Dict[str, List[int]], Optional[str]]:
    """
    Run RustScan on multiple targets and return IP->Ports map.

    Args:
        targets: List of IPs or CIDRs
        ports: Optional list of ports to scan
        ...

    Returns:
        Tuple of (Map{ip: [ports]}, error message or None)
    """
    if not is_rustscan_available():
        return {}, "RustScan not installed"

    if not targets:
        return {}, "No targets provided"

    # RustScan supports commas for targets: -a ip1,ip2,cidr1
    target_str = ",".join(targets)

    cmd = [
        "rustscan",
        "-a",
        target_str,
        "--ulimit",
        str(ulimit),
    ]

    if ports:
        port_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_str])

    cmd.append("-g")  # Greppable output

    runner = _make_runner(logger=logger, dry_run=dry_run, timeout=timeout)

    try:
        res = runner.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            check=False,
            text=True,
        )

        if res.returncode != 0:
            stderr = (res.stderr or "").strip()
            # mypy: res.stderr could be bytes, force str
            stderr_str = (
                stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
            )
            return {}, f"RustScan failed: {stderr_str[:200]}"

        if res.timed_out:
            return {}, f"RustScan timeout after {timeout}s"

        # Parse map
        stdout_val = res.stdout or ""
        if isinstance(stdout_val, bytes):
            stdout_val = stdout_val.decode("utf-8", errors="replace")
        result_map = _parse_rustscan_greppable_map(stdout_val)
        return result_map, None

    except Exception as e:
        return {}, str(e)
