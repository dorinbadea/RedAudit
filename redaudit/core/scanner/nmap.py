#!/usr/bin/env python3
"""
Scanner Nmap Logic - RedAudit
Separated from scanner.py for modularity.
"""

import os
import time
from typing import Dict, List, Optional, Any

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.core.scanner.utils import is_ipv6

_REDAUDIT_REDACT_ENV_KEYS = {"NVD_API_KEY", "GITHUB_TOKEN"}


def _is_dry_run(dry_run: Optional[bool] = None) -> bool:
    if dry_run is not None:
        return bool(dry_run)
    token = os.environ.get("REDAUDIT_DRY_RUN", "")
    return token.strip().lower() in {"1", "true", "yes", "y", "on"}


def _make_runner(
    *,
    logger=None,
    dry_run: Optional[bool] = None,
    timeout: Optional[float] = None,
    command_wrapper=None,
) -> CommandRunner:
    return CommandRunner(
        logger=logger,
        dry_run=_is_dry_run(dry_run),
        default_timeout=timeout,
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys=_REDAUDIT_REDACT_ENV_KEYS,
        command_wrapper=command_wrapper,
    )


def get_nmap_arguments(mode: str, config: Optional[Dict] = None) -> str:
    """
    Get nmap arguments for the specified scan mode.
    """
    # v3.2.3: Support stealth mode with different timing templates
    timing = config.get("nmap_timing", "T4") if config else "T4"
    args = {
        "rapido": f"-sn -{timing} --max-retries 1 --host-timeout 10s",
        "normal": f"-{timing} -F -sV --version-intensity 5 --host-timeout 60s --open",
        # v4.1: -A includes -sV -sC -O, removed redundant flags
        "completo": f"-{timing} -p- -A --version-intensity 9 --host-timeout 300s --max-retries 1",
    }
    return args.get(mode, args["normal"])


def get_nmap_arguments_for_target(mode: str, target: str) -> str:
    """
    Get nmap arguments for a specific target, adding -6 flag for IPv6.
    """
    base_args = get_nmap_arguments(mode)

    # Check if target is IPv6
    target_ip = target.split("/")[0] if "/" in target else target
    if is_ipv6(target_ip):
        return f"-6 {base_args}"

    return base_args


def run_nmap_command(
    cmd: List[str],
    timeout: int,
    host_ip: str,
    deep_obj: Dict,
    print_fn=None,
    t_fn=None,
    *,
    logger=None,
    dry_run: bool = False,
    proxy_manager=None,
    max_stdout: Optional[int] = 8000,
    max_stderr: Optional[int] = 2000,
    include_full_output: bool = False,
) -> Dict:
    """
    Run a single nmap command and collect output.
    """
    start = time.time()
    record: Dict[str, Any] = {"command": " ".join(cmd)}

    runner = _make_runner(
        logger=logger,
        dry_run=dry_run,
        timeout=float(timeout),
        command_wrapper=get_proxy_command_wrapper(proxy_manager),
    )
    res = runner.run(cmd, timeout=float(timeout), capture_output=True, check=False, text=True)

    duration = time.time() - start
    record["returncode"] = res.returncode
    stdout = res.stdout or ""
    stderr = res.stderr or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    stdout_text = str(stdout)
    stderr_text = str(stderr)
    if include_full_output:
        record["stdout_full"] = stdout_text
        record["stderr_full"] = stderr_text
    if max_stdout is None:
        record["stdout"] = stdout_text
    elif max_stdout <= 0:
        record["stdout"] = ""
    else:
        record["stdout"] = stdout_text[:max_stdout]
    if max_stderr is None:
        record["stderr"] = stderr_text
    elif max_stderr <= 0:
        record["stderr"] = ""
    else:
        record["stderr"] = stderr_text[:max_stderr]
    record["duration_seconds"] = round(duration, 2)
    if res.timed_out:
        record["error"] = f"Timeout after {timeout}s"

    deep_obj.setdefault("commands", []).append(record)
    return record
