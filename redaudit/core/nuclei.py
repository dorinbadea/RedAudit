#!/usr/bin/env python3
"""
RedAudit - Nuclei Integration Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.6: Nuclei template scanner integration for enhanced vulnerability detection.
"""

import os
import json
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Protocol, TypedDict, cast

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.utils.dry_run import is_dry_run
from redaudit.core.verify_vuln import check_nuclei_false_positive


class NucleiProgressCallback(Protocol):
    def __call__(self, completed: float, total: int, eta: str, detail: str = "") -> None:
        pass


_NUCLEI_HELP_CACHE: Optional[str] = None


def _get_nuclei_help_text(runner: CommandRunner) -> str:
    global _NUCLEI_HELP_CACHE
    if _NUCLEI_HELP_CACHE is not None:
        return _NUCLEI_HELP_CACHE
    try:
        res = runner.run(["nuclei", "-h"], capture_output=True, text=True, timeout=5.0)
        stdout = (
            res.stdout.decode("utf-8", errors="replace")
            if isinstance(res.stdout, bytes)
            else str(res.stdout or "")
        )
        stderr = (
            res.stderr.decode("utf-8", errors="replace")
            if isinstance(res.stderr, bytes)
            else str(res.stderr or "")
        )
        _NUCLEI_HELP_CACHE = f"{stdout}\n{stderr}".strip()
    except Exception:
        _NUCLEI_HELP_CACHE = ""
    return _NUCLEI_HELP_CACHE


def _nuclei_supports_flag(flag: str, runner: CommandRunner) -> bool:
    text = _get_nuclei_help_text(runner)
    if not text:
        return False
    return flag in text


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


# v4.11.0: Nuclei scan profile configurations
# v4.12.1: Added rate_limit and batch_size per profile for performance tuning


class NucleiProfileConfig(TypedDict, total=False):
    """Type definition for nuclei profile configuration."""

    severity: str
    tags: Optional[str]
    rate_limit: int
    batch_size: int


NUCLEI_PROFILES: Dict[str, NucleiProfileConfig] = {
    "full": {
        "severity": "low,medium,high,critical",
        "tags": None,  # All templates
        "rate_limit": 100,  # Conservative for full scan
        "batch_size": 10,
    },
    "balanced": {
        "severity": "medium,high,critical",
        "tags": "cve,default-login,exposure,misconfig",  # Core security templates
        "rate_limit": 150,  # Balanced speed
        "batch_size": 10,
    },
    "fast": {
        "severity": "high,critical",
        "tags": "cve",  # Only CVE templates
        "rate_limit": 300,  # v4.12.1: Higher rate for speed
        "batch_size": 15,  # v4.12.1: Larger batches for speed
    },
}


def run_nuclei_scan(
    targets: List[str],
    output_dir: str,
    *,
    severity: str = "medium,high,critical",
    templates: Optional[str] = None,
    rate_limit: int = 150,
    timeout: int = 600,  # v4.11.0: Increased default from 300s to 600s
    batch_size: int = 10,  # v4.11.0: Decreased default from 25 to 10
    request_timeout: Optional[int] = None,
    retries: Optional[int] = None,
    progress_callback: Optional[NucleiProgressCallback] = None,
    use_internal_progress: bool = True,
    logger=None,
    dry_run: bool = False,
    print_status=None,
    proxy_manager=None,
    profile: str = "balanced",  # v4.11.0: Scan profile (full/balanced/fast)
    max_runtime_s: Optional[int] = None,
    append_output: bool = False,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run Nuclei scan against HTTP/HTTPS targets.

    Args:
        targets: List of URLs (e.g., ["http://192.168.1.1:80", "https://192.168.1.1:443"])
        output_dir: Directory to save nuclei JSON output
        severity: Comma-separated severity levels (default: medium,high,critical)
        templates: Path to custom templates directory (optional)
        rate_limit: Requests per second (default: 150)
        timeout: Scan timeout in seconds (default: 600)
        batch_size: Targets per batch (default: 10)
        request_timeout: Per-request timeout in seconds (optional)
        retries: Request retries (optional)
        logger: Optional logger
        dry_run: If True, print command but don't execute
        print_status: Optional status print function
        profile: Scan profile - 'full', 'balanced', or 'fast' (default: balanced)
        max_runtime_s: Optional max runtime budget in seconds (None/unset = unlimited)
        append_output: If True, append to existing output file instead of truncating
        output_file: Optional explicit output file path for nuclei JSONL

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
        "partial": False,
        "timeout_batches": [],
        "failed_batches": [],
        "pending_targets": [],
        "budget_exceeded": False,
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
    output_file = output_file or os.path.join(output_dir, "nuclei_output.json")

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
        request_timeout_s = (
            int(request_timeout) if isinstance(request_timeout, int) and request_timeout > 0 else 10
        )
        if request_timeout_s < 3:
            request_timeout_s = 3
        if request_timeout_s > 60:
            request_timeout_s = 60
        retries_val = int(retries) if isinstance(retries, int) and retries >= 0 else 1
        if retries_val > 3:
            retries_val = 3

        # v4.12.1: Load profile config early to get rate_limit and batch_size
        # Explicit parameters override profile defaults for testing/customization
        profile_config = NUCLEI_PROFILES.get(profile, NUCLEI_PROFILES["balanced"])
        profile_rate = profile_config.get("rate_limit") or 150
        profile_batch = profile_config.get("batch_size") or 10
        # If caller passed explicit values different from defaults, use them
        effective_rate_limit: int = rate_limit if rate_limit != 150 else int(profile_rate)
        effective_batch_size: int = batch_size if batch_size != 10 else int(profile_batch)

        # v4.6.24: Smaller batches = fewer timeouts, faster completion
        # v4.12.1: Now uses profile-specific batch_size
        size = int(effective_batch_size) if isinstance(effective_batch_size, int) else 10
        if size < 1:
            size = 10
        batches = [targets[i : i + size] for i in range(0, len(targets), size)]
        total_batches = len(batches)
        total_targets = len(targets)
        completed_targets = 0.0
        max_progress_targets = 0.0
        # v4.6.25: Lock for shared resources (file I/O, stats) in parallel mode
        scan_lock = threading.Lock()
        active_batch_progress: Dict[int, float] = {}  # Track partial progress per batch
        max_split_depth = 6

        def _estimate_batch_timeout(
            batch_targets: List[str],
            *,
            split_depth: int = 0,
            retry_attempt: int = 0,
        ) -> float:
            base_timeout = float(timeout) if isinstance(timeout, (int, float)) else 600.0
            target_budget = float(request_timeout_s) * len(batch_targets) * 2
            min_timeout_s = max(60.0, float(request_timeout_s) * 2.0)
            if split_depth == 0:
                min_timeout_s = max(min_timeout_s, 300.0)
            batch_timeout_s = max(min_timeout_s, target_budget)
            if base_timeout > 0:
                batch_timeout_s = max(batch_timeout_s, base_timeout)
            if retry_attempt > 0:
                batch_timeout_s = batch_timeout_s * 1.5
            return batch_timeout_s

        def _build_cmd(
            targets_path: str,
            out_path: str,
            rate_limit_override: Optional[int],
        ) -> List[str]:
            # v4.12.1: Use profile-specific rate_limit as default
            effective_rate = (
                int(rate_limit_override)
                if isinstance(rate_limit_override, int) and rate_limit_override > 0
                else int(effective_rate_limit)
            )
            # v4.11.0: Apply profile-based severity and tags (profile_config from outer scope)
            effective_severity: str = str(profile_config.get("severity") or severity)
            profile_tags = profile_config.get("tags")

            cmd = [
                "nuclei",
                "-l",
                targets_path,
                "-o",
                out_path,
                "-jsonl",  # JSON Lines format
                "-severity",
                effective_severity,
                "-rate-limit",
                str(effective_rate),
                "-silent",  # Reduce noise
                "-nc",  # No color
            ]
            # v4.11.0: Add tag filtering for balanced/fast profiles
            if profile_tags and _nuclei_supports_flag("-tags", runner):
                cmd.extend(["-tags", profile_tags])
            timeout_flag = None
            if request_timeout_s > 0:
                if _nuclei_supports_flag("-timeout", runner):
                    timeout_flag = "-timeout"
                elif _nuclei_supports_flag("--timeout", runner):
                    timeout_flag = "--timeout"
            if timeout_flag:
                cmd.extend([timeout_flag, str(request_timeout_s)])
            retries_flag = None
            if retries_val >= 0:
                if _nuclei_supports_flag("-retries", runner):
                    retries_flag = "-retries"
                elif _nuclei_supports_flag("--retries", runner):
                    retries_flag = "--retries"
            if retries_flag:
                cmd.extend([retries_flag, str(retries_val)])
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

        def _emit_progress(completed: float, total: int, eta: str, detail: str = "") -> None:
            if progress_callback is None:
                return
            try:
                progress_callback(completed, total, eta, detail)
            except TypeError:
                try:
                    legacy_cb = cast(Callable[[float, int, str], None], progress_callback)
                    legacy_cb(completed, total, eta)
                except Exception:
                    pass
            except Exception:
                pass

        if print_status:
            print_status(
                f"[nuclei] scanning {len(targets)} targets in {total_batches} batch(es)...",
                "INFO",
            )

        # Ensure output_file exists before appending batch outputs.
        try:
            if append_output:
                if not os.path.exists(output_file):
                    with open(output_file, "w", encoding="utf-8") as f_out:
                        f_out.write("")
            else:
                with open(output_file, "w", encoding="utf-8") as f_out:
                    f_out.write("")
        except Exception as e:
            result["error"] = f"Failed to create nuclei output file: {e}"
            return result

        batch_durations: List[float] = []

        timed_out_batches: set[int] = set()
        failed_batches: set[int] = set()

        def _run_one_batch(
            batch_idx: int,
            batch_targets: List[str],
            *,
            allow_retry: bool = True,
            rate_limit_override: Optional[int] = None,
            split_depth: int = 0,
            retry_attempt: int = 0,  # v4.6.23: Simple retry before split
            budget_deadline: Optional[float] = None,
        ) -> bool:
            nonlocal completed_targets, max_progress_targets
            batch_start = time.time()
            if budget_deadline is not None and batch_start >= budget_deadline:
                return True
            # v4.7.2: Increased default timeout to 600s and minimum from 60s to 300s
            # 60s was causing 100% batch timeout rate on medium-sized networks
            batch_timeout_s = _estimate_batch_timeout(
                batch_targets,
                split_depth=split_depth,
                retry_attempt=retry_attempt,
            )
            budget_cap_active = False
            if budget_deadline is not None:
                remaining_budget = budget_deadline - time.time()
                if remaining_budget <= 0:
                    return True
                if remaining_budget < batch_timeout_s:
                    batch_timeout_s = max(1.0, remaining_budget)
                    budget_cap_active = True

            with tempfile.TemporaryDirectory(prefix="nuclei_tmp_", dir=output_dir) as tmpdir:
                batch_targets_file = os.path.join(tmpdir, f"targets_{batch_idx}.txt")
                batch_output_file = os.path.join(tmpdir, f"output_{batch_idx}.json")

                with open(batch_targets_file, "w", encoding="utf-8") as f_targets:
                    for t in batch_targets:
                        f_targets.write(f"{t}\n")

                cmd = _build_cmd(batch_targets_file, batch_output_file, rate_limit_override)
                res_holder: Dict[str, Any] = {}
                err_holder: Dict[str, BaseException] = {}

                def _execute() -> None:
                    try:
                        res_holder["res"] = runner.run(
                            cmd, capture_output=True, text=True, timeout=batch_timeout_s
                        )
                    except BaseException as exc:
                        err_holder["exc"] = exc

                if progress_callback is not None:
                    done = threading.Event()

                    def _execute_with_flag() -> None:
                        try:
                            _execute()
                        finally:
                            done.set()

                    worker = threading.Thread(target=_execute_with_flag, daemon=True)
                    worker.start()
                    heartbeat_s = 2.0
                    try:
                        while not done.wait(timeout=heartbeat_s):
                            elapsed = time.time() - batch_start
                            timeout_s = max(1.0, float(batch_timeout_s))
                            frac = min(elapsed / timeout_s, 0.95)
                            current_local = completed_targets + (frac * len(batch_targets))
                            current_local = max(0.0, current_local)

                            # Update shared progress view
                            with scan_lock:
                                active_batch_progress[batch_idx] = frac * len(batch_targets)
                                # Aggregate total progress from all workers
                                aggregated_current = completed_targets + sum(
                                    active_batch_progress.values()
                                )
                                max_progress_targets = max(max_progress_targets, aggregated_current)
                                final_display_val = max_progress_targets

                            eta_batch = _format_eta(max(0.0, timeout_s - elapsed))
                            active_count = len(active_batch_progress)
                            if max_parallel > 1 and total_batches > 1:
                                detail = (
                                    f"parallel batches {active_count}/{total_batches} running "
                                    f"{_format_eta(elapsed)} elapsed"
                                )
                            else:
                                detail = (
                                    f"batch {batch_idx}/{total_batches} running "
                                    f"{_format_eta(elapsed)} elapsed"
                                )
                            eta_label = f"ETA≈ {eta_batch}" if eta_batch != "--:--" else ""
                            _emit_progress(final_display_val, total_targets, eta_label, detail)
                    except KeyboardInterrupt:
                        # v4.6.34: Handle Ctrl+C gracefully
                        if logger:
                            logger.warning("Nuclei batch (thread) interrupted via Ctrl+C")
                        # Try to kill the runner if possible
                        try:
                            runner.run(["pkill", "-f", "nuclei"], check=False, timeout=2.0)
                        except Exception:
                            pass
                        raise

                    if err_holder.get("exc"):
                        raise err_holder["exc"]
                    res = res_holder.get("res")
                else:
                    _execute()
                    if err_holder.get("exc"):
                        raise err_holder["exc"]
                    res = res_holder.get("res")

                if res is None:
                    raise RuntimeError("Nuclei batch did not return a result")
                timed_out = bool(getattr(res, "timed_out", False))
                budget_exceeded = bool(timed_out and budget_cap_active)
                if timed_out:
                    if not budget_exceeded:
                        # v4.6.24: Split immediately on timeout (no extended retry)
                        # This avoids the infinite retry loop bug
                        # If retry also timed out, try splitting
                        if allow_retry and len(batch_targets) > 1 and split_depth < max_split_depth:
                            mid = max(1, len(batch_targets) // 2)
                            reduced_rate = max(25, int((rate_limit_override or rate_limit) / 2))
                            _run_one_batch(
                                batch_idx,
                                batch_targets[:mid],
                                allow_retry=True,
                                rate_limit_override=reduced_rate,
                                split_depth=split_depth + 1,
                                retry_attempt=0,
                            )
                            _run_one_batch(
                                batch_idx,
                                batch_targets[mid:],
                                allow_retry=True,
                                rate_limit_override=reduced_rate,
                                split_depth=split_depth + 1,
                                retry_attempt=0,
                            )
                            return False
                        with scan_lock:
                            timed_out_batches.add(batch_idx)
                            failed_batches.add(batch_idx)

                # Append JSONL output to the consolidated file, if present.
                # Copy partial output unless we timed out AND will actually retry.
                can_retry = (
                    allow_retry
                    and len(batch_targets) > 1
                    and split_depth < max_split_depth
                    and not budget_exceeded
                )
                if os.path.exists(batch_output_file) and not (timed_out and can_retry):
                    with scan_lock:
                        if os.path.exists(batch_output_file):
                            with (
                                open(
                                    batch_output_file, "r", encoding="utf-8", errors="ignore"
                                ) as fin,
                                open(output_file, "a", encoding="utf-8") as fout,
                            ):
                                for line in fin:
                                    if line.strip():
                                        fout.write(line if line.endswith("\n") else line + "\n")

                if res.stderr and "error" in str(res.stderr).lower() and not result["error"]:
                    result["error"] = str(res.stderr)[:500]

            with scan_lock:
                batch_durations.append(time.time() - batch_start)
                # Remove from active progress as it is now fully in completed_targets
                active_batch_progress.pop(batch_idx, None)
                if not budget_exceeded:
                    completed_targets += len(batch_targets)
                    if completed_targets > max_progress_targets:
                        max_progress_targets = completed_targets

            if budget_exceeded:
                return True
            return False

        max_parallel = min(4, max(1, len(batches)))  # Up to 4 parallel batches
        try:
            timeout_val = float(timeout)
        except Exception:
            timeout_val = None
        if timeout_val is not None and timeout_val >= 900 and max_parallel > 2:
            max_parallel = 2
            if logger:
                logger.info(
                    "Nuclei parallelism clamped to %d for long batch timeouts",
                    max_parallel,
                )

        try:
            runtime_budget_s = (
                int(max_runtime_s) if isinstance(max_runtime_s, int) and max_runtime_s > 0 else None
            )
        except Exception:
            runtime_budget_s = None
        if print_status and runtime_budget_s is not None:
            print_status("[nuclei] runtime budget enabled; running batches sequentially", "INFO")
        budget_start = time.time()
        budget_deadline = budget_start + runtime_budget_s if runtime_budget_s else None
        force_sequential = runtime_budget_s is not None

        if progress_callback is not None and not force_sequential:
            # v4.6.24: Parallel batch execution with ThreadPoolExecutor
            from concurrent.futures import ThreadPoolExecutor, as_completed

            batch_lock = threading.Lock()

            def _run_batch_wrapper(idx_batch):
                idx, batch = idx_batch
                _run_one_batch(idx, batch)
                return idx

            completed_batches = 0
            with ThreadPoolExecutor(max_workers=max_parallel) as executor:
                futures = {
                    executor.submit(_run_batch_wrapper, (idx, batch)): idx
                    for idx, batch in enumerate(batches, start=1)
                }
                for future in as_completed(futures):
                    try:
                        future.result()
                        completed_batches += 1
                        with batch_lock:
                            avg = (
                                (sum(batch_durations) / len(batch_durations))
                                if batch_durations
                                else 0.0
                            )
                        remaining = max(0, total_batches - completed_batches)
                        eta = _format_eta(avg * remaining) if avg > 0 else "--:--"
                        _emit_progress(
                            min(float(total_targets), max_progress_targets),
                            total_targets,
                            f"ETA≈ {eta}",
                            f"batches {completed_batches}/{total_batches} complete",
                        )
                    except Exception as e:
                        if logger:
                            logger.warning("Nuclei batch failed: %s", e)
        elif use_internal_progress and not force_sequential:
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

                    # v4.6.25: Parallel execution for CLI (Rich) too
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    batch_lock = threading.Lock()

                    def _run_batch_wrapper(idx_batch):
                        idx, batch = idx_batch
                        _run_one_batch(idx, batch)
                        return idx

                    completed_batches = 0
                    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
                        futures = {
                            executor.submit(_run_batch_wrapper, (idx, batch)): idx
                            for idx, batch in enumerate(batches, start=1)
                        }
                        for future in as_completed(futures):
                            future.result()
                            completed_batches += 1
                            with batch_lock:
                                avg = (
                                    (sum(batch_durations) / len(batch_durations))
                                    if batch_durations
                                    else 0.0
                                )
                            remaining = max(0, total_batches - completed_batches)
                            eta = _format_eta(avg * remaining) if avg > 0 else "--:--"
                            progress.update(
                                task,
                                advance=1,
                                description=f"[cyan]Nuclei ({completed_batches}/{total_batches})",
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
                if runtime_budget_s is not None:
                    elapsed = time.time() - budget_start
                    remaining_budget = runtime_budget_s - elapsed
                    if remaining_budget <= 0:
                        remaining_targets_budget: List[str] = []
                        for remain_batch in batches[idx - 1 :]:
                            remaining_targets_budget.extend(remain_batch)
                        result["pending_targets"] = remaining_targets_budget
                        result["targets_scanned"] = len(targets) - len(remaining_targets_budget)
                        result["budget_exceeded"] = True
                        result["partial"] = True
                        break
                    expected_batch_timeout = _estimate_batch_timeout(batch)
                    if remaining_budget < expected_batch_timeout:
                        if print_status:
                            print_status(
                                "[nuclei] budget too low for next batch; deferring remaining targets",
                                "INFO",
                            )
                        remaining_targets_budget = []
                        for remain_batch in batches[idx - 1 :]:
                            remaining_targets_budget.extend(remain_batch)
                        result["pending_targets"] = remaining_targets_budget
                        result["targets_scanned"] = max(0, int(max_progress_targets))
                        result["budget_exceeded"] = True
                        result["partial"] = True
                        break
                if print_status:
                    print_status(
                        f"[nuclei] batch {idx}/{total_batches} ({len(batch)} targets)", "INFO"
                    )
                budget_exceeded = _run_one_batch(idx, batch, budget_deadline=budget_deadline)
                if budget_exceeded:
                    remaining_targets_mid: List[str] = []
                    for remain_batch in batches[idx - 1 :]:
                        remaining_targets_mid.extend(remain_batch)
                    result["pending_targets"] = remaining_targets_mid
                    scanned_floor = max(0, len(targets) - len(remaining_targets_mid))
                    result["targets_scanned"] = max(scanned_floor, int(max_progress_targets))
                    result["budget_exceeded"] = True
                    result["partial"] = True
                    break

        if os.path.exists(output_file):
            result["findings"] = _parse_nuclei_output(output_file, logger)

        if timed_out_batches:
            result["partial"] = True
            result["timeout_batches"] = sorted(timed_out_batches)
        if failed_batches:
            result["failed_batches"] = sorted(failed_batches)
            if not result.get("error"):
                result["error"] = "timeout"

        # v4.11.0: Success if we have findings, even if some batches failed
        # Previously: result["success"] = os.path.exists(output_file) and not failed_batches
        findings_list = result.get("findings") or []
        result["success"] = os.path.exists(output_file) and (
            not failed_batches or bool(findings_list)
        )
        result["raw_output_file"] = output_file if os.path.exists(output_file) else None

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
        # v4.13.2: Extract additional rich fields
        "impact": info.get("impact", ""),
        "remediation": info.get("remediation", ""),
        "cvss_score": info.get("classification", {}).get("cvss-score") or 0,
        "cvss_metrics": info.get("classification", {}).get("cvss-metrics", ""),
        "host": raw.get("host", ""),
        "matched_at": raw.get("matched-at", raw.get("matchedAt", "")),
        "matcher_name": raw.get("matcher-name", raw.get("matcherName", "")),
        "curl_command": raw.get("curl-command", ""),
        "reference": info.get("reference", []),
        "tags": info.get("tags", []),
        "cve_ids": _extract_cve_ids(info),
        # v4.13.2: Include extracted results for evidence display
        "extracted_results": raw.get("extracted-results") or raw.get("extractedResults") or [],
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
