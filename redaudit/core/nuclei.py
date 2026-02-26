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
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    TypedDict,
    cast,
)

from redaudit.core.command_runner import CommandRunner
from redaudit.core.proxy import get_proxy_command_wrapper
from redaudit.utils.dry_run import is_dry_run
from redaudit.utils.i18n import get_text
from redaudit.core.verify_vuln import check_nuclei_false_positive


class NucleiProgressCallback(Protocol):
    def __call__(self, completed: float, total: int, eta: str, detail: str = "") -> None:
        pass


class NucleiStatusCallback(Protocol):
    def __call__(
        self,
        message: str,
        status: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
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
    status_callback: Optional[NucleiStatusCallback] = None,
    proxy_manager=None,
    profile: str = "balanced",  # v4.11.0: Scan profile (full/balanced/fast)
    max_runtime_s: Optional[int] = None,
    append_output: bool = False,
    output_file: Optional[str] = None,
    targets_file: Optional[str] = None,
    exception_targets: Optional[Set[str]] = None,
    fatigue_limit: Optional[int] = None,
    translate: Optional[Callable[..., str]] = None,
    lang: str = "en",
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
        targets_file: Optional path to persist the target list (defaults to nuclei_targets.txt)
        exception_targets: Optional set of targets eligible for retries/splitting on timeout
        fatigue_limit: Optional max split depth for exception targets (None = default)
        translate: Optional translation function (e.g., UIManager.t)
        lang: Language code for fallback translations (default: en)

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

    def _t(key: str, *args) -> str:
        if translate:
            try:
                return str(translate(key, *args))
            except Exception:
                pass
        return get_text(key, lang, *args)

    def _emit_status(
        message: str,
        status: str = "INFO",
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if status_callback:
            try:
                status_callback(message, status, metadata or {})
                return
            except TypeError:
                try:
                    status_callback(message, status)
                    return
                except Exception:
                    pass
            except Exception:
                pass
        if print_status:
            print_status(message, status)

    if not result["nuclei_available"]:
        result["error"] = "nuclei not installed"
        return result

    if not targets:
        result["error"] = "no targets provided"
        return result

    if dry_run or is_dry_run():
        _emit_status(_t("nuclei_dry_run_skipped"), "INFO")
        result["success"] = True
        result["error"] = "dry-run mode"
        return result

    # Create targets file for nuclei
    os.makedirs(output_dir, exist_ok=True)
    if targets_file:
        if not os.path.isabs(targets_file):
            targets_file = os.path.join(output_dir, targets_file)
    else:
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
        exception_set = set(exception_targets) if exception_targets is not None else None
        if exception_set is not None:
            exception_list = [t for t in targets if t in exception_set]
            optimized_list = [t for t in targets if t not in exception_set]
            exception_batches = [
                exception_list[i : i + size] for i in range(0, len(exception_list), size)
            ]
            optimized_batches = [
                optimized_list[i : i + size] for i in range(0, len(optimized_list), size)
            ]
            batches = exception_batches + optimized_batches
            batch_retry_flags = [True] * len(exception_batches) + [False] * len(optimized_batches)
        else:
            batches = [targets[i : i + size] for i in range(0, len(targets), size)]
            batch_retry_flags = [True] * len(batches)
        total_batches = len(batches)
        total_targets = len(targets)
        completed_targets = 0.0
        max_progress_targets = 0.0
        # v4.6.25: Lock for shared resources (file I/O, stats) in parallel mode
        scan_lock = threading.Lock()
        active_batch_progress: Dict[int, float] = {}  # Track partial progress per batch
        max_split_depth = 6
        if fatigue_limit is not None:
            try:
                max_split_depth = max(0, int(fatigue_limit))
            except Exception:
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
            if retry_attempt > 0:  # pragma: no cover
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
            except Exception:  # pragma: no cover
                return "--:--"
            h = sec // 3600
            m = (sec % 3600) // 60
            s = sec % 60
            return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"

        def _emit_progress(completed: float, total: int, eta: str, detail: str = "") -> None:
            if progress_callback is None:  # pragma: no cover
                return
            try:
                progress_callback(completed, total, eta, detail)
            except TypeError:  # pragma: no cover
                try:
                    legacy_cb = cast(Callable[[float, int, str], None], progress_callback)
                    legacy_cb(completed, total, eta)
                except Exception:
                    pass
            except Exception:  # pragma: no cover
                pass

        _emit_status(
            _t("nuclei_scanning_batches", len(targets), total_batches),
            "INFO",
            metadata={
                "event": "nuclei_scan_start",
                "targets": len(targets),
                "batches": total_batches,
            },
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
        timeout_targets: set[str] = set()

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
            if budget_deadline is not None and batch_start >= budget_deadline:  # pragma: no cover
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
                if remaining_budget <= 0:  # pragma: no cover
                    return True
                if remaining_budget < batch_timeout_s:  # pragma: no cover
                    batch_timeout_s = max(1.0, remaining_budget)
                    budget_cap_active = True
            retry_suffix = _format_retry_suffix(split_depth, retry_attempt, max_split_depth, _t)

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
                            if not force_sequential and max_parallel > 1 and total_batches > 1:
                                detail = _t(
                                    "nuclei_detail_parallel_running",
                                    active_count,
                                    total_batches,
                                    _format_eta(elapsed),
                                )
                            else:
                                detail = _t(
                                    "nuclei_detail_batch_running",
                                    batch_idx,
                                    total_batches,
                                    _format_eta(elapsed),
                                )
                            if retry_suffix:
                                detail = f"{detail}{retry_suffix}"
                            eta_label = f"ETA≈ {eta_batch}" if eta_batch != "--:--" else ""
                            _emit_progress(final_display_val, total_targets, eta_label, detail)
                    except KeyboardInterrupt:  # pragma: no cover
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
                    host_list, port_list = _summarize_batch_targets(batch_targets)
                    if host_list or port_list:
                        detail = _t(
                            "nuclei_timeout_targets",
                            host_list or "-",
                            port_list or "-",
                        )
                        _emit_status(
                            _t("nuclei_timeout_detail", batch_idx, total_batches, detail),
                            "WARNING",
                            metadata={
                                "event": "nuclei_timeout",
                                "batch_idx": int(batch_idx),
                                "total_batches": int(total_batches),
                                "detail": detail,
                                "host_list": host_list or "-",
                                "port_list": port_list or "-",
                                "split_depth": int(split_depth),
                                "retry_attempt": int(retry_attempt),
                            },
                        )
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
                            timeout_targets.update(batch_targets)

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

            if budget_exceeded:  # pragma: no cover
                return True
            return False

        max_parallel = min(4, max(1, len(batches)))  # Up to 4 parallel batches
        try:
            timeout_val = float(timeout)
        except Exception:  # pragma: no cover
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
        except Exception:  # pragma: no cover
            runtime_budget_s = None
        if runtime_budget_s is not None:
            _emit_status(_t("nuclei_runtime_budget_enabled"), "INFO")
        budget_start = time.time()
        budget_deadline = budget_start + runtime_budget_s if runtime_budget_s else None
        force_sequential = runtime_budget_s is not None

        if progress_callback is not None and not force_sequential:
            # v4.6.24: Parallel batch execution with ThreadPoolExecutor
            from concurrent.futures import ThreadPoolExecutor, as_completed

            batch_lock = threading.Lock()

            def _run_batch_wrapper(idx_batch):
                idx, batch, can_retry = idx_batch
                _run_one_batch(idx, batch, allow_retry=bool(can_retry))
                return idx

            completed_batches = 0
            with ThreadPoolExecutor(max_workers=max_parallel) as executor:
                futures = {
                    executor.submit(
                        _run_batch_wrapper,
                        (idx, batch, batch_retry_flags[idx - 1]),
                    ): idx
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
                            _t(
                                "nuclei_detail_batches_complete",
                                completed_batches,
                                total_batches,
                            ),
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
                        idx, batch, can_retry = idx_batch
                        _run_one_batch(idx, batch, allow_retry=bool(can_retry))
                        return idx

                    completed_batches = 0
                    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
                        futures = {
                            executor.submit(
                                _run_batch_wrapper,
                                (idx, batch, batch_retry_flags[idx - 1]),
                            ): idx
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
                    _emit_status(
                        _t("nuclei_batch_status", idx, total_batches, len(batch)),
                        "INFO",
                        metadata={
                            "event": "nuclei_batch_status",
                            "batch_idx": int(idx),
                            "total_batches": int(total_batches),
                            "batch_targets": len(batch),
                        },
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
                        _emit_status(
                            _t("nuclei_budget_too_low"),
                            "INFO",
                            metadata={
                                "event": "nuclei_budget_too_low",
                                "batch_idx": int(idx),
                                "total_batches": int(total_batches),
                            },
                        )
                        remaining_targets_budget = []
                        for remain_batch in batches[idx - 1 :]:
                            remaining_targets_budget.extend(remain_batch)
                        result["pending_targets"] = remaining_targets_budget
                        result["targets_scanned"] = max(0, int(max_progress_targets))
                        result["budget_exceeded"] = True
                        result["partial"] = True
                        break
                _emit_status(
                    _t("nuclei_batch_status", idx, total_batches, len(batch)),
                    "INFO",
                    metadata={
                        "event": "nuclei_batch_status",
                        "batch_idx": int(idx),
                        "total_batches": int(total_batches),
                        "batch_targets": len(batch),
                    },
                )
                budget_exceeded = _run_one_batch(
                    idx,
                    batch,
                    allow_retry=bool(batch_retry_flags[idx - 1]),
                    budget_deadline=budget_deadline,
                )
                if budget_exceeded:  # pragma: no cover
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
        if timeout_targets and not result.get("budget_exceeded"):
            ordered_timeout = [t for t in targets if t in timeout_targets]
            result["timeout_targets"] = ordered_timeout
            if not result.get("pending_targets"):
                result["pending_targets"] = ordered_timeout

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


def get_http_targets_by_host(hosts: List[Dict]) -> Dict[str, List[str]]:
    """
    Extract HTTP/HTTPS URLs grouped by host IP.

    Returns:
        Dict mapping IP -> list of URLs (deduped, stable order).
    """
    # Common HTTPS ports beyond 443
    HTTPS_PORTS = {443, 8443, 4443, 9443, 49443}
    targets_by_host: Dict[str, List[str]] = {}
    seen_by_host: Dict[str, set] = {}

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

            if not port_info.get("is_web_service"):
                continue

            service = str(port_info.get("service", "")).lower()
            if port in HTTPS_PORTS or "https" in service or "ssl" in service:
                url = f"https://{ip}:{port}"
            else:
                url = f"http://{ip}:{port}"

            host_list = targets_by_host.setdefault(ip, [])
            host_seen = seen_by_host.setdefault(ip, set())
            if url not in host_seen:
                host_list.append(url)
                host_seen.add(url)

    return targets_by_host


def _parse_target_port(url: str) -> int:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.port:
            return int(parsed.port)
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
    except Exception:
        return 0
    return 0


def _parse_target_host(url: str) -> str:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.hostname:
            return str(parsed.hostname)
    except Exception:
        return ""
    return ""


def _normalize_exclude_patterns(exclude: Optional[Iterable[str]]) -> List[str]:
    patterns: List[str] = []
    if not exclude:
        return patterns
    if isinstance(exclude, str):
        exclude = [exclude]
    for item in exclude:
        if item is None:
            continue
        if not isinstance(item, str):
            item = str(item)
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned:
                patterns.append(cleaned)
    return patterns


def normalize_nuclei_exclude(exclude: Optional[Iterable[str]]) -> List[str]:
    return _normalize_exclude_patterns(exclude)


def _is_target_excluded(target: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    target_clean = target.strip().rstrip("/")
    host = _parse_target_host(target)
    port = _parse_target_port(target)
    host_lower = host.lower() if host else ""
    for raw in patterns:
        pattern = raw.strip()
        if not pattern:
            continue
        if "://" in pattern:
            if target_clean == pattern.rstrip("/"):
                return True
            continue
        candidate = pattern
        candidate_host = candidate
        candidate_port = None
        if ":" in candidate and candidate.count(":") == 1:
            left, right = candidate.rsplit(":", 1)
            if right.isdigit():
                candidate_host = left
                candidate_port = int(right)
        candidate_host_lower = candidate_host.lower()
        if host_lower == candidate_host_lower:
            if candidate_port is None or candidate_port == port:
                return True
    return False


def _summarize_batch_targets(
    batch_targets: List[str], *, max_hosts: int = 3, max_ports: int = 6
) -> Tuple[str, str]:
    if not batch_targets:
        return "", ""
    host_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    for target in batch_targets:
        host = _parse_target_host(target)
        if host:
            host_counts[host] = host_counts.get(host, 0) + 1
        port = _parse_target_port(target)
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1
    host_items = sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))
    port_items = sorted(port_counts.items(), key=lambda item: (-item[1], item[0]))
    host_list = ", ".join(f"{host}({count})" for host, count in host_items[:max_hosts])
    port_list = ", ".join(str(port) for port, _count in port_items[:max_ports])
    return host_list, port_list


def _format_retry_suffix(
    split_depth: int, retry_attempt: int, max_split_depth: int, translate: Callable[..., str]
) -> str:
    parts: List[str] = []
    if retry_attempt > 0:
        parts.append(translate("nuclei_detail_retry", retry_attempt))
    if split_depth > 0:
        parts.append(translate("nuclei_detail_split", split_depth, max_split_depth))
    if not parts:
        return ""
    return " | " + " ".join(parts)


def _is_exception_host(host: Dict[str, Any], identity_threshold: int) -> Tuple[bool, str]:
    smart_scan = host.get("smart_scan") or {}
    trigger_deep = bool(smart_scan.get("trigger_deep"))
    identity_score = smart_scan.get("identity_score")
    threshold = smart_scan.get("identity_threshold")
    try:
        threshold_val = int(threshold) if threshold is not None else int(identity_threshold)
    except Exception:
        threshold_val = int(identity_threshold)

    reasons = smart_scan.get("reasons") or []
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    suspicious = "suspicious_service" in reasons
    low_visibility = any(
        r in reasons for r in ("ghost_identity", "low_visibility", "no_version_info")
    )

    if identity_score is None:
        return True, "identity_missing"
    try:
        identity_val = int(identity_score)
    except Exception:
        identity_val = 0

    identity_weak = identity_val < threshold_val

    if suspicious:
        return True, "suspicious_service"
    if low_visibility:
        return True, "low_visibility"
    if trigger_deep:
        return True, "trigger_deep"
    if identity_weak:
        return True, "identity_weak"
    return False, "identity_strong"


def _limit_targets_for_host(
    urls: List[str],
    *,
    priority_ports: Optional[Set[int]],
    max_targets: Optional[int],
) -> List[str]:
    if max_targets is None:
        return list(urls)
    if max_targets <= 0:
        return []
    if not urls:
        return []
    if not priority_ports:
        return urls[:max_targets]

    priority: List[str] = []
    fallback: List[str] = []
    for url in urls:
        port = _parse_target_port(url)
        if port in priority_ports:
            priority.append(url)
        else:
            fallback.append(url)

    selected: List[str] = []
    for url in priority:
        if url not in selected:
            selected.append(url)
        if len(selected) >= max_targets:
            return selected
    for url in fallback:
        if url not in selected:
            selected.append(url)
        if len(selected) >= max_targets:
            break
    return selected


def select_nuclei_targets(
    hosts: List[Dict[str, Any]],
    *,
    identity_threshold: int,
    priority_ports: Optional[Set[int]] = None,
    max_targets_per_host: Optional[int] = 2,
    exclude_patterns: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Select Nuclei targets using optimization-by-default and resilience-by-exception.

    - Exception hosts (ambiguous identity) receive all web targets.
    - Strong identity hosts are limited to priority ports with a small cap unless max_targets_per_host
      is None (full coverage).
    """
    targets_by_host = get_http_targets_by_host(hosts)
    exception_hosts: Set[str] = set()
    optimized_hosts: Set[str] = set()
    exception_targets: List[str] = []
    optimized_targets: List[str] = []
    selected_by_host: Dict[str, List[str]] = {}
    host_reasons: Dict[str, str] = {}
    exclude_list = _normalize_exclude_patterns(exclude_patterns)
    excluded_targets: Set[str] = set()

    for host in hosts:
        if isinstance(host, dict):
            ip = host.get("ip")
            host_record = host
        else:
            ip = getattr(host, "ip", None)
            host_record = getattr(host, "to_dict", lambda: {})()
        if not ip:
            continue
        urls = targets_by_host.get(ip) or []
        if not urls:
            continue

        is_exception, reason = _is_exception_host(host_record, identity_threshold)
        host_reasons[str(ip)] = reason
        if is_exception:
            exception_hosts.add(str(ip))
            filtered = [url for url in urls if not _is_target_excluded(url, exclude_list)]
            if len(filtered) != len(urls):
                excluded_targets.update({url for url in urls if url not in filtered})
            if not filtered:
                continue
            exception_targets.extend(filtered)
            selected_by_host[str(ip)] = list(filtered)
        else:
            optimized_hosts.add(str(ip))
            limited = _limit_targets_for_host(
                urls,
                priority_ports=priority_ports,
                max_targets=max_targets_per_host,
            )
            filtered = [url for url in limited if not _is_target_excluded(url, exclude_list)]
            if len(filtered) != len(limited):
                excluded_targets.update({url for url in limited if url not in filtered})
            if not filtered:
                continue
            optimized_targets.extend(filtered)
            selected_by_host[str(ip)] = list(filtered)

    targets = exception_targets + optimized_targets
    return {
        "targets": targets,
        "targets_by_host": targets_by_host,
        "selected_by_host": selected_by_host,
        "exception_targets": set(exception_targets),
        "exception_hosts": exception_hosts,
        "optimized_hosts": optimized_hosts,
        "targets_total": sum(len(v) for v in targets_by_host.values()),
        "targets_exception": len(exception_targets),
        "targets_optimized": len(optimized_targets),
        "targets_excluded": len(excluded_targets),
        "host_reasons": host_reasons,
    }
