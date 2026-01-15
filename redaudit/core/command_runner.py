#!/usr/bin/env python3
"""
RedAudit - Centralized Command Runner

Single entry point for external command execution (v3.5).
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class CommandResult:
    args: List[str]
    returncode: int
    stdout: Optional[str | bytes]
    stderr: Optional[str | bytes]
    duration_s: float
    timed_out: bool
    attempts: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandRunner:
    def __init__(
        self,
        *,
        logger: Any = None,
        dry_run: bool = False,
        default_timeout: Optional[float] = 60.0,
        default_retries: int = 0,
        backoff_base_s: float = 0.5,
        redact_env_keys: Optional[Iterable[str]] = None,
        command_wrapper: Optional[Callable[[Sequence[str]], Sequence[str]]] = None,
    ):
        self._logger = logger
        self._dry_run = bool(dry_run)
        self._default_timeout = default_timeout
        self._default_retries = int(default_retries)
        self._backoff_base_s = float(backoff_base_s)
        self._redact_env_keys: Set[str] = {k for k in (redact_env_keys or []) if isinstance(k, str)}
        self._command_wrapper = command_wrapper

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        capture_output: bool = True,
        stdout: Any = None,
        stderr: Any = None,
        check: bool = False,
        text: bool = True,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        cmd = self._validate_args(args)
        cmd = self._apply_command_wrapper(cmd)
        merged_env = self._merge_env(env)
        redact_values = self._collect_redact_values(merged_env)

        if capture_output and (stdout is not None or stderr is not None):
            raise ValueError("stdout/stderr cannot be used with capture_output=True")

        if self._dry_run:
            formatted = self._format_cmd(cmd, redact_values)
            self._log("INFO", f"[dry-run] {formatted}")
            try:
                print(f"[dry-run] {formatted}", flush=True)
            except Exception:
                pass
            empty_out: str | bytes | None
            if not capture_output:
                empty_out = None
            else:
                empty_out = "" if text else b""
            return CommandResult(
                args=list(cmd),
                returncode=0,
                stdout=empty_out,
                stderr=empty_out,
                duration_s=0.0,
                timed_out=False,
                attempts=0,
            )

        attempts = max(1, self._default_retries + 1)
        last_exc: Optional[BaseException] = None
        start_all = time.monotonic()
        for attempt in range(1, attempts + 1):
            try:
                self._log("DEBUG", f"exec: {self._format_cmd(cmd, redact_values)}")
                timeout_val = timeout if timeout is not None else self._default_timeout
                # v4.7.2: Nuclei scans need longer timeout (600s vs 60s default)
                # Nuclei template scans can take several minutes per batch
                if timeout_val == self._default_timeout and cmd and "nuclei" in cmd[0]:
                    timeout_val = 600.0
                completed = subprocess.run(
                    list(cmd),
                    cwd=cwd,
                    env=merged_env,
                    timeout=timeout_val,
                    capture_output=capture_output,
                    stdout=stdout,
                    stderr=stderr,
                    text=text,
                    check=check,
                    input=input_text if input_text is not None else None,
                )
                elapsed = time.monotonic() - start_all
                stdout_raw = completed.stdout if capture_output else None
                stderr_raw = completed.stderr if capture_output else None
                stdout = (
                    stdout_raw
                    if not isinstance(stdout_raw, str)
                    else self._redact_text(stdout_raw, redact_values)
                )
                stderr = (
                    stderr_raw
                    if not isinstance(stderr_raw, str)
                    else self._redact_text(stderr_raw, redact_values)
                )
                return CommandResult(
                    args=list(cmd),
                    returncode=int(completed.returncode),
                    stdout=stdout,
                    stderr=stderr,
                    duration_s=elapsed,
                    timed_out=False,
                    attempts=attempt,
                )
            except subprocess.TimeoutExpired as exc:
                last_exc = exc
                elapsed = time.monotonic() - start_all
                self._log("WARNING", f"timeout: {self._format_cmd(cmd, redact_values)}")
                if attempt >= attempts:
                    stdout_raw = getattr(exc, "stdout", None)
                    stderr_raw = getattr(exc, "stderr", None)
                    stdout = (
                        stdout_raw
                        if not isinstance(stdout_raw, str)
                        else self._redact_text(stdout_raw, redact_values)
                    )
                    stderr = (
                        stderr_raw
                        if not isinstance(stderr_raw, str)
                        else self._redact_text(stderr_raw, redact_values)
                    )
                    return CommandResult(
                        args=list(cmd),
                        returncode=124,
                        stdout=stdout,
                        stderr=stderr,
                        duration_s=elapsed,
                        timed_out=True,
                        attempts=attempt,
                    )
            except FileNotFoundError as exc:
                last_exc = exc
                elapsed = time.monotonic() - start_all
                self._log("FAIL", f"command not found: {self._format_cmd(cmd, redact_values)}")
                return CommandResult(
                    args=list(cmd),
                    returncode=127,
                    stdout=None,
                    stderr=str(exc),
                    duration_s=elapsed,
                    timed_out=False,
                    attempts=attempt,
                )
            except subprocess.CalledProcessError as exc:
                last_exc = exc
                elapsed = time.monotonic() - start_all
                stdout_raw = exc.stdout if capture_output else None
                stderr_raw = exc.stderr if capture_output else None
                stdout = (
                    stdout_raw
                    if not isinstance(stdout_raw, str)
                    else self._redact_text(stdout_raw, redact_values)
                )
                stderr = (
                    stderr_raw
                    if not isinstance(stderr_raw, str)
                    else self._redact_text(stderr_raw, redact_values)
                )
                if attempt >= attempts:
                    return CommandResult(
                        args=list(cmd),
                        returncode=int(exc.returncode),
                        stdout=stdout,
                        stderr=stderr,
                        duration_s=elapsed,
                        timed_out=False,
                        attempts=attempt,
                    )
            except Exception as exc:
                last_exc = exc
                if attempt >= attempts:
                    raise

            self._sleep_backoff(attempt)

        if last_exc:
            raise last_exc
        raise RuntimeError("CommandRunner run() failed unexpectedly")

    def check_output(
        self,
        args: Sequence[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        text: bool = True,
    ) -> str:
        if not text:
            raise ValueError("check_output requires text=True")
        result = self.run(
            args,
            cwd=cwd,
            env=env,
            timeout=timeout,
            capture_output=True,
            check=True,
            text=text,
        )
        return str(result.stdout or "")

    def _validate_args(self, args: Sequence[str]) -> Tuple[str, ...]:
        if isinstance(args, (str, bytes)):
            raise TypeError("CommandRunner expects args as a list/tuple of strings (shell=False)")
        cmd: List[str] = []
        for a in args:
            if not isinstance(a, str):
                cmd.append(str(a))
            else:
                cmd.append(a)
        if not cmd or not cmd[0].strip():
            raise ValueError("Empty command")
        return tuple(cmd)

    def _apply_command_wrapper(self, cmd: Tuple[str, ...]) -> Tuple[str, ...]:
        wrapper = self._command_wrapper
        if not wrapper:
            return cmd
        try:
            wrapped = wrapper(list(cmd))
        except Exception as exc:
            self._log("WARNING", f"command_wrapper failed: {exc}")
            return cmd
        try:
            return self._validate_args(wrapped)
        except Exception as exc:
            self._log("WARNING", f"command_wrapper returned invalid args: {exc}")
            return cmd

    def _merge_env(self, env: Optional[Mapping[str, str]]) -> Dict[str, str]:
        merged = os.environ.copy()
        if env:
            for k, v in env.items():
                if isinstance(k, str) and isinstance(v, str):
                    merged[k] = v
        return merged

    def _collect_redact_values(self, env: Mapping[str, str]) -> Set[str]:
        values: Set[str] = set()
        for k in self._redact_env_keys:
            v = env.get(k)
            if isinstance(v, str) and v:
                values.add(v)
        return values

    def _sleep_backoff(self, attempt: int) -> None:
        if attempt <= 0:
            return
        sleep_s = self._backoff_base_s * (2 ** (attempt - 1))
        try:
            time.sleep(sleep_s)
        except Exception:
            return

    def _format_cmd(self, args: Sequence[str], redact_values: Set[str]) -> str:
        rendered = " ".join(shlex.quote(a) for a in args)
        return self._redact_text(rendered, redact_values) or rendered

    def _redact_text(self, text: Optional[str], redact_values: Set[str]) -> Optional[str]:
        if not isinstance(text, str) or not text:
            return text
        redacted = text
        for val in redact_values:
            if not val:
                continue
            redacted = redacted.replace(val, "***")
        redacted = self._redact_known_flag_values(redacted)
        return redacted

    def _redact_known_flag_values(self, text: str) -> str:
        patterns = [
            r"(--nvd-key\s+)(\S+)",
            r"(--encrypt-password\s+)(\S+)",
        ]
        out = text
        for pat in patterns:
            out = re.sub(pat, r"\1***", out, flags=re.IGNORECASE)
        out = re.sub(r"(socks5://[^:\s]+:)([^@\s]+)(@)", r"\1***\3", out)
        return out

    def _log(self, level: str, message: str) -> None:
        if not self._logger:
            return
        try:
            if level == "DEBUG" and hasattr(self._logger, "debug"):
                self._logger.debug(message)
            elif level in {"WARNING", "WARN"} and hasattr(self._logger, "warning"):
                self._logger.warning(message)
            elif level == "FAIL" and hasattr(self._logger, "error"):
                self._logger.error(message)
            elif hasattr(self._logger, "info"):
                self._logger.info(message)
        except Exception:
            return
