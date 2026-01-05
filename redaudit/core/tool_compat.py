#!/usr/bin/env python3
"""
RedAudit - External tool compatibility checks.

Keep checks lightweight: warn about version mismatches that can affect output parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import shutil
from typing import Iterable, List, Optional, Sequence, TypedDict, cast

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run


@dataclass(frozen=True)
class ToolCompatIssue:
    tool: str
    version: str
    expected: str
    reason: str


class _ToolCompatRule(TypedDict):
    version_args: Sequence[str]
    pattern: str
    allowed_majors: set[int]
    expected: str


_TOOL_COMPAT_RULES: dict[str, _ToolCompatRule] = {
    "nmap": {
        "version_args": ["--version"],
        "pattern": r"Nmap version ([\d.]+)",
        "allowed_majors": {7, 8},
        "expected": "7.x/8.x",
    },
    "nuclei": {
        "version_args": ["-version"],
        "pattern": r"v?(\d+\.\d+(?:\.\d+)?)",
        "allowed_majors": {3},
        "expected": "3.x",
    },
}


def _make_runner(*, dry_run: Optional[bool] = None) -> CommandRunner:
    return CommandRunner(
        dry_run=is_dry_run(dry_run),
        default_timeout=5.0,
        default_retries=0,
        backoff_base_s=0.0,
    )


def _parse_major(version: str) -> Optional[int]:
    if not version:
        return None
    match = re.search(r"(\d+)", version)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _run_version_cmd(
    tool: str,
    version_args: Sequence[str],
    *,
    dry_run: Optional[bool] = None,
) -> str:
    runner = _make_runner(dry_run=dry_run)
    res = runner.run([tool] + list(version_args), capture_output=True, text=True, check=False)
    return f"{_coerce_text(res.stdout)}{_coerce_text(res.stderr)}"


def _coerce_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value) if value is not None else ""


def _extract_version(output: str, pattern: str) -> Optional[str]:
    if not output:
        return None
    match = re.search(pattern, output, re.IGNORECASE)
    if not match:
        return None
    return (match.group(1) or "").strip()


def check_tool_compatibility(
    tools: Iterable[str],
    *,
    dry_run: Optional[bool] = None,
) -> List[ToolCompatIssue]:
    """
    Check versions of key external tools and warn when versions are unknown or out of range.
    """
    if is_dry_run(dry_run):
        return []

    issues: List[ToolCompatIssue] = []
    for tool in tools:
        rule = _TOOL_COMPAT_RULES.get(tool)
        if not rule:
            continue
        if not shutil.which(tool):
            continue

        rule_typed = cast(_ToolCompatRule, rule)
        output = _run_version_cmd(tool, rule_typed["version_args"], dry_run=dry_run)
        version = _extract_version(output, rule_typed["pattern"])
        if not version and tool == "nuclei":
            output = _run_version_cmd(tool, ["--version"], dry_run=dry_run)
            version = _extract_version(output, rule_typed["pattern"])
        expected = rule_typed["expected"]

        if not version:
            issues.append(
                ToolCompatIssue(
                    tool=tool,
                    version="unknown",
                    expected=expected,
                    reason="unknown_version",
                )
            )
            continue

        major = _parse_major(version)
        if major is None or major not in rule_typed["allowed_majors"]:
            issues.append(
                ToolCompatIssue(
                    tool=tool,
                    version=version,
                    expected=expected,
                    reason="unsupported_major",
                )
            )

    return issues
