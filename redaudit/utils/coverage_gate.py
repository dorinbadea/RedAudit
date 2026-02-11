"""Utilities to enforce minimum coverage on changed Python files."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


@dataclass(frozen=True)
class CoverageFailure:
    """Represents one file that failed changed-file coverage policy."""

    path: str
    reason: str
    percent: float | None = None


def _run_git(args: Sequence[str]) -> str:
    """Run a git command and return stdout text (or empty on failure)."""
    try:
        result = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return ""
    return result.stdout.strip()


def normalize_path(path: str) -> str:
    """Normalize path to a stable POSIX-relative form."""
    return path.replace("\\", "/").lstrip("./")


def filter_changed_python_paths(paths: Iterable[str]) -> List[str]:
    """Keep only changed Python files under redaudit/ and normalize them."""
    out: List[str] = []
    for path in paths:
        norm = normalize_path(path)
        if not norm.endswith(".py"):
            continue
        if not norm.startswith("redaudit/"):
            continue
        out.append(norm)
    # Deterministic + de-duplicated while preserving order
    seen = set()
    deduped: List[str] = []
    for item in out:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def get_changed_python_paths(base_ref: str | None = None, head_ref: str = "HEAD") -> List[str]:
    """Get changed Python files via git diff against a base ref."""
    if base_ref:
        diff_range = f"{base_ref}...{head_ref}"
        stdout = _run_git(["diff", "--name-only", "--diff-filter=AMR", diff_range])
    else:
        stdout = _run_git(["diff", "--name-only", "--diff-filter=AMR", "HEAD~1", head_ref])
    paths = stdout.splitlines() if stdout else []
    return filter_changed_python_paths(paths)


def load_coverage_by_file(coverage_json_path: str) -> Dict[str, Dict[str, Any]]:
    """Load coverage.json and return a normalized per-file summary mapping."""
    raw = json.loads(Path(coverage_json_path).read_text(encoding="utf-8"))
    files = raw.get("files", {})
    mapped: Dict[str, Dict[str, Any]] = {}
    for file_path, payload in files.items():
        norm = normalize_path(file_path)
        mapped[norm] = payload.get("summary", {})
    return mapped


def evaluate_changed_file_coverage(
    changed_paths: Sequence[str],
    coverage_summaries: Mapping[str, Mapping[str, Any]],
    min_percent: float,
) -> List[CoverageFailure]:
    """Evaluate changed-file coverage against a threshold."""
    failures: List[CoverageFailure] = []
    for path in changed_paths:
        summary = coverage_summaries.get(path)
        if summary is None:
            failures.append(CoverageFailure(path=path, reason="missing coverage data"))
            continue
        statements = int(summary.get("num_statements", 0) or 0)
        # Empty modules should not fail the gate.
        if statements == 0:
            continue
        percent = float(summary.get("percent_covered", 0.0) or 0.0)
        if percent < min_percent:
            failures.append(
                CoverageFailure(path=path, reason=f"below {min_percent:.2f}%", percent=percent)
            )
    return failures


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if changed Python files under redaudit/ are below min coverage."
    )
    parser.add_argument("--coverage-file", default="coverage.json")
    parser.add_argument("--threshold", type=float, default=98.0)
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument(
        "--changed-path",
        action="append",
        default=[],
        help="Optional explicit changed paths (repeatable). If absent, git diff is used.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.changed_path:
        changed_paths = filter_changed_python_paths(args.changed_path)
    else:
        base_ref = args.base_ref.strip() or None
        changed_paths = get_changed_python_paths(base_ref=base_ref, head_ref=args.head_ref)

    if not changed_paths:
        print("Changed-file coverage gate: no changed redaudit/*.py files.")
        return 0

    summaries = load_coverage_by_file(args.coverage_file)
    failures = evaluate_changed_file_coverage(changed_paths, summaries, args.threshold)
    if failures:
        print(f"Changed-file coverage gate failed (threshold {args.threshold:.2f}%):")
        for item in failures:
            if item.percent is None:
                print(f"  - {item.path}: {item.reason}")
            else:
                print(f"  - {item.path}: {item.percent:.2f}% ({item.reason})")
        return 1

    print(f"Changed-file coverage gate passed (threshold {args.threshold:.2f}%).")
    for path in changed_paths:
        summary = summaries.get(path) or {}
        percent = float(summary.get("percent_covered", 0.0) or 0.0)
        print(f"  - {path}: {percent:.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
