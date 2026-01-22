#!/usr/bin/env python3
"""
RedAudit Metrics Report
Compute basic repo metrics to avoid estimations in docs/reports.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Set


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _iter_files(root: str, ext: str = ".py") -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git", ".venv"}]
        for name in filenames:
            if name.endswith(ext):
                yield os.path.join(dirpath, name)


def _count_lines(paths: Iterable[str]) -> int:
    total = 0
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                total += sum(1 for _ in f)
        except Exception:
            continue
    return total


def _extract_cli_flags(cli_path: str) -> List[str]:
    try:
        with open(cli_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return []
    flags = re.findall(r"--[a-z0-9][a-z0-9\\-]*", content, flags=re.IGNORECASE)
    return sorted({flag for flag in flags})


def main() -> None:
    core_root = os.path.join(REPO_ROOT, "redaudit", "core")
    pkg_root = os.path.join(REPO_ROOT, "redaudit")
    cli_path = os.path.join(REPO_ROOT, "redaudit", "cli.py")

    core_files = list(_iter_files(core_root))
    pkg_files = list(_iter_files(pkg_root))

    metrics = {
        "core_module_count": len(core_files),
        "package_module_count": len(pkg_files),
        "core_loc": _count_lines(core_files),
        "package_loc": _count_lines(pkg_files),
        "cli_flag_count": len(_extract_cli_flags(cli_path)),
    }

    print("RedAudit Metrics")
    for key, value in metrics.items():
        print(f"- {key}: {value}")


if __name__ == "__main__":
    main()
