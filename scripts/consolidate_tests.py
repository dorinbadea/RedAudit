#!/usr/bin/env python3
"""
Test Suite Consolidation Helper Script.

This script helps consolidate fragmented test files into semantic groupings.
It extracts test functions while removing duplicate mock definitions.
"""

import re
import ast
from pathlib import Path
from collections import defaultdict

TESTS_DIR = Path("/Users/dorin/Documents/AntiGravity/RedAudit/tests")

# Files to consolidate into test_auditor_core.py
AUDITOR_SCAN_FILES = [
    "test_auditor_scan_coverage.py",
    "test_auditor_scan_coverage_v2.py",
    "test_auditor_scan_deep.py",
    "test_auditor_scan_edge_cases.py",
    "test_auditor_scan_edge_cases_v2.py",
    "test_auditor_scan_helpers.py",
    "test_auditor_scan_host_ports.py",
    "test_auditor_scan_network.py",
    "test_auditor_scan_progress.py",
    "test_auditor_scan_to_85.py",
    "test_auditor_scan_to_90.py",
    "test_auditor_scan_utils.py",
]


def extract_test_functions(file_path: Path) -> list[tuple[str, str, int, int]]:
    """Extract test function names and their line ranges."""
    with open(file_path, "r") as f:
        content = f.read()

    tests = []
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                tests.append(
                    (node.name, file_path.name, node.lineno, node.end_lineno or node.lineno)
                )
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                        tests.append(
                            (
                                f"{node.name}.{item.name}",
                                file_path.name,
                                item.lineno,
                                item.end_lineno or item.lineno,
                            )
                        )
    except SyntaxError as e:
        print(f"Syntax error in {file_path}: {e}")

    return tests


def analyze_duplicates():
    """Find duplicate test names across files."""
    all_tests = defaultdict(list)

    for filename in AUDITOR_SCAN_FILES:
        filepath = TESTS_DIR / filename
        if filepath.exists():
            tests = extract_test_functions(filepath)
            for test_name, source_file, start, end in tests:
                # Normalize: remove class prefix for comparison
                base_name = test_name.split(".")[-1]
                all_tests[base_name].append((source_file, test_name, start, end))

    print("\n=== DUPLICATE TEST ANALYSIS ===\n")

    duplicates = {k: v for k, v in all_tests.items() if len(v) > 1}
    unique = {k: v for k, v in all_tests.items() if len(v) == 1}

    print(f"Total unique test names: {len(unique)}")
    print(f"Potential duplicates: {len(duplicates)}")

    if duplicates:
        print("\nDuplicates found:")
        for name, sources in sorted(duplicates.items()):
            print(f"  {name}:")
            for src, full_name, start, end in sources:
                print(f"    - {src}:{start}-{end}")

    return unique, duplicates


def count_mock_classes():
    """Count MockAuditor class definitions."""
    mock_count = 0

    for filename in AUDITOR_SCAN_FILES:
        filepath = TESTS_DIR / filename
        if filepath.exists():
            with open(filepath, "r") as f:
                content = f.read()
            count = len(re.findall(r"^class Mock\w+.*:", content, re.MULTILINE))
            if count:
                print(f"  {filename}: {count} mock class(es)")
                mock_count += count

    return mock_count


if __name__ == "__main__":
    print("=" * 60)
    print("TEST SUITE CONSOLIDATION ANALYSIS")
    print("=" * 60)

    print("\n=== MOCK CLASS ANALYSIS ===\n")
    total_mocks = count_mock_classes()
    print(f"\nTotal mock classes to consolidate: {total_mocks}")

    unique, duplicates = analyze_duplicates()

    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(unique)} unique tests, {len(duplicates)} potential duplicates")
    print("=" * 60)
