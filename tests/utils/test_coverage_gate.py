import json
from pathlib import Path
from unittest.mock import patch

from redaudit.utils import coverage_gate


def test_filter_changed_python_paths_limits_to_redaudit_python():
    paths = [
        "redaudit/core/a.py",
        "./redaudit/utils/b.py",
        "tests/test_x.py",
        "README.md",
        "redaudit/core/a.py",
    ]
    result = coverage_gate.filter_changed_python_paths(paths)
    assert result == ["redaudit/core/a.py", "redaudit/utils/b.py"]


def test_load_coverage_by_file_normalizes_paths(tmp_path):
    payload = {
        "files": {
            "./redaudit/core/a.py": {"summary": {"num_statements": 10, "percent_covered": 99.0}},
            "redaudit\\utils\\b.py": {"summary": {"num_statements": 5, "percent_covered": 100.0}},
        }
    }
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = coverage_gate.load_coverage_by_file(str(coverage_path))
    assert loaded["redaudit/core/a.py"]["percent_covered"] == 99.0
    assert loaded["redaudit/utils/b.py"]["percent_covered"] == 100.0


def test_evaluate_changed_file_coverage_reports_missing_and_low():
    changed = ["redaudit/core/a.py", "redaudit/core/b.py", "redaudit/core/c.py"]
    summaries = {
        "redaudit/core/a.py": {"num_statements": 10, "percent_covered": 97.99},
        "redaudit/core/b.py": {"num_statements": 0, "percent_covered": 0.0},
    }
    failures = coverage_gate.evaluate_changed_file_coverage(changed, summaries, min_percent=98.0)
    assert len(failures) == 2
    by_path = {f.path: f for f in failures}
    assert by_path["redaudit/core/a.py"].percent == 97.99
    assert by_path["redaudit/core/c.py"].reason == "missing coverage data"


def test_main_passes_with_explicit_changed_paths(tmp_path, capsys):
    payload = {
        "files": {
            "redaudit/core/a.py": {"summary": {"num_statements": 10, "percent_covered": 99.0}},
        }
    }
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(payload), encoding="utf-8")
    rc = coverage_gate.main(
        [
            "--coverage-file",
            str(coverage_path),
            "--threshold",
            "98",
            "--changed-path",
            "redaudit/core/a.py",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "passed" in out.lower()


def test_main_fails_when_below_threshold(tmp_path, capsys):
    payload = {
        "files": {
            "redaudit/core/a.py": {"summary": {"num_statements": 10, "percent_covered": 90.0}},
        }
    }
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(payload), encoding="utf-8")
    rc = coverage_gate.main(
        [
            "--coverage-file",
            str(coverage_path),
            "--threshold",
            "98",
            "--changed-path",
            "redaudit/core/a.py",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "failed" in out.lower()


def test_get_changed_python_paths_uses_git_diff():
    with patch(
        "redaudit.utils.coverage_gate._run_git", return_value="redaudit/core/a.py\nREADME.md"
    ):
        changed = coverage_gate.get_changed_python_paths(base_ref="origin/main", head_ref="HEAD")
    assert changed == ["redaudit/core/a.py"]
