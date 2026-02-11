import json
from pathlib import Path

from redaudit.utils import scan_artifact_gate


def _write_manifest(run_dir: Path, artifact_paths: list[str]) -> None:
    payload = {
        "artifacts": [{"path": rel, "size_bytes": 1} for rel in artifact_paths],
        "counts": {"hosts": 1, "findings": 1},
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_valid_summary(run_dir: Path) -> None:
    (run_dir / "summary.json").write_text(json.dumps({"ok": True}), encoding="utf-8")


def test_validate_scan_folder_strict_passes_with_valid_inputs(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()

    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text(
        json.dumps(
            {
                "asset_id": "a1",
                "ip": "192.168.1.10",
                "status": "up",
                "timestamp": "2026-02-11T00:00:00",
                "session_id": "s1",
                "schema_version": "1.0",
                "scanner": "RedAudit",
                "scanner_version": "4.20.4",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "findings.jsonl").write_text(
        json.dumps(
            {
                "asset_id": "a1",
                "asset_ip": "192.168.1.10",
                "severity": "low",
                "title": "test",
                "timestamp": "2026-02-11T00:00:00",
                "session_id": "s1",
                "schema_version": "1.0",
                "scanner": "RedAudit",
                "scanner_version": "4.20.4",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    pcap_rel = "captures/test.pcap"
    pcap_path = run_dir / pcap_rel
    pcap_path.parent.mkdir(parents=True)
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    _write_manifest(
        run_dir,
        ["run_manifest.json", "summary.json", "assets.jsonl", "findings.jsonl", pcap_rel],
    )

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert result.errors == []


def test_validate_scan_folder_reports_missing_manifest_artifact(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    _write_manifest(run_dir, ["missing.txt"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=False)
    assert any("missing artifact" in issue.message for issue in result.errors)


def test_validate_scan_folder_reports_invalid_pcap_header(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text("\n", encoding="utf-8")
    (run_dir / "findings.jsonl").write_text("\n", encoding="utf-8")
    (run_dir / "bad.pcap").write_bytes(b"NOTP" + b"\x00" * 20)
    _write_manifest(run_dir, ["bad.pcap", "summary.json", "assets.jsonl", "findings.jsonl"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("invalid PCAP header" in issue.message for issue in result.errors)


def test_validate_scan_folder_reports_invalid_jsonl_and_missing_keys(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text("{bad json}\n", encoding="utf-8")
    (run_dir / "findings.jsonl").write_text(
        json.dumps({"title": "missing keys"}) + "\n", encoding="utf-8"
    )
    _write_manifest(run_dir, ["summary.json", "assets.jsonl", "findings.jsonl"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("invalid JSON line" in issue.message for issue in result.errors)
    assert any("missing keys" in issue.message for issue in result.errors)


def test_validate_scan_folder_non_strict_warns_on_missing_siem_files(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_manifest(run_dir, ["run_manifest.json"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=False)
    assert result.errors == []
    assert len(result.warnings) >= 2


def test_main_returns_failure_when_run_dir_missing(tmp_path, capsys):
    rc = scan_artifact_gate.main(["--run-dir", str(tmp_path / "nope"), "--strict"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "run directory not found" in out


def test_read_json_rejects_non_object(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("[]", encoding="utf-8")
    try:
        scan_artifact_gate._read_json(path)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "expected JSON object" in str(exc)


def test_iter_manifest_artifacts_handles_non_list_and_non_dict_items():
    assert list(scan_artifact_gate._iter_manifest_artifacts({"artifacts": "bad"})) == []
    assert list(
        scan_artifact_gate._iter_manifest_artifacts(
            {"artifacts": [1, {"path": "ok.txt"}, {"path": ""}]}
        )
    ) == ["ok.txt"]


def test_validate_scan_folder_warns_when_manifest_has_no_artifacts(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    _write_manifest(run_dir, [])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=False)
    assert any("no artifacts[] entries" in issue.message for issue in result.warnings)


def test_validate_scan_folder_reports_artifact_not_file(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "nested").mkdir()
    _write_manifest(run_dir, ["nested"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("artifact is not a file" in issue.message for issue in result.errors)


def test_validate_scan_folder_reports_unreadable_artifact(tmp_path, monkeypatch):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    unreadable = run_dir / "locked.bin"
    unreadable.write_bytes(b"x")
    _write_manifest(run_dir, ["locked.bin", "summary.json"])

    original_open = Path.open

    def _patched_open(path_obj, *args, **kwargs):
        if path_obj == unreadable and args and "rb" in args[0]:
            raise OSError("permission denied")
        return original_open(path_obj, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _patched_open)
    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=False)
    assert any("artifact unreadable" in issue.message for issue in result.errors)


def test_validate_scan_folder_skips_missing_pcap_in_pcap_validation(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text("\n", encoding="utf-8")
    (run_dir / "findings.jsonl").write_text("\n", encoding="utf-8")
    _write_manifest(run_dir, ["missing.pcap", "summary.json", "assets.jsonl", "findings.jsonl"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("missing artifact: missing.pcap" in issue.message for issue in result.errors)
    assert not any("failed to read PCAP missing.pcap" in issue.message for issue in result.errors)


def test_validate_scan_folder_reports_unreadable_pcap(tmp_path, monkeypatch):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text("\n", encoding="utf-8")
    (run_dir / "findings.jsonl").write_text("\n", encoding="utf-8")
    pcap = run_dir / "locked.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    _write_manifest(run_dir, ["locked.pcap", "summary.json", "assets.jsonl", "findings.jsonl"])

    original_open = Path.open

    def _patched_open(path_obj, *args, **kwargs):
        if path_obj == pcap and args and "rb" in args[0]:
            raise OSError("blocked")
        return original_open(path_obj, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _patched_open)
    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("failed to read PCAP locked.pcap" in issue.message for issue in result.errors)


def test_validate_jsonl_contract_reports_non_object_records(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    (run_dir / "assets.jsonl").write_text('["not", "object"]\n', encoding="utf-8")
    (run_dir / "findings.jsonl").write_text(json.dumps({"title": "x"}) + "\n", encoding="utf-8")
    _write_manifest(run_dir, ["summary.json", "assets.jsonl", "findings.jsonl"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("expected JSON object" in issue.message for issue in result.errors)


def test_validate_scan_folder_missing_manifest(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("run_manifest.json not found" in issue.message for issue in result.errors)


def test_validate_scan_folder_invalid_manifest_json(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text("{bad}", encoding="utf-8")
    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("invalid run_manifest.json" in issue.message for issue in result.errors)


def test_validate_scan_folder_invalid_summary_json(tmp_path):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    (run_dir / "summary.json").write_text("{bad}", encoding="utf-8")
    (run_dir / "assets.jsonl").write_text("\n", encoding="utf-8")
    (run_dir / "findings.jsonl").write_text("\n", encoding="utf-8")
    _write_manifest(run_dir, ["summary.json", "assets.jsonl", "findings.jsonl"])

    result = scan_artifact_gate.validate_scan_folder(run_dir, strict=True)
    assert any("invalid summary.json" in issue.message for issue in result.errors)


def test_main_success_and_warning_output(tmp_path, capsys):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_valid_summary(run_dir)
    _write_manifest(run_dir, [])
    rc = scan_artifact_gate.main(["--run-dir", str(run_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[WARN]" in out
    assert "Validation passed" in out


def test_main_failure_prints_error_lines(tmp_path, capsys):
    run_dir = tmp_path / "scan"
    run_dir.mkdir()
    _write_manifest(run_dir, ["missing.txt"])
    rc = scan_artifact_gate.main(["--run-dir", str(run_dir), "--strict"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[FAIL]" in out
    assert "Validation failed" in out
