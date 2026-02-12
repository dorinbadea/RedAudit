#!/usr/bin/env python3
"""Artifact and SIEM JSON/JSONL validation gate for completed scan folders."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


_VALID_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian (usec)
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian (usec)
    b"\x4d\x3c\xb2\xa1",  # pcap little-endian (nsec)
    b"\xa1\xb2\x3c\x4d",  # pcap big-endian (nsec)
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


_ASSET_REQUIRED_KEYS = {
    "asset_id",
    "ip",
    "status",
    "timestamp",
    "session_id",
    "schema_version",
    "scanner",
    "scanner_version",
}

_FINDING_REQUIRED_KEYS = {
    "asset_id",
    "asset_ip",
    "severity",
    "title",
    "timestamp",
    "session_id",
    "schema_version",
    "scanner",
    "scanner_version",
}


@dataclass(frozen=True)
class ValidationIssue:
    severity: str  # "error" | "warning"
    category: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    issues: Sequence[ValidationIssue]

    @property
    def errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def _iter_manifest_artifacts(manifest: dict) -> Iterable[str]:
    artifacts = manifest.get("artifacts") or []
    if not isinstance(artifacts, list):
        return []
    out = []
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("path") or "").strip()
        if rel:
            out.append(rel)
    return out


def _validate_manifest_artifacts(run_dir: Path, manifest: dict) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    artifact_paths = list(_iter_manifest_artifacts(manifest))
    if not artifact_paths:
        issues.append(ValidationIssue("warning", "manifest", "manifest has no artifacts[] entries"))
        return issues

    for rel in artifact_paths:
        abs_path = run_dir / rel
        if not abs_path.exists():
            issues.append(ValidationIssue("error", "artifact", f"missing artifact: {rel}"))
            continue
        if not abs_path.is_file():
            issues.append(ValidationIssue("error", "artifact", f"artifact is not a file: {rel}"))
            continue
        try:
            with abs_path.open("rb") as handle:
                handle.read(1)
        except Exception as exc:
            issues.append(
                ValidationIssue("error", "artifact", f"artifact unreadable: {rel} ({exc})")
            )

    return issues


def _validate_pcaps(run_dir: Path, manifest: dict) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for rel in _iter_manifest_artifacts(manifest):
        if not rel.lower().endswith(".pcap"):
            continue
        pcap_path = run_dir / rel
        if not pcap_path.exists() or not pcap_path.is_file():
            continue
        try:
            with pcap_path.open("rb") as handle:
                magic = handle.read(4)
            if magic not in _VALID_PCAP_MAGICS:
                issues.append(ValidationIssue("error", "pcap", f"invalid PCAP header: {rel}"))
        except Exception as exc:
            issues.append(ValidationIssue("error", "pcap", f"failed to read PCAP {rel}: {exc}"))
    return issues


def _validate_jsonl_contract(
    jsonl_path: Path,
    *,
    required_keys: set[str],
    label: str,
) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                issues.append(
                    ValidationIssue(
                        "error",
                        "jsonl",
                        f"{label}:{idx} invalid JSON line ({exc.msg})",
                    )
                )
                continue
            if not isinstance(item, dict):
                issues.append(
                    ValidationIssue(
                        "error",
                        "jsonl",
                        f"{label}:{idx} expected JSON object",
                    )
                )
                continue
            missing = sorted(k for k in required_keys if k not in item)
            if missing:
                issues.append(
                    ValidationIssue(
                        "error",
                        "jsonl",
                        f"{label}:{idx} missing keys: {', '.join(missing)}",
                    )
                )
    return issues


def _validate_ndjson_output(
    ndjson_path: Path,
    *,
    label: str,
    allow_empty: bool = True,
) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    line_count = 0
    with ndjson_path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            line_count += 1
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei",
                        f"{label}:{idx} invalid NDJSON line ({exc.msg})",
                    )
                )
                continue
            if not isinstance(item, dict):
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei",
                        f"{label}:{idx} expected JSON object",
                    )
                )
    if line_count == 0:
        if allow_empty:
            issues.append(
                ValidationIssue(
                    "warning",
                    "nuclei",
                    f"{label} is empty (no additional Nuclei records)",
                )
            )
        else:
            issues.append(ValidationIssue("error", "nuclei", f"{label} is empty"))
    return issues


def _safe_int(value: int | float | str | None, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _validate_nuclei_parity(summary: dict, manifest: dict) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    summary_pipeline = summary.get("pipeline") or {}
    manifest_pipeline = manifest.get("pipeline") or {}
    if not isinstance(summary_pipeline, dict) or not isinstance(manifest_pipeline, dict):
        return issues

    summary_nuclei = summary_pipeline.get("nuclei") or {}
    manifest_nuclei = manifest_pipeline.get("nuclei") or {}
    if not isinstance(summary_nuclei, dict) or not isinstance(manifest_nuclei, dict):
        return issues

    for key in ("last_run_elapsed_s", "last_resume_elapsed_s", "nuclei_total_elapsed_s"):
        if key in summary_nuclei and key in manifest_nuclei:
            s_val = _safe_int(summary_nuclei.get(key), -1)
            m_val = _safe_int(manifest_nuclei.get(key), -1)
            if s_val != m_val:
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei_parity",
                        f"{key} mismatch (summary={s_val}, manifest={m_val})",
                    )
                )

    resume_meta = manifest.get("nuclei_resume")
    if isinstance(resume_meta, dict):
        if "resume_pending" in summary_nuclei and "pending_targets" in resume_meta:
            s_pending = _safe_int(summary_nuclei.get("resume_pending"), 0)
            m_pending = _safe_int(resume_meta.get("pending_targets"), 0)
            if s_pending != m_pending:
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei_parity",
                        f"resume_pending mismatch (summary={s_pending}, manifest={m_pending})",
                    )
                )
        if "resume_count" in summary_nuclei and "resume_count" in resume_meta:
            s_count = _safe_int(summary_nuclei.get("resume_count"), 0)
            m_count = _safe_int(resume_meta.get("resume_count"), 0)
            if s_count != m_count:
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei_parity",
                        f"resume_count mismatch (summary={s_count}, manifest={m_count})",
                    )
                )
        state_file = summary_nuclei.get("resume_state_file")
        manifest_path = resume_meta.get("path")
        if state_file and manifest_path:
            if Path(str(state_file)).name != Path(str(manifest_path)).name:
                issues.append(
                    ValidationIssue(
                        "error",
                        "nuclei_parity",
                        "resume_state_file mismatch between summary and manifest",
                    )
                )

    return issues


def validate_scan_folder(run_dir: Path, *, strict: bool = False) -> ValidationResult:
    issues: List[ValidationIssue] = []
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists() or not manifest_path.is_file():
        return ValidationResult(
            [ValidationIssue("error", "manifest", "run_manifest.json not found")]
        )

    try:
        manifest = _read_json(manifest_path)
    except Exception as exc:
        return ValidationResult(
            [ValidationIssue("error", "manifest", f"invalid run_manifest.json ({exc})")]
        )

    issues.extend(_validate_manifest_artifacts(run_dir, manifest))
    issues.extend(_validate_pcaps(run_dir, manifest))

    summary_path = run_dir / "summary.json"
    summary_data: dict = {}
    if summary_path.exists():
        try:
            summary_data = _read_json(summary_path)
        except Exception as exc:
            issues.append(ValidationIssue("error", "json", f"invalid summary.json ({exc})"))
    else:
        sev = "error" if strict else "warning"
        issues.append(ValidationIssue(sev, "json", "summary.json not found"))

    assets_path = run_dir / "assets.jsonl"
    findings_path = run_dir / "findings.jsonl"

    if assets_path.exists():
        issues.extend(
            _validate_jsonl_contract(
                assets_path,
                required_keys=_ASSET_REQUIRED_KEYS,
                label="assets.jsonl",
            )
        )
    else:
        sev = "error" if strict else "warning"
        issues.append(ValidationIssue(sev, "jsonl", "assets.jsonl not found"))

    if findings_path.exists():
        issues.extend(
            _validate_jsonl_contract(
                findings_path,
                required_keys=_FINDING_REQUIRED_KEYS,
                label="findings.jsonl",
            )
        )
    else:
        sev = "error" if strict else "warning"
        issues.append(ValidationIssue(sev, "jsonl", "findings.jsonl not found"))

    nuclei_output_path = run_dir / "nuclei_output.json"
    if nuclei_output_path.exists():
        issues.extend(
            _validate_ndjson_output(
                nuclei_output_path,
                label="nuclei_output.json",
                allow_empty=True,
            )
        )

    nuclei_resume_output_path = run_dir / "nuclei_output_resume.json"
    if nuclei_resume_output_path.exists():
        issues.extend(
            _validate_ndjson_output(
                nuclei_resume_output_path,
                label="nuclei_output_resume.json",
                allow_empty=True,
            )
        )

    if summary_data:
        issues.extend(_validate_nuclei_parity(summary_data, manifest))

    return ValidationResult(issues)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate RedAudit run artifacts and SIEM JSON/JSONL contracts"
    )
    parser.add_argument("--run-dir", required=True, help="Path to scan output directory")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if SIEM files are missing (summary/assets/findings)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    run_dir = Path(args.run_dir).expanduser()
    if not run_dir.exists() or not run_dir.is_dir():
        print(f"[FAIL] run directory not found: {run_dir}")
        return 1

    result = validate_scan_folder(run_dir, strict=bool(args.strict))

    for issue in result.issues:
        prefix = "FAIL" if issue.severity == "error" else "WARN"
        print(f"[{prefix}] {issue.category}: {issue.message}")

    if result.errors:
        print(
            f"\nValidation failed: {len(result.errors)} error(s), "
            f"{len(result.warnings)} warning(s)."
        )
        return 1

    print(f"\nValidation passed: 0 error(s), {len(result.warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
