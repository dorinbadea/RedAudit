#!/usr/bin/env python3
"""CLI wrapper for scan artifact + SIEM JSON/JSONL validation."""

from redaudit.utils.scan_artifact_gate import main


if __name__ == "__main__":
    raise SystemExit(main())
