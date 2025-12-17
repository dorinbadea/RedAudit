#!/usr/bin/env python3
"""
RedAudit - Dry-run helpers

Centralizes dry-run detection so modules can consistently honor --dry-run
via the REDAUDIT_DRY_RUN environment variable and/or explicit parameters.
"""

from __future__ import annotations

import os
from typing import Optional


def is_dry_run(dry_run: Optional[bool] = None) -> bool:
    """
    Determine whether dry-run mode is enabled.

    Precedence:
    - Explicit `dry_run` argument (if not None)
    - Environment variable `REDAUDIT_DRY_RUN` (truthy tokens)
    """
    if dry_run is not None:
        return bool(dry_run)
    token = os.environ.get("REDAUDIT_DRY_RUN", "")
    return token.strip().lower() in {"1", "true", "yes", "y", "on"}

