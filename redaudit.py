#!/usr/bin/env python3
"""
RedAudit - Interactive Network Auditor
Copyright (C) 2026  Dorin Badea
GPLv3 License

DEPRECATED: This file is a backward-compatibility wrapper.
The main codebase has been refactored into the redaudit/ package.

For new usage, run:
  - python -m redaudit
  - or: from redaudit import InteractiveNetworkAuditor
"""

import sys
import os

# Add possible package locations to path
# 1. System installation (by redaudit_install.sh)
# 2. Local directory (development/testing)
_script_dir = os.path.dirname(os.path.abspath(__file__))
_system_lib = "/usr/local/lib"

if os.path.isdir(os.path.join(_system_lib, "redaudit")):
    sys.path.insert(0, _system_lib)
elif os.path.isdir(os.path.join(_script_dir, "redaudit")):
    sys.path.insert(0, _script_dir)

# Re-export everything from the package for backward compatibility
from redaudit import InteractiveNetworkAuditor, VERSION
from redaudit.utils.constants import (
    MAX_INPUT_LENGTH,
    MAX_CIDR_LENGTH,
    MAX_SUBPROCESS_RETRIES,
    DEFAULT_LANG,
)
from redaudit.utils.i18n import TRANSLATIONS
from redaudit.cli import main, parse_arguments, configure_from_args

__all__ = [
    'InteractiveNetworkAuditor',
    'VERSION',
    'MAX_INPUT_LENGTH',
    'MAX_CIDR_LENGTH',
    'MAX_SUBPROCESS_RETRIES',
    'DEFAULT_LANG',
    'TRANSLATIONS',
    'main',
    'parse_arguments',
    'configure_from_args',
]

if __name__ == "__main__":
    main()
