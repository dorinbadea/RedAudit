#!/usr/bin/env python3
"""
RedAudit - Interactive Network Auditor
Copyright (C) 2026  Dorin Badea

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

RedAudit package initialization.
"""

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.utils.constants import VERSION

__all__ = ["InteractiveNetworkAuditor", "VERSION", "__version__"]
__version__ = VERSION
