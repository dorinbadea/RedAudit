#!/usr/bin/env python3
"""
RedAudit - Tests for auditor mixins.
"""

import logging
from logging.handlers import RotatingFileHandler
from unittest.mock import patch

from redaudit.core.auditor import InteractiveNetworkAuditor


def test_condense_for_ui_parses_full_scan():
    app = InteractiveNetworkAuditor()
    text = "[nmap] 10.0.0.1 \u2192 nmap -A -sV -p-"
    assert app._condense_for_ui(text) == "nmap 10.0.0.1 (full scan)"


def test_setup_logging_adds_rotating_handler(tmp_path):
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = []
    try:
        with patch(
            "redaudit.core.auditor_mixins.os.path.expanduser",
            return_value=str(tmp_path / "logs"),
        ):
            app = InteractiveNetworkAuditor()
        assert any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers)
    finally:
        logger.handlers = original_handlers
