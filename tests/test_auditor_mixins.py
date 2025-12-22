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


def test_format_eta_and_phase_detail():
    app = InteractiveNetworkAuditor()
    assert app._format_eta(65) == "1:05"
    assert app._format_eta(3661) == "1:01:01"
    assert app._format_eta("bad") == "--:--"

    app.current_phase = "vulns:testssl:1.2.3.4:443"
    assert app._phase_detail() == "testssl 1.2.3.4:443"
    app.current_phase = "ports:10.0.0.1"
    assert app._phase_detail() == "nmap 10.0.0.1"


def test_should_emit_during_progress_filters_noise():
    app = InteractiveNetworkAuditor()
    assert app._should_emit_during_progress("deep identity scan finished", "OK") is True
    assert app._should_emit_during_progress("routine info", "INFO") is False
    assert app._should_emit_during_progress("some error occurred", "WARN") is True


def test_coerce_text_variants():
    app = InteractiveNetworkAuditor()
    assert app._coerce_text(b"abc") == "abc"
    assert app._coerce_text("text") == "text"
    assert app._coerce_text(None) == ""
    assert app._coerce_text(123) == "123"
