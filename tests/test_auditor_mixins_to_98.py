import io
import time
import logging
import threading
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest
import base64
import sys
import os

from redaudit.core.auditor_mixins import (
    _ActivityIndicator,
    AuditorUIMixin,
    AuditorLoggingMixin,
    AuditorCryptoMixin,
    AuditorNVDMixin,
)

# -------------------------------------------------------------------------
# Full Mixin Class
# -------------------------------------------------------------------------


class MasterAuditor(AuditorUIMixin, AuditorLoggingMixin, AuditorCryptoMixin, AuditorNVDMixin):
    def __init__(self):
        self.COLORS = {
            "HEADER": "\033[95m",
            "OKBLUE": "\033[94m",
            "OKGREEN": "\033[92m",
            "WARNING": "\033[93m",
            "FAIL": "\033[91m",
            "ENDC": "\033[0m",
            "CYAN": "\033[96m",
        }
        self.logger = logging.getLogger("RedAudit")
        self.activity_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._ui_detail_lock = threading.Lock()
        self._ui_detail = ""
        self._ui_progress_active = False
        self.current_phase = "init"
        self.lang = "en"
        self.last_activity = datetime.now()
        self.config = {
            "output_dir": "/tmp",
            "debug": True,
            "encrypt": False,
            "cve_lookup_enabled": True,
        }
        self.heartbeat_thread = None
        self.heartbeat_stop = False
        self.cryptography_available = True
        self.encryption_enabled = False
        self.encryption_key = None

    def ask_yes_no(self, p, default="no"):
        return True

    def ask_choice(self, p, o, default=0):
        return 0

    def ask_password_twice(self, p, l):
        return "pass"

    def t(self, key, *args):
        return f"T({key})"


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


def test_activity_indicator_exhaustive():
    # TTY
    s = io.StringIO()
    s.isatty = lambda: True
    ind = _ActivityIndicator(label="L", initial="I", stream=s, refresh_s=0.01)
    with ind:
        time.sleep(0.02)
        ind.update("U")
        time.sleep(0.02)
    assert "L: U" in s.getvalue()

    # Non-TTY heartbeat
    s = io.StringIO()
    s.isatty = lambda: False
    start = time.monotonic()
    ind = _ActivityIndicator(label="L", stream=s, refresh_s=0.01)
    ind._stop = MagicMock()
    ind._stop.is_set.side_effect = [False, True]
    with patch("time.monotonic", side_effect=[start, start + 10]):
        with patch("time.sleep", return_value=None):
            ind._run()
    assert "[INFO]" in s.getvalue()

    # Edge cases
    ind = _ActivityIndicator(label="x")
    with patch("shutil.get_terminal_size", side_effect=Exception):
        assert ind._terminal_width() == 80
    ind._thread = MagicMock()
    ind._thread.join.side_effect = RuntimeError
    ind.__exit__(None, None, None)


def test_ui_mixin_exhaustive():
    a = MasterAuditor()
    # print_status branches
    for s in ["OKGREEN", "FAIL", "WARNING", "HEADER", "OK", "INFO"]:
        a.print_status("Msg", status=s)

    a._ui_progress_active = True
    a.print_status("Should be suppressed", status="INFO")
    a.print_status("Should be emitted", status="FAIL")
    a.print_status("Forced", status="OK", force=True)

    # ANSI Fallback
    with patch.dict(sys.modules, {"rich.console": None}):
        a.print_status("ANSI Fallback", status="FAIL", force=True)

    # should_emit branches
    a._should_emit_during_progress("error", "FAIL")
    a._should_emit_during_progress("finished", "OK")
    a._should_emit_during_progress("found", "WARN")
    a._should_emit_during_progress("alert", "WARN")

    # get_ui_detail branches
    a._ui_detail = "Existing"
    assert "Existing" in a._get_ui_detail()
    a._ui_detail = ""
    a.current_phase = "vulns:testssl:h"
    assert "testssl" in a._get_ui_detail()

    # phase_detail branches
    for p in [
        "vulns:testssl:h",
        "vulns:nikto:h",
        "vulns:whatweb:h",
        "ports:h",
        "deep:h",
        "discovery:h",
        "topology",
        "vulnerabilities",
        "net_discovery",
        "other",
    ]:
        a.current_phase = p
        a._phase_detail()

    # condense branches
    arrow = "\u2192"
    for s in ["testssl", "nikto", "whatweb", "nuclei", "agentless", "verify"]:
        a._condense_for_ui(f"[{s}] h {arrow} c")
    a._condense_for_ui(f"[SCAN] h {arrow} async udp probe")
    a._condense_for_ui(f"[SCAN] h {arrow} nmap -su")
    a._condense_for_ui(f"[SCAN] h {arrow} nmap -sv -p- -a")
    a._condense_for_ui(f"[SCAN] h {arrow} nmap --top-ports 100")
    a._condense_for_ui(f"[SERVICE] h {arrow} banner grab")

    # coercion
    a._coerce_text(None)
    a._coerce_text(Exception("e"))

    # Formatting
    a._format_eta(3600 * 2 + 65)
    a._format_eta(None)
    a._format_eta("bad")
    a._terminal_width()
    a._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    with patch("shutil.get_terminal_size", return_value=MagicMock(columns=40)):
        a._progress_columns(show_detail=False, show_eta=False, show_elapsed=False)
    a._progress_console()


def test_logging_mixin_exhaustive(tmp_path):
    a = MasterAuditor()
    a.config["output_dir"] = str(tmp_path)
    logging.getLogger("RedAudit").handlers = []
    a._setup_logging()

    # Heartbeat lifecycle
    a.start_heartbeat()
    a.start_heartbeat()
    a.stop_heartbeat()
    a.heartbeat_thread = MagicMock()
    a.heartbeat_thread.join.side_effect = RuntimeError
    a.stop_heartbeat()

    # Heartbeat Loop
    a.last_activity = datetime.now() - timedelta(seconds=200)
    a.current_phase = "scanning"
    a.heartbeat_stop = False
    with (
        patch("redaudit.core.auditor_mixins.HEARTBEAT_FAIL_THRESHOLD", 50),
        patch("redaudit.core.auditor_mixins.HEARTBEAT_WARN_THRESHOLD", 10),
        patch(
            "redaudit.core.auditor_mixins.time.sleep",
            side_effect=lambda x: setattr(a, "heartbeat_stop", True),
        ),
    ):
        a._heartbeat_loop()

    # StreamHandler suppression
    a._ui_progress_active = True
    # Routine log should be suppressed
    a.logger.info("Routine log during progress")
    # Critical log should be emitted
    a.logger.error("CRITICAL log during progress")

    # Formatter coverage
    try:
        raise ValueError("test")
    except Exception:
        a.logger.error("fail", exc_info=True)


def test_crypto_mixin_exhaustive():
    a = MasterAuditor()
    a.cryptography_available = False
    a.setup_encryption()
    a.setup_encryption(non_interactive=True)

    a.cryptography_available = True
    with (
        patch("redaudit.core.auditor_mixins.ask_password_twice", return_value="p"),
        patch("redaudit.core.auditor_mixins.derive_key_from_password", return_value=(b"k", b"s")),
    ):
        a.setup_encryption()

    with (
        patch("redaudit.core.auditor_mixins.derive_key_from_password", return_value=(b"k", b"s")),
        patch("redaudit.core.auditor_mixins.generate_random_password", return_value="p"),
    ):
        a.setup_encryption(non_interactive=True)


def test_nvd_mixin_exhaustive():
    a = MasterAuditor()
    with patch("redaudit.utils.config.get_nvd_api_key", return_value="key"):
        a.setup_nvd_api_key()

    with (
        patch("redaudit.utils.config.get_nvd_api_key", return_value=None),
        patch("redaudit.utils.config.validate_nvd_api_key", side_effect=[True, True, True, True]),
        patch("builtins.input", side_effect=["key", "bad_key", "good_key"]),
        patch("redaudit.utils.config.set_nvd_api_key", return_value=False),
    ):

        a.setup_nvd_api_key(api_key="cli_key")  # CLI success

        a.ask_choice = MagicMock(side_effect=[1, 2, 0])
        a.setup_nvd_api_key()  # Env
        a.setup_nvd_api_key()  # Skip
        a.setup_nvd_api_key()  # Save fail
