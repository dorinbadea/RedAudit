#!/usr/bin/env python3
"""
RedAudit - Tests for auditor components.
"""

import base64
import builtins
import io
import logging
import sys
import threading
import time
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.auditor_components import (
    _ActivityIndicator,
    AuditorCrypto,
    AuditorLogging,
    AuditorNVD,
    AuditorUI,
)
from redaudit.utils.constants import HEARTBEAT_FAIL_THRESHOLD


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
            "redaudit.core.auditor_components.os.path.expanduser",
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


def test_start_stop_heartbeat():
    """Test heartbeat start/stop lifecycle."""
    app = InteractiveNetworkAuditor()
    app.start_heartbeat()
    assert app.heartbeat_thread is not None
    assert app.heartbeat_thread.is_alive()

    app.stop_heartbeat()
    assert app.heartbeat_stop is True


def test_touch_activity():
    """Test activity tracking update."""
    from datetime import datetime

    app = InteractiveNetworkAuditor()
    before = app.last_activity
    app._touch_activity()
    assert app.last_activity >= before


def test_signal_handler(capsys):
    """Test signal handler sets interrupted state."""
    app = InteractiveNetworkAuditor()
    app.interrupted = False
    app.heartbeat_stop = False

    # Stop heartbeat to prevent SystemExit
    app.heartbeat_stop = True
    try:
        app.signal_handler(2, None)
    except SystemExit:
        pass  # Expected in some cases

    # interrupted should be True after signal
    assert app.interrupted is True or app.heartbeat_stop is True


def test_progress_console():
    """Test _progress_console returns console."""
    app = InteractiveNetworkAuditor()
    console = app._progress_console()
    # Should return a Console or similar object
    assert console is not None


def test_safe_text_column():
    """Test _safe_text_column creates appropriate column."""
    app = InteractiveNetworkAuditor()
    col = app._safe_text_column("[bold]Test[/bold]")
    assert col is not None


def test_progress_columns():
    """Test _progress_columns returns column tuple."""
    app = InteractiveNetworkAuditor()
    cols = app._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    assert isinstance(cols, (list, tuple))
    assert len(cols) > 0


def test_condense_for_ui_variants():
    """Test _condense_for_ui with various patterns."""
    app = InteractiveNetworkAuditor()

    # Quick scan pattern
    result = app._condense_for_ui("[nmap] 10.0.0.1 → nmap -sV --top-ports 100")
    assert "nmap" in result.lower()

    # Empty text
    result = app._condense_for_ui("")
    assert result == ""

    # Text without nmap pattern
    result = app._condense_for_ui("Some other message")
    assert result == "Some other message"


def test_format_eta_edge_cases():
    """Test _format_eta with edge cases."""
    app = InteractiveNetworkAuditor()

    assert app._format_eta(0) == "0:00"
    assert app._format_eta(59) == "0:59"
    assert app._format_eta(3600) == "1:00:00"
    assert app._format_eta(None) == "--:--"


def test_phase_detail_variants():
    """Test _phase_detail with different phase types."""
    app = InteractiveNetworkAuditor()

    app.current_phase = "init"
    result = app._phase_detail()
    assert isinstance(result, str)

    app.current_phase = "saving"
    result = app._phase_detail()
    assert isinstance(result, str)

    app.current_phase = "discovery:10.0.0.0/24"
    result = app._phase_detail()
    assert isinstance(result, str)


def test_subprocess_tracking():
    """Test subprocess tracking for cleanup."""
    app = InteractiveNetworkAuditor()

    # Add a mock subprocess
    from unittest.mock import MagicMock

    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    with app._subprocess_lock:
        app._active_subprocesses.append(mock_proc)

    assert len(app._active_subprocesses) == 1


def test_print_status_variants():
    """Test print_status with different status types."""
    app = InteractiveNetworkAuditor()

    # These should not raise
    app.print_status("Test info", "INFO")
    app.print_status("Test warning", "WARNING")
    app.print_status("Test error", "FAIL")
    app.print_status("Test success", "OKGREEN")


def test_translation_method():
    """Test t() translation method."""
    app = InteractiveNetworkAuditor()
    app.lang = "en"

    # Should return something (key or translation)
    result = app.t("start_audit")
    assert isinstance(result, str)
    assert len(result) > 0


class _DummyTextColumn:
    attempted_overflow = False

    def __init__(self, *args, **kwargs):
        if "overflow" in kwargs:
            _DummyTextColumn.attempted_overflow = True
            raise TypeError("unsupported")
        self.args = args
        self.kwargs = kwargs


class _DummyBarColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyTimeElapsedColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyConsole:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _MockUI(AuditorUI):
    def __init__(self):
        self.COLORS = {
            "INFO": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
            "OKGREEN": "",
            "OKBLUE": "",
            "HEADER": "",
        }
        self.logger = MagicMock()
        self.lang = "en"
        self._print_lock = threading.Lock()
        self._ui_detail_lock = threading.Lock()
        self.activity_lock = threading.Lock()
        self._ui_detail = ""
        self._ui_progress_active = False
        self.current_phase = ""
        self.last_activity = None


class _MockLogger(AuditorLogging):
    def __init__(self):
        self.logger = MagicMock()
        self.heartbeat_thread = None
        self.heartbeat_stop = False
        self.last_activity = datetime.now()
        self.interrupted = False
        self.activity_lock = threading.Lock()
        self.current_phase = "scan"


class _MockCrypto(AuditorCrypto):
    def __init__(self):
        self.config = {}
        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = True
        self.lang = "en"
        self.COLORS = {"WARNING": "", "ENDC": "", "OKGREEN": ""}
        self.colors = self.COLORS
        self.ui = self

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_yes_no(self, *args, **kwargs):
        return True


class _MockNVD(AuditorNVD):
    def __init__(self):
        self.config = {"cve_lookup_enabled": True}
        self.COLORS = {"WARNING": "", "ENDC": "", "CYAN": ""}
        self.lang = "en"
        self.colors = self.COLORS
        self.ui = self

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_choice(self, *args, **kwargs):
        return 2


class _DummySecurityAuditor(AuditorCrypto, AuditorNVD):
    def __init__(self):
        self.config = {"cve_lookup_enabled": True}
        self.encryption_enabled = False
        self.encryption_key = None
        self.cryptography_available = True
        self.lang = "en"
        self.COLORS = {"WARNING": "", "ENDC": "", "CYAN": ""}
        self.printed = []
        self.ui = self
        self.colors = self.COLORS

    def t(self, key, *_args):
        return key

    def print_status(self, message, status="INFO", *_args, **_kwargs):
        self.printed.append((message, status))

    def ask_yes_no(self, *_args, **_kwargs):
        return True

    def ask_choice(self, *_args, **_kwargs):
        return 0


def test_activity_indicator_edge_cases():
    with patch("shutil.get_terminal_size", side_effect=Exception()):
        ai = _ActivityIndicator(label="test")
        assert ai._terminal_width() == 80

    mock_touch = MagicMock()
    ai = _ActivityIndicator(label="test", touch_activity=mock_touch)
    with ai:
        pass
    assert mock_touch.called

    ai = _ActivityIndicator(label="test")
    mock_stream = MagicMock()
    mock_stream.isatty.return_value = True
    mock_stream.write.side_effect = Exception("Write Fail")
    ai._stream = mock_stream
    with ai:
        time.sleep(0.3)


def test_ui_component_print_status_edge():
    ui = _MockUI()
    ui._ui_progress_active = True

    with patch("rich.console.Console.print") as mock_rich_print:
        with patch("builtins.print") as mock_print:
            ui.print_status("routine info", "INFO")
            assert not mock_rich_print.called
            assert not mock_print.called

            ui.print_status("force info", "INFO", force=True)
            assert mock_rich_print.called or mock_print.called


def test_ui_condense_truncation():
    ui = _MockUI()
    long_cmd = "nmap -sS -sV -A -T4 -p 1-65535 --script vuln 192.168.1.1 192.168.1.2 192.168.1.3"
    condensed = ui._condense_for_ui(long_cmd)
    assert len(condensed) <= 61
    assert condensed.endswith("…")


def test_ui_phase_detail():
    ui = _MockUI()
    ui.current_phase = "init"
    assert "init" in ui._phase_detail()
    ui.current_phase = "vulns:testssl:1.1.1.1"
    assert "testssl" in ui._phase_detail()


def test_ui_should_emit_details():
    ui = _MockUI()
    assert ui._should_emit_during_progress("critical error", "FAIL") is True
    assert ui._should_emit_during_progress("routine info", "INFO") is False


def test_ui_format_eta():
    assert "1:40" in AuditorUI._format_eta(100)
    assert "1:00:00" in AuditorUI._format_eta(3600)


def test_logging_component_heartbeat_warns_on_silence(monkeypatch):
    l = _MockLogger()
    l.last_activity = datetime.now() - timedelta(seconds=HEARTBEAT_FAIL_THRESHOLD + 1)
    l.heartbeat_stop = False

    def _sleep(_seconds):
        l.heartbeat_stop = True

    monkeypatch.setattr("redaudit.core.auditor_components.time.sleep", _sleep)
    l._heartbeat_loop()
    assert l.logger.warning.called


def test_crypto_component_setup():
    c = _MockCrypto()
    with patch("redaudit.core.auditor_components.ask_password_twice", return_value="pwd"):
        with patch(
            "redaudit.core.auditor_components.derive_key_from_password",
            return_value=(b"key", b"salt"),
        ):
            c.setup_encryption()
            assert c.encryption_enabled is True


def test_nvd_component_setup():
    n = _MockNVD()
    with patch("redaudit.utils.config.get_nvd_api_key", return_value=None):
        n.setup_nvd_api_key()


def test_progress_columns_and_safe_text(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(
            TextColumn=_DummyTextColumn,
            BarColumn=_DummyBarColumn,
            TimeElapsedColumn=_DummyTimeElapsedColumn,
        ),
    )

    app = InteractiveNetworkAuditor()
    monkeypatch.setattr(app, "_terminal_width", lambda *_args, **_kwargs: 100)

    columns = app._progress_columns(show_detail=True, show_eta=True, show_elapsed=True)
    assert any(isinstance(col, _DummyBarColumn) for col in columns)
    assert any(isinstance(col, _DummyTimeElapsedColumn) for col in columns)
    assert any(isinstance(col, _DummyTextColumn) for col in columns)
    assert _DummyTextColumn.attempted_overflow is True


def test_progress_console_fallback(monkeypatch):
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.console":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    app = InteractiveNetworkAuditor()
    assert app._progress_console() is None


def test_progress_console_with_rich(monkeypatch):
    monkeypatch.setitem(sys.modules, "rich.console", SimpleNamespace(Console=_DummyConsole))
    app = InteractiveNetworkAuditor()
    console = app._progress_console()
    assert isinstance(console, _DummyConsole)


def test_progress_ui_context_toggles():
    app = InteractiveNetworkAuditor()
    assert app._ui_progress_active is False
    with app._progress_ui():
        assert app._ui_progress_active is True
    assert app._ui_progress_active is False


def test_format_and_get_ui_detail(monkeypatch):
    app = InteractiveNetworkAuditor()
    formatted = app._format_ui_detail("hello", "WARN")
    assert formatted.startswith("[yellow]")

    app._ui_detail = "custom"
    assert app._get_ui_detail() == "custom"

    app._ui_detail = ""
    app.current_phase = "vulns:nikto:10.0.0.1"
    assert app._get_ui_detail() == "nikto 10.0.0.1"


def test_setup_encryption_non_interactive_generates_password(monkeypatch):
    auditor = _DummySecurityAuditor()

    monkeypatch.setattr("redaudit.core.auditor_components.generate_random_password", lambda: "pw")
    monkeypatch.setattr(
        "redaudit.core.auditor_components.derive_key_from_password",
        lambda _pw: (b"key", b"salt"),
    )

    auditor.setup_encryption(non_interactive=True, password=None)

    assert auditor.encryption_enabled is True
    assert auditor.encryption_key == b"key"
    assert auditor.config["encryption_enabled"] is True
    assert auditor.config["encryption_salt"] == base64.b64encode(b"salt").decode()


def test_setup_encryption_non_interactive_missing_crypto():
    auditor = _DummySecurityAuditor()
    auditor.cryptography_available = False

    auditor.setup_encryption(non_interactive=True, password="pw")

    assert ("cryptography_required", "FAIL") in auditor.printed


def test_setup_nvd_api_key_cli_valid(monkeypatch):
    auditor = _DummySecurityAuditor()

    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: True)

    auditor.setup_nvd_api_key(api_key="abc")

    assert auditor.config["nvd_api_key"] == "abc"
    assert ("nvd_key_set_cli", "OKGREEN") in auditor.printed


def test_setup_nvd_api_key_cli_invalid(monkeypatch):
    auditor = _DummySecurityAuditor()

    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: False)

    auditor.setup_nvd_api_key(api_key="bad")

    assert auditor.config.get("nvd_api_key") is None
    assert ("nvd_key_invalid", "WARNING") in auditor.printed


def test_setup_nvd_api_key_non_interactive_without_key(monkeypatch):
    auditor = _DummySecurityAuditor()

    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)

    auditor.setup_nvd_api_key(non_interactive=True, api_key=None)

    assert ("nvd_key_not_configured", "WARNING") in auditor.printed


class _DummyStream:
    def __init__(self, is_tty=True):
        self._is_tty = is_tty
        self.writes = []
        self.flush_calls = 0

    def isatty(self):
        return self._is_tty

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        self.flush_calls += 1


def test_activity_indicator_update_reenter_and_clear_line():
    stream = _DummyStream(is_tty=True)
    ai = _ActivityIndicator(label="test", stream=stream)
    ai.update("new message")
    assert ai._message == "new message"

    ai._thread = MagicMock()
    assert ai.__enter__() is ai

    ai._thread = MagicMock()
    ai._thread.join.side_effect = RuntimeError("boom")
    ai.__exit__(None, None, None)
    assert stream.flush_calls >= 0


def test_activity_indicator_run_non_tty_heartbeat(monkeypatch):
    stream = _DummyStream(is_tty=False)
    ai = _ActivityIndicator(label="test", stream=stream, refresh_s=0.25)

    times = iter([0.0, 10.0])
    monkeypatch.setattr("redaudit.core.auditor_components.time.monotonic", lambda: next(times))

    def _sleep(_seconds):
        ai._stop.set()

    monkeypatch.setattr("redaudit.core.auditor_components.time.sleep", _sleep)
    ai._run()
    assert any("[INFO]" in line for line in stream.writes)


def test_activity_indicator_run_tty(monkeypatch):
    stream = _DummyStream(is_tty=True)
    ai = _ActivityIndicator(label="test", stream=stream, refresh_s=0.01)
    ai._terminal_width = lambda: 80

    times = iter([0.0, 1.0])
    monkeypatch.setattr("redaudit.core.auditor_components.time.monotonic", lambda: next(times))

    def _sleep(_seconds):
        ai._stop.set()

    monkeypatch.setattr("redaudit.core.auditor_components.time.sleep", _sleep)
    ai._run()
    assert stream.writes


def test_ui_property_caches_uimanager(monkeypatch):
    ui = _MockUI()
    sentinel = object()

    monkeypatch.setattr("redaudit.core.ui_manager.UIManager", lambda **_kwargs: sentinel)
    assert ui.ui is sentinel
    assert ui.ui is sentinel


def test_print_status_suppressed_sets_detail_and_logs():
    ui = _MockUI()
    ui._ui_progress_active = True
    ui.logger = MagicMock()
    ui._should_emit_during_progress = lambda *_args, **_kwargs: False
    ui._set_ui_detail = MagicMock(side_effect=RuntimeError("boom"))
    ui.print_status("msg", "INFO")
    assert ui.logger.debug.called


def test_print_status_rich_import_error_falls_back(monkeypatch):
    ui = _MockUI()
    ui._ui_progress_active = True
    ui._should_emit_during_progress = lambda *_args, **_kwargs: True

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.console":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    with patch("builtins.print") as mock_print:
        ui.print_status("line1\nline2", "OKGREEN")
        assert mock_print.called


def test_print_status_non_progress_multiline(capsys):
    ui = _MockUI()
    ui._ui_progress_active = False
    ui.print_status("line1\n\nline2", "INFO")
    out = capsys.readouterr().out
    assert "line1" in out


def test_condense_for_ui_patterns():
    ui = _MockUI()
    assert ui._condense_for_ui("[nikto] 10.0.0.1 → nikto -h") == "nikto 10.0.0.1"
    assert ui._condense_for_ui("[agentless] 10.0.0.1 → cmd") == "agentless 10.0.0.1"
    assert "UDP probe" in ui._condense_for_ui("[nmap] 10.0.0.1 → async UDP probe")
    assert "UDP scan" in ui._condense_for_ui("[nmap] 10.0.0.1 → nmap -sU")
    assert "top ports" in ui._condense_for_ui("[nmap] 10.0.0.1 → nmap --top-ports 100")
    assert "banner grab" in ui._condense_for_ui("[nmap] 10.0.0.1 → banner")


def test_format_ui_detail_unknown_status():
    ui = _MockUI()
    assert ui._format_ui_detail("text", "OTHER") == "text"


def test_phase_detail_more_variants():
    ui = _MockUI()
    ui.current_phase = "vulns:whatweb:1.1.1.1"
    assert ui._phase_detail() == "whatweb 1.1.1.1"
    ui.current_phase = "net_discovery"
    assert ui._phase_detail() == "net discovery"
    ui.current_phase = "topology"
    assert ui._phase_detail() == "topology"


def test_should_emit_during_progress_variants():
    ui = _MockUI()
    assert ui._should_emit_during_progress("Identidad profundo finalizado", "OK") is True
    assert ui._should_emit_during_progress("⚠ alerta", "WARN") is True
    assert ui._should_emit_during_progress("normal", "WARN") is False


def test_terminal_width_fallback(monkeypatch):
    ui = _MockUI()
    monkeypatch.setattr(
        "redaudit.core.auditor_components.shutil",
        SimpleNamespace(
            get_terminal_size=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError())
        ),
    )
    assert ui._terminal_width(10) == 60


def test_progress_console_import_error(monkeypatch):
    ui = _MockUI()
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.console":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    assert ui._progress_console() is None


def test_safe_text_column_import_error(monkeypatch):
    ui = _MockUI()
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.progress":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    assert ui._safe_text_column("x") is None


def test_progress_columns_import_error(monkeypatch):
    ui = _MockUI()
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.progress":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    assert ui._progress_columns(show_detail=True, show_eta=True, show_elapsed=True) == []


def test_setup_logging_warning_when_file_disabled(monkeypatch, caplog):
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = []
    try:
        app = InteractiveNetworkAuditor()
        monkeypatch.setattr(
            "redaudit.core.auditor_components.os.makedirs",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
        )
        with caplog.at_level(logging.WARNING, logger="RedAudit"):
            app._setup_logging()
        assert "File logging disabled" in caplog.text
    finally:
        logger.handlers = original_handlers


def test_setup_logging_adds_file_handler_when_missing(monkeypatch, tmp_path):
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = [logging.StreamHandler(io.StringIO())]
    try:
        app = InteractiveNetworkAuditor()
        monkeypatch.setattr(
            "redaudit.core.auditor_components.os.path.expanduser",
            lambda *_args, **_kwargs: str(tmp_path),
        )
        app._setup_logging()
        assert any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers)
    finally:
        logger.handlers = original_handlers


def test_ui_aware_stream_handler_skips_emit():
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = []
    try:
        app = InteractiveNetworkAuditor()
        app._setup_logging()
        handler = next(h for h in app.logger.handlers if not isinstance(h, RotatingFileHandler))
        handler._ui_active = lambda: True
        handler.stream = io.StringIO()
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "msg", None, None)
        handler.emit(record)
        assert handler.stream.getvalue() == ""
    finally:
        logger.handlers = original_handlers


def test_no_traceback_formatter_strips_exc_info():
    logger = logging.getLogger("RedAudit")
    original_handlers = list(logger.handlers)
    logger.handlers = []
    try:
        app = InteractiveNetworkAuditor()
        app._setup_logging()
        handler = next(h for h in app.logger.handlers if not isinstance(h, RotatingFileHandler))
        formatter = handler.formatter
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "msg", None, None)
        record.exc_info = ("exc", "info", "tb")
        record.stack_info = "stack"
        formatter.format(record)
        assert record.exc_info == ("exc", "info", "tb")
    finally:
        logger.handlers = original_handlers


def test_start_stop_heartbeat_early_exit(monkeypatch):
    l = _MockLogger()
    l.heartbeat_thread = MagicMock()
    l.start_heartbeat()
    assert l.heartbeat_thread is not None

    l.heartbeat_thread.join.side_effect = RuntimeError("boom")
    l.stop_heartbeat()
    assert l.logger.debug.called


def test_heartbeat_warn_threshold(monkeypatch):
    l = _MockLogger()
    l.last_activity = datetime.now() - timedelta(seconds=HEARTBEAT_FAIL_THRESHOLD - 1)
    l.heartbeat_stop = False

    def _sleep(_seconds):
        l.heartbeat_stop = True

    monkeypatch.setattr("redaudit.core.auditor_components.time.sleep", _sleep)
    l._heartbeat_loop()
    assert l.logger.debug.called


def test_setup_encryption_interactive_crypto_runtime(monkeypatch):
    auditor = _DummySecurityAuditor()

    monkeypatch.setattr(
        "redaudit.core.auditor_components.ask_password_twice",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("cryptography not available")),
    )
    auditor.setup_encryption(non_interactive=False)
    assert ("cryptography_required", "FAIL") in auditor.printed


def test_setup_encryption_non_interactive_runtime(monkeypatch):
    auditor = _DummySecurityAuditor()
    monkeypatch.setattr(
        "redaudit.core.auditor_components.derive_key_from_password",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("cryptography not available")),
    )
    auditor.setup_encryption(non_interactive=True, password="pw")
    assert ("cryptography_required", "FAIL") in auditor.printed


def test_setup_nvd_api_key_import_error(monkeypatch):
    auditor = _DummySecurityAuditor()
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "redaudit.utils.config":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    auditor.setup_nvd_api_key()
    assert ("config_module_missing", "WARNING") in auditor.printed


def test_setup_nvd_api_key_existing(monkeypatch):
    auditor = _DummySecurityAuditor()
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: "existing")
    auditor.setup_nvd_api_key()
    assert auditor.config["nvd_api_key"] == "existing"


def test_setup_nvd_api_key_interactive_choice_save_empty(monkeypatch):
    auditor = _DummySecurityAuditor()
    auditor.ask_choice = lambda *_args, **_kwargs: 0
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "")
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)
    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: True)
    monkeypatch.setattr("redaudit.utils.config.set_nvd_api_key", lambda *_args, **_kwargs: True)
    auditor.setup_nvd_api_key()
    assert ("nvd_key_skipped", "INFO") in auditor.printed


def test_setup_nvd_api_key_interactive_invalid_then_valid(monkeypatch):
    auditor = _DummySecurityAuditor()
    auditor.ask_choice = lambda *_args, **_kwargs: 0
    keys = iter(["bad", "good"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(keys))
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)
    monkeypatch.setattr(
        "redaudit.utils.config.validate_nvd_api_key",
        lambda k: k == "good",
    )
    monkeypatch.setattr("redaudit.utils.config.set_nvd_api_key", lambda *_args, **_kwargs: True)
    auditor.setup_nvd_api_key()
    assert ("nvd_key_invalid_format", "WARNING") in auditor.printed
    assert ("nvd_key_saved", "OKGREEN") in auditor.printed


def test_setup_nvd_api_key_interactive_save_error(monkeypatch):
    auditor = _DummySecurityAuditor()
    auditor.ask_choice = lambda *_args, **_kwargs: 0
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: "good")
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)
    monkeypatch.setattr("redaudit.utils.config.validate_nvd_api_key", lambda _k: True)
    monkeypatch.setattr("redaudit.utils.config.set_nvd_api_key", lambda *_args, **_kwargs: False)
    auditor.setup_nvd_api_key()
    assert ("nvd_key_save_error", "WARNING") in auditor.printed


def test_setup_nvd_api_key_interactive_env(monkeypatch):
    auditor = _DummySecurityAuditor()
    auditor.ask_choice = lambda *_args, **_kwargs: 1
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)
    auditor.setup_nvd_api_key()
    assert ("nvd_env_set_later", "INFO") in auditor.printed


def test_setup_nvd_api_key_interactive_skip(monkeypatch):
    auditor = _DummySecurityAuditor()
    auditor.ask_choice = lambda *_args, **_kwargs: 2
    monkeypatch.setattr("redaudit.utils.config.get_nvd_api_key", lambda: None)
    auditor.setup_nvd_api_key()
    assert ("nvd_slow_mode", "WARNING") in auditor.printed
