"""
Tests for i18n.py and session_log.py edge cases.
Target: Improve coverage of language detection and session logging.
"""

import pytest
from unittest.mock import patch, MagicMock
import os


class TestGetText:
    """Tests for get_text function."""

    def test_get_text_english(self):
        """Test getting English text."""
        from redaudit.utils.i18n import get_text

        result = get_text("legal_warn", "en")
        assert "LEGAL WARNING" in result

    def test_get_text_spanish(self):
        """Test getting Spanish text."""
        from redaudit.utils.i18n import get_text

        result = get_text("legal_warn", "es")
        assert "ADVERTENCIA LEGAL" in result

    def test_get_text_with_args(self):
        """Test text with format args."""
        from redaudit.utils.i18n import get_text

        result = get_text("hosts_active", "en", "192.168.1.0/24", 10)
        assert "192.168.1.0/24" in result
        assert "10" in result

    def test_get_text_missing_key(self):
        """Test missing key returns key."""
        from redaudit.utils.i18n import get_text

        result = get_text("nonexistent_key", "en")
        assert result == "nonexistent_key"

    def test_get_text_unknown_language_fallback(self):
        """Test unknown language falls back to English."""
        from redaudit.utils.i18n import get_text

        result = get_text("legal_warn", "fr")
        assert "LEGAL WARNING" in result


class TestDetectPreferredLanguage:
    """Tests for detect_preferred_language function."""

    def test_detect_explicit_preference(self):
        """Test explicit preference is used."""
        from redaudit.utils.i18n import detect_preferred_language

        result = detect_preferred_language("es")
        assert result == "es"

    def test_detect_invalid_explicit_preference(self):
        """Test invalid explicit preference falls back."""
        from redaudit.utils.i18n import detect_preferred_language

        with patch.dict(os.environ, {}, clear=True):
            with patch("locale.getlocale", return_value=(None, None)):
                with patch("locale.getdefaultlocale", return_value=(None, None)):
                    result = detect_preferred_language("fr")

        assert result == "en"

    def test_detect_from_lc_all(self):
        """Test detection from LC_ALL environment."""
        from redaudit.utils.i18n import detect_preferred_language

        with patch.dict(os.environ, {"LC_ALL": "es_ES.UTF-8"}, clear=True):
            result = detect_preferred_language()

        assert result == "es"

    def test_detect_from_lang(self):
        """Test detection from LANG environment."""
        from redaudit.utils.i18n import detect_preferred_language

        with patch.dict(os.environ, {"LANG": "en_US.UTF-8"}, clear=True):
            result = detect_preferred_language()

        assert result == "en"

    def test_detect_from_locale_getlocale(self):
        """Test detection from locale.getlocale()."""
        from redaudit.utils.i18n import detect_preferred_language

        with patch.dict(os.environ, {}, clear=True):
            with patch("locale.getlocale", return_value=("es_ES", "UTF-8")):
                result = detect_preferred_language()

        assert result == "es"

    def test_detect_locale_exception(self):
        """Test exception handling in locale detection."""
        from redaudit.utils.i18n import detect_preferred_language

        with patch.dict(os.environ, {}, clear=True):
            with patch("locale.getlocale") as mock_getlocale:
                mock_getlocale.side_effect = Exception("Locale error")
                with patch("locale.getdefaultlocale") as mock_getdefault:
                    mock_getdefault.side_effect = Exception("Default locale error")
                    result = detect_preferred_language()

        assert result == "en"


class TestSessionLogger:
    """Tests for SessionLogger class."""

    def test_session_logger_init(self, tmp_path):
        """Test SessionLogger initialization."""
        from redaudit.utils.session_log import SessionLogger

        logger = SessionLogger(str(tmp_path), "test_session")

        assert logger.output_dir == tmp_path
        assert logger.session_name == "test_session"
        assert logger.active is False

    def test_session_logger_start_disabled(self, tmp_path):
        """Test start when mode is disabled."""
        from redaudit.utils.session_log import SessionLogger

        logger = SessionLogger(str(tmp_path), mode="off")
        result = logger.start()

        assert result is False
        assert logger.active is False

    def test_session_logger_start_success(self, tmp_path):
        """Test successful start."""
        from redaudit.utils.session_log import SessionLogger
        import sys

        logger = SessionLogger(str(tmp_path), "test_session")
        result = logger.start()

        assert result is True
        assert logger.active is True

        # Cleanup
        logger.stop()

    def test_session_logger_stop(self, tmp_path):
        """Test stop restores streams."""
        from redaudit.utils.session_log import SessionLogger
        import sys

        original_stdout = sys.stdout

        logger = SessionLogger(str(tmp_path), "test_session")
        logger.start()
        logger.stop()

        assert logger.active is False
        assert sys.stdout == original_stdout


class TestTeeStream:
    """Tests for TeeStream helper class."""

    def test_tee_stream_write(self, tmp_path):
        """Test TeeStream writes to both streams."""
        from redaudit.utils.session_log import TeeStream
        import io

        main_stream = io.StringIO()
        log_stream = io.StringIO()

        tee = TeeStream(main_stream, log_stream)
        tee.write("test message")
        tee.flush()

        assert "test message" in main_stream.getvalue()

    def test_tee_stream_encoding_property(self, tmp_path):
        """Test TeeStream has encoding property."""
        from redaudit.utils.session_log import TeeStream
        import io

        main_stream = io.StringIO()
        log_stream = io.StringIO()

        tee = TeeStream(main_stream, log_stream)

        # Should have encoding attribute
        assert hasattr(tee, "encoding")
