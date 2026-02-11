import unittest
from unittest.mock import MagicMock, patch
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.config_context import ConfigurationContext


class TestAuditorUtils(unittest.TestCase):
    def setUp(self):
        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(
            side_effect=lambda k, *args: f"TRANSLATED_{k} {args}" if args else f"TRANSLATED_{k}"
        )
        self.auditor.ui.colors = {"FAIL": "", "ENDC": "", "INFO": ""}
        self.auditor.config = ConfigurationContext()
        self.auditor.ask_yes_no = MagicMock()

    def test_show_legal_warning(self):
        """Test legal warning display and confirmation."""
        self.auditor.ask_yes_no.return_value = True
        res = self.auditor.show_legal_warning()
        self.assertTrue(res)
        self.auditor.ask_yes_no.assert_called_with("TRANSLATED_legal_ask", default="no")

    def test_show_target_summary_empty(self):
        """Test summary with no targets."""
        self.auditor.config["target_networks"] = []
        self.auditor._show_target_summary()
        self.auditor.ui.print_status.assert_not_called()

    def test_show_target_summary_valid(self):
        """Test summary with converted network targets."""
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor._show_target_summary()
        # "192.168.1.0/24 (~256)"
        calls = self.auditor.ui.print_status.call_args_list
        self.assertTrue(any("192.168.1.0/24 (~256)" in str(c) for c in calls))

    def test_show_target_summary_invalid(self):
        """Test summary with invalid network strings."""
        self.auditor.config["target_networks"] = ["invalid_net"]
        self.auditor._show_target_summary()
        calls = self.auditor.ui.print_status.call_args_list
        self.assertTrue(any("invalid_net" in str(c) for c in calls))

    @patch("redaudit.core.auditor.show_config_summary")
    def test_show_config_summary(self, mock_show):
        self.auditor.show_config_summary()
        mock_show.assert_called_once()

    @patch("redaudit.core.auditor.show_results_summary")
    def test_show_results(self, mock_show):
        self.auditor.config["output_dir"] = "/tmp"
        self.auditor.show_results()
        mock_show.assert_called_once()

    @patch("redaudit.core.auditor.save_results")
    def test_save_results(self, mock_save):
        self.auditor.save_results(partial=True)
        self.assertEqual(self.auditor.current_phase, "saving")
        mock_save.assert_called_with(
            self.auditor.results,
            self.auditor.config,
            self.auditor.encryption_enabled,
            self.auditor.encryption_key,
            True,  # partial
            self.auditor.ui.print_status,
            self.auditor.ui.t,
            self.auditor.logger,
        )
