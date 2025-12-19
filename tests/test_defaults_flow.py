#!/usr/bin/env python3
"""
Tests for interactive defaults flow.
"""

import unittest
from unittest.mock import patch

from redaudit import InteractiveNetworkAuditor


class TestDefaultsFlow(unittest.TestCase):
    def test_review_defaults_skips_immediate_start_prompt_when_no_summary(self):
        app = InteractiveNetworkAuditor()

        # Make prompts deterministic by returning the key itself.
        app.t = lambda key, *args: key

        asked = []

        def fake_yes_no(question: str, default: str = "yes") -> bool:
            asked.append(question)
            if question == "defaults_show_summary_q":
                return False
            if question in ("save_defaults_q", "start_audit"):
                return False
            return False

        app.clear_screen = lambda: None
        app.print_banner = lambda: None
        app.check_dependencies = lambda: True
        app.show_legal_warning = lambda: True
        app.ask_choice = lambda q, opts, default=0: 1  # review/modify
        app.ask_network_range = lambda: ["192.168.1.0/24"]
        app._configure_scan_interactive = lambda defaults: None
        app.show_config_summary = lambda: None
        app.ask_yes_no = fake_yes_no

        with patch("redaudit.utils.config.get_persistent_defaults") as mock_get_defaults:
            mock_get_defaults.return_value = {"threads": 4, "scan_mode": "completo"}
            app.interactive_setup()

        self.assertIn("defaults_show_summary_q", asked)
        self.assertNotIn(
            "defaults_use_immediately_q",
            asked,
            "Should not ask to start immediately unless the summary was reviewed",
        )
