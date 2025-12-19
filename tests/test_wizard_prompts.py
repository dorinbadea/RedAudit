#!/usr/bin/env python3
"""
Tests for wizard prompt clarity.
"""

import unittest
from unittest.mock import patch

from redaudit import InteractiveNetworkAuditor


class TestWizardPrompts(unittest.TestCase):
    def test_net_discovery_snmp_prompt_shows_default_brackets(self):
        app = InteractiveNetworkAuditor()
        app.lang = "en"

        prompts = []

        def fake_input(prompt: str) -> str:
            prompts.append(prompt)
            return ""

        with patch("builtins.input", side_effect=fake_input):
            # Force the advanced options prompt to show.
            app.ask_yes_no = lambda q, default="yes": True
            opts = app.ask_net_discovery_options()

        self.assertEqual(opts.get("snmp_community"), "public")
        self.assertTrue(any("[public]" in p for p in prompts), "SNMP prompt should show [public]")
        self.assertTrue(
            any("ENTER" in p.upper() for p in prompts),
            "Prompt should clarify ENTER behavior",
        )
