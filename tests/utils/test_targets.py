#!/usr/bin/env python3
"""
RedAudit - Tests for targets utility.
"""

import unittest
from redaudit.utils import targets


class TestTargets(unittest.TestCase):
    """Tests for target parsing logic."""

    def test_parse_target_tokens_basic_cidr(self):
        """Test parsing valid CIDR strings."""
        tokens = ["192.168.1.0/24", "10.0.0.1"]
        valid, invalid = targets.parse_target_tokens(tokens, max_len=50)

        self.assertEqual(len(valid), 2)
        self.assertEqual(len(invalid), 0)
        self.assertIn("192.168.1.0/24", valid)
        self.assertIn("10.0.0.1/32", valid)

    def test_parse_target_tokens_ranges(self):
        """Test parsing IP ranges (start-end)."""
        # 192.168.1.1-192.168.1.3 covers .1, .2, .3
        # summarize_address_range returns minimal subnets:
        # .1/32 (no, wait, summarize is smarter)
        # 1-3 -> 1/32, 2/31 (2,3)
        tokens = ["192.168.1.1-192.168.1.3"]
        valid, invalid = targets.parse_target_tokens(tokens, max_len=50)

        self.assertEqual(len(invalid), 0)
        # Should result in 192.168.1.1/32 and 192.168.1.2/31 (which covers .2 and .3)
        self.assertEqual(len(valid), 2)
        self.assertIn("192.168.1.1/32", valid)
        self.assertIn("192.168.1.2/31", valid)

    def test_parse_target_tokens_invalid_inputs(self):
        """Test parsing invalid inputs."""
        tokens = [
            "",  # Empty
            "   ",  # Whitespace
            "invalid_ip",  # Garbage
            "192.168.1.1-invalid",  # Bad range end
            "invalid-192.168.1.1",  # Bad range start
            "192.168.1.1-",  # Incomplete range
            "-192.168.1.1",  # Incomplete range
        ]
        valid, invalid = targets.parse_target_tokens(tokens, max_len=50)

        self.assertEqual(len(valid), 0)
        self.assertEqual(len(invalid), 5)  # Empty/whitespace skipped, others added to invalid
        self.assertIn("invalid_ip", invalid)

    def test_parse_target_tokens_range_errors(self):
        """Test logic errors in ranges."""
        tokens = [
            "192.168.1.5-192.168.1.1",  # Start > End
            "192.168.1.1-2001:db8::1",  # Version mismatch
        ]
        valid, invalid = targets.parse_target_tokens(tokens, max_len=50)

        self.assertEqual(len(valid), 0)
        self.assertEqual(len(invalid), 2)

    def test_parse_target_tokens_max_len(self):
        """Test max length constraint."""
        long_token = "A" * 51
        valid, invalid = targets.parse_target_tokens([long_token], max_len=50)

        self.assertEqual(len(valid), 0)
        self.assertEqual(len(invalid), 1)
        self.assertIn(long_token, invalid)

    def test_parse_target_tokens_deduplication(self):
        """Test that duplicate subnets are removed."""
        tokens = ["192.168.1.1", "192.168.1.1", "10.0.0.0/24", "10.0.0.0/24"]
        valid, invalid = targets.parse_target_tokens(tokens, max_len=50)

        self.assertEqual(len(valid), 2)
        self.assertEqual(len(invalid), 0)

    def test_parse_target_tokens_whitespace_handling(self):
        """Test whitespace stripping."""
        # Just string stripping check
        valid, _ = targets.parse_target_tokens([" 192.168.1.1 "], max_len=50)
        self.assertIn("192.168.1.1/32", valid)
