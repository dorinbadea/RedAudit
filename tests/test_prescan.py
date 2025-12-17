#!/usr/bin/env python3
"""
Tests for RedAudit pre-scan module.
"""

import unittest
import sys
import os
import inspect  # Added for iscoroutinefunction check
from unittest.mock import patch, AsyncMock

from redaudit.core.prescan import (
    parse_port_range,
    TOP_100_PORTS,
    TOP_1024_PORTS,
)


class TestPortRangeParsing(unittest.TestCase):
    """Tests for port range parsing."""

    def test_simple_range(self):
        """Test simple port range."""
        result = parse_port_range("1-10")
        self.assertEqual(result, list(range(1, 11)))

    def test_single_port(self):
        """Test single port."""
        result = parse_port_range("80")
        self.assertEqual(result, [80])

    def test_comma_separated(self):
        """Test comma-separated ports."""
        result = parse_port_range("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_mixed_format(self):
        """Test mixed ranges and single ports."""
        result = parse_port_range("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_invalid_port(self):
        """Test invalid port is ignored."""
        result = parse_port_range("abc,80,xyz")
        self.assertEqual(result, [80])

    def test_out_of_range_port(self):
        """Test out of range ports are clamped."""
        result = parse_port_range("0-5,65534-65540")
        # 0 clamped to 1, 65540 clamped to 65535
        self.assertTrue(1 in result)
        self.assertTrue(65535 in result)
        self.assertFalse(0 in result)

    def test_empty_string(self):
        """Test empty string returns empty list."""
        result = parse_port_range("")
        self.assertEqual(result, [])

    def test_whitespace_handling(self):
        """Test whitespace is handled."""
        result = parse_port_range(" 22 , 80 , 443 ")
        self.assertEqual(result, [22, 80, 443])


class TestPortConstants(unittest.TestCase):
    """Tests for predefined port lists."""

    def test_top_100_ports_exist(self):
        """Test TOP_100_PORTS is defined and has content."""
        self.assertIsInstance(TOP_100_PORTS, list)
        self.assertGreater(len(TOP_100_PORTS), 20)

    def test_top_1024_ports(self):
        """Test TOP_1024_PORTS is 1-1024."""
        self.assertEqual(TOP_1024_PORTS, list(range(1, 1025)))
        self.assertEqual(len(TOP_1024_PORTS), 1024)

    def test_common_ports_included(self):
        """Test common ports are in TOP_100."""
        for port in [22, 80, 443, 3389, 8080]:
            self.assertIn(port, TOP_100_PORTS)


class TestPrescanModule(unittest.TestCase):
    """Tests for prescan module imports and structure."""

    def test_run_prescan_import(self):
        """Test run_prescan can be imported."""
        from redaudit.core.prescan import run_prescan

        self.assertTrue(callable(run_prescan))


class TestAsyncPrescan(unittest.TestCase):

    def test_async_functions_exist(self):
        """Verify that async functions are defined as coroutines"""
        from redaudit.core.prescan import prescan_host, check_port

        # Check that functions are coroutines
        self.assertTrue(inspect.iscoroutinefunction(prescan_host))
        self.assertTrue(inspect.iscoroutinefunction(check_port))


if __name__ == "__main__":
    unittest.main()
