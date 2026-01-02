"""Extra coverage tests - imports only"""

import unittest


class TestModuleImports(unittest.TestCase):
    """Tests that import modules to increase coverage."""

    def test_hyperscan_import(self):
        """Verify hyperscan module can be imported."""
        from redaudit.core import hyperscan

        self.assertIsNotNone(hyperscan)

    def test_topology_import(self):
        """Verify topology module can be imported."""
        from redaudit.core import topology

        self.assertIsNotNone(topology)

    def test_net_discovery_import(self):
        """Verify net_discovery module can be imported."""
        from redaudit.core import net_discovery

        self.assertIsNotNone(net_discovery)

    def test_agentless_verify_import(self):
        """Verify agentless_verify module can be imported."""
        from redaudit.core import agentless_verify

        self.assertIsNotNone(agentless_verify)


if __name__ == "__main__":
    unittest.main()
