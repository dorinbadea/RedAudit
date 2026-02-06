import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from redaudit.core.network_scanner import NetworkScanner  # noqa: E402


# Mock config
class MockConfig:
    identity_threshold = 4

    def get(self, k, default=None):
        return default


def test_ghost_identity_trigger():
    scanner = NetworkScanner(config=MockConfig(), ui=None)

    # Case: High identity score (e.g. 3 or 4 points from hints) but 0 ports
    # Should trigger deep scan now
    should, reason = scanner.should_trigger_deep_scan(
        total_ports=0,
        any_version=False,
        suspicious=False,
        device_type_hints=["router", "snmp_device"],
        identity_score=4,
        identity_threshold=4,
    )

    print(f"Case 1 (Score 4, Ports 0): Trigger={should}, Reason={reason}")
    if not should or reason != "high_identity_zero_ports":
        print("FAIL: Did not trigger on Ghost Identity")
        sys.exit(1)

    # Case: High identity score, ports exist
    should, reason = scanner.should_trigger_deep_scan(
        total_ports=5,
        any_version=True,
        suspicious=False,
        device_type_hints=["router"],
        identity_score=5,
        identity_threshold=4,
    )
    print(f"Case 2 (Score 5, Ports 5): Trigger={should}, Reason={reason}")
    if should:
        print("FAIL: Triggered unnecessarily")
        sys.exit(1)

    print("SUCCESS: NetworkScanner fix verified.")


if __name__ == "__main__":
    test_ghost_identity_trigger()
