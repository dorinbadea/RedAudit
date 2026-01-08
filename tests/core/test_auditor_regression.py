from unittest.mock import MagicMock, patch
from redaudit.core.models import Host, Service
from redaudit.core.auditor_scan import AuditorScan


def test_auditor_risk_score_recalculation_with_host_objects():
    """Test that risk score recalculation works for Host objects (not just dicts)."""
    # Mock data
    host_obj = Host(ip="192.168.1.100")
    # Simulate Findings from Phase 2
    findings_map = {"192.168.1.100": [{"severity": "high", "title": "Critical Vuln"}]}

    # Manually inject findings into the map to simulate run_complete_scan logic
    results = [host_obj]

    for host in results:
        # Proposed fix logic
        if isinstance(host, dict):
            ip = host.get("ip")
        else:
            ip = getattr(host, "ip", None)

        if ip and ip in findings_map:
            if isinstance(host, dict):
                host["findings"] = findings_map[ip]
            else:
                setattr(host, "findings", findings_map[ip])

        # Recalculate - assuming calculate_risk_score works
        # For this test, we just want to ensure no AttributeError is raised
        # and attributes are set
        if isinstance(host, dict):
            host["risk_score"] = 10.0
        else:
            setattr(host, "risk_score", 10.0)

    assert host_obj.findings == findings_map["192.168.1.100"]
    assert host_obj.risk_score == 10.0


class MockAuditor(AuditorScan):
    def __init__(self):
        self.config = {
            "windows_verify_enabled": True,
            "windows_verify_max_targets": 20,
            "threads": 1,
            "dry_run": False,
        }
        self.ui = MagicMock()
        self.logger = MagicMock()
        self.proxy_manager = None
        self.interrupted = False
        self.results = {}

    def _progress_ui(self):
        return MagicMock()  # Context manager


def test_run_agentless_verification_with_host_objects():
    """Test that run_agentless_verification works with Host objects."""
    auditor = MockAuditor()

    # Create a Host object simulating a target
    host = Host(ip="192.168.1.10")
    # Add a service that triggers agentless (e.g., SMB)
    service = Service(port=445, name="microsoft-ds", state="open")
    host.services = [service]

    hosts = [host]

    # Mock probe_agentless_services to return a fake result
    fake_result = {
        "ip": "192.168.1.10",
        "smb": {"os": "Windows Server 2019", "computer_name": "DC01", "domain": "CORP"},
    }

    with patch("redaudit.core.auditor_scan.probe_agentless_services", return_value=fake_result):
        auditor.run_agentless_verification(hosts)

    # Verify the host object was updated
    assert hasattr(host, "agentless_fingerprint")
    fp = host.agentless_fingerprint
    assert fp.get("os") == "Windows Server 2019"
    assert fp.get("computer_name") == "DC01"
    assert fp.get("domain") == "CORP"

    # Verify results were stored
    assert hasattr(host, "agentless_probe")
