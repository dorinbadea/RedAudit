#!/usr/bin/env python3

from redaudit.core.iot_scope_probes import (
    normalize_iot_probe_packs,
    run_iot_scope_probes,
    select_iot_probe_candidates,
)


def test_normalize_iot_probe_packs_filters_invalid_and_deduplicates():
    packs = normalize_iot_probe_packs(["ssdp,coap", "ssdp", "bad", "wiz"])
    assert packs == ["ssdp", "coap", "wiz"]


def test_select_iot_probe_candidates_requires_safe_mode_and_ambiguous_signal():
    hosts = [
        {
            "ip": "10.0.0.5",
            "smart_scan": {"identity_score": 1},
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        },
        {
            "ip": "10.0.0.6",
            "smart_scan": {"identity_score": 8},
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        },
    ]

    assert select_iot_probe_candidates(hosts, mode="off", selected_packs=["ssdp"]) == []

    candidates = select_iot_probe_candidates(hosts, mode="safe", selected_packs=["ssdp"])
    assert len(candidates) == 1
    assert candidates[0]["ip"] == "10.0.0.5"


def test_run_iot_scope_probes_collects_runtime_and_evidence():
    hosts = [
        {
            "ip": "10.0.0.20",
            "smart_scan": {"identity_score": 2},
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        }
    ]

    def _probe_runner(ip, ports, timeout, concurrency):
        port = int(ports[0])
        if port == 1900:
            return [{"port": 1900, "state": "responded"}]
        if port == 5683:
            return [{"port": 5683, "state": "closed"}]
        return [{"port": port, "state": "no_response"}]

    runtime = run_iot_scope_probes(
        hosts,
        mode="safe",
        packs=["ssdp", "coap"],
        budget_seconds=20,
        timeout_seconds=2,
        probe_runner=_probe_runner,
        time_provider=lambda: 0.0,
    )

    assert runtime["mode"] == "safe"
    assert runtime["packs"] == ["ssdp", "coap"]
    assert runtime["candidates"] == 1
    assert runtime["executed_hosts"] == 1
    assert runtime["probes_total"] == 2
    assert runtime["probes_executed"] == 2
    assert runtime["probes_responded"] == 1
    assert runtime["budget_exceeded_hosts"] == 0
    classifications = {e["classification"] for e in runtime["evidence"]}
    assert "evidence" in classifications
    assert "heuristic" in classifications


def test_run_iot_scope_probes_marks_budget_exceeded_as_hint():
    hosts = [
        {
            "ip": "10.0.0.30",
            "smart_scan": {"identity_score": 1},
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        }
    ]

    ticks = [0.0, 5.0, 5.0, 5.0]

    def _time_provider():
        return ticks.pop(0) if ticks else 5.0

    runtime = run_iot_scope_probes(
        hosts,
        mode="safe",
        packs=["ssdp"],
        budget_seconds=1,
        timeout_seconds=1,
        probe_runner=lambda *_args, **_kwargs: [{"port": 1900, "state": "responded"}],
        time_provider=_time_provider,
    )

    assert runtime["candidates"] == 1
    assert runtime["probes_executed"] == 0
    assert runtime["budget_exceeded_hosts"] == 1
    assert runtime["reasons"].get("budget_exceeded") == 1
    assert runtime["evidence"][0]["reason"] == "budget_exceeded"


def test_normalize_iot_probe_packs_edge_cases():
    """Test normalization with None, empty strings, and case sensitivity."""
    assert normalize_iot_probe_packs(None) == []
    assert normalize_iot_probe_packs([]) == []
    assert normalize_iot_probe_packs([""]) == []
    assert normalize_iot_probe_packs(["SSDP", "CoAP"]) == ["ssdp", "coap"]
    assert normalize_iot_probe_packs("ssdp, coap") == ["ssdp", "coap"]


def test_extract_open_udp_ports_malformed():
    """Test port extraction with malformed host data."""
    from redaudit.core.iot_scope_probes import _extract_open_udp_ports

    # Malformed port entry
    host = {"ports": [{"port": "invalid"}]}
    assert _extract_open_udp_ports(host) == []

    # Malformed service entry
    host = {"services": [{"port": "invalid"}]}
    assert _extract_open_udp_ports(host) == []

    # Mixed valid and invalid
    host = {"ports": [{"port": 1900, "protocol": "udp", "state": "open"}, {"port": "bad"}, {}]}
    assert _extract_open_udp_ports(host) == [1900]


def test_host_has_strong_iot_signal_variations():
    """Test signal detection with various attributes."""
    from redaudit.core.iot_scope_probes import _host_has_strong_iot_signal

    # Asset type
    assert _host_has_strong_iot_signal({"asset_type": "IoT"}, [])

    # Device type hints
    assert _host_has_strong_iot_signal({"device_type_hints": ["smart_tv"]}, [])

    # Agentless fingerprint type
    assert _host_has_strong_iot_signal({"agentless_fingerprint": {"device_type": "camera"}}, [])

    # Agentless fingerprint vendor
    assert _host_has_strong_iot_signal({"agentless_fingerprint": {"device_vendor": "Axis"}}, [])

    # UDP port overlap
    host = {"ports": [{"port": 1900, "protocol": "udp", "state": "open"}]}
    assert _host_has_strong_iot_signal(host, [1900])

    # No signal
    assert not _host_has_strong_iot_signal({}, [])


def test_run_iot_scope_probes_inputs_and_limits():
    """Test input validation and limit clamping."""
    # Min budget/timeout
    runtime = run_iot_scope_probes([], mode="safe", packs=None, budget_seconds=0, timeout_seconds=0)
    assert runtime["budget_seconds"] == 20
    assert runtime["timeout_seconds"] == 3

    # Max budget/timeout
    runtime = run_iot_scope_probes(
        [], mode="safe", packs=None, budget_seconds=1000, timeout_seconds=100
    )
    assert runtime["budget_seconds"] == 300
    assert runtime["timeout_seconds"] == 60

    # Invalid types
    runtime = run_iot_scope_probes(
        [], mode="safe", packs=None, budget_seconds="bad", timeout_seconds="bad"
    )
    assert runtime["budget_seconds"] == 20
    assert runtime["timeout_seconds"] == 3


def test_run_iot_scope_probes_runner_exception():
    """Test exception handling in probe runner."""
    hosts = [
        {
            "ip": "10.0.0.50",
            "smart_scan": {"identity_score": 1},
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        }
    ]

    def _runner_raise(*args, **kwargs):
        raise RuntimeError("Runner failed")

    runtime = run_iot_scope_probes(
        hosts,
        mode="safe",
        packs=["ssdp"],
        budget_seconds=20,
        timeout_seconds=2,
        probe_runner=_runner_raise,
    )

    assert runtime["probes_executed"] == 1
    assert runtime["reasons"].get("no_response") == 1


def test_host_get_attribute_access():
    """Test _host_get with object attributes instead of dict keys."""
    from redaudit.core.iot_scope_probes import _host_get

    class HostObj:
        def __init__(self):
            self.key = "value"

    obj = HostObj()
    assert _host_get(obj, "key") == "value"
    assert _host_get(obj, "missing", "default") == "default"


def test_extract_open_udp_ports_extensions():
    """Test extract_open_udp_ports with non-dict list items and services list."""
    from redaudit.core.iot_scope_probes import _extract_open_udp_ports

    host = {
        "ports": ["not-a-dict", {"port": 53, "protocol": "udp"}],
        "services": [
            {"port": 123, "protocol": "udp", "state": "open"},
            {"port": "bad"},
        ],
    }

    ports = _extract_open_udp_ports(host)
    assert 53 in ports
    assert 123 in ports
    assert len(ports) == 2


def test_select_iot_probe_candidates_missing_ip():
    """Test skipping hosts without IP or empty IP."""
    hosts = [{"ip": ""}, {"ip": None}, {"other": "value"}]
    candidates = select_iot_probe_candidates(hosts, mode="safe", selected_packs=["ssdp"])
    assert len(candidates) == 0


def test_select_iot_probe_candidates_identity_exception():
    """Test handling of malformed identity score."""
    # smart_scan is a list instead of dict, causing .get to fail or logic to break if not careful
    # The code does: int((smart_scan or {}).get("identity_score", 0))
    # If smart_scan is NOT a dict but has no get method, it raises Attribute Error caught by Exception
    pass
    # Actually checking the code:
    # try: identity_score = int((smart_scan or {}).get("identity_score", 0))
    # except Exception: identity_score = 0

    hosts = [
        {
            "ip": "10.0.0.1",
            "smart_scan": "not-a-dict",  # AttributeError on .get
            "tags": ["iot"],
            "ports": [{"port": 1900, "protocol": "udp", "state": "open"}],
        }
    ]
    candidates = select_iot_probe_candidates(hosts, mode="safe", selected_packs=["ssdp"])
    assert len(candidates) == 1
    assert candidates[0]["identity_score"] == 0
