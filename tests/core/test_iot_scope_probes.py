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
    assert runtime["evidence"][0]["classification"] == "hint"
    assert runtime["evidence"][0]["reason"] == "budget_exceeded"
