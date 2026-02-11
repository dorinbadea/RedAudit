#!/usr/bin/env python3
"""
Supplemental tests for redaudit.core.scope_expansion to improve coverage.
Focuses on edge cases, error handling, and IPv6 logic not covered by main tests.
"""

import ipaddress
from unittest.mock import patch

from redaudit.core.scope_expansion import (
    _extract_url_endpoints,
    _host_matches_allow_rules,
    _ip_matches_allow_rules,
    _is_internal_ip,
    _parse_network_list,
    _parse_allowlist,
    _parse_policy_targets,
    _resolve_profile_targets,
    normalize_leak_follow_policy_pack,
    normalize_leak_follow_profiles,
    evaluate_leak_follow_candidates,
    build_leak_follow_targets,
    extract_leak_follow_candidates,
)


def test_is_internal_ip_ipv6():
    # Loopback
    assert _is_internal_ip(ipaddress.ip_address("::1")) is False

    # Link-local
    assert _is_internal_ip(ipaddress.ip_address("fe80::1")) is True

    # Private (Unique Local)
    assert _is_internal_ip(ipaddress.ip_address("fc00::1")) is True

    # Public (Global Unicast) - using Google's DNS as example of public
    assert _is_internal_ip(ipaddress.ip_address("2001:4860:4860::8888")) is False


def test_extract_url_endpoints_malformed():
    # Test with port out of range which might trigger exceptions in some parsers,
    # or just general malformed URLs that regex catches but urlparse might dislike.

    # 1. Port out of range (urlparse usually handles this but let's check our logic)
    # The regex \b might not catch "http://foo:99999" as a valid url if strict,
    # but let's try to trigger the 'Exception' block in _extract_url_endpoints.

    # We can mock urlparse to raise an exception to ensure the except block is covered.
    with patch("redaudit.core.scope_expansion.urlparse") as mock_parse:
        mock_parse.side_effect = Exception("Boom")
        endpoints = _extract_url_endpoints("http://valid-looking.com")
        assert len(endpoints) == 0

    # 2. Test port extraction logic
    # "http://foo" -> port 80
    assert ("foo", 80, "http") in _extract_url_endpoints("http://foo")
    # "https://bar" -> port 443
    assert ("bar", 443, "https") in _extract_url_endpoints("https://bar")
    # The regex only matches http/https, so ftp won't be found.
    # Let's verify that behaviors is consistent.
    assert len(_extract_url_endpoints("ftp://baz")) == 0


def test_parse_network_list_edge_cases():
    assert _parse_network_list(None) == []
    assert _parse_network_list([]) == []
    assert _parse_network_list([None, ""]) == []

    # Invalid network
    networks = _parse_network_list(["192.168.1.0/24", "invalid-net"])
    assert len(networks) == 1
    assert str(networks[0]) == "192.168.1.0/24"


def test_parse_allowlist_edge_cases():
    nets, ips, hosts = _parse_allowlist(None)
    assert (nets, ips, hosts) == ([], set(), set())

    nets, ips, hosts = _parse_allowlist([None, "", "   "])
    assert (nets, ips, hosts) == ([], set(), set())

    # Mixed valid/invalid
    # "10.0.0.0/8" -> network
    # "192.168.1.1" -> parsed as network "192.168.1.1/32" first because strict=False
    # "example.com" -> host
    # "invalid-stuff" -> host

    input_list = ["10.0.0.0/8", "192.168.1.1", "example.com", "invalid-stuff"]
    nets, ips, hosts = _parse_allowlist(input_list)

    # 192.168.1.1 is parsed as a network due to strict=False check order
    assert len(nets) == 2
    assert any(str(n) == "192.168.1.1/32" for n in nets)

    assert len(ips) == 0

    # Use explicit set membership check to avoid CodeQL false positive
    expected_hosts = {"example.com", "invalid-stuff"}
    assert hosts == expected_hosts


def test_scope_policy_helpers():
    assert normalize_leak_follow_policy_pack("safe-extended") == "safe-extended"
    assert normalize_leak_follow_policy_pack("invalid") == "safe-default"
    assert normalize_leak_follow_profiles(["rfc1918-only,local-hosts", "bad"]) == [
        "rfc1918-only",
        "local-hosts",
    ]

    nets, ips, hosts, suffixes = _parse_policy_targets(["10.0.0.0/8", "router.local", "*.lan"])
    assert any(str(n) == "10.0.0.0/8" for n in nets)
    assert not ips
    assert "router.local" in hosts
    assert ".lan" in suffixes

    _, profile_nets, profile_ips, profile_hosts, profile_suffixes = _resolve_profile_targets(
        "safe-extended", ["ula-only"]
    )
    assert profile_ips == set()
    assert any(str(n) == "fc00::/7" for n in profile_nets)
    assert "localhost" in profile_hosts
    assert ".local" in profile_suffixes

    assert _host_matches_allow_rules("edge.lan", hosts=set(), suffixes={".lan"}) is True
    assert _host_matches_allow_rules("edge.local", hosts={"edge.local"}, suffixes=set()) is True
    assert (
        _ip_matches_allow_rules(ipaddress.ip_address("10.1.2.3"), networks=nets, ips=set()) is True
    )

    # Test rfc1918-only profile
    _, profile_nets, _, _, _ = _resolve_profile_targets("safe-default", ["rfc1918-only"])
    assert any(str(n) == "10.0.0.0/8" for n in profile_nets)
    assert any(str(n) == "172.16.0.0/12" for n in profile_nets)
    assert any(str(n) == "192.168.0.0/16" for n in profile_nets)


def test_evaluate_leak_follow_candidates_edge_cases():
    # 1. Candidate with empty string / None
    candidates = [
        {"candidate": None, "kind": "ip"},
        {"candidate": "", "kind": "ip"},
        {"candidate": "   ", "kind": "ip"},
    ]
    res = evaluate_leak_follow_candidates(candidates, mode="safe", target_networks=[], allowlist=[])
    assert res["detected"] == 0

    # 2. Candidate with invalid port
    candidates = [{"candidate": "10.0.0.1", "kind": "ip", "candidate_port": "invalid"}]
    res = evaluate_leak_follow_candidates(candidates, mode="off", target_networks=[], allowlist=[])
    # Should not have "candidate_port" key or it should be 0.
    # Logic: if candidate_port > 0: decision["candidate_port"] = candidate_port
    # 'invalid' -> int() ValueError -> 0.
    assert "candidate_port" not in res["decisions"][0]

    # 3. Candidate with http scheme
    candidates = [
        {"candidate": "10.0.0.1", "kind": "ip", "candidate_scheme": "HTTP", "candidate_port": 80}
    ]
    res = evaluate_leak_follow_candidates(candidates, mode="off", target_networks=[], allowlist=[])
    # Case insensitive match for scheme?
    # Logic: candidate_scheme = ... .lower()
    assert res["decisions"][0]["candidate_scheme"] == "http"


def test_evaluate_leak_follow_candidates_ip_logic_coverage():
    # Trigger "invalid_candidate" for kind="ip" but value not an IP
    candidates = [{"candidate": "not-an-ip", "kind": "ip"}]
    res = evaluate_leak_follow_candidates(candidates, mode="safe", target_networks=[], allowlist=[])
    assert res["decisions"][0]["reason"] == "invalid_candidate"

    # Trigger "public_candidate"
    candidates = [{"candidate": "8.8.8.8", "kind": "ip"}]
    res = evaluate_leak_follow_candidates(candidates, mode="safe", target_networks=[], allowlist=[])
    assert res["decisions"][0]["reason"] == "public_candidate"

    # Trigger "out_of_scope" (Internal IP but not in target networks or allowlist)
    candidates = [{"candidate": "192.168.1.1", "kind": "ip"}]
    res = evaluate_leak_follow_candidates(
        candidates, mode="safe", target_networks=["10.0.0.0/8"], allowlist=[]
    )
    assert res["decisions"][0]["reason"] == "out_of_scope"

    # Trigger "allowlisted" via Network match (since strict=False puts IP in allow_nets)
    candidates = [{"candidate": "192.168.1.1", "kind": "ip"}]
    # This will be parsed as 192.168.1.1/32 in allow_nets
    res = evaluate_leak_follow_candidates(
        candidates, mode="safe", target_networks=[], allowlist=["192.168.1.1"]
    )
    assert res["decisions"][0]["reason"] == "allowlisted"

    # Trigger "allowlisted" via CIDR match
    candidates = [{"candidate": "192.168.1.5", "kind": "ip"}]
    res = evaluate_leak_follow_candidates(
        candidates, mode="safe", target_networks=[], allowlist=["192.168.1.0/24"]
    )
    assert res["decisions"][0]["reason"] == "allowlisted"

    # Trigger "profile_allowlist" (IP matches profile networks)
    # Using rfc1918-only profile for testing
    candidates = [{"candidate": "192.168.99.99", "kind": "ip"}]
    res = evaluate_leak_follow_candidates(
        candidates,
        mode="safe",
        target_networks=[],
        allowlist=[],
        allowlist_profiles=["rfc1918-only"],
    )
    assert res["decisions"][0]["reason"] == "allowlisted"
    assert res["decisions"][0]["reason_detail"] == "profile_allowlist"


def test_evaluate_leak_follow_candidates_host_logic_coverage():
    # Trigger "denylisted" for host
    candidates = [{"candidate": "bad.host", "kind": "host"}]
    res = evaluate_leak_follow_candidates(
        candidates, mode="safe", target_networks=[], allowlist=[], denylist=["bad.host"]
    )
    assert res["decisions"][0]["reason"] == "denylisted"
    assert res["decisions"][0]["reason_detail"] == "explicit_denylist"

    # Trigger "allowlisted_host" via suffix
    candidates = [{"candidate": "good.local", "kind": "host"}]
    res = evaluate_leak_follow_candidates(
        candidates, mode="safe", target_networks=[], allowlist=["*.local"]
    )
    assert res["decisions"][0]["reason"] == "allowlisted_host"


def test_build_leak_follow_targets_edge_cases():
    # max_targets <= 0
    assert build_leak_follow_targets([], max_targets=0) == []

    # Empty candidate in decisions
    decisions = [
        {"candidate": "", "eligible": True},
        {"candidate": None, "eligible": True},
    ]
    assert build_leak_follow_targets(decisions) == []

    # Exception during port conversion (Formerly fatal, now should survive due to fix)
    decisions = [{"candidate": "10.0.0.1", "eligible": True, "candidate_port": "nan"}]
    targets = build_leak_follow_targets(decisions, max_targets=1)
    # Should default to port 0 logic (http:80, https:443) -> sorted -> yields http://10.0.0.1:80
    # Before fix, this crashed. Now it should pass.
    assert "http://10.0.0.1:80" in targets


def test_extract_leak_follow_candidates_inner_loops():
    # Cover the inner loops of extract_leak_follow_candidates
    # specifically the host/IP logic and exceptions

    # 1. "kind": "host" but value is valid internal IP -> converts to kind="ip"
    results = {
        "vulnerabilities": [
            {"host": "source", "vulnerabilities": [{"redirect_url": "http://192.168.1.1/foo"}]}
        ]
    }
    candidates = extract_leak_follow_candidates(results)
    assert candidates[0]["candidate"] == "192.168.1.1"
    assert candidates[0]["kind"] == "ip"

    # 2. "kind": "host" but value is Public IP -> skipped
    results = {
        "vulnerabilities": [
            {"host": "source", "vulnerabilities": [{"redirect_url": "http://8.8.8.8/foo"}]}
        ]
    }
    candidates = extract_leak_follow_candidates(results)
    assert len(candidates) == 0  # Should be skipped by _is_internal_ip check for IPs found in URLs

    # 3. Malformed findings structure
    results = {"vulnerabilities": [{"host": "source", "vulnerabilities": ["not-a-dict"]}]}
    assert extract_leak_follow_candidates(results) == []

    # 4. Finding not a dict
    results = {"vulnerabilities": ["not-a-dict"]}
    assert extract_leak_follow_candidates(results) == []
