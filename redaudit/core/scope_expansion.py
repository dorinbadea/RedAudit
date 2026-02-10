#!/usr/bin/env python3
"""
Scope expansion helpers for leak-follow runtime decisions.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse


_PRIVATE_IPV4_RE = re.compile(
    r"\b("
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    r"(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})|"
    r"(?:192\.168\.\d{1,3}\.\d{1,3})"
    r")\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

LEAK_FOLLOW_POLICY_PACKS = ("safe-default", "safe-strict", "safe-extended")
LEAK_FOLLOW_ALLOWLIST_PROFILES = ("rfc1918-only", "ula-only", "local-hosts")


def _iter_leak_texts(finding: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    fields = (
        "curl_headers",
        "wget_headers",
        "headers",
        "redirect_url",
    )
    for field in fields:
        value = finding.get(field)
        if isinstance(value, str) and value.strip():
            yield field, value
    nikto = finding.get("nikto_findings")
    if isinstance(nikto, list):
        for line in nikto:
            if isinstance(line, str) and line.strip():
                yield "nikto_findings", line


def _extract_url_endpoints(text: str) -> Set[Tuple[str, int, str]]:
    endpoints: Set[Tuple[str, int, str]] = set()
    for match in _URL_RE.findall(text):
        try:
            parsed = urlparse(match)
            host = (parsed.hostname or "").strip()
            scheme = str(parsed.scheme or "").strip().lower()
            port = int(parsed.port or 0)
            if not port:
                if scheme == "https":
                    port = 443
                elif scheme == "http":
                    port = 80
        except Exception:
            host = ""
            scheme = ""
            port = 0
        if host:
            endpoints.add((host, port, scheme))
    return endpoints


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _is_internal_ip(ip_obj: IPAddress) -> bool:
    if ip_obj.is_loopback:
        return False
    if ip_obj.version == 6:
        return bool(ip_obj.is_private or ip_obj.is_link_local)
    return bool(ip_obj.is_private)


def extract_leak_follow_candidates(results: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract leak-follow candidates from vulnerability HTTP evidence.

    Returns deduplicated candidates as dictionaries:
    {
      "candidate": "10.0.0.5",
      "kind": "ip" | "host",
      "source_host": "192.168.1.10",
      "source_field": "redirect_url",
    }
    """
    candidates: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    vulnerabilities = results.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return candidates

    for host_vuln in vulnerabilities:
        if not isinstance(host_vuln, dict):
            continue
        source_host = str(host_vuln.get("host") or "").strip()
        findings = host_vuln.get("vulnerabilities") or []
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for source_field, text in _iter_leak_texts(finding):
                # Extract private IPv4 hints from raw text.
                for ip_str in _PRIVATE_IPV4_RE.findall(text):
                    if ip_str == source_host:
                        continue
                    key = (ip_str, "ip", source_host, source_field)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(
                        {
                            "candidate": ip_str,
                            "kind": "ip",
                            "source_host": source_host,
                            "source_field": source_field,
                        }
                    )

                # Extract host/IP hints from explicit URLs.
                for host, port, scheme in _extract_url_endpoints(text):
                    if host == source_host:
                        continue
                    kind = "host"
                    try:
                        parsed_ip = ipaddress.ip_address(host)
                        if not _is_internal_ip(parsed_ip):
                            continue
                        kind = "ip"
                    except ValueError:
                        # Keep hostnames for allowlist-based safe mode.
                        pass
                    key = (host, kind, source_host, source_field)
                    if key in seen:
                        continue
                    seen.add(key)
                    item: Dict[str, str] = {
                        "candidate": host,
                        "kind": kind,
                        "source_host": source_host,
                        "source_field": source_field,
                    }
                    if port > 0:
                        item["candidate_port"] = str(port)
                    if scheme:
                        item["candidate_scheme"] = scheme
                    candidates.append(item)

    return candidates


def _parse_network_list(raw_targets: Optional[Iterable[Any]]) -> List[IPNetwork]:
    networks: List[IPNetwork] = []
    if raw_targets is None:
        return networks
    for item in raw_targets:
        if item is None:
            continue
        target = str(item).strip()
        if not target:
            continue
        try:
            networks.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            continue
    return networks


def _parse_allowlist(
    allowlist: Optional[Iterable[Any]],
) -> Tuple[List[IPNetwork], Set[IPAddress], Set[str]]:
    networks: List[IPNetwork] = []
    ips: Set[IPAddress] = set()
    hosts: Set[str] = set()
    if allowlist is None:
        return networks, ips, hosts
    for item in allowlist:
        if item is None:
            continue
        value = str(item).strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
            continue
        except ValueError:
            pass
        try:
            ips.add(ipaddress.ip_address(value))
            continue
        except ValueError:
            pass
        hosts.add(value.lower())
    return networks, ips, hosts


def normalize_leak_follow_policy_pack(value: Any) -> str:
    policy_pack = str(value or "").strip().lower()
    if policy_pack not in LEAK_FOLLOW_POLICY_PACKS:
        return "safe-default"
    return policy_pack


def normalize_leak_follow_profiles(raw_profiles: Optional[Iterable[Any]]) -> List[str]:
    if raw_profiles is None:
        return []
    if isinstance(raw_profiles, str):
        raw_profiles = [raw_profiles]

    normalized: List[str] = []
    seen: Set[str] = set()
    for item in raw_profiles:
        for token in str(item or "").split(","):
            profile = token.strip().lower()
            if not profile or profile not in LEAK_FOLLOW_ALLOWLIST_PROFILES or profile in seen:
                continue
            seen.add(profile)
            normalized.append(profile)
    return normalized


def _parse_policy_targets(
    values: Optional[Iterable[Any]],
) -> Tuple[List[IPNetwork], Set[IPAddress], Set[str], Set[str]]:
    materialized = list(values or [])
    networks, ips, hosts = _parse_allowlist(materialized)
    suffixes: Set[str] = set()
    for item in materialized:
        value = str(item or "").strip().lower()
        if not value:
            continue
        if value.startswith("*.") and len(value) > 2:
            suffixes.add(value[1:])
    return networks, ips, hosts, suffixes


def _resolve_profile_targets(
    policy_pack: str, raw_profiles: Optional[Iterable[Any]]
) -> Tuple[List[str], List[IPNetwork], Set[IPAddress], Set[str], Set[str]]:
    effective_profiles = normalize_leak_follow_profiles(raw_profiles)
    if policy_pack == "safe-extended" and "local-hosts" not in effective_profiles:
        effective_profiles.append("local-hosts")

    networks: List[IPNetwork] = []
    ips: Set[IPAddress] = set()
    hosts: Set[str] = set()
    suffixes: Set[str] = set()

    for profile in effective_profiles:
        if profile == "rfc1918-only":
            networks.extend(
                (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                )
            )
            continue
        if profile == "ula-only":
            networks.append(ipaddress.ip_network("fc00::/7"))
            continue
        if profile == "local-hosts":
            hosts.update(("localhost", "localhost.localdomain", "gateway.local", "router.local"))
            suffixes.update((".local", ".lan", ".home"))
            continue

    return effective_profiles, networks, ips, hosts, suffixes


def _ip_matches_allow_rules(
    ip_obj: IPAddress, *, networks: List[IPNetwork], ips: Set[IPAddress]
) -> bool:
    return ip_obj in ips or any(ip_obj in net for net in networks)


def _host_matches_allow_rules(host: str, *, hosts: Set[str], suffixes: Set[str]) -> bool:
    host_norm = host.lower()
    if host_norm in hosts:
        return True
    return any(host_norm.endswith(suffix) for suffix in suffixes)


def evaluate_leak_follow_candidates(
    candidates: List[Dict[str, str]],
    *,
    mode: str,
    target_networks: Optional[Iterable[Any]],
    allowlist: Optional[Iterable[Any]],
    policy_pack: str = "safe-default",
    allowlist_profiles: Optional[Iterable[Any]] = None,
    denylist: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluate candidates against safe scope controls.

    Returns a deterministic decision payload with counts and per-candidate reasons.
    """
    effective_mode = mode if mode in ("off", "safe") else "off"
    effective_policy_pack = normalize_leak_follow_policy_pack(policy_pack)
    target_nets = _parse_network_list(target_networks)
    allow_nets, allow_ips, allow_hosts, allow_host_suffixes = _parse_policy_targets(allowlist)
    deny_nets, deny_ips, deny_hosts, deny_host_suffixes = _parse_policy_targets(denylist)
    profile_names, profile_nets, profile_ips, profile_hosts, profile_host_suffixes = (
        _resolve_profile_targets(effective_policy_pack, allowlist_profiles)
    )

    decisions: List[Dict[str, Any]] = []
    accepted: Set[str] = set()

    for entry in candidates:
        candidate = str(entry.get("candidate") or "").strip()
        kind = str(entry.get("kind") or "")
        source_host = str(entry.get("source_host") or "")
        source_field = str(entry.get("source_field") or "")
        if not candidate:
            continue

        candidate_port_raw = str(entry.get("candidate_port") or "").strip()
        try:
            candidate_port = int(candidate_port_raw) if candidate_port_raw else 0
        except ValueError:
            candidate_port = 0
        candidate_scheme = str(entry.get("candidate_scheme") or "").strip().lower()

        decision = {
            "candidate": candidate,
            "kind": kind or "unknown",
            "source_host": source_host,
            "source_field": source_field,
            "eligible": False,
            "reason": "mode_off" if effective_mode == "off" else "unknown",
        }
        if candidate_port > 0:
            decision["candidate_port"] = candidate_port
        if candidate_scheme in ("http", "https"):
            decision["candidate_scheme"] = candidate_scheme

        if effective_mode == "off":
            decisions.append(decision)
            continue

        if kind == "ip":
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                decision["reason"] = "invalid_candidate"
                decisions.append(decision)
                continue
            if not _is_internal_ip(ip_obj):
                decision["reason"] = "public_candidate"
                decisions.append(decision)
                continue
            if _ip_matches_allow_rules(ip_obj, networks=deny_nets, ips=deny_ips):
                decision["reason"] = "denylisted"
                decision["reason_detail"] = "explicit_denylist"
                decisions.append(decision)
                continue
            if _ip_matches_allow_rules(ip_obj, networks=allow_nets, ips=allow_ips):
                decision["eligible"] = True
                decision["reason"] = "allowlisted"
                decision["reason_detail"] = "explicit_allowlist"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            if _ip_matches_allow_rules(ip_obj, networks=profile_nets, ips=profile_ips):
                decision["eligible"] = True
                decision["reason"] = "allowlisted"
                decision["reason_detail"] = "profile_allowlist"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            if any(ip_obj in net for net in target_nets):
                decision["eligible"] = True
                decision["reason"] = "in_scope"
                decision["reason_detail"] = "target_network"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            decision["reason"] = "out_of_scope"
            decisions.append(decision)
            continue

        if kind == "host":
            if _host_matches_allow_rules(candidate, hosts=deny_hosts, suffixes=deny_host_suffixes):
                decision["reason"] = "denylisted"
                decision["reason_detail"] = "explicit_denylist"
                decisions.append(decision)
                continue
            if _host_matches_allow_rules(
                candidate, hosts=allow_hosts, suffixes=allow_host_suffixes
            ):
                decision["eligible"] = True
                decision["reason"] = "allowlisted_host"
                decision["reason_detail"] = "explicit_allowlist"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            if effective_policy_pack == "safe-strict":
                decision["reason"] = "strict_hostname_block"
                decisions.append(decision)
                continue
            if _host_matches_allow_rules(
                candidate, hosts=profile_hosts, suffixes=profile_host_suffixes
            ):
                decision["eligible"] = True
                decision["reason"] = "allowlisted_host"
                decision["reason_detail"] = "profile_allowlist"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            decision["reason"] = "hostname_not_allowlisted"
            decisions.append(decision)
            continue

        decision["reason"] = "unknown_kind"
        decisions.append(decision)

    eligible = sum(1 for d in decisions if d.get("eligible"))
    return {
        "mode": effective_mode,
        "policy_pack": effective_policy_pack,
        "allowlist_profiles": profile_names,
        "detected": len(decisions),
        "eligible": eligible,
        "followed": 0,  # Phase B block B3 will execute follow actions.
        "skipped": len(decisions) - eligible,
        "accepted_candidates": sorted(accepted),
        "decisions": decisions,
    }


def _format_host_for_url(candidate: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(candidate)
        if ip_obj.version == 6:
            return f"[{candidate}]"
    except ValueError:
        pass
    return candidate


def build_leak_follow_targets(
    decisions: List[Dict[str, Any]],
    *,
    existing_targets: Optional[Iterable[str]] = None,
    max_targets: int = 8,
) -> List[str]:
    """
    Build deterministic URL targets from eligible leak-follow decisions.
    """
    if max_targets <= 0:
        return []
    existing = {str(t).strip() for t in (existing_targets or []) if str(t).strip()}
    built: List[str] = []

    ordered = sorted(
        [d for d in decisions if isinstance(d, dict) and d.get("eligible")],
        key=lambda d: (
            str(d.get("candidate") or ""),
            str(d.get("source_host") or ""),
            str(d.get("source_field") or ""),
            (
                0
                if not str(d.get("candidate_port") or "").isdigit()
                else int(d.get("candidate_port") or 0)
            ),
        ),
    )

    for decision in ordered:
        candidate = str(decision.get("candidate") or "").strip()
        if not candidate:
            continue
        host_for_url = _format_host_for_url(candidate)
        scheme = str(decision.get("candidate_scheme") or "").strip().lower()
        try:
            port = int(decision.get("candidate_port") or 0)
        except Exception:
            port = 0

        endpoint_pairs: List[Tuple[str, int]]
        if port > 0 and scheme in ("http", "https"):
            endpoint_pairs = [(scheme, port)]
        elif port > 0:
            endpoint_pairs = [("https" if port == 443 else "http", port)]
        elif scheme in ("http", "https"):
            endpoint_pairs = [(scheme, 443 if scheme == "https" else 80)]
        else:
            endpoint_pairs = [("http", 80), ("https", 443)]

        for target_scheme, target_port in endpoint_pairs:
            target = f"{target_scheme}://{host_for_url}:{target_port}"
            if target in existing or target in built:
                continue
            built.append(target)
            if len(built) >= max_targets:
                return built

    return built
