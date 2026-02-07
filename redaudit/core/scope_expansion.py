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


def evaluate_leak_follow_candidates(
    candidates: List[Dict[str, str]],
    *,
    mode: str,
    target_networks: Optional[Iterable[Any]],
    allowlist: Optional[Iterable[Any]],
) -> Dict[str, Any]:
    """
    Evaluate candidates against safe scope controls.

    Returns a deterministic decision payload with counts and per-candidate reasons.
    """
    effective_mode = mode if mode in ("off", "safe") else "off"
    target_nets = _parse_network_list(target_networks)
    allow_nets, allow_ips, allow_hosts = _parse_allowlist(allowlist)

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
            if any(ip_obj in net for net in target_nets):
                decision["eligible"] = True
                decision["reason"] = "in_scope"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            if ip_obj in allow_ips or any(ip_obj in net for net in allow_nets):
                decision["eligible"] = True
                decision["reason"] = "allowlisted"
                accepted.add(candidate)
                decisions.append(decision)
                continue
            decision["reason"] = "out_of_scope"
            decisions.append(decision)
            continue

        if kind == "host":
            if candidate.lower() in allow_hosts:
                decision["eligible"] = True
                decision["reason"] = "allowlisted_host"
                accepted.add(candidate)
            else:
                decision["reason"] = "hostname_not_allowlisted"
            decisions.append(decision)
            continue

        decision["reason"] = "unknown_kind"
        decisions.append(decision)

    eligible = sum(1 for d in decisions if d.get("eligible"))
    return {
        "mode": effective_mode,
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
