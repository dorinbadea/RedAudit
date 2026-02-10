#!/usr/bin/env python3
"""IoT scope-expansion probe orchestration with strict runtime guardrails."""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from redaudit.core.udp_probe import run_udp_probe


IOT_PROBE_PACKS: Dict[str, Tuple[int, ...]] = {
    "ssdp": (1900,),
    "coap": (5683,),
    "wiz": (38899,),
    "yeelight": (1982, 55443),
    "tuya": (6666, 6667),
}


def normalize_iot_probe_packs(raw_packs: Optional[Iterable[Any]]) -> List[str]:
    if raw_packs is None:
        return []
    if isinstance(raw_packs, str):
        raw_packs = [raw_packs]

    normalized: List[str] = []
    seen = set()
    for item in raw_packs:
        for token in str(item or "").split(","):
            pack = token.strip().lower()
            if not pack or pack not in IOT_PROBE_PACKS or pack in seen:
                continue
            seen.add(pack)
            normalized.append(pack)
    return normalized


def _host_get(host: Any, key: str, default: Any = None) -> Any:
    if isinstance(host, dict):
        return host.get(key, default)
    return getattr(host, key, default)


def _extract_open_udp_ports(host: Any) -> List[int]:
    ports: List[int] = []
    for entry in _host_get(host, "ports", []) or []:
        if not isinstance(entry, dict):
            continue
        try:
            port = int(entry.get("port"))
        except Exception:
            continue
        protocol = str(entry.get("protocol") or "").lower()
        state = str(entry.get("state") or "open").lower()
        if protocol == "udp" and state in ("open", "open|filtered"):
            ports.append(port)

    for svc in _host_get(host, "services", []) or []:
        try:
            port = int(_host_get(svc, "port", 0))
        except Exception:
            continue
        protocol = str(_host_get(svc, "protocol", "")).lower()
        state = str(_host_get(svc, "state", "open")).lower()
        if protocol == "udp" and state in ("open", "open|filtered"):
            ports.append(port)

    return sorted(set(p for p in ports if 1 <= p <= 65535))


def _host_has_strong_iot_signal(host: Any, selected_ports: Sequence[int]) -> bool:
    tags = {str(t).strip().lower() for t in (_host_get(host, "tags", []) or [])}
    if "iot" in tags:
        return True

    asset_type = str(_host_get(host, "asset_type", "")).strip().lower()
    if asset_type == "iot":
        return True

    hints = {str(h).strip().lower() for h in (_host_get(host, "device_type_hints", []) or [])}
    if any(h in hints for h in ("iot", "iot_lighting", "smart_tv", "camera", "embedded")):
        return True

    agentless = _host_get(host, "agentless_fingerprint", {}) or {}
    if isinstance(agentless, dict):
        if str(agentless.get("device_type") or "").strip().lower() in {
            "iot",
            "smart_device",
            "smart_tv",
            "camera",
        }:
            return True
        if str(agentless.get("device_vendor") or "").strip():
            return True

    open_udp = set(_extract_open_udp_ports(host))
    if open_udp.intersection(set(selected_ports)):
        return True

    return False


def select_iot_probe_candidates(
    hosts: Iterable[Any], *, mode: str, selected_packs: Sequence[str], identity_threshold: int = 4
) -> List[Dict[str, Any]]:
    effective_mode = mode if mode in ("off", "safe") else "off"
    if effective_mode != "safe":
        return []

    selected_ports: List[int] = []
    for pack in selected_packs:
        selected_ports.extend(IOT_PROBE_PACKS.get(pack, ()))
    selected_ports = sorted(set(selected_ports))

    candidates: List[Dict[str, Any]] = []
    for host in hosts or []:
        ip = str(_host_get(host, "ip", "") or "").strip()
        if not ip:
            continue

        smart_scan = _host_get(host, "smart_scan", {}) or {}
        try:
            identity_score = int((smart_scan or {}).get("identity_score", 0))
        except Exception:
            identity_score = 0
        ambiguous = identity_score < identity_threshold
        strong_signal = _host_has_strong_iot_signal(host, selected_ports)
        if ambiguous and strong_signal:
            candidates.append(
                {
                    "ip": ip,
                    "identity_score": identity_score,
                    "ambiguous": True,
                    "strong_signal": True,
                    "open_udp_ports": _extract_open_udp_ports(host),
                }
            )

    return candidates


def _build_evidence_record(
    *,
    host: str,
    source: str,
    signal: str,
    decision: str,
    reason: str,
    classification: str,
) -> Dict[str, Any]:
    raw_ref = hashlib.sha256(
        f"{host}|{source}|{signal}|{decision}|{reason}".encode("utf-8")
    ).hexdigest()
    return {
        "feature": "iot_probe",
        "classification": classification,
        "source": source,
        "signal": signal,
        "decision": decision,
        "reason": reason,
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "raw_ref": raw_ref,
    }


def run_iot_scope_probes(
    hosts: Iterable[Any],
    *,
    mode: str,
    packs: Optional[Iterable[Any]],
    budget_seconds: int,
    timeout_seconds: int,
    identity_threshold: int = 4,
    probe_runner: Callable[..., List[Dict[str, Any]]] = run_udp_probe,
    time_provider: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    effective_mode = mode if mode in ("off", "safe") else "off"
    selected_packs = normalize_iot_probe_packs(packs)
    if not selected_packs:
        selected_packs = list(IOT_PROBE_PACKS.keys())

    try:
        budget = int(budget_seconds)
    except Exception:
        budget = 20
    if budget < 1:
        budget = 20
    if budget > 300:
        budget = 300

    try:
        timeout = int(timeout_seconds)
    except Exception:
        timeout = 3
    if timeout < 1:
        timeout = 3
    if timeout > 60:
        timeout = 60

    candidates = select_iot_probe_candidates(
        hosts,
        mode=effective_mode,
        selected_packs=selected_packs,
        identity_threshold=identity_threshold,
    )

    all_ports: List[int] = []
    for pack in selected_packs:
        all_ports.extend(IOT_PROBE_PACKS.get(pack, ()))
    all_ports = sorted(set(all_ports))

    runtime: Dict[str, Any] = {
        "mode": effective_mode,
        "packs": list(selected_packs),
        "budget_seconds": budget,
        "timeout_seconds": timeout,
        "candidates": len(candidates),
        "executed_hosts": 0,
        "probes_total": len(candidates) * len(all_ports),
        "probes_executed": 0,
        "probes_responded": 0,
        "budget_exceeded_hosts": 0,
        "reasons": {},
        "hosts": [],
        "evidence": [],
    }

    if effective_mode != "safe" or not candidates or not all_ports:
        return runtime

    reason_counter: Counter[str] = Counter()
    evidence_records: List[Dict[str, Any]] = []

    for candidate in candidates:
        ip = candidate["ip"]
        started = time_provider()
        host_budget_exceeded = False
        host_result = {
            "host": ip,
            "identity_score": candidate.get("identity_score", 0),
            "attempted_ports": 0,
            "responded_ports": 0,
            "budget_exceeded": False,
            "signals": [],
        }

        for port in all_ports:
            elapsed = max(0.0, time_provider() - started)
            if elapsed + timeout > budget:
                host_budget_exceeded = True
                reason_counter["budget_exceeded"] += 1
                host_result["signals"].append(
                    {
                        "pack": next(
                            (p for p in selected_packs if port in IOT_PROBE_PACKS[p]), "unknown"
                        ),
                        "port": port,
                        "state": "skipped",
                        "classification": "hint",
                        "reason": "budget_exceeded",
                    }
                )
                evidence_records.append(
                    _build_evidence_record(
                        host=ip,
                        source=f"udp:{port}",
                        signal="skipped",
                        decision="budget_exceeded",
                        reason="budget_exceeded",
                        classification="hint",
                    )
                )
                break

            host_result["attempted_ports"] += 1
            runtime["probes_executed"] += 1
            pack_name = next((p for p in selected_packs if port in IOT_PROBE_PACKS[p]), "unknown")

            try:
                raw = probe_runner(ip, [port], timeout=float(timeout), concurrency=1) or []
                probe = raw[0] if raw else {"port": port, "state": "no_response"}
            except Exception:
                probe = {"port": port, "state": "no_response"}

            state = str(probe.get("state") or "no_response").lower()
            if state == "responded":
                runtime["probes_responded"] += 1
                host_result["responded_ports"] += 1
                classification = "evidence"
                decision = "promote_candidate"
                reason = "corroborated"
            elif state == "closed":
                classification = "heuristic"
                decision = "retain_candidate"
                reason = "port_closed"
            else:
                classification = "hint"
                decision = "retain_candidate"
                reason = "no_response"

            reason_counter[reason] += 1
            host_result["signals"].append(
                {
                    "pack": pack_name,
                    "port": int(probe.get("port") or port),
                    "state": state,
                    "classification": classification,
                    "reason": reason,
                }
            )
            evidence_records.append(
                _build_evidence_record(
                    host=ip,
                    source=f"udp:{port}",
                    signal=state,
                    decision=decision,
                    reason=reason,
                    classification=classification,
                )
            )

        host_result["budget_exceeded"] = host_budget_exceeded
        if host_budget_exceeded:
            runtime["budget_exceeded_hosts"] += 1
        runtime["executed_hosts"] += 1
        runtime["hosts"].append(host_result)

    runtime["reasons"] = dict(sorted(reason_counter.items()))
    runtime["evidence"] = evidence_records
    return runtime
