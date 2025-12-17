#!/usr/bin/env python3
"""
RedAudit - Async UDP Probe Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Best-effort UDP probing using asyncio.

Design goals:
- Be fast and bounded (short timeouts, concurrency limits).
- Confirm responsive UDP services (and sometimes detect closed ports).
- Never break scans if the environment doesn't support it (best-effort).
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, Iterable, List, Optional


def _build_dns_query() -> bytes:
    # Minimal DNS query for "." (root), type A, class IN.
    # ID 0x1234, flags 0x0100 (recursion desired), QDCOUNT=1.
    return (
        b"\x12\x34"
        + b"\x01\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00"
        + b"\x00\x01"
        + b"\x00\x01"
    )


UDP_PROBE_PAYLOADS: Dict[int, bytes] = {
    53: _build_dns_query(),  # DNS
    123: b"\x1b" + (b"\x00" * 47),  # NTP client request
}


def _normalize_ports(ports: Iterable[int]) -> List[int]:
    out: List[int] = []
    for p in ports:
        try:
            pi = int(p)
        except Exception:
            continue
        if 1 <= pi <= 65535:
            out.append(pi)
    return sorted(set(out))


def _hex_sample(data: bytes, max_bytes: int = 32) -> str:
    if not data:
        return ""
    return data[:max_bytes].hex()


async def udp_probe_port(
    ip: str,
    port: int,
    timeout: float = 0.8,
    payload: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Probe a single UDP port and return a best-effort classification.

    Returns a dict:
      - port: int
      - state: responded | closed | no_response
      - response_bytes: int
      - response_sample_hex: str
    """
    loop = asyncio.get_running_loop()
    payload = payload if payload is not None else UDP_PROBE_PAYLOADS.get(port, b"\x00")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        sock.connect((ip, port))

        try:
            await loop.sock_sendall(sock, payload)
        except (OSError, asyncio.CancelledError):
            return {
                "port": port,
                "state": "no_response",
                "response_bytes": 0,
                "response_sample_hex": "",
            }

        try:
            data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout)
            return {
                "port": port,
                "state": "responded",
                "response_bytes": len(data or b""),
                "response_sample_hex": _hex_sample(data or b""),
            }
        except ConnectionRefusedError:
            # Some stacks surface ICMP Port Unreachable as ECONNREFUSED on recv() for connected UDP.
            return {"port": port, "state": "closed", "response_bytes": 0, "response_sample_hex": ""}
        except asyncio.TimeoutError:
            return {
                "port": port,
                "state": "no_response",
                "response_bytes": 0,
                "response_sample_hex": "",
            }
        except OSError:
            return {
                "port": port,
                "state": "no_response",
                "response_bytes": 0,
                "response_sample_hex": "",
            }
    finally:
        try:
            sock.close()
        except Exception:
            pass


async def udp_probe_host(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.8,
    concurrency: int = 200,
) -> List[Dict[str, Any]]:
    """
    Probe multiple UDP ports concurrently for a single host.
    """
    ports_list = _normalize_ports(ports)
    if not ports_list:
        return []

    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def _guarded(port: int) -> Dict[str, Any]:
        async with sem:
            payload = UDP_PROBE_PAYLOADS.get(port)
            return await udp_probe_port(ip, port, timeout=timeout, payload=payload)

    tasks = [_guarded(p) for p in ports_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out: List[Dict[str, Any]] = []
    for port, res in zip(ports_list, results):
        if isinstance(res, BaseException):
            out.append(
                {
                    "port": port,
                    "state": "no_response",
                    "response_bytes": 0,
                    "response_sample_hex": "",
                }
            )
        else:
            out.append(res)

    return sorted(out, key=lambda x: int(x.get("port", 0)))


def run_udp_probe(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.8,
    concurrency: int = 200,
) -> List[Dict[str, Any]]:
    """
    Synchronous wrapper.

    If called from an environment where an asyncio loop is already running,
    it falls back to a best-effort sequential probe to avoid RuntimeError.
    """
    try:
        return asyncio.run(udp_probe_host(ip, ports, timeout=timeout, concurrency=concurrency))
    except RuntimeError:
        # Likely: "asyncio.run() cannot be called from a running event loop"
        # Run in a separate thread with a fresh event loop.
        import threading

        result: List[Dict[str, Any]] = []

        def _runner() -> None:
            nonlocal result
            try:
                result = asyncio.run(
                    udp_probe_host(ip, ports, timeout=timeout, concurrency=concurrency)
                )
            except Exception:
                result = []

        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        t.join()
        return result
