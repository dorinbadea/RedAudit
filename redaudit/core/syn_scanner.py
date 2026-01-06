#!/usr/bin/env python3
"""
RedAudit - SYN Scanner Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v4.3: Optional SYN-based port scanning using scapy.
Provides faster scanning for large networks when running as root.
"""

import asyncio
import os
import time
from typing import Dict, List, Optional, Tuple

# Scapy is optional - only required when using SYN mode
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf

    # Disable scapy verbosity
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    pass


def is_syn_scan_available() -> Tuple[bool, str]:
    """
    Check if SYN scan mode is available.

    Requires:
    1. Root privileges (euid == 0)
    2. Scapy library installed

    Returns:
        Tuple of (available: bool, reason: str)
    """
    if os.geteuid() != 0:
        return False, "requires_root"

    if not SCAPY_AVAILABLE:
        return False, "scapy_not_installed"

    return True, "available"


def syn_probe_single(ip: str, port: int, timeout: float = 0.5) -> bool:
    """
    Send SYN packet and check for SYN-ACK response.

    Args:
        ip: Target IP address
        port: Target port
        timeout: Response timeout in seconds

    Returns:
        True if port is open (received SYN-ACK)
    """
    if not SCAPY_AVAILABLE:
        return False

    try:
        # Build SYN packet
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")

        # Send and wait for response
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return False

        # Check for SYN-ACK (flags = 0x12 = SYN + ACK)
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer and tcp_layer.flags == 0x12:
            # Send RST to close half-open connection (stealth)
            rst = IP(dst=ip) / TCP(dport=port, sport=tcp_layer.dport, flags="R")
            sr1(rst, timeout=0.1, verbose=0)
            return True

        return False

    except Exception:
        return False


async def syn_sweep_batch(
    targets: List[str],
    ports: List[int],
    batch_size: int = 100,
    timeout: float = 0.3,
    logger=None,
) -> Dict[str, List[int]]:
    """
    SYN scan multiple hosts/ports using scapy.

    Uses asyncio.to_thread to avoid blocking the event loop.

    Args:
        targets: List of IP addresses
        ports: List of ports to scan
        batch_size: Max concurrent probes
        timeout: Response timeout per probe
        logger: Optional logger

    Returns:
        Dict mapping IP -> list of open ports
    """
    if not SCAPY_AVAILABLE:
        if logger:
            logger.warning("SYN scan unavailable: scapy not installed")
        return {}

    start_time = time.time()
    results: Dict[str, List[int]] = {ip: [] for ip in targets}
    total_probes = len(targets) * len(ports)

    if logger:
        logger.info(
            "SYN sweep: %d targets x %d ports = %d probes",
            len(targets),
            len(ports),
            total_probes,
        )

    # Create probe tasks
    async def probe(ip: str, port: int) -> Optional[Tuple[str, int]]:
        is_open = await asyncio.to_thread(syn_probe_single, ip, port, timeout)
        return (ip, port) if is_open else None

    # Process in batches
    semaphore = asyncio.Semaphore(batch_size)

    async def limited_probe(ip: str, port: int):
        async with semaphore:
            return await probe(ip, port)

    tasks = [limited_probe(ip, port) for ip in targets for port in ports]

    # Gather results
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    for resp in responses:
        if isinstance(resp, tuple):
            ip, port = resp
            results[ip].append(port)

    # Filter empty results
    results = {ip: ports for ip, ports in results.items() if ports}

    elapsed = time.time() - start_time
    if logger:
        total_open = sum(len(p) for p in results.values())
        logger.info(
            "SYN sweep complete: %d open ports on %d hosts in %.1fs",
            total_open,
            len(results),
            elapsed,
        )

    return results


def syn_sweep_sync(
    targets: List[str],
    ports: List[int],
    batch_size: int = 100,
    timeout: float = 0.3,
    logger=None,
) -> Dict[str, List[int]]:
    """
    Synchronous wrapper for syn_sweep_batch.
    """
    return asyncio.run(syn_sweep_batch(targets, ports, batch_size, timeout, logger))
