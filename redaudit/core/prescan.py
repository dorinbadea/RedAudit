#!/usr/bin/env python3
"""
RedAudit - Pre-scan Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Fast port discovery using asyncio TCP connect.
"""

import asyncio
from typing import List, Optional, Callable


async def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """
    Check if a port is open using TCP connect.

    Args:
        ip: Target IP address
        port: Port number to check
        timeout: Connection timeout in seconds

    Returns:
        True if port is open, False otherwise
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False


async def prescan_host(
    ip: str,
    ports: List[int],
    timeout: float = 0.5,
    batch_size: int = 500,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> List[int]:
    """
    Pre-scan host for open ports using asyncio.

    Args:
        ip: Target IP address
        ports: List of ports to check
        timeout: Connection timeout per port
        batch_size: Number of concurrent port checks
        progress_callback: Optional callback(checked, total) for progress

    Returns:
        Sorted list of open ports
    """
    open_ports = []
    total = len(ports)

    for i in range(0, total, batch_size):
        batch = ports[i:i + batch_size]
        tasks = [check_port(ip, p, timeout) for p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, result in zip(batch, results):
            if result is True:
                open_ports.append(port)

        if progress_callback:
            progress_callback(min(i + batch_size, total), total)

    return sorted(open_ports)


def run_prescan(
    ip: str,
    ports: List[int],
    timeout: float = 0.5,
    batch_size: int = 500
) -> List[int]:
    """
    Synchronous wrapper for prescan.

    Args:
        ip: Target IP address
        ports: List of ports to check
        timeout: Connection timeout per port
        batch_size: Number of concurrent checks

    Returns:
        Sorted list of open ports
    """
    return asyncio.run(prescan_host(ip, ports, timeout, batch_size))


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse a port specification string into list of ports.

    Args:
        port_spec: Port spec like "1-1024", "22,80,443", or "1-100,443,8080-8090"

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start = max(1, int(start))
                end = min(65535, int(end))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue
    return sorted(set(ports))


# Common port lists for quick access
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
    # Extended common ports
    7, 9, 13, 17, 19, 26, 37, 49, 79, 81, 82, 83, 84, 85, 88, 89,
    106, 113, 119, 144, 179, 199, 254, 255, 280, 311, 389, 427, 444,
    465, 497, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 902, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 4443, 4567,
    5000, 5001, 5060, 5357, 5800, 5985, 5986, 6000, 6001, 6379, 6646,
    7000, 7001, 8000, 8001, 8008, 8081, 8083, 8443, 8880, 8888, 9000,
    9090, 9200, 9999, 10000, 27017, 32768, 49152
]

TOP_1024_PORTS = list(range(1, 1025))
