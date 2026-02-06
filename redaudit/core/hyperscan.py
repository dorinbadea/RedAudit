#!/usr/bin/env python3
"""
RedAudit - HyperScan Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.2.3: Fast parallel discovery using asyncio batch scanning.
Discovers IoT devices, hidden hosts, and potential backdoors.
"""

import asyncio
import ipaddress
import socket
import struct
import time
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run
from redaudit.core.udp_probe import UDP_PROBE_PAYLOADS
from redaudit.utils.i18n import get_text, detect_preferred_language


_REDAUDIT_REDACT_ENV_KEYS = {"NVD_API_KEY", "GITHUB_TOKEN"}


HyperScanProgressCallback = Callable[[int, int, str], None]


def _make_runner(*, logger=None, dry_run: Optional[bool] = None, timeout: Optional[float] = None):
    return CommandRunner(
        logger=logger,
        dry_run=is_dry_run(dry_run),
        default_timeout=timeout,
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys=_REDAUDIT_REDACT_ENV_KEYS,
    )


def _get_fd_soft_limit() -> Optional[int]:
    try:
        import resource

        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit in (resource.RLIM_INFINITY, None):
            return None
        soft_int = int(soft_limit)
        return soft_int if soft_int > 0 else None
    except Exception:
        return None


def _compute_safe_max_batch(default_max: int, min_batch: int) -> int:
    soft_limit = _get_fd_soft_limit()
    if not soft_limit:
        return default_max
    safe_limit = max(min_batch, int(soft_limit * 0.8))
    return min(default_max, safe_limit)


# ============================================================================
# Configuration
# ============================================================================

# TCP batch scanning defaults
DEFAULT_TCP_BATCH_SIZE = 3000  # Concurrent connections per batch
DEFAULT_TCP_TIMEOUT = 0.5  # Seconds per connection attempt
DEFAULT_TCP_SEMAPHORE = 5000  # Max concurrent operations

# UDP Discovery ports - comprehensive list for all protocols
# Not limited to IoT - includes all common UDP services
UDP_DISCOVERY_PORTS = {
    # Network infrastructure
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmp-trap",
    500: "ipsec-ike",
    514: "syslog",
    520: "rip",
    1194: "openvpn",
    1701: "l2tp",
    1812: "radius",
    1813: "radius-acct",
    4500: "ipsec-nat-t",
    5060: "sip",
    5061: "sip-tls",
    # Discovery protocols
    1900: "ssdp",  # UPNP/SSDP
    5353: "mdns",  # mDNS/Bonjour
    5355: "llmnr",  # Link-Local Multicast
    # IoT and smart devices
    38899: "wiz",  # WiZ smart bulbs
    1982: "yeelight",  # Yeelight bulbs
    56700: "lifx",  # LIFX bulbs
    10001: "ubiquiti",  # Ubiquiti discovery
    8008: "chromecast",  # Chromecast
    8009: "chromecast-ctrl",  # Chromecast control
    # Gaming and media
    3478: "stun",  # STUN/TURN
    3479: "stun-alt",
    27015: "steam",  # Steam
    # Database and services
    1434: "mssql-browser",  # SQL Server Browser
    11211: "memcached",  # Memcached
    6379: "redis",  # Redis (also UDP)
    # VPN and tunnels
    1723: "pptp",
    4789: "vxlan",
    # Potential backdoors / unusual
    31337: "elite",  # Classic backdoor port
    4444: "metasploit",  # Metasploit default
    5555: "freeciv",  # Also Android debug
}

# Priority UDP ports for quick scan
UDP_PRIORITY_PORTS = [53, 67, 123, 137, 161, 500, 514, 1900, 5353, 38899, 1982, 6666, 6667, 5683]

# ARP scanning defaults
DEFAULT_ARP_RETRIES = 3
DEFAULT_ARP_TIMEOUT = 2.0


# ============================================================================
# Smart Throttle (AIMD)
# ============================================================================


class SmartThrottle:
    """Adaptive congestion control using AIMD algorithm."""

    def __init__(self, initial_batch: int = 500, min_batch: int = 100, max_batch: int = 20000):
        self.current_batch = initial_batch
        self.min_batch = min_batch
        self.max_batch = max_batch
        self.threshold_timeout = 0.05  # 5% failure rate triggers throttle

    def update(self, sent_count: int, timeout_count: int) -> str:
        """
        Update batch size based on execution results.
        Returns: 'THROTTLE_DOWN', 'ACCELERATE', or 'STABLE'
        """
        if sent_count == 0:
            return "STABLE"

        failure_rate = timeout_count / sent_count

        if failure_rate > self.threshold_timeout:
            # Multiplicative Decrease (congestion detected)
            self.current_batch = max(self.min_batch, int(self.current_batch * 0.5))
            return "THROTTLE_DOWN"
        elif failure_rate < 0.01:
            # Additive Increase (good conditions)
            old_batch = self.current_batch
            self.current_batch = min(self.max_batch, self.current_batch + 500)
            return "ACCELERATE" if self.current_batch > old_batch else "STABLE"

        return "STABLE"


# ============================================================================
# TCP Parallel Sweep
# ============================================================================


async def _tcp_connect(
    ip: str,
    port: int,
    timeout: float,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> Optional[Any]:
    """
    Attempt single TCP connection (semaphore optional).

    Returns (ip, port) if open, "CLOSED" if refused, None otherwise.
    """
    if semaphore:
        async with semaphore:
            return await _do_connect(ip, port, timeout)
    else:
        return await _do_connect(ip, port, timeout)


async def _do_connect(ip: str, port: int, timeout: float) -> Optional[Any]:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass
        return (ip, port)
    except ConnectionRefusedError:
        # v4.6.27: Explicitly return "CLOSED" so it's not counted as a timeout
        return "CLOSED"
    except (asyncio.TimeoutError, OSError):
        return None


async def hyperscan_tcp_sweep(
    targets: List[str],
    ports: List[int],
    batch_size: int = DEFAULT_TCP_BATCH_SIZE,
    timeout: float = DEFAULT_TCP_TIMEOUT,
    logger=None,
    progress_callback=None,
    mode: str = "auto",
) -> Dict[str, List[int]]:
    """
    Parallel TCP port sweep using asyncio batch scanning.

    Scans thousands of ports simultaneously for ultra-fast discovery.

    v4.3: Added mode parameter for SYN scan support.

    Args:
        targets: List of IP addresses to scan
        ports: List of ports to check
        batch_size: Max concurrent connections per batch
        timeout: Connection timeout in seconds
        logger: Optional logger
        progress_callback: Optional callback(completed, total, desc) for progress
        mode: Scan mode - 'auto', 'connect', or 'syn' (v4.3)

    Returns:
        Dict mapping IP -> list of open ports
    """
    if not targets or not ports:
        return {}

    # v4.3: Mode selection
    use_syn = False
    if mode in ("syn", "auto"):
        try:
            from redaudit.core.syn_scanner import is_syn_scan_available, syn_sweep_batch

            available, reason = is_syn_scan_available()
            if mode == "syn":
                if not available:
                    if logger:
                        logger.warning(
                            "SYN scan requested but unavailable (%s), falling back to connect",
                            reason,
                        )
                else:
                    use_syn = True
            elif mode == "auto" and available:
                use_syn = True
                if logger:
                    logger.info("HyperScan: Using SYN mode (root + scapy available)")
        except ImportError:
            if mode == "syn" and logger:
                logger.warning("SYN scan unavailable: syn_scanner module missing")

    # Use SYN scan if selected
    if use_syn:
        try:
            return await syn_sweep_batch(targets, ports, batch_size, timeout, logger)
        except Exception as e:
            if logger:
                logger.warning("SYN scan failed (%s), falling back to connect", e)

    # Default: TCP connect scan
    start_time = time.time()

    import itertools

    # Note: total_probes is still calculated for progress bar, but the list is not materialized
    total_probes = len(targets) * len(ports)

    # Lazy iterator
    probe_iterator = itertools.product(targets, ports)

    results: Dict[str, List[int]] = {ip: [] for ip in targets}

    if logger:
        logger.info(
            "HyperScan TCP (connect): %d targets x %d ports = %d probes",
            len(targets),
            len(ports),
            total_probes,
        )

    # Smart-Throttle initialization
    # Start with conservative batch size (500) regardless of default arg,
    # unless batch_size arg is unusually small (<500).
    safe_max_batch = _compute_safe_max_batch(20000, min_batch=100)
    safe_min_batch = min(100, safe_max_batch)
    initial_batch = min(500, batch_size, safe_max_batch)
    if initial_batch < safe_min_batch:
        initial_batch = safe_min_batch
    throttler = SmartThrottle(
        initial_batch=initial_batch,
        min_batch=safe_min_batch,
        max_batch=safe_max_batch,
    )
    if logger and safe_max_batch < 20000:
        logger.debug("HyperScan TCP: max_batch capped to %d due to FD limit", safe_max_batch)

    completed = 0

    while completed < total_probes:
        if completed >= total_probes:
            break

        current_batch_size = throttler.current_batch

        # Consume next batch from iterator
        batch_probes = list(itertools.islice(probe_iterator, current_batch_size))

        if not batch_probes:
            break

        # Create tasks for this batch (no individual semaphore, batch size controls concurrency)
        tasks = [_tcp_connect(ip, port, timeout, semaphore=None) for ip, port in batch_probes]

        # Run batch
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        timeouts = 0
        for res in batch_results:
            if res is None:
                timeouts += 1
            elif res == "CLOSED":
                # Host is responsive but port closed - do not count as timeout
                pass
            elif isinstance(res, tuple):
                ip, port = res
                results[ip].append(port)

        # Update AIMD controller
        event = throttler.update(len(batch_probes), timeouts)

        completed += len(batch_probes)

        if progress_callback:
            # Add dynamic feedback to UI
            speed = f"{throttler.current_batch}/s"
            icon = ""
            if event == "THROTTLE_DOWN":
                icon = "▼"
            elif event == "ACCELERATE":
                icon = "▲"

            desc = f"TCP sweep {icon} ({speed})"
            progress_callback(completed, total_probes, desc)

    duration = time.time() - start_time
    open_count = sum(len(ports) for ports in results.values())

    if logger:
        logger.info("HyperScan TCP: Found %d open ports in %.2fs", open_count, duration)

    return results


def hyperscan_tcp_sweep_sync(
    targets: List[str],
    ports: List[int],
    batch_size: int = DEFAULT_TCP_BATCH_SIZE,
    timeout: float = DEFAULT_TCP_TIMEOUT,
    logger=None,
    progress_callback: Optional[HyperScanProgressCallback] = None,
    mode: str = "auto",
) -> Dict[str, List[int]]:
    """
    Synchronous wrapper for hyperscan_tcp_sweep.

    v4.3: Added mode parameter for SYN scan support.
    """
    return asyncio.run(
        hyperscan_tcp_sweep(
            targets,
            ports,
            batch_size,
            timeout,
            logger,
            progress_callback=progress_callback,
            mode=mode,
        )
    )


def hyperscan_full_port_sweep(
    target_ip: str,
    batch_size: int = 64,  # Very conservative to work with default ulimit (1024 FDs)
    timeout: float = 1.5,
    logger=None,
    progress_callback: Optional[HyperScanProgressCallback] = None,
) -> List[int]:
    """
    v4.8: Scan ALL 65,535 TCP ports on a single host.

    Priority order:
    1. RustScan (fastest, ~3 seconds) - requires rustscan installed
    2. asyncio TCP connect (fallback, no external deps)

    Args:
        target_ip: Single IP address to scan
        batch_size: Concurrent connections for fallback mode
        timeout: Per-connection timeout in seconds
        logger: Optional logger
        progress_callback: Optional callback(completed, total, desc) for progress

    Returns:
        Sorted list of open port numbers
    """
    if not target_ip:
        return []

    start_time = time.time()

    # v4.8.0: Try RustScan first (fastest, integrates with nmap)
    try:
        from redaudit.core.rustscan import is_rustscan_available, run_rustscan_discovery_only

        if is_rustscan_available():
            if logger:
                logger.info(
                    "HyperScan FULL (RustScan): Fast port discovery on %s",
                    target_ip,
                )
            open_ports, error = run_rustscan_discovery_only(
                target_ip,
                port_range="1-65535",  # v4.8.2: Force full range (masscan parity)
                ulimit=5000,
                timeout=120.0,
                logger=logger,
            )
            if not error and open_ports:
                duration = time.time() - start_time
                if logger:
                    logger.info(
                        "HyperScan FULL (RustScan): Found %d ports on %s in %.1fs",
                        len(open_ports),
                        target_ip,
                        duration,
                    )
                return open_ports
            elif error:
                if logger:
                    logger.debug(
                        "RustScan failed on %s: %s, falling back to asyncio",
                        target_ip,
                        error,
                    )
            else:
                if logger:
                    logger.debug(
                        "RustScan found 0 ports on %s, falling back to asyncio",
                        target_ip,
                    )
    except ImportError:
        if logger:
            logger.debug("rustscan module not available, using fallback")
    except Exception as e:
        if logger:
            logger.warning("RustScan failed for %s: %s, falling back to asyncio", target_ip, e)

    # Fallback: Original asyncio TCP connect sweep
    # Generate all 65535 ports
    all_ports = list(range(1, 65536))

    if logger:
        logger.info(
            "HyperScan FULL: Scanning %d ports on %s (batch=%d, timeout=%.1fs)",
            len(all_ports),
            target_ip,
            batch_size,
            timeout,
        )

    open_ports = []

    # v4.1 fix: Use new event loop with proper cleanup to avoid FD exhaustion
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            hyperscan_tcp_sweep(
                targets=[target_ip],
                ports=all_ports,
                batch_size=batch_size,
                timeout=timeout,
                logger=logger,
                progress_callback=progress_callback,
            )
        )
        open_ports = sorted(results.get(target_ip, []))
    except Exception as e:
        if logger:
            logger.warning("HyperScan FULL failed for %s: %s", target_ip, e)
        open_ports = []
    finally:
        # Ensure loop is properly closed to release file descriptors
        if loop is not None:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
            asyncio.set_event_loop(None)

    duration = time.time() - start_time

    if logger:
        logger.info(
            "HyperScan FULL: Found %d open ports on %s in %.1fs",
            len(open_ports),
            target_ip,
            duration,
        )

    return open_ports


# ============================================================================
# UDP Parallel Sweep (Full Protocol Coverage)
# ============================================================================


async def _udp_probe(
    semaphore: asyncio.Semaphore,
    ip: str,
    port: int,
    timeout: float,
    payload: bytes = b"\x00",
) -> Optional[Tuple[str, int, bytes]]:
    """
    Attempt single UDP probe with semaphore limit.

    Returns (ip, port, response) if response received, None otherwise.
    """
    async with semaphore:
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.settimeout(timeout)

            await loop.sock_sendto(sock, payload, (ip, port))  # type: ignore[attr-defined]

            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
                return (ip, port, data)
            except asyncio.TimeoutError:
                return None
            finally:
                sock.close()
        except Exception:
            return None


async def hyperscan_udp_sweep(
    targets: List[str],
    ports: List[int] = None,
    batch_size: int = 1000,
    timeout: float = 0.5,
    logger=None,
) -> Dict[str, List[Dict]]:
    """
    Parallel UDP port sweep using asyncio.

    Probes all specified UDP ports across all targets for complete coverage.

    Args:
        targets: List of IP addresses to scan
        ports: List of UDP ports (default: UDP_DISCOVERY_PORTS keys)
        batch_size: Max concurrent probes
        timeout: Response timeout per probe
        logger: Optional logger

    Returns:
        Dict mapping IP -> list of responsive port info
    """
    if ports is None:
        ports = list(UDP_DISCOVERY_PORTS.keys())

    if not targets or not ports:
        return {}

    start_time = time.time()
    semaphore = asyncio.Semaphore(batch_size)
    results: Dict[str, List[Dict]] = {ip: [] for ip in targets}

    # Create all probe tasks
    tasks = []
    for ip in targets:
        for port in ports:
            # Use protocol-specific payload if available
            payload = UDP_PROBE_PAYLOADS.get(port, b"\x00")

            tasks.append(_udp_probe(semaphore, ip, port, timeout, payload))

    if logger:
        logger.info(
            "HyperScan UDP: %d targets x %d ports = %d probes", len(targets), len(ports), len(tasks)
        )

    # Execute all tasks concurrently
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results
    for result in completed:
        if isinstance(result, tuple) and len(result) == 3:
            ip, port, data = result
            protocol = UDP_DISCOVERY_PORTS.get(port, "unknown")
            results[ip].append(
                {
                    "port": port,
                    "protocol": protocol,
                    "response_size": len(data),
                    "response_preview": data[:50].hex() if data else "",
                }
            )

    duration = time.time() - start_time
    responsive_count = sum(len(ports_list) for ports_list in results.values())

    if logger:
        logger.info("HyperScan UDP: Found %d responsive ports in %.2fs", responsive_count, duration)

    return results


def hyperscan_udp_sweep_sync(
    targets: List[str],
    ports: List[int] = None,
    batch_size: int = 1000,
    timeout: float = 0.5,
    logger=None,
) -> Dict[str, List[Dict]]:
    """
    Synchronous wrapper for hyperscan_udp_sweep.
    """
    return asyncio.run(hyperscan_udp_sweep(targets, ports, batch_size, timeout, logger))


# ============================================================================
# UDP Broadcast Probes (Discovery Protocols)
# ============================================================================


def _build_ssdp_msearch() -> bytes:
    """Build SSDP M-SEARCH discovery packet."""
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 3\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )


def _build_mdns_query() -> bytes:
    """Build mDNS PTR query for _services._dns-sd._udp.local."""
    # Simple mDNS query header + question
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)  # ID, flags, QDCOUNT=1
    # Query for _services._dns-sd._udp.local PTR
    question = (
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c"  # PTR type
        b"\x00\x01"  # IN class
    )
    return header + question


def _build_wiz_discovery() -> bytes:
    """Build WiZ smart bulb discovery packet (UDP 38899)."""
    import json

    # WiZ bulbs respond to registration and getPilot queries
    # Using registration method for broader compatibility
    payload = {
        "method": "registration",
        "params": {"phoneMac": "AABBCCDDEEFF", "register": False, "phoneIp": "1.2.3.4"},
    }
    return json.dumps(payload).encode()


def hyperscan_udp_broadcast(
    network: str,
    timeout: float = 3.0,
    logger=None,
) -> List[Dict]:
    """
    Send UDP broadcast probes to discover IoT devices.

    Probes common IoT protocols: WiZ, SSDP, mDNS, etc.

    Args:
        network: Network CIDR (e.g., "192.168.1.0/24")
        timeout: Response timeout in seconds
        logger: Optional logger

    Returns:
        List of discovered devices with protocol info
    """
    discovered: List[Dict[str, Any]] = []

    try:
        net = ipaddress.ip_network(network, strict=False)
        broadcast = str(net.broadcast_address)
    except ValueError:
        return discovered

    # Protocol-specific probes for IoT discovery
    probes = [
        (1900, _build_ssdp_msearch(), "ssdp"),  # UPNP/SSDP (Chromecast, routers)
        (38899, _build_wiz_discovery(), "wiz"),  # WiZ smart bulbs
        (55443, b'{"id":1,"method":"get_prop","params":["power"]}', "yeelight"),  # Yeelight bulbs
        (20002, b"\\x02\\x00\\x00\\x01", "tapo"),  # TP-Link Tapo/Kasa devices
        (5353, _build_mdns_query(), "mdns"),  # mDNS (Apple devices, Chromecasts)
    ]

    for port, packet, protocol in probes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)

            # Send to broadcast address
            sock.sendto(packet, (broadcast, port))

            if logger:
                logger.debug("HyperScan UDP: Sent %s probe to %s:%d", protocol, broadcast, port)

            # Collect responses
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    sock.settimeout(max(0.1, end_time - time.time()))
                    data, addr = sock.recvfrom(2048)
                    if data:
                        discovered.append(
                            {
                                "ip": addr[0],
                                "port": addr[1],
                                "protocol": protocol,
                                "response_size": len(data),
                                "response_preview": data[:100].decode("utf-8", errors="ignore"),
                            }
                        )
                except socket.timeout:
                    break
                except Exception:
                    break

            sock.close()

        except Exception as exc:
            if logger:
                logger.debug("HyperScan UDP %s probe failed: %s", protocol, exc)

    # Also try unicast to common IoT IPs in subnet
    # Some devices don't respond to broadcast
    try:
        net = ipaddress.ip_network(network, strict=False)
        # Only scan first 50 and last 50 IPs for speed
        hosts_to_probe = []
        all_hosts = list(net.hosts())
        if len(all_hosts) <= 100:
            hosts_to_probe = all_hosts
        else:
            hosts_to_probe = all_hosts[:50] + all_hosts[-50:]

        for host in hosts_to_probe:
            ip = str(host)
            for port, packet, protocol in probes:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # WiZ bulbs are slow - need longer timeout
                    iot_timeout = 0.3 if protocol == "wiz" else 0.1
                    sock.settimeout(iot_timeout)
                    sock.sendto(packet, (ip, port))
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data:
                            discovered.append(
                                {
                                    "ip": addr[0],
                                    "port": port,
                                    "protocol": protocol,
                                    "response_size": len(data),
                                    "source": "unicast",
                                }
                            )
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception:
                    pass
    except Exception:
        pass

    # Deduplicate by IP
    seen_ips = set()
    unique = []
    for dev in discovered:
        if dev["ip"] not in seen_ips:
            seen_ips.add(dev["ip"])
            unique.append(dev)

    if logger and unique:
        logger.info("HyperScan UDP: Discovered %d IoT devices", len(unique))

    return unique


# ============================================================================
# ARP Aggressive Sweep
# ============================================================================


def hyperscan_arp_aggressive(
    network: str,
    retries: int = DEFAULT_ARP_RETRIES,
    timeout: float = DEFAULT_ARP_TIMEOUT,
    logger=None,
    dry_run: Optional[bool] = None,
) -> List[Dict]:
    """
    Aggressive ARP sweep with multiple retries.

    Uses arping or arp-scan with increased attempts to find
    hidden/slow-responding devices.

    Args:
        network: Network CIDR
        retries: Number of ARP attempts per host
        timeout: Timeout per sweep
        logger: Optional logger

    Returns:
        List of discovered hosts with MAC addresses
    """
    import shutil

    discovered = []
    seen_ips: Set[str] = set()
    runner = _make_runner(logger=logger, dry_run=dry_run, timeout=float(max(5.0, timeout * 2)))

    # Try arp-scan first (more reliable)
    arp_scan = shutil.which("arp-scan")
    if arp_scan:
        for attempt in range(retries):
            try:
                cmd = [
                    arp_scan,
                    "--interface=eth0",  # Will be overridden
                    "--retry=2",
                    "--timeout=500",
                    network,
                ]

                # Try to detect interface for network
                try:
                    # Simple heuristic for interface detection
                    route_output = runner.run(
                        ["ip", "route", "show", network],
                        capture_output=True,
                        text=True,
                        timeout=5.0,
                        check=False,
                    )
                    route_stdout = str(route_output.stdout or "")
                    if "dev" in route_stdout:
                        parts = route_stdout.split("dev")
                        if len(parts) > 1:
                            iface = parts[1].split()[0].strip()
                            cmd[1] = f"--interface={iface}"
                except Exception:
                    pass

                result = runner.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=float(timeout * 2),
                    check=False,
                )
                if result.timed_out:
                    if logger:
                        logger.warning("HyperScan ARP attempt %d timeout", attempt + 1)
                    continue

                # Parse arp-scan output
                for line in str(result.stdout or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1] if len(parts) > 1 else ""
                        vendor = " ".join(parts[2:]) if len(parts) > 2 else ""

                        # Validate IP
                        try:
                            ipaddress.ip_address(ip)
                            if ip not in seen_ips:
                                seen_ips.add(ip)
                                discovered.append(
                                    {
                                        "ip": ip,
                                        "mac": mac,
                                        "vendor": vendor,
                                        "method": "arp-scan",
                                        "attempt": attempt + 1,
                                    }
                                )
                        except ValueError:
                            pass

            except Exception as exc:
                if logger:
                    logger.debug("HyperScan ARP attempt %d error: %s", attempt + 1, exc)

    # Fallback to arping for hosts not found
    arping = shutil.which("arping")
    if arping and len(discovered) < 5:
        try:
            net = ipaddress.ip_network(network, strict=False)
            # Only probe first 30 hosts with arping (slow)
            for host in list(net.hosts())[:30]:
                ip = str(host)
                if ip in seen_ips:
                    continue

                try:
                    result = runner.run(
                        [arping, "-c", "1", "-w", "1", ip],
                        capture_output=True,
                        text=True,
                        timeout=3.0,
                        check=False,
                    )
                    if "reply from" in str(result.stdout or "").lower():
                        seen_ips.add(ip)
                        discovered.append(
                            {
                                "ip": ip,
                                "mac": "",
                                "method": "arping",
                            }
                        )
                except Exception:
                    pass
        except Exception:
            pass

    if logger:
        logger.info("HyperScan ARP: Found %d hosts in %s", len(discovered), network)

    return discovered


# ============================================================================
# Full Discovery Orchestrator
# ============================================================================


def hyperscan_full_discovery(
    networks: List[str],
    quick_ports: List[int] = None,
    include_tcp: bool = True,
    include_udp: bool = True,
    include_arp: bool = True,
    tcp_batch_size: int = DEFAULT_TCP_BATCH_SIZE,
    logger=None,
    dry_run: Optional[bool] = None,
    progress_callback: Optional[HyperScanProgressCallback] = None,
) -> Dict:
    """
    Full parallel discovery combining TCP/UDP/ARP scans.

    Args:
        networks: List of network CIDRs to scan
        quick_ports: Ports for quick TCP scan (default: common IoT/backdoor ports)
        include_tcp: Enable TCP batch scanning
        include_udp: Enable UDP IoT probes
        include_arp: Enable ARP sweep
        tcp_batch_size: Concurrent TCP connections
        logger: Optional logger

    Returns:
        Discovery results dictionary
    """
    if quick_ports is None:
        # Common IoT and potential backdoor ports
        quick_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            81,
            110,
            139,
            143,
            443,
            445,
            554,
            1080,
            1433,
            1521,
            1883,
            3306,
            3389,
            5000,
            5432,
            5900,
            6379,
            8000,
            8080,
            8443,
            8888,
            9000,
            9090,
            # IoT specific
            38899,
            1982,
            56700,
            10001,
            49152,
        ]

    results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "networks": networks,
        "tcp_hosts": {},
        "udp_devices": [],
        "arp_hosts": [],
        "total_hosts_found": 0,
    }

    start_time = time.time()

    total = 100
    completed = 0

    valid_networks: List[Tuple[str, Any, List[str]]] = []
    for network in networks:
        try:
            net = ipaddress.ip_network(network, strict=False)
            all_ips = [str(h) for h in net.hosts()]
            valid_networks.append((network, net, all_ips))
        except ValueError:
            continue

    if not valid_networks:
        if progress_callback:
            try:
                progress_callback(100, 100, "complete")
            except Exception:
                pass
        results["duration_seconds"] = round(time.time() - start_time, 2)
        return results

    # Progress mapping: split 100% across networks and stages.
    # This avoids premature 100% when scanning multiple networks.
    net_share = 100.0 / float(len(valid_networks))
    stage_weights = {
        "arp": 0.15,
        "udp": 0.25,
        "tcp": 0.60,
    }
    if not include_arp:
        stage_weights["arp"] = 0.0
    if not include_udp:
        stage_weights["udp"] = 0.0
    if not include_tcp:
        stage_weights["tcp"] = 0.0
    weight_sum = sum(stage_weights.values()) or 1.0
    for k in stage_weights:
        stage_weights[k] = stage_weights[k] / weight_sum

    def _report(progress: float, desc: str) -> None:
        nonlocal completed
        completed = max(0, min(int(round(progress)), total))
        if progress_callback:
            try:
                progress_callback(completed, total, str(desc)[:200])
            except Exception:
                return

    _report(0.0, "initializing")

    for idx, (network, net, all_ips) in enumerate(valid_networks):
        net_base = idx * net_share
        net_end = (idx + 1) * net_share
        net_span = max(0.0, net_end - net_base)

        def _net_progress(stage_offset: float, stage_span: float, frac: float, desc: str) -> None:
            pct = net_base + stage_offset + (stage_span * max(0.0, min(1.0, frac)))
            _report(pct, desc)

        # 1. ARP sweep first (fastest for L2)
        if include_arp:
            arp_off = net_span * 0.0
            arp_span = net_span * stage_weights["arp"]
            _net_progress(arp_off, arp_span, 0.0, f"ARP sweep ({network})")
            arp_results = hyperscan_arp_aggressive(network, logger=logger, dry_run=dry_run)
            results["arp_hosts"].extend(arp_results)
            _net_progress(arp_off, arp_span, 1.0, f"ARP done ({network})")

        # 2. UDP IoT probes
        if include_udp:
            udp_off = net_span * stage_weights["arp"]
            udp_span = net_span * stage_weights["udp"]
            lang = detect_preferred_language()
            _net_progress(udp_off, udp_span, 0.0, get_text("udp_probes_progress", lang, network))
            udp_results = hyperscan_udp_broadcast(network, logger=logger)
            results["udp_devices"].extend(udp_results)
            _net_progress(udp_off, udp_span, 1.0, f"UDP done ({network})")

        # 3. TCP batch scan (on discovered hosts or full subnet)
        if include_tcp:
            # Prioritize hosts found via ARP/UDP
            priority_ips = set()
            for h in results["arp_hosts"]:
                priority_ips.add(h["ip"])
            for d in results["udp_devices"]:
                priority_ips.add(d["ip"])

            # If we found hosts, scan those; otherwise sample the network
            if priority_ips:
                targets = list(priority_ips)
            else:
                # Sample: first 50 + last 50 + random 50
                if len(all_ips) > 150:
                    import random

                    targets = (
                        all_ips[:50]
                        + all_ips[-50:]
                        + random.sample(all_ips[50:-50], min(50, len(all_ips) - 100))
                    )
                else:
                    targets = all_ips

            tcp_off = net_span * (stage_weights["arp"] + stage_weights["udp"])
            tcp_span = net_span * stage_weights["tcp"]

            def _tcp_progress(c: int, t: int, desc: str) -> None:
                frac = (float(c) / float(t)) if t else 0.0
                _net_progress(tcp_off, tcp_span, frac, f"{desc} ({network})")

            tcp_results = hyperscan_tcp_sweep_sync(
                targets,
                quick_ports,
                tcp_batch_size,
                logger=logger,
                progress_callback=_tcp_progress,
            )

            for ip, ports in tcp_results.items():
                if ports:
                    results["tcp_hosts"][ip] = ports

            _net_progress(tcp_off, tcp_span, 1.0, f"TCP done ({network})")

    # Calculate totals
    all_found = set()
    for h in results["arp_hosts"]:
        all_found.add(h["ip"])
    for d in results["udp_devices"]:
        all_found.add(d["ip"])
    for ip in results["tcp_hosts"]:
        all_found.add(ip)

    results["total_hosts_found"] = len(all_found)
    results["duration_seconds"] = round(time.time() - start_time, 2)

    _report(100.0, "complete")

    if logger:
        logger.info(
            "HyperScan complete: %d hosts found in %.2fs",
            results["total_hosts_found"],
            results["duration_seconds"],
        )

    return results


# ============================================================================
# Backdoor Detection Helper
# ============================================================================


def detect_potential_backdoors(
    tcp_results: Dict[str, List[int]],
    service_info: Dict[str, Dict[int, str]] = None,
    logger=None,
) -> List[Dict]:
    """
    Analyze TCP results to identify potential backdoors.

    Looks for:
    - Unusual high ports with services
    - Standard ports with unexpected services
    - Known backdoor port patterns

    Args:
        tcp_results: Dict mapping IP -> list of open ports
        service_info: Optional dict mapping IP -> {port: service_name}
        logger: Optional logger

    Returns:
        List of suspicious findings
    """
    # Import is_port_anomaly from scanner if available
    try:
        from redaudit.core.scanner import is_port_anomaly, is_suspicious_service

        has_scanner_integration = True
    except ImportError:
        has_scanner_integration = False

    # Known suspicious port patterns
    SUSPICIOUS_RANGES = [
        (31337, 31337, "elite backdoor"),
        (4444, 4444, "metasploit default"),
        (5555, 5555, "android debug / freeciv"),
        (6666, 6667, "irc / possible c2"),
        (12345, 12346, "netbus"),
        (27374, 27374, "subseven"),
        (54321, 54321, "back orifice 2k"),
        (1337, 1337, "leet backdoor"),
        (666, 666, "doom/backdoor"),
        (65535, 65535, "unusual max port"),
    ]

    # Unusual high ports (above 49152 = dynamic range)
    DYNAMIC_PORT_START = 49152

    suspicious = []

    for ip, ports in tcp_results.items():
        for port in ports:
            reason = None
            severity = "low"

            # Check known backdoor ports
            for start, end, name in SUSPICIOUS_RANGES:
                if start <= port <= end:
                    reason = f"Known backdoor port pattern: {name}"
                    severity = "high"
                    break

            # Check unusual high ports
            if not reason and port >= DYNAMIC_PORT_START:
                reason = "Unusual high port in dynamic range"
                severity = "medium"

            # Check service anomalies if we have service info
            if not reason and has_scanner_integration and service_info:
                ip_services = service_info.get(ip, {})
                service_name = ip_services.get(port, "")
                if service_name:
                    # Check if service is suspicious
                    if is_suspicious_service(service_name):
                        reason = f"Suspicious service detected: {service_name}"
                        severity = "high"
                    # Check if port/service mismatch
                    elif is_port_anomaly(port, service_name):
                        reason = f"Port/service anomaly: {service_name} on port {port}"
                        severity = "high"

            if reason:
                suspicious.append(
                    {
                        "ip": ip,
                        "port": port,
                        "reason": reason,
                        "severity": severity,
                    }
                )

    if logger and suspicious:
        logger.warning("HyperScan: Found %d potential backdoor indicators", len(suspicious))

    return suspicious


# ============================================================================
# Deep Scan - Full 65535 Port Coverage
# ============================================================================


def hyperscan_deep_scan(
    target_ips: List[str],
    batch_size: int = 5000,
    timeout: float = 0.3,
    logger=None,
    progress_callback=None,
) -> Dict[str, List[int]]:
    """
    Deep scan ALL 65535 ports on suspicious hosts.

    This is the "sniffer dog" mode - scans absolutely everything.
    Use on hosts flagged as suspicious for comprehensive backdoor detection.

    Args:
        target_ips: List of IPs to deep scan
        batch_size: Concurrent connections (higher = faster but more aggressive)
        timeout: Connection timeout (lower = faster)
        logger: Optional logger
        progress_callback: Optional callback(completed, total, desc)

    Returns:
        Dict mapping IP -> list of ALL open ports
    """
    if not target_ips:
        return {}

    # Generate all 65535 ports
    all_ports = list(range(1, 65536))

    if logger:
        logger.info("HyperScan DEEP: Scanning ALL 65535 ports on %d hosts", len(target_ips))

    return hyperscan_tcp_sweep_sync(
        target_ips,
        all_ports,
        batch_size=batch_size,
        timeout=timeout,
        logger=logger,
    )


# ============================================================================
# Rich Progress Bar Wrapper
# ============================================================================


def hyperscan_with_progress(
    networks: List[str],
    print_fn=None,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Dict:
    """
    Run HyperScan with rich progress bars (for CLI integration).

    Args:
        networks: List of network CIDRs to scan
        print_fn: Optional print function for status messages
        logger: Optional logger

    Returns:
        Full discovery results
    """
    try:
        from rich.progress import (
            Progress,
            SpinnerColumn,
            BarColumn,
            TextColumn,
            TimeElapsedColumn,
        )

        use_rich = True
    except ImportError:
        use_rich = False

    if use_rich:
        from rich.console import Console

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=Console(file=getattr(sys, "__stdout__", sys.stdout)),
            refresh_per_second=4,
        ) as progress:
            task_id = progress.add_task("[cyan]HyperScan Discovery...", total=100)

            def progress_cb(completed: int, total: int, desc: str) -> None:
                pct = (completed / total * 100) if total > 0 else 0
                progress.update(task_id, completed=pct, description=f"[cyan]{desc}")

            # Run discovery with progress
            results = hyperscan_full_discovery(
                networks,
                logger=logger,
                dry_run=dry_run,
                progress_callback=progress_cb,
            )

            progress.update(task_id, completed=100)

            return results
    else:
        # Fallback without rich
        return hyperscan_full_discovery(networks, logger=logger, dry_run=dry_run)


# ============================================================================
# Integration Helper - Use All Available Tools
# ============================================================================


def hyperscan_with_nmap_enrichment(
    discovery_results: Dict,
    extra_tools: Dict = None,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Dict:
    """
    Enrich HyperScan results with nmap service detection.

    For hosts with open ports, runs nmap -sV to identify services,
    then applies backdoor detection with service info.

    Args:
        discovery_results: Results from hyperscan_full_discovery
        extra_tools: Dict of tool paths (e.g., {'nmap': '/usr/bin/nmap'})
        logger: Optional logger

    Returns:
        Enriched results with service info and backdoor analysis
    """
    import shutil

    nmap_path = (extra_tools or {}).get("nmap") or shutil.which("nmap")
    if not nmap_path:
        return discovery_results

    tcp_hosts = discovery_results.get("tcp_hosts", {})
    if not tcp_hosts:
        return discovery_results

    service_info: Dict[str, Dict[int, str]] = {}
    runner = _make_runner(logger=logger, dry_run=dry_run, timeout=60.0)

    for ip, ports in tcp_hosts.items():
        if not ports:
            continue

        # Run nmap service detection on found ports
        port_list = ",".join(str(p) for p in ports[:50])  # Limit to 50 ports
        cmd = [nmap_path, "-sV", "--version-light", "-p", port_list, ip]

        try:
            result = runner.run(cmd, capture_output=True, text=True, timeout=60.0, check=False)

            # Parse nmap output for service names
            ip_services: Dict[int, str] = {}
            for line in str(result.stdout or "").splitlines():
                # Match lines like: 22/tcp   open  ssh     OpenSSH 8.9
                import re

                match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
                if match:
                    port = int(match.group(1))
                    service = match.group(2)
                    ip_services[port] = service

            if ip_services:
                service_info[ip] = ip_services

        except Exception as exc:
            if logger:
                logger.debug("Nmap enrichment failed for %s: %s", ip, exc)

    # Add service info to results
    if service_info:
        discovery_results["service_info"] = service_info

        # Run backdoor detection with service info
        backdoors = detect_potential_backdoors(
            tcp_hosts,
            service_info=service_info,
            logger=logger,
        )
        if backdoors:
            discovery_results["potential_backdoors"] = backdoors

    return discovery_results
