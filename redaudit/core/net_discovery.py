#!/usr/bin/env python3
"""
RedAudit - Enhanced Network Discovery Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.2: Active discovery of guest networks, hidden VLANs, and additional network segments.

Goals:
- Detect DHCP servers on multiple VLANs (including guest networks)
- Enumerate NetBIOS/mDNS hostnames for entity resolution
- Fast L2 mapping via netdiscover/fping
- Optional Red Team techniques for deeper enumeration
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from redaudit.core.command_runner import CommandRunner
from redaudit.core.redteam import run_redteam_discovery
from redaudit.utils.dry_run import is_dry_run
from redaudit.utils.oui_lookup import lookup_vendor_online

ProgressCallback = Callable[[str, int, int], None]


def _run_cmd(
    args: List[str],
    timeout_s: int,
    logger=None,
) -> Tuple[int, str, str]:
    """Execute a command with timeout, returning (returncode, stdout, stderr)."""
    runner = CommandRunner(
        logger=logger,
        dry_run=is_dry_run(),
        default_timeout=float(timeout_s),
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
    )
    try:
        res = runner.run(
            args, timeout=float(timeout_s), capture_output=True, check=False, text=True
        )
        stdout = res.stdout if isinstance(res.stdout, str) else ""
        stderr = res.stderr if isinstance(res.stderr, str) else ""
        return int(res.returncode), stdout, stderr
    except Exception as e:
        if logger:
            logger.error(f"Command execution failed: {e}")
        return -1, "", str(e)


def _run_cmd_suppress_stderr(
    args: List[str],
    timeout_s: int,
    logger=None,
) -> Tuple[int, str, str]:
    """
    Execute a command suppressing stderr from being displayed on terminal.

    v4.3: Used for arp-scan which writes warnings directly to tty even when
    stderr is captured. We capture stderr in memory but don't let it pollute
    the terminal during progress UI.
    """
    import subprocess

    if is_dry_run():
        if logger:
            logger.debug(f"[dry-run] {' '.join(args)}")
        return 0, "", ""

    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # Capture stderr instead of DEVNULL
            timeout=float(timeout_s),
            text=True,
            check=False,
        )
        # Return captured stderr for analysis (e.g., counting warnings)
        # but it won't be printed to terminal
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        if logger:
            logger.warning("Command timeout: %s", " ".join(args))
        return 124, getattr(e, "stdout", "") or "", getattr(e, "stderr", "") or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}"
    except Exception as e:
        if logger:
            logger.error(f"Command execution failed: {e}")
        return -1, "", str(e)


_IFACE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\\-_]{0,31}$")
_VIRTUAL_IFACE_PREFIXES = (
    "br-",
    "docker",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "tap",
    "tun",
    "wg",
    "zt",
)
_WIRELESS_IFACE_PREFIXES = ("wl", "wlan", "wifi", "wlp")


def _sanitize_iface(iface: Optional[str]) -> Optional[str]:
    if not isinstance(iface, str):
        return None
    iface = iface.strip()
    if not iface or not _IFACE_RE.match(iface):
        return None
    return iface


def _check_tools() -> Dict[str, bool]:
    """Check availability of discovery tools."""
    return {
        "nmap": bool(shutil.which("nmap")),
        "fping": bool(shutil.which("fping")),
        "nbtscan": bool(shutil.which("nbtscan")),
        "netdiscover": bool(shutil.which("netdiscover")),
        "arp-scan": bool(shutil.which("arp-scan")),
        "avahi-browse": bool(shutil.which("avahi-browse")),
        "tcpdump": bool(shutil.which("tcpdump")),
        "snmpwalk": bool(shutil.which("snmpwalk")),
        "enum4linux": bool(shutil.which("enum4linux")),
        "masscan": bool(shutil.which("masscan")),
        "rpcclient": bool(shutil.which("rpcclient")),
        "ldapsearch": bool(shutil.which("ldapsearch")),
        "kerbrute": bool(shutil.which("kerbrute")),
        "dig": bool(shutil.which("dig")),
        "responder": bool(shutil.which("responder")),
        "bettercap": bool(shutil.which("bettercap")),
        "yersinia": bool(shutil.which("yersinia")),
        "frogger": bool(shutil.which("frogger")),
        "ip": bool(shutil.which("ip")),
        "ping6": bool(shutil.which("ping6")),
        "ping": bool(shutil.which("ping")),
    }


# =============================================================================
# DHCP Discovery
# =============================================================================


def detect_default_route_interface(logger=None) -> Optional[str]:
    """Return the interface tied to the system default route, if available."""
    if not shutil.which("ip"):
        return None

    rc, out, _ = _run_cmd(["ip", "route", "show", "default"], 4, logger)
    if rc != 0 and not out.strip():
        return None

    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("default"):
            continue
        parts = line.split()
        if "dev" in parts:
            try:
                return parts[parts.index("dev") + 1]
            except Exception:
                continue
    return None


def _classify_iface_name(interface: Optional[str]) -> Optional[str]:
    if not interface:
        return None
    name = interface.lower()
    if name == "lo" or name.startswith("lo"):
        return "loopback"
    for prefix in _VIRTUAL_IFACE_PREFIXES:
        if name.startswith(prefix):
            return "virtual"
    for prefix in _WIRELESS_IFACE_PREFIXES:
        if name.startswith(prefix):
            return "wireless"
    return None


def _get_interface_facts(interface: Optional[str], logger=None) -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "iface": None,
        "link_up": None,
        "carrier": None,
        "ipv4": [],
        "ipv6": [],
        "kind": None,
        "ipv4_checked": False,
        "ipv6_checked": False,
    }
    safe_iface = _sanitize_iface(interface)
    if not safe_iface:
        return facts
    facts["iface"] = safe_iface
    facts["kind"] = _classify_iface_name(safe_iface)

    if shutil.which("ip"):
        rc, out, _ = _run_cmd(["ip", "-o", "link", "show", "dev", safe_iface], 2, logger)
        if rc == 0 and out:
            line = out.strip()
            match = re.search(r"<([^>]+)>", line)
            flags = set()
            if match:
                flags = {f.strip().upper() for f in match.group(1).split(",")}
            if "UP" in flags:
                facts["link_up"] = True
            if "LOWER_UP" in flags:
                facts["carrier"] = True
            if "UP" not in flags and re.search(r"\\bstate\\s+(DOWN|LOWERLAYERDOWN)\\b", line):
                facts["link_up"] = False
            if "LOWER_UP" not in flags and re.search(r"\\bstate\\s+(DOWN|LOWERLAYERDOWN)\\b", line):
                facts["carrier"] = False

        rc, out, _ = _run_cmd(["ip", "-o", "-4", "addr", "show", "dev", safe_iface], 2, logger)
        if rc == 0:
            facts["ipv4_checked"] = True
        if rc == 0 and out:
            for line in out.splitlines():
                match = re.search(r"inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)/", line)
                if match:
                    facts["ipv4"].append(match.group(1))

        rc, out, _ = _run_cmd(["ip", "-o", "-6", "addr", "show", "dev", safe_iface], 2, logger)
        if rc == 0:
            facts["ipv6_checked"] = True
        if rc == 0 and out:
            for line in out.splitlines():
                match = re.search(r"inet6\\s+([0-9a-fA-F:]+)/", line)
                if match:
                    facts["ipv6"].append(match.group(1))

        return facts

    if shutil.which("ifconfig"):
        rc, out, _ = _run_cmd(["ifconfig", safe_iface], 2, logger)
        if rc == 0 and out:
            if "status: active" in out:
                facts["link_up"] = True
                facts["carrier"] = True
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    parts = line.split()
                    if len(parts) >= 2:
                        facts["ipv4"].append(parts[1])
                if line.startswith("inet6 "):
                    parts = line.split()
                    if len(parts) >= 2:
                        facts["ipv6"].append(parts[1])

    return facts


def _format_dhcp_timeout_hint(interface: Optional[str], logger=None) -> Optional[str]:
    iface_for_hint = interface or detect_default_route_interface(logger)
    facts = _get_interface_facts(iface_for_hint, logger)
    hints = []
    default_src_ip = None

    def _default_route_src_ip() -> Optional[str]:
        if not iface_for_hint or not shutil.which("ip"):
            return None
        rc, out, _ = _run_cmd(["ip", "route", "show", "default"], 4, logger)
        if rc != 0 and not out.strip():
            return None
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts and parts[parts.index("dev") + 1] == iface_for_hint:
                if "src" in parts:
                    try:
                        return parts[parts.index("src") + 1]
                    except Exception:
                        return None
        return None

    default_src_ip = _default_route_src_ip()

    def _add_hint(text: str) -> None:
        if text not in hints:
            hints.append(text)

    if facts.get("kind") == "loopback":
        _add_hint("interface is loopback; DHCP is not applicable")
    if facts.get("link_up") is False or facts.get("carrier") is False:
        _add_hint("interface appears down or has no carrier")
    if facts.get("ipv4_checked") and not facts.get("ipv4") and not default_src_ip:
        _add_hint("no IPv4 address detected on interface")
    if facts.get("kind") == "virtual":
        _add_hint("interface looks virtual/bridge; DHCP may be unavailable")
    if facts.get("kind") == "wireless":
        _add_hint("wireless interface; AP isolation can block DHCP broadcasts")

    _add_hint("no DHCP server responding on this network")

    if not hints:
        return None
    return "Possible causes: " + "; ".join(hints)


def dhcp_discover(
    interface: Optional[str] = None,
    timeout_s: int = 10,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover DHCP servers using nmap broadcast-dhcp-discover script.

    Returns:
        {
            "servers": [{"ip": "...", "subnet": "...", "gateway": "...", "dns": [...]}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"servers": [], "error": None}

    if not shutil.which("nmap"):
        result["error"] = "nmap not available"
        return result

    cmd = ["nmap", "--script", "broadcast-dhcp-discover"]
    if interface:
        cmd.extend(["-e", interface])

    rc, out, err = _run_cmd(cmd, timeout_s, logger)

    if rc != 0 and not out.strip():
        iface_label = interface or "default route"
        err_text = (err or "").strip()
        if rc == 124 or "timeout" in err_text.lower():
            hint = _format_dhcp_timeout_hint(interface, logger)
            if hint:
                result["error"] = (
                    f"no response to DHCP broadcast on {iface_label} (timeout). {hint}"
                )
            else:
                result["error"] = f"no response to DHCP broadcast on {iface_label} (timeout)"
        elif err_text:
            result["error"] = f"dhcp-discover failed on {iface_label}: {err_text}"
        else:
            result["error"] = f"dhcp-discover failed on {iface_label}"
        return result

    # Parse DHCP responses
    # Example output:
    # | DHCPOFFER:
    # |   Server Identifier: 192.168.178.1
    # |   IP Address Offered: 192.168.178.50
    # |   Subnet Mask: 255.255.255.0
    # |   Router: 192.168.178.1
    # |   Domain Name Server: 8.8.8.8

    current_server: Dict[str, Any] = {}
    for line in out.splitlines():
        line = line.strip()

        if "DHCPOFFER" in line or "DHCPACK" in line:
            if current_server.get("ip"):
                result["servers"].append(current_server)
            current_server = {"dns": []}

        if "Server Identifier:" in line:
            match = re.search(r"Server Identifier:\s*(\S+)", line)
            if match:
                current_server["ip"] = match.group(1)

        if "Subnet Mask:" in line:
            match = re.search(r"Subnet Mask:\s*(\S+)", line)
            if match:
                current_server["subnet"] = match.group(1)

        if "Router:" in line:
            match = re.search(r"Router:\s*(\S+)", line)
            if match:
                current_server["gateway"] = match.group(1)

        if "Domain Name Server:" in line:
            match = re.search(r"Domain Name Server:\s*(\S+)", line)
            if match:
                current_server.setdefault("dns", []).append(match.group(1))

        # Best-effort domain hints (useful for DNS/AD enumeration).
        match = re.search(r"^[\s|_]*Domain Name:\s*(.+)", line, re.IGNORECASE)
        if match:
            domain = match.group(1).strip().strip('"')
            if domain and domain.lower() != "local":
                current_server["domain"] = domain[:200]

        match = re.search(r"^[\s|_]*Domain Search:\s*(.+)", line, re.IGNORECASE)
        if match:
            search = match.group(1).strip().strip('"')
            if search:
                current_server["domain_search"] = search[:200]

    if current_server.get("ip"):
        result["servers"].append(current_server)

    return result


# =============================================================================
# Fping Sweep
# =============================================================================


def fping_sweep(
    target: str,
    timeout_s: int = 15,
    logger=None,
) -> Dict[str, Any]:
    """
    Fast ICMP host discovery using fping.

    Args:
        target: Network range (e.g., "192.168.178.0/24")

    Returns:
        {
            "alive_hosts": ["192.168.178.1", "192.168.178.2", ...],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"alive_hosts": [], "error": None}

    if not shutil.which("fping"):
        result["error"] = "fping not available"
        return result

    cmd = ["fping", "-a", "-g", target, "-q"]
    rc, out, err = _run_cmd(cmd, timeout_s, logger)

    # fping returns non-zero if some hosts are unreachable, but stdout still has alive hosts
    for line in out.splitlines():
        ip = line.strip()
        if ip and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            result["alive_hosts"].append(ip)

    # Also check stderr for alive hosts (some versions output there)
    for line in err.splitlines():
        if "is alive" in line:
            match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match and match.group(1) not in result["alive_hosts"]:
                result["alive_hosts"].append(match.group(1))

    return result


# =============================================================================
# NetBIOS Discovery
# =============================================================================


def netbios_discover(
    target: str,
    timeout_s: int = 15,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover Windows hosts via NetBIOS name queries.

    Args:
        target: Network range (e.g., "192.168.178.0/24")

    Returns:
        {
            "hosts": [{"ip": "...", "name": "...", "workgroup": "...", "mac": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"hosts": [], "error": None}

    # Try nbtscan first (faster), fall back to nmap
    if shutil.which("nbtscan"):
        cmd = ["nbtscan", "-r", target]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)

        if rc == 0 or out.strip():
            # Parse nbtscan output
            # IP             NetBIOS Name     Server    User              MAC
            # 192.168.178.10 DESKTOP-ABC      <server>  <user>           aa:bb:cc:dd:ee:ff
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
                    host = {"ip": parts[0], "name": parts[1]}
                    if len(parts) >= 5:
                        host["mac"] = parts[-1] if ":" in parts[-1] else None
                    result["hosts"].append(host)
            return result

    # Fallback to nmap
    if shutil.which("nmap"):
        cmd = ["nmap", "-sU", "-p", "137", "--script", "nbstat", target]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)

        if rc == 0 or out.strip():
            # Parse nmap nbstat output
            current_ip = None
            for line in out.splitlines():
                ip_match = re.search(r"Nmap scan report for (\S+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)

                name_match = re.search(r"NetBIOS name:\s*([^\s,]+)", line, re.IGNORECASE)
                if name_match and current_ip:
                    result["hosts"].append(
                        {
                            "ip": current_ip,
                            "name": name_match.group(1),
                        }
                    )
            return result

    result["error"] = "Neither nbtscan nor nmap available"
    return result


# =============================================================================
# Netdiscover (ARP)
# =============================================================================


def netdiscover_scan(
    target: str,
    timeout_s: int = 20,
    active: bool = True,
    interface: Optional[str] = None,
    logger=None,
) -> Dict[str, Any]:
    """
    L2 ARP discovery using netdiscover.

    v3.2.2b: Added active mode (default), increased timeout, interface support.
    Active mode sends ARP requests vs passive just sniffing.

    Args:
        target: Network range (e.g., "192.168.178.0/24")
        timeout_s: Timeout in seconds (default 20s)
        active: If True, use active ARP scanning (no -P flag)
        interface: Network interface to use (optional)

    Returns:
        {
            "hosts": [{"ip": "...", "mac": "...", "vendor": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"hosts": [], "error": None}

    if not shutil.which("netdiscover"):
        result["error"] = "netdiscover not available"
        return result

    # Build command
    # -r = range, -N = no headers, -P = passive (only if not active)
    cmd = ["netdiscover", "-r", target, "-N"]

    if interface:
        safe_iface = _sanitize_iface(interface)
        if safe_iface:
            cmd.extend(["-i", safe_iface])

    if not active:
        cmd.append("-P")  # Passive mode (just sniff)
    else:
        cmd.append("-f")  # Fast mode (active ARP)

    rc, out, err = _run_cmd(cmd, timeout_s, logger)

    # Parse netdiscover output
    # IP               At MAC Address     Count     Len  MAC Vendor
    # 192.168.178.1    d4:24:dd:07:7c:c5      1      60  Unknown vendor
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
            mac = parts[1] if len(parts) > 1 else None
            # Vendor is everything after the first few columns
            vendor = " ".join(parts[4:]) if len(parts) > 4 else None
            # v4.1: Enrich Unknown vendors via online OUI lookup
            if mac and (not vendor or "unknown" in vendor.lower()):
                try:
                    online_vendor = lookup_vendor_online(mac)
                    if online_vendor:
                        vendor = online_vendor
                except Exception:
                    pass
            host = {
                "ip": parts[0],
                "mac": mac,
            }
            if vendor:
                host["vendor"] = vendor
            result["hosts"].append(host)

    return result


def arp_scan_active(
    target: Optional[str] = None,
    interface: Optional[str] = None,
    timeout_s: int = 15,
    logger=None,
) -> Dict[str, Any]:
    """
    Active ARP scanning using arp-scan.

    v3.2.2b: New function for more reliable IoT discovery.
    arp-scan is more reliable than netdiscover for discovering devices
    behind client isolation or in power-save mode.

    Args:
        target: Network range (e.g., "192.168.178.0/24") or None for localnet
        interface: Network interface (-I option)
        timeout_s: Command timeout

    Returns:
        {
            "hosts": [{"ip": "...", "mac": "...", "vendor": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"hosts": [], "error": None}

    if not shutil.which("arp-scan"):
        result["error"] = "arp-scan not available"
        return result

    # Build command
    cmd = ["arp-scan"]

    if interface:
        safe_iface = _sanitize_iface(interface)
        if safe_iface:
            cmd.extend(["-I", safe_iface])

    if target:
        cmd.append(target)
    else:
        cmd.append("-l")  # Scan local network

    # Add retry for better IoT discovery
    cmd.extend(["--retry", "2"])

    # v4.3: Use suppress_stderr to prevent raw warnings from appearing in terminal
    # arp-scan warnings are captured, counted, and shown as a single consolidated message
    rc, out, err = _run_cmd_suppress_stderr(cmd, timeout_s, logger)

    # v4.3: Count and consolidate ARP warnings for didactic feedback
    # arp-scan emits "WARNING: Mac address to reach destination not found" for L2-unreachable hosts
    warning_count = 0
    for line in (err or "").splitlines():
        if "WARNING" in line and "Mac address" in line:
            warning_count += 1

    if warning_count > 0:
        # Store consolidated warning in result for UI formatting
        result["l2_warnings"] = warning_count
        result["l2_warning_note"] = (
            f"{warning_count} hosts detected outside your local network (different subnet/VLAN). "
            "TCP/UDP scanning will work normally for these hosts."
        )

    # Parse arp-scan output
    # 192.168.178.1	d4:24:dd:07:7c:c5	AVM GmbH
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip_match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})$", parts[0].strip())
            if ip_match:
                mac = parts[1].strip() if len(parts) > 1 else None
                vendor = parts[2].strip() if len(parts) > 2 else None
                # v4.1: Enrich Unknown vendors via online OUI lookup
                if mac and (not vendor or "unknown" in vendor.lower()):
                    try:
                        online_vendor = lookup_vendor_online(mac)
                        if online_vendor:
                            vendor = online_vendor
                    except Exception:
                        pass
                host = {
                    "ip": ip_match.group(1),
                    "mac": mac,
                }
                if vendor:
                    host["vendor"] = vendor
                result["hosts"].append(host)

    return result


# =============================================================================
# mDNS Discovery
# =============================================================================


def mdns_discover(
    timeout_s: int = 15,
    interface: Optional[str] = None,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover services via mDNS/Bonjour.

    v3.2.2b: Increased timeout (5s -> 15s), added IoT-specific service queries.

    Returns:
        {
            "services": [{"ip": "...", "name": "...", "type": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"services": [], "error": None}

    # IoT-specific service types to query
    iot_service_types = [
        "_hap._tcp",  # HomeKit
        "_airplay._tcp",  # AirPlay / Apple TV
        "_raop._tcp",  # AirPlay audio
        "_googlecast._tcp",  # Chromecast / Google Home
        "_spotify-connect._tcp",  # Spotify Connect
        "_amzn-wplay._tcp",  # Amazon Alexa
        "_http._tcp",  # Generic HTTP (many IoT)
        "_https._tcp",  # Generic HTTPS
        "_smb._tcp",  # SMB shares
        "_printer._tcp",  # Printers
        "_ipp._tcp",  # IPP printing
    ]

    if shutil.which("avahi-browse"):
        # First: browse all services
        cmd = ["avahi-browse", "-apt", "--resolve"]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)

        # Parse avahi-browse output
        # =;eth0;IPv4;hostname;_http._tcp;local
        for line in out.splitlines():
            if line.startswith("="):
                parts = line.split(";")
                if len(parts) >= 5:
                    service = {
                        "interface": parts[1],
                        "name": parts[3],
                        "type": parts[4],
                    }
                    # Look for IP in resolved output
                    if len(parts) >= 8:
                        service["ip"] = parts[7]
                    result["services"].append(service)

        # Second: query specific IoT service types if first pass found nothing
        if not result["services"]:
            for svc_type in iot_service_types[:5]:  # Top 5 most common
                cmd_specific = ["avahi-browse", "-pt", "--resolve", svc_type]
                rc2, out2, err2 = _run_cmd(cmd_specific, 5, logger)
                for line in out2.splitlines():
                    if line.startswith("="):
                        parts = line.split(";")
                        if len(parts) >= 5:
                            service = {
                                "interface": parts[1],
                                "name": parts[3],
                                "type": parts[4],
                            }
                            if len(parts) >= 8:
                                service["ip"] = parts[7]
                            result["services"].append(service)
        return result

    # Fallback to nmap dns-service-discovery
    if shutil.which("nmap"):
        cmd = ["nmap", "--script", "dns-service-discovery", "-p", "5353", "224.0.0.251"]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        # Basic parsing - nmap output is more complex
        if "_tcp" in out or "_udp" in out:
            result["services"].append({"raw": out[:500], "type": "nmap_raw"})
        return result

    result["error"] = "Neither avahi-browse nor nmap available"
    return result


# =============================================================================
# UPNP Discovery
# =============================================================================


def upnp_discover(
    timeout_s: int = 25,
    retries: int = 2,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover UPNP devices (routers, NAS, media servers, IoT).

    v3.2.2b: Increased timeout (10s -> 25s), added retry mechanism and SSDP fallback.

    Returns:
        {
            "devices": [{"ip": "...", "device": "...", "services": [...]}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"devices": [], "error": None}

    def _parse_upnp_output(out: str) -> List[Dict[str, Any]]:
        """Parse nmap UPNP output into device list."""
        devices = []
        current_device: Dict[str, Any] = {}
        for line in out.splitlines():
            line = line.strip()

            if "Server:" in line:
                if current_device.get("ip") or current_device.get("device"):
                    devices.append(current_device)
                current_device = {"services": []}
                match = re.search(r"Server:\s*(.+)", line)
                if match:
                    current_device["device"] = match.group(1)

            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:", line):
                current_device["ip"] = line.split(":")[0]

            if "urn:" in line:
                current_device.setdefault("services", []).append(line.strip())

        if current_device.get("ip") or current_device.get("device"):
            devices.append(current_device)
        return devices

    if not shutil.which("nmap"):
        result["error"] = "nmap not available"
        return result

    # Try nmap broadcast-upnp-info with retries
    for attempt in range(retries):
        cmd = ["nmap", "--script", "broadcast-upnp-info"]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        devices = _parse_upnp_output(out)
        if devices:
            result["devices"] = devices
            return result
        # Wait briefly before retry
        if attempt < retries - 1:
            import time

            time.sleep(1)

    # SSDP M-SEARCH fallback using raw socket simulation via nmap
    # This uses a different discovery method that may catch more devices
    cmd_ssdp = ["nmap", "--script", "upnp-info", "-sU", "-p", "1900", "--open", "239.255.255.250"]
    rc, out, err = _run_cmd(cmd_ssdp, timeout_s // 2, logger)
    devices = _parse_upnp_output(out)
    if devices:
        result["devices"] = devices

    return result


# =============================================================================
# Routing Discovery (Hidden Networks)
# =============================================================================


def detect_routed_networks(
    logger=None,
) -> Dict[str, Any]:
    """
    Detect routed networks and gateways via system routing table.

    Parses `ip route` and `ip neigh` to find subnets that are not
    directly configured on interfaces but are reachable via gateways.

    Returns:
        {
            "networks": ["10.0.100.0/24", ...],
            "gateways": [{"ip": "...", "mac": "...", "interface": "..."}],
            "error": None
        }
    """
    result: Dict[str, Any] = {"networks": [], "gateways": [], "error": None}

    if not shutil.which("ip"):
        result["error"] = "ip command not available"
        return result

    # 1. Parse ip route
    # default via 192.168.1.1 dev eth0 ...
    # 10.0.100.0/24 via 192.168.1.1 dev eth0
    # 192.168.1.0/24 dev eth0 proto kernel scope link src ...
    rc, out_route, err_route = _run_cmd(["ip", "route", "show"], 5, logger)
    if rc != 0:
        result["error"] = f"ip route failed: {err_route}"
        return result

    networks = set()
    gateways = set()

    for line in out_route.splitlines():
        parts = line.split()
        if not parts:
            continue

        # Skip default route for network discovery (it's 0.0.0.0/0)
        if parts[0] == "default":
            continue

        # Candidate network is usually the first token
        candidate = parts[0]

        # Valid CIDR check
        try:
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
                networks.add(candidate)
        except ValueError:
            pass

        # Check for gateway
        if "via" in parts:
            try:
                via_idx = parts.index("via") + 1
                if via_idx < len(parts):
                    gw_ip = parts[via_idx]
                    ipaddress.ip_address(gw_ip)  # Validate IP
                    gateways.add(gw_ip)
            except (ValueError, IndexError):
                pass

    # 2. Parse ip neigh to enrich gateways
    # 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
    rc, out_neigh, err_neigh = _run_cmd(["ip", "neigh", "show"], 5, logger)

    gateway_objs = []
    # If gateways list is empty, treat all router-like neighbors as potential gateways?
    # For now, we only trust gateways found in routing table or explicitly marked as routers.

    for line in out_neigh.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        ip = parts[0]
        dev = parts[2] if len(parts) > 2 else ""
        mac = parts[4] if len(parts) > 4 else ""

        # If this IP was identified as a gateway in routing table
        if ip in gateways:
            gateway_objs.append({"ip": ip, "mac": mac, "interface": dev})

    result["networks"] = sorted(list(networks))
    result["gateways"] = gateway_objs

    return result


# =============================================================================
# L2 Passive Discovery (LLDP/CDP/VLAN)
# =============================================================================


def detect_local_vlan_tags(
    interface: Optional[str] = None,
    logger=None,
) -> List[int]:
    """
    Detect local VLAN tags on the interface (ifconfig/ip output).

    Returns:
        List of VLAN IDs found (e.g., [100, 105]).
    """
    tags = set()
    if not interface:
        # Try finding default interface?
        # For now, if no interface provided, we can't easily guess which one to check for VLANs
        # effectively without iterating all.
        return []

    safe_iface = _sanitize_iface(interface)
    if not safe_iface:
        return []

    # Method 1: ip -d link show (Linux)
    if shutil.which("ip"):
        rc, out, _ = _run_cmd(["ip", "-d", "link", "show", safe_iface], 2, logger)
        if rc == 0:
            # Output example: "vlan protocol 802.1Q id 100 <REORDER_HDR>"
            for line in out.splitlines():
                m = re.search(r"vlan protocol 802\.1Q id (\d+)", line)
                if m:
                    tags.add(int(m.group(1)))

    # Method 2: ifconfig (macOS/BSD)
    # Output example: "vlan: 100 parent interface: en0"
    if not tags and shutil.which("ifconfig"):
        rc, out, _ = _run_cmd(["ifconfig", safe_iface], 2, logger)
        if rc == 0:
            for line in out.splitlines():
                # macOS: vlan: 100 parent interface: en0
                m = re.search(r"vlan:\s*(\d+)", line)
                if m:
                    tags.add(int(m.group(1)))

    return sorted(list(tags))


def listen_lldp(
    interface: str,
    timeout_s: int = 45,
    logger=None,
) -> Dict[str, Any]:
    """
    Listen for LLDP packets using tcpdump.

    Requires root.

    Returns:
        Dict with keys: system_name, port_id, vlan_id, etc.
    """
    result = {}
    if not shutil.which("tcpdump"):
        return {"error": "tcpdump not found"}

    safe_iface = _sanitize_iface(interface)
    if not safe_iface:
        return {"error": f"Invalid interface: {interface}"}

    # Capture 1 packet, verbose, snaplen 1500
    # Filter: ether proto 0x88cc (LLDP)
    cmd = [
        "tcpdump",
        "-i",
        safe_iface,
        "-v",
        "-s",
        "1500",
        "-c",
        "1",
        "ether",
        "proto",
        "0x88cc",
    ]

    # This will exit with 0 if packet found, or timeout (124) if not.
    # _run_cmd kills process on timeout, which is what we want.
    rc, out, err = _run_cmd(cmd, timeout_s, logger)

    output = out + "\n" + err
    if "LLDP" not in output:
        if rc != 0:
            return {"error": "Timeout or permission denied (requires root)"}
        return {"error": "No LLDP packets captured"}

    # Parse tcpdump -v output for LLDP
    # System Name TLV (5), length 18: Switch-01
    # Port ID TLV (4), length 7: GigabitEthernet1/0/1
    # VLAN parameters not always decoded by stock tcpdump easily, but we try.

    m_sys = re.search(r"System Name TLV.*?: (.+)", output)
    if m_sys:
        result["system_name"] = m_sys.group(1).strip()

    m_port = re.search(r"Port ID TLV.*?: (.+)", output)
    if m_port:
        result["port_id"] = m_port.group(1).strip()

    m_desc = re.search(r"System Description TLV.*?: (.+)", output)
    if m_desc:
        result["system_desc"] = m_desc.group(1).strip()

    m_mgmt = re.search(r"Management Address TLV.*?: ([\d\.]+)", output)
    if m_mgmt:
        result["management_ip"] = m_mgmt.group(1).strip()

    # VLAN ID? tcpdump sometimes shows "802.1Q VLAN ID: 100"
    m_vlan = re.search(r"VLAN ID: (\d+)", output)
    if m_vlan:
        result["vlan_id"] = int(m_vlan.group(1))

    return result


def listen_cdp(
    interface: str,
    timeout_s: int = 45,
    logger=None,
) -> Dict[str, Any]:
    """
    Listen for CDP packets using tcpdump.

    Requires root.
    """
    result = {}
    if not shutil.which("tcpdump"):
        return {"error": "tcpdump not found"}

    safe_iface = _sanitize_iface(interface)
    if not safe_iface:
        return {"error": f"Invalid interface: {interface}"}

    # Filter: SNAP header for CDP (0x2000) or multicast dst
    # tcpdump -v -s 1500 -c 1 ether[20:2] == 0x2000
    cmd = [
        "tcpdump",
        "-i",
        safe_iface,
        "-v",
        "-s",
        "1500",
        "-c",
        "1",
        "ether[20:2] == 0x2000",
    ]

    rc, out, err = _run_cmd(cmd, timeout_s, logger)
    output = out + "\n" + err

    if "CDP" not in output and "Cisco Discovery Protocol" not in output:
        return {}

    # Parse CDP
    # Device-ID (0x01), length: 12 bytes: 'Switch-01'
    # Port-ID (0x03), length: 16 bytes: 'FastEthernet0/1'
    # Native VLAN ID (0x0a), length: 2 bytes: 100

    m_dev = re.search(r"Device-ID.*?: '([^']+)'", output)
    if m_dev:
        result["device_id"] = m_dev.group(1)

    m_port = re.search(r"Port-ID.*?: '([^']+)'", output)
    if m_port:
        result["port_id"] = m_port.group(1)

    m_vlan = re.search(r"Native VLAN ID.*?: (\d+)", output)
    if m_vlan:
        result["native_vlan"] = int(m_vlan.group(1))

    m_plat = re.search(r"Platform.*?: '([^']+)'", output)
    if m_plat:
        result["platform"] = m_plat.group(1)

    return result


# =============================================================================
# Main Discovery Function
# =============================================================================


def discover_networks(
    target_networks: List[str],
    interface: Optional[str] = None,
    dhcp_interfaces: Optional[List[str]] = None,
    dhcp_timeout_s: Optional[int] = None,
    protocols: Optional[List[str]] = None,
    redteam: bool = False,
    redteam_options: Optional[Dict[str, Any]] = None,
    exclude_ips: Optional[Set[str]] = None,
    extra_tools: Optional[Dict[str, str]] = None,
    progress_callback: Optional[ProgressCallback] = None,
    logger=None,
) -> Dict[str, Any]:
    """
    Main entry point for enhanced network discovery.

    Args:
        target_networks: List of network ranges to scan
        interface: Network interface to use (optional)
        dhcp_interfaces: Optional list of interfaces to probe for DHCP discovery
        dhcp_timeout_s: Optional override for DHCP discovery timeout
        protocols: List of protocols to use (dhcp, netbios, mdns, upnp, arp, fping)
                   If None, uses all available
        redteam: Enable Red Team techniques (slower, noisier)
        exclude_ips: Optional set of IPs to skip for Red Team enumeration
        extra_tools: Override tool paths
        logger: Logger instance

    Returns:
        Complete net_discovery result object for JSON report
    """
    if protocols is None:
        protocols = ["dhcp", "fping", "netbios", "mdns", "upnp", "arp", "hyperscan", "routing"]

    protocols_norm = [p.strip().lower() for p in protocols if isinstance(p, str) and p.strip()]
    step_total = len(protocols_norm)

    def _progress(label: str, step_index: int) -> None:
        if not progress_callback:
            return
        try:
            progress_callback(str(label)[:200], int(step_index), int(step_total))
        except Exception:
            # Best-effort UX only; never fail discovery due to UI callback.
            return

    tools = _check_tools()
    errors: List[str] = []

    result: Dict[str, Any] = {
        "enabled": True,
        "generated_at": datetime.now().isoformat(),
        "protocols_used": protocols_norm,
        "redteam_enabled": redteam,
        "tools": tools,
        "dhcp_servers": [],
        "alive_hosts": [],
        "netbios_hosts": [],
        "arp_hosts": [],
        "mdns_services": [],
        "upnp_devices": [],
        "routing_networks": [],
        "routing_gateways": [],
        "candidate_vlans": [],
        "errors": errors,
    }

    # v4.6.32: Parallel execution of discovery protocols

    # Shared counter for monotonic progress updates
    _progress_lock = threading.Lock()
    _started_tasks = 0

    # Define a worker function to run one protocol and return its result key/value
    def _run_protocol(proto: str) -> Tuple[str, Dict[str, Any], List[str]]:
        nonlocal _started_tasks
        local_errors: List[str] = []
        local_res: Dict[str, Any] = {}

        # Monotonic progress update
        with _progress_lock:
            _started_tasks += 1
            current_idx = _started_tasks

        try:
            # v4.6.33: Added debug logging to identify slow protocols
            if logger:
                logger.debug(f"NetDiscovery: Starting {proto} on task #{current_idx}")

            if proto == "dhcp":
                _progress("DHCP discovery", current_idx)
                timeout_val = dhcp_timeout_s if dhcp_timeout_s is not None else 10
                targets = []
                if dhcp_interfaces:
                    targets = list(dhcp_interfaces)
                elif interface:
                    targets = [interface]
                else:
                    targets = [None]

                dhcp_servers: List[Dict[str, Any]] = []
                for dhcp_iface in targets:
                    dhcp_res = dhcp_discover(
                        interface=dhcp_iface, timeout_s=timeout_val, logger=logger
                    )
                    dhcp_servers.extend(dhcp_res.get("servers", []) or [])
                    if dhcp_res.get("error"):
                        local_errors.append(f"dhcp: {dhcp_res['error']}")

                local_res["dhcp_servers"] = dhcp_servers

            elif proto == "routing":
                _progress("Routing analysis", current_idx)
                # Routing analysis doesn't need target networks, it inspects system state
                route_res = detect_routed_networks(logger=logger)
                local_res["routing_networks"] = route_res.get("networks", [])
                local_res["routing_gateways"] = route_res.get("gateways", [])
                if route_res.get("error"):
                    local_errors.append(f"routing: {route_res['error']}")

            elif proto == "fping":
                _progress("ICMP sweep (fping)", current_idx)
                all_alive = []
                for idx, target in enumerate(target_networks, start=1):
                    fp_res = fping_sweep(target, logger=logger)
                    all_alive.extend(fp_res.get("alive_hosts", []))
                    if fp_res.get("error"):
                        local_errors.append(f"fping ({target}): {fp_res['error']}")
                local_res["alive_hosts"] = list(set(all_alive))

            elif proto == "netbios":
                _progress("NetBIOS discovery", current_idx)
                all_nb = []
                for idx, target in enumerate(target_networks, start=1):
                    nb_res = netbios_discover(target, logger=logger)
                    all_nb.extend(nb_res.get("hosts", []))
                    if nb_res.get("error"):
                        local_errors.append(f"netbios ({target}): {nb_res['error']}")
                local_res["netbios_hosts"] = all_nb

            elif proto == "arp":
                _progress("ARP discovery", current_idx)
                all_arp_h = []
                # Use a local seen set, will be merged later
                seen_ips_local = set()

                if tools.get("arp-scan") or shutil.which("arp-scan"):
                    tot_l2_warn = 0
                    for idx, target in enumerate(target_networks, start=1):
                        arp_res = arp_scan_active(target=target, interface=interface, logger=logger)
                        for h in arp_res.get("hosts", []):
                            ip = h.get("ip")
                            if ip and ip not in seen_ips_local:
                                seen_ips_local.add(ip)
                                all_arp_h.append(h)
                        if arp_res.get("error"):
                            local_errors.append(f"arp-scan ({target}): {arp_res['error']}")
                        tot_l2_warn += arp_res.get("l2_warnings", 0)

                    # Store L2 warning separately to avoid UI races (will print in main thread)
                    if tot_l2_warn > 0:
                        local_res["_l2_warning_count"] = tot_l2_warn

                for idx, target in enumerate(target_networks, start=1):
                    nd_res = netdiscover_scan(
                        target, active=True, interface=interface, logger=logger
                    )
                    for h in nd_res.get("hosts", []):
                        ip = h.get("ip")
                        if ip and ip not in seen_ips_local:
                            seen_ips_local.add(ip)
                            all_arp_h.append(h)
                    if nd_res.get("error"):
                        local_errors.append(f"netdiscover ({target}): {nd_res['error']}")

                local_res["arp_hosts"] = all_arp_h

            elif proto == "mdns":
                _progress("mDNS discovery", current_idx)
                md_res = mdns_discover(logger=logger)
                local_res["mdns_services"] = md_res.get("services", [])
                if md_res.get("error"):
                    local_errors.append(f"mdns: {md_res['error']}")

            elif proto == "upnp":
                _progress("UPnP discovery", current_idx)
                up_res = upnp_discover(logger=logger)
                local_res["upnp_devices"] = up_res.get("devices", [])
                if up_res.get("error"):
                    local_errors.append(f"upnp: {up_res['error']}")

            # Additional protocols (hyperscan/redteam) could be added here

            if logger:
                logger.debug(f"NetDiscovery: Finished {proto} on task #{current_idx}")

        except Exception as e:
            if logger:
                logger.error(f"Protocol {proto} failed: {e}", exc_info=True)
            local_errors.append(f"{proto}: {e}")

        return proto, local_res, local_errors

    # Execute all enabled protocols in parallel
    # Max workers = number of protocols (usually ~6-8)
    max_workers = len(protocols_norm)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_protocol, p): p
            for p in protocols_norm
            if p not in ["hyperscan"]  # Hyperscan is handled separately
        }

        for future in as_completed(futures):
            p_name = futures[future]
            try:
                _, p_res, p_errs = future.result()

                # Merge results into main result dict
                for k, v in p_res.items():
                    if k == "_l2_warning_count":
                        # Pass warning to caller via result dict; do NOT print here to avoid UI overlap
                        warn_count = v
                        if warn_count > 0:
                            if logger:
                                logger.warning(
                                    "ARP Discovery: %d hosts outside local L2 segment.", warn_count
                                )
                            result["l2_warning_note"] = (
                                f"{warn_count} hosts detected outside your local network."
                            )
                        continue

                    if k in result:
                        # Append or replace? Lists are empty initially, so direct assignment or extend is fine.
                        # For safety, we extend lists, replace others.
                        if isinstance(result[k], list) and isinstance(v, list):
                            # Special case: don't double-add if multiple protocols returned same key (unlikely here)
                            result[k].extend(v)
                        else:
                            result[k] = v
                    else:
                        result[k] = v

                if p_errs:
                    errors.extend(p_errs)

            except Exception as e:
                errors.append(f"{p_name} worker failed: {e}")
                if logger:
                    logger.error(f"Worker for {p_name} crashed: {e}", exc_info=True)

    # Handle hyperscan separately as it's a more complex, potentially longer-running step
    for step_index, protocol in enumerate(protocols_norm, start=1):
        if protocol == "hyperscan":
            _progress("HyperScan (parallel discovery)", step_index)
            try:
                from redaudit.core.hyperscan import hyperscan_full_discovery

                if logger:
                    logger.info("Running HyperScan parallel discovery...")

                last_pct = -1
                last_desc = ""
                last_t = 0.0

                def _hs_progress(completed: int, total: int, desc: str) -> None:
                    try:
                        pct = int((completed / total) * 100) if total else 0
                        nonlocal last_pct, last_desc, last_t
                        now = time.monotonic()
                        desc_norm = str(desc or "")[:120]

                        # v3.8.0: Reduced throttling for smoother progress (1% instead of 3%)
                        # Avoid flooding Rich with redraw updates (can cause flicker). Only update
                        # when progress changes meaningfully, the stage label changes, or enough
                        # time has elapsed.
                        should_update = False
                        if pct == 100 and completed >= total:
                            should_update = True
                        elif desc_norm and desc_norm != last_desc:
                            should_update = True
                        elif pct >= 0 and pct != last_pct and (pct - last_pct) >= 1:
                            should_update = True
                        elif now - last_t >= 0.25:
                            should_update = True

                        if should_update:
                            _progress(f"HyperScan: {desc_norm} ({pct}%)", step_index)
                            last_pct = pct
                            last_desc = desc_norm
                            last_t = now
                    except Exception:
                        return

                hyperscan_result = hyperscan_full_discovery(
                    target_networks,
                    logger=logger,
                    progress_callback=_hs_progress,
                )

                existing_ips = {h.get("ip") for h in result.get("arp_hosts", [])}
                for host in hyperscan_result.get("arp_hosts", []):
                    if host.get("ip") not in existing_ips:
                        result["arp_hosts"].append(host)
                        existing_ips.add(host.get("ip"))

                # Process UDP devices (IoT)
                udp_ports_map: Dict[str, List[int]] = {}
                for device in hyperscan_result.get("udp_devices", []):
                    ip = device.get("ip")
                    port = device.get("port")
                    # Add to upnp_devices for Context
                    result["upnp_devices"].append(
                        {
                            "ip": ip,
                            "device": f"IoT ({device.get('protocol', 'unknown')})",
                            "source": "hyperscan_udp",
                        }
                    )
                    # Track UDP ports
                    if ip and port:

                        if ip not in udp_ports_map:
                            udp_ports_map[ip] = []
                        if port not in udp_ports_map[ip]:
                            udp_ports_map[ip].append(port)

                    # Ensure host exists in main list
                    if ip and ip not in existing_ips:
                        result["arp_hosts"].append(
                            {
                                "ip": ip,
                                "mac": "",  # Unknown yet
                                "vendor": f"IoT ({device.get('protocol', 'unknown')})",
                            }
                        )
                        existing_ips.add(ip)

                if udp_ports_map:
                    result["hyperscan_udp_ports"] = udp_ports_map

                if hyperscan_result.get("tcp_hosts"):
                    result["hyperscan_tcp_hosts"] = hyperscan_result["tcp_hosts"]

                if hyperscan_result.get("potential_backdoors"):
                    result["potential_backdoors"] = hyperscan_result["potential_backdoors"]

                result["hyperscan_duration"] = hyperscan_result.get("duration_seconds", 0)

                if logger:
                    arp_count = len(hyperscan_result.get("arp_hosts", []))
                    udp_count = len(hyperscan_result.get("udp_devices", []))
                    tcp_count = len(hyperscan_result.get("tcp_hosts", {}))
                    duration = hyperscan_result.get("duration_seconds", 0)
                    logger.info(
                        "HyperScan complete: %s ARP, %s UDP, %s TCP hosts in %.1fs",
                        arp_count,
                        udp_count,
                        tcp_count,
                        float(duration),
                    )

            except ImportError as exc:
                errors.append(f"hyperscan: module not available ({exc})")
            except Exception as exc:
                errors.append(f"hyperscan: {exc}")

    _progress("Finalizing discovery", step_total)

    # Analyze for candidate VLANs
    result["candidate_vlans"] = _analyze_vlans(result)

    # Red Team techniques (optional)
    if redteam:
        _progress("Red Team discovery", step_total)
        run_redteam_discovery(
            result,
            target_networks,
            interface=interface,
            redteam_options=redteam_options,
            exclude_ips=exclude_ips,
            tools=result.get("tools"),
            logger=logger,
            progress_callback=progress_callback,
            progress_step=step_total,
            progress_total=step_total,
        )
        _progress("Red Team discovery complete", step_total)

    _progress("Discovery complete", step_total)

    return result


def _analyze_vlans(discovery_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze discovery results to identify potential VLANs/guest networks.
    """
    candidates = []

    # If multiple DHCP servers found with different subnets, likely different VLANs
    dhcp_servers = discovery_result.get("dhcp_servers", [])
    seen_subnets = set()

    for server in dhcp_servers:
        subnet = server.get("subnet")
        gateway = server.get("gateway")
        if subnet and gateway:
            network_key = f"{gateway}/{subnet}"
            if network_key not in seen_subnets:
                seen_subnets.add(network_key)
                if len(seen_subnets) > 1:
                    candidates.append(
                        {
                            "source": "dhcp_server",
                            "gateway": gateway,
                            "subnet": subnet,
                            "description": "Additional DHCP server detected (possible guest/VLAN)",
                        }
                    )

    return candidates
