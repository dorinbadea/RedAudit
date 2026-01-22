"""
RedAudit - Red Team Discovery Module

Extracted from net_discovery to keep red team enumeration isolated.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.core.rustscan import is_rustscan_available, run_rustscan_multi
from redaudit.utils.dry_run import is_dry_run

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


def run_redteam_discovery(
    result: Dict[str, Any],
    target_networks: List[str],
    interface: Optional[str] = None,
    redteam_options: Optional[Dict[str, Any]] = None,
    tools: Optional[Dict[str, bool]] = None,
    logger=None,
    progress_callback: Optional[ProgressCallback] = None,
    progress_step: Optional[int] = None,
    progress_total: Optional[int] = None,
) -> None:
    """
    Run optional Red Team discovery techniques.
    Modifies result in place.
    """
    tools = tools if isinstance(tools, dict) else result.get("tools") or {}

    options = redteam_options if isinstance(redteam_options, dict) else {}

    max_targets = options.get("max_targets", 50)
    if not isinstance(max_targets, int) or max_targets < 1 or max_targets > 500:
        max_targets = 50

    def _progress_redteam(label: str) -> None:
        if not progress_callback:
            return
        step_idx = int(progress_step or 1)
        step_total = int(progress_total or step_idx or 1)
        try:
            progress_callback(f"Red Team: {label}", step_idx, step_total)
        except Exception:
            return

    def _run_step(label: str, func):
        start = time.monotonic()
        stop_event = threading.Event()
        ticker = None

        if progress_callback:

            def _tick():
                while not stop_event.wait(3.0):
                    elapsed = int(time.monotonic() - start)
                    _progress_redteam(f"{label} ({elapsed}s)")

            ticker = threading.Thread(target=_tick, daemon=True)
            ticker.start()

        try:
            _progress_redteam(label)
            return func()
        finally:
            stop_event.set()
            if ticker:
                try:
                    ticker.join(timeout=0.5)
                except Exception:
                    pass
            _progress_redteam(f"{label} done")

    iface = _sanitize_iface(interface)

    snmp_community = options.get("snmp_community", "public")
    if not isinstance(snmp_community, str) or not snmp_community.strip():
        snmp_community = "public"
    snmp_community = snmp_community.strip()[:64]

    dns_zone = _sanitize_dns_zone(options.get("dns_zone"))
    kerberos_realm = _sanitize_dns_zone(options.get("kerberos_realm"))
    kerberos_userlist = options.get("kerberos_userlist")
    if not isinstance(kerberos_userlist, str) or not kerberos_userlist.strip():
        kerberos_userlist = None

    active_l2 = bool(options.get("active_l2", False))

    target_ips = _gather_redteam_targets(result, max_targets=max_targets)

    rustscan_res = {}
    if options.get("use_masscan", True):
        rustscan_res = _run_step(
            "rustscan sweep",
            lambda: _redteam_rustscan_sweep(target_networks, tools=tools, logger=logger),
        )
    open_tcp = _index_open_tcp_ports(rustscan_res)

    smb_targets = _filter_targets_by_port(target_ips, open_tcp, port=445, fallback_max=15)
    rpc_targets = _filter_targets_by_any_port(
        target_ips, open_tcp, ports=[445, 135], fallback_max=15
    )
    ldap_targets = _filter_targets_by_any_port(
        target_ips, open_tcp, ports=[389, 636], fallback_max=10
    )
    kerberos_targets = _filter_targets_by_port(target_ips, open_tcp, port=88, fallback_max=10)

    snmp = _run_step(
        "SNMP walk",
        lambda: _redteam_snmp_walk(
            target_ips,
            tools=tools,
            community=snmp_community,
            logger=logger,
        ),
    )
    smb = _run_step("SMB enum", lambda: _redteam_smb_enum(smb_targets, tools=tools, logger=logger))
    rpc = _run_step("RPC enum", lambda: _redteam_rpc_enum(rpc_targets, tools=tools, logger=logger))
    ldap = _run_step(
        "LDAP enum", lambda: _redteam_ldap_enum(ldap_targets, tools=tools, logger=logger)
    )
    kerberos = _run_step(
        "Kerberos enum",
        lambda: _redteam_kerberos_enum(
            kerberos_targets,
            tools=tools,
            realm=kerberos_realm,
            userlist_path=kerberos_userlist,
            logger=logger,
        ),
    )
    dns_zone_transfer = _run_step(
        "DNS zone transfer",
        lambda: _redteam_dns_zone_transfer(
            result,
            tools=tools,
            zone=dns_zone,
            logger=logger,
        ),
    )
    vlan_enum = _run_step(
        "VLAN enum", lambda: _redteam_vlan_enum(iface, tools=tools, logger=logger)
    )
    stp_topology = _run_step(
        "STP topology", lambda: _redteam_stp_topology(iface, tools=tools, logger=logger)
    )
    hsrp_vrrp = _run_step(
        "HSRP/VRRP", lambda: _redteam_hsrp_vrrp_discovery(iface, tools=tools, logger=logger)
    )
    llmnr_nbtns = _run_step(
        "LLMNR/NBT-NS", lambda: _redteam_llmnr_nbtns_capture(iface, tools=tools, logger=logger)
    )
    router_discovery = _run_step(
        "Router discovery",
        lambda: _redteam_router_discovery(iface, tools=tools, logger=logger),
    )
    ipv6_discovery = _run_step(
        "IPv6 discovery",
        lambda: _redteam_ipv6_discovery(iface, tools=tools, logger=logger),
    )
    bettercap_recon = _run_step(
        "Bettercap recon",
        lambda: _redteam_bettercap_recon(iface, tools=tools, active_l2=active_l2, logger=logger),
    )
    scapy_custom = _run_step(
        "Scapy probes",
        lambda: _redteam_scapy_custom(
            iface,
            tools=tools,
            active_l2=active_l2,
            logger=logger,
        ),
    )

    redteam: Dict[str, Any] = {
        "enabled": True,
        "interface": iface,
        "targets_considered": len(target_ips),
        "targets_sample": target_ips[:10],
        "masscan": rustscan_res,  # Legacy key for schema compatibility
        "rustscan": rustscan_res,
        "snmp": snmp,
        "smb": smb,
        "rpc": rpc,
        "ldap": ldap,
        "kerberos": kerberos,
        "dns_zone_transfer": dns_zone_transfer,
        "vlan_enum": vlan_enum,
        "stp_topology": stp_topology,
        "hsrp_vrrp": hsrp_vrrp,
        "llmnr_nbtns": llmnr_nbtns,
        "router_discovery": router_discovery,
        "ipv6_discovery": ipv6_discovery,
        "bettercap_recon": bettercap_recon,
        "scapy_custom": scapy_custom,
    }
    result["redteam"] = redteam


def _is_ipv4(ip_str: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv4Address)
    except ValueError:
        return False


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _gather_redteam_targets(discovery_result: Dict[str, Any], max_targets: int = 50) -> List[str]:
    candidates: List[str] = []

    for ip_str in discovery_result.get("alive_hosts", []) or []:
        if isinstance(ip_str, str) and _is_ipv4(ip_str):
            candidates.append(ip_str)

    for host in discovery_result.get("arp_hosts", []) or []:
        if isinstance(host, dict):
            ip_str = host.get("ip")
            if isinstance(ip_str, str) and _is_ipv4(ip_str):
                candidates.append(ip_str)

    for host in discovery_result.get("netbios_hosts", []) or []:
        if isinstance(host, dict):
            ip_str = host.get("ip")
            if isinstance(ip_str, str) and _is_ipv4(ip_str):
                candidates.append(ip_str)

    for srv in discovery_result.get("dhcp_servers", []) or []:
        if isinstance(srv, dict):
            ip_str = srv.get("ip")
            if isinstance(ip_str, str) and _is_ipv4(ip_str):
                candidates.append(ip_str)

    return _dedupe_preserve_order(candidates)[:max_targets]


_IFACE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,31}$")


def _sanitize_iface(iface: Optional[str]) -> Optional[str]:
    if not isinstance(iface, str):
        return None
    iface = iface.strip()
    if not iface or not _IFACE_RE.match(iface):
        return None
    return iface


def _sanitize_dns_zone(zone: Any) -> Optional[str]:
    if not isinstance(zone, str):
        return None
    zone = zone.strip().strip(".")
    if not zone or len(zone) > 253:
        return None
    if ".." in zone:
        return None
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$", zone):
        return None
    return zone


def _index_open_tcp_ports(masscan_result: Dict[str, Any]) -> Dict[str, set[int]]:
    idx: Dict[str, set[int]] = {}
    for entry in (masscan_result or {}).get("open_ports", []) or []:
        if not isinstance(entry, dict):
            continue
        ip_str = entry.get("ip")
        port = entry.get("port")
        proto = (entry.get("protocol") or "").lower()
        if not isinstance(ip_str, str) or not _is_ipv4(ip_str):
            continue
        if not isinstance(port, int) or not (1 <= port <= 65535):
            continue
        if proto and proto != "tcp":
            continue
        idx.setdefault(ip_str, set()).add(port)
    return idx


def _filter_targets_by_port(
    target_ips: List[str],
    open_tcp: Dict[str, set[int]],
    port: int,
    fallback_max: int,
) -> List[str]:
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return target_ips[:fallback_max]
    filtered = [ip for ip in target_ips if port in open_tcp.get(ip, set())]
    return filtered[:fallback_max] if filtered else target_ips[:fallback_max]


def _filter_targets_by_any_port(
    target_ips: List[str],
    open_tcp: Dict[str, set[int]],
    ports: List[int],
    fallback_max: int,
) -> List[str]:
    safe_ports = [p for p in ports if isinstance(p, int) and (1 <= p <= 65535)]
    if not safe_ports:
        return target_ips[:fallback_max]
    filtered = [ip for ip in target_ips if any(p in open_tcp.get(ip, set()) for p in safe_ports)]
    return filtered[:fallback_max] if filtered else target_ips[:fallback_max]


_SNMP_OID_MAP = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.7.0": "sysServices",
}


def _parse_snmpwalk(output: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([.0-9]+)\s*(?:=\s*)?(.*)$", line)
        if not m:
            continue
        oid = m.group(1).lstrip(".")
        value = (m.group(2) or "").strip()
        value = re.sub(r"^[A-Z][A-Z0-9\-]*:\s*", "", value).strip()
        value = value.strip('"')
        key = _SNMP_OID_MAP.get(oid)
        if key and value:
            parsed[key] = value[:250]
    return parsed


def _redteam_snmp_walk(
    target_ips: List[str],
    tools: Dict[str, bool],
    community: str = "public",
    logger=None,
) -> Dict[str, Any]:
    if not target_ips:
        return {"status": "no_targets", "hosts": []}
    if not tools.get("snmpwalk") or not shutil.which("snmpwalk"):
        return {"status": "tool_missing", "tool": "snmpwalk", "hosts": []}

    results: List[Dict[str, Any]] = []

    # v4.6.34: Parallel execution
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    full_lock = threading.Lock()

    def _scan_snmp(ip_str: str) -> Optional[Dict[str, Any]]:
        # Keep it quick and read-only: 1s timeout, 0 retries, system group only.
        cmd = [
            "snmpwalk",
            "-v2c",
            "-c",
            community,
            "-t",
            "1",
            "-r",
            "0",
            "-On",
            ip_str,
            "1.3.6.1.2.1.1",
        ]
        rc, out, err = _run_cmd(cmd, timeout_s=4, logger=logger)
        text = out or ""
        if rc != 0 and not text.strip():
            # don't return errors for simple timeouts/unreachables to reduce noise
            # unless significant error
            if err.strip() and "timeout" not in err.lower():
                return {"ip": ip_str, "error": err.strip()[:100]}
            return None

        if "timeout" in (err or "").lower() or "timeout" in text.lower():
            return None

        parsed = _parse_snmpwalk(text)
        if parsed:
            return {"ip": ip_str, **parsed}
        else:
            # Keep a tiny sample for debugging (avoid bloating the report).
            snippet = (text.strip() or err.strip())[:400]
            if snippet:
                return {"ip": ip_str, "raw": snippet}
        return None

    targets = target_ips[:20]
    errors: List[str] = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_scan_snmp, ip): ip for ip in targets}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    if "error" in res:
                        with full_lock:
                            errors.append(f"{res['ip']}: {res['error']}")
                    else:
                        with full_lock:
                            results.append(res)
            except Exception:
                pass

    status = "ok" if results else "no_data"
    payload: Dict[str, Any] = {
        "status": status,
        "community": community,
        "hosts": results,
    }
    if errors:
        payload["errors"] = errors[:20]
    return payload


def _parse_smb_nmap(output: str) -> Dict[str, Any]:
    text = output or ""
    parsed: Dict[str, Any] = {}

    # smb-os-discovery patterns (best-effort)
    patterns = {
        "os": r"\bOS:\s*(.+)",
        "computer_name": r"\bComputer name:\s*(\S+)",
        "netbios_name": r"\bNetBIOS computer name:\s*(\S+)",
        "domain": r"\bDomain name:\s*(\S+)",
        "workgroup": r"\bWorkgroup:\s*(\S+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            parsed[key] = m.group(1).strip()[:200]

    shares: List[str] = []
    # Match "Sharename: ..." (legacy/other) OR "\\IP\Share:" (standard nmap)
    for m in re.finditer(r"\bSharename:\s*([^\s]+)", text, re.IGNORECASE):
        share = m.group(1).strip()
        if share and share not in shares:
            shares.append(share)

    # Standard nmap smb-enum-shares: |  \\1.2.3.4\IPC$:
    if not shares:
        for m in re.finditer(r"\\\\(?:\d{1,3}(?:\.\d{1,3}){3}|[^\\]+)\\([^\s:]+):", text):
            share = m.group(1).strip()
            if share and share not in shares:
                shares.append(share)

    if shares:
        parsed["shares"] = shares[:20]

    return parsed


def _redteam_smb_enum(
    target_ips: List[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    if not target_ips:
        return {"status": "no_targets", "hosts": []}

    has_enum4linux = tools.get("enum4linux") and shutil.which("enum4linux")
    has_nmap = tools.get("nmap") and shutil.which("nmap")

    if not has_enum4linux and not has_nmap:
        return {"status": "tool_missing", "tool": "enum4linux/nmap", "hosts": []}

    tool = "enum4linux" if has_enum4linux else "nmap"
    results: List[Dict[str, Any]] = []

    # v4.6.34: Parallel execution to avoid 5+ minute serial blocking
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    full_lock = threading.Lock()

    def _scan_smb(ip_str: str) -> Optional[Dict[str, Any]]:
        if tool == "enum4linux":
            cmd = ["enum4linux", "-a", ip_str]
            rc, out, err = _run_cmd(cmd, timeout_s=25, logger=logger)
            text = (out or "") + "\n" + (err or "")
            snippet = text.strip()[:1200]
            if not snippet:
                return None
            return {"ip": ip_str, "tool": "enum4linux", "raw": snippet}
        else:
            cmd = [
                "nmap",
                "-p",
                "445",
                "--script",
                "smb-os-discovery,smb-enum-shares,smb-enum-users",
                ip_str,
            ]
            rc, out, err = _run_cmd(cmd, timeout_s=25, logger=logger)
            text = (out or "") + "\n" + (err or "")
            parsed = _parse_smb_nmap(text)
            if parsed:
                return {"ip": ip_str, "tool": "nmap", **parsed}
            else:
                snippet = text.strip()[:800]
                if snippet:
                    return {"ip": ip_str, "tool": "nmap", "raw": snippet}
        return None

    targets = target_ips[:15]
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_scan_smb, ip): ip for ip in targets}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    with full_lock:
                        results.append(res)
            except Exception:
                pass

    return {"status": "ok" if results else "no_data", "tool": tool, "hosts": results}


def _is_root() -> bool:
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def _redteam_rustscan_sweep(
    target_networks: List[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    """
    Optional fast port discovery using RustScan.

    Replaces legacy Masscan sweep.
    """
    if not target_networks:
        return {"status": "no_targets"}
    if not tools.get("rustscan") and not is_rustscan_available():
        return {"status": "tool_missing", "tool": "rustscan"}

    # Red Team specific ports
    ports_to_scan = [53, 88, 135, 389, 445, 636, 161]

    # Start scan
    found_map, error = run_rustscan_multi(
        target_networks,  # run_rustscan_multi handles list
        ports=ports_to_scan,
        ulimit=5000,
        timeout=30.0,
        logger=logger,
    )

    if error:
        return {"status": "error", "error": str(error)[:200]}

    # Flatten map to list of dicts for reporting
    open_ports = []
    for ip_addr, ports in found_map.items():
        for p in ports:
            open_ports.append(
                {"ip": ip_addr, "port": p, "protocol": "tcp"}  # RustScan is TCP only roughly
            )

    return {
        "status": "ok" if open_ports else "no_data",
        "ports_scanned": ports_to_scan,
        "ports_scanned_spec": ",".join(str(p) for p in ports_to_scan),
        "open_ports": open_ports,
    }


def _safe_truncate(text: str, limit: int) -> str:
    if not isinstance(text, str):
        return ""
    if limit <= 0:
        return ""
    return text if len(text) <= limit else text[:limit]


def _tcpdump_capture(
    iface: str,
    bpf_expr: str,
    tools: Dict[str, bool],
    timeout_s: int,
    packets: int = 50,
    logger=None,
) -> Dict[str, Any]:
    if not iface:
        return {"status": "skipped_no_interface"}
    if not tools.get("tcpdump") or not shutil.which("tcpdump"):
        return {"status": "tool_missing", "tool": "tcpdump"}
    if not _is_root():
        return {"status": "skipped_requires_root"}

    if not isinstance(packets, int) or packets < 1:
        packets = 50
    if packets > 200:
        packets = 200

    cmd = ["tcpdump", "-i", iface, "-n", "-e", "-vv", "-c", str(packets)]
    if isinstance(bpf_expr, str) and bpf_expr.strip():
        cmd.append(bpf_expr.strip())

    rc, out, err = _run_cmd(cmd, timeout_s=timeout_s, logger=logger)
    text = (out or "") + "\n" + (err or "")
    snippet = text.strip()

    payload: Dict[str, Any] = {
        "status": "ok" if snippet else "no_data",
        "returncode": rc,
    }
    if snippet:
        payload["raw_sample"] = _safe_truncate(snippet, 1600)
    if rc != 0 and err.strip():
        payload["error"] = _safe_truncate(err.strip(), 300)
    return payload


def _redteam_rpc_enum(
    target_ips: List[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    if not target_ips:
        return {"status": "no_targets", "hosts": []}

    has_rpcclient = tools.get("rpcclient") and shutil.which("rpcclient")
    has_nmap = tools.get("nmap") and shutil.which("nmap")
    if not has_rpcclient and not has_nmap:
        return {"status": "tool_missing", "tool": "rpcclient/nmap", "hosts": []}

    tool = "rpcclient" if has_rpcclient else "nmap"
    results: List[Dict[str, Any]] = []

    # v4.6.34: Parallel execution to avoid timeouts on large networks
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    full_lock = threading.Lock()

    def _scan_host(ip_str: str) -> Optional[Dict[str, Any]]:
        if tool == "rpcclient":
            cmd = ["rpcclient", "-U", "", "-N", ip_str, "-c", "srvinfo"]
            rc, out, err = _run_cmd(cmd, timeout_s=12, logger=logger)
            text = (out or "") + "\n" + (err or "")
            snippet = text.strip()
            if not snippet:
                return None

            parsed: Dict[str, Any] = {}
            patterns = {
                "os_version": r"(?i)^\s*os version\s*:\s*(.+)$",
                "server_type": r"(?i)^\s*server type\s*:\s*(.+)$",
                "comment": r"(?i)^\s*comment\s*:\s*(.+)$",
                "domain": r"(?i)^\s*domain\s*:\s*(.+)$",
            }
            for key, pat in patterns.items():
                m = re.search(pat, snippet, re.MULTILINE)
                if m:
                    parsed[key] = m.group(1).strip()[:200]

            if parsed:
                return {"ip": ip_str, "tool": "rpcclient", **parsed}
            else:
                return {"ip": ip_str, "tool": "rpcclient", "raw": _safe_truncate(snippet, 1200)}
        else:
            cmd = ["nmap", "-p", "135", "--script", "msrpc-enum", ip_str]
            rc, out, err = _run_cmd(cmd, timeout_s=20, logger=logger)
            text = (out or "") + "\n" + (err or "")
            snippet = text.strip()
            if snippet:
                return {"ip": ip_str, "tool": "nmap", "raw": _safe_truncate(snippet, 1200)}
        return None

    # Limit targets to 20 to avoid excessive noise, parallelize 8 threads
    targets = target_ips[:20]
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_scan_host, ip): ip for ip in targets}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    with full_lock:
                        results.append(res)
            except Exception:
                pass

    return {"status": "ok" if results else "no_data", "tool": tool, "hosts": results}


def _parse_ldap_rootdse(text: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    naming_contexts: List[str] = []
    sasl: List[str] = []
    versions: List[str] = []

    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if not key or not val:
            continue

        if key in (
            "defaultNamingContext",
            "rootDomainNamingContext",
            "dnsHostName",
            "ldapServiceName",
        ):
            parsed[key] = val[:250]
        elif key == "namingContexts":
            naming_contexts.append(val[:250])
        elif key == "supportedLDAPVersion":
            versions.append(val[:50])
        elif key == "supportedSASLMechanisms":
            sasl.append(val[:100])

    if naming_contexts:
        parsed["namingContexts"] = naming_contexts[:20]
    if versions:
        parsed["supportedLDAPVersion"] = versions[:10]
    if sasl:
        parsed["supportedSASLMechanisms"] = sasl[:20]

    return parsed


def _redteam_ldap_enum(
    target_ips: List[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    if not target_ips:
        return {"status": "no_targets", "hosts": []}

    has_ldapsearch = tools.get("ldapsearch") and shutil.which("ldapsearch")
    has_nmap = tools.get("nmap") and shutil.which("nmap")
    if not has_ldapsearch and not has_nmap:
        return {"status": "tool_missing", "tool": "ldapsearch/nmap", "hosts": []}

    tool = "ldapsearch" if has_ldapsearch else "nmap"
    results: List[Dict[str, Any]] = []

    # v4.6.34: Parallel execution to avoid serial blocking
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    full_lock = threading.Lock()

    def _scan_ldap(ip_str: str) -> Optional[Dict[str, Any]]:
        if tool == "ldapsearch":
            attrs = [
                "defaultNamingContext",
                "rootDomainNamingContext",
                "namingContexts",
                "dnsHostName",
                "ldapServiceName",
                "supportedLDAPVersion",
                "supportedSASLMechanisms",
            ]
            cmd = [
                "ldapsearch",
                "-x",
                "-LLL",
                "-H",
                f"ldap://{ip_str}",
                "-s",
                "base",
                "-b",
                "",
                "(objectClass=*)",
            ] + attrs
            rc, out, err = _run_cmd(cmd, timeout_s=12, logger=logger)
            text = (out or "") + "\n" + (err or "")
            parsed = _parse_ldap_rootdse(text)
            if parsed:
                return {"ip": ip_str, "tool": "ldapsearch", **parsed}
            else:
                snippet = text.strip()
                if snippet:
                    return {
                        "ip": ip_str,
                        "tool": "ldapsearch",
                        "raw": _safe_truncate(snippet, 1200),
                    }
        else:
            cmd = ["nmap", "-p", "389,636", "--script", "ldap-rootdse", ip_str]
            rc, out, err = _run_cmd(cmd, timeout_s=18, logger=logger)
            text = (out or "") + "\n" + (err or "")
            parsed = _parse_ldap_rootdse(text)
            if parsed:
                return {"ip": ip_str, "tool": "nmap", **parsed}
            else:
                snippet = text.strip()
                if snippet:
                    return {"ip": ip_str, "tool": "nmap", "raw": _safe_truncate(snippet, 1200)}
        return None

    targets = target_ips[:15]
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_scan_ldap, ip): ip for ip in targets}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    with full_lock:
                        results.append(res)
            except Exception:
                pass

    return {"status": "ok" if results else "no_data", "tool": tool, "hosts": results}


def _parse_nmap_krb5_info(text: str) -> List[str]:
    realms: List[str] = []
    for line in (text or "").splitlines():
        m = re.search(r"(?i)\brealm:\s*([A-Za-z0-9.-]+)", line)
        if not m:
            continue
        realm = m.group(1).strip().strip(".")
        if realm and realm not in realms:
            realms.append(realm[:200])
    return realms


def _redteam_kerberos_enum(
    target_ips: List[str],
    tools: Dict[str, bool],
    realm: Optional[str] = None,
    userlist_path: Optional[str] = None,
    logger=None,
) -> Dict[str, Any]:
    if not target_ips:
        return {"status": "no_targets", "hosts": []}

    has_nmap = tools.get("nmap") and shutil.which("nmap")
    has_kerbrute = tools.get("kerbrute") and shutil.which("kerbrute")
    if not has_nmap and not has_kerbrute:
        return {"status": "tool_missing", "tool": "nmap/kerbrute", "hosts": []}

    results: List[Dict[str, Any]] = []
    detected_realms: List[str] = []

    if has_nmap:
        for ip_str in target_ips[:10]:
            cmd = ["nmap", "-p", "88", "--script", "krb5-info", ip_str]
            rc, out, err = _run_cmd(cmd, timeout_s=18, logger=logger)
            text = (out or "") + "\n" + (err or "")
            realms = _parse_nmap_krb5_info(text)
            if realms:
                for r in realms:
                    if r not in detected_realms:
                        detected_realms.append(r)
                results.append({"ip": ip_str, "tool": "nmap", "realms": realms[:10]})
            else:
                snippet = text.strip()
                if snippet:
                    results.append(
                        {"ip": ip_str, "tool": "nmap", "raw": _safe_truncate(snippet, 800)}
                    )

    userenum: Dict[str, Any] = {"status": "skipped_no_userlist"}
    if userlist_path:
        if not has_kerbrute:
            userenum = {"status": "tool_missing", "tool": "kerbrute"}
        elif not os.path.exists(userlist_path):
            userenum = {"status": "error", "error": "kerberos_userlist not found"}
        else:
            used_realm = realm or (detected_realms[0] if detected_realms else None)
            if not used_realm:
                userenum = {"status": "skipped_no_realm"}
            else:
                dc_ip = target_ips[0]
                cmd = ["kerbrute", "userenum", "-d", used_realm, "--dc", dc_ip, userlist_path]
                rc, out, err = _run_cmd(cmd, timeout_s=25, logger=logger)
                text = (out or "") + "\n" + (err or "")
                valid_users: List[str] = []
                for line in text.splitlines():
                    if "VALID USERNAME" not in line.upper():
                        continue
                    m = re.search(r"(?i)valid username:\s*([^\s@]+)@", line)
                    if m:
                        u = m.group(1).strip()
                        if u and u not in valid_users:
                            valid_users.append(u[:120])
                    if len(valid_users) >= 50:
                        break
                userenum = {
                    "status": "ok" if valid_users else "no_data",
                    "tool": "kerbrute",
                    "realm": used_realm,
                    "dc": dc_ip,
                    "valid_users_sample": valid_users[:50],
                }
                if rc != 0 and err.strip():
                    userenum["error"] = _safe_truncate(err.strip(), 200)

    payload: Dict[str, Any] = {
        "status": (
            "ok" if results else ("no_data" if has_nmap else userenum.get("status", "no_data"))
        ),
        "detected_realms": detected_realms[:10],
        "hosts": results,
        "userenum": userenum,
    }
    if realm:
        payload["realm_hint"] = realm
    return payload


def _extract_dhcp_dns_servers(discovery_result: Dict[str, Any]) -> List[str]:
    servers: List[str] = []
    for dhcp in discovery_result.get("dhcp_servers", []) or []:
        if not isinstance(dhcp, dict):
            continue
        for ip_str in dhcp.get("dns", []) or []:
            if isinstance(ip_str, str) and _is_ipv4(ip_str) and ip_str not in servers:
                servers.append(ip_str)
    return servers


def _extract_dhcp_domains(discovery_result: Dict[str, Any]) -> List[str]:
    domains: List[str] = []
    for dhcp in discovery_result.get("dhcp_servers", []) or []:
        if not isinstance(dhcp, dict):
            continue
        for key in ("domain", "domain_search"):
            val = dhcp.get(key)
            if isinstance(val, str) and val.strip():
                dom = _sanitize_dns_zone(val.strip())
                if dom and dom not in domains:
                    domains.append(dom)
    return domains


def _redteam_dns_zone_transfer(
    discovery_result: Dict[str, Any],
    tools: Dict[str, bool],
    zone: Optional[str] = None,
    logger=None,
) -> Dict[str, Any]:
    if not tools.get("dig") or not shutil.which("dig"):
        return {"status": "tool_missing", "tool": "dig"}

    dns_servers = _extract_dhcp_dns_servers(discovery_result)
    if not dns_servers:
        return {"status": "no_targets", "reason": "no_dns_servers"}

    zone_hint = _sanitize_dns_zone(zone) if zone else None
    if not zone_hint:
        domains = _extract_dhcp_domains(discovery_result)
        zone_hint = domains[0] if domains else None

    if not zone_hint:
        return {"status": "skipped_no_zone", "dns_servers": dns_servers[:5]}

    attempts: List[Dict[str, Any]] = []
    errors: List[str] = []
    for dns_ip in dns_servers[:3]:
        cmd = ["dig", "+time=2", "+tries=1", "axfr", zone_hint, f"@{dns_ip}"]
        rc, out, err = _run_cmd(cmd, timeout_s=12, logger=logger)
        text = (out or "") + "\n" + (err or "")
        lines = []
        for line in (out or "").splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            lines.append(line[:300])
            if len(lines) >= 50:
                break

        success = bool(re.search(r"\bXFR size:\s*\d+", out or "", re.IGNORECASE))
        if not success and "transfer failed" in (text or "").lower():
            errors.append(f"{dns_ip}: transfer failed")
        attempts.append(
            {
                "dns_server": dns_ip,
                "success": success,
                "records_sample": lines,
                "raw_sample": _safe_truncate(text.strip(), 900) if not success else None,
            }
        )

    status = "ok" if any(a.get("success") for a in attempts) else "no_data"
    payload: Dict[str, Any] = {
        "status": status,
        "zone": zone_hint,
        "dns_servers": dns_servers[:5],
        "attempts": attempts,
    }
    if errors:
        payload["errors"] = errors[:10]
    return payload


def _redteam_vlan_enum(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    cap = _tcpdump_capture(
        safe_iface or "",
        "vlan or ether proto 0x8100 or ether dst 01:00:0c:cc:cc:cc",
        tools=tools,
        timeout_s=8,
        packets=60,
        logger=logger,
    )
    if cap.get("status") != "ok":
        return cap

    raw = cap.get("raw_sample", "") or ""
    vlan_ids: List[int] = []
    for m in re.finditer(r"\bvlan\s+(\d{1,4})\b", raw, re.IGNORECASE):
        try:
            vid = int(m.group(1))
        except Exception:
            continue
        if 1 <= vid <= 4094 and vid not in vlan_ids:
            vlan_ids.append(vid)
    dtp_observed = bool(re.search(r"(?i)\bDTP\b|01:00:0c:cc:cc:cc", raw))

    payload: Dict[str, Any] = {
        "status": "ok" if vlan_ids or dtp_observed else "no_data",
        "vlan_ids": vlan_ids[:50],
        "dtp_observed": dtp_observed,
    }
    if cap.get("raw_sample"):
        payload["raw_sample"] = cap["raw_sample"]
    if cap.get("error"):
        payload["error"] = cap["error"]
    return payload


def _redteam_stp_topology(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    cap = _tcpdump_capture(
        safe_iface or "",
        "ether dst 01:80:c2:00:00:00",
        tools=tools,
        timeout_s=8,
        packets=40,
        logger=logger,
    )
    if cap.get("status") != "ok":
        return cap

    raw = cap.get("raw_sample", "") or ""
    root_ids: List[str] = []
    bridge_ids: List[str] = []

    for m in re.finditer(r"(?i)\broot id\s+([0-9a-f:.]+)", raw):
        val = m.group(1).strip()
        if val and val not in root_ids:
            root_ids.append(val[:200])
    for m in re.finditer(r"(?i)\bbridge id\s+([0-9a-f:.]+)", raw):
        val = m.group(1).strip()
        if val and val not in bridge_ids:
            bridge_ids.append(val[:200])

    payload: Dict[str, Any] = {
        "status": "ok" if (root_ids or bridge_ids) else "no_data",
        "root_ids": root_ids[:10],
        "bridge_ids": bridge_ids[:10],
        "raw_sample": cap.get("raw_sample"),
    }
    if cap.get("error"):
        payload["error"] = cap["error"]
    return payload


def _redteam_hsrp_vrrp_discovery(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    cap = _tcpdump_capture(
        safe_iface or "",
        "udp port 1985 or udp port 2029 or ip proto 112",
        tools=tools,
        timeout_s=8,
        packets=60,
        logger=logger,
    )
    if cap.get("status") != "ok":
        return cap

    raw = cap.get("raw_sample", "") or ""
    protocols: List[str] = []
    if re.search(r"(?i)\bHSRP\b", raw):
        protocols.append("hsrp")
    if re.search(r"(?i)\bVRRP\b|ip proto 112", raw):
        protocols.append("vrrp")

    src_ips: List[str] = []
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw):
        ip_str = m.group(1)
        if ip_str and ip_str not in src_ips:
            src_ips.append(ip_str)
        if len(src_ips) >= 20:
            break

    payload: Dict[str, Any] = {
        "status": "ok" if protocols else "no_data",
        "protocols_observed": protocols,
        "ip_candidates": src_ips[:20],
        "raw_sample": cap.get("raw_sample"),
    }
    if cap.get("error"):
        payload["error"] = cap["error"]
    return payload


def _redteam_llmnr_nbtns_capture(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    cap = _tcpdump_capture(
        safe_iface or "",
        "udp port 5355 or udp port 137",
        tools=tools,
        timeout_s=10,
        packets=80,
        logger=logger,
    )
    if cap.get("status") != "ok":
        return cap

    raw = cap.get("raw_sample", "") or ""
    llmnr: List[str] = []
    nbns: List[str] = []

    for line in raw.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if ".5355" in line_stripped or " 5355" in line_stripped:
            m = re.search(r"\?\s*([A-Za-z0-9._-]+)", line_stripped)
            if m:
                q = m.group(1).strip()
                if q and q not in llmnr:
                    llmnr.append(q[:200])
        if ".137" in line_stripped or " 137" in line_stripped:
            m = re.search(r"\?\s*([A-Za-z0-9._-]+)", line_stripped)
            if m:
                q = m.group(1).strip()
                if q and q not in nbns:
                    nbns.append(q[:200])

    payload: Dict[str, Any] = {
        "status": "ok" if (llmnr or nbns) else "no_data",
        "llmnr_queries_sample": llmnr[:30],
        "nbns_queries_sample": nbns[:30],
        "raw_sample": cap.get("raw_sample"),
    }
    if cap.get("error"):
        payload["error"] = cap["error"]
    return payload


def _redteam_router_discovery(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    has_nmap = tools.get("nmap") and shutil.which("nmap")
    if has_nmap:
        cmd = ["nmap", "--script", "broadcast-igmp-discovery"]
        if safe_iface:
            cmd.extend(["-e", safe_iface])
        rc, out, err = _run_cmd(cmd, timeout_s=15, logger=logger)
        text = (out or "") + "\n" + (err or "")
        snippet = text.strip()
        if snippet:
            ips = []
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", snippet):
                ip_str = m.group(1)
                if ip_str and ip_str not in ips:
                    ips.append(ip_str)
                if len(ips) >= 20:
                    break
            return {
                "status": "ok" if ips else "no_data",
                "tool": "nmap",
                "router_candidates": ips[:20],
                "raw_sample": _safe_truncate(snippet, 1400),
            }

    # Fallback: passive IGMP capture
    cap = _tcpdump_capture(
        safe_iface or "",
        "igmp",
        tools=tools,
        timeout_s=8,
        packets=50,
        logger=logger,
    )
    if cap.get("status") != "ok":
        return cap
    raw = cap.get("raw_sample", "") or ""
    ips = []
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw):
        ip_str = m.group(1)
        if ip_str and ip_str not in ips:
            ips.append(ip_str)
        if len(ips) >= 20:
            break
    return {
        "status": "ok" if ips else "no_data",
        "tool": "tcpdump",
        "router_candidates": ips[:20],
        "raw_sample": cap.get("raw_sample"),
        "error": cap.get("error"),
    }


def _parse_ip6_neighbors(text: str) -> List[Dict[str, Any]]:
    neigh: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # ip -6 neigh: fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = line.split()
        entry: Dict[str, Any] = {"raw": line[:250]}
        if parts:
            entry["ip"] = parts[0]
        if "lladdr" in parts:
            try:
                entry["mac"] = parts[parts.index("lladdr") + 1].lower()
            except Exception:
                pass
        else:
            # Fallback for ndp (macOS) or other formats: find MAC-like string
            for part in parts:
                if re.match(r"^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$", part):
                    entry["mac"] = part.lower()
                    break

        if "dev" in parts:
            try:
                entry["dev"] = parts[parts.index("dev") + 1]
            except Exception:
                pass
        if entry.get("ip"):
            neigh.append(entry)
    return neigh


def _redteam_ipv6_discovery(
    iface: Optional[str],
    tools: Dict[str, bool],
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    if not safe_iface:
        return {"status": "skipped_no_interface"}

    if not _is_root():
        # On many systems, ICMPv6 + neighbor listing are restricted without CAP_NET_RAW.
        return {"status": "skipped_requires_root"}

    errors: List[str] = []

    # Stimulate neighbor discovery (best-effort).
    if tools.get("ping6") and shutil.which("ping6"):
        rc, out, err = _run_cmd(
            ["ping6", "-c", "2", "-I", safe_iface, "ff02::1"],
            timeout_s=6,
            logger=logger,
        )
        if rc != 0 and err.strip():
            errors.append(_safe_truncate(err.strip(), 200))
    elif tools.get("ping") and shutil.which("ping"):
        rc, out, err = _run_cmd(
            ["ping", "-6", "-c", "2", "-I", safe_iface, "ff02::1"],
            timeout_s=6,
            logger=logger,
        )
        if rc != 0 and err.strip():
            errors.append(_safe_truncate(err.strip(), 200))

    neigh: List[Dict[str, Any]] = []
    if tools.get("ip") and shutil.which("ip"):
        rc, out, err = _run_cmd(
            ["ip", "-6", "neigh", "show", "dev", safe_iface], timeout_s=4, logger=logger
        )
        neigh = _parse_ip6_neighbors((out or "") + "\n" + (err or ""))
    else:
        # macOS fallback
        if shutil.which("ndp"):
            rc, out, err = _run_cmd(["ndp", "-an"], timeout_s=4, logger=logger)
            neigh = _parse_ip6_neighbors((out or "") + "\n" + (err or ""))

    payload: Dict[str, Any] = {
        "status": "ok" if neigh else "no_data",
        "neighbors": neigh[:50],
    }
    if errors:
        payload["errors"] = errors[:10]
    return payload


def _redteam_bettercap_recon(
    iface: Optional[str],
    tools: Dict[str, bool],
    active_l2: bool = False,
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    if not safe_iface:
        return {"status": "skipped_no_interface"}
    if not active_l2:
        return {"status": "skipped_disabled", "reason": "active_l2_false"}
    if not tools.get("bettercap") or not shutil.which("bettercap"):
        return {"status": "tool_missing", "tool": "bettercap"}
    if not _is_root():
        return {"status": "skipped_requires_root"}

    cmd = [
        "bettercap",
        "-iface",
        safe_iface,
        "-eval",
        "net.recon on; net.probe on; net.show; quit",
    ]
    rc, out, err = _run_cmd(cmd, timeout_s=15, logger=logger)
    text = (out or "") + "\n" + (err or "")
    snippet = text.strip()
    payload: Dict[str, Any] = {
        "status": "ok" if snippet else "no_data",
        "tool": "bettercap",
    }
    if snippet:
        payload["raw_sample"] = _safe_truncate(snippet, 1600)
    if rc != 0 and err.strip():
        payload["error"] = _safe_truncate(err.strip(), 200)
    return payload


def _redteam_scapy_custom(
    iface: Optional[str],
    tools: Dict[str, bool],
    active_l2: bool = False,
    logger=None,
) -> Dict[str, Any]:
    safe_iface = _sanitize_iface(iface)
    if not safe_iface:
        return {"status": "skipped_no_interface"}
    if not active_l2:
        return {"status": "skipped_disabled", "reason": "active_l2_false"}
    if not _is_root():
        return {"status": "skipped_requires_root"}

    try:
        import scapy  # type: ignore
        from scapy.all import Dot1Q, sniff, conf  # type: ignore
        import logging

        # 4.3: Suppress scapy warnings
        conf.verb = 0
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:
        return {"status": "tool_missing", "tool": "scapy"}

    vlan_ids: List[int] = []

    def _on_pkt(pkt) -> None:  # type: ignore[no-untyped-def]
        try:
            if pkt.haslayer(Dot1Q):
                vid = int(pkt[Dot1Q].vlan)
                if 1 <= vid <= 4094 and vid not in vlan_ids:
                    vlan_ids.append(vid)
        except Exception:
            return

    try:
        sniff(iface=safe_iface, timeout=3, prn=_on_pkt, store=False)
    except Exception as exc:
        return {"status": "error", "error": _safe_truncate(str(exc), 200)}

    payload: Dict[str, Any] = {
        "status": "ok" if vlan_ids else "no_data",
        "tool": "scapy",
        "scapy_version": getattr(scapy, "__version__", None),
        "vlan_ids": vlan_ids[:50],
        "note": "Passive sniff only (no packet injection).",
    }
    return payload
