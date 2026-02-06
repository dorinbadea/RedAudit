#!/usr/bin/env python3
"""
RedAudit - Topology Discovery Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.1+: Best-effort topology discovery to detect "hidden" networks and L2 context.

Goals:
- Provide additional context for professional audits (SIEM + reporting).
- Keep runtime bounded (short timeouts, limited capture).
- Never fail the main scan (best-effort, optional).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from redaudit.core.command_runner import CommandRunner
from redaudit.utils.dry_run import is_dry_run
from redaudit.utils.oui_lookup import lookup_vendor_online


def _run_cmd(
    args: List[str],
    timeout_s: int,
    logger=None,
) -> Tuple[int, str, str]:
    runner = CommandRunner(
        logger=logger,
        dry_run=is_dry_run(),
        default_timeout=float(timeout_s),
        default_retries=0,
        backoff_base_s=0.0,
        redact_env_keys={"NVD_API_KEY", "GITHUB_TOKEN"},
    )
    res = runner.run(args, timeout=float(timeout_s), capture_output=True, check=False, text=True)
    stdout = res.stdout if isinstance(res.stdout, str) else ""
    stderr = res.stderr if isinstance(res.stderr, str) else ""
    return int(res.returncode), stdout, stderr


def _parse_ip_route(stdout: str) -> List[Dict[str, Any]]:
    routes: List[Dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue

        # Example: default via 192.168.1.1 dev eth0 proto dhcp metric 100
        # Example: 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100
        parts = line.split()
        route: Dict[str, Any] = {"raw": line}

        if parts[0] == "default":
            route["dst"] = "default"
            if "via" in parts:
                try:
                    route["via"] = parts[parts.index("via") + 1]
                except Exception:
                    pass
        else:
            route["dst"] = parts[0]

        if "dev" in parts:
            try:
                route["dev"] = parts[parts.index("dev") + 1]
            except Exception:
                pass
        if "src" in parts:
            try:
                route["src"] = parts[parts.index("src") + 1]
            except Exception:
                pass
        if "metric" in parts:
            try:
                route["metric"] = int(parts[parts.index("metric") + 1])
            except Exception:
                pass

        routes.append(route)
    return routes


def _extract_default_gateway(routes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for r in routes:
        if r.get("dst") == "default":
            return {
                "ip": r.get("via"),
                "interface": r.get("dev"),
                "metric": r.get("metric"),
            }
    return None


def _parse_arp_scan(stdout: str) -> List[Dict[str, Any]]:
    """Parse arp-scan output and enrich unknown vendors via OUI lookup.

    v4.12.1: Added OUI enrichment to resolve "(Unknown)" vendors.
    """
    hosts: List[Dict[str, Any]] = []
    seen = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("Interface:", "Starting arp-scan", "Ending arp-scan")):
            continue
        if line.startswith(("#", "packets", "WARNING")):
            continue

        # Expected columns: IP <whitespace> MAC <whitespace> Vendor...
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f:]{17})\s+(.+)$", line)
        if not m:
            continue
        ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()

        # v4.12.1: Enrich unknown vendors via OUI lookup
        if "unknown" in vendor.lower():
            try:
                enriched = lookup_vendor_online(mac)
                if enriched:
                    vendor = enriched
            except Exception:
                pass

        key = (ip, mac.lower())
        if key in seen:
            continue
        seen.add(key)
        hosts.append({"ip": ip, "mac": mac.lower(), "vendor": vendor})

    return hosts


def _parse_ip_neigh(stdout: str) -> List[Dict[str, Any]]:
    neigh: List[Dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = line.split()
        entry: Dict[str, Any] = {"raw": line}
        if parts:
            entry["ip"] = parts[0]
        if "dev" in parts:
            try:
                entry["dev"] = parts[parts.index("dev") + 1]
            except Exception:
                pass
        if "lladdr" in parts:
            try:
                entry["mac"] = parts[parts.index("lladdr") + 1].lower()
            except Exception:
                pass
        # State is usually last token.
        if parts:
            entry["state"] = parts[-1]
        neigh.append(entry)
    return neigh


def _parse_vlan_ids_from_ip_link(stdout: str) -> List[int]:
    vlan_ids: List[int] = []
    text = stdout or ""
    patterns = [
        r"\bvlan id\s+(\d{1,4})\b",
        r"\bvlan\b[^\n]*?\bid\s+(\d{1,4})\b",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            try:
                vid = int(m.group(1))
            except Exception:
                continue
            if 1 <= vid <= 4094 and vid not in vlan_ids:
                vlan_ids.append(vid)
    return vlan_ids


def _parse_vlan_ids_from_ifconfig(stdout: str) -> List[int]:
    vlan_ids: List[int] = []
    # macOS: vlan: 100 parent interface: en0
    for m in re.finditer(r"vlan:\s*(\d+)", stdout or "", re.IGNORECASE):
        try:
            vid = int(m.group(1))
            if 1 <= vid <= 4094 and vid not in vlan_ids:
                vlan_ids.append(vid)
        except Exception:
            continue
    return vlan_ids


def _parse_vlan_ids_from_tcpdump(stdout: str) -> List[int]:
    vlan_ids: List[int] = []
    for m in re.finditer(r"\bvlan\s+(\d{1,4})\b", stdout or "", re.IGNORECASE):
        try:
            vid = int(m.group(1))
        except Exception:
            continue
        if 1 <= vid <= 4094 and vid not in vlan_ids:
            vlan_ids.append(vid)
    return vlan_ids


def _parse_lldp_from_tcpdump(stdout: str) -> List[Dict[str, Any]]:
    neighbors = []

    # Simple state machine to parse verbose tcpdump output
    text = stdout or ""
    # LLDP packets usually start with "LLDP,"

    # We try to extract basic TLVs.
    # System Name TLV (5), length 18: Switch-01

    sys_name = re.search(r"System Name TLV.*?: (.+)", text)
    port_id = re.search(r"Port ID TLV.*?: (.+)", text)
    sys_desc = re.search(r"System Description TLV.*?: (.+)", text)
    mgmt_ip = re.search(r"Management Address TLV.*?: ([\d\.]+)", text)

    if sys_name or port_id:
        neighbor = {
            "chassis": {
                "name": sys_name.group(1).strip() if sys_name else None,
                "descr": sys_desc.group(1).strip() if sys_desc else None,
                "mgmt_ip": mgmt_ip.group(1).strip() if mgmt_ip else None,
            },
            "port": {
                "id": port_id.group(1).strip() if port_id else None,
            },
            "source": "tcpdump",
        }
        neighbors.append(neighbor)

    return neighbors


def _extract_lldp_neighbors(lldpctl_json: Dict[str, Any], iface: str) -> List[Dict[str, Any]]:
    neighbors: List[Dict[str, Any]] = []

    # lldpctl -f json returns a structure similar to:
    # {"lldp": {"interface": {"eth0": {"chassis": {...}, "port": {...}}}}}
    try:
        iface_obj = lldpctl_json.get("lldp", {}).get("interface", {}).get(iface)
        if not iface_obj:
            return []
        # Normalize to list of neighbors (lldpctl sometimes returns list or dict).
        if isinstance(iface_obj, list):
            iface_entries = iface_obj
        else:
            iface_entries = [iface_obj]
        for entry in iface_entries:
            chassis = entry.get("chassis", {}) if isinstance(entry, dict) else {}
            port = entry.get("port", {}) if isinstance(entry, dict) else {}
            neighbor = {
                "chassis": {
                    "name": chassis.get("name"),
                    "descr": chassis.get("descr"),
                    "mgmt_ip": chassis.get("mgmt-ip"),
                    "id": (
                        chassis.get("id", {}).get("value")
                        if isinstance(chassis.get("id"), dict)
                        else None
                    ),
                },
                "port": {
                    "id": (
                        port.get("id", {}).get("value")
                        if isinstance(port.get("id"), dict)
                        else None
                    ),
                    "descr": port.get("descr"),
                },
            }
            neighbors.append(neighbor)
    except Exception:
        return []

    # Remove empty shells.
    cleaned = []
    for n in neighbors:
        if any(v for v in (n.get("chassis", {}) or {}).values()) or any(
            v for v in (n.get("port", {}) or {}).values()
        ):
            cleaned.append(n)
    return cleaned


def _networks_from_route_table(routes: List[Dict[str, Any]]) -> List[str]:
    nets: List[str] = []
    for r in routes:
        dst = r.get("dst")
        if not dst or dst == "default":
            continue
        if "/" not in str(dst):
            continue
        try:
            net = ipaddress.ip_network(str(dst), strict=False)
            nets.append(str(net))
        except Exception:
            continue
    # Deduplicate preserving order
    seen = set()
    out = []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def discover_topology(
    target_networks: List[str],
    network_info: List[Dict[str, Any]],
    extra_tools: Optional[Dict[str, str]] = None,
    logger=None,
) -> Dict[str, Any]:
    """
    Best-effort topology discovery.

    Async acceleration (v3.1.3):
    - Runs independent commands concurrently (bounded by timeouts).
    - Falls back to the original sequential implementation if an event loop is already running
      or if asyncio execution fails for any reason.
    """
    try:
        # Avoid "asyncio.run() cannot be called from a running event loop"
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            return asyncio.run(
                _discover_topology_async(
                    target_networks=target_networks,
                    network_info=network_info,
                    extra_tools=extra_tools,
                    logger=logger,
                )
            )
        except Exception as exc:
            if logger:
                logger.warning("Async topology discovery failed, falling back: %s", exc)
    return _discover_topology_sync(
        target_networks=target_networks,
        network_info=network_info,
        extra_tools=extra_tools,
        logger=logger,
    )


async def _run_cmd_async(
    args: List[str],
    timeout_s: int,
    logger=None,
) -> Tuple[int, str, str]:
    return await asyncio.to_thread(_run_cmd, args, timeout_s, logger)


async def _discover_topology_async(
    target_networks: List[str],
    network_info: List[Dict[str, Any]],
    extra_tools: Optional[Dict[str, str]] = None,
    logger=None,
) -> Dict[str, Any]:
    tools = extra_tools or {}
    errors: List[str] = []

    # Detect system tools as needed (do not treat as hard deps).
    has_ip = bool(shutil.which("ip"))
    has_tcpdump = bool(shutil.which("tcpdump")) or bool(tools.get("tcpdump"))
    has_arp_scan = bool(shutil.which("arp-scan")) or bool(tools.get("arp-scan"))
    has_lldpctl = bool(shutil.which("lldpctl"))

    topology: Dict[str, Any] = {
        "enabled": True,
        "generated_at": datetime.now().isoformat(),
        "tools": {
            "ip": has_ip,
            "tcpdump": has_tcpdump,
            "arp-scan": has_arp_scan,
            "lldpctl": has_lldpctl,
        },
        "routes": [],
        "default_gateway": None,
        "interfaces": [],
        "candidate_networks": [],
        "errors": errors,
    }

    # Route table + LLDP can be gathered in parallel.
    routes: List[Dict[str, Any]] = []
    lldp_json: Dict[str, Any] = {}

    tasks: List[asyncio.Task] = []
    route_task = None
    lldp_task = None
    if has_ip:
        route_task = asyncio.create_task(
            _run_cmd_async(["ip", "route", "show"], timeout_s=3, logger=logger)
        )
        tasks.append(route_task)
    if has_lldpctl:
        lldp_task = asyncio.create_task(
            _run_cmd_async(["lldpctl", "-f", "json"], timeout_s=3, logger=logger)
        )
        tasks.append(lldp_task)

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    if route_task is not None:
        try:
            rc, out, err = route_task.result()
            if rc == 0 and (out or "").strip():
                routes = _parse_ip_route(out)
            else:
                errors.append(f"ip route show failed: {(err or '').strip() or 'unknown error'}")
        except Exception:
            errors.append("ip route show failed: unknown error")
    else:
        errors.append("ip command not found; route/gateway mapping unavailable")

    if lldp_task is not None:
        try:
            rc, out, err = lldp_task.result()
            if rc == 0 and (out or "").strip():
                try:
                    lldp_json = json.loads(out)
                except Exception:
                    lldp_json = {}
            elif (err or "").strip():
                lldp_err = (err or "").strip()
                # v3.2.1: Provide helpful suggestion for common LLDP socket error
                if "socket" in lldp_err.lower() or "unable to connect" in lldp_err.lower():
                    lldp_err += " (Hint: try 'sudo systemctl start lldpd')"
                errors.append(f"lldpctl failed: {lldp_err}")
        except Exception:
            pass

    topology["routes"] = routes
    topology["default_gateway"] = _extract_default_gateway(routes)

    # Choose interfaces relevant to target networks (best-effort intersection with local networks).
    target_objs: List[ipaddress._BaseNetwork] = []
    for t in target_networks or []:
        try:
            target_objs.append(ipaddress.ip_network(t, strict=False))
        except Exception:
            continue

    iface_map: Dict[str, Dict[str, Any]] = {}
    for ni in network_info or []:
        iface = ni.get("interface")
        if not iface:
            continue
        if iface not in iface_map:
            iface_map[iface] = {
                "interface": iface,
                "ip": ni.get("ip"),
                "networks": [],
            }
        if ni.get("network"):
            iface_map[iface]["networks"].append(ni["network"])

    selected_ifaces: List[str] = []
    if target_objs:
        for iface, meta in iface_map.items():
            for net_str in meta.get("networks", []) or []:
                try:
                    local_net = ipaddress.ip_network(net_str, strict=False)
                except Exception:
                    continue
                if any(local_net.overlaps(tn) for tn in target_objs):
                    selected_ifaces.append(iface)
                    break
    if not selected_ifaces:
        # Fallback to default gateway interface if known.
        gw = topology.get("default_gateway") or {}
        if gw.get("interface"):
            selected_ifaces.append(gw["interface"])
        else:
            selected_ifaces = list(iface_map.keys())

    # Deduplicate preserving order
    deduped_ifaces: List[str] = []
    seen: set[str] = set()
    for iface in selected_ifaces:
        if iface in seen:
            continue
        seen.add(iface)
        deduped_ifaces.append(iface)
    selected_ifaces = deduped_ifaces

    async def _collect_iface(iface: str) -> Tuple[Dict[str, Any], List[str]]:
        iface_errors: List[str] = []
        iface_entry: Dict[str, Any] = iface_map.get(
            iface, {"interface": iface, "networks": []}
        ).copy()
        iface_entry["arp"] = {"method": None, "hosts": [], "error": None}
        iface_entry["neighbor_cache"] = {"entries": [], "error": None}
        iface_entry["vlan"] = {"ids": [], "sources": []}
        iface_entry["lldp"] = {"neighbors": []}
        iface_entry["cdp"] = {"observations": []}

        arp_task = None
        neigh_task = None
        link_task = None

        if has_arp_scan:
            arp_task = asyncio.create_task(
                _run_cmd_async(
                    ["arp-scan", "--localnet", "--interface", iface],
                    timeout_s=15,
                    logger=logger,
                )
            )
        if has_ip:
            neigh_task = asyncio.create_task(
                _run_cmd_async(["ip", "neigh", "show", "dev", iface], timeout_s=3, logger=logger)
            )
            link_task = asyncio.create_task(
                _run_cmd_async(
                    ["ip", "-d", "link", "show", "dev", iface], timeout_s=3, logger=logger
                )
            )

        # tcpdump is intentionally kept sequential per interface to avoid concurrent sniffers on the same iface.
        vlan_result = None
        if has_tcpdump:
            vlan_result = await _run_cmd_async(
                ["tcpdump", "-nn", "-e", "-i", iface, "-c", "20", "vlan"],
                timeout_s=3,
                logger=logger,
            )

        cdp_result = None
        if has_tcpdump:
            cdp_result = await _run_cmd_async(
                [
                    "tcpdump",
                    "-nn",
                    "-e",
                    "-i",
                    iface,
                    "-c",
                    "10",
                    "ether",
                    "dst",
                    "01:00:0c:cc:cc:cc",
                ],
                timeout_s=3,
                logger=logger,
            )

        lldp_tcp_result = None
        if has_tcpdump and not has_lldpctl:
            lldp_tcp_result = await _run_cmd_async(
                [
                    "tcpdump",
                    "-nn",
                    "-v",
                    "-s",
                    "1500",
                    "-i",
                    iface,
                    "-c",
                    "1",
                    "ether",
                    "proto",
                    "0x88cc",
                ],
                timeout_s=3,
                logger=logger,
            )

        ifconfig_task = None
        if shutil.which("ifconfig"):
            ifconfig_task = asyncio.create_task(
                _run_cmd_async(["ifconfig", iface], timeout_s=2, logger=logger)
            )

        # Await other tasks
        if arp_task is not None:
            try:
                rc, out, err = await arp_task
                iface_entry["arp"]["method"] = "arp-scan"
                if rc == 0 and (out or "").strip():
                    iface_entry["arp"]["hosts"] = _parse_arp_scan(out)
                else:
                    iface_entry["arp"]["error"] = (err or "").strip() or "arp-scan failed"
            except Exception as exc:
                iface_entry["arp"]["method"] = "arp-scan"
                iface_entry["arp"]["error"] = str(exc)

        if neigh_task is not None:
            try:
                rc, out, err = await neigh_task
                if rc == 0 and (out or "").strip():
                    iface_entry["neighbor_cache"]["entries"] = _parse_ip_neigh(out)
                elif (err or "").strip():
                    iface_entry["neighbor_cache"]["error"] = (err or "").strip()
            except Exception as exc:
                iface_entry["neighbor_cache"]["error"] = str(exc)

        if link_task is not None:
            try:
                rc, out, err = await link_task
                if rc == 0 and (out or "").strip():
                    vids = _parse_vlan_ids_from_ip_link(out)
                    if vids:
                        iface_entry["vlan"]["ids"].extend(
                            [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                        )
                        iface_entry["vlan"]["sources"].append("ip_link")
                elif (err or "").strip():
                    iface_errors.append(f"ip link show failed for {iface}: {(err or '').strip()}")
            except Exception:
                pass

        if vlan_result is not None:
            _rc, out, _err = vlan_result
            if (out or "").strip():
                vids = _parse_vlan_ids_from_tcpdump(out)
                if vids:
                    iface_entry["vlan"]["ids"].extend(
                        [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                    )
                    iface_entry["vlan"]["sources"].append("tcpdump_vlan")

        if cdp_result is not None:
            _rc, out, _err = cdp_result
            if (out or "").strip():
                obs = []
                for line in out.splitlines():
                    s = line.strip()
                    if s and s not in obs:
                        obs.append(s[:200])
                    if len(obs) >= 10:
                        break
                iface_entry["cdp"]["observations"] = obs

        if lldp_tcp_result is not None:
            _rc, out, _err = lldp_tcp_result
            if (out or "").strip():
                neighbors = _parse_lldp_from_tcpdump(out)
                if neighbors:
                    iface_entry["lldp"]["neighbors"].extend(neighbors)

        if ifconfig_task is not None:
            try:
                rc, out, err = await ifconfig_task
                if rc == 0 and (out or "").strip():
                    vids = _parse_vlan_ids_from_ifconfig(out)
                    if vids:
                        iface_entry["vlan"]["ids"].extend(
                            [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                        )
                        iface_entry["vlan"]["sources"].append("ifconfig")
            except Exception:
                pass

        if lldp_json:
            iface_entry["lldp"]["neighbors"] = _extract_lldp_neighbors(lldp_json, iface)

        return iface_entry, iface_errors

    iface_tasks = [asyncio.create_task(_collect_iface(iface)) for iface in selected_ifaces]
    iface_results = await asyncio.gather(*iface_tasks, return_exceptions=True)

    for res in iface_results:
        if isinstance(res, BaseException):
            continue
        iface_entry, iface_errors = res
        topology["interfaces"].append(iface_entry)
        errors.extend(iface_errors)

    # Candidate networks: route destinations that are NOT already in targets.
    route_nets = _networks_from_route_table(routes)
    local_nets = set()
    for ni in network_info or []:
        if ni.get("network"):
            try:
                local_nets.add(str(ipaddress.ip_network(ni["network"], strict=False)))
            except Exception:
                continue

    target_nets = set(str(n) for n in target_objs)
    candidates = []
    for n in route_nets:
        if n in target_nets:
            continue
        if n in local_nets:
            continue
        # Skip special routes
        if n.startswith("127.") or n.startswith("169.254."):
            continue
        candidates.append(n)
    topology["candidate_networks"] = candidates

    return topology


def _discover_topology_sync(
    target_networks: List[str],
    network_info: List[Dict[str, Any]],
    extra_tools: Optional[Dict[str, str]] = None,
    logger=None,
) -> Dict[str, Any]:
    """Original sequential topology discovery implementation (fallback)."""
    tools = extra_tools or {}
    errors: List[str] = []

    # Detect system tools as needed (do not treat as hard deps).
    has_ip = bool(shutil.which("ip"))
    has_tcpdump = bool(shutil.which("tcpdump")) or bool(tools.get("tcpdump"))
    has_arp_scan = bool(shutil.which("arp-scan")) or bool(tools.get("arp-scan"))
    has_lldpctl = bool(shutil.which("lldpctl"))

    topology: Dict[str, Any] = {
        "enabled": True,
        "generated_at": datetime.now().isoformat(),
        "tools": {
            "ip": has_ip,
            "tcpdump": has_tcpdump,
            "arp-scan": has_arp_scan,
            "lldpctl": has_lldpctl,
        },
        "routes": [],
        "default_gateway": None,
        "interfaces": [],
        "candidate_networks": [],
        "errors": errors,
    }

    # Route table + default gateway
    routes: List[Dict[str, Any]] = []
    if has_ip:
        rc, out, err = _run_cmd(["ip", "route", "show"], timeout_s=3, logger=logger)
        if rc == 0 and out.strip():
            routes = _parse_ip_route(out)
        else:
            errors.append(f"ip route show failed: {err.strip() or 'unknown error'}")
    else:
        errors.append("ip command not found; route/gateway mapping unavailable")

    topology["routes"] = routes
    topology["default_gateway"] = _extract_default_gateway(routes)

    # Choose interfaces relevant to target networks (best-effort intersection with local networks).
    target_objs: List[ipaddress._BaseNetwork] = []
    for t in target_networks or []:
        try:
            target_objs.append(ipaddress.ip_network(t, strict=False))
        except Exception:
            continue

    iface_map: Dict[str, Dict[str, Any]] = {}
    for ni in network_info or []:
        iface = ni.get("interface")
        if not iface:
            continue
        if iface not in iface_map:
            iface_map[iface] = {
                "interface": iface,
                "ip": ni.get("ip"),
                "networks": [],
            }
        if ni.get("network"):
            iface_map[iface]["networks"].append(ni["network"])

    selected_ifaces: List[str] = []
    if target_objs:
        for iface, meta in iface_map.items():
            for net_str in meta.get("networks", []) or []:
                try:
                    local_net = ipaddress.ip_network(net_str, strict=False)
                except Exception:
                    continue
                if any(local_net.overlaps(tn) for tn in target_objs):
                    selected_ifaces.append(iface)
                    break
    if not selected_ifaces:
        # Fallback to default gateway interface if known.
        gw = topology.get("default_gateway") or {}
        if gw.get("interface"):
            selected_ifaces.append(gw["interface"])
        else:
            selected_ifaces = list(iface_map.keys())

    # Deduplicate preserving order
    deduped_ifaces: List[str] = []
    seen: set[str] = set()
    for iface in selected_ifaces:
        if iface in seen:
            continue
        seen.add(iface)
        deduped_ifaces.append(iface)
    selected_ifaces = deduped_ifaces

    # LLDP neighbors (if lldpctl available)
    lldp_json: Dict[str, Any] = {}
    if has_lldpctl:
        rc, out, err = _run_cmd(["lldpctl", "-f", "json"], timeout_s=3, logger=logger)
        if rc == 0 and out.strip():
            try:
                lldp_json = json.loads(out)
            except Exception:
                lldp_json = {}
        elif err.strip():
            lldp_err = err.strip()
            # v3.2.1: Provide helpful suggestion for common LLDP socket error
            if "socket" in lldp_err.lower() or "unable to connect" in lldp_err.lower():
                lldp_err += " (Hint: try 'sudo systemctl start lldpd')"
            errors.append(f"lldpctl failed: {lldp_err}")

    for iface in selected_ifaces:
        iface_entry: Dict[str, Any] = iface_map.get(
            iface, {"interface": iface, "networks": []}
        ).copy()
        iface_entry["arp"] = {"method": None, "hosts": [], "error": None}
        iface_entry["neighbor_cache"] = {"entries": [], "error": None}
        iface_entry["vlan"] = {"ids": [], "sources": []}
        iface_entry["lldp"] = {"neighbors": []}
        iface_entry["cdp"] = {"observations": []}

        # ARP scan (active)
        if has_arp_scan:
            rc, out, err = _run_cmd(
                ["arp-scan", "--localnet", "--interface", iface],
                timeout_s=15,
                logger=logger,
            )
            if rc == 0 and out.strip():
                iface_entry["arp"]["method"] = "arp-scan"
                iface_entry["arp"]["hosts"] = _parse_arp_scan(out)
            else:
                iface_entry["arp"]["method"] = "arp-scan"
                iface_entry["arp"]["error"] = err.strip() or "arp-scan failed"

        # Neighbor cache fallback (passive)
        if has_ip:
            rc, out, err = _run_cmd(
                ["ip", "neigh", "show", "dev", iface], timeout_s=3, logger=logger
            )
            if rc == 0 and out.strip():
                iface_entry["neighbor_cache"]["entries"] = _parse_ip_neigh(out)
            elif err.strip():
                iface_entry["neighbor_cache"]["error"] = err.strip()

        # macOS ifconfig support (Sync)
        if shutil.which("ifconfig"):
            rc, out, err = _run_cmd(["ifconfig", iface], timeout_s=2, logger=logger)
            if rc == 0 and out.strip():
                vids = _parse_vlan_ids_from_ifconfig(out)
                if vids:
                    iface_entry["vlan"]["ids"].extend(
                        [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                    )
                    iface_entry["vlan"]["sources"].append("ifconfig")

        # VLAN IDs from ip link details
        if has_ip:
            rc, out, err = _run_cmd(
                ["ip", "-d", "link", "show", "dev", iface], timeout_s=3, logger=logger
            )
            if rc == 0 and out.strip():
                vids = _parse_vlan_ids_from_ip_link(out)
                if vids:
                    iface_entry["vlan"]["ids"].extend(
                        [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                    )
                    iface_entry["vlan"]["sources"].append("ip_link")
            elif err.strip():
                errors.append(f"ip link show failed for {iface}: {err.strip()}")

        # VLAN IDs observed on the wire (best-effort, short timeout)
        if has_tcpdump:
            rc, out, err = _run_cmd(
                ["tcpdump", "-nn", "-e", "-i", iface, "-c", "20", "vlan"],
                timeout_s=3,
                logger=logger,
            )
            if out.strip():
                vids = _parse_vlan_ids_from_tcpdump(out)
                if vids:
                    iface_entry["vlan"]["ids"].extend(
                        [v for v in vids if v not in iface_entry["vlan"]["ids"]]
                    )
                    iface_entry["vlan"]["sources"].append("tcpdump_vlan")
            # Ignore timeout (no traffic) silently.

        # LLDP neighbors
        if lldp_json:
            iface_entry["lldp"]["neighbors"] = _extract_lldp_neighbors(lldp_json, iface)

        # LLDP via tcpdump (fallback if lldpctl missing)
        if has_tcpdump and not has_lldpctl:
            rc, out, err = _run_cmd(
                [
                    "tcpdump",
                    "-nn",
                    "-v",
                    "-s",
                    "1500",
                    "-i",
                    iface,
                    "-c",
                    "1",
                    "ether",
                    "proto",
                    "0x88cc",
                ],
                timeout_s=3,
                logger=logger,
            )
            if out.strip():
                neighbors = _parse_lldp_from_tcpdump(out)
                if neighbors:
                    iface_entry["lldp"]["neighbors"].extend(neighbors)

        # CDP observations (best-effort, short timeout)
        if has_tcpdump:
            rc, out, err = _run_cmd(
                [
                    "tcpdump",
                    "-nn",
                    "-e",
                    "-i",
                    iface,
                    "-c",
                    "10",
                    "ether",
                    "dst",
                    "01:00:0c:cc:cc:cc",
                ],
                timeout_s=3,
                logger=logger,
            )
            if out.strip():
                # Keep a few unique short lines as observations.
                obs = []
                for line in out.splitlines():
                    s = line.strip()
                    if s and s not in obs:
                        obs.append(s[:200])
                    if len(obs) >= 10:
                        break
                iface_entry["cdp"]["observations"] = obs

        topology["interfaces"].append(iface_entry)

    # Candidate networks: route destinations that are NOT already in targets.
    route_nets = _networks_from_route_table(routes)
    local_nets = set()
    for ni in network_info or []:
        if ni.get("network"):
            try:
                local_nets.add(str(ipaddress.ip_network(ni["network"], strict=False)))
            except Exception:
                continue

    target_nets = set(str(n) for n in target_objs)
    candidates = []
    for n in route_nets:
        if n in target_nets:
            continue
        if n in local_nets:
            continue
        # Skip special routes
        if n.startswith("127.") or n.startswith("169.254."):
            continue
        candidates.append(n)
    topology["candidate_networks"] = candidates

    return topology
