#!/usr/bin/env python3
"""
Scanner Traffic Logic - RedAudit
Separated from scanner.py for modularity.
"""

import os
import re
import subprocess
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional

from redaudit.utils.constants import (
    TRAFFIC_CAPTURE_DEFAULT_DURATION,
    TRAFFIC_CAPTURE_MAX_DURATION,
    TRAFFIC_CAPTURE_PACKETS,
)
from redaudit.core.scanner.utils import sanitize_ip
from redaudit.core.scanner.nmap import _make_runner, _is_dry_run


def capture_traffic_snippet(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    duration: int = TRAFFIC_CAPTURE_DEFAULT_DURATION,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Capture small PCAP snippet with tcpdump + optional tshark summary.
    """
    if not extra_tools.get("tcpdump"):
        return None

    if _is_dry_run(dry_run):
        if logger:
            logger.info("[dry-run] skipping traffic capture snippet")
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

    if (
        not isinstance(duration, (int, float))
        or duration <= 0
        or duration > TRAFFIC_CAPTURE_MAX_DURATION
    ):
        if logger:
            logger.warning("Invalid capture duration %s, using default", duration)
        duration = TRAFFIC_CAPTURE_DEFAULT_DURATION

    # Find interface for the IP
    iface = None
    try:
        ip_obj = ipaddress.ip_address(safe_ip)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    iface = net.get("interface")
                    break
            except Exception:
                continue
    except ValueError:
        return None

    if not iface:
        if logger:
            logger.info("No interface found for host %s, skipping traffic capture", safe_ip)
        return None

    if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
        return None

    ts = datetime.now().strftime("%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, f"traffic_{safe_ip.replace('.', '_')}_{ts}.pcap")

    cmd = [
        extra_tools["tcpdump"],
        "-i",
        iface,
        "host",
        safe_ip,
        "-c",
        str(TRAFFIC_CAPTURE_PACKETS),
        "-G",
        str(int(duration)),
        "-W",
        "1",
        "-w",
        pcap_file,
    ]

    # v3.1.4: Use relative path for portability, keep absolute for internal use
    pcap_filename = os.path.basename(pcap_file)
    info = {"pcap_file": pcap_filename, "pcap_file_abs": pcap_file, "iface": iface}

    try:
        runner = _make_runner(logger=logger, dry_run=dry_run, timeout=float(duration) + 5.0)
        res = runner.run(
            cmd,
            capture_output=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            timeout=float(duration) + 5.0,
        )
        if res.timed_out:
            info["tcpdump_error"] = f"Timeout after {int(duration) + 5}s"
    except Exception as exc:
        info["tcpdump_error"] = str(exc)

    # Optional tshark summary
    if extra_tools.get("tshark"):
        try:
            runner = _make_runner(logger=logger, dry_run=dry_run, timeout=10.0)
            res = runner.run(
                [extra_tools["tshark"], "-r", pcap_file, "-q", "-z", "io,phs"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10.0,
            )
            if res.timed_out:
                info["tshark_error"] = "Timeout after 10s"
            else:
                info["tshark_summary"] = (str(res.stdout or "") or str(res.stderr or ""))[:2000]
        except Exception as exc:
            info["tshark_error"] = str(exc)

    return info


def start_background_capture(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Start background traffic capture for concurrent scanning (v2.8.0).
    """
    if not extra_tools.get("tcpdump"):
        return None

    if _is_dry_run(dry_run):
        if logger:
            logger.info("[dry-run] skipping background traffic capture")
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

    # Find interface for the IP
    iface = None
    try:
        ip_obj = ipaddress.ip_address(safe_ip)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    iface = net.get("interface")
                    break
            except Exception:
                continue
    except ValueError:
        return None

    if not iface:
        if logger:
            logger.info("No interface found for host %s, skipping traffic capture", safe_ip)
        return None

    if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
        return None

    ts = datetime.now().strftime("%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, f"traffic_{safe_ip.replace('.', '_')}_{ts}.pcap")

    # v2.8.1: Limit capture to 200 packets for smaller PCAP files (~50-150KB)
    cmd = [
        extra_tools["tcpdump"],
        "-i",
        iface,
        "-c",
        "200",  # Capture max 200 packets
        "host",
        safe_ip,
        "-w",
        pcap_file,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # v3.1.4: Keep reports portable by storing relative filename; keep absolute for internal use.
        pcap_filename = os.path.basename(pcap_file)
        return {
            "process": proc,
            "pcap_file": pcap_filename,
            "pcap_file_abs": pcap_file,
            "iface": iface,
        }
    except Exception as exc:
        if logger:
            logger.debug("Failed to start background capture for %s: %s", safe_ip, exc)
        return None


def stop_background_capture(
    capture_info: Dict,
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Stop background traffic capture and collect results (v2.8.0).
    """
    if not capture_info or "process" not in capture_info:
        return None

    proc = capture_info["process"]
    pcap_file_abs = capture_info.get("pcap_file_abs") or capture_info.get("pcap_file", "")
    iface = capture_info.get("iface", "")

    pcap_file = capture_info.get("pcap_file")
    if not pcap_file:
        pcap_file = os.path.basename(pcap_file_abs) if pcap_file_abs else ""
    # If older capture_info stored an absolute path in pcap_file, normalize to portable filename.
    if pcap_file and ("/" in pcap_file or "\\" in pcap_file):
        pcap_file = os.path.basename(pcap_file)

    result = {"pcap_file": pcap_file, "pcap_file_abs": pcap_file_abs, "iface": iface}

    # Terminate the capture process
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        result["tcpdump_error"] = "Process killed after timeout"
    except Exception as exc:
        result["tcpdump_error"] = str(exc)

    # Generate tshark summary if available
    if pcap_file_abs and os.path.exists(pcap_file_abs):
        # Ensure PCAP is stored with secure permissions (best-effort).
        try:
            os.chmod(pcap_file_abs, 0o600)
        except Exception:
            pass

    if extra_tools.get("tshark") and pcap_file_abs and os.path.exists(pcap_file_abs):
        try:
            if _is_dry_run(dry_run):
                return result
            runner = _make_runner(logger=logger, timeout=10.0)
            res = runner.run(
                [extra_tools["tshark"], "-r", pcap_file_abs, "-q", "-z", "io,phs"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10.0,
            )
            if res.timed_out:
                result["tshark_error"] = "Timeout after 10s"
            else:
                summary = (str(res.stdout or "") or str(res.stderr or ""))[:2000]
                if summary.strip():
                    result["tshark_summary"] = summary
        except Exception as exc:
            result["tshark_error"] = str(exc)

    return result


def merge_pcap_files(
    output_dir: str,
    session_id: str,
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[str]:
    """
    Merge all individual PCAP files into a single consolidated capture.

    v4.3: PCAP management improvement - consolidates captures for easier analysis.

    Args:
        output_dir: Directory containing individual PCAP files
        session_id: Session identifier for naming the merged file
        extra_tools: Dict with tool paths (needs 'mergecap' or 'tshark')
        logger: Optional logger
        dry_run: If True, skip actual merge

    Returns:
        Path to merged PCAP file, or None if merge failed/skipped
    """
    import shutil
    import glob

    if _is_dry_run(dry_run):
        if logger:
            logger.info("[dry-run] skipping PCAP merge")
        return None

    # Find mergecap (part of Wireshark suite)
    mergecap = extra_tools.get("mergecap") or shutil.which("mergecap")
    if not mergecap:
        if logger:
            logger.debug("mergecap not found, skipping PCAP consolidation")
        return None

    # Find all individual PCAP files
    pcap_pattern = os.path.join(output_dir, "traffic_*.pcap")
    pcap_files = sorted(glob.glob(pcap_pattern))

    if len(pcap_files) < 2:
        if logger:
            logger.debug("Less than 2 PCAP files found, skipping merge")
        return None

    # Create merged file
    merged_filename = f"full_capture_{session_id}.pcap"
    merged_file = os.path.join(output_dir, merged_filename)

    cmd = [mergecap, "-w", merged_file] + pcap_files

    try:
        runner = _make_runner(logger=logger, dry_run=dry_run, timeout=60.0)
        res = runner.run(
            cmd,
            capture_output=True,
            check=False,
            text=True,
            timeout=60.0,
        )

        if res.returncode == 0 and os.path.exists(merged_file):
            # Set secure permissions
            try:
                os.chmod(merged_file, 0o600)
            except Exception:
                pass

            if logger:
                logger.info(
                    "Merged %d PCAP files into %s",
                    len(pcap_files),
                    merged_filename,
                )
            return merged_file
        else:
            if logger:
                error_msg = res.stderr or res.stdout or "Unknown error"
                logger.warning("PCAP merge failed: %s", error_msg[:200])
            return None

    except Exception as exc:
        if logger:
            logger.warning("PCAP merge error: %s", exc)
        return None


def organize_pcap_files(
    output_dir: str,
    merged_file: Optional[str] = None,
    logger=None,
) -> Optional[str]:
    """
    Move individual PCAP files to a raw_captures subdirectory.

    v4.3: PCAP management improvement - keeps output directory clean.

    Args:
        output_dir: Main output directory
        merged_file: Path to merged file (to exclude from move)
        logger: Optional logger

    Returns:
        Path to raw_captures directory, or None if no files moved
    """
    import shutil
    import glob

    # Find individual PCAP files
    pcap_pattern = os.path.join(output_dir, "traffic_*.pcap")
    pcap_files = glob.glob(pcap_pattern)

    if not pcap_files:
        return None

    # Create subdirectory
    raw_dir = os.path.join(output_dir, "raw_captures")
    try:
        os.makedirs(raw_dir, exist_ok=True)
    except Exception as exc:
        if logger:
            logger.warning("Failed to create raw_captures directory: %s", exc)
        return None

    moved_count = 0
    for pcap_file in pcap_files:
        # Don't move the merged file
        if merged_file and os.path.abspath(pcap_file) == os.path.abspath(merged_file):
            continue

        try:
            dest = os.path.join(raw_dir, os.path.basename(pcap_file))
            shutil.move(pcap_file, dest)
            moved_count += 1
        except Exception as exc:
            if logger:
                logger.debug("Failed to move %s: %s", pcap_file, exc)

    if moved_count > 0 and logger:
        logger.info("Moved %d PCAP files to raw_captures/", moved_count)

    return raw_dir if moved_count > 0 else None


def finalize_pcap_artifacts(
    output_dir: str,
    session_id: str,
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Finalize PCAP artifacts: merge individual files and organize into subdirectory.

    v4.3: Single entry point for PCAP post-processing.

    Args:
        output_dir: Main output directory
        session_id: Session identifier for naming
        extra_tools: Dict with tool paths
        logger: Optional logger
        dry_run: If True, skip actual operations

    Returns:
        Dict with 'merged_file' and 'raw_captures_dir' paths (may be None)
    """
    result: Dict[str, Any] = {
        "merged_file": None,
        "raw_captures_dir": None,
        "individual_count": 0,
    }

    import glob

    # Count individual files before processing
    pcap_pattern = os.path.join(output_dir, "traffic_*.pcap")
    pcap_files = glob.glob(pcap_pattern)
    result["individual_count"] = len(pcap_files)

    if not pcap_files:
        return result

    # Step 1: Merge files
    merged_file = merge_pcap_files(
        output_dir=output_dir,
        session_id=session_id,
        extra_tools=extra_tools,
        logger=logger,
        dry_run=dry_run,
    )
    result["merged_file"] = merged_file

    # Step 2: Organize into subdirectory
    raw_dir = organize_pcap_files(
        output_dir=output_dir,
        merged_file=merged_file,
        logger=logger,
    )
    result["raw_captures_dir"] = raw_dir

    return result
