#!/usr/bin/env python3
"""
RedAudit - Osquery Verification Module
Copyright (C) 2026  Dorin Badea
GPLv3 License

v3.7: Post-scan verification using Osquery to validate host configurations.
Executes predefined queries via SSH or Fleet API to confirm findings.
"""

import logging
import subprocess
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Predefined verification queries
VERIFICATION_QUERIES = {
    "listening_ports": {
        "query": "SELECT port, protocol, address, pid FROM listening_ports;",
        "description": "Verify open ports match scan results",
    },
    "firewall_rules": {
        "query": "SELECT * FROM iptables WHERE chain = 'INPUT';",
        "description": "Check firewall configuration",
        "platforms": ["linux"],
    },
    "running_services": {
        "query": "SELECT name, status, pid FROM services WHERE status = 'running';",
        "description": "Verify running services",
    },
    "users_logged_in": {
        "query": "SELECT user, type, host FROM logged_in_users;",
        "description": "Active sessions on host",
    },
    "ssh_config": {
        "query": "SELECT * FROM ssh_configs;",
        "description": "SSH server configuration",
        "platforms": ["linux", "darwin"],
    },
    "certificates": {
        "query": "SELECT common_name, issuer, not_valid_after FROM certificates WHERE not_valid_after < datetime('now', '+30 days');",
        "description": "Expiring certificates",
    },
    "vulnerabilities_packages": {
        "query": "SELECT name, version FROM deb_packages WHERE name LIKE '%openssl%' OR name LIKE '%apache%';",
        "description": "Check vulnerable package versions",
        "platforms": ["linux"],
    },
}


def is_osquery_available() -> bool:
    """Check if osqueryi is installed locally."""
    try:
        result = subprocess.run(
            ["osqueryi", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_local_query(query: str, timeout: int = 30) -> Optional[List[Dict]]:
    """
    Execute an Osquery query locally.

    Args:
        query: SQL query
        timeout: Execution timeout

    Returns:
        List of result rows or None on error
    """
    try:
        result = subprocess.run(
            ["osqueryi", "--json", query],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.warning("Osquery failed: %s", result.stderr)
            return None

        import json

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        logger.warning("Osquery timed out after %ds", timeout)
        return None
    except Exception as e:
        logger.warning("Osquery error: %s", e)
        return None


def run_remote_query(
    host: str,
    query: str,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    timeout: int = 60,
) -> Optional[List[Dict]]:
    """
    Execute an Osquery query on a remote host via SSH.

    Args:
        host: Target IP/hostname
        query: SQL query
        ssh_user: SSH username
        ssh_key: Path to SSH private key
        timeout: Execution timeout

    Returns:
        List of result rows or None on error
    """
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])

    ssh_cmd.append(f"{ssh_user}@{host}")
    ssh_cmd.append(f"osqueryi --json '{query}'")

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.debug("SSH/Osquery failed on %s: %s", host, result.stderr[:200])
            return None

        import json

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        logger.debug("SSH/Osquery timed out for %s", host)
        return None
    except Exception as e:
        logger.debug("SSH/Osquery error for %s: %s", host, e)
        return None


def verify_host(
    host: str,
    queries: Optional[List[str]] = None,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run verification queries on a host.

    Args:
        host: Target IP/hostname
        queries: List of query names (defaults to all)
        ssh_user: SSH username
        ssh_key: Path to SSH private key

    Returns:
        Dict with query results and verification status
    """
    results: Dict[str, Any] = {
        "host": host,
        "verified": False,
        "queries": {},
        "errors": [],
    }

    if queries is None:
        queries = list(VERIFICATION_QUERIES.keys())

    for query_name in queries:
        if query_name not in VERIFICATION_QUERIES:
            results["errors"].append(f"Unknown query: {query_name}")
            continue

        query_def = VERIFICATION_QUERIES[query_name]
        query_sql: str = query_def["query"]  # type: ignore[index]

        query_result = run_remote_query(
            host=host,
            query=query_sql,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
        )

        if query_result is not None:
            results["queries"][query_name] = {
                "success": True,
                "rows": len(query_result),
                "data": query_result[:10],  # Limit for report size
            }
        else:
            results["queries"][query_name] = {
                "success": False,
                "error": "Query execution failed",
            }

    # Mark as verified if at least one query succeeded
    successful = sum(1 for q in results["queries"].values() if q.get("success"))
    results["verified"] = successful > 0
    results["success_count"] = successful
    results["total_count"] = len(queries)

    return results


def generate_verification_report(
    hosts: List[str],
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    queries: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Generate a verification report for multiple hosts.

    Args:
        hosts: List of host IPs
        ssh_user: SSH username for all hosts
        ssh_key: Path to SSH private key
        queries: List of query names

    Returns:
        Verification report dict
    """
    report: Dict[str, Any] = {
        "verified_hosts": 0,
        "failed_hosts": 0,
        "hosts": [],
    }

    for host in hosts:
        result = verify_host(
            host=host,
            queries=queries,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
        )
        report["hosts"].append(result)

        if result["verified"]:
            report["verified_hosts"] += 1
        else:
            report["failed_hosts"] += 1

    return report
