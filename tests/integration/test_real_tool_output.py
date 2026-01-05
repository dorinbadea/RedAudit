#!/usr/bin/env python3
"""
RedAudit - Opt-in integration checks against real tool output.
"""

import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from redaudit.core.agentless_verify import parse_http_probe


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.integration
def test_parse_http_probe_with_real_nmap_output():
    if os.environ.get("REDAUDIT_REAL_TOOLS") != "1":
        pytest.skip("Set REDAUDIT_REAL_TOOLS=1 to run real tool output checks.")
    if shutil.which("nmap") is None:
        pytest.skip("nmap not available for real output checks.")

    port = _get_free_port()
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.3)
        result = subprocess.run(
            [
                "nmap",
                "-sT",
                "-Pn",
                "-sV",
                "-p",
                str(port),
                "--script",
                "http-title,http-server-header",
                "127.0.0.1",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        parsed = parse_http_probe(result.stdout + "\n" + result.stderr)
        assert "title" in parsed
        assert "server" in parsed
        assert "Directory listing" in parsed["title"]
        assert "SimpleHTTP" in parsed["server"]
    finally:
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
