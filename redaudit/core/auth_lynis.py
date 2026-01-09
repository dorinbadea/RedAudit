#!/usr/bin/env python3
"""
RedAudit - Lynis Integration (Phase 4.3)
Runs CIS hardening checks on remote Linux hosts via SSH.
"""

import logging
import re
from typing import List, Optional
from dataclasses import dataclass

from redaudit.core.auth_ssh import SSHScanner

logger = logging.getLogger("redaudit.auth_lynis")


@dataclass
class LynisResult:
    hardening_index: int = 0
    warnings: List[str] = None
    suggestions: List[str] = None
    tests_performed: int = 0
    raw_output: str = ""


class LynisScanner:
    """Remote Lynis execution via SSH."""

    def __init__(self, ssh_scanner: SSHScanner):
        self.ssh = ssh_scanner
        self.download_url = "https://github.com/CISOfy/lynis.git"

    def check_lynis_available(self) -> bool:
        """Verify Lynis is installed on target."""
        # Check standard paths
        out, _, code = self.ssh.run_command("which lynis")
        return code == 0

    def install_lynis_temp(self) -> bool:
        """Download Lynis to temp directory for one-time use."""
        # Must have git
        _, _, code = self.ssh.run_command("which git")
        if code != 0:
            logger.warning("Git missing on target, cannot download portable Lynis.")
            return False

        cmd = f"cd /tmp && rm -rf lynis && git clone --depth 1 {self.download_url}"
        out, err, code = self.ssh.run_command(cmd)
        if code != 0:
            logger.warning(f"Failed to clone Lynis: {err}")
            return False
        return True

    def run_audit(
        self, profile: str = "default", use_portable: bool = False
    ) -> Optional[LynisResult]:
        """Execute Lynis audit and parse results."""

        lynis_cmd = "lynis"

        if not self.check_lynis_available():
            if use_portable:
                logger.info("Lynis not found, attempting portable install...")
                if self.install_lynis_temp():
                    lynis_cmd = "/tmp/lynis/lynis"  # nosec B108
                else:
                    return None
            else:
                logger.info("Lynis not found on target.")
                return None

        # Run Audit
        # --quick: non-interactive
        # --no-colors: cleaner parsing
        # --pentest: focused scan (optional, stick to 'audit system' for hardening)
        cmd = f"{lynis_cmd} audit system --quick --no-colors"

        logger.info(f"Running Lynis: {cmd}")
        stdout, stderr, code = self.ssh.run_command(cmd)

        # Lynis returns non-zero often (warnings found), so we check output mainly
        return self._parse_lynis_output(stdout)

    def _parse_lynis_output(self, output: str) -> LynisResult:
        """Parse Lynis text output into structured data."""
        res = LynisResult(warnings=[], suggestions=[])
        res.raw_output = output  # Keep raw just in case, or truncated

        for line in output.splitlines():
            line = line.strip()
            # Hardening index : 65 [#############       ]
            if "Hardening index" in line:
                m = re.search(r"Hardening index\s*:\s*(\d+)", line)
                if m:
                    res.hardening_index = int(m.group(1))

            # Warnings (W)
            if line.startswith("! ["):
                # Warning pattern varies but usually has ID
                res.warnings.append(line)

            # Suggestions (S)
            if line.startswith("* ["):
                res.suggestions.append(line)

            # Tests performed
            if "Tests performed" in line:
                m = re.search(r"Tests performed\s*:\s*(\d+)", line)
                if m:
                    res.tests_performed = int(m.group(1))

        return res
