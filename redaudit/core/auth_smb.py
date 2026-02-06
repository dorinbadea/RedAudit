#!/usr/bin/env python3
"""
RedAudit - SMB/WMI Authenticated Scanner (Phase 4.2)
Uses Impacket to perform authenticated enumeration of Windows hosts.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from redaudit.core.credentials import Credential

# Optional Dependency: Impacket
try:
    from impacket.smbconnection import SMBConnection

    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    SMBConnection = object  # type: ignore

logger = logging.getLogger("redaudit.auth_smb")


@dataclass
class SMBHostInfo:
    os_name: str = "unknown"
    os_version: str = "unknown"
    domain: str = "unknown"
    hostname: str = "unknown"
    shares: List[Dict[str, str]] = None
    users: List[str] = None
    error: Optional[str] = None


class SMBConnectionError(Exception):
    """Raised when SMB connection or authentication fails."""

    pass


class SMBScanner:
    """Authenticated SMB/WMI scanner wrapper."""

    def __init__(self, credential: Credential, timeout: int = 15):
        if not IMPACKET_AVAILABLE:
            raise ImportError("Impacket library not found. Install via 'pip install impacket'.")

        self.credential = credential
        self.timeout = timeout
        self.conn: Optional[SMBConnection] = None
        self.target_ip: Optional[str] = None

    def connect(self, host: str, port: int = 445) -> bool:
        """Establish SMB connection and authenticate."""
        self.target_ip = host
        try:
            # Connect
            # Note: Impacket's SMBConnection first arg is remoteName (hostname), second is remoteHost (IP)
            # If we don't know hostname, we can use IP for both, but some checks might look weird.
            self.conn = SMBConnection(host, host, sess_port=port, timeout=self.timeout)

            # Login
            user = self.credential.username
            password = self.credential.password or ""
            domain = self.credential.domain or ""

            # TODO: Support Hash authentication (LM:NT) if needed
            self.conn.login(user, password, domain=domain)

            logger.info(f"SMB Auth successful for {user}@{host}")
            return True

        except Exception as e:
            logger.debug(f"SMB connection failed to {host}: {e}")
            raise SMBConnectionError(str(e))

    def close(self):
        """Close connection."""
        if self.conn:
            try:
                self.conn.logoff()
            except Exception:
                pass
            # SMBConnection doesn't have explicit close, logoff usually sufficient

    def gather_host_info(self) -> SMBHostInfo:
        """Collect all available info via SMB."""
        if not self.conn:
            raise SMBConnectionError("Not connected")

        info = SMBHostInfo(shares=[], users=[])

        try:
            # 1. OS Info
            info.os_name = self.conn.getServerOS()
            info.os_version = self.conn.getServerOSMajor() + "." + self.conn.getServerOSMinor()
            info.domain = self.conn.getServerDomain()
            info.hostname = self.conn.getServerName()

            # 2. Shares
            try:
                for share in self.conn.listShares():
                    # share is a SharedFile object usually? OR dict?
                    # Impacket listShares returns list of SharedFile
                    # SharedFile.get_name()

                    # Wait, listShares returns a list of SharedFile instances which have .name?
                    # Looking at impacket docs/source: returns list of SharedFile
                    name_val = share["shi1_netname"]
                    if isinstance(name_val, bytes):
                        name = name_val.decode("utf-8", errors="replace").rstrip("\0")
                    else:
                        name = str(name_val).rstrip("\0")

                    remark_val = share["shi1_remark"]
                    if isinstance(remark_val, bytes):
                        remark = remark_val.decode("utf-8", errors="replace").rstrip("\0")
                    else:
                        remark = str(remark_val).rstrip("\0")

                    type_val = share["shi1_type"]

                    info.shares.append({"name": name, "remark": remark, "type": str(type_val)})
            except Exception as e:
                logger.warning(f"Failed to list shares on {self.target_ip}: {e}")

            # 3. Users (via RPC if possible, skipped for lightweight MVP validation)
            # Keeping it simple for MVP phase 4.2

            return info

        except Exception as e:
            info.error = str(e)
            return info
