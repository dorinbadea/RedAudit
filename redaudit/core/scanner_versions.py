#!/usr/bin/env python3
"""
RedAudit - Scanner Versions Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.1: Detect and report versions of external scanning tools.
"""

import shutil
import subprocess
import re
from typing import Dict, Optional

from redaudit.utils.constants import VERSION


# Tool detection configuration
TOOL_CONFIGS = {
    "nmap": {
        "names": ["nmap"],
        "version_args": ["--version"],
        "pattern": r"Nmap version ([\d.]+)",
    },
    "nikto": {
        "names": ["nikto"],
        "version_args": ["-Version"],
        "pattern": r"Nikto v?([\d.]+)",
    },
    "testssl": {
        "names": ["testssl.sh", "testssl"],
        "version_args": ["--version"],
        "pattern": r"testssl\.sh ([\d.]+)",
    },
    "whatweb": {
        "names": ["whatweb"],
        "version_args": ["--version"],
        "pattern": r"WhatWeb version ([\d.]+)",
    },
    "searchsploit": {
        "names": ["searchsploit"],
        "version_args": ["--version"],
        "pattern": r"searchsploit ([\d.]+)",
    },
}


def _get_tool_version(tool_name: str, config: dict) -> Optional[str]:
    """
    Get version string for a specific tool.
    
    Args:
        tool_name: Name of the tool
        config: Tool configuration dict with names, version_args, pattern
        
    Returns:
        Version string or None if tool not found
    """
    # Find the tool binary
    tool_path = None
    for name in config["names"]:
        path = shutil.which(name)
        if path:
            tool_path = path
            break
    
    if not tool_path:
        return None
    
    try:
        result = subprocess.run(
            [tool_path] + config["version_args"],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + result.stderr
        
        match = re.search(config["pattern"], output, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Fallback: return "detected" if tool exists but version unknown
        return "detected"
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        # Tool exists but version detection failed
        return "detected"


def get_scanner_versions() -> Dict[str, str]:
    """
    Detect versions of all scanning tools used by RedAudit.
    
    Returns:
        Dictionary with tool names and their versions.
        Only includes tools that are detected on the system.
    """
    versions = {
        "redaudit": VERSION,
    }
    
    for tool_name, config in TOOL_CONFIGS.items():
        version = _get_tool_version(tool_name, config)
        if version:
            versions[tool_name] = version
    
    return versions
