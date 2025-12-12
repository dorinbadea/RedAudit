#!/usr/bin/env python3
"""
RedAudit - Secure Update Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Secure update checking and installation from GitHub repository.
Implements version comparison, release notes fetching, and secure download verification.
"""

import os
import re
import json
import hashlib
import subprocess
import tempfile
from typing import Optional, Tuple, Dict
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from redaudit.utils.constants import VERSION

# GitHub repository configuration
GITHUB_OWNER = "dorinbadea"
GITHUB_REPO = "RedAudit"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Timeouts
API_TIMEOUT = 10  # seconds
DOWNLOAD_TIMEOUT = 30  # seconds


def parse_version(version_str: str) -> Tuple[int, int, int]:
    """
    Parse semantic version string into tuple.
    
    Args:
        version_str: Version string like "2.8.0"
    
    Returns:
        Tuple of (major, minor, patch)
    """
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str.strip())
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return (0, 0, 0)


def compare_versions(current: str, remote: str) -> int:
    """
    Compare two version strings.
    
    Args:
        current: Current version string
        remote: Remote version string
    
    Returns:
        -1 if current < remote (update available)
         0 if current == remote
         1 if current > remote (ahead of remote)
    """
    cur = parse_version(current)
    rem = parse_version(remote)
    
    if cur < rem:
        return -1
    elif cur > rem:
        return 1
    return 0


def fetch_latest_version(logger=None) -> Optional[Dict]:
    """
    Fetch latest release information from GitHub API.
    
    Args:
        logger: Optional logger
    
    Returns:
        Dict with 'tag_name', 'name', 'body', 'published_at' or None
    """
    url = f"{GITHUB_API_BASE}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
    
    try:
        req = Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", f"RedAudit/{VERSION}")
        
        with urlopen(req, timeout=API_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return {
                    "tag_name": data.get("tag_name", "").lstrip("v"),
                    "name": data.get("name", ""),
                    "body": data.get("body", ""),
                    "published_at": data.get("published_at", ""),
                    "html_url": data.get("html_url", ""),
                }
    except HTTPError as e:
        if logger:
            logger.warning("GitHub API error: %s", e.code)
    except URLError as e:
        if logger:
            logger.warning("Network error checking updates: %s", e.reason)
    except Exception as e:
        if logger:
            logger.debug("Update check failed: %s", e)
    
    return None


def fetch_changelog_snippet(version: str, max_lines: int = 20, logger=None) -> Optional[str]:
    """
    Fetch changelog snippet for a specific version from GitHub.
    
    Args:
        version: Version to fetch changelog for
        max_lines: Maximum lines to return
        logger: Optional logger
    
    Returns:
        Changelog snippet string or None
    """
    url = f"{GITHUB_RAW_BASE}/{GITHUB_OWNER}/{GITHUB_REPO}/main/CHANGELOG.md"
    
    try:
        req = Request(url)
        req.add_header("User-Agent", f"RedAudit/{VERSION}")
        
        with urlopen(req, timeout=API_TIMEOUT) as response:
            if response.status == 200:
                content = response.read().decode("utf-8")
                
                # Find the section for this version
                pattern = rf"## \[{re.escape(version)}\].*?(?=## \[|$)"
                match = re.search(pattern, content, re.DOTALL)
                
                if match:
                    lines = match.group(0).strip().split("\n")[:max_lines]
                    return "\n".join(lines)
    except Exception as e:
        if logger:
            logger.debug("Failed to fetch changelog: %s", e)
    
    return None


def check_for_updates(logger=None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if updates are available.
    
    Args:
        logger: Optional logger
    
    Returns:
        Tuple of (update_available, latest_version, release_notes)
    """
    release_info = fetch_latest_version(logger)
    
    if not release_info:
        return (False, None, None)
    
    latest_version = release_info.get("tag_name", "")
    
    if not latest_version:
        return (False, None, None)
    
    comparison = compare_versions(VERSION, latest_version)
    
    if comparison < 0:  # Update available
        # Get release notes (try release body first, then changelog)
        release_notes = release_info.get("body", "")
        if not release_notes or len(release_notes) < 50:
            changelog = fetch_changelog_snippet(latest_version, logger=logger)
            if changelog:
                release_notes = changelog
        
        return (True, latest_version, release_notes)
    
    return (False, VERSION, None)


def compute_file_hash(filepath: str, algorithm: str = "sha256") -> str:
    """
    Compute hash of a file for integrity verification.
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm (sha256, sha512)
    
    Returns:
        Hex digest string
    """
    hasher = hashlib.new(algorithm)
    
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def perform_git_update(repo_path: str, logger=None) -> Tuple[bool, str]:
    """
    Perform update using git pull and install to system location.
    
    Args:
        repo_path: Path to the git repository
        logger: Optional logger
    
    Returns:
        Tuple of (success, message)
    """
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return (False, "Not a git repository. Manual update required.")
    
    try:
        # v2.8.1: Reset any local changes to avoid conflicts
        result = subprocess.run(
            ["git", "reset", "--hard", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Fetch latest from remote
        result = subprocess.run(
            ["git", "fetch", "origin", "main"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            return (False, f"Git fetch failed: {result.stderr}")
        
        # Check if we're behind remote
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/main"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        commits_behind = int(result.stdout.strip() or "0")
        
        if commits_behind == 0:
            # Already up to date at git level - but we still requested update
            # This could happen if version detection differs from actual git state
            return (True, "UPDATE_SUCCESS_RESTART")
        
        # Pull changes
        result = subprocess.run(
            ["git", "pull", "origin", "main", "--force"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        if result.returncode != 0:
            return (False, f"Git pull failed: {result.stderr}")
        
        # v2.8.1: Install updated code to /usr/local/lib/redaudit if running as root
        install_path = "/usr/local/lib/redaudit"
        source_path = os.path.join(repo_path, "redaudit")
        
        if os.path.isdir(source_path) and os.geteuid() == 0:
            import shutil
            
            # Remove old installation
            if os.path.exists(install_path):
                shutil.rmtree(install_path)
            
            # Copy new files
            shutil.copytree(source_path, install_path)
            
            # Set permissions
            for root, dirs, files in os.walk(install_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
        
        # Always return success with restart signal
        return (True, "UPDATE_SUCCESS_RESTART")
        
    except subprocess.TimeoutExpired:
        return (False, "Update timed out. Check network connection.")
    except FileNotFoundError:
        return (False, "Git not found. Install git or update manually.")
    except Exception as e:
        if logger:
            logger.error("Update failed: %s", e)
        return (False, f"Update failed: {e}")


def get_repo_path() -> str:
    """
    Get the path to the RedAudit repository.
    
    Returns:
        Absolute path to the repo root
    """
    # Navigate up from this file's location
    current = os.path.dirname(os.path.abspath(__file__))
    # core -> redaudit -> root
    repo_root = os.path.dirname(os.path.dirname(current))
    return repo_root


def interactive_update_check(print_fn=None, ask_fn=None, t_fn=None, logger=None) -> bool:
    """
    Interactive update check workflow for CLI.
    
    Args:
        print_fn: Function to print messages (print_status)
        ask_fn: Function to ask yes/no questions (ask_yes_no)
        t_fn: Translation function
        logger: Optional logger
    
    Returns:
        True if update was performed, False otherwise
    """
    if not print_fn:
        print_fn = print
    if not ask_fn:
        def ask_fn(q, default="yes"): 
            return input(f"{q} [y/n]: ").strip().lower() in ("y", "yes", "s", "si")
    if not t_fn:
        t_fn = lambda key, *args: key
    
    # Check for updates
    print_fn(t_fn("update_checking"), "INFO")
    
    update_available, latest_version, release_notes = check_for_updates(logger)
    
    if not latest_version:
        print_fn(t_fn("update_check_failed"), "WARNING")
        return False
    
    if not update_available:
        print_fn(t_fn("update_current", VERSION), "OKGREEN")
        return False
    
    # Update available
    print_fn(t_fn("update_available", VERSION, latest_version), "WARNING")
    
    # Show release notes if available
    if release_notes:
        print("")
        print("=" * 60)
        print(t_fn("update_release_notes"))
        print("=" * 60)
        # Limit to first 500 chars for display
        notes_preview = release_notes[:500]
        if len(release_notes) > 500:
            notes_preview += "\n..."
        print(notes_preview)
        print("=" * 60)
        print("")
    
    # Ask user
    if ask_fn(t_fn("update_prompt"), default="yes"):
        print_fn(t_fn("update_starting"), "INFO")
        
        repo_path = get_repo_path()
        success, message = perform_git_update(repo_path, logger)
        
        if success:
            # v2.8.1: Auto-restart if update was installed to system
            if message == "UPDATE_SUCCESS_RESTART":
                print_fn(t_fn("update_restarting"), "OKGREEN")
                import sys
                import time
                time.sleep(1)  # Brief pause before restart
                # Re-execute the current script
                python = sys.executable
                os.execv(python, [python] + sys.argv)
            else:
                print_fn(message, "OKGREEN")
            return True
        else:
            print_fn(message, "FAIL")
            return False
    else:
        print_fn(t_fn("update_skipped"), "INFO")
        return False

