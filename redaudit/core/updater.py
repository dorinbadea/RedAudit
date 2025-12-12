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


def perform_git_update(repo_path: str, lang: str = "en", logger=None) -> Tuple[bool, str]:
    """
    v3.0: Perform update using git clone approach for reliability.
    
    This method addresses issues with git pull failures by:
    1. Cloning fresh to a temp folder
    2. Running the install script with user's language
    3. Copying to user's home folder with all documentation
    4. Verifying installation
    
    Args:
        repo_path: Original repo path (used for reference, not modified)
        lang: User's language preference ('en' or 'es')
        logger: Optional logger
    
    Returns:
        Tuple of (success, message)
    """
    import shutil
    
    GITHUB_CLONE_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}.git"
    home_dir = os.path.expanduser("~")
    home_redaudit_path = os.path.join(home_dir, "RedAudit")
    install_path = "/usr/local/lib/redaudit"
    
    try:
        # Step 1: Clone to temporary directory
        temp_dir = tempfile.mkdtemp(prefix="redaudit_update_")
        clone_path = os.path.join(temp_dir, "RedAudit")
        
        if logger:
            logger.info("Cloning RedAudit to temp folder: %s", temp_dir)
        
        result = subprocess.run(
            ["git", "clone", "--depth", "1", GITHUB_CLONE_URL, clone_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return (False, f"Git clone failed: {result.stderr}")
        
        # Step 2: Run install script with user's language
        install_script = os.path.join(clone_path, "redaudit_install.sh")
        
        if os.path.isfile(install_script) and os.geteuid() == 0:
            if logger:
                logger.info("Running install script with language: %s", lang)
            
            # Make script executable
            os.chmod(install_script, 0o755)
            
            # Run install script
            env = os.environ.copy()
            env["REDAUDIT_LANG"] = lang
            env["REDAUDIT_AUTO_UPDATE"] = "1"  # Flag to skip prompts
            
            result = subprocess.run(
                ["bash", install_script],
                cwd=clone_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes max
            )
            
            if result.returncode != 0:
                if logger:
                    logger.warning("Install script returned non-zero: %s", result.stderr)
                # Continue anyway, we'll do manual installation
        
        # Step 3: Manual installation to /usr/local/lib/redaudit
        source_module = os.path.join(clone_path, "redaudit")
        
        if os.path.isdir(source_module) and os.geteuid() == 0:
            if logger:
                logger.info("Installing to %s", install_path)
            
            # Remove old installation
            if os.path.exists(install_path):
                shutil.rmtree(install_path)
            
            # Copy new files
            shutil.copytree(source_module, install_path)
            
            # Set permissions
            for root, dirs, files in os.walk(install_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
        
        # Step 4: Copy to user's home folder with documentation
        if logger:
            logger.info("Copying to home folder: %s", home_redaudit_path)
        
        # Backup existing if present
        if os.path.exists(home_redaudit_path):
            backup_path = f"{home_redaudit_path}_backup_{int(__import__('time').time())}"
            shutil.move(home_redaudit_path, backup_path)
            if logger:
                logger.info("Backed up existing to: %s", backup_path)
        
        # Copy entire clone (including docs) to home
        shutil.copytree(clone_path, home_redaudit_path)
        
        # Fix ownership if running as root
        if os.geteuid() == 0:
            import pwd
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                try:
                    user_info = pwd.getpwnam(sudo_user)
                    for root, dirs, files in os.walk(home_redaudit_path):
                        os.chown(root, user_info.pw_uid, user_info.pw_gid)
                        for d in dirs:
                            os.chown(os.path.join(root, d), user_info.pw_uid, user_info.pw_gid)
                        for f in files:
                            os.chown(os.path.join(root, f), user_info.pw_uid, user_info.pw_gid)
                except Exception as e:
                    if logger:
                        logger.warning("Could not fix ownership: %s", e)
        
        # Step 5: Verify installation
        verification_passed = True
        verification_errors = []
        
        # Check that main module exists
        if not os.path.isdir(install_path):
            verification_passed = False
            verification_errors.append("Module not installed to /usr/local/lib")
        
        # Check that key files exist
        key_files = ["__init__.py", "cli.py", "core/auditor.py"]
        for key_file in key_files:
            if not os.path.isfile(os.path.join(install_path, key_file)):
                verification_passed = False
                verification_errors.append(f"Missing file: {key_file}")
        
        # Check home copy
        if not os.path.isdir(home_redaudit_path):
            verification_passed = False
            verification_errors.append("Home copy not created")
        
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        if not verification_passed:
            return (False, f"Installation verification failed: {'; '.join(verification_errors)}")
        
        # Success!
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


def interactive_update_check(print_fn=None, ask_fn=None, t_fn=None, logger=None, lang: str = "en") -> bool:
    """
    Interactive update check workflow for CLI.
    
    v3.0: Now accepts lang parameter for install script.
    
    Args:
        print_fn: Function to print messages (print_status)
        ask_fn: Function to ask yes/no questions (ask_yes_no)
        t_fn: Translation function
        logger: Optional logger
        lang: User's language preference ('en' or 'es')
    
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
        # v3.0: Pass language to perform_git_update
        success, message = perform_git_update(repo_path, lang=lang, logger=logger)
        
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


