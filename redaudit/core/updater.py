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
from typing import Optional, Tuple, Dict, List
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


def _iter_files(root_dir: str) -> List[str]:
    """
    Return sorted relative file paths under root_dir.

    Excludes common Python cache artifacts.
    """
    root_dir = os.path.abspath(root_dir)
    rel_paths: List[str] = []
    for root, dirs, files in os.walk(root_dir):
        # Skip Python cache directories
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f.endswith((".pyc", ".pyo")):
                continue
            abs_path = os.path.join(root, f)
            rel_paths.append(os.path.relpath(abs_path, root_dir))
    return sorted(set(rel_paths))


def compute_tree_diff(old_dir: str, new_dir: str) -> Dict[str, List[str]]:
    """
    Compute a simple diff between two directory trees.

    Returns:
        Dict with keys: added, removed, modified (lists of relative file paths)
    """
    old_dir = os.path.abspath(old_dir)
    new_dir = os.path.abspath(new_dir)

    old_files = set(_iter_files(old_dir)) if os.path.isdir(old_dir) else set()
    new_files = set(_iter_files(new_dir)) if os.path.isdir(new_dir) else set()

    added = sorted(new_files - old_files)
    removed = sorted(old_files - new_files)
    common = sorted(old_files & new_files)

    modified: List[str] = []
    for rel_path in common:
        old_path = os.path.join(old_dir, rel_path)
        new_path = os.path.join(new_dir, rel_path)
        try:
            if os.path.getsize(old_path) != os.path.getsize(new_path):
                modified.append(rel_path)
                continue
            if compute_file_hash(old_path) != compute_file_hash(new_path):
                modified.append(rel_path)
        except Exception:
            # If we can't compare, assume modified
            modified.append(rel_path)

    return {"added": added, "removed": removed, "modified": sorted(modified)}


def _inject_default_lang(constants_file: str, lang: str) -> bool:
    """
    Inject DEFAULT_LANG into a constants.py file.

    Returns True if the file was modified or already had the desired value.
    """
    if lang not in ("en", "es"):
        lang = "en"
    try:
        if not os.path.isfile(constants_file):
            return False
        content = ""
        with open(constants_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Replace DEFAULT_LANG assignment line
        pattern = re.compile(r'^DEFAULT_LANG\s*=\s*["\'].*?["\']\s*$', re.MULTILINE)
        replacement = f'DEFAULT_LANG = "{lang}"'
        if pattern.search(content):
            new_content = pattern.sub(replacement, content, count=1)
        else:
            # If missing, append (should not happen, but keep robust)
            new_content = content.rstrip() + "\n\n" + replacement + "\n"

        if new_content != content:
            with open(constants_file, "w", encoding="utf-8") as f:
                f.write(new_content)
        return True
    except Exception:
        return False


def perform_git_update(
    repo_path: str,
    lang: str = "en",
    target_version: Optional[str] = None,
    logger=None,
    print_fn=None,
    t_fn=None,
) -> Tuple[bool, str]:
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

    if print_fn is None:
        def print_fn(msg, _status=None):  # type: ignore[no-redef]
            print(msg, flush=True)
    if t_fn is None:
        t_fn = lambda key, *args: key.format(*args) if args else key  # noqa: E731

    GITHUB_CLONE_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}.git"
    target_version = target_version or VERSION
    target_ref = f"v{target_version}"
    sudo_user = os.environ.get("SUDO_USER")
    target_home_dir = os.path.expanduser("~")
    target_uid = None
    target_gid = None
    if os.geteuid() == 0 and sudo_user:
        try:
            import pwd

            user_info = pwd.getpwnam(sudo_user)
            target_home_dir = user_info.pw_dir
            target_uid = user_info.pw_uid
            target_gid = user_info.pw_gid
        except Exception:
            target_home_dir = os.path.expanduser("~")

    home_redaudit_path = os.path.join(target_home_dir, "RedAudit")
    install_path = "/usr/local/lib/redaudit"
    
    try:
        # Step 1: Determine target commit for the current version tag
        try:
            git_env = os.environ.copy()
            git_env["GIT_TERMINAL_PROMPT"] = "0"
            git_env["GIT_ASKPASS"] = "echo"
            ls_remote = subprocess.check_output(
                ["git", "ls-remote", "--exit-code", GITHUB_CLONE_URL, target_ref],
                text=True,
                timeout=15,
                env=git_env,
            ).strip()
            expected_commit = ls_remote.split()[0]
        except Exception:
            return (False, f"Could not resolve tag {target_ref} from GitHub.")

        print_fn(f"  → Target ref: {target_ref}", "INFO")
        print_fn(f"  → Target commit: {expected_commit}", "INFO")

        # Step 2: Clone to temporary directory pinned to the tag
        temp_dir = tempfile.mkdtemp(prefix="redaudit_update_")
        clone_path = os.path.join(temp_dir, "RedAudit")
        print_fn(f"  → Temp directory: {temp_dir}", "INFO")
        print_fn(f"  → Clone path: {clone_path}", "INFO")
        
        if logger:
            logger.info("Cloning RedAudit to temp folder: %s", temp_dir)
        
        print_fn("  → Cloning from GitHub...", "INFO")
        
        # Ensure git doesn't prompt for credentials or any interaction
        git_env = os.environ.copy()
        git_env["GIT_TERMINAL_PROMPT"] = "0"
        git_env["GIT_ASKPASS"] = "echo"
        
        # Use Popen for real-time output instead of blocking run
        process = subprocess.Popen(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                target_ref,
                "--progress",
                GITHUB_CLONE_URL,
                clone_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=git_env,
            stdin=subprocess.DEVNULL,
        )
        
        # Read output with timeout monitoring
        import time
        start_time = time.time()
        output_lines = []
        
        while True:
            # Check timeout
            if time.time() - start_time > 120:
                process.kill()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return (False, "Git clone timed out after 120 seconds")
            
            line = process.stdout.readline()
            if line:
                output_lines.append(line)
                # Print progress indicators
                if "Receiving objects:" in line or "Resolving deltas:" in line:
                    print(f"  → {line.strip()}", flush=True)
            elif process.poll() is not None:
                break
        
        returncode = process.wait()
        
        if returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return (False, f"Git clone failed: {''.join(output_lines[-5:])}")
        
        # Verify pinned commit
        cloned_commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=clone_path, text=True
            ).strip()
            if os.path.isdir(clone_path)
            else "unknown"
        )

        if cloned_commit != expected_commit:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return (
                False,
                f"Clone verification failed (expected {expected_commit}, got {cloned_commit})",
            )

        print_fn("  → Clone complete and verified!", "OKGREEN")
        
        # Step 2: Run install script with user's language
        install_script = os.path.join(clone_path, "redaudit_install.sh")
        
        if os.path.isfile(install_script) and os.geteuid() == 0:
            if logger:
                logger.info("Running install script with language: %s", lang)
            print_fn(f"  → Running installer script (lang={lang}, auto-update=1)", "INFO")
            
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
                print_fn("  → Installer script returned non-zero; continuing with manual install", "WARNING")
                if logger:
                    logger.warning("Install script returned non-zero: %s", result.stderr)
                # Continue anyway, we'll do manual installation
            else:
                print_fn("  → Installer script completed", "OKGREEN")
        
        # Step 3: Manual installation to /usr/local/lib/redaudit
        source_module = os.path.join(clone_path, "redaudit")
        
        if os.path.isdir(source_module) and os.geteuid() == 0:
            if logger:
                logger.info("Installing to %s", install_path)

            # Show file-level changes vs existing system install (if present)
            if os.path.isdir(install_path):
                try:
                    diff = compute_tree_diff(install_path, source_module)
                    print_fn(
                        f"  → System install changes: +{len(diff['added'])} "
                        f"~{len(diff['modified'])} -{len(diff['removed'])}",
                        "INFO",
                    )
                    for label in ("added", "modified", "removed"):
                        items = diff[label]
                        if not items:
                            continue
                        preview = items[:25]
                        print(f"    {label.upper()} ({len(items)}):")
                        for p in preview:
                            print(f"      - {p}")
                        if len(items) > len(preview):
                            print(f"      ... ({len(items) - len(preview)} more)")
                except Exception:
                    pass
            
            # Remove old installation
            if os.path.exists(install_path):
                print_fn(f"  → Removing old system install: {install_path}", "WARNING")
                shutil.rmtree(install_path)
            
            # Copy new files
            print_fn(f"  → Installing new system files: {install_path}", "INFO")
            shutil.copytree(source_module, install_path)

            # Preserve language preference (manual install overwrites installer injection)
            constants_file = os.path.join(install_path, "utils", "constants.py")
            if _inject_default_lang(constants_file, lang):
                print_fn(f"  → Default language preserved: {lang}", "OKGREEN")
            
            # Set permissions
            for root, dirs, files in os.walk(install_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
        elif os.geteuid() != 0:
            print_fn("  → Skipping system install (not running as root)", "WARNING")

        # Step 4: Refuse to overwrite local changes in home repo (if present)
        if os.path.isdir(home_redaudit_path) and os.path.isdir(os.path.join(home_redaudit_path, ".git")):
            try:
                status = subprocess.check_output(
                    ["git", "status", "--porcelain"],
                    cwd=home_redaudit_path,
                    text=True,
                    timeout=10,
                    env=git_env,
                ).strip()
                if status:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return (
                        False,
                        f"Local changes detected in {home_redaudit_path}. Commit/stash or remove the folder before updating.",
                    )
            except Exception:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return (
                    False,
                    f"Could not verify local changes in {home_redaudit_path}. Update aborted for safety.",
                )

        # Step 5: Copy to user's home folder with documentation
        if logger:
            logger.info("Copying to home folder: %s", home_redaudit_path)
        print_fn(f"  → Updating home folder copy: {home_redaudit_path}", "INFO")
        
        # Backup existing if present
        if os.path.exists(home_redaudit_path):
            backup_path = f"{home_redaudit_path}_backup_{int(__import__('time').time())}"
            print_fn(f"  → Backing up home folder: {home_redaudit_path} → {backup_path}", "WARNING")
            shutil.move(home_redaudit_path, backup_path)
            if logger:
                logger.info("Backed up existing to: %s", backup_path)
        
        # Copy entire clone (including docs) to home
        shutil.copytree(clone_path, home_redaudit_path)

        # Keep home copy consistent with language preference (useful for local runs/docs).
        home_constants_file = os.path.join(home_redaudit_path, "redaudit", "utils", "constants.py")
        _inject_default_lang(home_constants_file, lang)
        
        # Fix ownership if running as root
        if os.geteuid() == 0 and target_uid is not None and target_gid is not None:
            try:
                for root, dirs, files in os.walk(home_redaudit_path):
                    os.chown(root, target_uid, target_gid)
                    for d in dirs:
                        os.chown(os.path.join(root, d), target_uid, target_gid)
                    for f in files:
                        os.chown(os.path.join(root, f), target_uid, target_gid)
            except Exception as e:
                if logger:
                    logger.warning("Could not fix ownership: %s", e)
        
        # Step 6: Verify installation
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
        # v3.0: Pass language and target version to perform_git_update
        success, message = perform_git_update(
            repo_path,
            lang=lang,
            target_version=latest_version,
            logger=logger,
            print_fn=print_fn,
            t_fn=t_fn,
        )
        
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
