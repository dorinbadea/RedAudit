#!/usr/bin/env python3
"""
RedAudit - Reliable Update Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

Reliable update checking and installation from GitHub repository.
Implements version comparison, release notes fetching, and verified tag checkout.

Note: This module verifies that cloned commits match expected git refs (ls-remote),
but does NOT perform cryptographic signature verification of tags or releases.
"""

import os
import sys
import re
import json
import hashlib
import subprocess
import tempfile
import textwrap
from typing import Optional, Tuple, Dict, List, Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from redaudit.utils.constants import VERSION
from redaudit.core.command_runner import CommandRunner

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


def fetch_changelog_snippet(
    version: str, max_lines: int = 40, logger=None, lang: str = "en"
) -> Optional[Tuple[str, str]]:
    """
    Fetch changelog snippet for a specific version from GitHub.

    Args:
        version: Version to fetch changelog for
        max_lines: Maximum lines to return
        logger: Optional logger
        lang: Preferred language ('en' or 'es')

    Returns:
        Changelog snippet string or None
    """
    filename = "CHANGELOG_ES.md" if lang == "es" else "CHANGELOG.md"
    urls: List[Tuple[str, str]] = [
        (f"{GITHUB_RAW_BASE}/{GITHUB_OWNER}/{GITHUB_REPO}/main/{filename}", lang)
    ]
    if filename != "CHANGELOG.md":
        urls.append((f"{GITHUB_RAW_BASE}/{GITHUB_OWNER}/{GITHUB_REPO}/main/CHANGELOG.md", "en"))

    try:
        for url, used_lang in urls:
            req = Request(url)
            req.add_header("User-Agent", f"RedAudit/{VERSION}")

            with urlopen(req, timeout=API_TIMEOUT) as response:
                if response.status != 200:
                    continue
                content = response.read().decode("utf-8")

            # Find the section for this version
            pattern = rf"## \[{re.escape(version)}\].*?(?=## \[|$)"
            match = re.search(pattern, content, re.DOTALL)

            if match:
                lines = match.group(0).strip().split("\n")[:max_lines]
                return ("\n".join(lines), used_lang)
    except Exception as e:
        if logger:
            logger.debug("Failed to fetch changelog: %s", e)

    return None


def check_for_updates(
    logger=None, lang: str = "en"
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Check if updates are available.

    Args:
        logger: Optional logger
        lang: Preferred language ('en' or 'es')

    Returns:
        Tuple of (update_available, latest_version, release_notes, release_url, published_at, notes_lang)
    """
    release_info = fetch_latest_version(logger)

    if not release_info:
        return (False, None, None, None, None, None)

    latest_version = release_info.get("tag_name", "")
    release_url = release_info.get("html_url", "") or None
    published_at = release_info.get("published_at", "") or None

    if not latest_version:
        return (False, None, None, None, published_at, None)

    comparison = compare_versions(VERSION, latest_version)

    if comparison < 0:  # Update available
        # Prefer changelog section (compact + language-specific), then fall back to release body.
        notes_lang = None
        snippet = fetch_changelog_snippet(latest_version, logger=logger, lang=lang)
        release_notes = (snippet[0] if snippet else "").strip()
        notes_lang = snippet[1] if snippet else None
        if not release_notes:
            release_notes = (release_info.get("body", "") or "").strip()
            # GitHub release bodies are typically English; leave notes_lang unknown.
            notes_lang = notes_lang or None

        return (True, latest_version, release_notes or None, release_url, published_at, notes_lang)

    return (False, VERSION, None, None, published_at, None)


def _parse_published_date(published_at: Optional[str]) -> Optional[str]:
    if not published_at:
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})", str(published_at).strip())
    return m.group(1) if m else None


def _extract_release_date_from_notes(notes: str, version: str) -> Optional[str]:
    if not notes:
        return None
    try:
        m = re.search(
            rf"^##\s*\[{re.escape(version)}\]\s*-\s*(\d{{4}}-\d{{2}}-\d{{2}})",
            notes,
            flags=re.MULTILINE,
        )
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _classify_release_type(current: str, latest: str) -> str:
    cur = parse_version(current)
    lat = parse_version(latest)
    if lat[0] > cur[0]:
        return "Major"
    if lat[1] > cur[1]:
        return "Minor"
    return "Patch"


def _extract_release_items(notes: str) -> Dict[str, Any]:
    """
    Extract structured items from a changelog/release notes Markdown block.

    Returns:
        Dict with keys: highlights (list), breaking (list)
    """
    if not notes:
        return {"highlights": [], "breaking": []}

    def normalize_heading(text: str) -> str:
        h = _strip_markdown_inline(text).strip().strip(":").lower()
        h = (
            h.replace("ó", "o")
            .replace("í", "i")
            .replace("á", "a")
            .replace("é", "e")
            .replace("ú", "u")
            .replace("ñ", "n")
        )
        mapping = {
            "added": "added",
            "anadido": "added",
            "changed": "changed",
            "cambiado": "changed",
            "fixed": "fixed",
            "corregido": "fixed",
            "security": "security",
            "seguridad": "security",
            "removed": "removed",
            "eliminado": "removed",
            "deprecated": "deprecated",
            "obsoleto": "deprecated",
            "breaking": "breaking",
            "breaking changes": "breaking",
            "cambios incompatibles": "breaking",
            "incompatible": "breaking",
            "incompatibles": "breaking",
        }
        return mapping.get(h, h)

    def should_drop(item: str) -> bool:
        low = item.lower()
        if "shields.io" in low:
            return True
        if "view in english" in low or "ver en español" in low:
            return True
        if "view in spanish" in low or "ver en ingles" in low:
            return True
        if re.fullmatch(r"https?://\\S+", item.strip()):
            return True
        return False

    current_section = "other"
    items: Dict[str, List[str]] = {
        "security": [],
        "added": [],
        "changed": [],
        "fixed": [],
        "removed": [],
        "deprecated": [],
        "breaking": [],
        "other": [],
    }

    lines = notes.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        h = re.match(r"^#{2,6}\s+(.*)$", line)
        if h:
            current_section = normalize_heading(h.group(1))
            continue

        m = re.match(r"^[-*•]\s+(.*)$", line) or re.match(r"^\d+\.\s+(.*)$", line)
        if not m:
            continue

        item = _strip_markdown_inline(m.group(1)).strip()
        if not item or should_drop(item):
            continue
        if current_section in items:
            items[current_section].append(item)
        else:
            items["other"].append(item)

    highlights: List[str] = []
    for section in ("security", "added", "changed", "fixed"):
        for item in items.get(section, []):
            if item not in highlights:
                highlights.append(item)

    if not highlights:
        for item in items.get("other", []):
            if item not in highlights:
                highlights.append(item)

    return {"highlights": highlights, "breaking": items.get("breaking", [])}


def render_update_summary_for_cli(
    *,
    current_version: str,
    latest_version: str,
    release_notes: Optional[str],
    release_url: Optional[str],
    published_at: Optional[str],
    lang: str,
    t_fn,
    notes_lang: Optional[str] = None,
    max_items: int = 10,
    max_breaking: int = 5,
) -> str:
    """
    Render a concise, terminal-friendly update summary (no raw Markdown).
    """
    try:
        import shutil

        width = shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else 100
        width = max(60, min(int(width), 120))
    except Exception:
        width = 100

    release_type = _classify_release_type(current_version, latest_version)
    release_date = _parse_published_date(published_at) or _extract_release_date_from_notes(
        release_notes or "", latest_version
    )

    extracted = _extract_release_items(release_notes or "")
    highlights = (extracted.get("highlights") or [])[: max(1, int(max_items))]
    breaking = (extracted.get("breaking") or [])[: max(0, int(max_breaking))]

    lines: List[str] = []
    if release_date:
        lines.append(t_fn("update_release_date", release_date))
    lines.append(t_fn("update_release_type", release_type))
    lines.append(t_fn("update_highlights"))
    for item in highlights:
        lines.append(f"- {item}")
    if breaking:
        lines.append(t_fn("update_breaking_changes"))
        for item in breaking:
            lines.append(f"- {item}")

    if notes_lang and notes_lang != lang:
        # Keep the note minimal; avoid mixing languages inside highlights.
        if notes_lang == "en":
            lines.append(t_fn("update_notes_fallback_en"))
        elif notes_lang == "es":
            lines.append(t_fn("update_notes_fallback_es"))

    if release_url:
        lines.append(t_fn("update_release_url", release_url))

    # Wrap while preserving bullet indentation.
    wrapped: List[str] = []
    for line in lines:
        if line.startswith("- "):
            wrapped.append(
                textwrap.fill(
                    line[2:],
                    width=width,
                    initial_indent="- ",
                    subsequent_indent="  ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
        else:
            wrapped.append(
                textwrap.fill(
                    line,
                    width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )

    return "\n".join([w for w in wrapped if w is not None])


def _strip_markdown_inline(text: str) -> str:
    # Remove badge/image links: [![alt](img)](url)
    text = re.sub(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", "", text)
    # Remove images: ![alt](url)
    text = re.sub(r"!\[([^\]]*)\]\(.*?\)", r"\1", text)
    # Replace links: [text](url) -> text
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
    # Replace autolinks: <https://...> -> https://...
    text = re.sub(r"<(https?://[^>]+)>", r"\1", text)
    # Remove basic emphasis/code markers
    text = text.replace("**", "").replace("__", "").replace("`", "")
    # Remove remaining HTML tags (best-effort)
    text = re.sub(r"</?[^>]+>", "", text)
    return text


def format_release_notes_for_cli(notes: str, width: int = 100, max_lines: int = 40) -> str:
    """
    Convert Markdown-ish release notes into a CLI-friendly, wrapped text preview.

    This is intentionally lightweight (no external deps) and aims for readability in plain terminals.
    """
    if not notes:
        return ""

    try:
        import shutil

        term_width = shutil.get_terminal_size((width, 24)).columns
        width = max(60, min(int(term_width), 140))
    except Exception:
        width = max(60, min(int(width or 100), 140))

    raw_lines = notes.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cleaned_lines: List[str] = []

    for raw in raw_lines:
        line = raw.rstrip()
        if not line.strip():
            # collapse multiple blank lines
            if cleaned_lines and cleaned_lines[-1] != "":
                cleaned_lines.append("")
            continue

        # Drop common visual-only markdown noise
        if re.fullmatch(r"\s*[-*_]{3,}\s*", line):
            continue

        if re.search(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", line):
            continue

        # Headings: "### Added" -> "Added:"
        m = re.match(r"^\s{0,3}#{1,6}\s+(.*)$", line)
        if m:
            heading = _strip_markdown_inline(m.group(1).strip())
            heading = heading.strip("[] ").strip()
            if heading:
                normalized = heading.lower().strip(":")
                if normalized in {"added", "changed", "fixed", "security", "removed", "deprecated"}:
                    heading = heading.rstrip(":") + ":"
                if normalized in {
                    "añadido",
                    "cambiado",
                    "corregido",
                    "seguridad",
                    "eliminado",
                    "obsoleto",
                }:
                    heading = heading.rstrip(":") + ":"
                cleaned_lines.append(heading)
            continue

        # Normalize bullets ("*", "•") -> "-"
        line = re.sub(r"^(\s*)[•*]\s+", r"\1- ", line)
        cleaned_lines.append(_strip_markdown_inline(line).rstrip())

    # Trim leading/trailing blank lines
    while cleaned_lines and cleaned_lines[0] == "":
        cleaned_lines.pop(0)
    while cleaned_lines and cleaned_lines[-1] == "":
        cleaned_lines.pop()

    if not cleaned_lines:
        return ""

    wrapped_lines: List[str] = []
    for line in cleaned_lines:
        if line == "":
            wrapped_lines.append("")
            continue

        indent_len = len(line) - len(line.lstrip(" "))
        indent = " " * indent_len
        body = line.lstrip(" ")

        bullet_match = re.match(r"^(-\s+|\d+\.\s+)", body)
        subsequent_indent = indent
        if bullet_match:
            subsequent_indent = indent + " " * len(bullet_match.group(1))

        segments = textwrap.wrap(
            body,
            width=max(20, width - indent_len),
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not segments:
            wrapped_lines.append(indent + body)
            continue
        wrapped_lines.append(indent + segments[0])
        for seg in segments[1:]:
            wrapped_lines.append(subsequent_indent + seg)

    if max_lines and len(wrapped_lines) > max_lines:
        wrapped_lines = wrapped_lines[:max_lines]
        if wrapped_lines and wrapped_lines[-1] != "...":
            wrapped_lines.append("...")

    return "\n".join(wrapped_lines)


def _suggest_restart_command() -> str:
    # Best-effort hint: updates typically require sudo/root for system install.
    if os.geteuid() == 0:
        return "sudo redaudit"
    return "redaudit"


def restart_self(logger=None) -> bool:
    """
    Best-effort restart after a successful update.

    Returns False if restart could not be performed.
    """
    import shutil
    import sys

    argv = list(sys.argv or [])
    if not argv:
        return False

    argv0 = argv[0]
    # 1) Re-run the original entrypoint (PATH-aware).
    try:
        os.execvp(argv0, argv)
    except Exception as e:
        if logger:
            logger.debug("Restart via execvp failed: %s", e)

    # 2) Resolve via PATH and try execv.
    try:
        resolved = shutil.which(argv0) or shutil.which(os.path.basename(argv0))
        if resolved:
            os.execv(resolved, [resolved] + argv[1:])
    except Exception as e:
        if logger:
            logger.debug("Restart via resolved execv failed: %s", e)

    # 3) Fallback: python + script path (only if argv0 is a file).
    try:
        if os.path.isfile(argv0):
            os.execv(sys.executable, [sys.executable, argv0] + argv[1:])
    except Exception as e:
        if logger:
            logger.debug("Restart via python execv failed: %s", e)

    return False


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
        runner = CommandRunner(
            logger=logger,
            dry_run=bool(os.environ.get("REDAUDIT_DRY_RUN")),
            default_timeout=30.0,
            default_retries=1,
            redact_env_keys={"GITHUB_TOKEN", "NVD_API_KEY"},
        )

        # Step 1: Determine target commit for the current version tag
        try:
            git_env = os.environ.copy()
            git_env["GIT_TERMINAL_PROMPT"] = "0"
            git_env["GIT_ASKPASS"] = "echo"
            # First try to get the dereferenced commit (for annotated tags)
            # The ^{} suffix dereferences an annotated tag to its underlying commit
            ls_remote_deref = runner.check_output(
                ["git", "ls-remote", GITHUB_CLONE_URL, f"{target_ref}^{{}}"],
                text=True,
                timeout=15,
                env=git_env,
            ).strip()

            if ls_remote_deref:
                # Got the dereferenced commit (annotated tag)
                expected_commit = ls_remote_deref.split()[0]
            else:
                # Fallback: lightweight tag or no dereference available
                ls_remote = runner.check_output(
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
        cloned_commit = "unknown"
        if os.path.isdir(clone_path):
            cloned_commit = runner.check_output(
                ["git", "rev-parse", "HEAD"], cwd=clone_path, text=True, timeout=15
            ).strip()

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
                print_fn(
                    "  → Installer script returned non-zero; continuing with manual install",
                    "WARNING",
                )
                if logger:
                    logger.warning("Install script returned non-zero: %s", result.stderr)
                # Continue anyway, we'll do manual installation
            else:
                print_fn("  → Installer script completed", "OKGREEN")

        # Step 3: Manual installation to /usr/local/lib/redaudit (STAGED/ATOMIC)
        source_module = os.path.join(clone_path, "redaudit")
        staged_install_path = f"{install_path}.new"
        old_install_path = f"{install_path}.old"

        if os.path.isdir(source_module) and os.geteuid() == 0:
            if logger:
                logger.info("Installing to %s (staged)", install_path)

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

            # STAGED INSTALL: Copy to .new first (non-destructive)
            if os.path.exists(staged_install_path):
                shutil.rmtree(staged_install_path)  # Clean previous failed attempt

            print_fn(f"  → Staging new files: {staged_install_path}", "INFO")
            shutil.copytree(source_module, staged_install_path)

            # Inject language preference into staged copy
            staged_constants = os.path.join(staged_install_path, "utils", "constants.py")
            _inject_default_lang(staged_constants, lang)

            # Set permissions on staged copy
            for root, dirs, files in os.walk(staged_install_path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)

            # Validate staged copy before swapping
            key_files = ["__init__.py", "cli.py", "core/auditor.py"]
            for key_file in key_files:
                if not os.path.isfile(os.path.join(staged_install_path, key_file)):
                    shutil.rmtree(staged_install_path, ignore_errors=True)
                    return (False, f"Staged install missing key file: {key_file}")

            # ATOMIC SWAP: rename old → .old, rename .new → final
            try:
                # Clean up any previous .old backup
                if os.path.exists(old_install_path):
                    shutil.rmtree(old_install_path)

                # Move current install to .old (if exists)
                if os.path.exists(install_path):
                    print_fn(
                        f"  → Backing up current install: {install_path} → {old_install_path}",
                        "INFO",
                    )
                    os.rename(install_path, old_install_path)

                # Move staged install to final location
                print_fn(
                    f"  → Activating new install: {staged_install_path} → {install_path}", "INFO"
                )
                os.rename(staged_install_path, install_path)

                print_fn(f"  → Default language preserved: {lang}", "OKGREEN")

                # Cleanup .old on success (keep for now, cleaned at end)

            except Exception as e:
                # ROLLBACK: restore .old if swap failed
                if os.path.exists(old_install_path) and not os.path.exists(install_path):
                    print_fn("  → ROLLBACK: Restoring previous install", "WARNING")
                    try:
                        os.rename(old_install_path, install_path)
                    except Exception:
                        pass
                shutil.rmtree(staged_install_path, ignore_errors=True)
                return (False, f"System install swap failed: {e}")

        elif os.geteuid() != 0:
            print_fn("  → Skipping system install (not running as root)", "WARNING")

        # Step 4: Refuse to overwrite local changes in home repo (if present)
        if os.path.isdir(home_redaudit_path) and os.path.isdir(
            os.path.join(home_redaudit_path, ".git")
        ):
            try:
                status = runner.check_output(
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

        # Step 5: Copy to user's home folder with documentation (STAGED/ATOMIC)
        staged_home_path = f"{home_redaudit_path}.new"
        backup_path = None

        if logger:
            logger.info("Copying to home folder: %s (staged)", home_redaudit_path)
        print_fn(f"  → Updating home folder copy: {home_redaudit_path}", "INFO")

        # Clean previous failed staged attempt
        if os.path.exists(staged_home_path):
            shutil.rmtree(staged_home_path, ignore_errors=True)

        # Stage: copy to .new first
        print_fn(f"  → Staging home folder: {staged_home_path}", "INFO")
        shutil.copytree(clone_path, staged_home_path)

        # Inject language preference into staged copy
        staged_home_constants = os.path.join(staged_home_path, "redaudit", "utils", "constants.py")
        _inject_default_lang(staged_home_constants, lang)

        # Validate staged home copy
        staged_key_file = os.path.join(staged_home_path, "redaudit", "__init__.py")
        if not os.path.isfile(staged_key_file):
            shutil.rmtree(staged_home_path, ignore_errors=True)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return (False, "Staged home copy missing key files")

        # ATOMIC SWAP for home folder
        try:
            # Backup existing if present
            if os.path.exists(home_redaudit_path):
                backup_path = f"{home_redaudit_path}_backup_{int(__import__('time').time())}"
                print_fn(
                    f"  → Backing up home folder: {home_redaudit_path} → {backup_path}", "INFO"
                )
                os.rename(home_redaudit_path, backup_path)
                if logger:
                    logger.info("Backed up existing to: %s", backup_path)

            # Activate staged home folder
            print_fn(
                f"  → Activating home folder: {staged_home_path} → {home_redaudit_path}", "INFO"
            )
            os.rename(staged_home_path, home_redaudit_path)

        except Exception as e:
            # ROLLBACK: restore backup if swap failed
            if (
                backup_path
                and os.path.exists(backup_path)
                and not os.path.exists(home_redaudit_path)
            ):
                print_fn("  → ROLLBACK: Restoring home folder from backup", "WARNING")
                try:
                    os.rename(backup_path, home_redaudit_path)
                except Exception:
                    pass
            shutil.rmtree(staged_home_path, ignore_errors=True)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return (False, f"Home folder swap failed: {e}")

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

        # Step 6: Post-install verification with ROLLBACK
        verification_passed = True
        verification_errors = []

        # Check that main module exists (only if running as root)
        if os.geteuid() == 0:
            if not os.path.isdir(install_path):
                verification_passed = False
                verification_errors.append("Module not installed to /usr/local/lib")
            else:
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
            # ROLLBACK on verification failure
            print_fn("  → Post-install verification failed, attempting rollback", "WARNING")

            # Restore system install from .old
            if os.geteuid() == 0 and os.path.exists(old_install_path):
                try:
                    if os.path.exists(install_path):
                        shutil.rmtree(install_path, ignore_errors=True)
                    os.rename(old_install_path, install_path)
                    print_fn("  → System install rolled back", "INFO")
                except Exception:
                    pass

            # Restore home from backup
            if backup_path and os.path.exists(backup_path):
                try:
                    if os.path.exists(home_redaudit_path):
                        shutil.rmtree(home_redaudit_path, ignore_errors=True)
                    os.rename(backup_path, home_redaudit_path)
                    print_fn("  → Home folder rolled back", "INFO")
                except Exception:
                    pass

            return (
                False,
                f"Installation verification failed (rolled back): {'; '.join(verification_errors)}",
            )

        # Cleanup .old system install on success
        if os.geteuid() == 0 and os.path.exists(old_install_path):
            shutil.rmtree(old_install_path, ignore_errors=True)

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


def interactive_update_check(
    print_fn=None, ask_fn=None, t_fn=None, logger=None, lang: str = "en"
) -> bool:
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
        t_fn = lambda key, *args: key.format(*args) if args else key  # noqa: E731

    # Check for updates
    print_fn(t_fn("update_checking"), "INFO")

    (
        update_available,
        latest_version,
        release_notes,
        release_url,
        published_at,
        notes_lang,
    ) = check_for_updates(logger=logger, lang=lang)

    if not latest_version:
        print_fn(t_fn("update_check_failed"), "WARNING")
        return False

    if not update_available:
        print_fn(t_fn("update_current", VERSION), "OKGREEN")
        return False

    # Update available
    print_fn(t_fn("update_available", latest_version, VERSION), "WARNING")

    # Show concise update summary (terminal-friendly; no raw Markdown).
    if release_notes or release_url or published_at:
        try:
            import shutil

            sep_width = shutil.get_terminal_size((60, 24)).columns if sys.stdout.isatty() else 60
            sep_width = max(60, min(int(sep_width), 120))
        except Exception:
            sep_width = 60

        summary = render_update_summary_for_cli(
            current_version=VERSION,
            latest_version=latest_version,
            release_notes=release_notes,
            release_url=release_url,
            published_at=published_at,
            lang=lang,
            notes_lang=notes_lang,
            t_fn=t_fn,
        )

        if summary.strip():
            print("")
            print("-" * sep_width)
            print(summary)
            print("-" * sep_width)
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
                import time

                time.sleep(1)  # Brief pause before restart
                if not restart_self(logger=logger):
                    print_fn(
                        t_fn("update_restart_failed", _suggest_restart_command()),
                        "WARNING",
                    )
            else:
                print_fn(message, "OKGREEN")
            return True
        else:
            print_fn(message, "FAIL")
            return False
    else:
        print_fn(t_fn("update_skipped"), "INFO")
        return False
