#!/usr/bin/env python3
"""
RedAudit - Path Resolution Helpers

This module centralizes path resolution for scenarios where RedAudit runs under sudo.
When executed as root via sudo, `~` and `$HOME` typically point to /root, but user-facing
artifacts (reports, defaults) should be stored under the invoking user whenever possible.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

try:
    import pwd  # Unix-only
except ImportError:  # pragma: no cover
    pwd = None


logger = logging.getLogger(__name__)


def _is_root() -> bool:
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def _resolve_home_dir_for_user(username: str) -> Optional[str]:
    if not username or not isinstance(username, str):
        return None

    if pwd is not None:
        try:
            return pwd.getpwnam(username).pw_dir
        except Exception:
            pass

    try:
        expanded = os.path.expanduser(f"~{username}")
        if expanded and isinstance(expanded, str) and not expanded.startswith("~"):
            return expanded
    except Exception:
        return None

    return None


def get_invoking_user() -> Optional[str]:
    """
    Return the invoking user when running under sudo, otherwise None.

    When executed as root without sudo, returns None.
    """

    if not _is_root():
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user.strip() and sudo_user.strip() != "root":
        return sudo_user.strip()
    return None


def _get_preferred_human_home_under_home() -> Optional[str]:
    """
    Best-effort: pick a "human" home directory under /home when running as root.

    This is useful on distributions like Kali where users may run RedAudit directly
    as root (without sudo) but still expect artifacts to land under /home/<user>.
    We only return a home directory when we can do so safely (single candidate, or
    a clear default like 'kali').
    """

    if not _is_root() or pwd is None:
        return None

    try:
        entries = pwd.getpwall()
    except Exception:
        return None

    candidates: dict[str, str] = {}
    for entry in entries:
        try:
            username = getattr(entry, "pw_name", None)
            uid = getattr(entry, "pw_uid", None)
            home_dir = getattr(entry, "pw_dir", None)
            shell = getattr(entry, "pw_shell", None)
            if not username or not isinstance(username, str):
                continue
            if username in {"root", "nobody"}:
                continue
            if not isinstance(uid, int) or uid < 1000:
                continue
            if not home_dir or not isinstance(home_dir, str) or not home_dir.startswith("/home/"):
                continue
            if isinstance(shell, str) and shell in {"/usr/sbin/nologin", "/bin/false"}:
                continue
            if not os.path.isdir(home_dir):
                continue
            candidates[username] = home_dir
        except Exception:
            continue

    if not candidates:
        return None
    # Common Kali default user.
    if "kali" in candidates:
        return candidates["kali"]
    if len(candidates) == 1:
        return next(iter(candidates.values()))
    return None


def get_reports_home_dir() -> str:
    """
    Resolve the preferred home directory for user-facing artifacts (reports).

    Priority:
    1) SUDO invoking user (when available)
    2) A single detected "human" user under /home when running as root
    3) Current user's home directory
    """

    invoking_user = get_invoking_user()
    if invoking_user:
        home_dir = _resolve_home_dir_for_user(invoking_user)
        if home_dir:
            return home_dir

    fallback_home = _get_preferred_human_home_under_home()
    if fallback_home:
        return fallback_home

    return os.path.expanduser("~")


def get_invoking_home_dir() -> str:
    """
    Resolve the home directory for the user that invoked sudo, if available.

    Falls back to the current user's home directory.
    """

    invoking_user = get_invoking_user()
    if invoking_user:
        home_dir = _resolve_home_dir_for_user(invoking_user)
        if home_dir:
            return home_dir
    return os.path.expanduser("~")


def expand_user_path(path: str) -> str:
    """
    Expand a user path, resolving `~` to the invoking user's home under sudo.
    """

    if not isinstance(path, str):
        return str(path)
    raw = path.strip()
    if not raw:
        return raw

    invoking_user = get_invoking_user()
    if invoking_user and (raw == "~" or raw.startswith("~/")):
        home_dir = get_invoking_home_dir()
        if raw == "~":
            return home_dir
        return os.path.join(home_dir, raw[2:])

    return os.path.expanduser(raw)


def _read_xdg_documents_dir(home_dir: str) -> Optional[str]:
    user_dirs_file = os.path.join(home_dir, ".config", "user-dirs.dirs")
    try:
        with open(user_dirs_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith("XDG_DOCUMENTS_DIR="):
                    continue
                _, value = stripped.split("=", 1)
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                value = value.replace("$HOME", home_dir).replace("${HOME}", home_dir)
                value = value.replace('\\"', '"')
                if not value:
                    return None
                if not os.path.isabs(value):
                    value = os.path.join(home_dir, value)
                return value
    except FileNotFoundError:
        return None
    except Exception:
        return None

    return None


def get_documents_dir(home_dir: Optional[str] = None) -> str:
    """
    Resolve the user's Documents directory.

    On Linux desktop environments, prefers XDG user-dirs (user-dirs.dirs).
    Otherwise falls back to commonly used folder names.
    """

    resolved_home = home_dir or get_reports_home_dir()

    xdg_documents = _read_xdg_documents_dir(resolved_home)
    if xdg_documents:
        return xdg_documents

    documents = os.path.join(resolved_home, "Documents")
    documentos = os.path.join(resolved_home, "Documentos")
    if os.path.isdir(documentos) and not os.path.isdir(documents):
        return documentos
    return documents if os.path.isdir(documents) or not os.path.isdir(documentos) else documentos


def get_default_reports_base_dir() -> str:
    """
    Default base directory for reports (where timestamped RedAudit_* folders go).
    """

    return os.path.join(get_documents_dir(), "RedAuditReports")


def resolve_invoking_user_owner() -> Optional[Tuple[int, int]]:
    """
    Resolve the uid/gid for the invoking user under sudo.
    """

    if not _is_root():
        return None

    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid and sudo_uid.isdigit() and sudo_gid.isdigit():
        return int(sudo_uid), int(sudo_gid)

    invoking_user = get_invoking_user()
    if invoking_user and pwd is not None:
        try:
            pw = pwd.getpwnam(invoking_user)
            return pw.pw_uid, pw.pw_gid
        except Exception:
            return None

    return None


def maybe_chown_to_invoking_user(path: str) -> None:
    """
    Best-effort: chown a path to the invoking user (sudo) to avoid root-owned artifacts.
    """

    owner = resolve_invoking_user_owner()
    if not owner:
        return
    if not hasattr(os, "chown"):
        return

    uid, gid = owner
    try:
        os.chown(path, uid, gid)
    except Exception:
        logger.debug("Failed to chown path to invoking user: %s", path, exc_info=True)
        return


def maybe_chown_tree_to_invoking_user(root_path: str) -> None:
    """
    Best-effort: chown a directory tree to the invoking user (sudo).

    Used for report output folders to avoid root-owned artifacts under the user's home.
    """

    owner = resolve_invoking_user_owner()
    if not owner:
        return
    if not hasattr(os, "chown"):
        return

    uid, gid = owner
    try:
        os.chown(root_path, uid, gid)
    except Exception:
        logger.debug("Failed to chown root path to invoking user: %s", root_path, exc_info=True)
        pass

    try:
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            for name in dirnames:
                try:
                    os.chown(os.path.join(dirpath, name), uid, gid)
                except Exception:
                    logger.debug(
                        "Failed to chown dir to invoking user: %s",
                        os.path.join(dirpath, name),
                        exc_info=True,
                    )
                    pass
            for name in filenames:
                try:
                    os.chown(os.path.join(dirpath, name), uid, gid)
                except Exception:
                    logger.debug(
                        "Failed to chown file to invoking user: %s",
                        os.path.join(dirpath, name),
                        exc_info=True,
                    )
                    pass
    except Exception:
        logger.debug("Failed to walk path for chown: %s", root_path, exc_info=True)
        return
