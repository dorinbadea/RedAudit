"""
RedAudit - Auditor Runtime Adapter

Provides composition-friendly access to legacy component behavior while the main
auditor class stays composition-first. The runtime adapter forwards state to the
owning auditor instance to avoid duplicate state.
"""

from __future__ import annotations

from redaudit.core.auditor_components import (
    AuditorCrypto,
    AuditorLogging,
    AuditorNVD,
    AuditorUI,
)
from redaudit.core.auditor_scan import AuditorScan
from redaudit.core.auditor_vuln import AuditorVuln
from redaudit.core.wizard import Wizard


class AuditorRuntime(
    AuditorUI,
    AuditorLogging,
    AuditorCrypto,
    AuditorNVD,
    AuditorScan,
    AuditorVuln,
    Wizard,
):
    """
    Adapter that binds component methods to the owning auditor instance.

    The adapter keeps legacy behavior while allowing the public auditor class
    to use composition instead of inheritance chains.
    """

    def __init__(self, auditor: object) -> None:
        object.__setattr__(self, "_auditor", auditor)

    def __getattribute__(self, name: str):
        if name in {
            "_auditor",
            "__class__",
            "__dict__",
            "__getattr__",
            "__getattribute__",
            "__setattr__",
        }:
            return object.__getattribute__(self, name)
        auditor = object.__getattribute__(self, "_auditor")
        auditor_dict = getattr(auditor, "__dict__", {})
        if isinstance(auditor_dict, dict) and name in auditor_dict:
            return getattr(auditor, name)
        return object.__getattribute__(self, name)

    def __getattr__(self, name: str):
        # Avoid recursion loop: do not blindly call getattr(self._auditor, name)
        # because Auditor.__getattr__ might call back here.
        # Check if attribute exists on the auditor instance or class explicitly.
        auditor = self._auditor

        # 1. Check instance dictionary (state)
        if name in auditor.__dict__:
            return getattr(auditor, name)

        # 2. Check class attributes (methods/descriptors)
        # We lookup on the type to avoid triggering instance __getattr__
        if hasattr(type(auditor), name):
            return getattr(auditor, name)

        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def __setattr__(self, name: str, value) -> None:
        if name == "_auditor":
            object.__setattr__(self, name, value)
        else:
            setattr(self._auditor, name, value)
