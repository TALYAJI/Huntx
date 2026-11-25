"""HUNTX dependency checker — stdlib only, never auto-installs."""
from __future__ import annotations

import importlib
import shutil
import sys
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_PACKAGES: list[str] = [
    "cryptography",
    "rich",
    "typer",
]

OPTIONAL_TOOLS: list[str] = ["jadx", "aapt"]


# ---------------------------------------------------------------------------
# Report dataclass
# ---------------------------------------------------------------------------


@dataclass
class DependencyReport:
    """Result of a full dependency check.

    Attributes:
        python_ok: True when Python >= 3.10.
        missing_required: Names of required pip packages not importable.
        missing_optional: Names of optional external tools not on PATH.
        available_optional: Names of optional external tools found on PATH.
        install_commands: Suggested shell commands to install missing packages.
    """

    python_ok: bool = False
    missing_required: List[str] = field(default_factory=list)
    missing_optional: List[str] = field(default_factory=list)
    available_optional: List[str] = field(default_factory=list)
    install_commands: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_all() -> DependencyReport:
    """Run all dependency checks and return a :class:`DependencyReport`.

    This function never raises; failures are captured in the report.
    It never installs anything.
    """
    report = DependencyReport()

    # --- Python version -------------------------------------------------------
    major, minor = sys.version_info[:2]
    report.python_ok = (major, minor) >= (3, 10)

    # --- Required pip packages ------------------------------------------------
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except ImportError:
            report.missing_required.append(package)

    if report.missing_required:
        pkgs = " ".join(report.missing_required)
        report.install_commands.append(f"pip install {pkgs}")

    # --- Optional external tools ----------------------------------------------
    for tool in OPTIONAL_TOOLS:
        if shutil.which(tool) is not None:
            report.available_optional.append(tool)
        else:
            report.missing_optional.append(tool)

    return report


def format_report(report: DependencyReport) -> str:
    """Return a human-readable plain-text summary of *report*.

    Args:
        report: A :class:`DependencyReport` produced by :func:`check_all`.

    Returns:
        Multi-line string suitable for printing to stdout.
    """
    lines: list[str] = []
    lines.append("=" * 50)
    lines.append("HUNTX Dependency Report")
    lines.append("=" * 50)

    # Python version
    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    status = "OK" if report.python_ok else "FAIL (need >= 3.10)"
    lines.append(f"Python {py_ver}: {status}")

    lines.append("")
    lines.append("Required packages:")
    for pkg in REQUIRED_PACKAGES:
        ok = pkg not in report.missing_required
        mark = "[OK]" if ok else "[MISSING]"
        lines.append(f"  {mark} {pkg}")

    lines.append("")
    lines.append("Optional external tools:")
    for tool in OPTIONAL_TOOLS:
        if tool in report.available_optional:
            lines.append(f"  [OK]      {tool}")
        else:
            lines.append(f"  [MISSING] {tool}")

    if report.install_commands:
        lines.append("")
        lines.append("To install missing packages:")
        for cmd in report.install_commands:
            lines.append(f"  $ {cmd}")

    lines.append("=" * 50)
    return "\n".join(lines)
