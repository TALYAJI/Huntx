"""HUNTX System Doctor & Diagnostic Engine.

Runs environment, binary, package, database, and permissions diagnostics
and presents actionable troubleshooting without external network calls.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from typing import Any, Dict

from rich.table import Table

from huntx.cli.theme import get_console
from huntx.core.config import load_config
from huntx.core.dependency_checker import check_all


def run_doctor() -> Dict[str, Any]:
    """Execute all system and framework health diagnostics."""
    console = get_console()

    table = Table(
        title="[bold green]HUNTX ENVIRONMENT & SYSTEM DOCTOR[/bold green]",
        box=None,
        expand=True,
        header_style="bold green",
        border_style="bright_black",
        padding=(0, 2),
    )
    table.add_column("Subsystem / Component", style="bold white", width=30)
    table.add_column("Diagnostic Status", width=22)
    table.add_column("Details & Actionable Recommendation", style="dim")

    # 1. Python Runtime
    py_ok = sys.version_info >= (3, 10)
    py_ver_str = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if py_ok:
        table.add_row("Python Environment", "[bold green][✓] HEALTHY[/bold green]", py_ver_str)
    else:
        table.add_row(
            "Python Environment",
            "[bold red][✗] INCOMPATIBLE[/bold red]",
            f"{py_ver_str} (Python 3.10+ required)",
        )

    # 2. Package Dependencies
    dep_rep = check_all()
    if not dep_rep.missing_required:
        table.add_row("Core Python Packages", "[bold green][✓] INSTALLED[/bold green]", "All required dependencies present")
    else:
        missing_str = ", ".join(dep_rep.missing_required)
        table.add_row(
            "Core Python Packages",
            "[bold yellow][!] PACKAGES MISSING[/bold yellow]",
            f"Run: pip install {missing_str}",
        )

    # 3. Target Base Directory
    cfg = load_config()
    tgt_base = cfg.target_base
    if tgt_base.exists() and os.access(tgt_base, os.W_OK):
        table.add_row("Target Base Storage", "[bold green][✓] WRITABLE[/bold green]", str(tgt_base))
    elif tgt_base.exists():
        table.add_row("Target Base Storage", "[bold red][✗] READ ONLY[/bold red]", f"Permission denied at {tgt_base}")
    else:
        table.add_row("Target Base Storage", "[bold yellow][!] NOT CREATED[/bold yellow]", f"Will be created at {tgt_base}")

    # 4. SQLite Database Engine
    try:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE _diag (id INT);")
        conn.close()
        table.add_row("SQLite Engine", "[bold green][✓] OPERATIONAL[/bold green]", f"SQLite v{sqlite3.sqlite_version} ready")
    except Exception as e:
        table.add_row("SQLite Engine", "[bold red][✗] ERROR[/bold red]", str(e))

    # 5. External Tooling
    jadx_path = shutil.which("jadx")
    if jadx_path:
        table.add_row("Decompiler: JADX", "[bold green][✓] AVAILABLE[/bold green]", jadx_path)
    else:
        table.add_row("Decompiler: JADX", "[dim][-] NOT FOUND[/dim]", "Optional: installs bytecode decompiler for Java source reconstruction")

    aapt_path = shutil.which("aapt") or shutil.which("aapt2")
    if aapt_path:
        table.add_row("Android Asset Tool (aapt)", "[bold green][✓] AVAILABLE[/bold green]", aapt_path)
    else:
        table.add_row("Android Asset Tool (aapt)", "[dim][-] NOT FOUND[/dim]", "Optional: HUNTX uses native pure-Python AXML parser")

    console.print()
    console.print(table)
    console.print()

    return {
        "python_ok": py_ok,
        "missing_packages": dep_rep.missing_required,
        "target_base": str(tgt_base),
        "jadx_available": bool(jadx_path),
        "aapt_available": bool(aapt_path),
    }
