"""HUNTX Rich Theme and Terminal Display Helpers.

Provides a unified, professional, security-focused palette and layout tools.
Palette matches high-end terminal and pentest tools (Nmap, Metasploit, Burp):
- Dark charcoal / deep navy canvas
- Muted green / teal accents
- Monospace technical labels
- Clean borders and tables with zero neon / rainbow / decorative gradient effects.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from rich.box import ROUNDED, SQUARE
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Professional Security Terminal Palette
HUNTX_THEME = Theme({
    "brand": "bold green",
    "version": "dim cyan",
    "accent": "green",
    "accent.dim": "dim green",
    "info": "cyan",
    "warn": "yellow",
    "error": "bold red",
    "risk": "bold red",
    "success": "bold green",
    "muted": "bright_black",
    "path": "bold cyan",
    "mono": "cyan",
    "label": "bold white",
    "stat.num": "bold green",
    "border": "bright_black",
    "panel.border": "green",
})

console = Console(theme=HUNTX_THEME, highlight=False)


def get_console() -> Console:
    """Return the global Rich console configured with HUNTX theme."""
    return console


def make_header_panel(
    target_name: Optional[str] = None,
    apk_name: Optional[str] = None,
    session_id: Optional[str] = None,
    is_offline: bool = True,
) -> Panel:
    """Render the professional Command Centre Header.

    Includes:
    - Logo and framework title
    - Selected Target
    - Selected APK
    - Current Session ID
    - Current System Time (UTC)
    - Offline Engine Status
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_str = "[bold green]OFFLINE RECON READY[/bold green]" if is_offline else "[cyan]NETWORK CAPABLE[/cyan]"

    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=3)
    grid.add_column(justify="right", ratio=2)

    left_text = Text()
    left_text.append("HUNTX ", style="bold green")
    left_text.append("v1.0.0  ", style="dim cyan")
    left_text.append("•  Android & API Reconnaissance Command Centre\n", style="bright_black")

    # Metadata row
    tgt_disp = target_name or "[dim]None[/dim]"
    apk_disp = apk_name or "[dim]None[/dim]"
    sess_disp = session_id or "[dim]None[/dim]"

    meta_line = f"Target: [bold white]{tgt_disp}[/bold white]  │  APK: [cyan]{apk_disp}[/cyan]  │  Session: [mono]{sess_disp}[/mono]"
    
    grid.add_row(
        Group(left_text, Text.from_markup(meta_line)),
        Group(
            Text.from_markup(f"[bright_black]Status:[/bright_black] {status_str}"),
            Text.from_markup(f"[bright_black]System Time:[/bright_black] [dim]{now_str}[/dim]"),
        ),
    )

    return Panel(
        grid,
        border_style="green",
        box=ROUNDED,
        padding=(0, 1),
    )


def make_status_bar(
    target_dir: Optional[Path] = None,
    db_status: str = "Connected (SQLite)",
    shortcuts: str = "0: Exit  •  b: Back  •  h: Help  •  r: Refresh  •  all: Select All",
) -> Panel:
    """Render the bottom status strip."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    tgt_path = str(target_dir) if target_dir else "Target/"

    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=3)
    grid.add_column(justify="right", ratio=2)

    left = f"[bright_black]Env:[/bright_black] Python {py_ver}  │  [bright_black]DB:[/bright_black] [green]{db_status}[/green]  │  [bright_black]Target Base:[/bright_black] [cyan]{tgt_path}[/cyan]"
    right = f"[dim]{shortcuts}[/dim]"

    grid.add_row(Text.from_markup(left), Text.from_markup(right))
    return Panel(grid, border_style="bright_black", box=SQUARE, padding=(0, 1))


def make_metrics_table(stats: Dict[str, Any]) -> Table:
    """Render technical attack surface summary metrics."""
    table = Table(
        title="[bold green]ATTACK SURFACE METRICS[/bold green]",
        box=ROUNDED,
        border_style="bright_black",
        header_style="bold green",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Category", style="bright_black")
    table.add_column("Count", justify="right", style="bold green")
    table.add_column("Context / Security Relevance", style="dim")

    endpoints_cnt = stats.get("total_endpoints", 0)
    domains_cnt = stats.get("total_domains", 0)
    exported_comps = stats.get("exported_components", 0)
    unprotected_comps = stats.get("unprotected_components", 0)
    dang_perms = stats.get("dangerous_perms", 0)
    total_perms = stats.get("total_perms", 0)

    table.add_row("API Endpoints", str(endpoints_cnt), "Routes extracted from DEX & observed traffic")
    table.add_row("External Hostnames", str(domains_cnt), "Target domains & external services")
    
    exp_style = "bold red" if unprotected_comps > 0 else "green"
    table.add_row(
        "Exported Components",
        str(exported_comps),
        f"[{exp_style}]{unprotected_comps} unprotected[/{exp_style}] attack surface vectors",
    )
    
    perm_style = "yellow" if dang_perms > 0 else "dim"
    table.add_row(
        "Privileged Permissions",
        str(dang_perms),
        f"[{perm_style}]Out of {total_perms} declared permissions[/{perm_style}]",
    )

    return table


def make_command_centre_layout(
    header: Panel,
    nav_table: Table,
    workspace_panel: Panel,
    status_bar: Panel,
    intel_panel: Optional[Panel] = None,
) -> Layout:
    """Assemble the Command Centre multi-panel layout."""
    root = Layout(name="root")
    root.split_column(
        Layout(header, name="header", size=4),
        Layout(name="body", ratio=1),
        Layout(status_bar, name="footer", size=3),
    )

    if intel_panel is not None:
        root["body"].split_row(
            Layout(nav_table, name="left", ratio=3),
            Layout(workspace_panel, name="center", ratio=6),
            Layout(intel_panel, name="right", ratio=3),
        )
    else:
        root["body"].split_row(
            Layout(nav_table, name="left", ratio=4),
            Layout(workspace_panel, name="center", ratio=8),
        )

    return root
