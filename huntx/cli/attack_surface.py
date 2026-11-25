"""HUNTX Attack Surface Visualizer.

Renders an interactive hierarchical tree representation of the application
attack surface:
APK
 ├── Manifest (Flags & SDKs)
 ├── Exported Activities
 ├── Exported Services
 ├── Broadcast Receivers
 ├── Content Providers
 ├── Declared Permissions
 ├── API Endpoints
 └── Discovered Domains
"""
from __future__ import annotations

import json

from rich.markup import escape
from rich.panel import Panel
from rich.tree import Tree

from huntx.cli.theme import get_console
from huntx.core.session import Session
from huntx.engines.android.components import is_unprotected


def build_attack_surface_tree(session: Session) -> Tree:
    """Construct an attack surface tree from active session data."""
    meta = getattr(session, "metadata", None)
    target_name = getattr(meta, "target_name", "Unknown Target")
    apk_files = getattr(meta, "apk_files", [])
    apk_label = escape(apk_files[0]["filename"]) if apk_files else "Application Package"

    root = Tree(f"[bold green]{apk_label}[/bold green] [dim]({target_name})[/dim]")

    run_path = getattr(session, "run_path", None)
    if not run_path or not run_path.exists():
        root.add("[dim](No extraction data generated yet)[/dim]")
        return root

    # 1. Manifest Node
    manifest_f = run_path / "android" / "manifest-analysis.json"
    manifest_node = root.add("[bold white]Manifest Attributes & Security Flags[/bold white]")
    if manifest_f.exists():
        try:
            mdata = json.loads(manifest_f.read_text(encoding="utf-8"))
            pkg = escape(str(mdata.get("package", "N/A")))
            manifest_node.add(f"Package: [cyan]{pkg}[/cyan]")
            
            # Security flags
            flags = []
            mdata = {**mdata, **mdata.get("flags", {})}
            if mdata.get("debuggable"):
                flags.append("[bold red]debuggable=true[/bold red]")
            if mdata.get("allow_backup"):
                flags.append("[yellow]allowBackup=true[/yellow]")
            if mdata.get("uses_cleartext_traffic"):
                flags.append("[bold red]usesCleartextTraffic=true[/bold red]")
            
            if flags:
                manifest_node.add("Flags: " + ", ".join(flags))
            else:
                manifest_node.add("[dim]Standard restricted flags[/dim]")
        except Exception:
            manifest_node.add("[dim]Unparsed[/dim]")
    else:
        manifest_node.add("[dim]Run Manifest Analysis (Op 2) to populate[/dim]")

    # 2. Components Nodes
    comp_f = run_path / "android" / "components.json"
    activities_node = root.add("[bold white]Activities (Attack Surface)[/bold white]")
    services_node = root.add("[bold white]Services (Background Daemons)[/bold white]")
    receivers_node = root.add("[bold white]Broadcast Receivers (Event Handlers)[/bold white]")
    providers_node = root.add("[bold white]Content Providers (Data Stores)[/bold white]")

    if comp_f.exists():
        try:
            cdata = json.loads(comp_f.read_text(encoding="utf-8"))
            comps = cdata.get("components", []) if isinstance(cdata, dict) else cdata
            
            for c in comps:
                ctype = (c.get("component_type") or "").lower()
                cname = escape(c.get("class_name") or c.get("name", ""))
                exported = c.get("exported", False)
                perm = c.get("permission", "")

                if is_unprotected(c):
                    badge = "[bold red]EXPORTED (UNPROTECTED)[/bold red]"
                elif exported:
                    badge = "[yellow]EXPORTED (PROTECTED)[/yellow]" if perm else "[yellow]EXPORTED (LAUNCHER)[/yellow]"
                else:
                    badge = "[dim]internal[/dim]"

                line = f"[cyan]{cname}[/cyan] • {badge}"
                
                if "activity" in ctype:
                    activities_node.add(line)
                elif "service" in ctype:
                    services_node.add(line)
                elif "receiver" in ctype:
                    receivers_node.add(line)
                elif "provider" in ctype:
                    providers_node.add(line)
        except Exception as exc:
            root.add(f"[red]Unreadable: {escape(str(exc))}[/red]")
    else:
        activities_node.add("[dim]Run Component Enumeration (Op 4) to populate[/dim]")

    # 3. Permissions Node
    perm_f = run_path / "android" / "permissions.json"
    perm_node = root.add("[bold white]Declared Privileges & Permissions[/bold white]")
    if perm_f.exists():
        try:
            pdata = json.loads(perm_f.read_text(encoding="utf-8"))
            perms = pdata.get("permissions", []) if isinstance(pdata, dict) else pdata
            for p in perms:
                pname = escape(p.get("name", "") if isinstance(p, dict) else str(p))
                is_dang = p.get("is_dangerous") if isinstance(p, dict) else False
                if is_dang:
                    perm_node.add(f"[bold red]{pname}[/bold red] [dim](Dangerous)[/dim]")
                else:
                    perm_node.add(f"[dim]{pname}[/dim]")
        except Exception as exc:
            root.add(f"[red]Unreadable: {escape(str(exc))}[/red]")
    else:
        perm_node.add("[dim]Run Permission Analysis (Op 3) to populate[/dim]")

    # 4. Endpoints & Domains
    ep_f = run_path / "api" / "endpoints.json"
    ep_node = root.add("[bold white]API Endpoints (Client Vectors)[/bold white]")
    if ep_f.exists():
        try:
            epdata = json.loads(ep_f.read_text(encoding="utf-8"))
            eps = epdata.get("endpoints", []) if isinstance(epdata, dict) else epdata
            for ep in eps[:20]:
                m = escape((ep.get("method") or "ANY").upper())
                p = escape((ep.get("domain") or "") + (ep.get("path") or "/"))
                ep_node.add(f"[bold green]{m}[/bold green] [cyan]{p}[/cyan]")
            if len(eps) > 20:
                ep_node.add(f"[dim]... and {len(eps) - 20} more endpoints[/dim]")
        except Exception as exc:
            root.add(f"[red]Unreadable: {escape(str(exc))}[/red]")
    else:
        ep_node.add("[dim]Run API Endpoint Extraction (Op 8) to populate[/dim]")

    dom_f = run_path / "api" / "domains.json"
    dom_node = root.add("[bold white]Discovered Domains & Hosts[/bold white]")
    if dom_f.exists():
        try:
            ddata = json.loads(dom_f.read_text(encoding="utf-8"))
            doms = ddata.get("domains", []) if isinstance(ddata, dict) else ddata
            for d in doms[:15]:
                name = escape(d.get("domain", "") if isinstance(d, dict) else str(d))
                dom_node.add(f"[cyan]{name}[/cyan]")
            if len(doms) > 15:
                dom_node.add(f"[dim]... and {len(doms) - 15} more hosts[/dim]")
        except Exception as exc:
            root.add(f"[red]Unreadable: {escape(str(exc))}[/red]")
    else:
        dom_node.add("[dim]Run Domain Discovery (Op 7) to populate[/dim]")

    return root


def show_attack_surface(session: Session) -> None:
    """Render the Attack Surface Tree into a terminal panel."""
    console = get_console()
    tree = build_attack_surface_tree(session)
    console.print()
    console.print(Panel(tree, title="[bold green]HUNTX ATTACK SURFACE VISUALIZER[/bold green]", border_style="green"))
    console.print()
