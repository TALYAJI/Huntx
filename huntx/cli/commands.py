"""HUNTX command line interface. ``huntx`` with no arguments opens the interactive menu."""
from __future__ import annotations

import shutil
import time
import webbrowser
from pathlib import Path
from typing import List, Optional
from xml.etree.ElementTree import ParseError

import typer
from rich.markup import escape
from rich.table import Table

from huntx.cli.theme import get_console
from huntx.core.config import HUNTX_VERSION, SUPPORTED_APK_EXTENSIONS, load_config
from huntx.core.pipeline import ScanError, open_session, run_pipeline, write_reports
from huntx.core.session import Session, SessionManager, compute_sha256
from huntx.core.target_manager import TargetManager

cli_app = typer.Typer(
    name="huntx",
    help="HUNTX - passive Android & API reconnaissance",
    add_completion=False,
    no_args_is_help=False,
    pretty_exceptions_show_locals=False,
)


def _table(title: str) -> Table:
    return Table(title=title, box=None, header_style="bold green", padding=(0, 2))


def _fail(message: str) -> typer.Exit:
    get_console().print(f"[bold red]{escape(message)}[/bold red]")
    return typer.Exit(1)


def _target_dir(target: str) -> Path:
    base = load_config().target_base
    path = base / target
    if not path.is_dir() or base.resolve() not in path.resolve().parents:
        raise _fail(f"Target '{target}' not found in {base}")
    return path


def _latest_session(target: str) -> Session:
    manager = SessionManager(_target_dir(target))
    sessions = manager.list_sessions()
    if not sessions:
        raise _fail(f"No analysis sessions for '{target}'. Run: huntx scan {target}")
    return manager.load_session(sessions[0].run_dir)


@cli_app.command(name="doctor")
def cmd_doctor() -> None:
    """Check the environment, dependencies, permissions and optional tools."""
    from huntx.cli.doctor import run_doctor

    result = run_doctor()
    if result["missing_packages"] or not result["python_ok"]:
        raise typer.Exit(1)


@cli_app.command(name="targets")
def cmd_targets() -> None:
    """List target workspaces."""
    console = get_console()
    base = load_config().target_base
    manager = TargetManager(base)
    targets = manager.list_targets()
    if not targets:
        console.print(f"[dim]No targets located in {base}[/dim]")
        return

    table = _table(f"[bold green]AVAILABLE TARGET WORKSPACES[/bold green] [dim]({base})[/dim]")
    table.add_column("No.", style="dim")
    table.add_column("Target Name", style="bold white")
    table.add_column("Packages", style="cyan")
    table.add_column("Sessions", justify="right")
    for idx, name in enumerate(targets, 1):
        apks = ", ".join(f"{escape(a.filename)} ({a.size_human})" for a in manager.find_apks(base / name))
        table.add_row(str(idx), name, apks or "[dim]none[/dim]", str(len(SessionManager(base / name).list_sessions())))
    console.print(table)


@cli_app.command(name="apks")
def cmd_apks(target: str = typer.Argument(..., help="Target name")) -> None:
    """List the packages of a target with their SHA-256."""
    path = _target_dir(target)
    table = _table(f"[bold green]PACKAGES[/bold green] [dim]({target})[/dim]")
    for column in ("File", "Size", "SHA-256"):
        table.add_column(column, overflow="fold")
    for apk in TargetManager(path.parent).find_apks(path):
        table.add_row(escape(apk.filename), apk.size_human, compute_sha256(apk.path))
    get_console().print(table)


@cli_app.command(name="surface")
def cmd_surface(target: str = typer.Argument(..., help="Target name")) -> None:
    """Show the attack surface tree of the latest session."""
    from huntx.cli.attack_surface import show_attack_surface

    show_attack_surface(_latest_session(target))


@cli_app.command(name="timeline")
def cmd_timeline(target: str = typer.Argument(..., help="Target name")) -> None:
    """Show the investigation timeline of the latest session."""
    from huntx.cli.notebook import InvestigationTimeline

    InvestigationTimeline(_latest_session(target)).display()


@cli_app.command(name="notes")
def cmd_notes(
    target: str = typer.Argument(..., help="Target name"),
    add: Optional[str] = typer.Option(None, "--add", help="Note text to record"),
    entity: str = typer.Option("general", "--entity", help="What the note is about (class, endpoint id, ...)"),
    tag: str = typer.Option("Investigation", "--tag"),
) -> None:
    """Show research notes, or record one with --add."""
    from huntx.cli.notebook import InvestigationTimeline, ResearchNotebook

    session = _latest_session(target)
    notebook = ResearchNotebook(session)
    if add:
        notebook.add_note("General", entity, add, tag)
        InvestigationTimeline(session).log_event("Note Added", f"{entity}: {add[:80]}")
    notebook.display()


@cli_app.command(name="search")
def cmd_search(
    target: str = typer.Argument(..., help="Target name"),
    query: str = typer.Argument(..., help="Text to look for"),
    limit: int = typer.Option(50, "--limit", min=1),
) -> None:
    """Search the evidence of the latest session."""
    from huntx.core.search import SearchEngine

    session = _latest_session(target)
    results = SearchEngine(session.db_path, session_run_path=session.run_path).search(query)
    console = get_console()
    for hit in results[:limit]:
        console.print(escape(str(hit.get("_display") or hit)))
    console.print(f"[dim]{len(results)} match(es)[/dim]")


@cli_app.command(name="report")
def cmd_report(
    target: str = typer.Argument(..., help="Target name"),
    open_report: bool = typer.Option(False, "--open", "-o", help="Open the summary in a browser"),
) -> None:
    """Regenerate all reports and exports for the latest session."""
    paths = write_reports(_latest_session(target))
    for name, path in paths.items():
        get_console().print(f"  [cyan]{name:14}[/cyan] {escape(str(path))}", soft_wrap=True)
    if open_report:
        webbrowser.open(paths["summary"].resolve().as_uri())


def _resolve_run(value: str) -> Path:
    """Accept a run directory path, or ``target`` / ``target/RUN_x`` under the base."""
    path = Path(value)
    if (path / "session.json").exists():
        return path
    path = load_config().target_base / value
    if (path / "session.json").exists():
        return path
    if path.is_dir():
        sessions = SessionManager(path).list_sessions()
        if sessions:
            return path / sessions[0].run_dir
    raise _fail(f"Not a HUNTX session: {value}")


@cli_app.command(name="diff")
def cmd_diff(
    run1: str = typer.Argument(..., help="Base run directory, target, or target/RUN_*"),
    run2: str = typer.Argument(..., help="Run to compare against the base"),
) -> None:
    """Compare two runs (components, permissions, endpoints, domains)."""
    from huntx.intelligence.apk_diff import compare_apk_runs

    s = compare_apk_runs(_resolve_run(run1), _resolve_run(run2)).summary
    table = _table("[bold green]APK RECONNAISSANCE DIFF SUMMARY[/bold green]")
    table.add_column("Metric", style="bold white")
    table.add_column("Delta", justify="right")
    table.add_row("New Domains", f"[green]+{s.new_domains_count}[/green]")
    table.add_row("Removed Domains", f"[red]-{s.removed_domains_count}[/red]")
    table.add_row("New API Endpoints", f"[green]+{s.new_endpoints_count}[/green]")
    table.add_row("Removed Endpoints", f"[red]-{s.removed_endpoints_count}[/red]")
    table.add_row("Added Permissions", f"[yellow]+{s.added_permissions_count}[/yellow]")
    table.add_row("Security Risk Delta", f"[bold red]{s.security_risk_delta.upper()}[/bold red]")
    get_console().print(table)


def _pick_sources(directory: Path, manager: TargetManager) -> List[Path]:
    """Choose what one scan covers: a split set together, else the newest package."""
    found = [a.path for a in manager.find_apks(directory)]
    if not found:
        raise _fail(f"No APK files found in {directory}")
    if any(p.name.startswith(("split_", "config.")) for p in found):
        return [p for p in found if p.suffix.lower() == ".apk"]
    newest = max(found, key=lambda p: p.stat().st_mtime)
    if len(found) > 1:
        get_console().print(f"[yellow]{len(found)} packages found; scanning the newest: {escape(newest.name)}[/yellow]")
    return [newest]


def _resolve_scan(target_input: str, manager: TargetManager) -> tuple[Path, List[Path]]:
    path = Path(target_input).expanduser()
    if path.is_file():
        if path.suffix.lower() not in SUPPORTED_APK_EXTENSIONS:
            raise _fail(f"Unsupported file type '{path.suffix}'. Expected: {', '.join(SUPPORTED_APK_EXTENSIONS)}")
        target_dir = manager.create_target(manager.name_from_file(path))
        stored = target_dir / path.name
        if path.resolve() != stored.resolve():
            shutil.copy2(path, stored)  # always refresh: a rebuilt APK often keeps its name
        return target_dir, [stored]
    in_base = manager.base_path / target_input
    if in_base.is_dir() and manager.base_path.resolve() in in_base.resolve().parents:
        return in_base, _pick_sources(in_base, manager)
    if path.is_dir():
        sources = _pick_sources(path, manager)
        return manager.create_target(manager.name_from_file(path.resolve())), sources
    raise _fail(f"Target or APK not found: {target_input}")


@cli_app.command(name="scan")
def cmd_scan(
    target_input: str = typer.Argument(..., help="APK/XAPK/APKS file, directory, or target name"),
    burp: Optional[Path] = typer.Option(None, "--burp", exists=True, dir_okay=False, help="Burp Suite XML export"),
    har: Optional[Path] = typer.Option(None, "--har", exists=True, dir_okay=False, help="HAR archive"),
    raw: bool = typer.Option(False, "--raw", help="Keep SDK/library noise in endpoints.json"),
    open_report: bool = typer.Option(False, "--open", "-o", help="Open the summary in a browser"),
) -> None:
    """Run the full passive analysis on an Android package."""
    from huntx.cli.notebook import InvestigationTimeline

    console = get_console()
    start = time.perf_counter()
    target_dir, sources = _resolve_scan(target_input, TargetManager(load_config().target_base))
    console.print(f"\n[bold green][+] Passive scan:[/bold green] {escape(', '.join(s.name for s in sources))}")

    try:
        with console.status("[bold cyan]Preparing...[/bold cyan]") as status:
            session, apks = open_session(target_dir, sources)
            r = run_pipeline(
                session, apks,
                traffic=[p for p in (burp, har) if p],
                filter_noise=False if raw else None,
                progress=lambda label: status.update(f"[bold cyan]{label}...[/bold cyan]"),
            )
    except (ScanError, OSError) as exc:
        raise _fail(str(exc)) from exc
    except (ParseError, ValueError) as exc:
        raise _fail(f"Could not parse input: {exc}") from exc

    elapsed = time.perf_counter() - start
    InvestigationTimeline(session).log_event("Scan Completed", f"{len(r['passports'])} endpoints in {elapsed:.1f}s")
    _print_summary(r, elapsed)
    if open_report:
        webbrowser.open(r["reports"]["summary"].resolve().as_uri())


def _print_summary(r: dict, elapsed: float) -> None:
    console = get_console()
    info, comp, audit = r["apk_info"], r["components"], r["audit"]
    fp = audit["fingerprint"]
    debuggable = r["manifest"]["flags"]["debuggable"]
    unprotected = comp["unprotected_count"]
    title = escape(f"{info['package_name']} v{info['version_name']}")

    table = _table(f"[bold green]TRIAGE SUMMARY: {title}[/bold green] [dim]({elapsed:.2f}s)[/dim]")
    table.add_column("Attack Surface Metric", style="bold white")
    table.add_column("Count / State", style="bold yellow", justify="right")
    for label, value in (
        ("Framework", ", ".join(fp["frameworks"])),
        ("Networking Libraries", ", ".join(fp["networking_libraries"]) or "none detected"),
        ("Debuggable Build", "[bold red]TRUE (HIGH RISK)[/bold red]" if debuggable else "[green]False[/green]"),
        ("Components (Exported)", f"{comp['total_components']} ({comp['exported_count']})"),
        ("Unprotected Exported Components", f"[bold red]{unprotected}[/bold red]" if unprotected else "0"),
        ("Permissions (Dangerous)", f"{r['permissions']['total_permissions']} ({r['permissions']['dangerous_count']})"),
        ("Domains", str(r["domains"]["total_domains"])),
        ("Candidate API Endpoints", str(len(r["passports"]))),
        ("Mapped Source Classes", str(r["mapping"].android_api_map["total_mapped_classes"])),
        ("Candidate Secrets / Cloud Assets", f"{audit['secrets_count']} / {audit['cloud_assets_count']}"),
        ("Defenses / WebView Signals", f"{len(fp['defenses'])} / {len(fp['webview_signals'])}"),
        ("ADB Verification Commands", str(audit["adb_pocs_count"])),
    ):
        table.add_row(label, value)
    console.print(table)

    console.print("[bold green]Reports & exports[/bold green]")
    for name, path in r["reports"].items():
        console.print(f"  [cyan]{name:14}[/cyan] {escape(str(path))}", soft_wrap=True)


@cli_app.command(name="ui")
def cmd_ui() -> None:
    """Launch the interactive Command Centre menu."""
    from huntx.cli.menu import main as menu_main

    menu_main()


def _version(value: bool) -> None:
    if value:
        typer.echo(f"huntx {HUNTX_VERSION}")
        raise typer.Exit()


@cli_app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", callback=_version, is_eager=True, help="Show the version"),
) -> None:
    """Open the interactive menu when no command is given."""
    if ctx.invoked_subcommand is None:
        cmd_ui()


if __name__ == "__main__":
    cli_app()
