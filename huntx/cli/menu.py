"""
HUNTX Interactive Menu System.
Drives the entire HUNTX user experience.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

from huntx.core.config import HUNTX_VERSION

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()

def _c(text: str, code: str) -> str:
    """Wrap text in ANSI escape code if terminal supports it."""
    if _USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text

def _green(t: str) -> str:  return _c(t, "32")
def _yellow(t: str) -> str: return _c(t, "33")
def _red(t: str) -> str:    return _c(t, "31")
def _bold(t: str) -> str:   return _c(t, "1")
def _cyan(t: str) -> str:   return _c(t, "36")

# ---------------------------------------------------------------------------
# Operation tables
# ---------------------------------------------------------------------------
OPERATION_NAMES: dict[int, str] = {
    1:  "APK Information",
    2:  "Manifest Analysis",
    3:  "Permission Analysis",
    4:  "Component Enumeration",
    5:  "String Extraction",
    6:  "Resource Analysis",
    7:  "Domain Discovery",
    8:  "API Endpoint Extraction",
    9:  "Parameter Extraction",
    10: "API Endpoint Normalization",
    11: "Import Burp Suite XML",
    12: "Import HAR File",
    13: "Analyze Imported Traffic",
    14: "Android-to-API Mapping",
    15: "Endpoint Passport Generation",
    16: "APK Version Comparison",
    17: "Search Collected Evidence",
    18: "Generate JSON Report",
    19: "Generate CSV Report",
    20: "Generate HTML Report",
    21: "Security Audit & Exports",
    22: "Session Information",
    23: "View Previous Results",
    24: "Resume Previous Session",
}

OPERATION_DEPENDENCIES: dict[int, list[int]] = {
    1:  [],
    2:  [1],
    3:  [1],
    4:  [2],
    5:  [1],
    6:  [1],
    7:  [1, 5],
    8:  [7],
    9:  [8],
    10: [8],
    11: [],
    12: [],
    13: [],
    14: [8, 15],
    15: [8],
    16: [1],
    17: [],
    18: [],
    19: [],
    20: [],
    21: [1, 2, 4, 5],
    22: [],
    23: [],
    24: [],
}


# "all" runs everything that needs no prompt, with reports last
FULL_RECON: list[int] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 15, 14, 21, 18, 19, 20]


def resolve_dependencies(selected_ops: list[int], completed: frozenset[int] = frozenset()) -> list[int]:
    """Return ops in execution order with dependencies included.

    Dependencies already *completed* in this session are not repeated.
    """
    visited: set[int] = set(completed) - set(selected_ops)
    result: list[int] = []

    def visit(op: int) -> None:
        if op in visited:
            return
        visited.add(op)
        for dep in OPERATION_DEPENDENCIES.get(op, []):
            visit(dep)
        result.append(op)

    for op in selected_ops:
        visit(op)
    return result


# ---------------------------------------------------------------------------
# MenuSystem
# ---------------------------------------------------------------------------
class MenuSystem:
    """Main HUNTX interactive menu system."""

    def __init__(self) -> None:
        self.config = None
        self.target_manager = None
        self.current_target: Optional[str] = None
        self.current_session = None
        self.selected_apks: list = []
        self.has_rich: bool = False
        self._setup()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _setup(self) -> None:
        """Initialise optional deps and config."""
        # Try rich
        try:
            import rich  # noqa: F401
            self.has_rich = True
        except ImportError:
            self.has_rich = False

        # Try config
        try:
            from huntx.core.config import load_config
            self.config = load_config()
        except Exception:
            self.config = None

        # Sys.path: ensure project root on path
        project_root = Path(__file__).resolve().parent.parent.parent
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------
    def _clear_screen(self) -> None:
        print("\033[2J\033[H" if sys.stdout.isatty() else "", end="", flush=True)

    def _print_banner(self) -> None:
        """Print banner with or without Rich."""
        banner_lines = [
            "╔══════════════════════════════════════════╗",
            "║                 HUNTX                   ║",
            "║      Android & API Reconnaissance       ║",
            "║            Version " + HUNTX_VERSION.ljust(20) + "║",
            "╚══════════════════════════════════════════╝",
        ]
        if self.has_rich:
            try:
                from rich.console import Console
                from rich.panel import Panel
                from rich.text import Text
                console = Console()
                content = Text(
                    "\n".join([
                        "HUNTX",
                        "Android & API Reconnaissance",
                        f"Version {HUNTX_VERSION}",
                    ]),
                    justify="center",
                )
                console.print(Panel(content, border_style="green", expand=False))
                return
            except Exception as exc:
                logger.debug("Ignored: %s", exc)
        # Fallback
        for line in banner_lines:
            print(_green(line))

    def _print_separator(self, title: str = "") -> None:
        line = "=" * 40
        print(line)
        if title:
            print(f"{title:^40}")
            print(line)

    def _print_status(self, msg: str, status: str = "info") -> None:
        """Print a coloured status line."""
        if status == "info":
            prefix = _green("[+]")
        elif status == "warn":
            prefix = _yellow("[!]")
        elif status == "error":
            prefix = _red("[-]")
        elif status == "ok":
            prefix = _green("[✓]")
        else:
            prefix = "[*]"
        print(f"{prefix} {msg}")

    def _get_input(self, prompt: str) -> Optional[str]:
        """Wrapper around input() — returns None on interrupt, '' on empty."""
        try:
            val = input(prompt)
            return val.strip()
        except (KeyboardInterrupt, EOFError):
            return None

    def _press_enter(self) -> None:
        try:
            input("\nPress Enter to continue...")
        except (KeyboardInterrupt, EOFError):
            pass

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------
    def _show_startup(self) -> None:
        self._clear_screen()
        self._print_banner()
        print()

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Main entry point. Never exits unexpectedly on bad input."""
        self._show_startup()
        self._run_target_selection()

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------
    def _render_targets_table(self, targets: list, base: Path, tm) -> None:
        """Render target selection using professional Rich Table."""
        from huntx.cli.theme import get_console, make_header_panel, make_status_bar
        from rich.table import Table
        from rich.panel import Panel

        console = get_console()
        console.print(make_header_panel())

        table = Table(
            title=f"[bold green]AVAILABLE TARGET WORKSPACES[/bold green] [dim]({base})[/dim]",
            box=None,
            border_style="bright_black",
            header_style="bold green",
            expand=True,
            padding=(0, 2),
        )
        table.add_column("No.", style="bold cyan", width=6)
        table.add_column("Target Name", style="bold white", width=25)
        table.add_column("Discovered APKs & Bundles", style="cyan")

        if targets:
            for idx, t in enumerate(targets, 1):
                apks = tm.find_apks(base / t) if tm else []
                apk_str = ", ".join(f"{a.filename} ({a.size_human})" for a in apks) if apks else "[dim]No APKs[/dim]"
                table.add_row(f"{idx:>2}.", t, apk_str)
        else:
            table.add_row("-", "[dim](no targets found in directory)[/dim]", "[dim]Use 'N' to create new target workspace[/dim]")

        console.print(Panel(table, border_style="bright_black"))
        console.print(make_status_bar(target_dir=base, shortcuts="1-N: Select Target  •  N: New Target  •  0: Exit  •  h: Help  •  r: Refresh"))
        console.print()

    def _render_apks_table(self, apks: list, target_path: Path) -> None:
        """Render APK selection using professional Rich Table."""
        from huntx.cli.theme import get_console, make_header_panel, make_status_bar
        from rich.table import Table
        from rich.panel import Panel

        console = get_console()
        console.print(make_header_panel(target_name=target_path.name))

        table = Table(
            title=f"[bold green]DISCOVERED APK FILES & CONTAINERS[/bold green] [dim]({target_path.name})[/dim]",
            box=None,
            border_style="bright_black",
            header_style="bold green",
            expand=True,
            padding=(0, 2),
        )
        table.add_column("No.", style="bold cyan", width=6)
        table.add_column("Filename", style="bold white", width=36)
        table.add_column("Size", justify="right", style="green", width=12)
        table.add_column("Container Type", style="dim")

        if apks:
            for idx, apk in enumerate(apks, 1):
                size_str = self._human_size(apk.stat().st_size) if hasattr(apk, 'stat') else ""
                name_part = apk.name if isinstance(apk, Path) else str(apk)
                ext = Path(name_part).suffix.lower()
                ctype = "XAPK / Split Bundle" if ext in (".xapk", ".apks") else "Android Package (APK)"
                table.add_row(f"{idx:>2}.", name_part, size_str, ctype)
        else:
            table.add_row("-", "[yellow]No APK files found in target folder[/yellow]", "-", "[dim]Place .apk/.xapk or enter manual path[/dim]")

        console.print(Panel(table, border_style="bright_black"))
        console.print(make_status_bar(target_dir=target_path, shortcuts="1-N: Select APK(s)  •  A: Select All  •  B: Enter Path Manually  •  0: Back"))
        console.print()

    def _get_target_base(self) -> Path:
        if self.config and hasattr(self.config, "target_base"):
            return Path(self.config.target_base)
        try:
            from huntx.core.config import DEFAULT_TARGET_BASE
            return DEFAULT_TARGET_BASE
        except Exception:
            return Path(__file__).resolve().parent.parent.parent / "Target"

    def _get_target_manager(self, base: Path):
        try:
            from huntx.core.target_manager import TargetManager
            return TargetManager(base)
        except Exception:
            return None

    def _run_target_selection(self) -> None:
        while True:
            self._clear_screen()
            base = self._get_target_base()

            # Ensure base dir exists
            if not base.exists():
                print()
                ans = self._get_input(
                    f"  Target directory {base} does not exist. Create it? (Y/N): "
                )
                if ans is None:
                    print("\nInterrupted.")
                    sys.exit(0)
                if ans.lower() == "y":
                    try:
                        base.mkdir(parents=True, exist_ok=True)
                        self._print_status(f"Created {base}", "ok")
                    except OSError as exc:
                        self._print_status(f"Could not create directory: {exc}", "error")
                        self._press_enter()
                        continue
                else:
                    print("Exiting.")
                    sys.exit(0)

            tm = self._get_target_manager(base)

            # List targets
            if tm:
                try:
                    targets = tm.list_targets()
                except Exception:
                    targets = []
            else:
                targets = [
                    d.name for d in base.iterdir()
                    if d.is_dir() and not d.name.startswith(".")
                ] if base.exists() else []

            # Render Rich Target Table
            self._render_targets_table(targets, base, tm)

            choice = self._get_input("Select Target [1-N, N=new, 0=exit, h=help, r=refresh]: ")

            if choice is None:
                print("\nInterrupted. Goodbye.")
                sys.exit(0)

            if choice == "0":
                print("Goodbye.")
                sys.exit(0)

            if choice.lower() == "r":
                continue

            if choice.lower() == "h":
                self._help_target_selection()
                self._press_enter()
                continue

            if choice.lower() == "n":
                self._create_new_target(base, tm)
                continue

            # Numeric selection
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(targets):
                    self.current_target = targets[idx - 1]
                    target_path = base / self.current_target
                    self._run_apk_selection(target_path)
                else:
                    self._print_status(f"Invalid choice: {choice}. Enter 1-{len(targets)}, N, 0.", "error")
                    self._press_enter()
            else:
                self._print_status(f"Invalid input: '{choice}'. Use a number, N, 0, h, or r.", "error")
                self._press_enter()

    def _create_new_target(self, base: Path, tm) -> None:
        name = self._get_input("  Enter new target name: ")
        if name is None or name == "":
            self._print_status("Target name cannot be empty.", "error")
            self._press_enter()
            return
        if tm:
            try:
                sanitized = tm.sanitize_name(name)
                tm.create_target(sanitized)
                self._print_status(f"Target '{sanitized}' created.", "ok")
            except ValueError as exc:
                self._print_status(str(exc), "error")
            except Exception as exc:
                self._print_status(f"Error creating target: {exc}", "error")
        else:
            # Fallback: basic validation
            import re
            if not re.match(r'^[A-Za-z0-9_\-]+$', name):
                self._print_status("Name must be alphanumeric with dashes/underscores only.", "error")
                self._press_enter()
                return
            target_path = base / name
            target_path.mkdir(parents=True, exist_ok=True)
            self._print_status(f"Target '{name}' created at {target_path}", "ok")
        self._press_enter()

    def _help_target_selection(self) -> None:
        print()
        print(_bold("TARGET SELECTION HELP"))
        print("─" * 40)
        print("  Enter a number  : Select that target")
        print("  N               : Create a new target")
        print("  0               : Exit HUNTX")
        print("  r               : Refresh target list")
        print("  h               : Show this help")
        print()
        print("Targets are directories inside:")
        base = self._get_target_base()
        print(f"  {base}")

    # ------------------------------------------------------------------
    # APK selection
    # ------------------------------------------------------------------
    def _run_apk_selection(self, target_path: Path) -> None:
        while True:
            self._clear_screen()

            # Find APKs
            apks = self._find_apks(target_path)

            # Render Rich APK Table
            self._render_apks_table(apks, target_path)

            choice = self._get_input("Select APK(s) [1-N, A=all, B=manual, 0=back]: ")

            if choice is None:
                break

            if choice == "0":
                break

            if choice.lower() == "b":
                apk_path = self._get_input("  Enter APK file path: ")
                if apk_path:
                    p = Path(apk_path.strip("'\"")).expanduser()
                    if p.is_file() and p.suffix.lower() in (".apk", ".xapk", ".apks"):
                        self.selected_apks = [p]
                        self._run_session_menu(target_path, self.selected_apks)
                    else:
                        self._print_status("File not found or not an APK.", "error")
                        self._press_enter()
                continue

            if choice.lower() in ("a", "all"):
                if not apks:
                    self._print_status("No APKs to select.", "warn")
                    self._press_enter()
                    continue
                selected = list(apks)
            else:
                # Parse comma-separated or single
                parts = [p.strip() for p in choice.split(",")]
                selected = []
                valid = True
                for part in parts:
                    if not part.isdigit():
                        self._print_status(f"Invalid selection: '{part}'.", "error")
                        valid = False
                        break
                    idx = int(part)
                    if idx < 1 or idx > len(apks):
                        self._print_status(f"Number {idx} is out of range.", "error")
                        valid = False
                        break
                    candidate = apks[idx - 1]
                    if candidate not in selected:
                        selected.append(candidate)
                if not valid:
                    self._press_enter()
                    continue

            if not selected:
                self._print_status("No APKs selected.", "warn")
                self._press_enter()
                continue

            # Confirm
            print()
            print("Selected APKs:")
            for apk in selected:
                name_part = apk.name if isinstance(apk, Path) else str(apk)
                print(f"  {_green('✓')} {name_part}")
            print()

            confirm = self._get_input("Proceed with these APKs? (Y/N/b=back): ")
            if confirm is None or confirm.lower() == "b":
                continue
            if confirm.lower() == "y":
                self.selected_apks = selected
                self._run_session_menu(target_path, selected)
            # else loop back

    def _find_apks(self, target_path: Path) -> list:
        """Find APK files; use TargetManager if available."""
        try:
            from huntx.core.target_manager import TargetManager
            base = self._get_target_base()
            tm = TargetManager(base)
            apk_files = tm.find_apks(target_path)
            return [af.path for af in apk_files]
        except Exception as exc:
            logger.debug("Ignored: %s", exc)
        # Fallback
        if not target_path.exists():
            return []
        return sorted(target_path.rglob("*.apk"))

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024  # type: ignore[assignment]
        return f"{size_bytes:.1f} TB"

    # ------------------------------------------------------------------
    # Session menu
    # ------------------------------------------------------------------
    def _run_session_menu(self, target_path: Path, apks: list) -> None:
        while True:
            self._clear_screen()
            self._print_banner()
            print()
            self._print_separator("SESSION MANAGEMENT")
            print()
            apk_names = ", ".join(
                (a.name if isinstance(a, Path) else str(a)) for a in apks
            )
            print(f"  Target: {_cyan(target_path.name)}")
            print(f"  APKs  : {apk_names}")
            print()
            print("  1. Start New Session")
            print("  2. Resume Existing Session")
            print()
            print("  0. Back")
            print()

            choice = self._get_input("Choice: ")

            if choice is None or choice == "0":
                break

            if choice == "1":
                session = self._start_new_session(target_path, apks)
                if session:
                    self.current_session = session
                    self._run_recon_menu(target_path, apks)
                else:
                    self._press_enter()

            elif choice == "2":
                session = self._resume_session(target_path, apks)
                if session:
                    self.current_session = session
                    self._run_recon_menu(target_path, apks)
                else:
                    self._press_enter()
            else:
                self._print_status(f"Invalid choice: '{choice}'.", "error")
                self._press_enter()

    def _start_new_session(self, target_path: Path, apks: list):
        from huntx.core.pipeline import ScanError, open_session
        try:
            session, self.selected_apks = open_session(target_path, [Path(a) for a in apks])
        except (ScanError, OSError) as exc:
            self._print_status(f"Could not start session: {exc}", "error")
            return None
        self._print_status(f"Session created: {session.metadata.run_dir} ({len(self.selected_apks)} APK file(s))", "ok")
        self._press_enter()
        return session

    def _resume_session(self, target_path: Path, apks: list):
        from huntx.core.session import SessionManager
        sm = SessionManager(target_path)
        sessions = sm.list_sessions()

        if not sessions:
            self._print_status("No existing sessions found.", "warn")
            return None

        print()
        print("Recent Sessions:")
        shown = sessions[:5]
        for idx, s in enumerate(shown, 1):
            print(f"  {idx}. {s.run_dir}  {s.created_at[:19]}")
        print("  0. Back")
        print()

        choice = self._get_input("Select session: ")
        if choice is None or choice == "0":
            return None

        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(shown):
                selected = shown[idx - 1]
                try:
                    return sm.load_session(selected.run_dir)
                except (OSError, ValueError, TypeError) as exc:
                    self._print_status(f"Cannot load {selected.run_dir}: {exc}", "error")
                    return None

        self._print_status("Invalid selection.", "error")
        return None

    # ------------------------------------------------------------------
    # Recon menu
    # ------------------------------------------------------------------
    def _get_session_summary_stats(self) -> dict:
        """Collect attack surface summary statistics for Command Centre dashboard."""
        stats = {
            "total_endpoints": 0,
            "total_domains": 0,
            "exported_components": 0,
            "unprotected_components": 0,
            "dangerous_perms": 0,
            "total_perms": 0,
        }
        if not self.current_session or not hasattr(self.current_session, "run_path"):
            return stats

        run_path = self.current_session.run_path
        
        # Endpoints
        ep_f = run_path / "api" / "endpoints.json"
        if ep_f.exists():
            try:
                d = json.loads(ep_f.read_text(encoding="utf-8"))
                stats["total_endpoints"] = len(d.get("endpoints", []) if isinstance(d, dict) else d)
            except Exception as exc:
                logger.debug("Ignored: %s", exc)

        # Domains
        dom_f = run_path / "api" / "domains.json"
        if dom_f.exists():
            try:
                d = json.loads(dom_f.read_text(encoding="utf-8"))
                stats["total_domains"] = len(d.get("domains", []) if isinstance(d, dict) else d)
            except Exception as exc:
                logger.debug("Ignored: %s", exc)

        # Components
        comp_f = run_path / "android" / "components.json"
        if comp_f.exists():
            try:
                d = json.loads(comp_f.read_text(encoding="utf-8"))
                comps = d.get("components", []) if isinstance(d, dict) else d
                stats["exported_components"] = len([c for c in comps if c.get("exported")])
                stats["unprotected_components"] = len([c for c in comps if c.get("unprotected")])
            except Exception as exc:
                logger.debug("Ignored: %s", exc)

        # Permissions
        perm_f = run_path / "android" / "permissions.json"
        if perm_f.exists():
            try:
                d = json.loads(perm_f.read_text(encoding="utf-8"))
                perms = d.get("permissions", []) if isinstance(d, dict) else d
                stats["total_perms"] = len(perms)
                stats["dangerous_perms"] = len([p for p in perms if p.get("is_dangerous") or "dangerous" in str(p.get("protection_level", "")).lower()])
            except Exception as exc:
                logger.debug("Ignored: %s", exc)

        return stats

    def _render_command_centre_tui(self, target_path: Path, apks: list, session_id: str) -> None:
        """Render the Command Centre multi-column terminal interface."""
        from huntx.cli.theme import get_console, make_header_panel, make_status_bar, make_metrics_table
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        console = get_console()
        apk_names = ", ".join(
            (a.name if isinstance(a, Path) else str(a)) for a in apks
        )
        header = make_header_panel(
            target_name=target_path.name,
            apk_name=apk_names or "None",
            session_id=session_id,
            is_offline=True,
        )
        console.print(header)

        # 1. Left Nav & Operation Matrix
        nav_table = Table(
            title="[bold green]COMMAND CENTRE OPERATIONS[/bold green]",
            box=None,
            header_style="bold green",
            border_style="bright_black",
            expand=True,
            padding=(0, 1),
        )
        nav_table.add_column("No.", style="bold cyan", width=5)
        nav_table.add_column("Recon Engine Module", style="bold white", width=28)
        nav_table.add_column("Capability Focus", style="dim")

        # Operations grouped with clean security headings
        groups = [
            ("ANDROID ANALYSIS", [
                (1, "APK Information", "Metadata, ABIs, SDKs, Signing Keys"),
                (2, "Manifest Analysis", "Exported attack surface & security flags"),
                (3, "Permission Analysis", "11 functional permission buckets"),
                (4, "Component Enumeration", "Activities, Services, Receivers, Providers"),
                (5, "String Extraction", "DEX strings, candidate tokens, credentials"),
                (6, "Resource Analysis", "Network security config, XML resources"),
            ]),
            ("API RECONNAISSANCE", [
                (7, "Domain Discovery", "Hostnames, API domains, endpoints"),
                (8, "API Endpoint Extraction", "Full URLs, relative routes, Retrofit"),
                (9, "Parameter Extraction", "Path, query, header, body taxonomy"),
                (10, "Endpoint Normalization", "Parameter abstraction ({id}, {uuid})"),
            ]),
            ("TRAFFIC ANALYSIS", [
                (11, "Import Burp Suite XML", "Passive Burp HTTP/HTTPS history"),
                (12, "Import HAR File", "Standard HTTP Archive traffic logs"),
                (13, "Analyze Imported Traffic", "Correlate wire requests with static routes"),
            ]),
            ("INTELLIGENCE & VISUALIZATION", [
                (14, "Android-to-API Mapping", "Associate Android Classes to API routes"),
                (15, "Endpoint Passport Gen", "Unified EP-00001 evidence passports"),
                (16, "APK Version Comparison", "Delta diff between APK analysis runs"),
                (17, "Search Collected Evidence", "Offline keyword/endpoint query engine"),
                (18, "Generate JSON Report", "Authoritative machine-readable export"),
                (19, "Generate CSV Report", "Spreadsheets for endpoints & domains"),
                (20, "Generate HTML Report", "Standalone technical report"),
                (21, "Security Audit & Exports", "Secrets, ADB checks, Postman, wordlists"),
            ]),
            ("INVESTIGATION & WORKSPACE", [
                (22, "Session Information", "Session directory, database & file paths"),
                (23, "View Previous Results", "Browse completed analysis outputs"),
                (24, "Resume Previous Session", "Switch to an existing RUN_* directory"),
            ]),
        ]

        for grp_name, ops in groups:
            nav_table.add_row("", f"[bold green]{grp_name}[/bold green]", "")
            for num, name, desc in ops:
                nav_table.add_row(f"{num:>2}.", name, desc)

        # 2. Right Stats Panel
        stats = self._get_session_summary_stats()
        metrics_table = make_metrics_table(stats)

        # 3. Print Two-Column Command Centre Layout
        cols = Columns([
            Panel(nav_table, border_style="bright_black", padding=(0, 1)),
            Panel(metrics_table, border_style="bright_black", padding=(0, 1)),
        ], expand=True)

        console.print(cols)

        # 4. Bottom Status Strip
        base = self._get_target_base()
        status_strip = make_status_bar(
            target_dir=base / target_path.name,
            db_status="Connected (SQLite)",
            shortcuts="1-24: Run Module  •  all: Full Recon  •  0/b: Back  •  h: Help",
        )
        console.print(status_strip)
        console.print()

    def _run_recon_menu(self, target_path: Path, apks: list) -> None:
        while True:
            self._clear_screen()
            session = self.current_session
            session_id = getattr(getattr(session, "metadata", None), "session_id", "N/A")
            
            # Render Rich Command Centre TUI
            self._render_command_centre_tui(target_path, apks, session_id)

            choice = self._get_input("Select Operations [e.g. 1,2,4 or all or 0 to exit]: ")

            if choice is None or choice == "0" or choice.lower() == "b":
                break

            if choice.lower() == "h":
                self._help_recon_menu()
                self._press_enter()
                continue

            if choice.lower() == "r":
                continue

            # Parse selection
            if choice.lower() == "all":
                raw_ops = list(FULL_RECON)
            else:
                parts = [p.strip() for p in choice.split(",")]
                raw_ops = []
                valid = True
                for part in parts:
                    if not part.isdigit():
                        self._print_status(f"Invalid input: '{part}'. Use numbers, 'all', or 0.", "error")
                        valid = False
                        break
                    num = int(part)
                    if num == 0:
                        valid = False
                        break
                    if num not in OPERATION_NAMES:
                        self._print_status(f"Operation {num} is out of range (1-24).", "error")
                        valid = False
                        break
                    if num not in raw_ops:
                        raw_ops.append(num)
                if not valid:
                    self._press_enter()
                    continue

            if not raw_ops:
                self._press_enter()
                continue

            # Resolve deps and confirm
            done = frozenset(int(x) for x in session.metadata.completed_ops if str(x).isdigit())
            resolved = resolve_dependencies(raw_ops, done)

            print()
            print("Selected Operations:")
            for op in resolved:
                # Indicate if auto-added as dependency
                print(f"  {_green('[+]') if op in raw_ops else _yellow('[dep]')} {OPERATION_NAMES[op]}")
            print()

            confirm = self._get_input("Proceed? (Y/N): ")
            if confirm is None or confirm.lower() != "y":
                continue

            print()
            for op in resolved:
                success = self._execute_operation(op)
                if not success:
                    self._print_status(f"Operation {op} failed.", "error")
            print()

            # Display direct links to generated reports if available
            self._display_report_links()

            self._press_enter()

    def _display_report_links(self) -> None:
        """Display clickable file:// links for generated reports."""
        if not self.current_session or not hasattr(self.current_session, "run_path"):
            return
        
        rep_dir = self.current_session.run_path / "reports"
        summary_report = rep_dir / "huntx-summary.html"
        html_report = rep_dir / "huntx-report.html"
        json_report = rep_dir / "huntx-report.json"

        found_links = []
        if summary_report.exists():
            found_links.append(("Executive Summary", summary_report))
        if html_report.exists():
            found_links.append(("HTML Report", html_report))
        if json_report.exists():
            found_links.append(("JSON Report", json_report))

        if not found_links:
            return

        print(_bold("═" * 60))
        print(_bold("  RECONNAISSANCE ARTIFACTS & REPORT LINKS"))
        print(_bold("═" * 60))
        for title, p in found_links:
            uri = p.as_uri()
            print(f"  • {title:22}: {_cyan(uri)}")
            print(f"    (Path: {p})")
        print(_bold("═" * 60))
        print()

    def _help_recon_menu(self) -> None:
        print()
        print(_bold("RECONNAISSANCE MENU HELP"))
        print("─" * 40)
        print("  Single number  : Run one operation (e.g. 1)")
        print("  Comma-separated: Run multiple (e.g. 1,2,7,8)")
        print("  all            : Run all operations")
        print("  0 or b         : Back to previous menu")
        print("  r              : Refresh/redisplay menu")
        print("  h              : Show this help")
        print()
        print("Dependencies are automatically resolved and")
        print("included. E.g. selecting 8 also runs 7.")

    # ------------------------------------------------------------------
    # Operation dispatcher & execution
    # ------------------------------------------------------------------
    def _execute_operation(self, op_num: int) -> bool:
        """Execute a single operation. Returns True on success."""
        op_name = OPERATION_NAMES.get(op_num, f"Op {op_num}")
        print()
        self._print_status(f"Starting Operation {op_num}: {op_name}...", "info")

        dispatch = {
            1: self._op_apk_info,
            2: self._op_manifest_analysis,
            3: self._op_permission_analysis,
            4: self._op_component_enumeration,
            5: self._op_string_extraction,
            6: self._op_resource_analysis,
            7: self._op_domain_discovery,
            8: self._op_endpoint_extraction,
            9: self._op_parameter_extraction,
            10: self._op_endpoint_normalization,
            11: self._op_import_burp,
            12: self._op_import_har,
            13: self._op_analyze_traffic,
            14: self._op_android_api_mapping,
            15: self._op_endpoint_passport,
            16: self._op_apk_diff,
            17: self._op_search,
            18: self._op_json_report,
            19: self._op_csv_report,
            20: self._op_html_report,
            21: self._op_security_audit,
            22: self._op_session_info,
            23: self._op_view_results,
            24: self._op_resume_session,
        }

        handler = dispatch.get(op_num)
        if handler is None:
            self._print_status(f"Unknown operation: {op_num}", "error")
            return False

        try:
            success = handler()
            if success:
                self._record_completed_op(op_num)
                self._print_status(f"Operation {op_num} ({op_name}) completed successfully.", "ok")
            else:
                self._print_status(f"Operation {op_num} ({op_name}) reported issues or incomplete output.", "warn")
            return success
        except Exception as e:
            logger.exception("Operation %s failed", op_num)
            self._print_status(f"Error executing {op_name}: {e}", "error")
            return False

    def _record_completed_op(self, op_num: int) -> None:
        if self.current_session is None:
            return
        meta = getattr(self.current_session, "metadata", None)
        if meta is None:
            return
        op_str = str(op_num)
        if op_str not in meta.completed_ops:
            meta.completed_ops.append(op_str)
        try:
            from huntx.core.session import SessionManager
            SessionManager(self.current_session.run_path.parent).save_metadata(self.current_session)
        except (OSError, AttributeError, TypeError) as exc:
            logger.warning("Could not save session metadata: %s", exc)

    def _session_apks(self) -> list[Path]:
        """Every APK of the active session, base first."""
        from huntx.core.session import sort_apks
        run_path = getattr(self.current_session, "run_path", None)
        input_dir = run_path / "input" if run_path else None
        if not input_dir or not input_dir.exists():
            return []
        pkg_name = ""
        try:
            pkg_name = str(json.loads((input_dir / "manifest.json").read_text(encoding="utf-8")).get("package_name", ""))
        except (OSError, ValueError, AttributeError):
            pass  # only XAPK bundles carry one
        return sort_apks(list(input_dir.glob("*.apk")), pkg_name)

    def _get_active_apk(self) -> Optional[Path]:
        session = self.current_session
        if session and hasattr(session, "run_path") and session.run_path:
            input_dir = session.run_path / "input"
            if input_dir.exists():
                apks = self._session_apks()
                if apks:
                    return apks[0]

                # If container exists in input, unpack it
                containers = list(input_dir.glob("*.xapk")) + list(input_dir.glob("*.apks"))
                if containers:
                    from huntx.core.session import unpack_xapk
                    extracted = unpack_xapk(containers[0], input_dir)
                    if extracted:
                        return extracted[0]

        if self.selected_apks:
            for apk in self.selected_apks:
                p = Path(apk) if isinstance(apk, (str, Path)) else None
                if p and p.exists():
                    ext = p.suffix.lower()
                    if ext == ".apk":
                        return p
                    elif ext in (".xapk", ".apks"):
                        if session and hasattr(session, "run_path") and session.run_path:
                            inp = session.run_path / "input"
                            inp.mkdir(parents=True, exist_ok=True)
                            from huntx.core.session import unpack_xapk
                            extracted = unpack_xapk(p, inp)
                            if extracted:
                                return extracted[0]
                        return p

        meta = getattr(session, "metadata", None)
        if meta and hasattr(meta, "apk_files") and meta.apk_files:
            apk_item = meta.apk_files[0]
            fname = apk_item.get("filename") if isinstance(apk_item, dict) else str(apk_item)
            if self.current_target:
                p = self._get_target_base() / self.current_target / fname
                if p.exists():
                    if p.suffix.lower() == ".apk":
                        return p
                    elif p.suffix.lower() in (".xapk", ".apks"):
                        return p

        return None

    # Op 1: APK Information
    def _op_apk_info(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.apk_info import extract_apk_info
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        info = extract_apk_info(apk, output_dir=out_dir)
        pkg = info.get("package_name", "N/A")
        ver = info.get("version_name", "N/A")
        self._print_status(f"Package: {pkg} (Version: {ver})", "info")
        return True

    # Op 2: Manifest Analysis
    def _op_manifest_analysis(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.manifest import analyze_manifest
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        res = analyze_manifest(apk, output_dir=out_dir)
        pkg = res.get("package", "")
        perms = len(res.get("used_permissions", []))
        comps = len(res.get("components", []))
        self._print_status(f"Manifest analyzed: {pkg} ({perms} permissions, {comps} components)", "info")
        return True

    # Op 3: Permission Analysis
    def _op_permission_analysis(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.permissions import analyze_permissions
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        res = analyze_permissions(apk, output_dir=out_dir)
        total = res.get("total_permissions", 0)
        dang = res.get("dangerous_count", 0)
        self._print_status(f"Permissions: {total} total, {dang} dangerous privileges", "info")
        return True

    # Op 4: Component Enumeration
    def _op_component_enumeration(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.components import enumerate_components
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        res = enumerate_components(apk, output_dir=out_dir, session=self.current_session)
        total = res.get("total_components", 0)
        exp = res.get("exported_count", 0)
        self._print_status(f"Components: {total} total, {exp} exported", "info")
        return True

    # Op 5: String Extraction
    def _op_string_extraction(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.strings import extract_strings
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        apks = self._session_apks() or [apk]
        res = extract_strings(apks, output_dir=out_dir)
        if self.current_session:
            from huntx.core.pipeline import write_dex_xrefs
            write_dex_xrefs(apks, self.current_session.run_path)
        total = res.get("total_extracted", 0)
        secrets = len(res.get("tokens", []))
        self._print_status(f"Strings: {total} extracted, {secrets} candidate secrets identified", "info")
        return True

    # Op 6: Resource Analysis
    def _op_resource_analysis(self) -> bool:
        apk = self._get_active_apk()
        if not apk:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.resources import analyze_resources
        out_dir = self.current_session.run_path / "android" if self.current_session else None
        res = analyze_resources(apk, output_dir=out_dir)
        cleartext = res.get("network_security_config", {}).get("base_cleartext_permitted")
        self._print_status(f"Resources analyzed (security config cleartext: {cleartext if cleartext is not None else 'not set'})", "info")
        return True

    # Op 7: Domain Discovery
    def _op_domain_discovery(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.engines.api.domains import run_domain_discovery
        out_dir = self.current_session.run_path / "api"
        res = run_domain_discovery(session=self.current_session, output_dir=out_dir)
        count = res.get("total_domains", len(res.get("domains", [])))
        self._print_status(f"Discovered {count} unique domains", "info")
        return True

    # Op 8: API Endpoint Extraction
    def _op_endpoint_extraction(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.engines.api.endpoints import run_endpoint_extraction
        out_dir = self.current_session.run_path / "api"
        res = run_endpoint_extraction(session=self.current_session, output_dir=out_dir)
        count = res.get("total_endpoints", len(res.get("endpoints", [])))
        self._print_status(f"Extracted {count} API endpoints", "info")
        return True

    # Op 9: Parameter Extraction
    def _op_parameter_extraction(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.engines.api.parameters import run_parameter_extraction
        out_dir = self.current_session.run_path / "api"
        res = run_parameter_extraction(session=self.current_session, output_dir=out_dir)
        count = res.get("total_parameters", len(res.get("parameters", [])))
        self._print_status(f"Extracted {count} parameters", "info")
        return True

    # Op 10: API Endpoint Normalization
    def _op_endpoint_normalization(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.engines.api.normalizer import run_normalization
        out_dir = self.current_session.run_path / "api"
        res = run_normalization(session=self.current_session, output_dir=out_dir)
        count = res.get("total_unique_patterns", len(res.get("normalized_endpoints", [])))
        self._print_status(f"Normalized {count} unique endpoint patterns", "info")
        return True

    # Op 11: Import Burp Suite XML
    def _op_import_burp(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        file_path_str = self._get_input("  Path to Burp XML file: ")
        if not file_path_str:
            self._print_status("No file path provided.", "warn")
            return False
        p = Path(file_path_str.strip('"\''))
        if not p.exists():
            self._print_status(f"File not found: {p}", "error")
            return False
        from huntx.engines.traffic.parser import run_traffic_analysis
        out_dir = self.current_session.run_path / "traffic"
        res = run_traffic_analysis(session=self.current_session, source_files=[p], output_dir=out_dir)
        total = res.get("total_requests", 0)
        self._print_status(f"Imported Burp XML: {total} requests parsed", "info")
        return True

    # Op 12: Import HAR File
    def _op_import_har(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        file_path_str = self._get_input("  Path to HAR file: ")
        if not file_path_str:
            self._print_status("No file path provided.", "warn")
            return False
        p = Path(file_path_str.strip('"\''))
        if not p.exists():
            self._print_status(f"File not found: {p}", "error")
            return False
        from huntx.engines.traffic.parser import run_traffic_analysis
        out_dir = self.current_session.run_path / "traffic"
        res = run_traffic_analysis(session=self.current_session, source_files=[p], output_dir=out_dir)
        total = res.get("total_requests", 0)
        self._print_status(f"Imported HAR: {total} requests parsed", "info")
        return True

    # Op 13: Analyze Imported Traffic
    def _op_analyze_traffic(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.engines.traffic.parser import run_traffic_analysis
        out_dir = self.current_session.run_path / "traffic"
        res = run_traffic_analysis(session=self.current_session, output_dir=out_dir)
        total = res.get("total_requests", 0)
        eps = res.get("unique_endpoints", 0)
        self._print_status(f"Traffic analyzed: {total} requests, {eps} unique endpoints", "info")
        return True

    # Op 14: Android-to-API Mapping
    def _op_android_api_mapping(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.intelligence.android_api_mapper import map_android_to_apis
        res = map_android_to_apis(session=self.current_session)
        cls_count = res.android_api_map.get("total_mapped_classes", 0)
        ep_count = res.endpoint_sources.get("total_mapped_endpoints", 0)
        self._print_status(f"Mapped {cls_count} Android classes to {ep_count} API endpoints", "info")
        return True

    # Op 15: Endpoint Passport Generation
    def _op_endpoint_passport(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.intelligence.endpoint_passport import generate_endpoint_passports
        passports = generate_endpoint_passports(session=self.current_session)
        self._print_status(f"Generated {len(passports)} unified Endpoint Passports (EP-00001 ...)", "info")
        return True

    # Op 16: APK Version Comparison
    def _op_apk_diff(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.core.session import SessionManager
        from huntx.intelligence.apk_diff import compare_apk_runs
        target_path = self._get_target_base() / (self.current_target or "")
        sm = SessionManager(target_path) if target_path.exists() else None
        other_sessions = [s for s in sm.list_sessions() if s.session_id != self.current_session.metadata.session_id] if sm else []

        target_run = None
        if other_sessions:
            print()
            print(_bold("Available prior sessions for comparison:"))
            for i, s in enumerate(other_sessions, start=1):
                print(f"  [{i}] {s.run_dir} ({s.created_at})")
            sel = self._get_input("\nSelect session number to compare against (or enter directory path): ")
            if sel and sel.isdigit() and 1 <= int(sel) <= len(other_sessions):
                target_meta = other_sessions[int(sel) - 1]
                target_run = sm.load_session(target_meta.run_dir)
            elif sel:
                target_run = Path(sel.strip('"\''))
        else:
            sel = self._get_input("Path to previous session directory or APK: ")
            if sel:
                target_run = Path(sel.strip('"\''))

        if not target_run:
            self._print_status("No comparison target selected.", "warn")
            return False

        out_file = self.current_session.run_path / "mapping" / "apk-comparison.json"
        diff = compare_apk_runs(target_run, self.current_session, output_file=out_file)
        s = diff.summary
        self._print_status(
            f"APK Diff: +{s.new_endpoints_count}/-{s.removed_endpoints_count} endpoints, "
            f"+{s.new_domains_count}/-{s.removed_domains_count} domains, "
            f"+{s.added_permissions_count} perms (Risk: {s.security_risk_delta})",
            "info"
        )
        return True

    # Op 17: Search Collected Evidence
    def _op_search(self) -> bool:
        query = self._get_input("  Search query: ")
        if not query:
            self._print_status("Empty query.", "warn")
            return False

        from huntx.core.search import SearchEngine
        session = self.current_session
        db_path = getattr(session, "db_path", None) or Path("huntx.db")
        run_path = getattr(session, "run_path", None)
        engine = SearchEngine(db_path, session_run_path=run_path)
        results = engine.search(query)

        if results:
            print()
            print(_bold(f"Search Results for '{query}' ({len(results)} matches):"))
            print("─" * 50)
            for r in results[:25]:
                disp = r.get("_display") or str(r)
                print(f"  {disp}")
            if len(results) > 25:
                print(f"  ... and {len(results) - 25} more")
        else:
            self._print_status("No matches found.", "info")
        return True

    # Op 18: Generate JSON Report
    def _op_json_report(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.reporting.json_report import generate_json_report
        generate_json_report(session=self.current_session)
        path = self.current_session.run_path / "reports" / "huntx-report.json"
        self._print_status(f"Unified JSON Report generated: {path}", "ok")
        return True

    # Op 19: Generate CSV Report
    def _op_csv_report(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.reporting.csv_report import generate_csv_reports
        csvs = generate_csv_reports(session=self.current_session)
        self._print_status(f"CSV Reports generated ({', '.join(csvs.keys())}) in reports/", "ok")
        return True

    # Op 20: Generate HTML Report
    def _op_html_report(self) -> bool:
        if not self.current_session:
            self._print_status("No active session.", "error")
            return False
        from huntx.reporting.summary_report import generate_summary_report
        from huntx.reporting.html_report import generate_html_report

        sum_path = generate_summary_report(session=self.current_session)
        sum_uri = Path(sum_path).as_uri()

        det_path = generate_html_report(session=self.current_session)
        det_uri = Path(det_path).as_uri()

        self._print_status(f"Executive One-Page Report generated: {sum_path}", "ok")
        print(f"  --> Executive Summary (A4 Print-Ready): {_cyan(sum_uri)}")
        self._print_status(f"Detailed Inventory Report generated: {det_path}", "ok")
        print(f"  --> Technical Inventory Report: {_cyan(det_uri)}")
        return True

    # Op 21: Security Audit & Exports
    def _op_security_audit(self) -> bool:
        apk = self._get_active_apk()
        if not apk or not self.current_session:
            self._print_status("No APK file found in active session.", "error")
            return False
        from huntx.engines.android.security_audit import run_security_audit
        from huntx.reporting.exporters import export_bug_bounty_artifacts
        res = run_security_audit(self._session_apks() or [apk], run_path=self.current_session.run_path)
        exports = export_bug_bounty_artifacts(self.current_session.run_path)
        self._print_status(
            f"{res['secrets_count']} candidate secrets, {res['cloud_assets_count']} cloud assets, "
            f"{res['adb_pocs_count']} ADB commands; {len(exports)} exports in {self.current_session.run_path / 'exports'}",
            "info",
        )
        return True

    # Op 22: Session Information
    def _op_session_info(self) -> bool:
        """Display real session information."""
        session = self.current_session
        if session is None:
            self._print_status("No active session.", "error")
            return False

        meta = getattr(session, "metadata", None)
        run_path = getattr(session, "run_path", None)
        db_path = getattr(session, "db_path", None)
        log_path = getattr(session, "log_path", None)

        print()
        print(_bold("SESSION INFORMATION"))
        print("=" * 19)
        print(f"Session ID  : {getattr(meta, 'session_id', 'N/A')}")
        print(f"Target      : {getattr(meta, 'target_name', 'N/A')}")
        print(f"Run Dir     : {getattr(meta, 'run_dir', str(run_path) if run_path else 'N/A')}")
        print(f"Created     : {getattr(meta, 'created_at', 'N/A')}")
        print(f"DB Path     : {db_path}")
        print(f"Log Path    : {log_path}")

        # APK files
        apk_files = getattr(meta, "apk_files", [])
        print()
        print("APK Files:")
        if apk_files:
            for apk in apk_files:
                if isinstance(apk, dict):
                    name = apk.get("filename", apk.get("path", str(apk)))
                    sha = apk.get("sha256", "N/A")
                else:
                    name = str(apk)
                    sha = "N/A"
                print(f"  • {name}  (SHA-256: {sha})")
        elif self.selected_apks:
            for apk in self.selected_apks:
                name = apk.name if isinstance(apk, Path) else str(apk)
                sha = "N/A"
                try:
                    import hashlib
                    h = hashlib.sha256()
                    with open(apk, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            h.update(chunk)
                    sha = h.hexdigest()[:16] + "..."
                except Exception as exc:
                    logger.debug("Ignored: %s", exc)
                print(f"  • {name}  (SHA-256: {sha})")
        else:
            print("  (none)")

        # Subdirectories
        subdirs = ["input", "android", "api", "traffic", "mapping", "reports", "logs"]
        print()
        print("Subdirectories:")
        if run_path:
            for sub in subdirs:
                p = run_path / sub
                status = _green("✓") if p.exists() else _red("✗")
                label = "exists" if p.exists() else "missing"
                print(f"  {status} {sub + '/':12} {label}")
        else:
            print("  (run path unknown)")

        return True

    # Op 23: View Previous Results
    def _op_view_results(self) -> bool:
        session = self.current_session
        if not session or not session.run_path:
            self._print_status("No active session.", "error")
            return False
        print()
        print(_bold("SESSION ARTIFACTS & REPORTS"))
        print("=" * 35)
        for sub in ["reports", "mapping", "api", "android", "traffic"]:
            sub_dir = session.run_path / sub
            if sub_dir.exists():
                files = list(sub_dir.glob("*"))
                if files:
                    print(f"\n{sub.upper()}/")
                    for f in sorted(files):
                        sz = f.stat().st_size
                        sz_str = f"{sz} B" if sz < 1024 else f"{sz / 1024:.1f} KB"
                        print(f"  • {f.name:32} ({sz_str})")
        return True

    # Op 24: Resume Previous Session
    def _op_resume_session(self) -> bool:
        from huntx.core.session import SessionManager
        base = self._get_target_base()
        target_dir = base / (self.current_target or "")
        if not target_dir.exists():
            self._print_status("Target directory not found.", "error")
            return False
        sm = SessionManager(target_dir)
        sessions = sm.list_sessions()
        if not sessions:
            self._print_status("No previous sessions found for this target.", "warn")
            return False
        print()
        print(_bold("AVAILABLE SESSIONS FOR RESUME"))
        print("=" * 30)
        for idx, s in enumerate(sessions, start=1):
            print(f"  [{idx}] {s.run_dir} (ID: {s.session_id[:8]}... Created: {s.created_at})")
        val = self._get_input("\nSelect session to resume: ")
        if not val or not val.isdigit() or not (1 <= int(val) <= len(sessions)):
            self._print_status("Invalid selection.", "warn")
            return False
        selected_meta = sessions[int(val) - 1]
        self.current_session = sm.load_session(selected_meta.run_dir)
        self._print_status(f"Resumed session: {selected_meta.run_dir}", "ok")
        return True


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
def main() -> None:
    """Entry point for huntx CLI."""
    menu = MenuSystem()
    menu.run()


def run_menu() -> None:
    """Alias for huntx.sh compatibility."""
    main()


if __name__ == "__main__":
    main()
