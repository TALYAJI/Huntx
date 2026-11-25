"""HUNTX Research Notebook and Investigation Timeline.

Enables security researchers to attach manual findings, hypothesis notes,
and track chronological milestones across assessment sessions.
Notes and timeline events are persisted in the session storage.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from huntx.cli.theme import get_console
from huntx.core.session import Session


class ResearchNotebook:
    """Manages manual researcher annotations and evidence hypotheses."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.notes_file = session.run_path / "mapping" / "research_notes.json"
        self._ensure_file()

    def _ensure_file(self) -> None:
        self.notes_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.notes_file.exists():
            self.notes_file.write_text(json.dumps([], indent=2), encoding="utf-8")

    def list_notes(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.notes_file.read_text(encoding="utf-8"))
        except Exception:
            return []

    def add_note(self, entity_type: str, entity_name: str, note_text: str, tag: str = "Investigation") -> None:
        notes = self.list_notes()
        now_str = datetime.now(timezone.utc).isoformat()
        notes.append({
            "id": f"NOTE-{len(notes) + 1:04d}",
            "entity_type": entity_type,
            "entity_name": entity_name,
            "tag": tag,
            "text": note_text,
            "created_at": now_str,
        })
        self.notes_file.write_text(json.dumps(notes, indent=2), encoding="utf-8")

    def display(self) -> None:
        console = get_console()
        notes = self.list_notes()
        
        table = Table(
            title="[bold green]RESEARCH NOTEBOOK ENTRIES[/bold green]",
            box=None,
            border_style="bright_black",
            header_style="bold green",
            expand=True,
            padding=(0, 2),
        )
        table.add_column("ID", style="dim", width=12)
        table.add_column("Type", style="bright_black", width=14)
        table.add_column("Entity / Target", style="cyan", width=30)
        table.add_column("Tag", style="yellow", width=16)
        table.add_column("Research Notes & Observations", style="white")

        if not notes:
            console.print(Panel("[dim]No research notes logged for this session yet. Add one with: huntx notes <target> --add \"...\"[/dim]", border_style="bright_black"))
            return

        for n in notes:
            table.add_row(
                n.get("id", ""),
                n.get("entity_type", "General"),
                escape(n.get("entity_name", "N/A")),
                escape(n.get("tag", "Note")),
                escape(n.get("text", "")),
            )

        console.print(table)


class InvestigationTimeline:
    """Maintains an immutable audit timeline of analysis events."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.timeline_file = session.run_path / "logs" / "timeline.json"
        self._ensure_file()

    def _ensure_file(self) -> None:
        self.timeline_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.timeline_file.exists():
            initial_event = {
                "timestamp": getattr(self.session.metadata, "created_at", datetime.now(timezone.utc).isoformat()),
                "event": "Session Initialized",
                "details": f"Target: {self.session.metadata.target_name}",
            }
            self.timeline_file.write_text(json.dumps([initial_event], indent=2), encoding="utf-8")

    def log_event(self, event_title: str, details: str = "") -> None:
        events = self.get_events()
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_title,
            "details": details,
        })
        self.timeline_file.write_text(json.dumps(events, indent=2), encoding="utf-8")

    def get_events(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.timeline_file.read_text(encoding="utf-8"))
        except Exception:
            return []

    def display(self) -> None:
        console = get_console()
        events = self.get_events()

        table = Table(
            title="[bold green]INVESTIGATION TIMELINE AUDIT LOG[/bold green]",
            box=None,
            border_style="bright_black",
            header_style="bold green",
            expand=True,
            padding=(0, 2),
        )
        table.add_column("Timestamp (UTC)", style="dim", width=24)
        table.add_column("Recon Event", style="bold white", width=32)
        table.add_column("Operational Details", style="cyan")

        for ev in events:
            t = ev.get("timestamp", "")[:19].replace("T", " ")
            table.add_row(t, ev.get("event", "Event"), ev.get("details", ""))

        console.print()
        console.print(table)
        console.print()
