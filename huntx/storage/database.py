"""HUNTX SQLite database layer — stdlib sqlite3 only."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    target_name   TEXT NOT NULL,
    run_dir       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS endpoints (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ep_id                TEXT NOT NULL DEFAULT '',
    domain               TEXT NOT NULL DEFAULT '',
    path                 TEXT NOT NULL DEFAULT '',
    normalized_path      TEXT NOT NULL DEFAULT '',
    method               TEXT NOT NULL DEFAULT '',
    parameters_json      TEXT NOT NULL DEFAULT '[]',
    discovery_sources_json TEXT NOT NULL DEFAULT '[]',
    feature_group        TEXT NOT NULL DEFAULT '',
    confidence           REAL NOT NULL DEFAULT 0.0,
    session_id           TEXT NOT NULL DEFAULT '',
    first_seen           TEXT NOT NULL DEFAULT '',
    last_seen            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS components (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    component_type TEXT NOT NULL DEFAULT '',
    class_name     TEXT NOT NULL DEFAULT '',
    exported       INTEGER NOT NULL DEFAULT 0,
    permission     TEXT NOT NULL DEFAULT '',
    session_id     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS strings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    value           TEXT NOT NULL DEFAULT '',
    source_location TEXT NOT NULL DEFAULT '',
    source_type     TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS traffic_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    method          TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    host            TEXT NOT NULL DEFAULT '',
    headers_json    TEXT NOT NULL DEFAULT '{}',
    body_hash       TEXT NOT NULL DEFAULT '',
    response_status INTEGER,
    timestamp       TEXT NOT NULL DEFAULT '',
    source_file     TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS parameters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL DEFAULT '',
    param_type  TEXT NOT NULL DEFAULT '',
    endpoint_id INTEGER,
    session_id  TEXT NOT NULL DEFAULT ''
);
"""


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------


class Database:
    """Thin wrapper around a SQLite connection for HUNTX data storage.

    Supports use as a context manager::

        with Database(db_path) as db:
            db.insert("domains", {"domain": "example.com", ...})

    Args:
        db_path: Path to the SQLite ``.db`` file (created if absent).
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Database":
        """Open the connection."""
        self._open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Commit (on success) and close the connection."""
        if self._conn:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open (or reuse) the SQLite connection."""
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL;")

    def close(self) -> None:
        """Commit pending changes and close the connection."""
        if self._conn:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create all tables if they do not already exist."""
        self._open()
        assert self._conn is not None
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def insert(self, table: str, data_dict: Dict[str, Any]) -> int:
        """Insert *data_dict* into *table* and return the new row id.

        Rows are committed together by :meth:`close` / leaving the context manager.

        Uses parameterized queries; never constructs SQL from user data.

        Args:
            table: Target table name (must be one of the HUNTX tables).
            data_dict: Column → value mapping for the new row.

        Returns:
            The ``lastrowid`` of the inserted row.

        Raises:
            sqlite3.Error: On any database error.
        """
        self._open()
        assert self._conn is not None
        columns = ", ".join(data_dict.keys())
        placeholders = ", ".join("?" for _ in data_dict)
        values = list(data_dict.values())
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"  # noqa: S608
        cursor = self._conn.execute(sql, values)
        return cursor.lastrowid  # type: ignore[return-value]

    def clear(self, table: str) -> None:
        """Delete every row of *table* (internal table names only)."""
        self._open()
        assert self._conn is not None
        self._conn.execute(f"DELETE FROM {table}")  # noqa: S608

    def query_all(self, table: str) -> List[Dict[str, Any]]:
        """Return all rows from *table* as a list of dicts.

        Args:
            table: Table name to query.

        Returns:
            List of row dicts (column → value).
        """
        self._open()
        assert self._conn is not None
        cursor = self._conn.execute(f"SELECT * FROM {table}")  # noqa: S608
        return [dict(row) for row in cursor.fetchall()]

    def search_text(self, query: str) -> List[Dict[str, Any]]:
        """LIKE search across ``domains.domain``, ``endpoints.path``, and ``strings.value``.

        Args:
            query: Free-text search string; ``%`` wildcards are added automatically.

        Returns:
            Merged list of matching row dicts with a ``_table`` key.
        """
        self._open()
        assert self._conn is not None
        pattern = f"%{query}%"
        results: list[dict] = []

        for table, col in (
            ("domains", "domain"),
            ("endpoints", "path"),
            ("strings", "value"),
        ):
            cursor = self._conn.execute(
                f"SELECT * FROM {table} WHERE {col} LIKE ?",  # noqa: S608
                (pattern,),
            )
            for row in cursor.fetchall():
                d = dict(row)
                d["_table"] = table
                results.append(d)

        return results
