"""HUNTX Search Engine — multi-entity evidence search across database and session artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntx.core.logger import get_logger

logger = get_logger("huntx.core.search")


class SearchEngine:
    """Multi-entity search across collected HUNTX evidence.

    Queries SQLite tables (domains, endpoints, strings, components) and falls back
    gracefully to session JSON artifacts if the database is not yet populated.

    Args:
        db_path: Path to the SQLite database file for the active session.
        session_run_path: Optional Path to the session's run directory for fallback.
    """

    def __init__(self, db_path: Path, session_run_path: Optional[Path] = None) -> None:
        self.db_path = db_path
        self.session_run_path = session_run_path
        self._ready = db_path.exists()

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def search(self, query: str, search_type: str = "all") -> List[Dict[str, Any]]:
        """Search collected evidence for *query*.

        Args:
            query: Free-text search string.
            search_type: One of ``"all"``, ``"domains"``, ``"endpoints"``,
                ``"strings"``, ``"components"``.

        Returns:
            List of matching result dicts.
        """
        query_str = query.strip()
        if not query_str:
            return []

        search_type_lower = search_type.lower()
        results: List[Dict[str, Any]] = []

        # 1. Try SQLite database search first
        if self._ready:
            try:
                from huntx.storage.database import Database
                with Database(self.db_path) as db:
                    pattern = f"%{query_str}%"
                    conn = db._conn
                    if conn is not None:
                        # Domains
                        if search_type_lower in ["all", "domains"]:
                            cur = conn.execute(
                                "SELECT * FROM domains WHERE domain LIKE ? OR source LIKE ?",
                                (pattern, pattern),
                            )
                            for row in cur.fetchall():
                                d = dict(row)
                                d["_table"] = "domains"
                                d["_display"] = f"[domain] {d.get('domain', '')} ({d.get('source', '')})"
                                results.append(d)

                        # Endpoints
                        if search_type_lower in ["all", "endpoints"]:
                            cur = conn.execute(
                                "SELECT * FROM endpoints WHERE path LIKE ? OR domain LIKE ? OR ep_id LIKE ? OR feature_group LIKE ?",
                                (pattern, pattern, pattern, pattern),
                            )
                            for row in cur.fetchall():
                                d = dict(row)
                                d["_table"] = "endpoints"
                                d["_display"] = f"[endpoint] {d.get('method', '')} {d.get('path', '')} ({d.get('domain', '')})"
                                results.append(d)

                        # Components
                        if search_type_lower in ["all", "components"]:
                            cur = conn.execute(
                                "SELECT * FROM components WHERE class_name LIKE ? OR component_type LIKE ? OR permission LIKE ?",
                                (pattern, pattern, pattern),
                            )
                            for row in cur.fetchall():
                                d = dict(row)
                                d["_table"] = "components"
                                d["_display"] = f"[component] {d.get('component_type', '')}: {d.get('class_name', '')}"
                                results.append(d)

                        # Strings
                        if search_type_lower in ["all", "strings"]:
                            cur = conn.execute(
                                "SELECT * FROM strings WHERE value LIKE ? OR source_location LIKE ?",
                                (pattern, pattern),
                            )
                            for row in cur.fetchall():
                                d = dict(row)
                                d["_table"] = "strings"
                                d["_display"] = f"[string] {d.get('value', '')[:80]} ({d.get('source_location', '')})"
                                results.append(d)
            except Exception as e:
                logger.debug("Database search error: %s", e)

        # 2. Strings live only in the session files; everything else falls back to them
        if results and search_type_lower in ("all", "strings") and self.session_run_path:
            results.extend(self._search_session_files(query_str, "strings"))
        if not results and self.session_run_path and self.session_run_path.exists():
            results = self._search_session_files(query_str, search_type_lower)

        return results

    def _search_session_files(self, query: str, search_type: str) -> List[Dict[str, Any]]:
        """Fallback search across JSON files in session directories."""
        results: List[Dict[str, Any]] = []
        q_lower = query.lower()
        run_path = self.session_run_path
        if not run_path:
            return results

        # Domains
        if search_type in ["all", "domains"]:
            dom_file = run_path / "api" / "domains.json"
            if dom_file.exists():
                try:
                    with open(dom_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        items = data.get("domains", []) if isinstance(data, dict) else data
                        for item in items:
                            val = item.get("domain", str(item)) if isinstance(item, dict) else str(item)
                            if q_lower in val.lower():
                                results.append({
                                    "_table": "domains",
                                    "_display": f"[domain] {val}",
                                    "domain": val,
                                })
                except Exception as exc:
                    logger.debug("Unreadable evidence file: %s", exc)

        # Endpoints
        if search_type in ["all", "endpoints"]:
            for rel in ["mapping/endpoint-passports.json", "api/endpoints.json"]:
                ep_file = run_path / rel
                if ep_file.exists():
                    try:
                        with open(ep_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            items = data if isinstance(data, list) else data.get("passports") or data.get("endpoints") or []
                            for item in items:
                                p = item.get("path", "")
                                d = item.get("domain", "")
                                if q_lower in p.lower() or q_lower in d.lower():
                                    results.append({
                                        "_table": "endpoints",
                                        "_display": f"[endpoint] {item.get('method', '')} {p} ({d})",
                                        **item,
                                    })
                        break
                    except Exception as exc:
                        logger.debug("Unreadable evidence file: %s", exc)

        # Components
        if search_type in ["all", "components"]:
            comp_file = run_path / "android" / "components.json"
            if comp_file.exists():
                try:
                    with open(comp_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        items = data.get("components", []) if isinstance(data, dict) else data
                        for item in items:
                            cls_name = item.get("class_name") or item.get("name", "")
                            if q_lower in cls_name.lower():
                                results.append({
                                    "_table": "components",
                                    "_display": f"[component] {item.get('component_type', '')}: {cls_name}",
                                    **item,
                                })
                except Exception as exc:
                    logger.debug("Unreadable evidence file: %s", exc)

        # Strings
        if search_type in ["all", "strings"]:
            str_file = run_path / "android" / "strings.json"
            if str_file.exists():
                try:
                    with open(str_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        items = data if isinstance(data, list) else data.get("strings") or [
                            x for k in ("urls", "domains", "api_paths", "emails", "ips", "tokens") for x in data.get(k, [])
                        ]
                        for item in items:
                            val = item.get("value", "")
                            if q_lower in val.lower():
                                results.append({
                                    "_table": "strings",
                                    "_display": f"[string] {val[:80]}",
                                    **item,
                                })
                except Exception as exc:
                    logger.debug("Unreadable evidence file: %s", exc)

        return results

    # ------------------------------------------------------------------
    # Indexing methods
    # ------------------------------------------------------------------

    def index_domains(self, domains: list) -> None:
        """Index a list of domain records into the database."""
        if not domains:
            return
        try:
            from huntx.storage.database import Database
            with Database(self.db_path) as db:
                db.initialize()
                for d in domains:
                    row = {
                        "domain": d.get("domain", str(d)) if isinstance(d, dict) else str(d),
                        "source": d.get("source", "recon") if isinstance(d, dict) else "recon",
                        "session_id": d.get("session_id", "") if isinstance(d, dict) else "",
                        "first_seen": d.get("first_seen", "") if isinstance(d, dict) else "",
                    }
                    db.insert("domains", row)
            self._ready = True
        except Exception as e:
            logger.warning("Error indexing domains: %s", e)

    def index_endpoints(self, endpoints: list) -> None:
        """Index a list of endpoint records into the database."""
        if not endpoints:
            return
        try:
            from huntx.storage.database import Database
            with Database(self.db_path) as db:
                db.initialize()
                for ep in endpoints:
                    if not isinstance(ep, dict):
                        continue
                    row = {
                        "ep_id": ep.get("endpoint_id") or ep.get("ep_id", ""),
                        "domain": ep.get("domain", ""),
                        "path": ep.get("path", ""),
                        "normalized_path": ep.get("normalized_path", ep.get("path", "")),
                        "method": ep.get("method", ""),
                        "parameters_json": json.dumps(ep.get("parameters", [])),
                        "discovery_sources_json": json.dumps(ep.get("discovery_sources", [])),
                        "feature_group": ep.get("feature_group", ""),
                        "confidence": float(ep.get("confidence", 0.0)),
                        "session_id": ep.get("session_id", ""),
                        "first_seen": ep.get("first_seen", ""),
                        "last_seen": ep.get("last_seen", ""),
                    }
                    db.insert("endpoints", row)
            self._ready = True
        except Exception as e:
            logger.warning("Error indexing endpoints: %s", e)

    def index_strings(self, strings: list) -> None:
        """Index a list of extracted strings into the database."""
        if not strings:
            return
        try:
            from huntx.storage.database import Database
            with Database(self.db_path) as db:
                db.initialize()
                for s in strings:
                    row = {
                        "value": s.get("value", str(s)) if isinstance(s, dict) else str(s),
                        "source_location": s.get("source_location", "") if isinstance(s, dict) else "",
                        "source_type": s.get("source_type", "dex") if isinstance(s, dict) else "dex",
                        "session_id": s.get("session_id", "") if isinstance(s, dict) else "",
                    }
                    db.insert("strings", row)
            self._ready = True
        except Exception as e:
            logger.warning("Error indexing strings: %s", e)

    def index_components(self, components: list) -> None:
        """Index a list of components into the database."""
        if not components:
            return
        try:
            from huntx.storage.database import Database
            with Database(self.db_path) as db:
                db.initialize()
                for c in components:
                    if not isinstance(c, dict):
                        continue
                    row = {
                        "component_type": c.get("component_type", ""),
                        "class_name": c.get("class_name", ""),
                        "exported": int(bool(c.get("exported", False))),
                        "permission": c.get("permission", ""),
                        "session_id": c.get("session_id", ""),
                    }
                    db.insert("components", row)
            self._ready = True
        except Exception as e:
            logger.warning("Error indexing components: %s", e)
