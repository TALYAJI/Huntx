"""HUNTX repository — higher-level DB access with deduplication."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Set, Tuple

from huntx.core.session import Session
from huntx.storage.database import Database


class Repository:
    """High-level data access layer for a single HUNTX session.

    Wraps :class:`~huntx.storage.database.Database` with deduplication logic
    so that callers can safely call ``save_*`` methods multiple times without
    creating duplicate rows.

    Args:
        session: The active :class:`~huntx.core.session.Session`; its
            ``db_path`` determines which database file is used.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._db = Database(session.db_path)
        self._db.initialize()
        self._known: Dict[str, Set[Any]] = {}

    def __enter__(self) -> "Repository":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._db.__exit__(exc_type, exc_val, exc_tb)

    def close(self) -> None:
        """Commit and close."""
        self._db.close()

    def _is_new(self, table: str, key: Tuple[Any, ...], row_key: Callable[[Dict[str, Any]], Tuple[Any, ...]]) -> bool:
        """Remember *key* for *table*; existing rows are read from disk only once."""
        if table not in self._known:
            self._known[table] = {row_key(r) for r in self._db.query_all(table)}
        if key in self._known[table]:
            return False
        self._known[table].add(key)
        return True

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def save_domain(self, domain: Dict[str, Any]) -> None:
        """Persist *domain* if no row with the same ``domain`` value exists.

        Deduplication key: ``(domain,)``.

        Args:
            domain: Dict with at minimum a ``"domain"`` key.
        """
        if self._is_new("domains", (domain.get("domain", ""),), lambda r: (r["domain"],)):
            row = {
                "domain": domain.get("domain", ""),
                "source": domain.get("source", ""),
                "session_id": domain.get("session_id", self._session.metadata.session_id),
                "first_seen": domain.get("first_seen", ""),
            }
            self._db.insert("domains", row)

    def get_all_domains(self) -> List[Dict[str, Any]]:
        """Return all domain rows for the current database.

        Returns:
            List of domain row dicts.
        """
        return self._db.query_all("domains")

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def save_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Persist *endpoint* if no duplicate ``(domain, path, method)`` exists.

        Deduplication key: ``(domain, path, method)``.

        Args:
            endpoint: Dict with at minimum ``"domain"``, ``"path"``,
                ``"method"`` keys.
        """
        import json as _json

        method = endpoint.get("method", "")
        if method == "UNKNOWN":  # passports say UNKNOWN where raw endpoints say ""
            method = ""
        key = (endpoint.get("domain", ""), endpoint.get("path", ""), method)
        if self._is_new("endpoints", key, lambda r: (r["domain"], r["path"], r["method"])):
            row: Dict[str, Any] = {
                "ep_id": endpoint.get("ep_id", ""),
                "domain": endpoint.get("domain", ""),
                "path": endpoint.get("path", ""),
                "normalized_path": endpoint.get("normalized_path", ""),
                "method": method,
                "parameters_json": _json.dumps(endpoint.get("parameters", [])),
                "discovery_sources_json": _json.dumps(endpoint.get("discovery_sources", [])),
                "feature_group": endpoint.get("feature_group", ""),
                "confidence": endpoint.get("confidence", 0.0),
                "session_id": endpoint.get(
                    "session_id", self._session.metadata.session_id
                ),
                "first_seen": endpoint.get("first_seen", ""),
                "last_seen": endpoint.get("last_seen", ""),
            }
            self._db.insert("endpoints", row)

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Return all endpoint rows for the current database.

        Returns:
            List of endpoint row dicts.
        """
        return self._db.query_all("endpoints")

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def save_component(self, component: Dict[str, Any]) -> None:
        """Persist *component* once per ``(component_type, class_name)``.

        Args:
            component: Dict with component data.
        """
        row: Dict[str, Any] = {
            "component_type": component.get("component_type", ""),
            "class_name": component.get("class_name", ""),
            "exported": int(bool(component.get("exported", False))),
            "permission": component.get("permission", ""),
            "session_id": component.get(
                "session_id", self._session.metadata.session_id
            ),
        }
        if self._is_new(
            "components",
            (row["component_type"], row["class_name"]),
            lambda r: (r["component_type"], r["class_name"]),
        ):
            self._db.insert("components", row)

    def get_all_components(self) -> List[Dict[str, Any]]:
        """Return all component rows for the current database.

        Returns:
            List of component row dicts.
        """
        return self._db.query_all("components")

    # ------------------------------------------------------------------
    # Traffic Requests
    # ------------------------------------------------------------------

    def save_traffic_request(self, request: Dict[str, Any]) -> None:
        """Persist a captured traffic request.

        Args:
            request: Dict with traffic request data.
        """
        import hashlib as _hashlib
        import json as _json

        body_text = request.get("body", "")
        body_hash = (
            _hashlib.sha256(body_text.encode("utf-8")).hexdigest()
            if body_text
            else ""
        )
        headers = request.get("headers", {})
        headers_str = headers if isinstance(headers, str) else _json.dumps(headers)

        row: Dict[str, Any] = {
            "method": request.get("method", ""),
            "url": request.get("url", ""),
            "host": request.get("host", ""),
            "headers_json": headers_str,
            "body_hash": body_hash,
            "response_status": request.get("response_status"),
            "timestamp": request.get("timestamp", ""),
            "source_file": request.get("source_file", ""),
            "session_id": request.get(
                "session_id", self._session.metadata.session_id
            ),
        }
        self._db.insert("traffic_requests", row)

    def get_all_traffic_requests(self) -> List[Dict[str, Any]]:
        """Return all traffic request rows for the current database.

        Returns:
            List of traffic request row dicts.
        """
        return self._db.query_all("traffic_requests")

    # ------------------------------------------------------------------
    # Parameters
    # ------------------------------------------------------------------

    def save_parameter(self, param: Dict[str, Any]) -> None:
        """Persist a discovered parameter.

        Args:
            param: Dict with parameter data.
        """
        row: Dict[str, Any] = {
            "name": param.get("name", ""),
            "param_type": param.get("param_type", ""),
            "endpoint_id": param.get("endpoint_id"),
            "session_id": param.get(
                "session_id", self._session.metadata.session_id
            ),
        }
        self._db.insert("parameters", row)

    def get_all_parameters(self) -> List[Dict[str, Any]]:
        """Return all parameter rows for the current database.

        Returns:
            List of parameter row dicts.
        """
        return self._db.query_all("parameters")
