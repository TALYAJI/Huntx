"""HUNTX Endpoint Passport data model and aggregation engine."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntx.core.logger import get_logger

logger = get_logger("huntx.intelligence.endpoint_passport")

# Keywords for feature group inference
_FEATURE_GROUP_KEYWORDS = {
    "Authentication": ["auth", "login", "logout", "signin", "signout", "token", "oauth", "signup", "register", "password", "session"],
    "User Management": ["user", "users", "profile", "account", "member", "me", "avatar"],
    "Billing & Payments": ["pay", "payment", "billing", "checkout", "invoice", "order", "cart", "subscription", "purchase", "wallet"],
    "Settings & Config": ["setting", "settings", "config", "configuration", "pref", "preferences"],
    "Notifications & Messaging": ["notification", "notifications", "push", "alert", "message", "messages", "chat", "inbox"],
    "Search": ["search", "query", "find", "filter"],
    "Media & Files": ["upload", "download", "media", "file", "files", "image", "images", "asset", "assets", "video"],
    "Analytics & Tracking": ["analytic", "analytics", "telemetry", "event", "events", "track", "tracking", "metric", "metrics", "log", "logs"],
}

_AUTH_HEADERS = ["authorization", "x-auth-token", "x-api-key", "api-key", "apikey", "x-session-id", "cookie", "token", "jwt"]


@dataclass
class EndpointPassport:
    """Central data model for an Endpoint Passport (EP-00001, EP-00002...).

    Aggregates static analysis findings and dynamic traffic observations into
    a single authoritative profile of an API endpoint.
    """

    endpoint_id: str
    domain: str
    path: str
    normalized_path: str
    method: str = "UNKNOWN"
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    discovery_sources: List[str] = field(default_factory=list)
    source_class: str = ""
    source_method: str = ""
    feature_group: str = "General API"
    authentication_evidence: str = ""
    confidence: float = 0.5
    evidence: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the passport to a plain JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EndpointPassport:
        """Create an EndpointPassport instance from a dictionary."""
        # Sanitize known fields
        known_fields = {
            "endpoint_id",
            "domain",
            "path",
            "normalized_path",
            "method",
            "parameters",
            "discovery_sources",
            "source_class",
            "source_method",
            "feature_group",
            "authentication_evidence",
            "confidence",
            "evidence",
            "first_seen",
            "last_seen",
            "session_id",
        }
        filtered = {k: v for k, v in data.items() if k in known_fields}
        # Fallbacks for mandatory or special fields
        if "endpoint_id" not in filtered or not filtered["endpoint_id"]:
            filtered["endpoint_id"] = "EP-00000"
        if "domain" not in filtered:
            filtered["domain"] = ""
        if "path" not in filtered:
            filtered["path"] = ""
        if "normalized_path" not in filtered or not filtered["normalized_path"]:
            filtered["normalized_path"] = filtered["path"]
        if "method" in filtered and filtered["method"]:
            filtered["method"] = str(filtered["method"]).upper()
        else:
            filtered["method"] = "UNKNOWN"
        if "parameters" in filtered and isinstance(filtered["parameters"], str):
            try:
                filtered["parameters"] = json.loads(filtered["parameters"])
            except Exception:
                filtered["parameters"] = []
        if "discovery_sources" in filtered and isinstance(filtered["discovery_sources"], str):
            try:
                filtered["discovery_sources"] = json.loads(filtered["discovery_sources"])
            except Exception:
                filtered["discovery_sources"] = [filtered["discovery_sources"]]
        return cls(**filtered)


def normalize_path_str(p: str) -> str:
    """Normalize dynamic segments in path (IDs, UUIDs, hashes) to placeholder tokens."""
    if not p:
        return ""
    try:
        from huntx.engines.api.normalizer import normalize_path
        res, _ = normalize_path(p)
        return res
    except Exception:
        import re
        norm = re.sub(r'/[0-9]+(?=/|$)', '/{id}', p)
        norm = re.sub(r'/[0-9a-fA-F-]{36}(?=/|$)', '/{uuid}', norm)
        return norm


def infer_feature_group(path: str, class_name: str = "") -> str:
    """Infer feature category from URL path and/or Java class name."""
    target_str = f"{path} {class_name}".lower()
    for group, keywords in _FEATURE_GROUP_KEYWORDS.items():
        for kw in keywords:
            # Match keyword bounded by non-alphanumeric chars or camelCase
            if re.search(rf"\b{kw}\b|/{kw}/|/{kw}$|_{kw}_|{kw}\.", target_str, re.IGNORECASE):
                return group
    return "General API"


def detect_auth_evidence(headers: Optional[Dict[str, Any]] = None,
                         parameters: Optional[List[Dict[str, Any]]] = None,
                         path: str = "") -> str:
    """Detect evidence of authentication requirements in headers, params, or path."""
    evidence_parts = []
    
    if headers:
        for h, v in headers.items():
            h_lower = h.lower()
            if h_lower == "authorization":
                v_str = str(v)
                if v_str.lower().startswith("bearer"):
                    evidence_parts.append("Bearer token in Authorization header")
                elif v_str.lower().startswith("basic"):
                    evidence_parts.append("Basic auth in Authorization header")
                else:
                    evidence_parts.append("Authorization header present")
            elif h_lower in _AUTH_HEADERS:
                evidence_parts.append(f"Auth header '{h}' present")

    if parameters:
        for p in parameters:
            p_name = p.get("name", "") if isinstance(p, dict) else str(p)
            p_lower = p_name.lower()
            if any(k in p_lower for k in ["token", "auth", "api_key", "apikey", "session", "jwt", "secret"]):
                p_in = p.get("in", "param") if isinstance(p, dict) else "param"
                evidence_parts.append(f"Credential parameter '{p_name}' in {p_in}")

    if re.search(r"/(oauth|auth|login|token)/", path, re.IGNORECASE):
        evidence_parts.append("Authentication path pattern in URL")

    return "; ".join(evidence_parts)


def _endpoint_params(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Endpoint records carry query/path params separately; passports hold one list."""
    out = []
    for kind in ("query", "path"):
        for p in item.get(f"{kind}_params") or []:
            name = p.get("name") if isinstance(p, dict) else str(p)
            if name:
                out.append({"name": name, "in": kind})
    return out


def generate_endpoint_passports(
    session: Any = None,
    static_endpoints: Optional[List[Dict[str, Any]]] = None,
    traffic_endpoints: Optional[List[Dict[str, Any]]] = None,
    traffic_requests: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[Path] = None,
) -> List[EndpointPassport]:
    """Aggregate static analysis findings and traffic observations into Endpoint Passports.

    Args:
        session: Active HUNTX session instance (optional).
        static_endpoints: Explicit list of static endpoint dicts.
        traffic_endpoints: Explicit list of traffic endpoint dicts.
        traffic_requests: Explicit list of raw traffic requests.
        output_path: Explicit file path to save passports JSON.

    Returns:
        List of generated EndpointPassport instances.
    """
    logger.info("Starting Endpoint Passport aggregation")
    static_list: List[Dict[str, Any]] = list(static_endpoints or [])
    traffic_list: List[Dict[str, Any]] = list(traffic_endpoints or [])
    requests_list: List[Dict[str, Any]] = list(traffic_requests or [])
    session_id = ""

    # Load from session directory if available and not explicitly provided
    if session is not None:
        session_id = getattr(getattr(session, "metadata", None), "session_id", "")
        run_path = getattr(session, "run_path", None)
        if run_path and isinstance(run_path, Path):
            # Check static endpoints file
            api_ep_file = run_path / "api" / "endpoints.json"
            if not static_list and api_ep_file.exists():
                try:
                    with open(api_ep_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            static_list = data
                        elif isinstance(data, dict) and "endpoints" in data:
                            static_list = data["endpoints"]
                except Exception as e:
                    logger.warning("Failed to load static endpoints from %s: %s", api_ep_file, e)

            # Check traffic endpoints file
            traffic_ep_file = run_path / "traffic" / "endpoints.json"
            if not traffic_list and traffic_ep_file.exists():
                try:
                    with open(traffic_ep_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            traffic_list = data
                        elif isinstance(data, dict) and "endpoints" in data:
                            traffic_list = data["endpoints"]
                except Exception as e:
                    logger.warning("Failed to load traffic endpoints from %s: %s", traffic_ep_file, e)

            # Check traffic requests file
            traffic_req_file = run_path / "traffic" / "requests.json"
            if not requests_list and traffic_req_file.exists():
                try:
                    with open(traffic_req_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            requests_list = data
                        elif isinstance(data, dict) and "requests" in data:
                            requests_list = data["requests"]
                except Exception as e:
                    logger.warning("Failed to load traffic requests from %s: %s", traffic_req_file, e)

    # Correlate requests with traffic endpoints if requests exist
    for req in requests_list:
        url = req.get("url", "")
        method = (req.get("method") or "GET").upper()
        host = req.get("host", "")
        headers = req.get("headers", {})
        query_params = req.get("query_params", {})
        timestamp = req.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Extract path from URL if url contains scheme and host
        path = url
        if not isinstance(query_params, dict):
            query_params = {}
        if "://" in url:
            parts = url.split("://", 1)[1]
            if "/" in parts:
                path = "/" + parts.split("/", 1)[1].split("?")[0]
            else:
                path = "/"
        elif "?" in url:
            path = url.split("?")[0]

        params = [{"name": k, "value": v, "in": "query"} for k, v in query_params.items()]
        auth_ev = detect_auth_evidence(headers=headers, parameters=params, path=path)

        traffic_list.append({
            "domain": host,
            "path": path,
            "normalized_path": path,
            "method": method,
            "parameters": params,
            "discovery_sources": ["traffic_capture"],
            "authentication_evidence": auth_ev,
            "confidence": 0.90,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "evidence": f"Observed in traffic: {method} {url}",
        })

    # Group and merge records
    # Key: (domain.lower(), normalized_path or path, method)
    merged_map: Dict[tuple, Dict[str, Any]] = {}
    by_domain: Dict[str, List[tuple]] = {}

    def _process_item(item: Dict[str, Any], is_static: bool):
        domain = item.get("domain", "").strip()
        path = item.get("path", "").strip()
        if not path and not domain:
            return
        if not path.startswith("/") and not path.startswith("http"):
            path = "/" + path

        norm_path = item.get("normalized_path", "").strip() or path
        norm_path = normalize_path_str(norm_path)
        if not norm_path.startswith("/") and not norm_path.startswith("http"):
            norm_path = "/" + norm_path

        method = (item.get("method") or "UNKNOWN").upper().strip()
        
        # Deduplication key & fuzzy matching
        key = (domain.lower(), norm_path, method)

        matched_key = None
        if key in merged_map:
            matched_key = key
        else:
            for k in by_domain.get(domain.lower(), ()):
                rec = merged_map[k]
                if (k[2] == method or method == "UNKNOWN" or k[2] == "UNKNOWN"):
                    if rec["path"] == path or rec["normalized_path"] == norm_path or rec["path"] == norm_path or rec["normalized_path"] == path:
                        matched_key = k
                        break

        if matched_key is None:
            sources = item.get("discovery_sources", [])
            if isinstance(sources, str):
                sources = [sources]
            elif not sources:
                sources = ["static_dex"] if is_static else ["traffic_capture"]

            params = item.get("parameters") or _endpoint_params(item)
            if isinstance(params, str):
                try:
                    params = json.loads(params)
                except Exception:
                    params = []

            feature = item.get("feature_group") or infer_feature_group(norm_path, item.get("source_class", ""))
            auth_ev = item.get("authentication_evidence") or detect_auth_evidence(parameters=params, path=norm_path)
            confidence = float(item.get("confidence", 0.6 if is_static else 0.85))

            now_iso = datetime.now(timezone.utc).isoformat()
            first_seen = item.get("first_seen") or now_iso
            last_seen = item.get("last_seen") or now_iso

            by_domain.setdefault(domain.lower(), []).append(key)
            merged_map[key] = {
                "domain": domain,
                "path": path,
                "normalized_path": norm_path,
                "method": method,
                "parameters": list(params),
                "discovery_sources": list(set(sources)),
                "source_class": item.get("source_class", ""),
                "source_method": item.get("source_method", ""),
                "feature_group": feature,
                "authentication_evidence": auth_ev,
                "confidence": confidence,
                "evidence": item.get("evidence", ""),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "session_id": item.get("session_id", session_id),
                "_seen_static": is_static,
                "_seen_traffic": not is_static,
            }
        else:
            existing = merged_map[matched_key]
            # Merge sources
            sources = item.get("discovery_sources", [])
            if isinstance(sources, str):
                sources = [sources]
            elif not sources:
                sources = ["static_dex"] if is_static else ["traffic_capture"]
            existing["discovery_sources"] = sorted(list(set(existing["discovery_sources"] + sources)))

            # Merge parameters by name
            existing_param_names = {
                p.get("name") if isinstance(p, dict) else str(p)
                for p in existing["parameters"]
            }
            new_params = item.get("parameters") or _endpoint_params(item)
            if isinstance(new_params, str):
                try:
                    new_params = json.loads(new_params)
                except Exception:
                    new_params = []
            for p in new_params:
                p_name = p.get("name") if isinstance(p, dict) else str(p)
                if p_name not in existing_param_names:
                    existing["parameters"].append(p)
                    existing_param_names.add(p_name)

            if is_static:
                existing["_seen_static"] = True
                if item.get("source_class") and not existing.get("source_class"):
                    existing["source_class"] = item["source_class"]
                if item.get("source_method") and not existing.get("source_method"):
                    existing["source_method"] = item["source_method"]
            else:
                existing["_seen_traffic"] = True

            # If seen in both static AND dynamic, boost confidence significantly
            # A known verb beats UNKNOWN
            if existing["method"] == "UNKNOWN" and method != "UNKNOWN":
                existing["method"] = method

            if existing.get("_seen_static") and existing.get("_seen_traffic"):
                existing["confidence"] = min(1.0, max(existing["confidence"], 0.95))
            else:
                item_conf = float(item.get("confidence", 0.6 if is_static else 0.85))
                existing["confidence"] = min(1.0, max(existing["confidence"], item_conf))

            # Merge auth evidence
            new_auth = item.get("authentication_evidence", "")
            if new_auth and new_auth not in existing["authentication_evidence"]:
                if existing["authentication_evidence"]:
                    existing["authentication_evidence"] += f"; {new_auth}"
                else:
                    existing["authentication_evidence"] = new_auth

            # Timestamps
            if item.get("first_seen") and item["first_seen"] < existing["first_seen"]:
                existing["first_seen"] = item["first_seen"]
            if item.get("last_seen") and item["last_seen"] > existing["last_seen"]:
                existing["last_seen"] = item["last_seen"]

    for s_item in static_list:
        _process_item(s_item, is_static=True)

    for t_item in traffic_list:
        _process_item(t_item, is_static=False)

    # Build sorted EndpointPassport objects with sequential IDs
    passports: List[EndpointPassport] = []
    # Sort deterministically: domain, path, method
    sorted_keys = sorted(merged_map.keys(), key=lambda k: (k[0], k[1], k[2]))

    for idx, key in enumerate(sorted_keys, start=1):
        record = merged_map[key]
        ep_id = f"EP-{idx:05d}"
        
        passport = EndpointPassport(
            endpoint_id=ep_id,
            domain=record["domain"],
            path=record["path"],
            normalized_path=record["normalized_path"],
            method=record["method"],
            parameters=record["parameters"],
            discovery_sources=record["discovery_sources"],
            source_class=record.get("source_class", ""),
            source_method=record.get("source_method", ""),
            feature_group=record.get("feature_group", "General API"),
            authentication_evidence=record.get("authentication_evidence", ""),
            confidence=round(record.get("confidence", 0.5), 2),
            evidence=record.get("evidence", ""),
            first_seen=record.get("first_seen", ""),
            last_seen=record.get("last_seen", ""),
            session_id=record.get("session_id", session_id),
        )
        passports.append(passport)

    logger.info("Generated %d Endpoint Passports", len(passports))

    # Persist to JSON output file
    target_file = output_path
    if target_file is None and session is not None:
        run_path = getattr(session, "run_path", None)
        if run_path and isinstance(run_path, Path):
            target_file = run_path / "mapping" / "endpoint-passports.json"

    if target_file is not None:
        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            output_data = {
                "total_passports": len(passports),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "passports": [p.to_dict() for p in passports],
            }
            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            logger.info("Saved Endpoint Passports to %s", target_file)
        except Exception as e:
            logger.error("Failed to write passports to %s: %s", target_file, e)

    # Also update session database if repository exists
    if session is not None:
        try:
            from huntx.storage.repository import Repository
            with Repository(session) as repo:
                for p in passports:
                    repo.save_endpoint({
                        "ep_id": p.endpoint_id,
                        "domain": p.domain,
                        "path": p.path,
                        "normalized_path": p.normalized_path,
                        "method": p.method,
                        "parameters": p.parameters,
                        "discovery_sources": p.discovery_sources,
                        "feature_group": p.feature_group,
                        "confidence": p.confidence,
                        "first_seen": p.first_seen,
                        "last_seen": p.last_seen,
                        "session_id": session_id,
                    })
        except Exception as e:
            logger.debug("Database sync skipped or failed: %s", e)

    return passports
