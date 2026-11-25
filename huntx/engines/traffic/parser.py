"""HUNTX Traffic Engine — Core Traffic Parser and Analyzer.

Coordinates parsing of Burp Suite XML and HAR traffic logs, redacts sensitive
authentication tokens and credentials by default, extracts runtime endpoints,
and produces comprehensive traffic reconnaissance summaries.

SAFETY GUARANTEE:
This module is strictly passive and analytical. It NEVER replays, sends,
modifies, or executes network traffic against any host.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from huntx.engines.api.normalizer import normalize_endpoint
from huntx.engines.traffic.burp import parse_burp_xml
from huntx.engines.traffic.har import parse_har

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive Headers & Parameter Patterns for Redaction
# ---------------------------------------------------------------------------

SENSITIVE_HEADERS: Set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "session-id",
    "x-csrf-token",
    "x-xsrf-token",
    "token",
    "bearer",
    "jwt",
    "private-token",
}

SENSITIVE_PARAM_NAMES: Set[str] = {
    "password", "passwd", "pwd", "pass",
    "secret", "api_key", "apikey", "key",
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "pin", "ssn", "cvv", "cvc", "credit_card",
    "private_key", "client_secret",
}


# ---------------------------------------------------------------------------
# Redaction Helpers
# ---------------------------------------------------------------------------

def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with sensitive authorization values redacted.

    Args:
        headers: Dict of header name -> value.

    Returns:
        Redacted dictionary of headers.
    """
    redacted: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in SENSITIVE_HEADERS or any(s in k_lower for s in ("auth", "token", "secret", "cookie", "key")):
            if str(v).lower().startswith("bearer "):
                redacted[k] = "Bearer [REDACTED]"
            elif str(v).lower().startswith("basic "):
                redacted[k] = "Basic [REDACTED]"
            else:
                redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def redact_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of parameters with sensitive fields redacted.

    Args:
        params: Dict of parameter name -> value.

    Returns:
        Redacted parameter dictionary.
    """
    redacted: Dict[str, Any] = {}
    for k, v in params.items():
        k_lower = str(k).lower().replace("-", "_")
        if k_lower in SENSITIVE_PARAM_NAMES or any(s in k_lower for s in ("password", "secret", "token", "key")):
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


_SECRET_NAME = r"[\w.\-]*(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|auth|session|jwt|cvv|cvc|ssn|credit_card|private_key)[\w.\-]*"
_RE_KV = re.compile(rf"((?:^|[?&;\s])(?:{_SECRET_NAME}|pass|pin|key)=)[^&#;\s\"']+", re.IGNORECASE)
_RE_JSON_KV = re.compile(
    rf'("(?:{_SECRET_NAME}|pass|pin|key)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?\d[\d.]*)', re.IGNORECASE
)
_RE_AUTH_LINE = re.compile(r"(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-[\w-]*(?:key|token)):[^\r\n]*")
_RE_JWT = re.compile(r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")


def redact_text(text: str) -> str:
    """Redact credentials embedded in URLs, form/JSON bodies and raw messages."""
    text = _RE_KV.sub(r"\1[REDACTED]", text)
    text = _RE_JSON_KV.sub(r'\1"[REDACTED]"', text)
    text = _RE_AUTH_LINE.sub(r"\1: [REDACTED]", text)
    return _RE_JWT.sub("[REDACTED]", text)


def redact_traffic_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a safe, redacted version of a traffic request record.

    Redacts sensitive headers, query parameters, URL query strings and
    request/response bodies.

    Args:
        entry: Raw traffic request dictionary.

    Returns:
        Redacted traffic record.
    """
    copied = {k: redact_text(v) if isinstance(v, str) else v for k, v in entry.items()}
    copied["headers"] = redact_headers(entry.get("headers", {}))
    copied["response_headers"] = redact_headers(entry.get("response_headers", {}))
    if isinstance(entry.get("query_params"), dict):
        copied["query_params"] = redact_parameters(entry["query_params"])
    return copied


# ---------------------------------------------------------------------------
# Traffic Analysis & Summarization
# ---------------------------------------------------------------------------

def extract_endpoints_from_traffic_entries(
    entries: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Extract distinct API endpoints discovered in runtime traffic.

    Args:
        entries: Collection of parsed traffic records.

    Returns:
        List of normalized endpoint dictionaries with observed traffic evidence.
    """
    endpoints_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for item in entries:
        method = (item.get("method") or "GET").upper()
        host = (item.get("host") or "").lower()
        path = item.get("path") or "/"

        norm = normalize_endpoint({
            "domain": host,
            "path": path,
            "method": method,
        })
        norm_path = norm["normalized_path"]
        key = (host, norm_path, method)

        status_code = item.get("response_status")
        status_list = [status_code] if status_code is not None else []
        src_file = item.get("source_file") or "traffic"

        if key not in endpoints_map:
            endpoints_map[key] = {
                "domain": host,
                "path": path,
                "normalized_path": norm_path,
                "method": method,
                "status_codes": set(status_list),
                "query_params": set(item.get("query_params", {}).keys()) if isinstance(item.get("query_params"), dict) else set(),
                "content_types": {item.get("content_type")} if item.get("content_type") else set(),
                "discovery_sources": [f"traffic:{src_file}"],
                "confidence": 1.0,  # Directly captured runtime traffic
                "request_count": 1,
                "sample_url": item.get("url") or f"{host}{path}",
                "first_seen": item.get("timestamp") or now,
                "last_seen": item.get("timestamp") or now,
            }
        else:
            ep = endpoints_map[key]
            ep["request_count"] += 1
            if status_code is not None:
                ep["status_codes"].add(status_code)
            if isinstance(item.get("query_params"), dict):
                for qk in item["query_params"].keys():
                    ep["query_params"].add(qk)
            if item.get("content_type"):
                ep["content_types"].add(item["content_type"])
            src_tag = f"traffic:{src_file}"
            if src_tag not in ep["discovery_sources"]:
                ep["discovery_sources"].append(src_tag)
            if item.get("timestamp"):
                ep["last_seen"] = item["timestamp"]

    # Convert sets to sorted lists for JSON serialization
    results: List[Dict[str, Any]] = []
    for ep in endpoints_map.values():
        rec = dict(ep)
        rec["status_codes"] = sorted(list(ep["status_codes"]))
        rec["query_params"] = sorted(list(ep["query_params"]))
        rec["content_types"] = sorted(list(ep["content_types"]))
        rec["evidence"] = f"Runtime traffic: {rec['method']} {rec['sample_url']} (calls: {rec['request_count']})"
        results.append(rec)

    results.sort(key=lambda x: (x["domain"], x["normalized_path"], x["method"]))
    return results


def summarize_traffic(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate reconnaissance metrics over captured traffic logs.

    Args:
        entries: Collection of parsed traffic records.

    Returns:
        Dict with total counts, method distribution, status distribution,
        host distribution, and sensitive header metrics.
    """
    total = len(entries)
    hosts: Dict[str, int] = {}
    methods: Dict[str, int] = {}
    status_codes: Dict[str, int] = {}
    content_types: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    sensitive_headers_found = 0

    for item in entries:
        h = item.get("host") or "unknown"
        hosts[h] = hosts.get(h, 0) + 1

        m = item.get("method") or "UNKNOWN"
        methods[m] = methods.get(m, 0) + 1

        sc = item.get("response_status")
        sc_key = str(sc) if sc is not None else "no_response"
        status_codes[sc_key] = status_codes.get(sc_key, 0) + 1

        ct = item.get("content_type") or "unspecified"
        content_types[ct] = content_types.get(ct, 0) + 1

        src = item.get("source_file") or "unknown"
        sources[src] = sources.get(src, 0) + 1

        # Check for sensitive headers
        hdrs = item.get("headers") or {}
        for k in hdrs.keys():
            if k.lower() in SENSITIVE_HEADERS:
                sensitive_headers_found += 1
                break

    return {
        "total_requests": total,
        "unique_hosts_count": len(hosts),
        "hosts": hosts,
        "methods_distribution": methods,
        "status_codes_distribution": status_codes,
        "content_types_distribution": content_types,
        "sources_analyzed": sources,
        "requests_with_sensitive_headers": sensitive_headers_found,
    }


# ---------------------------------------------------------------------------
# File Loader & Auto-Detector
# ---------------------------------------------------------------------------

def parse_traffic_file(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Auto-detect format (Burp XML vs HAR JSON) and parse traffic file.

    Args:
        file_path: Path to traffic export file.

    Returns:
        List of parsed traffic request records.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return []

    # Read prefix to detect XML vs JSON
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            start_chunk = f.read(500).strip()
    except Exception:
        return []

    if start_chunk.startswith("<") or "<items" in start_chunk or "<item" in start_chunk:
        return parse_burp_xml(path)
    elif start_chunk.startswith("{") or '"log"' in start_chunk:
        return parse_har(path)
    else:
        # Try both
        try:
            return parse_burp_xml(path)
        except Exception:
            try:
                return parse_har(path)
            except Exception:
                return []


# ---------------------------------------------------------------------------
# High-Level Orchestrator
# ---------------------------------------------------------------------------

def run_traffic_analysis(
    session: Optional[Any] = None,
    source_files: Optional[List[Union[str, Path]]] = None,
    output_dir: Optional[Path] = None,
    redact_output: bool = True,
) -> Dict[str, Any]:
    """Execute full traffic reconnaissance workflow and write output files.

    Writes:
        - ``traffic/requests.json``: All parsed HTTP requests (redacted by default).
        - ``traffic/endpoints.json``: Distinct endpoints observed in traffic.
        - ``traffic/traffic-summary.json``: Aggregate traffic statistics.

    Args:
        session: Active HUNTX session.
        source_files: Explicit list of Burp XML or HAR files to process.
        output_dir: Output directory.
        redact_output: Whether to redact sensitive auth tokens/cookies.

    Returns:
        Summary dict containing parsed counts, summary stats, and discovered endpoints.
    """
    files_to_process: List[Path] = []

    if source_files:
        for f in source_files:
            p = Path(f)
            if p.exists() and p.is_file():
                files_to_process.append(p)
    elif session is not None and hasattr(session, "run_path"):
        input_dir = session.run_path / "input"
        if input_dir.exists():
            for ext in ("*.xml", "*.har", "*.json"):
                # manifest.json is the XAPK bundle descriptor, not a capture
                files_to_process.extend(p for p in sorted(input_dir.glob(ext)) if p.name != "manifest.json")

    all_entries: List[Dict[str, Any]] = []
    for fp in files_to_process:
        entries = parse_traffic_file(fp)
        for entry in entries:
            entry["source_file"] = fp.name
        all_entries.extend(entries)

    if redact_output:
        all_entries = [redact_traffic_entry(e) for e in all_entries]

    # Accumulate across imports: a HAR import must not wipe an earlier Burp one
    processed = {fp.name for fp in files_to_process}
    prior_dir = output_dir or (session.run_path / "traffic" if session is not None and hasattr(session, "run_path") else None)
    if prior_dir is not None and (prior_dir / "requests.json").exists():
        try:
            prior = json.loads((prior_dir / "requests.json").read_text(encoding="utf-8"))
            all_entries = [e for e in prior if e.get("source_file") not in processed] + all_entries
        except (OSError, ValueError, AttributeError) as exc:
            logger.warning("Previous traffic import unreadable: %s", exc)

    # Compute summaries
    summary = summarize_traffic(all_entries)
    traffic_endpoints = extract_endpoints_from_traffic_entries(all_entries)

    export_entries = all_entries

    # Output to disk
    dest_dir = output_dir
    if dest_dir is None and session is not None and hasattr(session, "run_path"):
        dest_dir = session.run_path / "traffic"

    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)

        # 1. requests.json
        req_file = dest_dir / "requests.json"
        with req_file.open("w", encoding="utf-8") as f:
            json.dump(export_entries, f, indent=2)

        # 2. endpoints.json
        ep_file = dest_dir / "endpoints.json"
        with ep_file.open("w", encoding="utf-8") as f:
            json.dump(traffic_endpoints, f, indent=2)

        # 3. traffic-summary.json
        sum_file = dest_dir / "traffic-summary.json"
        payload = {
            "summary": summary,
            "endpoints_count": len(traffic_endpoints),
            "files_analyzed": sorted({str(e.get("source_file", "")) for e in all_entries}),
        }
        with sum_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    # Persist to database if session is active
    if session is not None and hasattr(session, "db_path"):
        try:
            from huntx.storage.database import Database
            with Database(session.db_path) as db:
                db.initialize()
                db.clear("traffic_requests")
                for entry in export_entries:
                    body_text = entry.get("body", "")
                    body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest() if body_text else ""
                    db.insert("traffic_requests", {
                        "method": entry.get("method", ""),
                        "url": entry.get("url", ""),
                        "host": entry.get("host", ""),
                        "headers_json": json.dumps(entry.get("headers", {})),
                        "body_hash": body_hash,
                        "response_status": entry.get("response_status"),
                        "timestamp": entry.get("timestamp", ""),
                        "source_file": entry.get("source_file", ""),
                        "session_id": getattr(session.metadata, "session_id", ""),
                    })
        except Exception as exc:
            logger.warning("Skipped unreadable data: %s", exc)

    return {
        "total_requests": len(all_entries),
        "total_endpoints": len(traffic_endpoints),
        "unique_endpoints": len(traffic_endpoints),
        "summary": summary,
        "endpoints": traffic_endpoints,
        "requests": export_entries,
    }
