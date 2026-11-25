"""HUNTX API Engine — Parameter Extraction and Classification.

Extracts and classifies API parameters into path, query, header, and body parameters
from discovered endpoints, Retrofit annotations, and traffic requests.
"""
from __future__ import annotations

import logging
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive Parameter Keywords
# ---------------------------------------------------------------------------

SENSITIVE_PARAM_NAMES: Set[str] = {
    "password", "passwd", "pass", "pwd",
    "secret", "api_key", "apikey", "key",
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "authorization", "auth", "bearer",
    "pin", "ssn", "cvv", "cvc", "credit_card", "card_number",
    "private_key", "client_secret", "signature",
    "session", "session_id", "sessionid", "xsrf", "csrf",
}

# ---------------------------------------------------------------------------
# Type Inference Helpers
# ---------------------------------------------------------------------------

_UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def infer_data_type(value: Any) -> str:
    """Infer the data type of a parameter value.

    Args:
        value: Any sample value or string.

    Returns:
        One of: "integer", "float", "boolean", "uuid", "date", "array", "object", "string", "null".
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"

    val_str = str(value).strip()
    if val_str.lower() in ("true", "false"):
        return "boolean"
    if val_str.isdigit():
        return "integer"
    try:
        float(val_str)
        if "." in val_str:
            return "float"
    except ValueError:
        pass

    if _UUID_REGEX.match(val_str):
        return "uuid"
    if _DATE_REGEX.match(val_str):
        return "date"

    return "string"


def is_sensitive_parameter(name: str) -> bool:
    """Check whether a parameter name indicates sensitive information.

    Args:
        name: Parameter name.

    Returns:
        True if parameter is security-sensitive, False otherwise.
    """
    if not name:
        return False
    clean = name.strip().lower().replace("-", "_")
    if clean in SENSITIVE_PARAM_NAMES:
        return True
    for sensitive in SENSITIVE_PARAM_NAMES:
        if sensitive in clean:
            return True
    return False


# ---------------------------------------------------------------------------
# Parameter Extraction
# ---------------------------------------------------------------------------

def extract_parameters_from_endpoints(
    endpoints: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Extract path and query parameters from endpoint records.

    Args:
        endpoints: List of endpoint dictionaries.

    Returns:
        List of parameter dictionaries.
    """
    parameters: List[Dict[str, Any]] = []

    for ep in endpoints:
        path = ep.get("normalized_path") or ep.get("path") or "/"
        method = ep.get("method") or ""
        domain = ep.get("domain") or ""
        sources = ep.get("discovery_sources") or []

        # 1. Path parameters
        path_params = ep.get("path_params") or []
        # Also extract directly from path string {param}
        for match in re.finditer(r"\{([a-zA-Z0-9_-]+)\}", path):
            p_name = match.group(1)
            if p_name not in path_params:
                path_params.append(p_name)

        for p_name in path_params:
            parameters.append({
                "name": p_name,
                "param_type": "path",
                "endpoint_path": path,
                "endpoint_method": method,
                "domain": domain,
                "data_type": "string" if p_name != "id" else "integer",
                "sample_value": "",
                "is_sensitive": is_sensitive_parameter(p_name),
                "sources": list(sources),
            })

        # 2. Query parameters
        query_params = ep.get("query_params") or []
        for qp in query_params:
            if isinstance(qp, dict):
                name = qp.get("name", "")
                sample = qp.get("sample_value", "")
            else:
                name = str(qp)
                sample = ""

            if not name:
                continue

            parameters.append({
                "name": name,
                "param_type": "query",
                "endpoint_path": path,
                "endpoint_method": method,
                "domain": domain,
                "data_type": infer_data_type(sample) if sample else "string",
                "sample_value": sample if not is_sensitive_parameter(name) else "[REDACTED]",
                "is_sensitive": is_sensitive_parameter(name),
                "sources": list(sources),
            })

    return deduplicate_parameters(parameters)


def extract_parameters_from_traffic(
    traffic_requests: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Extract query, header, and body parameters from captured traffic.

    Args:
        traffic_requests: List of traffic request dicts.

    Returns:
        List of parameter dictionaries.
    """
    parameters: List[Dict[str, Any]] = []

    for req in traffic_requests:
        path = req.get("path") or req.get("url") or "/"
        # Strip query from path
        base_path = path.split("?")[0]
        method = req.get("method") or ""
        domain = req.get("host") or ""
        src = req.get("source_file") or "traffic"

        # 1. Query parameters
        q_params = req.get("query_params") or {}
        if isinstance(q_params, dict):
            for k, v in q_params.items():
                parameters.append({
                    "name": str(k),
                    "param_type": "query",
                    "endpoint_path": base_path,
                    "endpoint_method": method,
                    "domain": domain,
                    "data_type": infer_data_type(v),
                    "sample_value": str(v) if not is_sensitive_parameter(str(k)) else "[REDACTED]",
                    "is_sensitive": is_sensitive_parameter(str(k)),
                    "sources": [f"traffic:{src}"],
                })
        elif isinstance(q_params, list):
            for item in q_params:
                name = item.get("name") if isinstance(item, dict) else str(item)
                val = item.get("value") if isinstance(item, dict) else ""
                if name:
                    parameters.append({
                        "name": name,
                        "param_type": "query",
                        "endpoint_path": base_path,
                        "endpoint_method": method,
                        "domain": domain,
                        "data_type": infer_data_type(val),
                        "sample_value": str(val) if not is_sensitive_parameter(name) else "[REDACTED]",
                        "is_sensitive": is_sensitive_parameter(name),
                        "sources": [f"traffic:{src}"],
                    })

        # 2. Header parameters
        headers = req.get("headers") or {}
        for h_k, h_v in headers.items():
            parameters.append({
                "name": str(h_k),
                "param_type": "header",
                "endpoint_path": base_path,
                "endpoint_method": method,
                "domain": domain,
                "data_type": "string",
                "sample_value": str(h_v) if not is_sensitive_parameter(str(h_k)) else "[REDACTED]",
                "is_sensitive": is_sensitive_parameter(str(h_k)),
                "sources": [f"traffic:{src}"],
            })

        # 3. Body parameters (JSON or form)
        body = req.get("body")
        if body and isinstance(body, str):
            body_trimmed = body.strip()
            # Try JSON body
            if body_trimmed.startswith("{") and body_trimmed.endswith("}"):
                try:
                    parsed_json = json.loads(body_trimmed)
                    _extract_json_body_params(parsed_json, base_path, method, domain, src, parameters)
                except Exception as exc:
                    logger.debug("Skipped malformed value: %s", exc)
            # Try form-urlencoded body
            elif "=" in body_trimmed and not body_trimmed.startswith("<"):
                try:
                    parsed_form = parse_qs(body_trimmed, keep_blank_values=True)
                    for f_k, f_vals in parsed_form.items():
                        sample_v = f_vals[0] if f_vals else ""
                        parameters.append({
                            "name": str(f_k),
                            "param_type": "body",
                            "endpoint_path": base_path,
                            "endpoint_method": method,
                            "domain": domain,
                            "data_type": infer_data_type(sample_v),
                            "sample_value": str(sample_v) if not is_sensitive_parameter(str(f_k)) else "[REDACTED]",
                            "is_sensitive": is_sensitive_parameter(str(f_k)),
                            "sources": [f"traffic:{src}"],
                        })
                except Exception as exc:
                    logger.debug("Skipped malformed value: %s", exc)

    return deduplicate_parameters(parameters)


def _extract_json_body_params(
    data: Any,
    path: str,
    method: str,
    domain: str,
    src: str,
    output: List[Dict[str, Any]],
    prefix: str = "",
) -> None:
    """Recursively extract key names and types from JSON body objects."""
    if isinstance(data, dict):
        for k, v in data.items():
            full_name = f"{prefix}.{k}" if prefix else str(k)
            output.append({
                "name": full_name,
                "param_type": "body",
                "endpoint_path": path,
                "endpoint_method": method,
                "domain": domain,
                "data_type": infer_data_type(v),
                "sample_value": str(v)[:100] if not is_sensitive_parameter(full_name) else "[REDACTED]",
                "is_sensitive": is_sensitive_parameter(full_name),
                "sources": [f"traffic:{src}"],
            })
            if isinstance(v, (dict, list)):
                _extract_json_body_params(v, path, method, domain, src, output, prefix=full_name)
    elif isinstance(data, list) and data:
        if isinstance(data[0], (dict, list)):
            _extract_json_body_params(data[0], path, method, domain, src, output, prefix=f"{prefix}[]" if prefix else "item")


def deduplicate_parameters(parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate parameter records based on (name, param_type, endpoint_path).

    Merges sources and preserves sample values.

    Args:
        parameters: List of raw parameter dicts.

    Returns:
        Deduplicated list of parameter dicts.
    """
    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for param in parameters:
        key = (
            param.get("name", "").lower(),
            param.get("param_type", "").lower(),
            param.get("endpoint_path", "/"),
        )
        if key not in merged:
            copy_p = dict(param)
            copy_p["sources"] = list(param.get("sources", []))
            merged[key] = copy_p
        else:
            existing = merged[key]
            for s in param.get("sources", []):
                if s not in existing["sources"]:
                    existing["sources"].append(s)
            if not existing.get("sample_value") and param.get("sample_value"):
                existing["sample_value"] = param["sample_value"]
            if existing.get("data_type") == "string" and param.get("data_type") != "string":
                existing["data_type"] = param["data_type"]

    return list(merged.values())


# ---------------------------------------------------------------------------
# High-Level Orchestrator
# ---------------------------------------------------------------------------

def run_parameter_extraction(
    session: Optional[Any] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    traffic: Optional[List[Dict[str, Any]]] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute parameter extraction and write ``api/parameters.json``.

    Args:
        session: Active HUNTX session.
        endpoints: Optional endpoint collection.
        traffic: Optional traffic request collection.
        output_dir: Explicit output directory.

    Returns:
        Summary dict containing parameters inventory and statistics.
    """
    collected_params: List[Dict[str, Any]] = []

    # 1. From endpoints
    input_endpoints: List[Dict[str, Any]] = []
    if endpoints is not None:
        input_endpoints.extend(endpoints)
    elif session is not None and hasattr(session, "run_path"):
        ep_json = session.run_path / "api" / "endpoints.json"
        if ep_json.exists():
            try:
                with ep_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        input_endpoints.extend(data)
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

    if input_endpoints:
        collected_params.extend(extract_parameters_from_endpoints(input_endpoints))

    # 2. From traffic
    input_traffic: List[Dict[str, Any]] = []
    if traffic is not None:
        input_traffic.extend(traffic)
    elif session is not None and hasattr(session, "run_path"):
        traffic_json = session.run_path / "traffic" / "requests.json"
        if traffic_json.exists():
            try:
                with traffic_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        input_traffic.extend(data)
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

    if input_traffic:
        collected_params.extend(extract_parameters_from_traffic(input_traffic))

    deduped = deduplicate_parameters(collected_params)

    # Sort deterministically
    deduped.sort(key=lambda x: (x.get("param_type", ""), x.get("endpoint_path", ""), x.get("name", "")))

    # Statistics
    type_counts: Dict[str, int] = {}
    sensitive_count = 0
    for p in deduped:
        pt = p.get("param_type", "unknown")
        type_counts[pt] = type_counts.get(pt, 0) + 1
        if p.get("is_sensitive"):
            sensitive_count += 1

    payload = {
        "total_parameters": len(deduped),
        "path_parameters": type_counts.get("path", 0),
        "query_parameters": type_counts.get("query", 0),
        "header_parameters": type_counts.get("header", 0),
        "body_parameters": type_counts.get("body", 0),
        "sensitive_parameters_count": sensitive_count,
        "type_breakdown": type_counts,
        "parameters": deduped,
    }

    # Output to disk
    dest_dir = output_dir
    if dest_dir is None and session is not None and hasattr(session, "run_path"):
        dest_dir = session.run_path / "api"

    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        json_path = dest_dir / "parameters.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    return payload
