"""HUNTX API Engine — OpenAPI Specification Ingest and Export.

Ingests existing OpenAPI 2.0 (Swagger) and 3.0/3.1 JSON/YAML files, and exports
discovered endpoints into valid OpenAPI 3.0.3 specifications annotated with
reconnaissance evidence, confidence ratings, and parameter details.
"""
from __future__ import annotations

import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Set
from urllib.parse import urlparse

from huntx.engines.api.normalizer import normalize_endpoint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenAPI Ingestion
# ---------------------------------------------------------------------------

def parse_openapi_spec(
    spec_data: Union[Dict[str, Any], str, Path]
) -> List[Dict[str, Any]]:
    """Parse an OpenAPI (v2 Swagger or v3) document into HUNTX Endpoint records.

    Supports dict, JSON string, or Path to JSON/YAML file.

    Args:
        spec_data: Spec dict, raw JSON string, or Path to spec file.

    Returns:
        List of normalized HUNTX Endpoint dictionaries.
    """
    raw_dict = _load_spec_dict(spec_data)
    if not raw_dict:
        return []

    is_swagger_2 = "swagger" in raw_dict and raw_dict["swagger"].startswith("2")
    is_openapi_3 = "openapi" in raw_dict

    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    # Determine default domain / server URL
    base_domain = ""
    base_path = ""

    if is_swagger_2:
        base_domain = raw_dict.get("host", "").split(":")[0]
        base_path = raw_dict.get("basePath", "")
        if base_path == "/":
            base_path = ""
    elif is_openapi_3:
        servers = raw_dict.get("servers") or []
        if servers and isinstance(servers, list):
            first_url = servers[0].get("url", "")
            if "://" in first_url:
                try:
                    parsed = urlparse(first_url)
                    base_domain = parsed.netloc.split(":")[0]
                    base_path = parsed.path.rstrip("/")
                except Exception as exc:
                    logger.debug("Skipped malformed value: %s", exc)
            elif first_url.startswith("/"):
                base_path = first_url.rstrip("/")

    paths = raw_dict.get("paths") or {}
    standard_methods = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

    for path_key, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        full_path = f"{base_path}{path_key}" if not path_key.startswith(base_path) else path_key
        if not full_path.startswith("/"):
            full_path = "/" + full_path

        # Path-level parameters
        common_parameters = path_item.get("parameters") or []

        for method_key, operation in path_item.items():
            if method_key.lower() not in standard_methods or not isinstance(operation, dict):
                continue

            method = method_key.upper()
            op_id = operation.get("operationId", "")
            summary = operation.get("summary") or operation.get("description") or ""

            # Combine path-level and operation-level parameters
            op_params = operation.get("parameters") or []
            all_params = list(common_parameters) + list(op_params)

            query_params = []
            path_params = []
            header_params = []

            for p in all_params:
                if not isinstance(p, dict):
                    continue
                p_name = p.get("name", "")
                p_in = p.get("in", "")
                if p_in == "query":
                    query_params.append({
                        "name": p_name,
                        "type": "query",
                        "data_type": p.get("schema", {}).get("type", "string"),
                        "required": p.get("required", False),
                    })
                elif p_in == "path":
                    path_params.append(p_name)
                elif p_in == "header":
                    header_params.append(p_name)

            # Request body content type in OpenAPI 3
            content_type = ""
            if "requestBody" in operation:
                rb = operation["requestBody"]
                if isinstance(rb, dict) and "content" in rb:
                    content_types = list(rb["content"].keys())
                    if content_types:
                        content_type = content_types[0]

            ep = {
                "domain": base_domain,
                "path": full_path,
                "method": method,
                "query_params": query_params,
                "path_params": path_params,
                "content_type": content_type,
                "source_file": "openapi_spec",
                "source_class": op_id,
                "source_method": summary[:100],
                "discovery_sources": ["openapi"],
                "confidence": 1.0,
                "evidence": f"OpenAPI: {method} {full_path} ({op_id or summary})",
                "first_seen": now,
                "last_seen": now,
            }
            endpoints.append(normalize_endpoint(ep))

    return endpoints


def _load_spec_dict(spec_data: Union[Dict[str, Any], str, Path]) -> Optional[Dict[str, Any]]:
    """Helper to convert input into a Python dict."""
    if isinstance(spec_data, dict):
        return spec_data

    raw_str = ""
    if isinstance(spec_data, Path) or (isinstance(spec_data, str) and (spec_data.endswith(".json") or spec_data.endswith(".yaml") or spec_data.endswith(".yml"))):
        p = Path(spec_data)
        if p.exists() and p.is_file():
            raw_str = p.read_text(encoding="utf-8", errors="replace")
        else:
            raw_str = str(spec_data)
    else:
        raw_str = str(spec_data)

    if not raw_str:
        return None

    # Try JSON
    trimmed = raw_str.strip()
    if trimmed.startswith("{"):
        try:
            return json.loads(trimmed)
        except Exception as exc:
            logger.debug("Skipped malformed value: %s", exc)

    # Try YAML if available
    try:
        import yaml
        loaded = yaml.safe_load(raw_str)
        if isinstance(loaded, dict):
            return loaded
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Skipped malformed value: %s", exc)

    return None


# ---------------------------------------------------------------------------
# OpenAPI Export
# ---------------------------------------------------------------------------

def export_openapi_spec(
    endpoints: List[Dict[str, Any]],
    title: str = "HUNTX Discovered API",
    version: str = "1.0.0",
    base_url: str = "",
) -> Dict[str, Any]:
    """Export discovered endpoints into a valid OpenAPI 3.0.3 specification.

    Endpoints are enriched with discovery sources, confidence scores,
    path parameters, and query parameters.

    Args:
        endpoints: Collection of discovered endpoint dictionaries.
        title: API title for the info block.
        version: API version string.
        base_url: Optional base server URL.

    Returns:
        Valid OpenAPI 3.0.3 specification as a Python dictionary.
    """
    domains: Set[str] = set()
    for ep in endpoints:
        d = ep.get("domain")
        if d:
            domains.add(d)

    servers = []
    if base_url:
        servers.append({"url": base_url})
    for d in sorted(domains):
        servers.append({
            "url": f"https://{d}",
            "description": f"Observed host {d}",
        })
    if not servers:
        servers.append({"url": "https://api.example.com", "description": "Default base URL"})

    paths_dict: Dict[str, Dict[str, Any]] = {}

    for ep in endpoints:
        norm_path = ep.get("normalized_path") or ep.get("path") or "/"
        method = (ep.get("method") or "GET").lower()

        # OpenAPI requires lowercase standard HTTP methods
        if method not in {"get", "post", "put", "delete", "patch", "head", "options", "trace"}:
            method = "get"

        if norm_path not in paths_dict:
            paths_dict[norm_path] = {}

        # Parameters block
        parameters: List[Dict[str, Any]] = []

        # Path params
        for pp in ep.get("path_params", []):
            parameters.append({
                "name": pp,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"Dynamic path parameter '{pp}'",
            })

        # Query params
        for qp in ep.get("query_params", []):
            name = qp.get("name") if isinstance(qp, dict) else str(qp)
            if not name:
                continue
            sample = qp.get("sample_value") if isinstance(qp, dict) else ""
            parameters.append({
                "name": name,
                "in": "query",
                "required": False,
                "schema": {"type": "string", "example": sample} if sample else {"type": "string"},
                "description": f"Query parameter '{name}'",
            })

        operation: Dict[str, Any] = {
            "summary": f"{method.upper()} {norm_path}",
            "description": ep.get("evidence") or "Discovered by HUNTX reconnaissance",
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                }
            },
            # HUNTX Evidence Metadata Extension fields
            "x-huntx-confidence": ep.get("confidence", 0.5),
            "x-huntx-sources": ep.get("discovery_sources", []),
            "x-huntx-original-path": ep.get("path", norm_path),
        }

        if parameters:
            operation["parameters"] = parameters

        if ep.get("content_type"):
            ct = ep["content_type"]
            operation["requestBody"] = {
                "required": False,
                "content": {
                    ct: {
                        "schema": {"type": "object"}
                    }
                }
            }

        if ep.get("source_class"):
            operation["x-huntx-source-class"] = ep["source_class"]

        paths_dict[norm_path][method] = operation

    spec: Dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "version": version,
            "description": "Generated by HUNTX Android & API Reconnaissance Engine.",
            "x-generated-at": datetime.now(timezone.utc).isoformat(),
        },
        "servers": servers,
        "paths": paths_dict,
    }

    return spec


def save_openapi_spec(
    spec: Dict[str, Any], output_path: Union[str, Path]
) -> Path:
    """Save OpenAPI specification dictionary to disk as JSON.

    Args:
        spec: OpenAPI specification dictionary.
        output_path: Target file path.

    Returns:
        Path of written specification file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)
    return path
