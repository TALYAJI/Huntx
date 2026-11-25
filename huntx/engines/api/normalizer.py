"""HUNTX API Engine — Path and Endpoint Normalizer.

Detects dynamic path segments (numeric IDs, UUIDs, hex hashes, dates, timestamps)
and replaces them with standard placeholder tokens while preserving raw paths,
normalization rules applied, and query parameter differences.
"""
from __future__ import annotations

import logging
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dynamic Segment Patterns
# ---------------------------------------------------------------------------

# UUID v1-v5 (with or without hyphens)
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_UUID_NO_HYPHEN = re.compile(
    r"^[0-9a-f]{32}$",
    re.IGNORECASE,
)

# Hex hashes: SHA-256 (64 hex), SHA-1 (40 hex), MD5 (32 hex covered above)
_HEX_HASH_PATTERN = re.compile(
    r"^[0-9a-f]{40}$|^[0-9a-f]{64}$",
    re.IGNORECASE,
)

# ISO dates: YYYY-MM-DD or YYYYMMDD
_DATE_PATTERN = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$"
)
_DATE_COMPACT_PATTERN = re.compile(
    r"^\d{4}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$"
)

# Unix timestamps (seconds 10 digits or milliseconds 13 digits)
_TIMESTAMP_PATTERN = re.compile(
    r"^(?:1[5-9]\d{8}|2[0-9]\d{8}|1[5-9]\d{11}|2[0-9]\d{11})$"
)

# Integer ID (pure digits, not version numbers like v1, v2)
_NUMERIC_ID_PATTERN = re.compile(r"^\d+$")

# Prefixed ID patterns (e.g., usr_12345, ord_abcdef123, acc-9921)
_PREFIXED_ID_PATTERN = re.compile(
    r"^[a-zA-Z]{2,6}[_-][0-9a-zA-Z]{6,36}$"
)

# Version segment pattern (e.g., v1, v2, v1.0, v2beta) - should NOT be normalized
_VERSION_PATTERN = re.compile(r"^v\d+(?:\.\d+)?(?:[a-zA-Z0-9]+)?$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Normalization Logic
# ---------------------------------------------------------------------------

def normalize_segment(segment: str, position: int) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Inspect a single path segment and normalize if dynamic.

    Args:
        segment: Path segment string (without slashes).
        position: Zero-based segment index in path.

    Returns:
        Tuple of (replacement_string, rule_dict_or_None).
    """
    if not segment:
        return segment, None

    # Already parameterized (e.g., {userId}, {id}, :id, <id>)
    if (segment.startswith("{") and segment.endswith("}")) or (segment.startswith("<") and segment.endswith(">")):
        return segment, None
    if segment.startswith(":") and len(segment) > 1:
        param_name = segment[1:]
        return f"{{{param_name}}}", {
            "position": position,
            "original_segment": segment,
            "rule": "colon_param",
            "replacement": f"{{{param_name}}}",
        }

    # Do not normalize API versions (v1, v2, etc.)
    if _VERSION_PATTERN.match(segment):
        return segment, None

    # Check UUID
    if _UUID_PATTERN.match(segment):
        return "{uuid}", {
            "position": position,
            "original_segment": segment,
            "rule": "uuid",
            "replacement": "{uuid}",
        }

    # Check Date
    if _DATE_PATTERN.match(segment) or _DATE_COMPACT_PATTERN.match(segment):
        return "{date}", {
            "position": position,
            "original_segment": segment,
            "rule": "date",
            "replacement": "{date}",
        }

    # Check Timestamp
    if _TIMESTAMP_PATTERN.match(segment):
        return "{timestamp}", {
            "position": position,
            "original_segment": segment,
            "rule": "timestamp",
            "replacement": "{timestamp}",
        }

    # Check Hex Hash (40 or 64 hex chars)
    if _HEX_HASH_PATTERN.match(segment):
        return "{hash}", {
            "position": position,
            "original_segment": segment,
            "rule": "hex_hash",
            "replacement": "{hash}",
        }

    # 32 hex chars: can be MD5 or UUID no hyphen
    if _UUID_NO_HYPHEN.match(segment):
        return "{hash}", {
            "position": position,
            "original_segment": segment,
            "rule": "hex_hash",
            "replacement": "{hash}",
        }

    # Check Pure Numeric ID
    if _NUMERIC_ID_PATTERN.match(segment):
        return "{id}", {
            "position": position,
            "original_segment": segment,
            "rule": "numeric_id",
            "replacement": "{id}",
        }

    # Check Prefixed ID (e.g., user_abc123)
    if _PREFIXED_ID_PATTERN.match(segment):
        prefix = segment.split("_", 1)[0] if "_" in segment else segment.split("-", 1)[0]
        replacement = f"{{{prefix}_id}}"
        return replacement, {
            "position": position,
            "original_segment": segment,
            "rule": "prefixed_id",
            "replacement": replacement,
        }

    return segment, None


def normalize_path(path: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Normalize dynamic elements in an API path.

    Splits query parameters, normalizes path segments, and re-attaches path.

    Args:
        path: Raw URL path, e.g. ``"/api/v1/users/123/profile"`` or with query.

    Returns:
        Tuple of (normalized_path, list_of_applied_rules).
    """
    if not path or not isinstance(path, str):
        return "/", []

    # Separate query string if present
    base_path = path.split("?")[0].split("#")[0]
    has_leading_slash = base_path.startswith("/")
    has_trailing_slash = base_path.endswith("/") and len(base_path) > 1

    segments = base_path.strip("/").split("/")
    normalized_segments: List[str] = []
    rules: List[Dict[str, Any]] = []

    for idx, seg in enumerate(segments):
        norm_seg, rule = normalize_segment(seg, idx)
        normalized_segments.append(norm_seg)
        if rule is not None:
            rules.append(rule)

    norm_path = "/".join(normalized_segments)
    if has_leading_slash:
        norm_path = "/" + norm_path
    if has_trailing_slash and not norm_path.endswith("/"):
        norm_path = norm_path + "/"

    return norm_path, rules


def normalize_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Apply normalization to an endpoint dictionary.

    Preserves original ``path``, populates ``normalized_path``, records
    ``normalization_rules`` applied, and preserves ``method`` and query params.

    Args:
        endpoint: Endpoint dictionary.

    Returns:
        Enriched endpoint dictionary with normalization details.
    """
    raw_path = endpoint.get("path") or "/"
    norm_path, rules = normalize_path(raw_path)

    updated = dict(endpoint)
    updated["original_path"] = raw_path
    updated["normalized_path"] = norm_path
    updated["normalization_rules"] = rules

    # Ensure path params are populated
    path_params = list(updated.get("path_params") or [])
    for match in re.finditer(r"\{([a-zA-Z0-9_-]+)\}", norm_path):
        param_name = match.group(1)
        if param_name not in path_params:
            path_params.append(param_name)
    updated["path_params"] = path_params

    return updated


def normalize_endpoints_list(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize a list of endpoint dictionaries.

    Args:
        endpoints: Collection of raw endpoint dicts.

    Returns:
        List of normalized endpoint dictionaries.
    """
    return [normalize_endpoint(ep) for ep in endpoints]


def group_by_normalized_path(
    endpoints: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Group concrete endpoint instances by their normalized path and method.

    Tracks differences in observed query parameters and original paths.

    Args:
        endpoints: List of endpoint dictionaries.

    Returns:
        Dict mapping group key ``"{method} {domain}{normalized_path}"`` to group summary.
    """
    groups: Dict[str, Dict[str, Any]] = {}

    for ep in endpoints:
        norm = normalize_endpoint(ep)
        method = (norm.get("method") or "UNKNOWN").upper()
        domain = norm.get("domain") or ""
        norm_path = norm.get("normalized_path") or "/"

        key = f"{method} {domain}{norm_path}".strip()

        if key not in groups:
            groups[key] = {
                "key": key,
                "method": method if method != "UNKNOWN" else "",
                "domain": domain,
                "normalized_path": norm_path,
                "path_params": norm.get("path_params", []),
                "observed_instances": [norm.get("original_path", norm_path)],
                "query_param_variations": set(),
                "discovery_sources": set(norm.get("discovery_sources", [])),
                "normalization_rules": norm.get("normalization_rules", []),
                "count": 1,
            }
        else:
            group = groups[key]
            group["count"] += 1
            orig = norm.get("original_path", norm_path)
            if orig not in group["observed_instances"]:
                group["observed_instances"].append(orig)
            for src in norm.get("discovery_sources", []):
                group["discovery_sources"].add(src)

        # Track query parameter variations
        q_params = norm.get("query_params") or []
        if isinstance(q_params, list):
            for qp in q_params:
                name = qp.get("name") if isinstance(qp, dict) else str(qp)
                if name:
                    groups[key]["query_param_variations"].add(name)
        elif isinstance(q_params, dict):
            for k in q_params:
                groups[key]["query_param_variations"].add(str(k))

    # Convert sets to sorted lists for JSON serialization
    serialized: Dict[str, Dict[str, Any]] = {}
    for k, v in groups.items():
        v_copy = dict(v)
        v_copy["query_param_variations"] = sorted(list(v["query_param_variations"]))
        v_copy["discovery_sources"] = sorted(list(v["discovery_sources"]))
        serialized[k] = v_copy

    return serialized


def run_normalization(
    session: Optional[Any] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute normalization on discovered endpoints and save results.

    Args:
        session: Active HUNTX session.
        endpoints: Optional endpoint dict list. If None, reads from session.
        output_dir: Explicit output directory.

    Returns:
        Summary dict containing normalized endpoints and grouping stats.
    """
    raw_endpoints: List[Dict[str, Any]] = []
    if endpoints is not None:
        raw_endpoints.extend(endpoints)
    elif session is not None and hasattr(session, "run_path"):
        ep_json = session.run_path / "api" / "endpoints.json"
        if ep_json.exists():
            try:
                with ep_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        raw_endpoints.extend(data)
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

    normalized = normalize_endpoints_list(raw_endpoints)
    groups = group_by_normalized_path(normalized)

    # Output to disk
    dest_dir = output_dir
    if dest_dir is None and session is not None and hasattr(session, "run_path"):
        dest_dir = session.run_path / "api"

    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_file = dest_dir / "endpoints-normalized.json"
        payload = {
            "total_raw_endpoints": len(raw_endpoints),
            "total_normalized_groups": len(groups),
            "groups": list(groups.values()),
            "normalized_endpoints": normalized,
        }
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    return {
        "total_raw": len(raw_endpoints),
        "total_grouped": len(groups),
        "groups": groups,
        "normalized_endpoints": normalized,
    }
