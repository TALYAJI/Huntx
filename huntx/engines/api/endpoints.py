"""HUNTX API Engine — Endpoint Extraction and Inventory.

Extracts API endpoints from URLs, relative API paths, Retrofit annotations,
DEX strings, OpenAPI documents, and traffic logs.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from huntx.core.csvsafe import safe_row
from huntx.engines.api.normalizer import normalize_endpoint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extraction Patterns
# ---------------------------------------------------------------------------

# Full URL regex
_URL_REGEX = re.compile(
    r"(?i)\b(https?://[a-zA-Z0-9.-]+(?::\d{1,5})?(?:/[^\s\"'<>{}|\^`\\]*)?)",
    re.IGNORECASE,
)

# Relative API path regex (e.g., /api/v1/users, /rest/v2/items, /graphql)
_RELATIVE_API_REGEX = re.compile(
    r"(?<![\w.$/:}-])(/(?:api|v\d+|rest|graphql|oauth|auth|v\d+\.\d+|service|services|gateway|v1alpha\d?|v1beta\d?)(?:/[a-zA-Z0-9_\-/{}:]+)*(?:\?[a-zA-Z0-9_=&%-]*)?)",
    re.IGNORECASE,
)

# Retrofit annotations
_RETROFIT_METHOD_REGEX = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']*)["\']\s*\)',
    re.IGNORECASE,
)
_RETROFIT_HTTP_REGEX = re.compile(
    r'@HTTP\s*\(\s*method\s*=\s*["\']([A-Z]+)["\']\s*,\s*path\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_RETROFIT_PARAM_REGEX = re.compile(
    r'@(Query|Path|Header|Field|Part)\s*\(\s*["\']([^"\']+)["\']\s*\)',
    re.IGNORECASE,
)
_RETROFIT_BODY_REGEX = re.compile(
    r'@Body\b',
    re.IGNORECASE,
)

# Static asset extensions to ignore
_IGNORED_PATH_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".wav", ".mp4", ".ogg",
    ".css", ".arsc",
)

# Configurable SDK/library noise signatures
_SDK_NOISE_DOMAINS = (
    "schemas.android.com",
    "www.w3.org",
    "xml.org",
    "xmlpull.org",
    "purl.org",
    "apache.org",
)

_SDK_NOISE_PATH_PREFIXES = (
    "/xmlpull/",
    "/v1/xmlpull",
    "/auth/x500/",
    "/v4/app/",
    "/v4/graphics/",
    "/v4/os/",
    "/v4/media/",
    "/v7/widget/",
    "/v7/view/",
    "/apk/res-auto",
    "/apk/res/android",
)


def is_sdk_noise_endpoint(path: str, domain: str = "") -> bool:
    """Return True if endpoint matches known Android/Java SDK internal paths or XML namespaces."""
    d_lower = (domain or "").strip().lower()
    p_lower = (path or "").strip().lower()
    if d_lower in _SDK_NOISE_DOMAINS or any(d_lower.endswith("." + sd) for sd in _SDK_NOISE_DOMAINS):
        return True
    if any(p_lower.startswith(pref) or pref in p_lower for pref in _SDK_NOISE_PATH_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------------------
# Extraction Functions
# ---------------------------------------------------------------------------

def extract_endpoints_from_urls(
    urls: Iterable[str], source: str = "url"
) -> List[Dict[str, Any]]:
    """Extract structured endpoint records from full URL strings.

    Args:
        urls: Collection of URL strings.
        source: Discovery source label.

    Returns:
        List of raw endpoint dictionaries.
    """
    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for raw_url in urls:
        if not raw_url or not isinstance(raw_url, str):
            continue
        raw_url = raw_url.strip().strip("'\"<>[]()")
        if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
            continue

        try:
            parsed = urlparse(raw_url)
        except Exception as exc:
            logger.debug("Skipped malformed value: %s", exc)
            continue

        domain = parsed.netloc.split(":")[0].lower()
        path = parsed.path or "/"

        # Check ignored file extensions
        if any(path.lower().endswith(ext) for ext in _IGNORED_PATH_EXTENSIONS):
            continue

        # Extract query parameters
        query_params = []
        if parsed.query:
            try:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for k, vals in qs.items():
                    query_params.append({
                        "name": k,
                        "sample_value": vals[0] if vals else "",
                        "type": "query",
                    })
            except Exception as exc:
                logger.warning("Skipped unreadable data: %s", exc)

        ep = {
            "domain": domain,
            "path": path,
            "method": "",  # Method unknown from bare URL string
            "query_params": query_params,
            "path_params": [],
            "content_type": "",
            "source_file": "",
            "source_class": "",
            "source_method": "",
            "discovery_sources": [source],
            "confidence": 0.75,
            "evidence": raw_url[:300],
            "first_seen": now,
            "last_seen": now,
        }
        endpoints.append(normalize_endpoint(ep))

    return endpoints


def extract_endpoints_from_strings(
    strings: Iterable[Any], default_source: str = "dex_strings"
) -> List[Dict[str, Any]]:
    """Extract endpoints from strings found in DEX, manifest, resources, or configs.

    Args:
        strings: List of string values, or list of dicts with 'value' and 'source_location'.
        default_source: Fallback source name.

    Returns:
        List of normalized endpoint dictionaries.
    """
    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for item in strings:
        if isinstance(item, dict):
            text = str(item.get("value") or item.get("string") or "")
            src_loc = str(item.get("source_location") or "")
            src = str(item.get("source") or default_source)
        elif isinstance(item, str):
            text = item
            src_loc = ""
            src = default_source
        else:
            text = str(item)
            src_loc = ""
            src = default_source

        if not text:
            continue

        # 1. Look for full URLs
        for match in _URL_REGEX.finditer(text):
            url_str = match.group(1)
            try:
                parsed = urlparse(url_str)
                domain = parsed.netloc.split(":")[0].lower()
                path = parsed.path or "/"

                if any(path.lower().endswith(ext) for ext in _IGNORED_PATH_EXTENSIONS):
                    continue

                query_params = []
                if parsed.query:
                    try:
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        for k, vals in qs.items():
                            query_params.append({
                                "name": k,
                                "sample_value": vals[0] if vals else "",
                                "type": "query",
                            })
                    except Exception as exc:
                        logger.warning("Skipped unreadable data: %s", exc)

                ep = {
                    "domain": domain,
                    "path": path,
                    "method": "",
                    "query_params": query_params,
                    "path_params": [],
                    "content_type": "",
                    "source_file": src_loc,
                    "source_class": "",
                    "source_method": "",
                    "discovery_sources": [src],
                    "confidence": 0.7,
                    "evidence": text[:300],
                    "first_seen": now,
                    "last_seen": now,
                }
                endpoints.append(normalize_endpoint(ep))
            except Exception as exc:
                logger.warning("Skipped unreadable data: %s", exc)

        # 2. Look for relative API paths
        for match in _RELATIVE_API_REGEX.finditer(text):
            rel_path = match.group(1)
            raw_path = rel_path.split("?")[0]

            if any(raw_path.lower().endswith(ext) for ext in _IGNORED_PATH_EXTENSIONS):
                continue

            query_params = []
            if "?" in rel_path:
                q_part = rel_path.split("?", 1)[1]
                try:
                    qs = parse_qs(q_part, keep_blank_values=True)
                    for k, vals in qs.items():
                        query_params.append({
                            "name": k,
                            "sample_value": vals[0] if vals else "",
                            "type": "query",
                        })
                except Exception as exc:
                    logger.warning("Skipped unreadable data: %s", exc)

            ep = {
                "domain": "",
                "path": raw_path,
                "method": "",
                "query_params": query_params,
                "path_params": [],
                "content_type": "",
                "source_file": src_loc,
                "source_class": "",
                "source_method": "",
                "discovery_sources": [f"{src}:relative_path"],
                "confidence": 0.6,
                "evidence": text[:300],
                "first_seen": now,
                "last_seen": now,
            }
            endpoints.append(normalize_endpoint(ep))

        # 3. Look for Retrofit annotations in decompiled code strings
        if "@" not in text:
            continue
        retrofit_eps = extract_endpoints_from_retrofit(text, source_location=src_loc)
        endpoints.extend(retrofit_eps)

    return deduplicate_endpoints(endpoints)


def extract_endpoints_from_retrofit(
    code_or_strings: Any, source_location: str = ""
) -> List[Dict[str, Any]]:
    """Extract endpoints from Retrofit interface annotations.

    Identifies HTTP methods (@GET, @POST, etc.), target paths, and parameter annotations.

    Args:
        code_or_strings: Text or collection of strings containing Java/Kotlin/Smali code.
        source_location: Source file/class location.

    Returns:
        List of normalized endpoint dictionaries with known HTTP methods.
    """
    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    if isinstance(code_or_strings, (list, tuple, set)):
        texts = [str(x) for x in code_or_strings]
    else:
        texts = [str(code_or_strings)]

    for text in texts:
        # Check standard @METHOD("path")
        for match in _RETROFIT_METHOD_REGEX.finditer(text):
            method = match.group(1).upper()
            path_val = match.group(2).strip()

            # Ensure leading slash if not empty
            if path_val and not path_val.startswith("/"):
                path_val = "/" + path_val
            elif not path_val:
                path_val = "/"

            # Extract surrounding method context for parameters
            start_pos = match.start()
            end_pos = min(len(text), match.end() + 250)
            context = text[start_pos:end_pos]

            query_params = []
            path_params = []
            for p_match in _RETROFIT_PARAM_REGEX.finditer(context):
                p_type = p_match.group(1).lower()
                p_name = p_match.group(2)
                if p_type == "query":
                    query_params.append({"name": p_name, "type": "query"})
                elif p_type == "path":
                    path_params.append(p_name)

            ep = {
                "domain": "",
                "path": path_val,
                "method": method,
                "query_params": query_params,
                "path_params": path_params,
                "content_type": "",
                "source_file": source_location,
                "source_class": source_location,
                "source_method": "",
                "discovery_sources": ["retrofit"],
                "confidence": 0.95,
                "evidence": context[:250].strip(),
                "first_seen": now,
                "last_seen": now,
            }
            endpoints.append(normalize_endpoint(ep))

        # Check @HTTP(method="...", path="...")
        for match in _RETROFIT_HTTP_REGEX.finditer(text):
            method = match.group(1).upper()
            path_val = match.group(2).strip()

            if path_val and not path_val.startswith("/"):
                path_val = "/" + path_val
            elif not path_val:
                path_val = "/"

            ep = {
                "domain": "",
                "path": path_val,
                "method": method,
                "query_params": [],
                "path_params": [],
                "content_type": "",
                "source_file": source_location,
                "source_class": source_location,
                "source_method": "",
                "discovery_sources": ["retrofit"],
                "confidence": 0.95,
                "evidence": match.group(0),
                "first_seen": now,
                "last_seen": now,
            }
            endpoints.append(normalize_endpoint(ep))

    return endpoints


def extract_endpoints_from_traffic(
    traffic_requests: Iterable[Dict[str, Any]], source: str = "traffic"
) -> List[Dict[str, Any]]:
    """Extract endpoints from parsed traffic requests (Burp/HAR).

    Args:
        traffic_requests: Collection of traffic request dicts.
        source: Discovery source label.

    Returns:
        List of normalized endpoint dictionaries with definite methods and domains.
    """
    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for req in traffic_requests:
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""
        host = (req.get("host") or "").lower()
        path = req.get("path") or ""

        if not path and url:
            try:
                parsed = urlparse(url)
                path = parsed.path or "/"
                if not host:
                    host = parsed.netloc.split(":")[0].lower()
            except Exception:
                path = "/"

        # Separate query string from path
        raw_path = path.split("?")[0] if "?" in path else path
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path

        # Content-type from request headers
        headers = req.get("headers") or {}
        content_type = ""
        for h_k, h_v in headers.items():
            if h_k.lower() == "content-type":
                content_type = h_v.split(";")[0].strip()
                break

        # Query parameters from request or URL
        query_params = []
        raw_qp = req.get("query_params") or {}
        if isinstance(raw_qp, dict):
            for k, v in raw_qp.items():
                query_params.append({"name": str(k), "sample_value": str(v), "type": "query"})
        elif isinstance(raw_qp, list):
            for item in raw_qp:
                if isinstance(item, dict):
                    query_params.append(item)
                else:
                    query_params.append({"name": str(item), "type": "query"})

        ts = req.get("timestamp") or now
        src_file = req.get("source_file") or source

        ep = {
            "domain": host,
            "path": raw_path,
            "method": method,  # Known exact HTTP method from traffic
            "query_params": query_params,
            "path_params": [],
            "content_type": content_type,
            "source_file": src_file,
            "source_class": "",
            "source_method": "",
            "discovery_sources": [f"traffic:{src_file}"],
            "confidence": 1.0,  # Observed in runtime traffic
            "evidence": f"{method} {url}" if url else f"{method} {host}{raw_path}",
            "first_seen": ts,
            "last_seen": ts,
        }
        endpoints.append(normalize_endpoint(ep))

    return deduplicate_endpoints(endpoints)


def extract_endpoints_from_xrefs(xrefs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build confirmed endpoints from Retrofit annotations read out of DEX files."""
    endpoints: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for xr in xrefs:
        if not xr.get("retrofit"):
            continue
        raw = (xr.get("strings") or [""])[0]
        try:
            parsed = urlparse(raw)
            query = parse_qs(parsed.query, keep_blank_values=True)
        except ValueError:
            continue
        params = xr.get("params", [])
        path = parsed.path if parsed.netloc else "/" + parsed.path.lstrip("/")
        endpoints.append(normalize_endpoint({
            "domain": parsed.netloc.split(":")[0].lower(),
            "path": path or "/",
            "method": xr.get("inferred_http_method") or "",
            "method_confidence": "confirmed",
            "query_params": [{"name": k, "type": "query"} for k in query]
            + [{"name": p["name"], "type": "query"} for p in params if p.get("type") == "query"],
            "path_params": [p["name"] for p in params if p.get("type") == "path"],
            "content_type": "",
            "source_file": xr.get("dex_source", ""),
            "source_class": xr.get("class_name", ""),
            "source_method": xr.get("method_name", ""),
            "discovery_sources": ["retrofit"],
            "confidence": 0.95,
            "evidence": xr.get("inference_evidence", ""),
            "first_seen": now,
            "last_seen": now,
        }))
    return endpoints


def match_xref(ep: Dict[str, Any], xref_strings: List[Tuple[str, Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Find the method whose string constant really is this endpoint.

    A shared hostname alone is not evidence: it would attribute every path on a
    host to whichever class mentions the host first.
    """
    path, dom = ep.get("path", ""), ep.get("domain", "")
    for s, xr in xref_strings:
        bare, _, _ = s.partition("?")
        if path in ("", "/"):
            if dom and bare.rstrip("/").endswith("//" + dom):
                return xr
            continue
        if dom:
            if bare.endswith(path) and f"//{dom}" in bare:
                return xr
        elif bare in (path, path.lstrip("/")):
            return xr
    return None


def deduplicate_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate endpoints based on (domain, normalized_path, method).

    Merges query parameters, discovery sources, and keeps highest confidence.

    Args:
        endpoints: List of endpoint dictionaries.

    Returns:
        Deduplicated list of endpoints.
    """
    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for ep in endpoints:
        domain = ep.get("domain", "").lower()
        norm_path = ep.get("normalized_path") or ep.get("path", "/")
        method = (ep.get("method") or "").upper()
        key = (domain, norm_path, method)

        if key not in merged:
            copy_ep = dict(ep)
            copy_ep["domain"] = domain
            copy_ep["normalized_path"] = norm_path
            copy_ep["method"] = method
            copy_ep["discovery_sources"] = list(ep.get("discovery_sources", []))
            copy_ep["query_params"] = list(ep.get("query_params", []))
            copy_ep["path_params"] = list(ep.get("path_params", []))
            merged[key] = copy_ep
        else:
            existing = merged[key]
            # Merge sources
            for s in ep.get("discovery_sources", []):
                if s not in existing["discovery_sources"]:
                    existing["discovery_sources"].append(s)

            # Merge query params
            existing_qp_names = {
                qp.get("name") if isinstance(qp, dict) else str(qp)
                for qp in existing["query_params"]
            }
            for qp in ep.get("query_params", []):
                name = qp.get("name") if isinstance(qp, dict) else str(qp)
                if name and name not in existing_qp_names:
                    existing["query_params"].append(qp)
                    existing_qp_names.add(name)

            # Merge path params
            for pp in ep.get("path_params", []):
                if pp not in existing["path_params"]:
                    existing["path_params"].append(pp)

            # Keep highest confidence
            existing["confidence"] = max(existing.get("confidence", 0.0), ep.get("confidence", 0.0))

            # Keep content type if not set
            if not existing.get("content_type") and ep.get("content_type"):
                existing["content_type"] = ep["content_type"]

            # Update last_seen
            if ep.get("last_seen"):
                existing["last_seen"] = ep["last_seen"]

    return list(merged.values())


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def export_endpoints_csv(endpoints: List[Dict[str, Any]]) -> str:
    """Export endpoints to CSV format string.

    Headers:
        Domain, Path, Method, Normalized Path, Query Parameters, Path Parameters,
        Content-Type, Discovery Sources, Confidence, Evidence

    Args:
        endpoints: List of endpoint dicts.

    Returns:
        CSV formatted string.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Domain",
        "Path",
        "Method",
        "Normalized Path",
        "Query Parameters",
        "Path Parameters",
        "Content-Type",
        "Discovery Sources",
        "Confidence",
        "Evidence",
    ])

    for ep in endpoints:
        qp_str = ",".join(
            qp.get("name", "") if isinstance(qp, dict) else str(qp)
            for qp in ep.get("query_params", [])
        )
        pp_str = ",".join(ep.get("path_params", []))
        src_str = ",".join(ep.get("discovery_sources", []))

        writer.writerow(safe_row([
            ep.get("domain", ""),
            ep.get("path", ""),
            ep.get("method", ""),
            ep.get("normalized_path", ""),
            qp_str,
            pp_str,
            ep.get("content_type", ""),
            src_str,
            f"{ep.get('confidence', 0.0):.2f}",
            ep.get("evidence", "")[:150],
        ]))

    return output.getvalue()


# ---------------------------------------------------------------------------
# High-Level Orchestrator
# ---------------------------------------------------------------------------

def run_endpoint_extraction(
    session: Optional[Any] = None,
    strings: Optional[List[Any]] = None,
    traffic: Optional[List[Dict[str, Any]]] = None,
    output_dir: Optional[Path] = None,
    filter_noise: Optional[bool] = None,
) -> Dict[str, Any]:
    """Execute endpoint extraction across all available data sources.

    Writes:
        - ``api/endpoints.json``: Full endpoint inventory with metadata.
        - ``api/endpoints.txt``: Clean plaintext list of endpoints (`METHOD /path` or `/path`).
        - ``api/api-inventory.csv``: Comprehensive tabular CSV inventory.

    Args:
        session: Active HUNTX session.
        strings: Optional pre-loaded strings.
        traffic: Optional pre-loaded traffic requests.
        output_dir: Explicit output directory.

    Returns:
        Summary dict containing extracted endpoints and statistics.
    """
    collected: List[Dict[str, Any]] = []

    # 1. Ingest strings
    input_strings: List[Any] = []
    if strings is not None:
        input_strings.extend(strings)
    elif session is not None and hasattr(session, "run_path"):
        str_json = session.run_path / "android" / "strings.json"
        if str_json.exists():
            try:
                with str_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        input_strings.extend(data)
                    elif isinstance(data, dict):
                        for k in ("strings", "all_strings", "raw_strings", "urls", "domains", "api_paths"):
                            if k in data and isinstance(data[k], list):
                                input_strings.extend(data[k])
            except Exception as exc:
                logger.warning("Skipped unreadable data: %s", exc)

    if input_strings:
        collected.extend(extract_endpoints_from_strings(input_strings, default_source="android_strings"))

    # 2. Ingest traffic
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
                logger.warning("Skipped unreadable data: %s", exc)

    if input_traffic:
        collected.extend(extract_endpoints_from_traffic(input_traffic, source="traffic"))

    # 3. Dalvik bytecode XRefs (class, method, HTTP verb)
    xref_list: List[Dict[str, Any]] = []
    if session is not None and hasattr(session, "run_path"):
        xref_json = session.run_path / "android" / "dex-xrefs.json"
        if xref_json.exists():
            try:
                x_data = json.loads(xref_json.read_text(encoding="utf-8"))
                if isinstance(x_data, list):
                    xref_list = x_data
            except (OSError, ValueError) as exc:
                logger.warning("Could not read %s: %s", xref_json, exc)

    collected.extend(extract_endpoints_from_xrefs(xref_list))
    deduped = deduplicate_endpoints(collected)

    # A verb-less string hit is the same route as a Retrofit/traffic entry that knows the verb
    with_verb = {(e["domain"], e["normalized_path"]) for e in deduped if e["method"]}
    deduped = [e for e in deduped if e["method"] or (e["domain"], e["normalized_path"]) not in with_verb]

    xref_strings = [(s, xr) for xr in xref_list for s in xr.get("strings", [])]
    for ep in deduped:
        cur_m = (ep.get("method") or "").strip().upper()
        ep.setdefault("method_confidence", "confirmed" if cur_m and cur_m != "UNKNOWN" else "unknown")

        if xref_strings and (not ep.get("source_class") or ep["method_confidence"] == "unknown"):
            xr = match_xref(ep, xref_strings)
            if xr:
                if not ep.get("source_class"):
                    ep["source_class"] = xr.get("class_name", "")
                    ep["source_method"] = xr.get("method_name", "")
                if ep["method_confidence"] == "unknown" and xr.get("inferred_http_method"):
                    ep["method"] = xr["inferred_http_method"]
                    ep["method_confidence"] = "inferred"
                    ep["inference_evidence"] = xr.get("inference_evidence", "")

        ep["is_sdk_noise"] = is_sdk_noise_endpoint(ep.get("path", ""), ep.get("domain", ""))

    # Sort endpoints: domain, path, method
    deduped.sort(key=lambda x: (x.get("domain", ""), x.get("normalized_path", ""), x.get("method", "")))

    if filter_noise is None:
        try:
            from huntx.core.config import load_config
            filter_noise = load_config().filter_sdk_noise
        except Exception:
            filter_noise = True

    raw_endpoints = list(deduped)
    if filter_noise:
        deduped = [ep for ep in raw_endpoints if not ep.get("is_sdk_noise", False)]

    # Output to disk
    dest_dir = output_dir
    if dest_dir is None and session is not None and hasattr(session, "run_path"):
        dest_dir = session.run_path / "api"

    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)

        # 0. endpoints-raw.json (preserves 100% of raw evidence including SDK noise)
        raw_json_path = dest_dir / "endpoints-raw.json"
        with raw_json_path.open("w", encoding="utf-8") as f:
            json.dump(raw_endpoints, f, indent=2)

        # 1. endpoints.json (filtered if filter_noise=True)
        json_path = dest_dir / "endpoints.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(deduped, f, indent=2)

        # 2. endpoints.txt
        txt_path = dest_dir / "endpoints.txt"
        with txt_path.open("w", encoding="utf-8") as f:
            for ep in deduped:
                m = ep.get("method", "")
                d = ep.get("domain", "")
                p = ep.get("path", "")
                prefix = f"[{m}] " if m else ""
                host_prefix = f"{d}" if d else ""
                f.write(f"{prefix}{host_prefix}{p}\n")

        # 3. api-inventory.csv
        csv_path = dest_dir / "api-inventory.csv"
        csv_content = export_endpoints_csv(deduped)
        with csv_path.open("w", encoding="utf-8") as f:
            f.write(csv_content)

    # Save to DB via Repository if session is active
    if session is not None and hasattr(session, "db_path"):
        try:
            from huntx.storage.repository import Repository
            with Repository(session) as repo:
                for idx, ep in enumerate(deduped, 1):
                    repo.save_endpoint({
                        "ep_id": f"EP-{idx:05d}",
                        "domain": ep.get("domain", ""),
                        "path": ep.get("path", ""),
                        "normalized_path": ep.get("normalized_path", ""),
                        "method": ep.get("method", ""),
                        "parameters": ep.get("query_params", []),
                        "discovery_sources": ep.get("discovery_sources", []),
                        "feature_group": ep.get("feature_group", ""),
                        "confidence": ep.get("confidence", 0.0),
                        "session_id": getattr(session.metadata, "session_id", ""),
                        "first_seen": ep.get("first_seen", ""),
                        "last_seen": ep.get("last_seen", ""),
                    })
        except Exception as exc:
            logger.warning("Skipped unreadable data: %s", exc)

    # Summary breakdown
    methods: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    for ep in deduped:
        m = ep.get("method") or "UNSPECIFIED"
        methods[m] = methods.get(m, 0) + 1
        for s in ep.get("discovery_sources", []):
            base_s = s.split(":")[0]
            sources[base_s] = sources.get(base_s, 0) + 1

    return {
        "total_endpoints": len(deduped),
        "methods_breakdown": methods,
        "sources_breakdown": sources,
        "endpoints": deduped,
    }
