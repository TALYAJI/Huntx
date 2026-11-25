"""HUNTX Traffic Engine — HAR (HTTP Archive) JSON Parser.

Parses standard HAR 1.2 JSON files containing browser or proxy traffic logs,
safely decodes base64 content payloads, and normalizes into structured
traffic entries.

SAFETY: Never replays, executes, or initiates network requests.
"""
from __future__ import annotations

import logging
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HAR Parser
# ---------------------------------------------------------------------------

def parse_har(
    har_input: Union[Dict[str, Any], str, Path]
) -> List[Dict[str, Any]]:
    """Parse a HAR (HTTP Archive) document into normalized traffic records.

    Args:
        har_input: Parsed HAR dict, JSON string, or Path to HAR file.

    Returns:
        List of normalized traffic request dictionaries.
    """
    har_data: Optional[Dict[str, Any]] = None
    source_file = "har_log"

    if isinstance(har_input, dict):
        har_data = har_input
    elif isinstance(har_input, Path) or (isinstance(har_input, str) and not har_input.strip().startswith("{")):
        path = Path(har_input)
        if path.exists() and path.is_file():
            source_file = path.name
            with path.open("r", encoding="utf-8", errors="replace") as f:
                har_data = json.load(f)
        else:
            try:
                har_data = json.loads(str(har_input))
            except Exception:
                return []
    else:
        try:
            har_data = json.loads(str(har_input))
        except Exception:
            return []

    if not har_data or not isinstance(har_data, dict):
        return []

    log_obj = har_data.get("log") or har_data
    entries = log_obj.get("entries") or []
    if not isinstance(entries, list):
        return []

    results: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for idx, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            continue

        started_dt = entry.get("startedDateTime") or now
        server_ip = entry.get("serverIPAddress", "")

        # Request
        req_obj = entry.get("request") or {}
        method = (req_obj.get("method") or "GET").upper()
        url = req_obj.get("url") or ""

        # Parse host, port, protocol, path from URL
        host = ""
        port = 443 if url.startswith("https") else 80
        protocol = "https" if url.startswith("https") else "http"
        clean_path = "/"
        raw_path = "/"

        if url:
            try:
                parsed_u = urlparse(url)
                host = parsed_u.netloc.split(":")[0].lower()
                if ":" in parsed_u.netloc:
                    try:
                        port = int(parsed_u.netloc.split(":")[1])
                    except ValueError:
                        pass
                protocol = parsed_u.scheme or protocol
                clean_path = parsed_u.path or "/"
                raw_path = f"{clean_path}?{parsed_u.query}" if parsed_u.query else clean_path
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

        # Request Headers
        headers: Dict[str, str] = {}
        for h in req_obj.get("headers") or []:
            if isinstance(h, dict) and "name" in h:
                headers[h["name"]] = str(h.get("value", ""))

        content_type = ""
        for h_k, h_v in headers.items():
            if h_k.lower() == "content-type":
                content_type = h_v.split(";")[0].strip()
                break

        # Query Parameters
        query_params: Dict[str, Any] = {}
        for qp in req_obj.get("queryString") or []:
            if isinstance(qp, dict) and "name" in qp:
                query_params[qp["name"]] = qp.get("value", "")

        # Also parse query from raw_path if queryString was empty
        if not query_params and "?" in raw_path:
            try:
                qs = parse_qs(raw_path.split("?", 1)[1], keep_blank_values=True)
                for k, v in qs.items():
                    query_params[k] = v[0] if len(v) == 1 else v
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

        # Request Body
        body = ""
        post_data = req_obj.get("postData") or {}
        if isinstance(post_data, dict):
            body = post_data.get("text", "")
            if not content_type and post_data.get("mimeType"):
                content_type = post_data["mimeType"].split(";")[0].strip()

        # Response
        resp_obj = entry.get("response") or {}
        status_code = resp_obj.get("status")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except ValueError:
                status_code = None

        resp_headers: Dict[str, str] = {}
        for h in resp_obj.get("headers") or []:
            if isinstance(h, dict) and "name" in h:
                resp_headers[h["name"]] = str(h.get("value", ""))

        resp_content_type = ""
        for h_k, h_v in resp_headers.items():
            if h_k.lower() == "content-type":
                resp_content_type = h_v.split(";")[0].strip()
                break

        # Response Body
        resp_content = resp_obj.get("content") or {}
        resp_body = ""
        if isinstance(resp_content, dict):
            raw_resp_text = resp_content.get("text", "")
            is_base64 = resp_content.get("encoding", "").lower() == "base64"
            if is_base64 and raw_resp_text:
                try:
                    decoded = base64.b64decode(raw_resp_text)
                    resp_body = decoded.decode("utf-8", errors="replace")
                except Exception:
                    resp_body = raw_resp_text
            else:
                resp_body = raw_resp_text

            if not resp_content_type and resp_content.get("mimeType"):
                resp_content_type = resp_content["mimeType"].split(";")[0].strip()

        record: Dict[str, Any] = {
            "traffic_id": f"HAR-{idx:05d}",
            "timestamp": started_dt,
            "method": method,
            "url": url,
            "host": host,
            "host_ip": server_ip,
            "port": port,
            "protocol": protocol,
            "path": clean_path,
            "raw_path": raw_path,
            "query_params": query_params,
            "headers": headers,
            "body": body,
            "content_type": content_type,
            "response_status": status_code,
            "response_headers": resp_headers,
            "response_body": resp_body,
            "response_content_type": resp_content_type,
            "source_type": "har_json",
            "source_file": source_file,
        }
        results.append(record)

    return results
