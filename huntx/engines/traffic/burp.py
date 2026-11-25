"""HUNTX Traffic Engine — Burp Suite XML Export Parser.

Parses Burp Suite XML exports containing captured HTTP requests and responses,
safely decodes base64-encoded payloads, extracts HTTP metadata, and normalizes
into structured traffic entries.

SAFETY: Never replays, executes, or initiates network requests.
"""
from __future__ import annotations

import logging
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP Raw Message Parser
# ---------------------------------------------------------------------------

def parse_raw_http_request(raw_bytes_or_str: Union[bytes, str]) -> Dict[str, Any]:
    """Parse a raw HTTP request message (request line, headers, body).

    Args:
        raw_bytes_or_str: Raw HTTP request bytes or decoded string.

    Returns:
        Dict with method, path, http_version, headers, query_params, and body.
    """
    if isinstance(raw_bytes_or_str, bytes):
        text = raw_bytes_or_str.decode("utf-8", errors="replace")
    else:
        text = str(raw_bytes_or_str or "")

    if not text.strip():
        return {
            "method": "",
            "path": "/",
            "http_version": "",
            "headers": {},
            "query_params": {},
            "body": "",
            "content_type": "",
        }

    # Split header section from body
    if "\r\n\r\n" in text:
        header_section, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        header_section, body = text.split("\n\n", 1)
    else:
        header_section = text
        body = ""

    lines = [ln.rstrip("\r\n") for ln in header_section.splitlines() if ln.strip()]
    if not lines:
        return {
            "method": "",
            "path": "/",
            "http_version": "",
            "headers": {},
            "query_params": {},
            "body": body,
            "content_type": "",
        }

    # Request line: METHOD URI HTTP/X.X
    request_line = lines[0]
    parts = request_line.split()
    method = parts[0].upper() if len(parts) >= 1 else ""
    raw_uri = parts[1] if len(parts) >= 2 else "/"
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    # Separate path and query string
    if "?" in raw_uri:
        path, query_str = raw_uri.split("?", 1)
        try:
            query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_str, keep_blank_values=True).items()}
        except Exception:
            query_params = {}
    else:
        path = raw_uri
        query_params = {}

    headers: Dict[str, str] = {}
    content_type = ""

    for line in lines[1:]:
        if ":" in line:
            h_name, h_val = line.split(":", 1)
            h_key = h_name.strip()
            h_value = h_val.strip()
            headers[h_key] = h_value
            if h_key.lower() == "content-type":
                content_type = h_value.split(";")[0].strip()

    return {
        "method": method,
        "path": path,
        "http_version": http_version,
        "headers": headers,
        "query_params": query_params,
        "body": body,
        "content_type": content_type,
    }


def parse_raw_http_response(raw_bytes_or_str: Union[bytes, str]) -> Dict[str, Any]:
    """Parse a raw HTTP response message (status line, headers, body).

    Args:
        raw_bytes_or_str: Raw HTTP response bytes or decoded string.

    Returns:
        Dict with status_code, status_text, headers, content_type, body.
    """
    if isinstance(raw_bytes_or_str, bytes):
        text = raw_bytes_or_str.decode("utf-8", errors="replace")
    else:
        text = str(raw_bytes_or_str or "")

    if not text.strip():
        return {
            "status_code": None,
            "status_text": "",
            "headers": {},
            "content_type": "",
            "body": "",
        }

    if "\r\n\r\n" in text:
        header_section, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        header_section, body = text.split("\n\n", 1)
    else:
        header_section = text
        body = ""

    lines = [ln.rstrip("\r\n") for ln in header_section.splitlines() if ln.strip()]
    if not lines:
        return {
            "status_code": None,
            "status_text": "",
            "headers": {},
            "content_type": "",
            "body": body,
        }

    status_line = lines[0]
    parts = status_line.split(None, 2)
    status_code = None
    status_text = ""
    if len(parts) >= 2:
        try:
            status_code = int(parts[1])
        except ValueError:
            pass
    if len(parts) >= 3:
        status_text = parts[2]

    headers: Dict[str, str] = {}
    content_type = ""

    for line in lines[1:]:
        if ":" in line:
            h_name, h_val = line.split(":", 1)
            h_key = h_name.strip()
            h_value = h_val.strip()
            headers[h_key] = h_value
            if h_key.lower() == "content-type":
                content_type = h_value.split(";")[0].strip()

    return {
        "status_code": status_code,
        "status_text": status_text,
        "headers": headers,
        "content_type": content_type,
        "body": body,
    }


# ---------------------------------------------------------------------------
# Base64 Helper
# ---------------------------------------------------------------------------

def _decode_element_text(element: Optional[ET.Element]) -> str:
    """Decode text from an XML element, respecting base64 attribute if present."""
    if element is None or element.text is None:
        return ""

    raw_text = element.text.strip()
    is_base64 = element.attrib.get("base64", "").lower() == "true"

    if is_base64:
        try:
            decoded_bytes = base64.b64decode(raw_text)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return raw_text

    return raw_text


# ---------------------------------------------------------------------------
# Burp XML Parser
# ---------------------------------------------------------------------------

def parse_burp_xml(
    xml_input: Union[str, Path, bytes]
) -> List[Dict[str, Any]]:
    """Parse Burp Suite XML export into normalized traffic request records.

    Handles `<items><item>...</item></items>` format with base64 decoding.

    Args:
        xml_input: File path, XML string, or XML bytes.

    Returns:
        List of traffic request dictionaries.
    """
    source_file = "burp_xml"
    if isinstance(xml_input, Path) or (isinstance(xml_input, str) and not xml_input.strip().startswith("<")):
        path = Path(xml_input)
        source_file = path.name
        raw = path.read_bytes()
    else:
        raw = xml_input if isinstance(xml_input, bytes) else xml_input.encode("utf-8")
    if b"<!ENTITY" in raw:  # Burp's DTD declares none; anything else is an attack
        raise ValueError("XML entity declarations are not allowed in Burp exports")
    root = ET.fromstring(raw)


    # Find item elements
    items = root.findall(".//item") if root.tag != "item" else [root]
    results: List[Dict[str, Any]] = []

    now = datetime.now(timezone.utc).isoformat()

    for idx, item in enumerate(items, 1):
        time_elem = item.find("time")
        timestamp = time_elem.text.strip() if time_elem is not None and time_elem.text else now

        url_elem = item.find("url")
        url = url_elem.text.strip() if url_elem is not None and url_elem.text else ""

        host_elem = item.find("host")
        host = host_elem.text.strip().lower() if host_elem is not None and host_elem.text else ""
        host_ip = host_elem.attrib.get("ip", "") if host_elem is not None else ""

        port_elem = item.find("port")
        try:
            port = int(port_elem.text.strip()) if port_elem is not None and port_elem.text else (443 if url.startswith("https") else 80)
        except ValueError:
            port = 443 if url.startswith("https") else 80

        protocol_elem = item.find("protocol")
        protocol = protocol_elem.text.strip().lower() if protocol_elem is not None and protocol_elem.text else ("https" if port == 443 else "http")

        method_elem = item.find("method")
        method = method_elem.text.strip().upper() if method_elem is not None and method_elem.text else ""

        path_elem = item.find("path")
        path = path_elem.text.strip() if path_elem is not None and path_elem.text else ""

        status_elem = item.find("status")
        try:
            status_code = int(status_elem.text.strip()) if status_elem is not None and status_elem.text else None
        except ValueError:
            status_code = None

        mimetype_elem = item.find("mimetype")
        mimetype = mimetype_elem.text.strip() if mimetype_elem is not None and mimetype_elem.text else ""

        # Decode raw request
        req_elem = item.find("request")
        raw_req = _decode_element_text(req_elem)
        parsed_req = parse_raw_http_request(raw_req)

        # Decode raw response
        resp_elem = item.find("response")
        raw_resp = _decode_element_text(resp_elem)
        parsed_resp = parse_raw_http_response(raw_resp)

        # Consolidate method & path
        final_method = method or parsed_req.get("method") or "GET"
        raw_path = path or parsed_req.get("path") or "/"
        clean_path = raw_path.split("?")[0]
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        # If host is empty, parse from URL
        if not host and url:
            try:
                parsed_u = urlparse(url)
                host = parsed_u.netloc.split(":")[0].lower()
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

        # If URL is empty, construct from host & path
        if not url and host:
            scheme = protocol or "https"
            port_str = f":{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else ""
            url = f"{scheme}://{host}{port_str}{raw_path}"

        # Combine query parameters
        query_params = dict(parsed_req.get("query_params") or {})
        if "?" in raw_path:
            try:
                qs = parse_qs(raw_path.split("?", 1)[1], keep_blank_values=True)
                for k, v in qs.items():
                    query_params[k] = v[0] if len(v) == 1 else v
            except Exception as exc:
                logger.debug("Skipped malformed value: %s", exc)

        # Final status
        final_status = status_code if status_code is not None else parsed_resp.get("status_code")

        record: Dict[str, Any] = {
            "traffic_id": f"BURP-{idx:05d}",
            "timestamp": timestamp,
            "method": final_method,
            "url": url,
            "host": host,
            "host_ip": host_ip,
            "port": port,
            "protocol": protocol,
            "path": clean_path,
            "raw_path": raw_path,
            "query_params": query_params,
            "headers": parsed_req.get("headers", {}),
            "body": parsed_req.get("body", ""),
            "content_type": parsed_req.get("content_type") or mimetype,
            "response_status": final_status,
            "response_headers": parsed_resp.get("headers", {}),
            "response_body": parsed_resp.get("body", ""),
            "response_content_type": parsed_resp.get("content_type") or mimetype,
            "source_type": "burp_xml",
            "source_file": source_file,
        }
        results.append(record)

    return results
