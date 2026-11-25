"""HUNTX Traffic Reconnaissance Engine package.

Exposes Burp Suite XML parsing, HAR JSON parsing, sensitive data redaction,
runtime endpoint extraction, and traffic summarization.
"""
from __future__ import annotations

from huntx.engines.traffic.burp import (
    parse_burp_xml,
    parse_raw_http_request,
    parse_raw_http_response,
)
from huntx.engines.traffic.har import parse_har
from huntx.engines.traffic.parser import (
    SENSITIVE_HEADERS,
    extract_endpoints_from_traffic_entries,
    parse_traffic_file,
    redact_headers,
    redact_parameters,
    redact_traffic_entry,
    run_traffic_analysis,
    summarize_traffic,
)

__all__ = [
    # Burp
    "parse_burp_xml",
    "parse_raw_http_request",
    "parse_raw_http_response",
    # HAR
    "parse_har",
    # Parser & Analyzer
    "SENSITIVE_HEADERS",
    "redact_headers",
    "redact_parameters",
    "redact_traffic_entry",
    "extract_endpoints_from_traffic_entries",
    "summarize_traffic",
    "parse_traffic_file",
    "run_traffic_analysis",
]
