"""HUNTX API Reconnaissance Engine package.

Exposes domain discovery, endpoint extraction, parameter extraction,
path normalization, and OpenAPI integration.
"""
from __future__ import annotations

from huntx.engines.api.domains import (
    categorize_domain,
    clean_domain,
    extract_domains_from_strings,
    extract_domains_from_traffic,
    extract_domains_from_urls,
    is_system_namespace,
    run_domain_discovery,
)
from huntx.engines.api.endpoints import (
    deduplicate_endpoints,
    export_endpoints_csv,
    extract_endpoints_from_retrofit,
    extract_endpoints_from_strings,
    extract_endpoints_from_traffic,
    extract_endpoints_from_urls,
    run_endpoint_extraction,
)
from huntx.engines.api.normalizer import (
    group_by_normalized_path,
    normalize_endpoint,
    normalize_endpoints_list,
    normalize_path,
    normalize_segment,
    run_normalization,
)
from huntx.engines.api.openapi import (
    export_openapi_spec,
    parse_openapi_spec,
    save_openapi_spec,
)
from huntx.engines.api.parameters import (
    deduplicate_parameters,
    extract_parameters_from_endpoints,
    extract_parameters_from_traffic,
    infer_data_type,
    is_sensitive_parameter,
    run_parameter_extraction,
)

__all__ = [
    # Domains
    "clean_domain",
    "is_system_namespace",
    "categorize_domain",
    "extract_domains_from_urls",
    "extract_domains_from_strings",
    "extract_domains_from_traffic",
    "run_domain_discovery",
    # Endpoints
    "extract_endpoints_from_urls",
    "extract_endpoints_from_strings",
    "extract_endpoints_from_retrofit",
    "extract_endpoints_from_traffic",
    "deduplicate_endpoints",
    "export_endpoints_csv",
    "run_endpoint_extraction",
    # Normalizer
    "normalize_segment",
    "normalize_path",
    "normalize_endpoint",
    "normalize_endpoints_list",
    "group_by_normalized_path",
    "run_normalization",
    # Parameters
    "infer_data_type",
    "is_sensitive_parameter",
    "extract_parameters_from_endpoints",
    "extract_parameters_from_traffic",
    "deduplicate_parameters",
    "run_parameter_extraction",
    # OpenAPI
    "parse_openapi_spec",
    "export_openapi_spec",
    "save_openapi_spec",
]
