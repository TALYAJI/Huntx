"""Tests for HUNTX Phase 3: API Reconnaissance Engine."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path


from huntx.engines.api.domains import (
    categorize_domain,
    clean_domain,
    extract_domains_from_strings,
    extract_domains_from_urls,
    is_system_namespace,
    run_domain_discovery,
)
from huntx.engines.api.endpoints import (
    export_endpoints_csv,
    extract_endpoints_from_retrofit,
    extract_endpoints_from_strings,
    extract_endpoints_from_urls,
    run_endpoint_extraction,
)
from huntx.engines.api.normalizer import (
    group_by_normalized_path,
    normalize_endpoint,
    normalize_path,
    normalize_segment,
)
from huntx.engines.api.openapi import (
    export_openapi_spec,
    parse_openapi_spec,
    save_openapi_spec,
)
from huntx.engines.api.parameters import (
    extract_parameters_from_endpoints,
    extract_parameters_from_traffic,
    infer_data_type,
    is_sensitive_parameter,
    run_parameter_extraction,
)


# ===========================================================================
# 1. Domain Discovery Tests
# ===========================================================================

class TestDomains:
    def test_clean_domain_basic(self) -> None:
        assert clean_domain("https://api.example.com/v1/users") == "api.example.com"
        assert clean_domain("http://user:pass@staging.corp.internal:8080/path") == "staging.corp.internal"
        assert clean_domain("  'SUB.TARGET.COM:443'  ") == "sub.target.com"
        assert clean_domain("192.168.1.100:8443") == "192.168.1.100"

    def test_clean_domain_rejections(self) -> None:
        # Rejects Java packages / Android permissions / file extensions
        assert clean_domain("android.permission.INTERNET") == ""
        assert clean_domain("androidx.appcompat.app.AppCompatActivity") == ""
        assert clean_domain("com.example.app.R$id") == ""
        assert clean_domain("image_logo.png") == ""
        assert clean_domain("AndroidManifest.xml") == ""

    def test_is_system_namespace(self) -> None:
        assert is_system_namespace("schemas.android.com") is True
        assert is_system_namespace("http://schemas.android.com/apk/res/android") is True
        assert is_system_namespace("www.w3.org") is True
        assert is_system_namespace("xmlpull.org") is True
        assert is_system_namespace("schemas.xmlsoap.org") is True
        assert is_system_namespace("api.target-app.com") is False

    def test_categorize_domain(self) -> None:
        assert categorize_domain("schemas.android.com") == "system"
        assert categorize_domain("play.google.com") == "google_service"
        assert categorize_domain("crashlytics.com") == "analytics_tracking"
        assert categorize_domain("app-measurement.com") == "analytics_tracking"
        assert categorize_domain("s3.amazonaws.com") == "cloud_cdn"
        assert categorize_domain("localhost") == "local_test"
        assert categorize_domain("127.0.0.1") == "local_test"
        assert categorize_domain("api.mybankingapp.com") == "target"

    def test_extract_domains_from_urls(self) -> None:
        urls = [
            "https://api.huntx.io/v1/login",
            "https://api.huntx.io/v1/logout",
            "http://schemas.android.com/apk/res/android",
            "https://crashlytics.com/api/v2",
        ]
        results = extract_domains_from_urls(urls, source="test_urls")
        domain_names = {r["domain"] for r in results}
        assert "api.huntx.io" in domain_names
        assert "schemas.android.com" in domain_names
        assert "crashlytics.com" in domain_names

        # Check fields
        target_rec = next(r for r in results if r["domain"] == "api.huntx.io")
        assert target_rec["category"] == "target"
        assert target_rec["is_system"] is False
        assert "test_urls" in target_rec["sources"]

        sys_rec = next(r for r in results if r["domain"] == "schemas.android.com")
        assert sys_rec["is_system"] is True
        assert sys_rec["category"] == "system"

    def test_extract_domains_from_strings(self) -> None:
        strings = [
            "Connecting to https://backend.corp.net/api...",
            {"value": "Server host is auth.identity.org:443", "source_location": "Config.smali"},
            "android.permission.CAMERA",  # should be ignored
            "Found IP 10.0.2.15 in resources",
        ]
        results = extract_domains_from_strings(strings)
        domains = {r["domain"] for r in results}
        assert "backend.corp.net" in domains
        assert "auth.identity.org" in domains
        assert "10.0.2.15" in domains
        assert "android.permission.CAMERA" not in domains

    def test_run_domain_discovery_outputs(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "api"
        strings = [
            "https://api.target.com/v1",
            "https://schemas.android.com/apk/res-auto",
            "https://telemetry.analytics.io/events",
        ]
        res = run_domain_discovery(strings=strings, output_dir=out_dir)

        assert res["total_domains"] == 3
        assert (out_dir / "domains.json").exists()
        assert (out_dir / "domains.txt").exists()

        with (out_dir / "domains.txt").open() as f:
            lines = [l.strip() for l in f]
            assert "api.target.com" in lines
            assert "schemas.android.com" in lines


# ===========================================================================
# 2. Path Normalizer Tests
# ===========================================================================

class TestNormalizer:
    def test_normalize_segment_types(self) -> None:
        # Numeric ID
        norm, rule = normalize_segment("12345", 0)
        assert norm == "{id}"
        assert rule is not None and rule["rule"] == "numeric_id"

        # UUID
        norm, rule = normalize_segment("550e8400-e29b-41d4-a716-446655440000", 1)
        assert norm == "{uuid}"
        assert rule is not None and rule["rule"] == "uuid"

        # Hex Hash (SHA-256)
        norm, rule = normalize_segment("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 2)
        assert norm == "{hash}"
        assert rule is not None and rule["rule"] == "hex_hash"

        # Date
        norm, rule = normalize_segment("2026-11-19", 1)
        assert norm == "{date}"
        assert rule is not None and rule["rule"] == "date"

        # Timestamp
        norm, rule = normalize_segment("1700481234", 1)
        assert norm == "{timestamp}"
        assert rule is not None and rule["rule"] == "timestamp"

        # API Version - MUST NOT BE NORMALIZED
        norm, rule = normalize_segment("v1", 0)
        assert norm == "v1"
        assert rule is None
        norm, rule = normalize_segment("v2", 0)
        assert norm == "v2"
        assert rule is None

        # Colon param
        norm, rule = normalize_segment(":userId", 1)
        assert norm == "{userId}"
        assert rule is not None and rule["rule"] == "colon_param"

    def test_normalize_path_full(self) -> None:
        path = "/api/v1/users/42/orders/550e8400-e29b-41d4-a716-446655440000/details"
        norm_path, rules = normalize_path(path)
        assert norm_path == "/api/v1/users/{id}/orders/{uuid}/details"
        assert len(rules) == 2
        assert rules[0]["rule"] == "numeric_id"
        assert rules[1]["rule"] == "uuid"

    def test_normalize_endpoint_preserves_method_and_query(self) -> None:
        ep = {
            "path": "/api/v2/items/999?sort=asc",
            "method": "POST",
            "domain": "api.example.com",
            "query_params": [{"name": "sort", "sample_value": "asc"}],
        }
        res = normalize_endpoint(ep)
        assert res["original_path"] == "/api/v2/items/999?sort=asc"
        assert res["normalized_path"] == "/api/v2/items/{id}"
        assert res["method"] == "POST"
        assert "id" in res["path_params"]
        assert len(res["normalization_rules"]) == 1

    def test_group_by_normalized_path(self) -> None:
        endpoints = [
            {"path": "/api/v1/users/1", "method": "GET", "domain": "api.com", "query_params": ["page"]},
            {"path": "/api/v1/users/2", "method": "GET", "domain": "api.com", "query_params": ["limit"]},
            {"path": "/api/v1/users/3", "method": "GET", "domain": "api.com", "query_params": ["page", "limit"]},
        ]
        groups = group_by_normalized_path(endpoints)
        assert len(groups) == 1
        key = list(groups.keys())[0]
        assert "GET api.com/api/v1/users/{id}" in key
        group = groups[key]
        assert group["count"] == 3
        assert set(group["query_param_variations"]) == {"page", "limit"}


# ===========================================================================
# 3. Endpoint Extraction Tests
# ===========================================================================

class TestEndpoints:
    def test_extract_endpoints_from_urls(self) -> None:
        urls = [
            "https://api.target.com/api/v1/accounts?status=active",
            "https://api.target.com/api/v1/accounts/123",
            "https://cdn.target.com/assets/logo.png",  # static asset ignored
        ]
        results = extract_endpoints_from_urls(urls)
        assert len(results) == 2
        paths = {r["normalized_path"] for r in results}
        assert "/api/v1/accounts" in paths
        assert "/api/v1/accounts/{id}" in paths
        # Method must remain empty (do NOT invent method for bare URLs)
        assert results[0]["method"] == ""

    def test_extract_endpoints_from_strings_relative(self) -> None:
        strings = [
            'String endpoint = "/api/v2/auth/login";',
            'String graph = "/graphql";',
            'String rest = "/rest/services/catalog/456";',
        ]
        results = extract_endpoints_from_strings(strings)
        paths = {r["normalized_path"] for r in results}
        assert "/api/v2/auth/login" in paths
        assert "/graphql" in paths
        assert "/rest/services/catalog/{id}" in paths

    def test_extract_endpoints_from_retrofit(self) -> None:
        code = """
        public interface ApiService {
            @GET("users/{id}")
            Call<User> getUser(@Path("id") int userId, @Query("fields") String fields);

            @POST("/api/v1/auth/token")
            Call<TokenResponse> login(@Body LoginRequest req);

            @DELETE("items/{uuid}/delete")
            Call<Void> deleteItem(@Path("uuid") String uuid);
        }
        """
        results = extract_endpoints_from_retrofit(code, source_location="ApiService.java")
        assert len(results) == 3

        get_ep = next(r for r in results if r["method"] == "GET")
        assert get_ep["path"] == "/users/{id}"
        assert "users/{id}" in get_ep["normalized_path"]
        assert get_ep["confidence"] >= 0.9
        assert "id" in get_ep["path_params"]
        assert any(qp["name"] == "fields" for qp in get_ep["query_params"])

        post_ep = next(r for r in results if r["method"] == "POST")
        assert post_ep["path"] == "/api/v1/auth/token"

        del_ep = next(r for r in results if r["method"] == "DELETE")
        assert del_ep["method"] == "DELETE"

    def test_export_endpoints_csv(self) -> None:
        endpoints = [
            {
                "domain": "api.example.com",
                "path": "/api/v1/users/42",
                "normalized_path": "/api/v1/users/{id}",
                "method": "GET",
                "query_params": [{"name": "filter"}],
                "path_params": ["id"],
                "content_type": "application/json",
                "discovery_sources": ["retrofit"],
                "confidence": 0.95,
                "evidence": '@GET("users/{id}")',
            }
        ]
        csv_text = export_endpoints_csv(endpoints)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["Domain"] == "api.example.com"
        assert rows[0]["Method"] == "GET"
        assert rows[0]["Normalized Path"] == "/api/v1/users/{id}"
        assert rows[0]["Query Parameters"] == "filter"

    def test_run_endpoint_extraction_outputs(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "api"
        strings = [
            'String url = "https://api.test.com/v1/checkout";',
            '@POST("api/v1/orders")\nCall<Order> placeOrder();',
        ]
        res = run_endpoint_extraction(strings=strings, output_dir=out_dir)
        assert res["total_endpoints"] >= 2
        assert (out_dir / "endpoints.json").exists()
        assert (out_dir / "endpoints.txt").exists()
        assert (out_dir / "api-inventory.csv").exists()


# ===========================================================================
# 4. Parameter Extraction Tests
# ===========================================================================

class TestParameters:
    def test_infer_data_type(self) -> None:
        assert infer_data_type("123") == "integer"
        assert infer_data_type("99.9") == "float"
        assert infer_data_type("true") == "boolean"
        assert infer_data_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"
        assert infer_data_type("2026-11-19") == "date"
        assert infer_data_type("hello_world") == "string"
        assert infer_data_type({"k": "v"}) == "object"
        assert infer_data_type([1, 2, 3]) == "array"

    def test_is_sensitive_parameter(self) -> None:
        assert is_sensitive_parameter("password") is True
        assert is_sensitive_parameter("user_password") is True
        assert is_sensitive_parameter("access_token") is True
        assert is_sensitive_parameter("api_key") is True
        assert is_sensitive_parameter("Authorization") is True
        assert is_sensitive_parameter("page_number") is False
        assert is_sensitive_parameter("category") is False

    def test_extract_parameters_from_endpoints(self) -> None:
        endpoints = [
            {
                "path": "/api/v1/users/{user_id}/posts",
                "normalized_path": "/api/v1/users/{user_id}/posts",
                "method": "GET",
                "domain": "api.test.com",
                "path_params": ["user_id"],
                "query_params": [{"name": "limit", "sample_value": "20"}, {"name": "token", "sample_value": "secret123"}],
                "discovery_sources": ["retrofit"],
            }
        ]
        params = extract_parameters_from_endpoints(endpoints)
        assert len(params) == 3

        user_id_param = next(p for p in params if p["name"] == "user_id")
        assert user_id_param["param_type"] == "path"

        limit_param = next(p for p in params if p["name"] == "limit")
        assert limit_param["param_type"] == "query"
        assert limit_param["data_type"] == "integer"
        assert limit_param["is_sensitive"] is False

        token_param = next(p for p in params if p["name"] == "token")
        assert token_param["is_sensitive"] is True
        assert token_param["sample_value"] == "[REDACTED]"

    def test_extract_parameters_from_traffic(self) -> None:
        traffic = [
            {
                "method": "POST",
                "path": "/api/v1/login",
                "host": "auth.target.com",
                "query_params": {"ref": "app"},
                "headers": {"Authorization": "Bearer xxx", "X-Custom-Client": "v1.0"},
                "body": json.dumps({"username": "alice", "password": "SuperSecret123!"}),
                "source_file": "capture.xml",
            }
        ]
        params = extract_parameters_from_traffic(traffic)
        param_names = {p["name"]: p for p in params}

        assert "ref" in param_names
        assert param_names["ref"]["param_type"] == "query"

        assert "Authorization" in param_names
        assert param_names["Authorization"]["param_type"] == "header"
        assert param_names["Authorization"]["is_sensitive"] is True

        assert "username" in param_names
        assert param_names["username"]["param_type"] == "body"

        assert "password" in param_names
        assert param_names["password"]["param_type"] == "body"
        assert param_names["password"]["is_sensitive"] is True
        assert param_names["password"]["sample_value"] == "[REDACTED]"

    def test_run_parameter_extraction_outputs(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "api"
        endpoints = [
            {"path": "/api/v1/search", "query_params": [{"name": "q"}]}
        ]
        res = run_parameter_extraction(endpoints=endpoints, output_dir=out_dir)
        assert res["total_parameters"] >= 1
        assert (out_dir / "parameters.json").exists()


# ===========================================================================
# 5. OpenAPI Ingest & Export Tests
# ===========================================================================

class TestOpenAPI:
    def test_parse_openapi_3_spec(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.sample.com/v1"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUserById",
                        "summary": "Fetch single user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True},
                            {"name": "fields", "in": "query", "required": False},
                        ],
                    },
                    "delete": {
                        "operationId": "deleteUser",
                    }
                }
            }
        }
        endpoints = parse_openapi_spec(spec)
        assert len(endpoints) == 2

        get_ep = next(e for e in endpoints if e["method"] == "GET")
        assert get_ep["domain"] == "api.sample.com"
        assert get_ep["path"] == "/v1/users/{id}"
        assert "id" in get_ep["path_params"]
        assert any(qp["name"] == "fields" for qp in get_ep["query_params"])
        assert get_ep["confidence"] == 1.0

    def test_export_openapi_spec(self) -> None:
        endpoints = [
            {
                "domain": "api.huntx.io",
                "path": "/api/v1/orders/{order_id}",
                "normalized_path": "/api/v1/orders/{order_id}",
                "method": "GET",
                "query_params": [{"name": "status", "sample_value": "pending"}],
                "path_params": ["order_id"],
                "content_type": "application/json",
                "discovery_sources": ["retrofit", "traffic"],
                "confidence": 0.95,
                "evidence": "GET /api/v1/orders/123",
            }
        ]
        spec = export_openapi_spec(endpoints, title="HUNTX Test API")
        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "HUNTX Test API"
        assert "https://api.huntx.io" in [s["url"] for s in spec["servers"]]
        assert "/api/v1/orders/{order_id}" in spec["paths"]

        path_item = spec["paths"]["/api/v1/orders/{order_id}"]
        assert "get" in path_item
        op = path_item["get"]
        assert op["x-huntx-confidence"] == 0.95
        assert "retrofit" in op["x-huntx-sources"]
        assert len(op["parameters"]) == 2

    def test_save_openapi_spec(self, tmp_path: Path) -> None:
        spec = {"openapi": "3.0.3", "info": {"title": "T", "version": "1.0"}, "paths": {}}
        out_file = tmp_path / "api" / "openapi.json"
        saved = save_openapi_spec(spec, out_file)
        assert saved.exists()
        with saved.open() as f:
            data = json.load(f)
            assert data["openapi"] == "3.0.3"
