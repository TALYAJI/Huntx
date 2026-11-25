"""Tests for HUNTX Phase 4: Traffic Reconnaissance Engine."""
from __future__ import annotations

import base64
import json
from pathlib import Path


from huntx.engines.traffic.burp import (
    parse_burp_xml,
    parse_raw_http_request,
    parse_raw_http_response,
)
from huntx.engines.traffic.har import parse_har
from huntx.engines.traffic.parser import (
    extract_endpoints_from_traffic_entries,
    parse_traffic_file,
    redact_headers,
    redact_parameters,
    redact_traffic_entry,
    run_traffic_analysis,
    summarize_traffic,
)


# ===========================================================================
# 1. Burp Parser Tests
# ===========================================================================

class TestBurpParser:
    def test_parse_raw_http_request(self) -> None:
        raw_req = (
            "POST /api/v1/login?ref=mobile HTTP/1.1\r\n"
            "Host: auth.example.com\r\n"
            "User-Agent: HuntxMobile/1.0\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Authorization: Bearer my-secret-token\r\n"
            "\r\n"
            '{"username": "testuser", "password": "secretpassword"}'
        )
        parsed = parse_raw_http_request(raw_req)
        assert parsed["method"] == "POST"
        assert parsed["path"] == "/api/v1/login"
        assert parsed["query_params"]["ref"] == "mobile"
        assert parsed["headers"]["Host"] == "auth.example.com"
        assert parsed["headers"]["Authorization"] == "Bearer my-secret-token"
        assert parsed["content_type"] == "application/json"
        assert "testuser" in parsed["body"]

    def test_parse_raw_http_response(self) -> None:
        raw_resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Set-Cookie: sessionid=xyz123; HttpOnly; Secure\r\n"
            "\r\n"
            '{"status": "authenticated", "userId": 42}'
        )
        parsed = parse_raw_http_response(raw_resp)
        assert parsed["status_code"] == 200
        assert parsed["status_text"] == "OK"
        assert parsed["content_type"] == "application/json"
        assert "sessionid=xyz123" in parsed["headers"]["Set-Cookie"]
        assert '"userId": 42' in parsed["body"]

    def test_parse_burp_xml_plaintext(self) -> None:
        xml_content = """<?xml version="1.0"?>
        <items burpVersion="2023.1.1" exportTime="Wed Nov 19 12:00:00 UTC 2026">
          <item>
            <time>2026-11-19T10:00:00Z</time>
            <url>https://api.mybank.com/v1/accounts/12345</url>
            <host ip="104.20.1.2">api.mybank.com</host>
            <port>443</port>
            <protocol>https</protocol>
            <method>GET</method>
            <path>/v1/accounts/12345</path>
            <status>200</status>
            <mimetype>JSON</mimetype>
            <request base64="false">GET /v1/accounts/12345 HTTP/1.1&#xD;&#xA;Host: api.mybank.com&#xD;&#xA;&#xD;&#xA;</request>
            <response base64="false">HTTP/1.1 200 OK&#xD;&#xA;Content-Type: application/json&#xD;&#xA;&#xD;&#xA;{"balance": 1000}</response>
          </item>
        </items>
        """
        records = parse_burp_xml(xml_content)
        assert len(records) == 1
        item = records[0]
        assert item["method"] == "GET"
        assert item["host"] == "api.mybank.com"
        assert item["host_ip"] == "104.20.1.2"
        assert item["port"] == 443
        assert item["path"] == "/v1/accounts/12345"
        assert item["response_status"] == 200
        assert item["source_type"] == "burp_xml"

    def test_parse_burp_xml_base64_encoded(self) -> None:
        req_raw = b"POST /oauth/token HTTP/1.1\r\nHost: auth.corp.com\r\n\r\ngrant_type=client_credentials"
        resp_raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"access_token\": \"abc\"}"

        req_b64 = base64.b64encode(req_raw).decode("ascii")
        resp_b64 = base64.b64encode(resp_raw).decode("ascii")

        xml_content = f"""<?xml version="1.0"?>
        <items>
          <item>
            <time>2026-11-19T10:05:00Z</time>
            <url>https://auth.corp.com/oauth/token</url>
            <host>auth.corp.com</host>
            <port>443</port>
            <protocol>https</protocol>
            <method>POST</method>
            <path>/oauth/token</path>
            <status>200</status>
            <request base64="true">{req_b64}</request>
            <response base64="true">{resp_b64}</response>
          </item>
        </items>
        """
        records = parse_burp_xml(xml_content)
        assert len(records) == 1
        item = records[0]
        assert item["method"] == "POST"
        assert item["host"] == "auth.corp.com"
        assert item["body"] == "grant_type=client_credentials"
        assert '"access_token": "abc"' in item["response_body"]


# ===========================================================================
# 2. HAR Parser Tests
# ===========================================================================

class TestHARParser:
    def test_parse_har_json(self) -> None:
        har_dict = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Huntx Proxy", "version": "1.0"},
                "entries": [
                    {
                        "startedDateTime": "2026-11-19T11:00:00.000Z",
                        "time": 45,
                        "serverIPAddress": "198.51.100.1",
                        "request": {
                            "method": "GET",
                            "url": "https://api.shop.com/products/42?currency=USD",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Host", "value": "api.shop.com"},
                                {"name": "User-Agent", "value": "MobileApp/2.0"},
                                {"name": "Authorization", "value": "Bearer user-token-999"},
                            ],
                            "queryString": [
                                {"name": "currency", "value": "USD"}
                            ],
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json; charset=utf-8"},
                            ],
                            "content": {
                                "size": 34,
                                "mimeType": "application/json",
                                "text": '{"id": 42, "name": "Test Gadget"}',
                            }
                        }
                    }
                ]
            }
        }
        records = parse_har(har_dict)
        assert len(records) == 1
        item = records[0]
        assert item["method"] == "GET"
        assert item["url"] == "https://api.shop.com/products/42?currency=USD"
        assert item["host"] == "api.shop.com"
        assert item["path"] == "/products/42"
        assert item["host_ip"] == "198.51.100.1"
        assert item["query_params"]["currency"] == "USD"
        assert item["headers"]["Authorization"] == "Bearer user-token-999"
        assert item["response_status"] == 200
        assert "Test Gadget" in item["response_body"]
        assert item["source_type"] == "har_json"

    def test_parse_har_base64_response(self) -> None:
        resp_text = "Compressed or encoded binary data"
        resp_b64 = base64.b64encode(resp_text.encode("utf-8")).decode("ascii")

        har_dict = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.test.com/data.bin",
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "text": resp_b64,
                                "encoding": "base64",
                                "mimeType": "application/octet-stream",
                            }
                        }
                    }
                ]
            }
        }
        records = parse_har(har_dict)
        assert len(records) == 1
        assert records[0]["response_body"] == resp_text


# ===========================================================================
# 3. Parser, Redaction & Summary Tests
# ===========================================================================

class TestTrafficParserAndRedaction:
    def test_redact_headers(self) -> None:
        headers = {
            "Host": "api.example.com",
            "Authorization": "Bearer eyJhbGciOi...",
            "Cookie": "session_id=s3cr3t; auth=true",
            "X-Api-Key": "live_abcdef123456",
            "User-Agent": "Dalvik/2.1.0",
        }
        redacted = redact_headers(headers)
        assert redacted["Host"] == "api.example.com"
        assert redacted["Authorization"] == "Bearer [REDACTED]"
        assert redacted["Cookie"] == "[REDACTED]"
        assert redacted["X-Api-Key"] == "[REDACTED]"
        assert redacted["User-Agent"] == "Dalvik/2.1.0"

    def test_redact_parameters(self) -> None:
        params = {
            "page": "1",
            "password": "MySuperPassword123!",
            "client_secret": "secret999",
            "sort": "desc",
        }
        redacted = redact_parameters(params)
        assert redacted["page"] == "1"
        assert redacted["sort"] == "desc"
        assert redacted["password"] == "[REDACTED]"
        assert redacted["client_secret"] == "[REDACTED]"

    def test_redact_traffic_entry(self) -> None:
        entry = {
            "method": "POST",
            "url": "https://api.target.com/login",
            "headers": {"Authorization": "Bearer 12345", "Host": "api.target.com"},
            "response_headers": {"Set-Cookie": "auth_token=abc"},
            "query_params": {"api_key": "privatekey", "debug": "false"},
        }
        safe_entry = redact_traffic_entry(entry)
        assert safe_entry["headers"]["Authorization"] == "Bearer [REDACTED]"
        assert safe_entry["response_headers"]["Set-Cookie"] == "[REDACTED]"
        assert safe_entry["query_params"]["api_key"] == "[REDACTED]"
        assert safe_entry["query_params"]["debug"] == "false"

    def test_extract_endpoints_from_traffic_entries(self) -> None:
        entries = [
            {
                "method": "GET",
                "host": "api.mybank.com",
                "path": "/api/v1/users/1",
                "response_status": 200,
                "content_type": "application/json",
                "source_file": "burp.xml",
            },
            {
                "method": "GET",
                "host": "api.mybank.com",
                "path": "/api/v1/users/2",
                "response_status": 200,
                "content_type": "application/json",
                "source_file": "burp.xml",
            },
            {
                "method": "POST",
                "host": "api.mybank.com",
                "path": "/api/v1/users",
                "response_status": 201,
                "content_type": "application/json",
                "source_file": "har.json",
            },
        ]
        endpoints = extract_endpoints_from_traffic_entries(entries)
        assert len(endpoints) == 2

        get_user = next(ep for ep in endpoints if ep["method"] == "GET")
        assert get_user["normalized_path"] == "/api/v1/users/{id}"
        assert get_user["request_count"] == 2
        assert get_user["status_codes"] == [200]
        assert get_user["confidence"] == 1.0

        post_user = next(ep for ep in endpoints if ep["method"] == "POST")
        assert post_user["normalized_path"] == "/api/v1/users"
        assert post_user["status_codes"] == [201]

    def test_summarize_traffic(self) -> None:
        entries = [
            {"host": "api.a.com", "method": "GET", "response_status": 200, "content_type": "application/json", "headers": {"Authorization": "x"}},
            {"host": "api.a.com", "method": "GET", "response_status": 404, "content_type": "application/json", "headers": {}},
            {"host": "api.b.com", "method": "POST", "response_status": 500, "content_type": "text/html", "headers": {"Cookie": "y"}},
        ]
        summary = summarize_traffic(entries)
        assert summary["total_requests"] == 3
        assert summary["unique_hosts_count"] == 2
        assert summary["methods_distribution"]["GET"] == 2
        assert summary["methods_distribution"]["POST"] == 1
        assert summary["status_codes_distribution"]["200"] == 1
        assert summary["status_codes_distribution"]["404"] == 1
        assert summary["status_codes_distribution"]["500"] == 1
        assert summary["requests_with_sensitive_headers"] == 2

    def test_parse_traffic_file_auto_detect(self, tmp_path: Path) -> None:
        # Create sample Burp file
        burp_file = tmp_path / "burp_export.xml"
        burp_file.write_text("""<?xml version="1.0"?>
        <items>
          <item>
            <url>https://api.test.com/v1/ping</url>
            <host>api.test.com</host>
            <method>GET</method>
            <path>/v1/ping</path>
            <status>200</status>
          </item>
        </items>
        """, encoding="utf-8")

        # Create sample HAR file
        har_file = tmp_path / "browser_export.har"
        har_file.write_text(json.dumps({
            "log": {
                "entries": [
                    {
                        "request": {"method": "POST", "url": "https://api.test.com/v1/data"},
                        "response": {"status": 200}
                    }
                ]
            }
        }), encoding="utf-8")

        burp_records = parse_traffic_file(burp_file)
        assert len(burp_records) == 1
        assert burp_records[0]["path"] == "/v1/ping"

        har_records = parse_traffic_file(har_file)
        assert len(har_records) == 1
        assert har_records[0]["path"] == "/v1/data"

    def test_run_traffic_analysis_outputs(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "traffic"
        burp_file = tmp_path / "sample.xml"
        burp_file.write_text("""<?xml version="1.0"?>
        <items>
          <item>
            <url>https://api.example.com/v1/status</url>
            <host>api.example.com</host>
            <method>GET</method>
            <path>/v1/status</path>
            <status>200</status>
            <request base64="false">GET /v1/status HTTP/1.1&#xD;&#xA;Host: api.example.com&#xD;&#xA;Authorization: Bearer secret&#xD;&#xA;&#xD;&#xA;</request>
            <response base64="false">HTTP/1.1 200 OK&#xD;&#xA;&#xD;&#xA;</response>
          </item>
        </items>
        """, encoding="utf-8")

        res = run_traffic_analysis(source_files=[burp_file], output_dir=out_dir)
        assert res["total_requests"] == 1
        assert res["total_endpoints"] == 1

        # Check output files exist
        assert (out_dir / "requests.json").exists()
        assert (out_dir / "endpoints.json").exists()
        assert (out_dir / "traffic-summary.json").exists()

        # Check sensitive headers are redacted in requests.json
        with (out_dir / "requests.json").open() as f:
            saved_reqs = json.load(f)
            assert saved_reqs[0]["headers"]["Authorization"] == "Bearer [REDACTED]"
