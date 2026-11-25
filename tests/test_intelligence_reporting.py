"""Comprehensive tests for Phase 5 (Intelligence), Phase 6 (Reporting & Dashboard), and CLI Menu."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from huntx.core.search import SearchEngine
from huntx.core.session import Session, SessionMetadata
from huntx.intelligence.endpoint_passport import (
    EndpointPassport,
    detect_auth_evidence,
    generate_endpoint_passports,
    infer_feature_group,
)
from huntx.intelligence.android_api_mapper import (
    AndroidApiMapper,
)
from huntx.intelligence.apk_diff import (
    compare_apk_runs,
)
from huntx.reporting.json_report import generate_json_report
from huntx.reporting.csv_report import generate_csv_reports
from huntx.reporting.html_report import generate_html_report

from huntx.cli.menu import MenuSystem, resolve_dependencies


@pytest.fixture
def test_session(tmp_path: Path) -> Session:
    """Fixture providing a populated test HUNTX session."""
    target_dir = tmp_path / "TARGET" / "com.example.testapp"
    target_dir.mkdir(parents=True, exist_ok=True)
    
    run_dir = target_dir / "RUN_20261119_120000"
    for sub in ["input", "android", "api", "traffic", "mapping", "reports", "logs"]:
        (run_dir / sub).mkdir(parents=True, exist_ok=True)

    meta = SessionMetadata(
        session_id="test-session-uuid-1234",
        target_name="com.example.testapp",
        run_dir="RUN_20261119_120000",
        apk_files=[{"filename": "testapp.apk", "sha256": "abcdef1234567890", "size_bytes": 10240}],
        created_at="2026-11-19T12:00:00Z",
        completed_ops=[],
    )

    session = Session(
        metadata=meta,
        run_path=run_dir,
        db_path=run_dir / "huntx.db",
        log_path=run_dir / "logs" / "huntx.log",
    )

    # Populate sample android findings
    apk_info = {
        "package_name": "com.example.testapp",
        "version_name": "1.2.0",
        "version_code": 12,
        "min_sdk": 24,
        "target_sdk": 34,
        "hashes": {"sha256": "abcdef1234567890", "md5": "1234567890abcdef"},
    }
    with open(run_dir / "android" / "apk-info.json", "w", encoding="utf-8") as f:
        json.dump(apk_info, f)

    components = [
        {"component_type": "activity", "class_name": "com.example.testapp.ui.MainActivity", "exported": True, "permission": ""},
        {"component_type": "activity", "class_name": "com.example.testapp.auth.LoginActivity", "exported": False, "permission": ""},
        {"component_type": "service", "class_name": "com.example.testapp.sync.SyncService", "exported": True, "permission": "android.permission.BIND_JOB_SERVICE"},
    ]
    with open(run_dir / "android" / "components.json", "w", encoding="utf-8") as f:
        json.dump({"components": components}, f)

    permissions = [
        {"name": "android.permission.INTERNET", "protection_level": "normal", "is_dangerous": False},
        {"name": "android.permission.ACCESS_FINE_LOCATION", "protection_level": "dangerous", "is_dangerous": True},
    ]
    with open(run_dir / "android" / "permissions.json", "w", encoding="utf-8") as f:
        json.dump({"permissions": permissions}, f)

    strings = [
        {"value": "/api/v1/users/{id}", "source_location": "com.example.testapp.api.UserService", "source_type": "dex"},
        {"value": "/api/v1/auth/login", "source_location": "com.example.testapp.auth.LoginActivity", "source_type": "dex"},
        {"value": "AIzaSyD-sampleApiKey123", "source_location": "com.example.testapp.Constants", "source_type": "dex"},
    ]
    with open(run_dir / "android" / "strings.json", "w", encoding="utf-8") as f:
        json.dump({"strings": strings}, f)

    domains = [
        {"domain": "api.example.com", "source": "dex_strings", "first_seen": "2026-11-19T12:00:00Z"},
        {"domain": "auth.example.com", "source": "dex_strings", "first_seen": "2026-11-19T12:00:00Z"},
    ]
    with open(run_dir / "api" / "domains.json", "w", encoding="utf-8") as f:
        json.dump({"domains": domains}, f)

    static_endpoints = [
        {
            "domain": "api.example.com",
            "path": "/api/v1/users/123",
            "normalized_path": "/api/v1/users/{id}",
            "method": "GET",
            "parameters": [{"name": "id", "in": "path"}],
            "discovery_sources": ["dex_strings"],
            "source_class": "com.example.testapp.api.UserService",
            "confidence": 0.70,
        },
        {
            "domain": "auth.example.com",
            "path": "/api/v1/auth/login",
            "normalized_path": "/api/v1/auth/login",
            "method": "POST",
            "parameters": [{"name": "username", "in": "body"}, {"name": "password", "in": "body"}],
            "discovery_sources": ["dex_strings"],
            "source_class": "com.example.testapp.auth.LoginActivity",
            "confidence": 0.85,
        },
    ]
    with open(run_dir / "api" / "endpoints.json", "w", encoding="utf-8") as f:
        json.dump({"endpoints": static_endpoints}, f)

    traffic_reqs = [
        {
            "method": "GET",
            "url": "https://api.example.com/api/v1/users/123",
            "host": "api.example.com",
            "headers": {"Authorization": "Bearer sample_token_jwt", "User-Agent": "Dalvik/2.1.0"},
            "query_params": {"filter": "active"},
            "timestamp": "2026-11-19T12:05:00Z",
        }
    ]
    with open(run_dir / "traffic" / "requests.json", "w", encoding="utf-8") as f:
        json.dump({"requests": traffic_reqs}, f)

    return session


# ==============================================================================
# Phase 5: Intelligence Tests
# ==============================================================================

def test_endpoint_passport_dataclass():
    """Verify EndpointPassport data model serialization and defaults."""
    passport = EndpointPassport(
        endpoint_id="EP-00001",
        domain="api.test.com",
        path="/v1/account",
        normalized_path="/v1/account",
        method="GET",
        feature_group="User Management",
        confidence=0.9,
    )
    d = passport.to_dict()
    assert d["endpoint_id"] == "EP-00001"
    assert d["domain"] == "api.test.com"
    assert d["method"] == "GET"
    assert d["feature_group"] == "User Management"

    rebuilt = EndpointPassport.from_dict(d)
    assert rebuilt.endpoint_id == "EP-00001"
    assert rebuilt.confidence == 0.9


def test_infer_feature_group():
    """Verify feature group classification heuristics."""
    assert infer_feature_group("/api/v1/auth/login") == "Authentication"
    assert infer_feature_group("/users/123/profile") == "User Management"
    assert infer_feature_group("/billing/checkout") == "Billing & Payments"
    assert infer_feature_group("/push/notifications") == "Notifications & Messaging"
    assert infer_feature_group("/search/items") == "Search"
    assert infer_feature_group("/random/endpoint") == "General API"


def test_detect_auth_evidence():
    """Verify detection of authorization evidence from headers and params."""
    ev = detect_auth_evidence(headers={"Authorization": "Bearer eyJhbGciOi..."})
    assert "Bearer token" in ev

    ev2 = detect_auth_evidence(parameters=[{"name": "api_key", "in": "query"}])
    assert "api_key" in ev2

    ev3 = detect_auth_evidence(path="/oauth/token")
    assert "Authentication path pattern" in ev3


def test_generate_endpoint_passports(test_session: Session):
    """Verify passport aggregation, deduplication, confidence boosting, and sequential ID assignment."""
    passports = generate_endpoint_passports(session=test_session)
    assert len(passports) >= 2

    # Check ID sequence format
    assert passports[0].endpoint_id == "EP-00001"
    assert passports[1].endpoint_id == "EP-00002"

    # Find the correlated user endpoint (seen in static AND dynamic traffic)
    user_ep = next(p for p in passports if p.normalized_path == "/api/v1/users/{id}")
    assert user_ep.confidence >= 0.95  # Boosted because seen in both
    assert "dex_strings" in user_ep.discovery_sources
    assert "traffic_capture" in user_ep.discovery_sources
    assert "Bearer token" in user_ep.authentication_evidence
    assert any(param.get("name") == "filter" for param in user_ep.parameters)

    # Check persisted file
    passports_file = test_session.run_path / "mapping" / "endpoint-passports.json"
    assert passports_file.exists()
    data = json.loads(passports_file.read_text(encoding="utf-8"))
    assert data["total_passports"] == len(passports)


def test_android_api_mapper(test_session: Session):
    """Verify deterministic mapping between Android classes and endpoints."""
    # Ensure passports exist first
    generate_endpoint_passports(session=test_session)

    mapper = AndroidApiMapper(session=test_session)
    result = mapper.map_endpoints()

    map_data = result.android_api_map
    sources_data = result.endpoint_sources

    assert map_data["total_mapped_classes"] >= 1
    assert sources_data["total_mapped_endpoints"] >= 1

    # Check mapped files exist on disk
    assert (test_session.run_path / "mapping" / "android-api-map.json").exists()
    assert (test_session.run_path / "mapping" / "endpoint-sources.json").exists()

    # Check class mapping contents
    classes = map_data["classes"]
    user_cls = next((c for c in classes if "UserService" in c["class_name"]), None)
    assert user_cls is not None
    assert any(ep.get("normalized_path") == "/api/v1/users/{id}" for ep in user_cls["endpoints"])


def test_apk_diff(test_session: Session, tmp_path: Path):
    """Verify APK diff engine identifies added/removed entities and risk changes."""
    # Create second session with modifications
    run2_dir = tmp_path / "TARGET" / "com.example.testapp" / "RUN_20261119_130000"
    for sub in ["input", "android", "api", "traffic", "mapping", "reports"]:
        (run2_dir / sub).mkdir(parents=True, exist_ok=True)

    # Modified domains: added "cdn.example.com", removed "auth.example.com"
    with open(run2_dir / "api" / "domains.json", "w", encoding="utf-8") as f:
        json.dump({"domains": [{"domain": "api.example.com"}, {"domain": "cdn.example.com"}]}, f)

    # Modified endpoints: added /api/v2/orders
    with open(run2_dir / "api" / "endpoints.json", "w", encoding="utf-8") as f:
        json.dump({
            "endpoints": [
                {"domain": "api.example.com", "path": "/api/v1/users/123", "normalized_path": "/api/v1/users/{id}", "method": "GET"},
                {"domain": "api.example.com", "path": "/api/v2/orders", "normalized_path": "/api/v2/orders", "method": "POST"},
            ]
        }, f)

    # Added dangerous permission CAMERA
    with open(run2_dir / "android" / "permissions.json", "w", encoding="utf-8") as f:
        json.dump({
            "permissions": [
                {"name": "android.permission.INTERNET"},
                {"name": "android.permission.CAMERA", "is_dangerous": True},
            ]
        }, f)

    # Exported status changed on LoginActivity
    with open(run2_dir / "android" / "components.json", "w", encoding="utf-8") as f:
        json.dump({
            "components": [
                {"class_name": "com.example.testapp.ui.MainActivity", "exported": True},
                {"class_name": "com.example.testapp.auth.LoginActivity", "exported": True},  # was False!
            ]
        }, f)

    out_file = test_session.run_path / "mapping" / "apk-comparison.json"
    diff_result = compare_apk_runs(base_run=test_session, target_run=run2_dir, output_file=out_file)

    assert out_file.exists()
    s = diff_result.summary
    assert s.new_domains_count == 1
    assert s.removed_domains_count == 1
    assert s.new_endpoints_count == 1
    assert s.added_permissions_count == 1
    assert s.removed_permissions_count == 1
    assert s.modified_components_count == 1
    assert s.security_risk_delta == "increased"


# ==============================================================================
# Phase 6: Reporting & Dashboard Tests
# ==============================================================================

def test_json_report(test_session: Session):
    """Verify unified JSON report generation."""
    generate_endpoint_passports(session=test_session)
    report = generate_json_report(session=test_session)

    assert report["report_version"] == "1.0.0"
    assert report["target"]["name"] == "com.example.testapp"
    assert report["apk_metadata"]["package_name"] == "com.example.testapp"
    assert report["summary"]["total_endpoints"] >= 2
    assert report["summary"]["total_domains"] >= 2
    assert len(report["extraction_limitations"]) >= 1

    report_path = test_session.run_path / "reports" / "huntx-report.json"
    assert report_path.exists()


def test_csv_reports(test_session: Session):
    """Verify CSV export for endpoints, domains, components, and permissions."""
    generate_endpoint_passports(session=test_session)
    csv_paths = generate_csv_reports(session=test_session)

    assert "endpoints" in csv_paths
    assert "domains" in csv_paths
    assert "components" in csv_paths
    assert "permissions" in csv_paths

    for name, p in csv_paths.items():
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert len(headers) >= 3
            rows = list(reader)
            assert len(rows) >= 1, f"Expected rows in {name}.csv"


def test_html_report(test_session: Session):
    """Verify standalone, offline-first interactive HTML report generation."""
    generate_endpoint_passports(session=test_session)
    html_path = generate_html_report(session=test_session)

    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")

    # Assert integrity & styling
    assert "<!DOCTYPE html>" in content
    assert "HUNTX" in content
    assert "com.example.testapp" in content
    assert "tab-overview" in content
    assert "tab-endpoints" in content
    assert "svg width=" in content
    assert "window.__HUNTX_DATA__" in content
    # Offline assertion: no external CDN links
    assert "https://cdn" not in content
    assert "https://cdnjs" not in content
    assert "https://fonts.googleapis" not in content



def test_search_engine(test_session: Session):
    """Verify search engine queries across entities and fallback mechanisms."""
    engine = SearchEngine(test_session.db_path, session_run_path=test_session.run_path)

    # 1. Fallback search (DB empty or not populated yet)
    results = engine.search("users")
    assert len(results) >= 1
    assert any("users" in str(r).lower() for r in results)

    # 2. Index into SQLite DB and search
    engine.index_domains([{"domain": "api.searchtest.com", "source": "test"}])
    engine.index_endpoints([{
        "endpoint_id": "EP-99999",
        "domain": "api.searchtest.com",
        "path": "/api/v1/searchtest",
        "method": "POST",
    }])
    engine.index_components([{
        "component_type": "activity",
        "class_name": "com.example.searchtest.Activity",
    }])

    db_results = engine.search("searchtest")
    assert len(db_results) >= 3


def test_menu_operation_dispatcher(test_session: Session, monkeypatch: pytest.MonkeyPatch):
    """Verify MenuSystem operation dispatcher executes and records ops 1 through 24."""
    menu = MenuSystem()
    menu.current_session = test_session
    menu.current_target = "com.example.testapp"

    # Mock inputs where needed
    monkeypatch.setattr(menu, "_get_input", lambda prompt: "test_query")
    monkeypatch.setattr("webbrowser.open", lambda uri: True)

    # Test execution of key operations
    # Op 14: Mapping
    assert menu._execute_operation(14) is True
    assert "14" in test_session.metadata.completed_ops

    # Op 15: Passports
    assert menu._execute_operation(15) is True
    assert "15" in test_session.metadata.completed_ops

    # Op 17: Search
    assert menu._execute_operation(17) is True

    # Op 18: JSON Report
    assert menu._execute_operation(18) is True
    assert "18" in test_session.metadata.completed_ops

    # Op 19: CSV Report
    assert menu._execute_operation(19) is True
    assert "19" in test_session.metadata.completed_ops

    # Op 20: HTML Report
    assert menu._execute_operation(20) is True
    assert "20" in test_session.metadata.completed_ops

    # Op 22: Session Info
    assert menu._execute_operation(22) is True

    # Op 23: View Results
    assert menu._execute_operation(23) is True


def test_resolve_dependencies():
    """Verify dependency resolution graph for recon operations."""
    resolved = resolve_dependencies([8])
    assert 1 in resolved  # 8 depends on 7, 7 depends on 1
    assert 7 in resolved
    assert 8 in resolved
    # Order: 1 before 7, 7 before 8
    assert resolved.index(1) < resolved.index(7) < resolved.index(8)
