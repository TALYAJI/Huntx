"""Tests for HUNTX One-Page Summary Report Generator and container-aware metadata extraction."""
import json
import zipfile
from pathlib import Path

from huntx.engines.android.apk_info import extract_apk_info
from huntx.reporting.json_report import JSONReportGenerator
from huntx.reporting.summary_report import generate_summary_report


def test_extract_apk_info_hashes_and_container(tmp_path: Path):
    """Test that extract_apk_info computes complete hashes and parses container manifest."""
    fake_xapk = tmp_path / "test_app.xapk"
    manifest_data = {
        "xapk_version": 2,
        "package_name": "com.example.secureapp",
        "name": "SecureApp",
        "version_name": "2.1.0",
        "version_code": "105",
        "min_sdk_version": "26",
        "target_sdk_version": "34",
    }
    with zipfile.ZipFile(fake_xapk, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest_data))
        zf.writestr("dummy.txt", "sample content")

    info = extract_apk_info(fake_xapk)
    assert info["package_name"] == "com.example.secureapp"
    assert info["application_name"] == "SecureApp"
    assert info["version_name"] == "2.1.0"
    assert info["version_code"] == 105
    assert info["min_sdk"] == "26"
    assert info["target_sdk"] == "34"
    assert "hashes" in info
    assert "sha256" in info["hashes"]
    assert "sha1" in info["hashes"]
    assert "md5" in info["hashes"]
    assert len(info["hashes"]["sha256"]) == 64


def test_json_report_clean_metadata_resolution(tmp_path: Path):
    """Test that JSONReportGenerator resolves application name, flags, and file sizes properly."""
    session_dir = tmp_path / "RUN_TEST"
    session_dir.mkdir(parents=True)
    (session_dir / "android").mkdir()
    (session_dir / "reports").mkdir()

    # Write mock apk-info.json
    apk_info = {
        "package_name": "com.test.banking",
        "application_name": "@0x7f120001",
        "version_name": "3.0.1",
        "version_code": 301,
        "min_sdk": "24",
        "target_sdk": "34",
        "size_human": "25.40 MB",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "hashes": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
    }
    (session_dir / "android" / "apk-info.json").write_text(json.dumps(apk_info), encoding="utf-8")

    # Write manifest-analysis with flags
    manifest_info = {
        "package": "com.test.banking",
        "flags": {
            "debuggable": False,
            "uses_cleartext_traffic": True,
            "allow_backup": False,
        },
    }
    (session_dir / "android" / "manifest-analysis.json").write_text(json.dumps(manifest_info), encoding="utf-8")

    class FakeSession:
        run_path = session_dir
        metadata = None

    generator = JSONReportGenerator(session=FakeSession())
    rep = generator.generate()

    meta = rep["apk_metadata"]
    assert meta["package_name"] == "com.test.banking"
    assert meta["application_name"] == "Banking"  # Derived from package name
    assert meta["version_name"] == "3.0.1"
    assert meta["version_code"] == 301
    assert meta["debuggable"] is False
    assert meta["cleartext_traffic"] is True
    assert meta["allow_backup"] is False
    assert meta["sha256"] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def test_generate_summary_report_html_structure(tmp_path: Path):
    """Test generating one-page A4 summary report HTML with centering and tables."""
    out_html = tmp_path / "huntx-summary.html"
    mock_data = {
        "target": {
            "name": "AcmePay",
            "session_id": "test-session-1234",
            "created_at": "2026-11-19T12:00:00Z",
        },
        "apk_metadata": {
            "application_name": "AcmePay",
            "package_name": "com.acme.pay",
            "version_name": "1.4.0",
            "version_code": 42,
            "min_sdk": "24",
            "target_sdk": "34",
            "debuggable": True,
            "cleartext_traffic": False,
            "size_human": "18.5 MB",
            "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        },
        "summary": {
            "total_endpoints": 120,
            "total_domains": 8,
            "total_components": 32,
            "exported_components": 5,
            "high_risk_exported_components": 1,
            "total_permissions": 12,
            "dangerous_permissions": 2,
        },
        "findings": {
            "domains": [{"domain": "api.acmepay.com", "protocol": "HTTPS"}],
            "endpoints": [{"method": "POST", "path": "/v1/auth/login"}],
            "components": [
                {"name": "com.acme.pay.AuthService", "component_type": "service", "exported": True, "permission": None}
            ],
            "permissions": [
                {"name": "android.permission.CAMERA", "is_dangerous": True, "protection_level": "dangerous"}
            ],
            "networking_libraries": ["OkHttp", "Retrofit"],
        },
        "extraction_limitations": ["Static bytecode inspection only."],
    }

    path = generate_summary_report(report_data=mock_data, output_path=out_html)
    assert path.exists()

    content = path.read_text(encoding="utf-8")
    # Verify horizontal centering & layout
    assert "width: 210mm;" in content
    assert "margin: 0 auto;" in content
    assert "@page" in content
    assert "A4 portrait" in content

    # Verify typography and identity fields
    assert "AcmePay" in content
    assert "com.acme.pay" in content
    assert "v1.4.0" in content
    assert "YES (HIGH RISK)" in content  # Debuggable flag
    assert "api.acmepay.com" in content
    assert "/v1/auth/login" in content
    assert "OkHttp, Retrofit" in content
    assert "AuthService" in content
    assert "test-session-1234" in content
