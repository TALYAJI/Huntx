"""Regression tests for HUNTX Approved Engineering Improvements (1-7)."""
from __future__ import annotations

import json
import sys
import tomllib
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_sdk_noise_filtering_and_raw_preservation(tmp_path: Path) -> None:
    """Improvement 1: Configurable noise filter keeps endpoints-raw.json intact."""
    from huntx.engines.api.endpoints import is_sdk_noise_endpoint, run_endpoint_extraction

    assert is_sdk_noise_endpoint("/auth/x500/X500Principal") is True
    assert is_sdk_noise_endpoint("/v1/XmlPullParser") is True
    assert is_sdk_noise_endpoint("/v4/app/INotificationSideChannel") is True
    assert is_sdk_noise_endpoint("/apk/res-auto", "schemas.android.com") is True
    assert is_sdk_noise_endpoint("/V2/Browser/SaveBrowserData", "api.coupang.com") is False

    out_dir = tmp_path / "api"
    raw_strings = [
        {"value": "https://schemas.android.com/apk/res-auto", "source": "classes.dex"},
        {"value": "/xmlpull/v1/XmlPullParser", "source": "classes2.dex"},
        {"value": "https://api.coupang.com/V2/Browser/SaveBrowserData", "source": "classes.dex"},
    ]
    res = run_endpoint_extraction(strings=raw_strings, output_dir=out_dir, filter_noise=True)
    filtered_paths = [e["path"] for e in res["endpoints"]]
    assert "/V2/Browser/SaveBrowserData" in filtered_paths
    assert "/v1/XmlPullParser" not in filtered_paths

    raw_file = out_dir / "endpoints-raw.json"
    assert raw_file.exists()
    raw_data = json.loads(raw_file.read_text(encoding="utf-8"))
    raw_paths = [e["path"] for e in raw_data]
    assert "/apk/res-auto" in raw_paths
    assert "/V2/Browser/SaveBrowserData" in raw_paths


def test_http_method_inference_preserves_unknown() -> None:
    """Improvement 2: Evidence-based HTTP method inference preserves UNKNOWN when inconclusive."""
    from huntx.engines.android.dex_xref import _infer_http_method_from_calls

    verb, ev = _infer_http_method_from_calls(
        ["https://api.example.com/v1/login"],
        ["Lokhttp3/Request$Builder;->post"],
    )
    assert verb == "POST"
    assert "OkHttp" in ev

    # Ambiguous (both GET and POST in same method) -> must return None (UNKNOWN)
    verb_ambig, _ = _infer_http_method_from_calls(
        ["https://api.example.com/v1/items"],
        ["Lokhttp3/Request$Builder;->get", "Lokhttp3/Request$Builder;->post"],
    )
    assert verb_ambig is None

    # No HTTP client invocation -> must return None (UNKNOWN)
    verb_none, _ = _infer_http_method_from_calls(
        ["/V2/Browser/SaveBrowserData"],
        ["Ljava/lang/StringBuilder;->append"],
    )
    assert verb_none is None


def test_androgoat_dex_xref_if_present() -> None:
    """Improvement 3: Real AndroGoat Dalvik bytecode cross-referencing maps exact classes/methods."""
    androgoat_apk = Path(__file__).parent.parent / "Target" / "androgoat" / "AndroGoat.apk"
    if not androgoat_apk.exists():
        return

    from huntx.engines.android.dex_xref import extract_apk_xrefs

    xrefs = extract_apk_xrefs([androgoat_apk])
    classes = {x.class_name: x.method_name for x in xrefs}
    assert any(c.split("$")[0] == "owasp.sat.agoat.DownloadInvoiceService" for c in classes)  # Kotlin lambda
    assert "owasp.sat.agoat.TrafficActivity" in classes


def test_multi_apk_string_aggregation(tmp_path: Path) -> None:
    """Improvement 4: Aggregate strings across split APKs preserving APK source provenance."""
    from huntx.engines.android.strings import extract_strings

    apk1 = tmp_path / "base.apk"
    apk2 = tmp_path / "split_feature.apk"

    with zipfile.ZipFile(apk1, "w") as z1:
        z1.writestr("assets/config.json", '{"api": "https://api.base.local/v1/ping"}')
    with zipfile.ZipFile(apk2, "w") as z2:
        z2.writestr("assets/feature.json", '{"api": "https://api.split.local/v2/checkout"}')

    res = extract_strings([apk1, apk2])
    url_map = {u["value"]: u["source"] for u in res["urls"]}
    assert url_map["https://api.base.local/v1/ping"] == "base.apk:assets/config.json"
    assert url_map["https://api.split.local/v2/checkout"] == "split_feature.apk:assets/feature.json"


def test_html_report_includes_security_audit_tab(tmp_path: Path) -> None:
    """Improvement 6: huntx-report.html integrates Security Audit, WebView, SSL, JWT, and ADB PoCs."""
    from huntx.reporting.html_report import generate_html_report

    report_data = {
        "target": {"name": "testapp", "session_id": "sess-123"},
        "apk_metadata": {"application_name": "TestApp", "package_name": "com.test.app"},
        "summary": {"total_endpoints": 0, "total_domains": 0},
        "findings": {
            "domains": [],
            "endpoints": [],
            "components": [],
            "permissions": [],
            "android_api_mapping": [],
            "security_audit": {
                "fingerprint": {
                    "frameworks": ["React Native"],
                    "defenses": ["OkHttp CertificatePinner (SSL Pinning)"],
                    "webview_signals": ["WebView.addJavascriptInterface (JS Bridge)"],
                },
                "secrets": [{"type": "stripe_key", "value": "sk_live_test", "source": "classes.dex"}],
                "cloud_assets": [{"type": "firebase_db", "value": "https://test.firebaseio.com", "source": "resources.arsc"}],
                "decoded_jwts": [{"source": "classes.dex", "decoded": {"header": {"alg": "HS256"}, "payload": {"role": "user"}}}],
                "adb_pocs": [{"type": "Exported Activity", "component": "com.test.Main", "command": "adb shell am start -n com.test.app/com.test.Main"}],
            },
        },
        "extraction_limitations": [],
    }
    out_html = tmp_path / "huntx-report.html"
    generate_html_report(report_data=report_data, output_path=out_html)
    content = out_html.read_text(encoding="utf-8")
    assert "Security Audit &amp; PoCs" in content
    assert "React Native" in content
    assert "OkHttp CertificatePinner" in content
    assert "addJavascriptInterface" in content
    assert "adb shell am start -n com.test.app/com.test.Main" in content
    assert "JWT_DECODED" in content


def test_pyproject_toml_valid() -> None:
    """Improvement 7: pyproject.toml defines huntx CLI entry point."""
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    assert pyproject.exists()
    with pyproject.open("rb") as f:
        data = tomllib.load(f)
    assert data["project"]["name"] == "huntx"
    assert data["project"]["scripts"]["huntx"] == "huntx.cli.commands:cli_app"
