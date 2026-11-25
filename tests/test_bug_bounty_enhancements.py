"""Tests for HUNTX Bug Bounty & Passive Security Audit Enhancements."""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_expanded_secret_and_cloud_patterns() -> None:
    """Verify cloud storage, Stripe, Firebase, and JWT patterns classify correctly."""
    from huntx.engines.android.strings import classify_strings

    samples = [
        ("https://my-corp-assets.s3.amazonaws.com/backups/db.sql", "classes.dex"),
        ("https://storage.googleapis.com/corp-public-bucket/config.json", "assets/index.android.bundle"),
        ("https://my-app-prod.firebaseio.com", "resources.arsc"),
        ("sk_" + "live_" + "0" * 24, "classes2.dex"),
    ]
    res = classify_strings(samples)
    tok_types = {t["token_type"] for t in res["tokens"]}
    assert "aws_s3_bucket" in tok_types
    assert "gcs_bucket" in tok_types
    assert "firebase_db" in tok_types
    assert "stripe_key" in tok_types


def test_passive_jwt_decode() -> None:
    """Verify passive JWT decoding extracts header and payload safely."""
    from huntx.engines.android.security_audit import _decode_jwt_passive

    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    pay = base64.urlsafe_b64encode(b'{"sub":"123","role":"admin"}').decode().rstrip("=")
    tok = f"{hdr}.{pay}.fakesig"

    decoded = _decode_jwt_passive(tok)
    assert decoded is not None
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["role"] == "admin"


def test_adb_poc_generation() -> None:
    """Verify ADB PoC commands are generated for unprotected exported components and deep links."""
    from huntx.engines.android.security_audit import _generate_adb_pocs

    comps = [
        {
            "name": "com.target.DeepLinkActivity",
            "component_type": "activity",
            "exported": True,
            "permission": None,
            "intent_filters": [{"data": [{"scheme": "myapp", "host": "auth", "pathPrefix": "/cb"}]}],
        },
        {
            "name": "com.target.SecretService",
            "component_type": "service",
            "exported": True,
            "permission": None,
            "intent_filters": [],
        },
        {
            "name": "com.target.UserProvider",
            "component_type": "provider",
            "exported": True,
            "read_permission": None,
            "write_permission": None,
            "authorities": "com.target.provider",
        },
    ]

    pocs = _generate_adb_pocs("com.target", comps)
    cmds = [p["command"] for p in pocs]
    assert any("myapp://auth/cb" in c for c in cmds)
    assert any("am startservice -n com.target/com.target.SecretService" in c for c in cmds)
    assert any("content query --uri content://com.target.provider/" in c for c in cmds)


def test_bug_bounty_exporters(tmp_path: Path) -> None:
    """Verify all bug bounty wordlists, Postman collection, and Markdown drafts export cleanly."""
    from huntx.reporting.exporters import export_bug_bounty_artifacts

    run_dir = tmp_path / "RUN_TEST"
    (run_dir / "android").mkdir(parents=True)
    (run_dir / "api").mkdir(parents=True)
    (run_dir / "mapping").mkdir(parents=True)

    (run_dir / "android" / "apk-info.json").write_text(
        json.dumps({"package_name": "com.example.app", "app_name": "ExampleApp", "version_name": "2.1", "sha256": "abc123"}),
        encoding="utf-8",
    )
    (run_dir / "android" / "manifest-analysis.json").write_text(
        json.dumps({"security_flags": {"debuggable": True, "uses_cleartext_traffic": False}}),
        encoding="utf-8",
    )
    (run_dir / "android" / "security-audit.json").write_text(
        json.dumps({
            "secrets": [{"type": "stripe_key", "value": "sk_live_test123", "source": "classes.dex"}],
            "cloud_assets": [{"type": "firebase_db", "value": "https://demo.firebaseio.com", "source": "resources.arsc"}],
            "adb_pocs": [{"type": "Exported Activity", "component": "com.example.Main", "command": "adb shell am start -n com.example.app/com.example.Main"}],
        }),
        encoding="utf-8",
    )
    (run_dir / "api" / "domains.json").write_text(
        json.dumps({"domains": [{"domain": "api.example.com"}, {"domain": "schemas.android.com"}]}),
        encoding="utf-8",
    )
    (run_dir / "api" / "endpoints.json").write_text(
        json.dumps([{"path": "/v1/users/42", "normalized_path": "/v1/users/{id}", "domain": "api.example.com"}]),
        encoding="utf-8",
    )

    exports = export_bug_bounty_artifacts(run_dir)
    assert exports["domains"].read_text(encoding="utf-8").strip() == "api.example.com"
    assert "/v1/users/{id}" in exports["endpoints"].read_text(encoding="utf-8")
    assert "sk_live_test123" in exports["secrets"].read_text(encoding="utf-8")
    assert "https://demo.firebaseio.com" in exports["cloud_assets"].read_text(encoding="utf-8")
    assert "adb shell am start" in exports["adb_pocs"].read_text(encoding="utf-8")
    assert "CWE-489" in exports["bounty_drafts"].read_text(encoding="utf-8")

    pm = json.loads(exports["postman"].read_text(encoding="utf-8"))
    assert pm["info"]["name"] == "HUNTX Recon - ExampleApp (com.example.app)"
    assert len(pm["item"]) == 1
