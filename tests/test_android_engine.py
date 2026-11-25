"""HUNTX Phase 2 Android Engine Test Suite.

Comprehensive tests for:
- apk_info: APK metadata, hashes, ABIs, signing certificates.
- manifest: AXML parsing, component flags, intent filters, deep links.
- permissions: Reconnaissance grouping (Internet, Storage, Camera, etc.), zero vulnerability labeling.
- components: Activities, services, receivers, providers, exported logic.
- strings: Dalvik DEX string extraction, URL, domain, API path, IP, token discovery.
- resources: Network security config, certificate pinning, strings, assets.
- run_android_recon: Master orchestrator.
"""
from __future__ import annotations

import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import List

import pytest

# Ensure HUNTX root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from huntx.engines.android import (
    analyze_manifest,
    analyze_permissions,
    analyze_resources,
    axml_to_xml,
    enumerate_components,
    extract_apk_info,
    extract_strings,
    parse_axml,
    run_android_recon,
)
from huntx.engines.android.permissions import categorize_permission
from huntx.engines.android.strings import parse_dex_strings


# ---------------------------------------------------------------------------
# Helpers to generate mock artifacts
# ---------------------------------------------------------------------------

def _build_test_dex(strings: List[str]) -> bytes:
    """Generate a minimal valid Dalvik DEX file containing given strings."""
    def encode_uleb128(val: int) -> bytes:
        out = bytearray()
        while True:
            byte = val & 0x7F
            val >>= 7
            if val != 0:
                byte |= 0x80
            out.append(byte)
            if val == 0:
                break
        return bytes(out)

    str_data_items = []
    for s in strings:
        encoded = s.encode("utf-8")
        str_data_items.append(encode_uleb128(len(s)) + encoded + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)

    cur_data_off = header_size + (string_ids_size * 4)
    str_offsets = []
    for item in str_data_items:
        str_offsets.append(cur_data_off)
        cur_data_off += len(item)

    total_file_size = cur_data_off

    header = bytearray(b"dex\n035\x00")
    header += b"\x00" * 4  # checksum
    header += b"\x00" * 20  # signature
    header += struct.pack(
        "<IIIIIII", total_file_size, header_size, 0x12345678, 0, 0, 0, string_ids_size
    )
    header += struct.pack("<I", string_ids_off)
    header += b"\x00" * (header_size - len(header))

    str_ids_table = b"".join(struct.pack("<I", off) for off in str_offsets)
    return bytes(header) + str_ids_table + b"".join(str_data_items)


def _build_minimal_axml(strings: List[str], package_name: str, version_code: int) -> bytes:
    """Generate a minimal valid binary AXML structure."""
    str_offsets = []
    str_data = bytearray()
    for s in strings:
        str_offsets.append(len(str_data))
        encoded = s.encode("utf-16le")
        str_data += struct.pack("<H", len(s)) + encoded + b"\x00\x00"

    header_size = 28
    offsets_size = len(strings) * 4
    strings_start = header_size + offsets_size
    sp_chunk_size = strings_start + len(str_data)
    pad = (4 - (sp_chunk_size % 4)) % 4
    str_data += b"\x00" * pad
    sp_chunk_size += pad

    sp_header = struct.pack(
        "<HHIIIIII", 1, 28, sp_chunk_size, len(strings), 0, 0, strings_start, 0
    )
    sp_offsets = b"".join(struct.pack("<I", off) for off in str_offsets)
    sp_chunk = sp_header + sp_offsets + bytes(str_data)

    res_map = struct.pack("<HHI", 0x0180, 8, 8)

    # Attr 1: package
    attr1 = struct.pack("<iiiHBBI", -1, 1, 2, 8, 0, 3, 2)
    # Attr 2: versionCode
    attr2 = struct.pack("<iiiHBBI", -1, 3, -1, 8, 0, 0x10, version_code)

    elem_header_size = 16
    elem_body_size = 20
    elem_size = elem_header_size + elem_body_size + len(attr1) + len(attr2)
    start_manifest = struct.pack("<HHI", 0x0102, 16, elem_size)
    start_manifest += struct.pack("<II", 1, 0xFFFFFFFF)
    start_manifest += struct.pack("<iiHHHHHH", -1, 0, 20, 20, 2, 0, 0, 0)
    start_manifest += attr1 + attr2

    end_manifest = struct.pack("<HHI", 0x0103, 16, 24)
    end_manifest += struct.pack("<IIii", 1, 0xFFFFFFFF, -1, 0)

    body = sp_chunk + res_map + start_manifest + end_manifest
    file_hdr = struct.pack("<HHI", 3, 8, 8 + len(body))
    return file_hdr + body


SAMPLE_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.huntxapp"
    android:versionCode="210"
    android:versionName="2.1.0">

    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" android:maxSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.BLUETOOTH" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="com.example.custom.PERMISSION_TEST" />

    <permission android:name="com.example.huntxapp.PRIVATE_ACCESS"
        android:protectionLevel="signature"
        android:label="Private Access" />

    <application
        android:name=".HuntxApplication"
        android:label="Huntx App"
        android:debuggable="true"
        android:allowBackup="false"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="huntx" android:host="api.huntx.internal" android:pathPrefix="/auth" />
            </intent-filter>
        </activity>

        <service android:name=".BackgroundSyncService"
            android:exported="false"
            android:permission="android.permission.BIND_JOB_SERVICE" />

        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <provider android:name=".UserDataProvider"
            android:authorities="com.example.huntxapp.provider"
            android:exported="false"
            android:grantUriPermissions="true" />

    </application>
</manifest>
"""

SAMPLE_NSC_XML = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.huntx.internal</domain>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
        <pin-set expiration="2027-12-31">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmElZhWvWAIcYiYc0=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

SAMPLE_STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Huntx App</string>
    <string name="api_url">https://api.huntx.internal/v1</string>
    <string name="support_email">support@huntx.internal</string>
</resources>
"""


def create_mock_apk(apk_file: Path, binary_axml: bool = False) -> Path:
    """Create a fully featured mock APK zip archive."""
    with zipfile.ZipFile(apk_file, "w") as zf:
        # 1. AndroidManifest
        if binary_axml:
            axml_data = _build_minimal_axml(
                strings=["manifest", "package", "com.example.binaryapp", "versionCode"],
                package_name="com.example.binaryapp",
                version_code=300,
            )
            zf.writestr("AndroidManifest.xml", axml_data)
        else:
            zf.writestr("AndroidManifest.xml", SAMPLE_MANIFEST_XML.encode("utf-8"))

        # 2. DEX with interesting strings
        dex_strings = [
            "https://api.huntx.internal/v1/auth/login",
            "https://production.service.huntx.com/graphql",
            "/api/v2/users/me",
            "/oauth/token",
            "security-alerts@huntx.internal",
            "10.0.0.1",
            "192.168.1.100",
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaSyA_ExampleApiKey35CharactersLong_01",
            "https://my-app.firebaseio.com",
            "com.example.huntxapp.MainActivity",
        ]
        zf.writestr("classes.dex", _build_test_dex(dex_strings))

        # 3. Native ABIs
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF\x02\x01\x01\x00")
        zf.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF\x01\x01\x01\x00")

        # 4. Resources
        zf.writestr("res/xml/network_security_config.xml", SAMPLE_NSC_XML.encode("utf-8"))
        zf.writestr("res/values/strings.xml", SAMPLE_STRINGS_XML.encode("utf-8"))

        # 5. Assets & Config
        zf.writestr(
            "assets/google-services.json",
            json.dumps({"project_info": {"project_id": "huntx-recon-test"}}),
        )
        zf.writestr("assets/config.properties", "api_key=secret_1234567890abcdef\n")

        # 6. META-INF Signature block
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: HUNTX Test\n")
        zf.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x0a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + b"\x55\x04\x03\x13\x09HUNTXTestCert")

    return apk_file


# ===========================================================================
# Test Cases
# ===========================================================================

def test_axml_parser_plaintext() -> None:
    """Test AXML parser correctly handles plaintext XML."""
    elem = parse_axml(SAMPLE_MANIFEST_XML.encode("utf-8"))
    assert elem is not None
    assert elem.tag == "manifest"
    assert elem.attrib.get("package") == "com.example.huntxapp"

    xml_text = axml_to_xml(SAMPLE_MANIFEST_XML.encode("utf-8"))
    assert 'package="com.example.huntxapp"' in xml_text
    assert xml_text.startswith("<?xml")


def test_axml_parser_binary() -> None:
    """Test AXML parser correctly decodes binary AXML bytes."""
    binary_data = _build_minimal_axml(
        strings=["manifest", "package", "com.example.bin", "versionCode"],
        package_name="com.example.bin",
        version_code=42,
    )
    elem = parse_axml(binary_data)
    assert elem is not None
    assert elem.tag == "manifest"
    assert elem.attrib.get("package") == "com.example.bin"
    assert elem.attrib.get("versionCode") == "42"


def test_apk_info_extraction(tmp_path: Path) -> None:
    """Test apk_info.py extracts metadata, ABIs, certificates, and generates output files."""
    apk_path = create_mock_apk(tmp_path / "test-app.apk")
    out_dir = tmp_path / "android"

    info = extract_apk_info(apk_path, output_dir=out_dir)

    assert info["filename"] == "test-app.apk"
    assert info["package_name"] == "com.example.huntxapp"
    assert info["version_name"] == "2.1.0"
    assert info["version_code"] == 210
    assert info["min_sdk"] == "24"
    assert info["target_sdk"] == "33"
    assert info["max_sdk"] == "34"
    assert "arm64-v8a" in info["supported_abis"]
    assert "armeabi-v7a" in info["supported_abis"]
    assert info["signing"]["v1_signed"] is True
    # The mock's CERT.RSA is not real PKCS#7: report nothing rather than invent a signer
    assert info["signing"]["certificates"] == []
    assert info["sha256"] != ""

    # Check files generated
    json_path = out_dir / "apk-info.json"
    txt_path = out_dir / "apk-info.txt"
    assert json_path.exists()
    assert txt_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["package_name"] == "com.example.huntxapp"

    txt_content = txt_path.read_text(encoding="utf-8")
    assert "HUNTX - APK INFORMATION REPORT" in txt_content
    assert "com.example.huntxapp" in txt_content
    assert "arm64-v8a" in txt_content


def test_manifest_analysis(tmp_path: Path) -> None:
    """Test manifest.py extracts flags, components, deep links, custom permissions."""
    apk_path = create_mock_apk(tmp_path / "test-manifest.apk")
    out_dir = tmp_path / "android"

    manifest_data = analyze_manifest(apk_path, output_dir=out_dir)

    assert manifest_data["package"] == "com.example.huntxapp"
    assert manifest_data["flags"]["debuggable"] is True
    assert manifest_data["flags"]["allow_backup"] is False
    assert manifest_data["flags"]["uses_cleartext_traffic"] is True
    assert manifest_data["network_security_config"] == "@xml/network_security_config"

    # Deep links
    deep_links = manifest_data["deep_links"]
    assert len(deep_links) >= 1
    dl = deep_links[0]
    assert dl["scheme"] == "huntx"
    assert dl["host"] == "api.huntx.internal"
    assert dl["path_prefix"] == "/auth"
    assert "huntx://api.huntx.internal/auth*" in dl["full_pattern"]

    # Custom permissions
    custom_perms = manifest_data["custom_permissions"]
    assert len(custom_perms) == 1
    assert custom_perms[0]["name"] == "com.example.huntxapp.PRIVATE_ACCESS"
    assert custom_perms[0]["protection_level"] == "signature"

    # Outputs
    assert (out_dir / "manifest.xml").exists()
    assert (out_dir / "manifest-analysis.json").exists()


def test_permissions_categorization(tmp_path: Path) -> None:
    """Test permissions.py categorizes declared permissions without vulnerability labeling."""
    apk_path = create_mock_apk(tmp_path / "test-perms.apk")
    out_dir = tmp_path / "android"

    perms_data = analyze_permissions(apk_path, output_dir=out_dir)

    categories = perms_data["categories"]
    assert "android.permission.INTERNET" in categories["Internet"]
    assert "android.permission.READ_EXTERNAL_STORAGE" in categories["Storage"]
    assert "android.permission.CAMERA" in categories["Camera"]
    assert "android.permission.ACCESS_FINE_LOCATION" in categories["Location"]
    assert "android.permission.READ_CONTACTS" in categories["Contacts"]
    assert "android.permission.RECORD_AUDIO" in categories["Microphone"]
    assert "android.permission.READ_PHONE_STATE" in categories["Phone"]
    assert "android.permission.SEND_SMS" in categories["SMS"]
    assert "android.permission.BLUETOOTH" in categories["Network"]
    assert "android.permission.RECEIVE_BOOT_COMPLETED" in categories["System-level"]
    assert "com.example.custom.PERMISSION_TEST" in categories["Other"]

    # Verify no vulnerability labeling
    json_str = json.dumps(perms_data).lower()
    for forbidden in ["vulnerability", "exploit", "threat", "danger_level", "risk_score"]:
        assert forbidden not in json_str

    # Outputs
    assert (out_dir / "permissions.json").exists()
    assert (out_dir / "permissions.txt").exists()


def test_categorize_permission_heuristics() -> None:
    """Test individual permission categorization rules."""
    assert categorize_permission("android.permission.INTERNET") == "Internet"
    assert categorize_permission("android.permission.CAMERA") == "Camera"
    assert categorize_permission("android.permission.ACCESS_COARSE_LOCATION") == "Location"
    assert categorize_permission("android.permission.WRITE_EXTERNAL_STORAGE") == "Storage"
    assert categorize_permission("android.permission.RECORD_AUDIO") == "Microphone"
    assert categorize_permission("android.permission.CALL_PHONE") == "Phone"
    assert categorize_permission("android.permission.READ_SMS") == "SMS"
    assert categorize_permission("android.permission.ACCESS_WIFI_STATE") == "Network"
    assert categorize_permission("android.permission.WAKE_LOCK") == "System-level"
    assert categorize_permission("com.vendor.custom.SOME_PERMISSION") == "Other"


def test_components_enumeration(tmp_path: Path) -> None:
    """Test components.py enumerates activities, services, receivers, providers."""
    apk_path = create_mock_apk(tmp_path / "test-comps.apk")
    out_dir = tmp_path / "android"

    comps = enumerate_components(apk_path, output_dir=out_dir)

    summary = comps["summary"]
    assert summary["counts_by_type"]["activity"] == 2
    assert summary["counts_by_type"]["service"] == 1
    assert summary["counts_by_type"]["receiver"] == 1
    assert summary["counts_by_type"]["provider"] == 1
    assert summary["total_components"] == 5

    # Check exported resolution
    # MainActivity: exported=true
    main_act = next(c for c in comps["activities"] if "MainActivity" in c["name"])
    assert main_act["exported"] is True

    # BackgroundSyncService: exported=false, permission=BIND_JOB_SERVICE
    sync_svc = comps["services"][0]
    assert sync_svc["exported"] is False
    assert sync_svc["permission"] == "android.permission.BIND_JOB_SERVICE"

    # UserDataProvider: authorities=com.example.huntxapp.provider
    provider = comps["providers"][0]
    assert provider["authorities"] == "com.example.huntxapp.provider"
    assert provider["grant_uri_permissions"] is True

    assert (out_dir / "components.json").exists()


def test_components_repository_save(tmp_path: Path, request) -> None:
    """Test components enumeration persists records to session repository."""
    from huntx.core.session import Session, SessionMetadata

    apk_path = create_mock_apk(tmp_path / "test-repo.apk")
    db_file = tmp_path / "huntx.db"
    log_file = tmp_path / "huntx.log"

    session = Session(
        metadata=SessionMetadata(
            session_id="test-session-123",
            target_name="test-target",
            run_dir="RUN_TEST",
        ),
        run_path=tmp_path,
        db_path=db_file,
        log_path=log_file,
    )

    enumerate_components(apk_path, output_dir=tmp_path / "android", session=session)

    from huntx.storage.repository import Repository
    repo = Repository(session)
    request.addfinalizer(repo.close)
    stored = repo.get_all_components()
    assert len(stored) == 5
    types = {s["component_type"] for s in stored}
    assert types == {"activity", "service", "receiver", "provider"}


def test_strings_extraction(tmp_path: Path) -> None:
    """Test strings.py extracts URLs, domains, API paths, emails, IPs, and tokens."""
    apk_path = create_mock_apk(tmp_path / "test-strings.apk")
    out_dir = tmp_path / "android"

    result = extract_strings(apk_path, output_dir=out_dir)

    urls = [u["value"] for u in result["urls"]]
    assert "https://api.huntx.internal/v1/auth/login" in urls
    assert "https://production.service.huntx.com/graphql" in urls

    domains = [d["value"] for d in result["domains"]]
    assert "production.service.huntx.com" in domains or "huntx.com" in domains

    api_paths = [p["value"] for p in result["api_paths"]]
    assert any("/api/v2/users/me" in p for p in api_paths)
    assert any("/oauth/token" in p for p in api_paths)

    emails = [e["value"] for e in result["emails"]]
    assert "security-alerts@huntx.internal" in emails

    ips = [i["value"] for i in result["ips"]]
    assert "10.0.0.1" in ips
    assert "192.168.1.100" in ips

    # Tokens
    tokens = {t["value"]: t["token_type"] for t in result["tokens"]}
    assert "AKIAIOSFODNN7EXAMPLE" in tokens
    assert tokens["AKIAIOSFODNN7EXAMPLE"] == "aws_access_key"
    assert "AIzaSyA_ExampleApiKey35CharactersLong_01" in tokens
    assert tokens["AIzaSyA_ExampleApiKey35CharactersLong_01"] == "google_api_key"

    # Source check
    dex_finding = next(u for u in result["urls"] if "classes.dex" in u.get("source", ""))
    assert dex_finding["source"] == "classes.dex"

    assert (out_dir / "strings.json").exists()
    assert (out_dir / "strings.txt").exists()


def test_resources_analysis(tmp_path: Path) -> None:
    """Test resources.py parses network security config, string resources, and assets."""
    apk_path = create_mock_apk(tmp_path / "test-res.apk")
    out_dir = tmp_path / "android"

    res_data = analyze_resources(apk_path, output_dir=out_dir)

    nsc = res_data["network_security_config"]
    assert nsc["present"] is True
    assert nsc["base_cleartext_permitted"] is False
    assert nsc["has_certificate_pinning"] is True
    assert nsc["allows_user_certs_in_debug"] is True

    # Domain config
    assert len(nsc["domain_configs"]) >= 1
    dc = nsc["domain_configs"][0]
    assert dc["cleartext_traffic_permitted"] is True
    assert dc["domains"][0]["domain"] == "api.huntx.internal"
    assert dc["domains"][0]["include_subdomains"] is True
    assert len(dc["pin_set"]["pins"]) == 1
    assert dc["pin_set"]["pins"][0]["digest"] == "SHA-256"

    # String resources
    strings = res_data["string_resources"]
    assert strings.get("app_name") == "Huntx App"
    assert strings.get("api_url") == "https://api.huntx.internal/v1"
    assert strings.get("support_email") == "support@huntx.internal"

    # Assets & Config files
    assert res_data["assets_count"] >= 2
    assert "assets/google-services.json" in res_data["config_files"]
    cfg = res_data["config_files"]["assets/google-services.json"]
    assert cfg["project_info"]["project_id"] == "huntx-recon-test"

    assert (out_dir / "resources.json").exists()
    assert (out_dir / "resources.txt").exists()


def test_run_android_recon_orchestrator(tmp_path: Path) -> None:
    """Test master run_android_recon executes all engines and produces all required output files."""
    apk_path = create_mock_apk(tmp_path / "recon-test.apk")
    out_dir = tmp_path / "android"

    results = run_android_recon(apk_path, output_dir=out_dir)

    assert "apk_info" in results
    assert "manifest" in results
    assert "permissions" in results
    assert "components" in results
    assert "strings" in results
    assert "resources" in results

    # Verify all expected output files exist
    expected_files = [
        "apk-info.json",
        "apk-info.txt",
        "manifest.xml",
        "manifest-analysis.json",
        "permissions.json",
        "permissions.txt",
        "components.json",
        "strings.json",
        "strings.txt",
        "resources.json",
        "resources.txt",
    ]

    for fname in expected_files:
        p = out_dir / fname
        assert p.exists(), f"Expected output file missing: {fname}"
        assert p.stat().st_size > 0, f"Output file is empty: {fname}"


def test_edge_cases(tmp_path: Path) -> None:
    """Test error handling and resilience on non-existent or corrupted files."""
    # 1. Non-existent file
    with pytest.raises(FileNotFoundError):
        extract_apk_info(tmp_path / "does_not_exist.apk")

    # 2. Corrupt/Empty file should not crash
    corrupt_file = tmp_path / "corrupt.apk"
    corrupt_file.write_bytes(b"NOT_A_ZIP_FILE_RANDOM_GARBAGE")

    info = extract_apk_info(corrupt_file)
    assert info["filename"] == "corrupt.apk"
    assert info["package_name"] == "unknown.package"

    # 3. Empty DEX buffer
    assert parse_dex_strings(b"") == []
    assert parse_dex_strings(b"dex\n035\x00") == []
