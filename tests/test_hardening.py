"""Regression tests for correctness and hostile-input handling."""
from __future__ import annotations

import csv
import datetime as dt
import json
import re
import shlex
import struct
import zipfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from typer.testing import CliRunner

from huntx.cli.commands import cli_app
from huntx.core.config import load_config
from huntx.core.session import SessionManager
from huntx.core.target_manager import TargetManager

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
EVIL = "');alert(1)//</ScRiPt><img src=x onerror=alert(1)>"

MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo"
  android:versionCode="7" android:versionName="1.2">
 <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
 <uses-permission android:name="android.permission.CAMERA"/>
 <uses-permission android:name="android.permission.INTERNET"/>
 <application android:label="Demo" android:debuggable="true">
  <activity android:name=".Main" android:exported="true"><intent-filter>
    <action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/>
  </intent-filter></activity>
  <activity android:name=".Link" android:exported="true"><intent-filter>
    <action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https"/><data android:host="demo.com"/><data android:pathPrefix="/o"/>
  </intent-filter></activity>
  <service android:name=".Sync" android:exported="true"/>
  <provider android:name=".P" android:exported="true" android:permission="x.Y" android:authorities="com.demo.p"/>
 </application></manifest>"""


def make_apk(path: Path, manifest: bytes = MANIFEST, **extra: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", (FIXTURES / "retrofit_demo.dex").read_bytes())
        for name, data in extra.items():
            zf.writestr(name, data)
    return path


def scan(arg, *opts: str) -> Path:
    result = runner.invoke(cli_app, ["scan", str(arg), *map(str, opts)])
    assert result.exit_code == 0, result.output
    return max(load_config().target_base.glob("*/RUN_*"), key=lambda p: p.stat().st_mtime_ns)


def load(run: Path, rel: str):
    return json.loads((run / rel).read_text(encoding="utf-8"))


# --- end to end ---------------------------------------------------------------


def test_scan_end_to_end(tmp_path):
    run = scan(make_apk(tmp_path / "com.demo-1.2.apk"))  # dots used to crash

    perms = load(run, "android/permissions.json")
    assert perms["dangerous_count"] == 1  # used to be always 0
    comps = {c["class_name"]: c["unprotected"] for c in load(run, "android/components.json")["components"]}
    assert comps == {"com.demo.Main": False, "com.demo.Link": True, "com.demo.Sync": True, "com.demo.P": False}

    eps = {(e["method"], e["domain"], e["path"]): e for e in load(run, "api/endpoints.json")}
    user = eps["GET", "", "/api/v1/users/{id}"]
    assert (user["source_class"], user["source_method"]) == ("com.demo.Api", "user")
    assert user["path_params"] == ["id"] and user["query_params"] == [{"name": "expand", "type": "query"}]
    assert ("POST", "", "/login") in eps
    assert ("PATCH", "", "/orders/{oid}") in eps
    assert ("DELETE", "admin.demo.com", "/v2/sessions") in eps
    health = next(e for k, e in eps.items() if k[2] == "/health")
    assert health["source_class"] == "com.demo.Client"

    rows = list(csv.DictReader((run / "reports/components.csv").read_text(encoding="utf-8").splitlines()))
    assert "com.demo.Sync" in {r["class_name"] for r in rows}  # column used to be empty
    assert {r["is_dangerous"] for r in csv.DictReader((run / "reports/permissions.csv").read_text(encoding="utf-8").splitlines())} == {"True", "False"}

    mapping = {c["class_name"] for c in load(run, "mapping/android-api-map.json")["classes"]}
    assert "com.demo.Api" in mapping and not any(c.endswith((".dex", ".xml")) for c in mapping)
    # mapping and passports must agree on ids
    ids = {p["endpoint_id"]: p["path"] for p in load(run, "mapping/endpoint-passports.json")["passports"]}
    for e in load(run, "mapping/endpoint-sources.json")["endpoints"]:
        assert ids[e["endpoint_id"]] == e["path"]

    assert "https://demo.com/o" in (run / "exports/deep_links.txt").read_text()  # split <data>
    assert load(run, "exports/openapi.json")["openapi"].startswith("3.")
    postman = load(run, "exports/postman_collection.json")
    login = next(i for i in postman["item"] if i["name"].endswith("/login"))
    assert login["request"]["url"]["raw"].startswith("{{baseUrl}}/")  # never a guessed host
    assert (run / "logs/huntx.log").stat().st_size > 0


def test_rescan_ignores_previous_sessions_and_refreshes_apk(tmp_path):
    apk = make_apk(tmp_path / "app.apk")
    first = scan(apk)
    make_apk(apk, MANIFEST.replace(b"1.2", b"9.9"))
    second = scan(apk)
    assert first != second
    assert load(second, "android/apk-info.json")["version_name"] == "9.9"
    third = scan("app")  # by target name
    assert len(load(third, "session.json")["apk_files"]) == 1


def test_xapk_bundle_and_all_splits(tmp_path):
    base = make_apk(tmp_path / "com.demo.apk")
    split = tmp_path / "config.arm64_v8a.apk"
    with zipfile.ZipFile(split, "w") as zf:
        zf.writestr("AndroidManifest.xml", b'<manifest package="com.demo" split="config.arm64_v8a"/>')
        zf.writestr("lib/arm64-v8a/libflutter.so", b"x")
    with zipfile.ZipFile(tmp_path / "b.xapk", "w") as zf:
        zf.write(split, split.name)
        zf.write(base, base.name)
        zf.writestr("manifest.json", json.dumps({"package_name": "com.demo"}))
    run = scan(tmp_path / "b.xapk")
    assert load(run, "android/apk-info.json")["version_name"] == "1.2"
    assert "Flutter" in load(run, "android/security-audit.json")["fingerprint"]["frameworks"]


@pytest.mark.parametrize("name,data", [("a.apk", b"not a zip"), ("b.xapk", b"PK\x05\x06" + b"\0" * 18), ("c.txt", b"x")])
def test_bad_input_fails_cleanly(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    result = runner.invoke(cli_app, ["scan", str(path)])
    assert result.exit_code == 1
    assert "Traceback" not in result.output and isinstance(result.exception, SystemExit)


def test_cli_commands(tmp_path):
    scan(make_apk(tmp_path / "app.apk"))
    for args in (["--version"], ["targets"], ["apks", "app"], ["surface", "app"], ["timeline", "app"],
                 ["notes", "app", "--add", "check [bold]this[/bold]"], ["search", "app", "login"],
                 ["report", "app"], ["diff", "app", "app"]):
        result = runner.invoke(cli_app, args)
        assert result.exit_code == 0, (args, result.output)
    assert "/login" in runner.invoke(cli_app, ["search", "app", "login"]).output
    assert runner.invoke(cli_app, ["surface", "../.."]).exit_code == 1
    assert runner.invoke(cli_app, ["notes", "missing"]).exit_code == 1


def test_menu_full_recon_matches_scan(tmp_path, monkeypatch):
    from huntx.cli.menu import MenuSystem

    scan_run = scan(make_apk(tmp_path / "app.apk"))
    answers = iter(["1", "1", "y", "1", "all", "y", "0", "0", "0", "0"])
    monkeypatch.setattr(MenuSystem, "_get_input", lambda self, prompt: next(answers))
    monkeypatch.setattr(MenuSystem, "_press_enter", lambda self: None)
    with pytest.raises(SystemExit):
        MenuSystem().run()
    menu_run = max(scan_run.parent.glob("RUN_*"), key=lambda p: p.stat().st_mtime_ns)
    assert menu_run != scan_run
    key = lambda r: [(p["endpoint_id"], p["method"], p["path"], p["source_class"])  # noqa: E731
                     for p in load(r, "mapping/endpoint-passports.json")["passports"]]
    assert key(menu_run) == key(scan_run)
    assert (menu_run / "exports/adb_pocs.txt").exists()


def test_menu_resumes_real_session(tmp_path, monkeypatch):
    from huntx.cli.menu import MenuSystem

    run = scan(make_apk(tmp_path / "app.apk"))
    menu = MenuSystem()
    monkeypatch.setattr(menu, "_get_input", lambda prompt: "1")
    assert menu._resume_session(run.parent, []).run_path == run


# --- hostile input --------------------------------------------------------------


def test_html_report_is_inert_for_hostile_strings(tmp_path):
    from xml.sax.saxutils import quoteattr

    evil = quoteattr("a.b" + EVIL).encode()
    manifest = MANIFEST.replace(b'".Sync"', evil).replace(b'"Demo"', evil).replace(b'"24"', evil)
    run = scan(make_apk(tmp_path / "e.apk", manifest))
    for name in ("huntx-report.html", "huntx-summary.html"):
        page = (run / "reports" / name).read_text(encoding="utf-8")
        assert "<img src=x" not in page
        assert page.lower().count("</script>") == page.lower().count("<script")
        assert not re.search(r"""onclick="copyToClipboard\('""", page)


def test_adb_commands_survive_two_shells():
    from huntx.engines.android.security_audit import adb_shell

    for evil in ['x";reboot;"', "$(reboot)", "`id`", "a'b", "a\nreboot", "com.a/.B$C"]:
        cmd = adb_shell("am", "start", "-d", evil)
        assert "\n" not in cmd
        local = shlex.split(cmd)
        device = shlex.split(" ".join(local[2:]))
        assert device == ["am", "start", "-d", evil.replace("\n", "")]
    assert adb_shell("am", "start", "-n", "a.b/.C") == "adb shell am start -n a.b/.C"


def test_csv_formula_injection():
    from huntx.core.csvsafe import safe_row

    assert safe_row(["=cmd|x", "+1", "@a", "-2", "/ok", 5]) == ["'=cmd|x", "'+1", "'@a", "'-2", "/ok", 5]


def test_zip_bomb_and_zip_slip(tmp_path, monkeypatch):
    from huntx.core import safezip
    from huntx.core.session import unpack_xapk

    with zipfile.ZipFile(tmp_path / "z.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big", b"\0" * 100_000)
    with zipfile.ZipFile(tmp_path / "z.zip") as zf, pytest.raises(safezip.UnsafeArchiveError):
        safezip.read_member(zf, "big", limit=1000)

    with zipfile.ZipFile(tmp_path / "s.xapk", "w") as zf:
        zf.writestr("../../evil.apk", b"x")
        zf.writestr("/abs.apk", b"x")
    out = tmp_path / "out"
    out.mkdir()
    assert unpack_xapk(tmp_path / "s.xapk", out) == [] and not list(out.iterdir())


def test_xml_entities_rejected(tmp_path):
    from huntx.engines.traffic.burp import parse_burp_xml

    with pytest.raises(ValueError):
        parse_burp_xml('<!DOCTYPE a [<!ENTITY x "y">]><items>&x;</items>')


def test_truncated_dex_and_arsc_never_crash():
    from huntx.engines.android.arsc import parse_arsc
    from huntx.engines.android.axml import parse_axml
    from huntx.engines.android.dex_xref import analyze_dex_xrefs
    from huntx.engines.android.strings import parse_dex_strings

    dex = (FIXTURES / "retrofit_demo.dex").read_bytes()
    for i in range(0, len(dex), 7):
        for blob in (dex[:i], dex[:i] + b"\xff" * 8 + dex[i + 8 :]):
            parse_dex_strings(blob)
            parse_arsc(blob)
            parse_axml(blob)
            try:
                analyze_dex_xrefs(blob)
            except (struct.error, IndexError):
                pass  # the per-file handler in extract_apk_xrefs logs these


def test_huge_single_line_is_bounded():
    import time

    from huntx.engines.android.strings import classify_strings

    start = time.perf_counter()
    result = classify_strings([("a." * 100_000 + " https://late.example.com/api/v1/x", "assets/i.js")])
    assert time.perf_counter() - start < 10
    assert any(u["value"] == "https://late.example.com/api/v1/x" for u in result["urls"])


# --- engines --------------------------------------------------------------------


def _cert() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Signer")])
    now = dt.datetime(2026, 1, 1)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(99).not_valid_before(now).not_valid_after(now + dt.timedelta(days=9))
            .sign(key, hashes.SHA256()).public_bytes(Encoding.DER))


@pytest.mark.parametrize("block_id,scheme", [(0x7109871A, "v2_signed"), (0xF05368C0, "v3_signed")])
def test_signing_block_certificate(tmp_path, block_id, scheme):
    import hashlib

    from huntx.engines.android.apk_info import extract_apk_info

    apk = make_apk(tmp_path / "a.apk")
    assert not extract_apk_info(apk)["signing"]["v1_signed"]

    der, lp = _cert(), lambda b: struct.pack("<I", len(b)) + b
    value = lp(lp(lp(lp(b"digests") + lp(lp(der)) + lp(b""))))
    pair = struct.pack("<QI", len(value) + 4, block_id) + value
    size = len(pair) + 24
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    raw = bytearray(apk.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", raw, eocd + 16)[0]
    struct.pack_into("<I", raw, eocd + 16, cd + len(block))
    apk.write_bytes(bytes(raw[:cd]) + block + bytes(raw[cd:]))

    signing = extract_apk_info(apk)["signing"]
    assert signing[scheme] is True and signing["v1_signed"] is False
    cert = signing["certificates"][0]
    assert cert["subject"] == "CN=Signer"
    assert cert["sha256_fingerprint"].replace(":", "").lower() == hashlib.sha256(der).hexdigest()


def test_dalvik_descriptors_and_package_names_are_not_endpoints():
    from huntx.engines.android.strings import classify_strings

    res = classify_strings([
        ("Landroid/support/v4/content/Loader;", "classes.dex"),
        ("org/xmlpull/v1/XmlSerializer", "classes.dex"),
        ("com.example.app", "classes.dex"),
        ("https://real.example.com/api/v1/items", "classes.dex"),
        ("/api/v2/orders", "classes.dex"),
        ("de.wikipedia.org", "classes.dex"),
    ])
    assert [p["value"] for p in res["api_paths"]] == ["/api/v2/orders"]
    assert [d["value"] for d in res["domains"]] == ["de.wikipedia.org", "real.example.com"]


def test_shared_host_is_not_attribution():
    from huntx.engines.api.endpoints import match_xref

    xrefs = [("https://a.com/one", {"class_name": "One"}), ("https://a.com/two", {"class_name": "Two"})]
    assert match_xref({"domain": "a.com", "path": "/two"}, xrefs)["class_name"] == "Two"
    assert match_xref({"domain": "a.com", "path": "/three"}, xrefs) is None


def test_traffic_is_redacted_and_accumulates(tmp_path):
    har = {"log": {"entries": [{"startedDateTime": "2026-01-01T00:00:00Z", "request": {
        "method": "POST", "url": "https://a.com/api/login?access_token=SECRETURL&q=1",
        "headers": [{"name": "Authorization", "value": "Bearer SECRETHDR"}],
        "queryString": [{"name": "access_token", "value": "SECRETURL"}],
        "postData": {"mimeType": "application/json", "text": '{"user":"bob","password":"SECRETBODY"}'}},
        "response": {"status": 200, "headers": [], "content": {"text": '{"refresh_token":"SECRETRESP"}'}}}]}}
    (tmp_path / "t.har").write_text(json.dumps(har))
    (tmp_path / "t.xml").write_text(
        "<items><item><url>https://b.com/x?token=SECRETBURP</url><host>b.com</host><method>GET</method>"
        "<path>/x?token=SECRETBURP</path><status>200</status></item></items>")
    run = scan(make_apk(tmp_path / "app.apk"), "--har", tmp_path / "t.har")

    from huntx.engines.traffic.parser import run_traffic_analysis

    session = SessionManager(run.parent).load_session(run.name)
    run_traffic_analysis(session=session, source_files=[tmp_path / "t.xml"])
    run_traffic_analysis(session=session)  # re-analysis must not wipe imports
    hosts = {e["host"] for e in load(run, "traffic/requests.json")}
    assert hosts == {"a.com", "b.com"}
    for path in run.rglob("*"):
        if path.is_file():
            assert b"SECRET" not in path.read_bytes(), path


def test_find_apks_skips_run_dirs(tmp_path):
    (tmp_path / "RUN_1/input").mkdir(parents=True)
    (tmp_path / "RUN_1/input/a.apk").write_bytes(b"")
    (tmp_path / "a.apk").write_bytes(b"")
    assert [a.path for a in TargetManager(tmp_path).find_apks(tmp_path)] == [tmp_path / "a.apk"]


def test_arsc_default_value_wins():
    from huntx.engines.android.arsc import parse_arsc, resolve_reference

    def pool(*items: str) -> bytes:
        blobs = [bytes([len(s), len(s)]) + s.encode() + b"\0" for s in items]
        offs, pos = b"", 0
        for b in blobs:
            offs += struct.pack("<I", pos)
            pos += len(b)
        body = offs + b"".join(blobs)
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<HHIIIIII", 1, 28, 28 + len(body), len(items), 0, 0x100, 28 + len(offs), 0) + body

    def type_chunk(value_idx: int, lang: bytes) -> bytes:
        cfg = struct.pack("<I", 12) + b"\0" * 4 + lang.ljust(4, b"\0")
        hdr = 20 + len(cfg)
        entry = struct.pack("<HHIHBBI", 8, 0, 0, 8, 0, 3, value_idx)
        return struct.pack("<HHIBBHII", 0x201, hdr, hdr + 4 + len(entry), 1, 0, 0, 1, hdr + 4) + cfg + struct.pack("<I", 0) + entry

    types, keys = pool("string"), pool("app_name")
    body = types + keys + type_chunk(1, b"fr") + type_chunk(0, b"")
    pkg = struct.pack("<HHII", 0x200, 288, 288 + len(body), 0x7F) + b"\0" * 256
    pkg += struct.pack("<IIIII", 288, 1, 288 + len(types), 1, 0) + body
    values = pool("Default", "Francais")
    table = parse_arsc(struct.pack("<HHII", 2, 12, 12 + len(values) + len(pkg), 1) + values + pkg)
    assert table[0x7F010000] == ("string", "app_name", "Default")
    assert resolve_reference("@0x7f010000", table) == "Default"


def test_domains_ignore_emails_packages_and_resource_refs():
    from huntx.engines.android.strings import classify_strings

    res = classify_strings([(t, "classes.dex") for t in (
        "mail me@live.com", "x@mail.corp.io now", "libcore.io.DiskLruCache", "ctx.getString(R.string.no)",
        "first.me@corp.com", "host api.real.io:443", "see docs.site.org.", "shop.co.uk")])
    assert [d["value"] for d in res["domains"]] == ["api.real.io", "docs.site.org", "shop.co.uk"]
    assert "me@live.com" in {e["value"] for e in res["emails"]}


def test_configuration_findings_reach_every_report(tmp_path):
    nsc = b"""<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors>
      <certificates src="system"/><certificates src="user"/></trust-anchors></base-config></network-security-config>"""
    manifest = MANIFEST.replace(b'android:label="Demo"', b'android:label="Demo" android:networkSecurityConfig="@xml/n"')
    run = scan(make_apk(tmp_path / "c.apk", manifest, **{"res/xml/network_security_config.xml": nsc}))
    titles = {c["title"] for c in load(run, "reports/huntx-report.json")["findings"]["configuration"]}
    assert titles >= {"Cleartext HTTP traffic permitted", "User-installed CA certificates trusted",
                      "Application is debuggable", "Application backup allowed"}
    for rel in ("exports/bounty_drafts.md", "reports/huntx-summary.html", "reports/huntx-report.html"):
        text = (run / rel).read_text(encoding="utf-8")
        assert all(t in text for t in titles), rel
    assert "CWE-798" not in (run / "exports/bounty_drafts.md").read_text()


def test_configuration_findings_precedence():
    from huntx.engines.android.config_findings import config_findings

    def ids(flags, nsc, sdk, subject=""):
        info = {"target_sdk": sdk, "signing": {"certificates": [{"subject": subject}]}}
        return [c["id"] for c in config_findings({"flags": flags}, nsc, info)]

    off = {"allow_backup": False}
    assert ids(off, {}, "34") == []
    assert ids(off, {}, "26") == ["cleartext"]
    assert ids({**off, "uses_cleartext_traffic": True}, {}, "34") == ["cleartext"]
    # the security config overrides the manifest flag
    cfg = {"present": True, "source_file": "n.xml", "base_cleartext_permitted": False}
    assert ids({**off, "uses_cleartext_traffic": True}, cfg, "34") == []
    assert ids(off, {**cfg, "debug_trust_anchors": [{"src": "user"}]}, "34") == []
    assert ids(off, {}, "34", "C=US,O=Android,CN=Android Debug") == ["debug_cert"]
