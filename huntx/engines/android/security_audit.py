"""HUNTX Passive Security Audit, Fingerprinting & PoC Generator.

Performs strictly passive, read-only reconnaissance over APK containers and
extracted session artifacts:
  - Mobile Framework Fingerprinting (Native, Flutter, React Native, Cordova, Unity, Xamarin)
  - Defense Fingerprinting (SSL Pinning, Root/Frida detection)
  - WebView Risk Signal Detection
  - Passive JWT Header/Payload Decoding
  - Ready-to-run ADB PoC Generation for Exported Components, Deep Links & Content Providers

Outputs:
  - android/security-audit.json
"""
from __future__ import annotations

import base64
import json
import logging
import re
import shlex
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from huntx.core.safezip import read_member
from huntx.engines.android.components import is_unprotected

logger = logging.getLogger(__name__)


def _decode_jwt_passive(token: str) -> Optional[Dict[str, Any]]:
    """Passively base64-decode a JWT header and payload without modifying or verifying."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        def _b64_json(seg: str) -> Any:
            pad = "=" * (-len(seg) % 4)
            raw = base64.urlsafe_b64decode(seg + pad)
            return json.loads(raw.decode("utf-8", errors="replace"))

        header = _b64_json(parts[0])
        payload = _b64_json(parts[1])
        return {"header": header, "payload": payload}
    except Exception:
        return None


_DEFENSES = [
    (b"Lokhttp3/CertificatePinner$Builder;", "OkHttp CertificatePinner bundled (confirm pins are configured)"),
    (b"TrustKit", "TrustKit SSL Pinning"),
    (b"RootBeer", "RootBeer Root Detection"),
    (b"/system/bin/su", "SU Binary Root Check"),
    (b"re.frida.server", "Frida Server Detection"),
    (b"XposedBridge", "Xposed Framework Detection"),
]
_WEBVIEW = [
    (b"addJavascriptInterface", "WebView.addJavascriptInterface (JS Bridge)"),
    (b"setJavaScriptEnabled", "WebView.setJavaScriptEnabled"),
    (b"setAllowFileAccessFromFileURLs", "WebView.setAllowFileAccessFromFileURLs"),
    (b"setAllowUniversalAccessFromFileURLs", "WebView.setAllowUniversalAccessFromFileURLs"),
    (b"onReceivedSslError", "WebViewClient.onReceivedSslError (Check for handler.proceed())"),
]
_NETWORK_LIBS = [
    (b"Lokhttp3/", "OkHttp"),
    (b"Lretrofit2/", "Retrofit"),
    (b"Lcom/android/volley/", "Volley"),
    (b"Lorg/apache/http/", "Apache HttpClient"),
    (b"Lorg/chromium/net/Cronet", "Cronet"),
    (b"Lio/ktor/", "Ktor"),
    (b"Lio/grpc/", "gRPC"),
    (b"Ljava/net/HttpURLConnection;", "HttpURLConnection"),
]
_FRAMEWORKS = [
    (("libflutter.so",), "Flutter"),
    (("index.android.bundle", "libreactnativejni.so", "libreactnative.so"), "React Native"),
    (("libmonodroid.so", "libmonosgen-2.0.so"), "Xamarin / .NET MAUI"),
    (("libunity.so",), "Unity"),
]


def _fingerprint_apk_container(apk_paths: Path | Iterable[Path]) -> Dict[str, Any]:
    """Inspect ZIP entries and DEX markers across an APK and its splits."""
    paths = [apk_paths] if isinstance(apk_paths, Path) else list(apk_paths)
    paths = [p for p in paths if p.is_file()]
    if not paths:
        return {
            "frameworks": ["Unknown"], "defenses": [], "webview_signals": [],
            "networking_libraries": [], "native_libs_count": 0,
        }

    frameworks: Set[str] = set()
    hits: Set[bytes] = set()
    native_libs, has_nsc = 0, False
    markers = [m for m, _ in _DEFENSES + _WEBVIEW + _NETWORK_LIBS]

    for path in paths:
        try:
            with zipfile.ZipFile(path) as zf:
                for n in zf.namelist():
                    nl = n.lower()
                    native_libs += nl.endswith(".so")
                    has_nsc = has_nsc or n == "res/xml/network_security_config.xml"
                    for needles, label in _FRAMEWORKS:
                        if any(x in nl for x in needles):
                            frameworks.add(label)
                    if nl.startswith("assets/www/") and nl.endswith(".html"):
                        frameworks.add("Cordova / Capacitor / Ionic")
                    if nl.startswith("assemblies/") and nl.endswith((".dll", ".blob")):
                        frameworks.add("Xamarin / .NET MAUI")
                    if n.startswith("classes") and n.endswith(".dex"):
                        dex = read_member(zf, n)  # one DEX in memory at a time
                        hits.update(m for m in markers if m not in hits and m in dex)
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            logger.warning("Fingerprinting failed on %s: %s", path, exc)

    defenses = [label for m, label in _DEFENSES if m in hits]
    if has_nsc:
        defenses.append("Network Security Config XML Present")
    return {
        "frameworks": sorted(frameworks) or ["Native Android (Java/Kotlin)"],
        "defenses": defenses,
        "webview_signals": [label for m, label in _WEBVIEW if m in hits],
        "networking_libraries": [label for m, label in _NETWORK_LIBS if m in hits],
        "native_libs_count": native_libs,
    }


def adb_shell(*args: str) -> str:
    """Build a copy-paste-safe ``adb shell`` command.

    Arguments come from a hostile manifest and are parsed twice: by the
    analyst's shell and again by the device shell. Quote for both.
    """
    inner = shlex.join(re.sub(r"[\x00-\x1f\x7f]", "", a) for a in args)
    return f"adb shell {inner if inner == shlex.quote(inner) or _PLAIN.fullmatch(inner) else shlex.quote(inner)}"


# shlex.join already quoted anything unsafe, so unquoted text is inert in both shells
_PLAIN = re.compile(r"[\w@%+=:,./ -]*", re.ASCII)


def _generate_adb_pocs(package_name: str, components: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Generate copy-pasteable ADB verification commands for exported components."""
    pocs: List[Dict[str, str]] = []
    if not package_name:
        return pocs

    for comp in components:
        if not comp.get("exported"):
            continue
        name = comp.get("name", "")
        ctype = comp.get("component_type", "activity").lower()
        perm = comp.get("permission")

        if ctype == "activity":
            # Check deep links
            has_deeplink = False
            links = 0
            for flt in comp.get("intent_filters", []):
                for data in flt.get("data", []):
                    scheme = data.get("scheme", "")
                    host = data.get("host", "")
                    path_p = data.get("pathPrefix", "") or data.get("path", "") or ""
                    if scheme and links < 10:  # one app can declare thousands of patterns
                        has_deeplink = True
                        links += 1
                        uri = f"{scheme}://{host}{path_p}" if host else f"{scheme}://{path_p}"
                        pocs.append({
                            "type": "Deep Link Activity" + (" (Unprotected)" if not perm else ""),
                            "component": name,
                            "command": adb_shell("am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", uri, package_name),
                        })
            if not has_deeplink and is_unprotected({"component_type": "activity", **comp}):
                pocs.append({
                    "type": "Exported Activity (No Permission)",
                    "component": name,
                    "command": adb_shell("am", "start", "-n", f"{package_name}/{name}"),
                })

        elif ctype == "service" and not perm:
            pocs.append({
                "type": "Exported Service (No Permission)",
                "component": name,
                "command": adb_shell("am", "startservice", "-n", f"{package_name}/{name}"),
            })

        elif ctype == "receiver" and not perm:
            pocs.append({
                "type": "Exported Receiver (No Permission)",
                "component": name,
                "command": adb_shell("am", "broadcast", "-n", f"{package_name}/{name}"),
            })

        elif ctype == "provider" and is_unprotected(comp):
            auths = comp.get("authorities") or ""
            for auth in str(auths).split(";"):
                auth = auth.strip()
                if auth:
                    pocs.append({
                        "type": "Exported Content Provider",
                        "component": name,
                        "command": adb_shell("content", "query", "--uri", f"content://{auth}/"),
                    })

    return pocs


def run_security_audit(
    apk_path: Path | Iterable[Path],
    run_path: Path,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run passive security audit, fingerprinting, JWT decode, and ADB PoC generation."""
    android_dir = output_dir or (run_path / "android")
    android_dir.mkdir(parents=True, exist_ok=True)

    # Load existing static outputs
    def _load(p: Path, default: Any) -> Any:
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return default

    apk_info = _load(android_dir / "apk-info.json", {})
    comp_data = _load(android_dir / "components.json", {})
    str_data = _load(android_dir / "strings.json", {})

    pkg_name = apk_info.get("package_name", "")
    components = comp_data.get("components", []) if isinstance(comp_data, dict) else []
    tokens = str_data.get("tokens", []) if isinstance(str_data, dict) else []

    fingerprint = _fingerprint_apk_container(apk_path)
    adb_pocs = _generate_adb_pocs(pkg_name, components)

    # Decode any discovered JWTs passively
    decoded_jwts: List[Dict[str, Any]] = []
    cloud_assets: List[Dict[str, str]] = []
    secrets: List[Dict[str, str]] = []

    cloud_types = {"aws_s3_bucket", "gcs_bucket", "azure_blob", "firebase_db"}
    for tok in tokens:
        t_type = tok.get("token_type", "")
        val = tok.get("value", "")
        src = tok.get("source", "")
        if t_type == "jwt_token":
            dec = _decode_jwt_passive(val)
            if dec:
                decoded_jwts.append({"token_preview": val[:32] + "...", "source": src, "decoded": dec})
            secrets.append({"type": t_type, "value": val, "source": src})
        elif t_type in cloud_types:
            cloud_assets.append({"type": t_type, "value": val, "source": src})
        else:
            secrets.append({"type": t_type, "value": val, "source": src})

    result = {
        "package_name": pkg_name,
        "fingerprint": fingerprint,
        "secrets_count": len(secrets),
        "secrets": secrets,
        "cloud_assets_count": len(cloud_assets),
        "cloud_assets": cloud_assets,
        "decoded_jwts": decoded_jwts,
        "adb_pocs_count": len(adb_pocs),
        "adb_pocs": adb_pocs,
    }

    out_file = android_dir / "security-audit.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
