"""Evidence-backed configuration findings shared by every report and export."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


def effective_cleartext(flags: Dict[str, Any], nsc: Dict[str, Any], target_sdk: Any) -> Tuple[bool, str]:
    """Is cleartext allowed app-wide, and why. A security config overrides the manifest flag."""
    default = str(target_sdk).isdigit() and int(target_sdk) < 28
    if nsc.get("present"):
        base = nsc.get("base_cleartext_permitted")
        if base is not None:
            return bool(base), f"{nsc.get('source_file')} base-config sets cleartextTrafficPermitted={str(base).lower()}"
    elif flags.get("uses_cleartext_traffic") is not None:
        value = bool(flags["uses_cleartext_traffic"])
        return value, f"android:usesCleartextTraffic={str(value).lower()}"
    return default, f"Platform default for targetSdk {target_sdk}"


def config_findings(manifest: Dict[str, Any], nsc: Dict[str, Any], apk_info: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return findings as dicts of id, title, severity, cwe, evidence and verify."""
    flags = manifest.get("security_flags") or manifest.get("flags") or {}
    sdk = apk_info.get("target_sdk")
    pkg = apk_info.get("package_name") or manifest.get("package") or "PACKAGE"
    out: List[Dict[str, str]] = []

    def add(id_: str, title: str, severity: str, cwe: str, evidence: str, verify: str) -> None:
        out.append({"id": id_, "title": title, "severity": severity, "cwe": cwe, "evidence": evidence, "verify": verify})

    if flags.get("debuggable"):
        add("debuggable", "Application is debuggable", "HIGH", "CWE-489 (Active Debug Code)",
            'AndroidManifest.xml sets android:debuggable="true".', f"adb shell run-as {pkg} id")

    allowed, why = effective_cleartext(flags, nsc, sdk)
    domains = [d["domain"] for dc in nsc.get("domain_configs", []) if dc.get("cleartext_traffic_permitted")
               for d in dc.get("domains", []) if d.get("domain")]
    if allowed or domains:
        evidence = why if allowed else "Cleartext allowed for: " + ", ".join(domains[:10])
        add("cleartext", "Cleartext HTTP traffic permitted", "MEDIUM",
            "CWE-319 (Cleartext Transmission of Sensitive Information)", evidence,
            "Proxy the app and check whether sensitive data is actually sent over http://")

    anchors = list(nsc.get("base_trust_anchors", []))
    for dc in nsc.get("domain_configs", []):
        anchors += dc.get("trust_anchors", [])
    if any(a.get("src") == "user" for a in anchors):
        add("user_ca", "User-installed CA certificates trusted", "MEDIUM",
            "CWE-295 (Improper Certificate Validation)",
            f"{nsc.get('source_file')} trusts src=user outside debug-overrides.",
            "Install a proxy CA as a user certificate and check whether HTTPS is readable")
    elif str(sdk).isdigit() and int(sdk) < 24 and not nsc.get("base_trust_anchors"):
        add("user_ca", "User-installed CA certificates trusted", "MEDIUM",
            "CWE-295 (Improper Certificate Validation)",
            f"Platform default for targetSdk {sdk} (below 24).",
            "Install a proxy CA as a user certificate and check whether HTTPS is readable")

    if flags.get("allow_backup"):
        add("backup", "Application backup allowed", "LOW",
            "CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere)",
            "android:allowBackup is true (explicitly or by platform default).",
            f"adb backup -f app.ab {pkg}  (limited on Android 12+ for targetSdk 31+)")

    signers = (apk_info.get("signing") or {}).get("certificates", [])
    if any("CN=Android Debug" in c.get("subject", "") for c in signers):
        add("debug_cert", "Signed with an Android debug certificate", "INFO", "",
            "Signer subject contains CN=Android Debug.", "Confirm this is not the production build")
    return out
