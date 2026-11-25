"""HUNTX APK Information Engine.

Extracts core APK metadata:
- APK filename, SHA-256 hash, size
- Package name, application name, version name, version code
- Minimum, target, and maximum SDK versions
- Supported ABIs (native libraries)
- Signing certificate information (v1/v2/v3 signatures, fingerprints, subjects)

Outputs:
- android/apk-info.json
- android/apk-info.txt
"""
from __future__ import annotations

import hashlib
import json
import logging
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntx.core.safezip import read_member
from huntx.engines.android.arsc import load_arsc, resolve_reference
from huntx.engines.android.axml import parse_axml
from huntx.engines.android.signing import inspect_signing

logger = logging.getLogger(__name__)


def _get_attr(elem: ET.Element, attr_name: str, default: Any = None) -> Any:
    """Robust attribute lookup handling plain, android:, and XMLNS prefixed names."""
    if attr_name in elem.attrib:
        return elem.attrib[attr_name]
    android_name = f"android:{attr_name}"
    if android_name in elem.attrib:
        return elem.attrib[android_name]
    ns_name = f"{{http://schemas.android.com/apk/res/android}}{attr_name}"
    if ns_name in elem.attrib:
        return elem.attrib[ns_name]
    for k, v in elem.attrib.items():
        stripped = k.split("}")[-1].split(":")[-1]
        if stripped == attr_name:
            return v
    return default


@dataclass
class CertificateInfo:
    """Certificate metadata."""

    subject: str = "Unknown"
    issuer: str = "Unknown"
    sha256_fingerprint: str = ""
    sha1_fingerprint: str = ""
    md5_fingerprint: str = ""
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SigningInfo:
    """APK signing scheme information."""

    v1_signed: bool = False
    v2_signed: bool = False
    v3_signed: bool = False
    certificates: List[CertificateInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v1_signed": self.v1_signed,
            "v2_signed": self.v2_signed,
            "v3_signed": self.v3_signed,
            "certificates": [c.to_dict() for c in self.certificates],
        }


@dataclass
class APKInfo:
    """Complete APK metadata record."""

    filename: str = ""
    sha256: str = ""
    size_bytes: int = 0
    size_human: str = "0 B"
    package_name: str = ""
    application_name: str = ""
    version_name: str = ""
    version_code: Optional[int] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    max_sdk: Optional[str] = None
    supported_abis: List[str] = field(default_factory=list)
    signing: SigningInfo = field(default_factory=SigningInfo)
    hashes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["signing"] = self.signing.to_dict()
        return d


def _format_size(size_bytes: int) -> str:
    """Format size in human readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size_bytes)} {unit}"
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} B"


def _compute_hashes(path: Path) -> Dict[str, str]:
    """Compute SHA-256, SHA-1, and MD5 hashes of a file."""
    h_sha256 = hashlib.sha256()
    h_sha1 = hashlib.sha1()
    h_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)
    return {
        "sha256": h_sha256.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "md5": h_md5.hexdigest(),
    }


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    return _compute_hashes(path)["sha256"]


def _extract_abis(zip_file: zipfile.ZipFile) -> List[str]:
    """Extract supported native ABIs from lib/ directory."""
    abis = set()
    for name in zip_file.namelist():
        parts = name.split("/")
        if len(parts) >= 3 and parts[0] == "lib" and parts[2].endswith(".so"):
            abi = parts[1]
            if abi:
                abis.add(abi)
        elif len(parts) >= 2 and parts[0] == "lib" and parts[1]:
            abi = parts[1]
            if not abi.endswith(".so") and not abi.endswith("/"):
                abis.add(abi)
    return sorted(list(abis))


def _extract_certs(zip_file: zipfile.ZipFile, apk_path: Path) -> SigningInfo:
    """Extract signing schemes and X.509 signer certificates."""
    info = inspect_signing(zip_file, apk_path)
    certs = [CertificateInfo(**c) for c in info.pop("certificates")]
    return SigningInfo(**info, certificates=certs)


def extract_apk_info(
    apk_path: str | Path,
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Extract complete APK information and optionally write outputs.

    Args:
        apk_path: Path to the .apk file.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `apk-info.json` and `apk-info.txt`.

    Returns:
        Dict representing the extracted APK information.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK file not found: {path}")

    size_bytes = path.stat().st_size
    size_human = _format_size(size_bytes)
    file_hashes = _compute_hashes(path)
    sha256_hash = file_hashes["sha256"]

    package_name = ""
    app_name = ""
    version_name = ""
    version_code: Optional[int] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    max_sdk: Optional[str] = None
    supported_abis: List[str] = []
    signing = SigningInfo()

    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = zf.namelist()

            if "AndroidManifest.xml" in namelist:
                supported_abis = _extract_abis(zf)
                signing = _extract_certs(zf, path)
                manifest_data = read_member(zf, "AndroidManifest.xml")
                elem = parse_axml(manifest_data)
                resources = load_arsc(zf)
                if elem is not None:
                    package_name = _get_attr(elem, "package", "")

                    vc_raw = _get_attr(elem, "versionCode")
                    if vc_raw is not None and str(vc_raw).isdigit():
                        version_code = int(str(vc_raw))

                    version_name = str(resolve_reference(_get_attr(elem, "versionName", ""), resources))

                    for child in elem:
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if tag == "application":
                            app_name = (
                                resolve_reference(_get_attr(child, "label"), resources)
                                or _get_attr(child, "name")
                                or ""
                            )
                        elif tag == "uses-sdk":
                            min_sdk = _get_attr(child, "minSdkVersion")
                            target_sdk = _get_attr(child, "targetSdkVersion")
                            max_sdk = _get_attr(child, "maxSdkVersion")
            else:
                # XAPK / Split container handling
                import io
                if "manifest.json" in namelist:
                    try:
                        m_raw = json.loads(read_member(zf, "manifest.json").decode("utf-8", errors="ignore"))
                        package_name = m_raw.get("package_name", "")
                        app_name = m_raw.get("name", "")
                        version_name = str(m_raw.get("version_name", ""))
                        if m_raw.get("version_code"):
                            version_code = int(m_raw.get("version_code"))
                        min_sdk = str(m_raw.get("min_sdk_version", "")) or None
                        target_sdk = str(m_raw.get("target_sdk_version", "")) or None
                    except Exception as ex:
                        logger.debug("Failed reading manifest.json inside container: %s", ex)

                apk_entries = [n for n in namelist if n.lower().endswith(".apk")]
                if apk_entries:
                    def _entry_key(n: str):
                        nl = n.lower()
                        if "base" in nl or (package_name and package_name.lower() in nl):
                            return (0, -zf.getinfo(n).file_size)
                        if nl.startswith("config.") or nl.startswith("split_"):
                            return (2, -zf.getinfo(n).file_size)
                        return (1, -zf.getinfo(n).file_size)

                    apk_entries.sort(key=_entry_key)
                    primary_entry = apk_entries[0]
                    try:
                        inner_bytes = read_member(zf, primary_entry)
                        with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner_zf:
                            supported_abis = _extract_abis(inner_zf)
                            resources = load_arsc(inner_zf)
                            if "AndroidManifest.xml" in inner_zf.namelist():
                                inner_manifest = read_member(inner_zf, "AndroidManifest.xml")
                                elem = parse_axml(inner_manifest)
                                if elem is not None:
                                    if not package_name:
                                        package_name = _get_attr(elem, "package", "")
                                    vc_raw = _get_attr(elem, "versionCode")
                                    if version_code is None and vc_raw is not None and str(vc_raw).isdigit():
                                        version_code = int(str(vc_raw))
                                    if not version_name:
                                        version_name = str(_get_attr(elem, "versionName", ""))
                                    for child in elem:
                                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                                        if tag == "application" and not app_name:
                                            app_name = (
                                                resolve_reference(_get_attr(child, "label"), resources)
                                                or _get_attr(child, "name")
                                                or ""
                                            )
                                        elif tag == "uses-sdk":
                                            if min_sdk is None:
                                                min_sdk = _get_attr(child, "minSdkVersion")
                                            if target_sdk is None:
                                                target_sdk = _get_attr(child, "targetSdkVersion")
                                            if max_sdk is None:
                                                max_sdk = _get_attr(child, "maxSdkVersion")
                    except Exception as ex:
                        logger.debug("Failed inspecting inner APK %s: %s", primary_entry, ex)

    except zipfile.BadZipFile:
        logger.warning("File is not a valid zip archive: %s", path)
    except Exception as e:
        logger.error("Error inspecting APK %s: %s", path, e)

    # Resolve application name if missing or raw resource identifier e.g. @0x7f12035b
    if not app_name or app_name.startswith("@") or app_name.lower() == "unknown":
        parent_manifest = path.parent / "manifest.json"
        if parent_manifest.exists():
            try:
                with open(parent_manifest, "r", encoding="utf-8") as f:
                    m_data = json.load(f)
                    if m_data.get("name"):
                        app_name = m_data.get("name")
            except (OSError, ValueError, AttributeError) as ex:
                logger.debug("Ignoring bundle manifest %s: %s", parent_manifest, ex)

        if (not app_name or app_name.startswith("@") or app_name.lower() == "unknown") and package_name and package_name != "unknown.package":
            parts = package_name.split(".")
            candidate = parts[-1]
            if candidate in ("app", "mobile", "android") and len(parts) >= 2:
                candidate = parts[-2]
            app_name = candidate.capitalize()

    info = APKInfo(
        filename=path.name,
        sha256=sha256_hash,
        size_bytes=size_bytes,
        size_human=size_human,
        package_name=package_name or "unknown.package",
        application_name=app_name or (package_name.split(".")[-1] if package_name else "Unknown"),
        version_name=version_name or "unknown",
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        max_sdk=max_sdk,
        supported_abis=supported_abis,
        signing=signing,
        hashes=file_hashes,
    )

    info_dict = info.to_dict()

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        json_file = out_path / "apk-info.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(info_dict, f, indent=2)

        txt_file = out_path / "apk-info.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(format_apk_info_txt(info))

    return info_dict


def format_apk_info_txt(info: APKInfo) -> str:
    """Format APKInfo into clean human-readable text."""
    lines = [
        "=" * 80,
        "HUNTX - APK INFORMATION REPORT",
        "=" * 80,
        f"Filename       : {info.filename}",
        f"Size           : {info.size_human} ({info.size_bytes:,} bytes)",
        f"SHA-256        : {info.sha256}",
        "",
        "APPLICATION IDENTITY",
        "-" * 80,
        f"Package Name   : {info.package_name}",
        f"Application    : {info.application_name}",
        f"Version Name   : {info.version_name}",
        f"Version Code   : {info.version_code if info.version_code is not None else 'N/A'}",
        "",
        "SDK REQUIREMENTS",
        "-" * 80,
        f"Min SDK        : {info.min_sdk or 'N/A'}",
        f"Target SDK     : {info.target_sdk or 'N/A'}",
        f"Max SDK        : {info.max_sdk or 'N/A'}",
        "",
        "SUPPORTED ARCHITECTURES (ABIs)",
        "-" * 80,
        f"Supported ABIs : {', '.join(info.supported_abis) if info.supported_abis else 'None (Pure Java/Kotlin)'}",
        "",
        "SIGNING INFORMATION",
        "-" * 80,
        f"Scheme v1 (JAR): {'Yes' if info.signing.v1_signed else 'No'}",
        f"Scheme v2 (APK): {'Yes' if info.signing.v2_signed else 'No'}",
        f"Scheme v3 (APK): {'Yes' if info.signing.v3_signed else 'No'}",
    ]

    if info.signing.certificates:
        lines.append("Certificates   :")
        for idx, cert in enumerate(info.signing.certificates, 1):
            lines.append(f"  [{idx}] Subject   : {cert.subject}")
            lines.append(f"      Issuer    : {cert.issuer}")
            lines.append(f"      SHA-256 FP: {cert.sha256_fingerprint}")
            lines.append(f"      SHA-1 FP  : {cert.sha1_fingerprint}")
            lines.append(f"      MD5 FP    : {cert.md5_fingerprint}")
    else:
        lines.append("Certificates   : None observed")

    lines.append("=" * 80)
    lines.append("")
    return "\n".join(lines)
