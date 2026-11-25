"""HUNTX Android Resources Analysis Engine.

Inspects XML resources, network security config, string resources, and assets:
- res/xml/network_security_config.xml:
  - cleartextTrafficPermitted flags
  - domain-config (domain rules, includeSubdomains)
  - pin-set (certificate pinning, digests, expirations)
  - trust-anchors (system, user, custom certificates)
  - debug-overrides (user certificate trust)
- res/values/strings.xml and string resource tables
- assets/ files and configuration files (google-services.json, awsconfiguration.json, etc.)

Outputs:
- android/resources.json
- android/resources.txt
"""
from __future__ import annotations

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

logger = logging.getLogger(__name__)


@dataclass
class CertificatePin:
    """Certificate pin entry."""

    digest: str
    pin: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PinSet:
    """Pin set configuration."""

    expiration: Optional[str] = None
    pins: List[CertificatePin] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expiration": self.expiration,
            "pins": [p.to_dict() for p in self.pins],
        }


@dataclass
class TrustAnchor:
    """Certificate trust anchor."""

    src: str  # system, user, @raw/...
    override_pins: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainConfig:
    """Domain-specific network security rule."""

    domains: List[Dict[str, Any]] = field(default_factory=list)
    cleartext_traffic_permitted: Optional[bool] = None
    pin_set: Optional[PinSet] = None
    trust_anchors: List[TrustAnchor] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": self.domains,
            "cleartext_traffic_permitted": self.cleartext_traffic_permitted,
            "pin_set": self.pin_set.to_dict() if self.pin_set else None,
            "trust_anchors": [t.to_dict() for t in self.trust_anchors],
        }


@dataclass
class NetworkSecurityConfig:
    """Complete network security configuration."""

    present: bool = False
    source_file: Optional[str] = None
    base_cleartext_permitted: Optional[bool] = None
    base_trust_anchors: List[TrustAnchor] = field(default_factory=list)
    domain_configs: List[DomainConfig] = field(default_factory=list)
    debug_trust_anchors: List[TrustAnchor] = field(default_factory=list)
    allows_user_certs_in_debug: bool = False
    has_certificate_pinning: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "source_file": self.source_file,
            "base_cleartext_permitted": self.base_cleartext_permitted,
            "base_trust_anchors": [t.to_dict() for t in self.base_trust_anchors],
            "domain_configs": [d.to_dict() for d in self.domain_configs],
            "debug_trust_anchors": [t.to_dict() for t in self.debug_trust_anchors],
            "allows_user_certs_in_debug": self.allows_user_certs_in_debug,
            "has_certificate_pinning": self.has_certificate_pinning,
        }


@dataclass
class AssetFile:
    """An asset entry within the APK."""

    path: str
    size_bytes: int
    is_config: bool
    config_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_bool(val: Optional[str], default: Optional[bool] = None) -> Optional[bool]:
    """Helper to parse boolean attributes."""
    if val is None:
        return default
    v = str(val).strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    return default


def parse_network_security_config(xml_data: bytes, source_name: str = "") -> NetworkSecurityConfig:
    """Parse network security config XML into a structured configuration."""
    elem = parse_axml(xml_data)
    if elem is None:
        return NetworkSecurityConfig(present=False)

    nsc = NetworkSecurityConfig(present=True, source_file=source_name)

    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag

        if tag == "base-config":
            c_raw = child.attrib.get("cleartextTrafficPermitted")
            nsc.base_cleartext_permitted = _parse_bool(c_raw)
            for sub in child:
                sub_tag = sub.tag.split("}")[-1] if "}" in sub.tag else sub.tag
                if sub_tag == "trust-anchors":
                    for cert in sub:
                        src = cert.attrib.get("src", "system")
                        override = _parse_bool(cert.attrib.get("overridePins"), default=False) or False
                        nsc.base_trust_anchors.append(TrustAnchor(src=src, override_pins=override))

        elif tag == "domain-config":
            dc = _parse_domain_config(child)
            nsc.domain_configs.append(dc)
            if dc.pin_set and dc.pin_set.pins:
                nsc.has_certificate_pinning = True

        elif tag == "debug-overrides":
            for sub in child:
                sub_tag = sub.tag.split("}")[-1] if "}" in sub.tag else sub.tag
                if sub_tag == "trust-anchors":
                    for cert in sub:
                        src = cert.attrib.get("src", "user")
                        override = _parse_bool(cert.attrib.get("overridePins"), default=False) or False
                        nsc.debug_trust_anchors.append(TrustAnchor(src=src, override_pins=override))
                        if src == "user":
                            nsc.allows_user_certs_in_debug = True

    return nsc


def _parse_domain_config(elem: ET.Element) -> DomainConfig:
    """Parse an individual <domain-config> element."""
    dc = DomainConfig()
    c_raw = elem.attrib.get("cleartextTrafficPermitted")
    dc.cleartext_traffic_permitted = _parse_bool(c_raw)

    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag

        if tag == "domain":
            dom_name = (child.text or "").strip()
            include_sub = _parse_bool(child.attrib.get("includeSubdomains"), default=False) or False
            if dom_name:
                dc.domains.append({"domain": dom_name, "include_subdomains": include_sub})

        elif tag == "pin-set":
            expiration = child.attrib.get("expiration")
            pins = []
            for pin_elem in child:
                pin_tag = pin_elem.tag.split("}")[-1] if "}" in pin_elem.tag else pin_elem.tag
                if pin_tag == "pin":
                    digest = pin_elem.attrib.get("digest", "SHA-256")
                    pin_val = (pin_elem.text or "").strip()
                    if pin_val:
                        pins.append(CertificatePin(digest=digest, pin=pin_val))
            dc.pin_set = PinSet(expiration=expiration, pins=pins)

        elif tag == "trust-anchors":
            for cert in child:
                src = cert.attrib.get("src", "system")
                override = _parse_bool(cert.attrib.get("overridePins"), default=False) or False
                dc.trust_anchors.append(TrustAnchor(src=src, override_pins=override))

        elif tag == "domain-config":
            # Nested domain config
            nested_dc = _parse_domain_config(child)
            dc.domains.extend(nested_dc.domains)
            if nested_dc.pin_set:
                dc.pin_set = nested_dc.pin_set

    return dc


def parse_string_resources(xml_data: bytes) -> Dict[str, str]:
    """Parse string resources from a values/strings.xml file."""
    elem = parse_axml(xml_data)
    strings: Dict[str, str] = {}
    if elem is None:
        return strings

    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "string":
            name = child.attrib.get("name")
            text = (child.text or "").strip()
            if name:
                strings[name] = text
    return strings


def analyze_resources(
    apk_path: str | Path,
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Analyze resources in an APK or unpacked directory.

    Args:
        apk_path: Path to the APK file or directory.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `resources.json` and `resources.txt`.

    Returns:
        Dict representing resource analysis.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"Target not found: {path}")

    nsc = NetworkSecurityConfig()
    string_resources: Dict[str, str] = {}
    assets: List[AssetFile] = []
    config_files: Dict[str, Any] = {}

    if path.is_file():
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()

                table = load_arsc(zf)

                # 1. Network security config: follow the manifest reference (file
                # names are routinely obfuscated), else fall back to the usual name
                nsc_ref = None
                if "AndroidManifest.xml" in names:
                    app = parse_axml(read_member(zf, "AndroidManifest.xml")).find("application")
                    if app is not None:
                        nsc_ref = resolve_reference(app.get("android:networkSecurityConfig"), table)
                nsc_candidates = [nsc_ref] if nsc_ref in names else [
                    n for n in names if n.endswith("network_security_config.xml") or n.endswith("network-security-config.xml")
                ]
                if nsc_candidates:
                    try:
                        nsc_data = read_member(zf, nsc_candidates[0])
                        nsc = parse_network_security_config(nsc_data, source_name=nsc_candidates[0])
                    except Exception as e:
                        logger.debug("Failed parsing network security config: %s", e)

                # 2. String resources (compiled table, plus plain XML when present)
                string_resources.update({r.name: r.value for r in table.values() if r.type == "string"})
                str_res_candidates = [
                    n for n in names if n.startswith("res/values") and n.endswith("strings.xml")
                ]
                for sc in str_res_candidates:
                    try:
                        data = read_member(zf, sc)
                        parsed_strs = parse_string_resources(data)
                        string_resources.update(parsed_strs)
                    except Exception as e:
                        logger.debug("Failed parsing strings.xml: %s", e)

                # 3. Assets & Config files
                for name in names:
                    if name.startswith("assets/"):
                        info = zf.getinfo(name)
                        if not info.is_dir():
                            is_cfg = False
                            cfg_type = None
                            lower = name.lower()
                            if lower.endswith(".json"):
                                is_cfg = True
                                cfg_type = "json"
                            elif lower.endswith(".xml"):
                                is_cfg = True
                                cfg_type = "xml"
                            elif lower.endswith(".properties"):
                                is_cfg = True
                                cfg_type = "properties"

                            assets.append(
                                AssetFile(
                                    path=name,
                                    size_bytes=info.file_size,
                                    is_config=is_cfg,
                                    config_type=cfg_type,
                                )
                            )

                            # Parse well-known configuration files
                            if "google-services.json" in lower:
                                try:
                                    raw = read_member(zf, name)
                                    parsed_json = json.loads(raw.decode("utf-8", errors="replace"))
                                    config_files[name] = parsed_json
                                except ValueError as e:
                                    logger.debug("Invalid JSON in %s: %s", name, e)

        except zipfile.BadZipFile:
            logger.warning("Target is not a valid zip archive: %s", path)

    elif path.is_dir():
        # Directory scanning
        nsc_files = list(path.rglob("*network_security_config.xml")) + list(
            path.rglob("*network-security-config.xml")
        )
        if nsc_files:
            try:
                nsc = parse_network_security_config(nsc_files[0].read_bytes(), source_name=str(nsc_files[0].name))
            except Exception as e:
                logger.debug("Failed parsing network security config: %s", e)

        for s_file in path.rglob("*strings.xml"):
            try:
                parsed_strs = parse_string_resources(s_file.read_bytes())
                string_resources.update(parsed_strs)
            except Exception as e:
                logger.debug("Failed parsing strings.xml: %s", e)

        assets_dir = path / "assets"
        if assets_dir.exists() and assets_dir.is_dir():
            for f in assets_dir.rglob("*"):
                if f.is_file():
                    rel = f.relative_to(path).as_posix()
                    lower = rel.lower()
                    is_cfg = any(lower.endswith(ext) for ext in [".json", ".xml", ".properties"])
                    cfg_type = "json" if lower.endswith(".json") else ("xml" if lower.endswith(".xml") else "properties")
                    assets.append(
                        AssetFile(
                            path=rel,
                            size_bytes=f.stat().st_size,
                            is_config=is_cfg,
                            config_type=cfg_type if is_cfg else None,
                        )
                    )
                    if "google-services.json" in lower:
                        try:
                            config_files[rel] = json.loads(f.read_text(encoding="utf-8"))
                        except (OSError, ValueError) as e:
                            logger.debug("Invalid JSON in %s: %s", rel, e)

    result = {
        "network_security_config": nsc.to_dict(),
        "string_resources_count": len(string_resources),
        "string_resources": string_resources,
        "assets_count": len(assets),
        "assets": [a.to_dict() for a in assets],
        "config_files": config_files,
    }

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        json_file = out_path / "resources.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        txt_file = out_path / "resources.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(format_resources_txt(result))

    return result


def format_resources_txt(data: Dict[str, Any]) -> str:
    """Format resource analysis into clean human-readable text."""
    nsc = data.get("network_security_config", {})
    lines = [
        "=" * 80,
        "HUNTX - ANDROID RESOURCES REPORT",
        "=" * 80,
        f"String Resources Found : {data.get('string_resources_count', 0)}",
        f"Total Assets Found     : {data.get('assets_count', 0)}",
        "",
        "NETWORK SECURITY CONFIGURATION",
        "-" * 80,
    ]

    if not nsc.get("present"):
        lines.append("  Status: Not present in application resources.")
    else:
        lines.append(f"  Status                  : Present ({nsc.get('source_file')})")
        lines.append(f"  Base Cleartext Permitted: {nsc.get('base_cleartext_permitted')}")
        lines.append(f"  Certificate Pinning     : {'Yes' if nsc.get('has_certificate_pinning') else 'No'}")
        lines.append(f"  Debug User Certs Allowed: {'Yes' if nsc.get('allows_user_certs_in_debug') else 'No'}")

        domain_configs = nsc.get("domain_configs", [])
        if domain_configs:
            lines.append("")
            lines.append("  Domain Rules:")
            for dc in domain_configs:
                doms = [f"{d['domain']} (subdomains={'yes' if d.get('include_subdomains') else 'no'})" for d in dc.get("domains", [])]
                lines.append(f"    • Domains: {', '.join(doms)}")
                lines.append(f"      Cleartext Permitted: {dc.get('cleartext_traffic_permitted')}")
                if dc.get("pin_set"):
                    ps = dc["pin_set"]
                    lines.append(f"      Pin Set (expires: {ps.get('expiration') or 'never'}):")
                    for pin in ps.get("pins", []):
                        lines.append(f"        - [{pin['digest']}] {pin['pin']}")

    lines.append("")
    lines.append("ASSETS & CONFIGURATIONS")
    lines.append("-" * 80)
    assets = data.get("assets", [])
    if not assets:
        lines.append("  No assets found.")
    else:
        for a in assets:
            cfg_flag = f" [{a['config_type'].upper()} CONFIG]" if a.get("is_config") else ""
            lines.append(f"  • {a['path']} ({a['size_bytes']:,} bytes){cfg_flag}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("")
    return "\n".join(lines)
