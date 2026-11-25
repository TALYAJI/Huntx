"""HUNTX Android Manifest Analysis Engine.

Extracts and analyzes AndroidManifest.xml:
- Package identifier and versioning
- Application attributes and security flags (debuggable, allowBackup, usesCleartextTraffic)
- Network security configuration reference
- Exported components (activities, services, broadcast receivers, content providers)
- Intent filters and deep links (schemes, hosts, paths)
- Custom permissions and used permissions

Outputs:
- android/manifest.xml (formatted XML)
- android/manifest-analysis.json (structured analysis)
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
from huntx.engines.android.axml import axml_to_xml, parse_axml

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
class DeepLink:
    """Deep link pattern extracted from an intent filter."""

    component: str
    component_type: str
    scheme: str
    host: Optional[str] = None
    port: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    mime_type: Optional[str] = None
    is_app_link: bool = False
    full_pattern: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntentFilterData:
    """Intent filter configuration."""

    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentRecord:
    """Android component record."""

    name: str
    type: str  # activity, service, receiver, provider
    exported: bool
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    authorities: Optional[str] = None
    grant_uri_permissions: bool = False
    intent_filters: List[IntentFilterData] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["intent_filters"] = [f.to_dict() for f in self.intent_filters]
        return d


@dataclass
class CustomPermission:
    """Custom permission declared by the application."""

    name: str
    protection_level: str = "normal"
    permission_group: Optional[str] = None
    label: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManifestAnalysis:
    """Complete manifest analysis result."""

    package: str = ""
    version_code: Optional[int] = None
    version_name: str = ""
    app_name: str = ""
    app_attributes: Dict[str, str] = field(default_factory=dict)
    debuggable: bool = False
    allow_backup: bool = True  # Android default is true
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    request_legacy_external_storage: Optional[bool] = None
    components_count: int = 0
    exported_components_count: int = 0
    components: List[ComponentRecord] = field(default_factory=list)
    deep_links: List[DeepLink] = field(default_factory=list)
    custom_permissions: List[CustomPermission] = field(default_factory=list)
    used_permissions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "app_name": self.app_name,
            "flags": {
                "debuggable": self.debuggable,
                "allow_backup": self.allow_backup,
                "uses_cleartext_traffic": self.uses_cleartext_traffic,
                "request_legacy_external_storage": self.request_legacy_external_storage,
            },
            "network_security_config": self.network_security_config,
            "app_attributes": self.app_attributes,
            "summary": {
                "total_components": self.components_count,
                "exported_components": self.exported_components_count,
                "total_deep_links": len(self.deep_links),
                "total_custom_permissions": len(self.custom_permissions),
                "total_used_permissions": len(self.used_permissions),
            },
            "components": [c.to_dict() for c in self.components],
            "deep_links": [d.to_dict() for d in self.deep_links],
            "custom_permissions": [p.to_dict() for p in self.custom_permissions],
            "used_permissions": self.used_permissions,
        }


def _resolve_class_name(name: str, package: str) -> str:
    """Resolve relative class names using the manifest package."""
    if not name:
        return ""
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name:
        return f"{package}.{name}"
    return name


def _parse_bool(val: Optional[str], default: bool = False) -> bool:
    """Parse string boolean value."""
    if val is None:
        return default
    val_clean = str(val).strip().lower()
    if val_clean in ("true", "1", "yes"):
        return True
    if val_clean in ("false", "0", "no"):
        return False
    return default


def parse_manifest_element(root: ET.Element) -> ManifestAnalysis:
    """Parse ElementTree root element of an AndroidManifest."""
    package = _get_attr(root, "package", "")
    vc_raw = _get_attr(root, "versionCode")
    version_code = int(str(vc_raw)) if vc_raw is not None and str(vc_raw).isdigit() else None
    version_name = str(_get_attr(root, "versionName", ""))

    analysis = ManifestAnalysis(
        package=package,
        version_code=version_code,
        version_name=version_name,
    )

    for child in root:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag

        if tag in ("uses-permission", "uses-permission-sdk-23"):
            name = _get_attr(child, "name")
            if name and name not in analysis.used_permissions:
                analysis.used_permissions.append(name)

        elif tag == "permission":
            name = _get_attr(child, "name")
            if name:
                prot = _get_attr(child, "protectionLevel", "normal")
                grp = _get_attr(child, "permissionGroup")
                lbl = _get_attr(child, "label")
                desc = _get_attr(child, "description")
                analysis.custom_permissions.append(
                    CustomPermission(
                        name=name,
                        protection_level=prot,
                        permission_group=grp,
                        label=lbl,
                        description=desc,
                    )
                )

        elif tag == "application":
            _parse_application(child, package, analysis)

    analysis.components_count = len(analysis.components)
    analysis.exported_components_count = sum(1 for c in analysis.components if c.exported)
    return analysis


def _parse_application(
    app_elem: ET.Element, package: str, analysis: ManifestAnalysis
) -> None:
    """Parse <application> tag attributes and enclosed components."""
    analysis.app_attributes = dict(app_elem.attrib)
    analysis.app_name = (
        _get_attr(app_elem, "label")
        or _get_attr(app_elem, "name")
        or (package.split(".")[-1] if package else "")
    )

    # Security flags
    debuggable_raw = _get_attr(app_elem, "debuggable")
    analysis.debuggable = _parse_bool(debuggable_raw, default=False)

    backup_raw = _get_attr(app_elem, "allowBackup")
    analysis.allow_backup = _parse_bool(backup_raw, default=True)

    cleartext_raw = _get_attr(app_elem, "usesCleartextTraffic")
    if cleartext_raw is not None:
        analysis.uses_cleartext_traffic = _parse_bool(cleartext_raw, default=False)

    nsc_raw = _get_attr(app_elem, "networkSecurityConfig")
    analysis.network_security_config = nsc_raw

    legacy_storage_raw = _get_attr(app_elem, "requestLegacyExternalStorage")
    if legacy_storage_raw is not None:
        analysis.request_legacy_external_storage = _parse_bool(legacy_storage_raw, default=False)

    component_types = {
        "activity": "activity",
        "activity-alias": "activity",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }

    for child in app_elem:
        child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child_tag in component_types:
            c_type = component_types[child_tag]
            comp = _parse_component(child, c_type, package)
            if comp:
                # <application android:permission> is the default for every component
                comp.permission = comp.permission or _get_attr(app_elem, "permission")
                analysis.components.append(comp)
                _extract_deep_links(comp, analysis.deep_links)


def _parse_component(
    elem: ET.Element, comp_type: str, package: str
) -> Optional[ComponentRecord]:
    """Parse an individual component tag."""
    raw_name = _get_attr(elem, "name")
    if not raw_name:
        return None

    full_name = _resolve_class_name(raw_name, package)

    filters: List[IntentFilterData] = []
    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "intent-filter":
            f_data = IntentFilterData()
            for sub in child:
                sub_tag = sub.tag.split("}")[-1] if "}" in sub.tag else sub.tag
                if sub_tag == "action":
                    a_name = _get_attr(sub, "name")
                    if a_name:
                        f_data.actions.append(a_name)
                elif sub_tag == "category":
                    c_name = _get_attr(sub, "name")
                    if c_name:
                        f_data.categories.append(c_name)
                elif sub_tag == "data":
                    data_entry = {}
                    for k, v in sub.attrib.items():
                        clean_k = k.split("}")[-1].split(":")[-1]
                        data_entry[clean_k] = v
                    if data_entry:
                        f_data.data.append(data_entry)
            f_data.data = _merge_data(f_data.data)
            filters.append(f_data)

    exported_raw = _get_attr(elem, "exported")
    if exported_raw is not None:
        exported = _parse_bool(exported_raw)
    else:
        exported = len(filters) > 0

    perm = _get_attr(elem, "permission")
    read_perm = _get_attr(elem, "readPermission")
    write_perm = _get_attr(elem, "writePermission")
    authorities = _get_attr(elem, "authorities")
    grant_uri_raw = _get_attr(elem, "grantUriPermissions")
    grant_uri = _parse_bool(grant_uri_raw, default=False)

    return ComponentRecord(
        name=full_name,
        type=comp_type,
        exported=exported,
        permission=perm,
        read_permission=read_perm,
        write_permission=write_perm,
        authorities=authorities,
        grant_uri_permissions=grant_uri,
        intent_filters=filters,
        attributes=dict(elem.attrib),
    )


def _merge_data(entries: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Combine ``<data>`` siblings the way Android does.

    ``<data scheme="https"/><data host="a.com"/>`` is one URI pattern, not two.
    Entries that all carry their own scheme are already self-contained.
    """
    schemes = [e for e in entries if "scheme" in e]
    if not schemes or len(schemes) == len(entries):
        return entries
    hosts = [{k: e[k] for k in ("host", "port") if k in e} for e in entries if "host" in e] or [{}]
    paths = [{k: v} for e in entries for k, v in e.items() if k.startswith("path")] or [{}]
    mimes = [{"mimeType": e["mimeType"]} for e in entries if "mimeType" in e] or [{}]
    merged: List[Dict[str, str]] = []
    for scheme in dict.fromkeys(e["scheme"] for e in schemes):
        for host in hosts:
            for path in paths:
                for mime in mimes:
                    item = {"scheme": scheme, **host, **path, **mime}
                    if item not in merged:
                        merged.append(item)
                    if len(merged) >= 200:
                        return merged
    return merged


def _extract_deep_links(comp: ComponentRecord, target_list: List[DeepLink]) -> None:
    """Extract deep links from intent filters of a component."""
    for ifilter in comp.intent_filters:
        has_browsable = "android.intent.category.BROWSABLE" in ifilter.categories
        for data_entry in ifilter.data:
            scheme = data_entry.get("scheme", "")
            host = data_entry.get("host")
            port = data_entry.get("port")
            path = data_entry.get("path")
            path_prefix = data_entry.get("pathPrefix")
            path_pattern = data_entry.get("pathPattern")
            mime_type = data_entry.get("mimeType")

            if scheme:
                is_app_link = scheme.lower() in ("http", "https") and has_browsable

                pattern = f"{scheme}://"
                if host:
                    pattern += host
                    if port:
                        pattern += f":{port}"
                if path:
                    pattern += path
                elif path_prefix:
                    pattern += f"{path_prefix}*"
                elif path_pattern:
                    pattern += path_pattern
                else:
                    if host:
                        pattern += "/*"

                target_list.append(
                    DeepLink(
                        component=comp.name,
                        component_type=comp.type,
                        scheme=scheme,
                        host=host,
                        port=port,
                        path=path,
                        path_prefix=path_prefix,
                        path_pattern=path_pattern,
                        mime_type=mime_type,
                        is_app_link=is_app_link,
                        full_pattern=pattern,
                    )
                )


def analyze_manifest(
    apk_path: str | Path,
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Analyze AndroidManifest.xml from an APK archive or extracted directory.

    Args:
        apk_path: Path to the APK file or directory containing AndroidManifest.xml.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `manifest.xml` and `manifest-analysis.json`.

    Returns:
        Dict representing manifest analysis.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest target not found: {path}")

    raw_manifest: Optional[bytes] = None

    if path.is_file():
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    raw_manifest = read_member(zf, "AndroidManifest.xml")
        except zipfile.BadZipFile:
            logger.warning("Target is not a valid zip archive: %s", path)
    elif path.is_dir():
        manifest_file = path / "AndroidManifest.xml"
        if manifest_file.exists():
            raw_manifest = manifest_file.read_bytes()

    if not raw_manifest:
        logger.warning("AndroidManifest.xml could not be located in %s", path)
        elem = ET.Element("manifest")
        elem.set("package", "unknown")
        xml_text = '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="unknown"/>'
    else:
        elem = parse_axml(raw_manifest)
        xml_text = axml_to_xml(raw_manifest)

    analysis = parse_manifest_element(elem)
    analysis_dict = analysis.to_dict()

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        manifest_out = out_path / "manifest.xml"
        with open(manifest_out, "w", encoding="utf-8") as f:
            f.write(xml_text)

        analysis_out = out_path / "manifest-analysis.json"
        with open(analysis_out, "w", encoding="utf-8") as f:
            json.dump(analysis_dict, f, indent=2)

    return analysis_dict
