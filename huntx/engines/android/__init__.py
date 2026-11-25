"""HUNTX Android Reconnaissance Engine.

Provides static reconnaissance modules for Android APK analysis:
- apk_info: File metadata, hashing, package/version info, signing certs, ABIs.
- manifest: Comprehensive AndroidManifest.xml analysis, security flags, deep links.
- permissions: Categorization of declared permissions into standard recon groups.
- components: Enumeration of activities, services, receivers, and providers.
- strings: Dalvik DEX string extraction, URL, domain, API path, IP, token discovery.
- resources: Network security config, certificate pinning, strings, and assets.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union

from huntx.engines.android.apk_info import APKInfo, extract_apk_info
from huntx.engines.android.axml import axml_to_xml, parse_axml
from huntx.engines.android.components import enumerate_components
from huntx.engines.android.manifest import analyze_manifest
from huntx.engines.android.permissions import analyze_permissions
from huntx.engines.android.resources import analyze_resources
from huntx.engines.android.strings import extract_strings

logger = logging.getLogger(__name__)

__all__ = [
    "extract_apk_info",
    "analyze_manifest",
    "analyze_permissions",
    "enumerate_components",
    "extract_strings",
    "analyze_resources",
    "parse_axml",
    "axml_to_xml",
    "run_android_recon",
    "APKInfo",
]


def run_android_recon(
    apk_path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    session: Any = None,
) -> Dict[str, Any]:
    """Execute complete Android reconnaissance suite for an APK.

    Executes all sub-engines:
    1. APK Information (`android/apk-info.json`, `android/apk-info.txt`)
    2. Manifest Analysis (`android/manifest.xml`, `android/manifest-analysis.json`)
    3. Permissions Analysis (`android/permissions.json`, `android/permissions.txt`)
    4. Component Enumeration (`android/components.json`)
    5. String Extraction (`android/strings.json`, `android/strings.txt`)
    6. Resource Analysis (`android/resources.json`, `android/resources.txt`)

    Args:
        apk_path: Path to the target APK file.
        output_dir: Target output directory (e.g. `session.run_path / "android"`).
            If None and session is provided, resolves to `session.run_path / "android"`.
        session: Optional HUNTX Session object.

    Returns:
        Unified dictionary containing results from all reconnaissance engines.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"Target APK does not exist: {path}")

    # Resolve output directory from session if not explicitly provided
    resolved_out_dir: Optional[Path] = None
    if output_dir:
        resolved_out_dir = Path(output_dir)
    elif session is not None and hasattr(session, "run_path"):
        resolved_out_dir = Path(session.run_path) / "android"

    if resolved_out_dir:
        resolved_out_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, Any] = {}

    # 1. APK Info
    try:
        results["apk_info"] = extract_apk_info(path, output_dir=resolved_out_dir)
    except Exception as e:
        logger.error("Failed executing apk_info engine: %s", e)
        results["apk_info"] = {"error": str(e)}

    # 2. Manifest
    try:
        results["manifest"] = analyze_manifest(path, output_dir=resolved_out_dir)
    except Exception as e:
        logger.error("Failed executing manifest engine: %s", e)
        results["manifest"] = {"error": str(e)}

    # 3. Permissions
    try:
        results["permissions"] = analyze_permissions(
            results.get("manifest") or path, output_dir=resolved_out_dir
        )
    except Exception as e:
        logger.error("Failed executing permissions engine: %s", e)
        results["permissions"] = {"error": str(e)}

    # 4. Components
    try:
        results["components"] = enumerate_components(
            results.get("manifest") or path,
            output_dir=resolved_out_dir,
            session=session,
        )
    except Exception as e:
        logger.error("Failed executing components engine: %s", e)
        results["components"] = {"error": str(e)}

    # 5. Strings
    try:
        results["strings"] = extract_strings(path, output_dir=resolved_out_dir)
    except Exception as e:
        logger.error("Failed executing strings engine: %s", e)
        results["strings"] = {"error": str(e)}

    # 6. Resources
    try:
        results["resources"] = analyze_resources(path, output_dir=resolved_out_dir)
    except Exception as e:
        logger.error("Failed executing resources engine: %s", e)
        results["resources"] = {"error": str(e)}

    # Mark completed ops on session if present
    if session is not None and hasattr(session, "metadata"):
        for op_name in [
            "apk_info",
            "manifest",
            "permissions",
            "components",
            "strings",
            "resources",
        ]:
            if op_name not in session.metadata.completed_ops:
                session.metadata.completed_ops.append(op_name)

    return results
