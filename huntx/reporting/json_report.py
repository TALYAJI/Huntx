"""HUNTX unified JSON report generator."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from huntx.core.logger import get_logger
from huntx.engines.android.components import is_unprotected
from huntx.engines.android.config_findings import config_findings, effective_cleartext

logger = get_logger("huntx.reporting.json_report")


def _format_size(size_bytes: int) -> str:
    """Format bytes into human-readable string."""
    try:
        sb = float(size_bytes)
    except (TypeError, ValueError):
        return "Not Available"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if sb < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(sb)} {unit}"
            return f"{sb:.2f} {unit}"
        sb /= 1024.0
    return f"{sb:.2f} B"


class JSONReportGenerator:
    """Consolidates all reconnaissance findings into a unified, authoritative JSON report."""

    def __init__(self, session: Any = None) -> None:
        self.session = session
        self.meta = getattr(session, "metadata", None)
        self.run_path: Optional[Path] = getattr(session, "run_path", None)

    def _resolve_app_name(
        self,
        apk_info_raw: Dict[str, Any],
        manifest_data: Dict[str, Any],
        package_name: str,
        target_name: str,
    ) -> str:
        name = apk_info_raw.get("application_name", "")
        if name and not name.startswith("@") and name.lower() not in ("unknown", "n/a"):
            return name

        # Check input manifest.json (from XAPK)
        input_manifest = self._read_json_file("input/manifest.json", {})
        if isinstance(input_manifest, dict) and input_manifest.get("name"):
            return str(input_manifest["name"])

        # Check manifest analysis app_name
        m_app = manifest_data.get("app_name", "")
        if m_app and not m_app.startswith("@") and m_app.lower() not in ("unknown", "n/a"):
            return str(m_app)

        # Check app_attributes
        app_attr = manifest_data.get("app_attributes", {})
        if isinstance(app_attr, dict):
            android_name = app_attr.get("android:name", "")
            if android_name:
                last = android_name.split(".")[-1]
                for clean_suffix in ["APP", "App", "Application", "Activity"]:
                    if last.endswith(clean_suffix) and len(last) > len(clean_suffix):
                        last = last[: -len(clean_suffix)]
                if last.lower() in ("multidex", "application", "baseapplication", "corecomponentfactory", "app", "activity", "main"):
                    last = ""
                if last:
                    return last

        # Check apk_files filename
        apk_files = getattr(self.meta, "apk_files", [])
        if apk_files and isinstance(apk_files[0], dict) and apk_files[0].get("filename"):
            fname = apk_files[0]["filename"]
            clean_name = fname.split(".")[0].split("+")[0].split("_")[0].split("-")[0]
            if clean_name and clean_name.lower() not in ("base", "app", "release", "debug"):
                return clean_name

        # Check target name
        if target_name and target_name.lower() not in ("unknown", "unknown target"):
            return target_name.capitalize()

        # Check package name parts
        if package_name and package_name not in ("unknown.package", "N/A", "Not Available"):
            parts = package_name.split(".")
            candidate = parts[-1]
            if candidate in ("app", "mobile", "android") and len(parts) >= 2:
                candidate = parts[-2]
            return candidate.capitalize()

        return "Not Available"

    def _read_json_file(self, rel_path: str, default: Any = None) -> Any:
        """Safely read a JSON file from the session directory."""
        if not self.run_path or not isinstance(self.run_path, Path):
            return default
        file_path = self.run_path / rel_path
        if not file_path.exists():
            return default
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not read %s: %s", file_path, e)
            return default

    def generate(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Compile and generate the unified report.

        Args:
            output_path: Optional explicit file path for huntx-report.json.

        Returns:
            The complete JSON report dictionary.
        """
        logger.info("Generating unified JSON report")
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Target and Session Metadata
        target_name = getattr(self.meta, "target_name", "Unknown Target")
        session_id = getattr(self.meta, "session_id", "N/A")
        run_dir = str(self.run_path) if self.run_path else "N/A"
        created_at = getattr(self.meta, "created_at", now_iso)
        completed_ops = getattr(self.meta, "completed_ops", [])

        # Read raw engine artifacts first for comprehensive cross-referencing
        manifest_data = self._read_json_file("android/manifest-analysis.json", {})
        permissions_data = self._read_json_file("android/permissions.json", [])
        components_data = self._read_json_file("android/components.json", [])
        security_audit_data = self._read_json_file("android/security-audit.json", {})
        secrets_data = security_audit_data.get("secrets", [])
        resources_data = self._read_json_file("android/resources.json", {})
        netsec_data = resources_data.get("network_security_config", {}) if isinstance(resources_data, dict) else {}
        domains_data = self._read_json_file("api/domains.json", [])
        endpoints_data = self._read_json_file("api/endpoints.json", [])
        passports_data = self._read_json_file("mapping/endpoint-passports.json", {})
        traffic_summary = self._read_json_file("traffic/traffic-summary.json", {})
        api_map_data = self._read_json_file("mapping/android-api-map.json", {})
        endpoint_sources_data = self._read_json_file("mapping/endpoint-sources.json", {})

        # 2. APK Metadata & Hashes
        apk_info_raw = self._read_json_file("android/apk-info.json", {})
        apk_files = getattr(self.meta, "apk_files", [])

        package_name = apk_info_raw.get("package_name") or manifest_data.get("package") or "Not Available"
        if package_name == "unknown.package" and manifest_data.get("package"):
            package_name = manifest_data.get("package")

        app_name = self._resolve_app_name(apk_info_raw, manifest_data, package_name, target_name)
        version_name = apk_info_raw.get("version_name") or manifest_data.get("version_name") or "Not Available"
        version_code = apk_info_raw.get("version_code")
        if version_code is None and manifest_data.get("version_code") is not None:
            version_code = manifest_data.get("version_code")

        min_sdk = apk_info_raw.get("min_sdk") or "Not Available"
        target_sdk = apk_info_raw.get("target_sdk") or "Not Available"

        flags = manifest_data.get("flags", {}) if isinstance(manifest_data, dict) else {}
        debuggable = flags.get("debuggable", False)
        cleartext_traffic, _ = effective_cleartext(flags, netsec_data, target_sdk)
        allow_backup = flags.get("allow_backup", True)

        hashes = dict(apk_info_raw.get("hashes", {}))
        if not hashes:
            if apk_info_raw.get("sha256"):
                hashes["sha256"] = apk_info_raw["sha256"]
            elif apk_files and isinstance(apk_files[0], dict) and apk_files[0].get("sha256"):
                hashes["sha256"] = apk_files[0]["sha256"]

        file_size_human = apk_info_raw.get("size_human")
        if (not file_size_human or file_size_human == "0 B") and apk_files and isinstance(apk_files[0], dict):
            file_size_human = _format_size(apk_files[0].get("size_bytes", 0))

        apk_metadata = {
            "application_name": app_name,
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code if version_code is not None else "Not Available",
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "debuggable": bool(debuggable),
            "cleartext_traffic": bool(cleartext_traffic),
            "allow_backup": bool(allow_backup),
            "size_human": file_size_human or "Not Available",
            "sha256": hashes.get("sha256", "Not Available"),
            "hashes": hashes,
            "signing": apk_info_raw.get("signing", {}),
            "files": apk_files,
        }

        # Normalize lists if stored in wrapper objects
        if isinstance(permissions_data, dict) and "permissions" in permissions_data:
            permissions_list = permissions_data["permissions"]
        elif isinstance(permissions_data, list):
            permissions_list = permissions_data
        else:
            permissions_list = []

        if isinstance(components_data, dict) and "components" in components_data:
            components_list = components_data["components"]
        elif isinstance(components_data, list):
            components_list = components_data
        else:
            components_list = []

        if isinstance(domains_data, dict) and "domains" in domains_data:
            domains_list = domains_data["domains"]
        elif isinstance(domains_data, list):
            domains_list = domains_data
        else:
            domains_list = []

        if isinstance(passports_data, dict) and "passports" in passports_data:
            passports_list = passports_data["passports"]
        elif isinstance(passports_data, list):
            passports_list = passports_data
        elif isinstance(endpoints_data, dict) and "endpoints" in endpoints_data:
            passports_list = endpoints_data["endpoints"]
        elif isinstance(endpoints_data, list):
            passports_list = endpoints_data
        else:
            passports_list = []

        # Exported components & security warnings
        exported_components = [c for c in components_list if isinstance(c, dict) and c.get("exported")]
        exported_without_perm = [c for c in exported_components if is_unprotected(c)]

        dangerous_perms = [
            p for p in permissions_list
            if isinstance(p, dict) and (
                p.get("is_dangerous") or "dangerous" in str(p.get("protection_level", "")).lower()
            )
        ]

        # 4. Extraction limitations
        limitations = [
            "Analysis represents static inspection and imported traffic captures available during session.",
            "Native binaries (.so shared objects) were not disassembled or dynamically traced.",
        ]
        if not traffic_summary:
            limitations.append("Dynamic network traffic analysis was not provided or imported for this session.")
        if any(len(str(c.get("class_name", "")).rsplit(".", 1)[-1]) <= 2 for c in api_map_data.get("classes", [])):
            limitations.append("Obfuscated class names detected: class-to-endpoint attribution is best effort.")

        # 5. Compile Findings Summary
        summary = {
            "total_domains": len(domains_list),
            "total_endpoints": len(passports_list),
            "total_components": len(components_list),
            "exported_components": len(exported_components),
            "high_risk_exported_components": len(exported_without_perm),
            "total_permissions": len(permissions_list),
            "dangerous_permissions": len(dangerous_perms),
            "total_secrets_detected": len(secrets_data) if isinstance(secrets_data, list) else 0,
            "cleartext_traffic_permitted": bool(cleartext_traffic),
            "modules_completed": len(completed_ops),
        }

        networking_libs = security_audit_data.get("fingerprint", {}).get("networking_libraries", [])

        # 6. Assemble Full Report
        report = {
            "report_version": "1.0.0",
            "generated_at": now_iso,
            "target": {
                "name": target_name,
                "session_id": session_id,
                "run_dir": run_dir,
                "created_at": created_at,
                "completed_operations": completed_ops,
            },
            "apk_metadata": apk_metadata,
            "summary": summary,
            "findings": {
                "domains": domains_list,
                "endpoints": passports_list,
                "components": components_list,
                "permissions": permissions_list,
                "secrets": secrets_data,
                "network_security": netsec_data,
                "configuration": config_findings(manifest_data, netsec_data, apk_info_raw),
                "security_audit": security_audit_data,
                "traffic": traffic_summary,
                "android_api_mapping": api_map_data.get("classes", []),
                "endpoint_sources": endpoint_sources_data.get("endpoints", []),
                "networking_libraries": networking_libs,
            },
            "extraction_limitations": limitations,
        }

        # Persist report
        target_path = output_path
        if target_path is None and self.run_path and isinstance(self.run_path, Path):
            target_path = self.run_path / "reports" / "huntx-report.json"

        if target_path is not None:
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
                logger.info("Saved unified JSON report to %s", target_path)
            except Exception as e:
                logger.error("Failed to write report to %s: %s", target_path, e)

        return report


def generate_json_report(session: Any = None, output_path: Optional[Path] = None) -> Dict[str, Any]:
    """Convenience wrapper for JSONReportGenerator."""
    generator = JSONReportGenerator(session=session)
    return generator.generate(output_path=output_path)
