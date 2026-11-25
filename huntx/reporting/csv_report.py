"""HUNTX CSV report exporter for endpoints, domains, components, and permissions."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntx.core.csvsafe import safe_row
from huntx.core.logger import get_logger

logger = get_logger("huntx.reporting.csv_report")


class _SafeWriter:
    def __init__(self, fh: Any) -> None:
        self._w = csv.writer(fh)

    def writerow(self, row: List[Any]) -> None:
        self._w.writerow(safe_row(row))


class CSVReportGenerator:
    """Exports structured HUNTX reconnaissance datasets into standard CSV spreadsheets."""

    def __init__(self, session: Any = None) -> None:
        self.session = session
        self.run_path: Optional[Path] = getattr(session, "run_path", None)
        self.session_id = getattr(getattr(session, "metadata", None), "session_id", "")

    def _read_data(self, rel_path: str, key: str = "") -> List[Any]:
        """Safely read JSON data from session directory."""
        if not self.run_path or not isinstance(self.run_path, Path):
            return []
        p = self.run_path / rel_path
        if not p.exists():
            return []
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    if key and key in data:
                        return data[key]
                    # Check common keys
                    for k in ["passports", "endpoints", "domains", "components", "permissions"]:
                        if k in data:
                            return data[k]
                return []
        except Exception as e:
            logger.warning("Error reading %s for CSV export: %s", p, e)
            return []

    def export_all(self, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """Export all CSV reports to the reports directory.

        Returns:
            Dictionary mapping report name to generated Path.
        """
        logger.info("Exporting CSV reports")
        target_dir = output_dir
        if target_dir is None and self.run_path and isinstance(self.run_path, Path):
            target_dir = self.run_path / "reports"

        if target_dir is None:
            target_dir = Path("reports")
        target_dir.mkdir(parents=True, exist_ok=True)

        results: Dict[str, Path] = {}

        # 1. Endpoints CSV
        ep_file = target_dir / "endpoints.csv"
        self.export_endpoints_csv(ep_file)
        results["endpoints"] = ep_file

        # 2. Domains CSV
        dom_file = target_dir / "domains.csv"
        self.export_domains_csv(dom_file)
        results["domains"] = dom_file

        # 3. Components CSV
        comp_file = target_dir / "components.csv"
        self.export_components_csv(comp_file)
        results["components"] = comp_file

        # 4. Permissions CSV
        perm_file = target_dir / "permissions.csv"
        self.export_permissions_csv(perm_file)
        results["permissions"] = perm_file

        return results

    def export_endpoints_csv(self, file_path: Path) -> Path:
        """Export endpoints / passports to CSV."""
        endpoints = self._read_data("mapping/endpoint-passports.json", "passports")
        if not endpoints:
            endpoints = self._read_data("api/endpoints.json", "endpoints")

        headers = [
            "endpoint_id",
            "domain",
            "method",
            "path",
            "normalized_path",
            "feature_group",
            "confidence",
            "parameters",
            "discovery_sources",
            "authentication_evidence",
            "source_class",
            "source_method",
            "first_seen",
            "last_seen",
        ]

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = _SafeWriter(f)
            writer.writerow(headers)
            for idx, ep in enumerate(endpoints, start=1):
                params = ep.get("parameters", [])
                if isinstance(params, (list, dict)):
                    params_str = json.dumps(params)
                else:
                    params_str = str(params)

                sources = ep.get("discovery_sources", [])
                if isinstance(sources, list):
                    sources_str = ", ".join(str(s) for s in sources)
                else:
                    sources_str = str(sources)

                writer.writerow([
                    ep.get("endpoint_id", f"EP-{idx:05d}"),
                    ep.get("domain", ""),
                    ep.get("method", "UNKNOWN"),
                    ep.get("path", ""),
                    ep.get("normalized_path", ep.get("path", "")),
                    ep.get("feature_group", ""),
                    ep.get("confidence", 0.0),
                    params_str,
                    sources_str,
                    ep.get("authentication_evidence", ""),
                    ep.get("source_class", ""),
                    ep.get("source_method", ""),
                    ep.get("first_seen", ""),
                    ep.get("last_seen", ""),
                ])

        logger.info("Exported %d endpoints to %s", len(endpoints), file_path)
        return file_path

    def export_domains_csv(self, file_path: Path) -> Path:
        """Export domains to CSV."""
        domains = self._read_data("api/domains.json", "domains")

        headers = ["domain", "source", "first_seen", "session_id"]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = _SafeWriter(f)
            writer.writerow(headers)
            for d in domains:
                if isinstance(d, dict):
                    writer.writerow([
                        d.get("domain", ""),
                        "; ".join(d.get("sources", [])) or d.get("source", "recon"),
                        d.get("first_seen", ""),
                        d.get("session_id", self.session_id),
                    ])
                else:
                    writer.writerow([str(d), "recon", "", self.session_id])

        logger.info("Exported %d domains to %s", len(domains), file_path)
        return file_path

    def export_components_csv(self, file_path: Path) -> Path:
        """Export components to CSV."""
        components = self._read_data("android/components.json", "components")

        headers = ["component_type", "class_name", "exported", "permission", "session_id"]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = _SafeWriter(f)
            writer.writerow(headers)
            for c in components:
                if isinstance(c, dict):
                    writer.writerow([
                        c.get("component_type", ""),
                        c.get("class_name") or c.get("name", ""),
                        c.get("exported", False),
                        c.get("permission") or "",
                        c.get("session_id", self.session_id),
                    ])

        logger.info("Exported %d components to %s", len(components), file_path)
        return file_path

    def export_permissions_csv(self, file_path: Path) -> Path:
        """Export permissions to CSV."""
        permissions = self._read_data("android/permissions.json", "permissions")

        headers = ["permission", "protection_level", "is_dangerous", "session_id"]
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = _SafeWriter(f)
            writer.writerow(headers)
            for p in permissions:
                if isinstance(p, dict):
                    writer.writerow([
                        p.get("name") or p.get("permission", ""),
                        p.get("protection_level", "normal"),
                        p.get("is_dangerous", False),
                        p.get("session_id", self.session_id),
                    ])
                else:
                    writer.writerow([str(p), "normal", False, self.session_id])

        logger.info("Exported %d permissions to %s", len(permissions), file_path)
        return file_path


def generate_csv_reports(session: Any = None, output_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Convenience wrapper for CSVReportGenerator."""
    generator = CSVReportGenerator(session=session)
    return generator.export_all(output_dir=output_dir)
