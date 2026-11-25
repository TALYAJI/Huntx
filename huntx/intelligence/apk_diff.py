"""HUNTX APK Version Comparison (Diff) engine.

Compares two APK analysis runs to identify security surface changes:
new/removed domains, endpoints, permissions, and components.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from huntx.core.logger import get_logger

logger = get_logger("huntx.intelligence.apk_diff")


@dataclass
class APKDiffSummary:
    """Statistical summary of differences between two runs."""

    new_domains_count: int = 0
    removed_domains_count: int = 0
    new_endpoints_count: int = 0
    removed_endpoints_count: int = 0
    added_permissions_count: int = 0
    removed_permissions_count: int = 0
    added_components_count: int = 0
    removed_components_count: int = 0
    modified_components_count: int = 0
    security_risk_delta: str = "neutral"  # increased, decreased, neutral

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APKDiffResult:
    """Full diff result comparing two analysis sessions or runs."""

    base_run_id: str
    target_run_id: str
    timestamp: str
    summary: APKDiffSummary
    domains: Dict[str, List[Any]] = field(default_factory=dict)
    endpoints: Dict[str, List[Any]] = field(default_factory=dict)
    permissions: Dict[str, List[Any]] = field(default_factory=dict)
    components: Dict[str, List[Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["summary"] = self.summary.to_dict()
        return d


def _load_run_data(source: Union[Path, str, Any, Dict[str, Any]]) -> Dict[str, Any]:
    """Extract normalized data (domains, endpoints, permissions, components) from run source."""
    data = {
        "run_id": "unknown",
        "domains": [],
        "endpoints": [],
        "permissions": [],
        "components": [],
    }

    if isinstance(source, dict):
        data["run_id"] = source.get("run_id") or source.get("session_id", "dict_input")
        data["domains"] = source.get("domains", [])
        data["endpoints"] = source.get("endpoints", [])
        data["permissions"] = source.get("permissions", [])
        data["components"] = source.get("components", [])
        return data

    # Check if Session object
    run_path = getattr(source, "run_path", None)
    if run_path is None and isinstance(source, (str, Path)):
        run_path = Path(source)

    if run_path and isinstance(run_path, Path):
        data["run_id"] = getattr(getattr(source, "metadata", None), "session_id", run_path.name)
        
        # Load domains from api/domains.json or api/domains.txt
        dom_json = run_path / "api" / "domains.json"
        if dom_json.exists():
            try:
                with open(dom_json, "r", encoding="utf-8") as f:
                    dom_data = json.load(f)
                    data["domains"] = dom_data.get("domains", []) if isinstance(dom_data, dict) else dom_data
            except Exception as e:
                logger.warning("Error reading %s: %s", dom_json, e)

        # Load endpoints from mapping/endpoint-passports.json or api/endpoints.json
        passports_file = run_path / "mapping" / "endpoint-passports.json"
        api_ep_file = run_path / "api" / "endpoints.json"
        if passports_file.exists():
            try:
                with open(passports_file, "r", encoding="utf-8") as f:
                    ep_data = json.load(f)
                    data["endpoints"] = ep_data.get("passports", []) if isinstance(ep_data, dict) else ep_data
            except Exception as e:
                logger.warning("Error reading %s: %s", passports_file, e)
        elif api_ep_file.exists():
            try:
                with open(api_ep_file, "r", encoding="utf-8") as f:
                    ep_data = json.load(f)
                    data["endpoints"] = ep_data.get("endpoints", []) if isinstance(ep_data, dict) else ep_data
            except Exception as e:
                logger.warning("Error reading %s: %s", api_ep_file, e)

        # Load permissions from android/permissions.json or android/manifest-analysis.json
        perm_file = run_path / "android" / "permissions.json"
        if perm_file.exists():
            try:
                with open(perm_file, "r", encoding="utf-8") as f:
                    p_data = json.load(f)
                    data["permissions"] = p_data.get("permissions", []) if isinstance(p_data, dict) else p_data
            except Exception as e:
                logger.warning("Error reading %s: %s", perm_file, e)

        # Load components from android/components.json
        comp_file = run_path / "android" / "components.json"
        if comp_file.exists():
            try:
                with open(comp_file, "r", encoding="utf-8") as f:
                    c_data = json.load(f)
                    data["components"] = c_data.get("components", []) if isinstance(c_data, dict) else c_data
            except Exception as e:
                logger.warning("Error reading %s: %s", comp_file, e)

    return data


class APKDiff:
    """Compares two APK analysis runs to identify security and attack surface changes."""

    def __init__(self, base_source: Any, target_source: Any) -> None:
        self.base_data = _load_run_data(base_source)
        self.target_data = _load_run_data(target_source)

    def compare(self, output_file: Optional[Path] = None) -> APKDiffResult:
        """Execute difference comparison and optionally save result to JSON."""
        logger.info("Comparing run %s with run %s", self.base_data["run_id"], self.target_data["run_id"])

        # 1. Domains comparison
        base_dom_map = {d.get("domain", d) if isinstance(d, dict) else str(d): d for d in self.base_data["domains"]}
        target_dom_map = {d.get("domain", d) if isinstance(d, dict) else str(d): d for d in self.target_data["domains"]}

        added_domains = [target_dom_map[d] for d in target_dom_map if d not in base_dom_map]
        removed_domains = [base_dom_map[d] for d in base_dom_map if d not in target_dom_map]
        retained_domains = [target_dom_map[d] for d in target_dom_map if d in base_dom_map]

        # 2. Endpoints comparison (key on normalized_path or path + method)
        def _ep_key(ep: Any) -> str:
            if isinstance(ep, dict):
                p = ep.get("normalized_path") or ep.get("path") or ""
                m = ep.get("method") or "UNKNOWN"
                d = ep.get("domain") or ""
                return f"{m.upper()}:{d}:{p}"
            return str(ep)

        base_ep_map = {_ep_key(e): e for e in self.base_data["endpoints"]}
        target_ep_map = {_ep_key(e): e for e in self.target_data["endpoints"]}

        added_endpoints = [target_ep_map[k] for k in target_ep_map if k not in base_ep_map]
        removed_endpoints = [base_ep_map[k] for k in base_ep_map if k not in target_ep_map]
        retained_endpoints = [target_ep_map[k] for k in target_ep_map if k in base_ep_map]

        # 3. Permissions comparison
        def _perm_key(p: Any) -> str:
            if isinstance(p, dict):
                return p.get("name") or p.get("permission") or ""
            return str(p)

        base_perm_map = {_perm_key(p): p for p in self.base_data["permissions"]}
        target_perm_map = {_perm_key(p): p for p in self.target_data["permissions"]}

        added_permissions = [target_perm_map[k] for k in target_perm_map if k not in base_perm_map]
        removed_permissions = [base_perm_map[k] for k in base_perm_map if k not in target_perm_map]
        retained_permissions = [target_perm_map[k] for k in target_perm_map if k in base_perm_map]

        # 4. Components comparison
        def _comp_key(c: Any) -> str:
            if isinstance(c, dict):
                return c.get("class_name") or ""
            return str(c)

        base_comp_map = {_comp_key(c): c for c in self.base_data["components"]}
        target_comp_map = {_comp_key(c): c for c in self.target_data["components"]}

        added_components = [target_comp_map[k] for k in target_comp_map if k not in base_comp_map]
        removed_components = [base_comp_map[k] for k in base_comp_map if k not in target_comp_map]
        retained_components = []
        modified_components = []

        for k in target_comp_map:
            if k in base_comp_map:
                t_comp = target_comp_map[k]
                b_comp = base_comp_map[k]
                # Check if exported status or permissions changed
                if isinstance(t_comp, dict) and isinstance(b_comp, dict):
                    t_exp = bool(t_comp.get("exported", False))
                    b_exp = bool(b_comp.get("exported", False))
                    t_perm = t_comp.get("permission", "")
                    b_perm = b_comp.get("permission", "")
                    
                    if t_exp != b_exp or t_perm != b_perm:
                        modified_components.append({
                            "class_name": k,
                            "component_type": t_comp.get("component_type", ""),
                            "previous": {"exported": b_exp, "permission": b_perm},
                            "current": {"exported": t_exp, "permission": t_perm},
                            "change_type": "export_status_changed" if t_exp != b_exp else "permission_changed",
                        })
                    else:
                        retained_components.append(t_comp)
                else:
                    retained_components.append(t_comp)

        # Calculate security risk delta
        # Risk increases if: new endpoints added, new exported components, new dangerous permissions
        new_exported_count = sum(1 for c in added_components if isinstance(c, dict) and c.get("exported"))
        new_exported_count += sum(1 for m in modified_components if m.get("current", {}).get("exported") and not m.get("previous", {}).get("exported"))
        
        risk_score = 0
        if len(added_endpoints) > 0:
            risk_score += 1
        if len(added_domains) > 0:
            risk_score += 1
        if len(added_permissions) > 0:
            risk_score += 2
        if new_exported_count > 0:
            risk_score += 3
        
        if risk_score >= 3:
            risk_delta = "increased"
        elif len(removed_components) > 0 and risk_score == 0:
            risk_delta = "decreased"
        else:
            risk_delta = "neutral"

        summary = APKDiffSummary(
            new_domains_count=len(added_domains),
            removed_domains_count=len(removed_domains),
            new_endpoints_count=len(added_endpoints),
            removed_endpoints_count=len(removed_endpoints),
            added_permissions_count=len(added_permissions),
            removed_permissions_count=len(removed_permissions),
            added_components_count=len(added_components),
            removed_components_count=len(removed_components),
            modified_components_count=len(modified_components),
            security_risk_delta=risk_delta,
        )

        result = APKDiffResult(
            base_run_id=self.base_data["run_id"],
            target_run_id=self.target_data["run_id"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            domains={
                "added": added_domains,
                "removed": removed_domains,
                "retained": retained_domains,
            },
            endpoints={
                "added": added_endpoints,
                "removed": removed_endpoints,
                "retained": retained_endpoints,
            },
            permissions={
                "added": added_permissions,
                "removed": removed_permissions,
                "retained": retained_permissions,
            },
            components={
                "added": added_components,
                "removed": removed_components,
                "retained": retained_components,
                "modified": modified_components,
            },
        )

        if output_file is not None:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(result.to_dict(), f, indent=2)
                logger.info("Saved comparison result to %s", output_file)
            except Exception as e:
                logger.error("Failed to write diff output to %s: %s", output_file, e)

        return result


def compare_apk_runs(base_run: Any, target_run: Any, output_file: Optional[Path] = None) -> APKDiffResult:
    """Convenience wrapper for APKDiff."""
    diff_engine = APKDiff(base_run, target_run)
    return diff_engine.compare(output_file=output_file)
