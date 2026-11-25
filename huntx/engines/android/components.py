"""HUNTX Android Components Enumeration Engine.

Enumerates and inspects application components declared in AndroidManifest:
- Activities and activity aliases
- Services
- Broadcast Receivers
- Content Providers

Extracts exported status, required permissions, intent filters, and class names.
Optionally persists components to the HUNTX session database repository.

Outputs:
- android/components.json
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from huntx.engines.android.manifest import analyze_manifest

logger = logging.getLogger(__name__)


@dataclass
class IntentFilterInfo:
    """Intent filter summary."""

    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentDetail:
    """Detailed component information."""

    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    authorities: Optional[str] = None
    grant_uri_permissions: bool = False
    intent_filters: List[IntentFilterInfo] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["intent_filters"] = [f.to_dict() for f in self.intent_filters]
        return d


def is_unprotected(comp: Dict[str, Any]) -> bool:
    """Exported, reachable by any app, and not merely the launcher entry point."""
    if not comp.get("exported"):
        return False
    if (comp.get("component_type") or "").lower() == "provider":
        return not (comp.get("permission") or (comp.get("read_permission") and comp.get("write_permission")))
    if comp.get("permission"):
        return False
    # ponytail: a launcher activity with extra filters (deep links) still counts
    return not (
        (comp.get("component_type") or "").lower() == "activity"
        and comp.get("intent_filters")
        and all("android.intent.category.LAUNCHER" in f.get("categories", []) for f in comp["intent_filters"])
    )


def enumerate_components(
    target: Union[str, Path, Dict[str, Any]],
    output_dir: Optional[Union[str, Path]] = None,
    session: Any = None,
) -> Dict[str, Any]:
    """Enumerate and categorize all components from an APK or manifest data.

    Args:
        target: APK file path, directory path, or already parsed manifest dict.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `components.json`.
        session: Optional HUNTX Session object to save components to SQLite DB.

    Returns:
        Dict representing comprehensive components inventory and statistics.
    """
    if isinstance(target, dict):
        manifest_data = target
    else:
        manifest_data = analyze_manifest(target)

    raw_components = manifest_data.get("components", [])

    activities: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    receivers: List[Dict[str, Any]] = []
    providers: List[Dict[str, Any]] = []
    all_components: List[Dict[str, Any]] = []

    counts_by_type = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}
    exported_by_type = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}

    for c in raw_components:
        c_type = c.get("type", "activity")
        name = c.get("name", "")
        exported = bool(c.get("exported", False))
        perm = c.get("permission")
        read_perm = c.get("read_permission")
        write_perm = c.get("write_permission")
        authorities = c.get("authorities")
        grant_uri = bool(c.get("grant_uri_permissions", False))
        attrs = c.get("attributes", {})

        raw_filters = c.get("intent_filters", [])
        filters = []
        for rf in raw_filters:
            filters.append(
                IntentFilterInfo(
                    actions=rf.get("actions", []),
                    categories=rf.get("categories", []),
                    data=rf.get("data", []),
                )
            )

        detail = ComponentDetail(
            name=name,
            component_type=c_type,
            exported=exported,
            permission=perm,
            read_permission=read_perm,
            write_permission=write_perm,
            authorities=authorities,
            grant_uri_permissions=grant_uri,
            intent_filters=filters,
            attributes=attrs,
        )

        detail_dict = detail.to_dict()
        detail_dict["class_name"] = name
        detail_dict["unprotected"] = is_unprotected(detail_dict)
        all_components.append(detail_dict)

        if c_type in counts_by_type:
            counts_by_type[c_type] += 1
            if exported:
                exported_by_type[c_type] += 1

        if c_type == "activity":
            activities.append(detail_dict)
        elif c_type == "service":
            services.append(detail_dict)
        elif c_type == "receiver":
            receivers.append(detail_dict)
        elif c_type == "provider":
            providers.append(detail_dict)

    result = {
        "summary": {
            "total_components": len(all_components),
            "total_exported": sum(exported_by_type.values()),
            "counts_by_type": counts_by_type,
            "exported_by_type": exported_by_type,
        },
        "total_components": len(all_components),
        "exported_count": sum(exported_by_type.values()),
        "unprotected_count": sum(c["unprotected"] for c in all_components),
        "components": all_components,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
    }

    # Save to SQLite database if session repository is available
    if session is not None:
        try:
            from huntx.storage.repository import Repository

            with Repository(session) as repo:
                for comp in all_components:
                    repo.save_component(
                        {
                            "component_type": comp["component_type"],
                            "class_name": comp["name"],
                            "exported": comp["exported"],
                            "permission": comp.get("permission") or "",
                            "session_id": getattr(session.metadata, "session_id", ""),
                        }
                    )
        except Exception as e:
            logger.debug("Could not save components to repository: %s", e)

    # Write output file if output_dir provided
    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        json_file = out_path / "components.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    return result
