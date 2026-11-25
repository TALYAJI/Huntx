"""HUNTX Android-to-API Mapper engine.

Associates API endpoints with Android components, classes, activities, services,
and Retrofit interfaces using deterministic matching and confidence scoring.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from huntx.core.logger import get_logger
from huntx.engines.api.endpoints import match_xref
from huntx.intelligence.endpoint_passport import infer_feature_group

logger = get_logger("huntx.intelligence.android_api_mapper")

_FILE_LOCATION = re.compile(r"\.(?:dex|xml|arsc|json|properties|txt|conf|js|bundle|apk)(?::|$)|^assets/", re.IGNORECASE)


@dataclass
class EndpointSourceMatch:
    """A match linking an API endpoint to an Android source location."""

    class_name: str
    method_name: str = ""
    component_type: str = "class"  # activity, service, receiver, provider, retrofit_interface, helper
    confidence: float = 0.5
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClassEndpointMapping:
    """An Android class with all associated API endpoints."""

    class_name: str
    component_type: str
    feature_group: str
    confidence: float
    endpoints: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MappingResult:
    """Result of Android-to-API mapping analysis."""

    android_api_map: Dict[str, Any]
    endpoint_sources: Dict[str, Any]


class AndroidApiMapper:
    """Engine for correlating Android components and classes with API endpoints."""

    def __init__(self, session: Any = None) -> None:
        self.session = session
        self.session_id = getattr(getattr(session, "metadata", None), "session_id", "")
        self.run_path = getattr(session, "run_path", None)

    def map_endpoints(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        components: Optional[List[Dict[str, Any]]] = None,
        strings: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None,
    ) -> MappingResult:
        """Perform deterministic correlation between Android code and endpoints.

        Args:
            endpoints: Optional list of endpoint or passport dicts.
            components: Optional list of component dicts.
            strings: Optional list of extracted string dicts.
            output_dir: Optional directory to save output JSON files.

        Returns:
            MappingResult containing android_api_map and endpoint_sources.
        """
        logger.info("Starting Android-to-API mapping")

        endpoints_list = list(endpoints or [])
        components_list = list(components or [])
        strings_list = list(strings or [])

        # Attempt to read from session files if not provided
        if self.run_path and isinstance(self.run_path, Path):
            if not endpoints_list:
                passport_file = self.run_path / "mapping" / "endpoint-passports.json"
                api_ep_file = self.run_path / "api" / "endpoints.json"
                if passport_file.exists():
                    try:
                        with open(passport_file, "r", encoding="utf-8") as f:
                            p_data = json.load(f)
                            endpoints_list = p_data.get("passports", []) if isinstance(p_data, dict) else p_data
                    except Exception as e:
                        logger.warning("Error reading %s: %s", passport_file, e)
                elif api_ep_file.exists():
                    try:
                        with open(api_ep_file, "r", encoding="utf-8") as f:
                            e_data = json.load(f)
                            endpoints_list = e_data.get("endpoints", []) if isinstance(e_data, dict) else e_data
                    except Exception as e:
                        logger.warning("Error reading %s: %s", api_ep_file, e)

            if not components_list:
                comp_file = self.run_path / "android" / "components.json"
                if comp_file.exists():
                    try:
                        with open(comp_file, "r", encoding="utf-8") as f:
                            c_data = json.load(f)
                            components_list = c_data.get("components", []) if isinstance(c_data, dict) else c_data
                    except Exception as e:
                        logger.warning("Error reading %s: %s", comp_file, e)

            if not strings_list:
                strings_file = self.run_path / "android" / "strings.json"
                if strings_file.exists():
                    try:
                        with open(strings_file, "r", encoding="utf-8") as f:
                            s_data = json.load(f)
                            if isinstance(s_data, dict):
                                strings_list = s_data.get("strings", [])
                                if not strings_list:
                                    strings_list = (
                                        s_data.get("urls", [])
                                        + s_data.get("api_paths", [])
                                        + s_data.get("domains", [])
                                    )
                            else:
                                strings_list = s_data
                    except Exception as e:
                        logger.warning("Error reading %s: %s", strings_file, e)

        # Build index of components
        component_type_by_class: Dict[str, str] = {}
        for c in components_list:
            c_name = c.get("name") or c.get("class_name", "")
            c_type = c.get("component_type", "activity").lower()
            if c_name:
                component_type_by_class[c_name] = c_type

        # Build index of extracted strings pointing to classes
        # Format of string entry: {"value": "...", "source_location": "...", "source_type": "..."}
        # source_location could be "com/target/app/api/UserClient.smali" or "com.target.app.MainActivity"
        string_matches_by_class: Dict[str, List[Tuple[str, str]]] = {}
        for s in strings_list:
            val = s.get("value", "")
            loc = s.get("source_location", "") or s.get("source", "")
            # "classes.dex" or "res/xml/a.xml" says which file, not which class
            if not val or not loc or _FILE_LOCATION.search(loc):
                continue
            # Normalize class name from smali or dot notation
            clean_class = loc.replace("/", ".").replace(".smali", "").strip()
            # If method is included e.g. "com.example.Class->method"
            method = ""
            if "->" in clean_class:
                parts = clean_class.split("->", 1)
                clean_class = parts[0]
                method = parts[1].split("(")[0]
            elif ":" in clean_class:
                parts = clean_class.split(":", 1)
                clean_class = parts[0]
                method = parts[1]

            if clean_class not in string_matches_by_class:
                string_matches_by_class[clean_class] = []
            string_matches_by_class[clean_class].append((val, method))

        # Maps for our two output views
        # 1. endpoint_id -> list of EndpointSourceMatch
        endpoint_sources_map: Dict[str, List[EndpointSourceMatch]] = {}
        # 2. class_name -> ClassEndpointMapping
        class_endpoints_map: Dict[str, ClassEndpointMapping] = {}

        for ep_idx, ep in enumerate(endpoints_list, start=1):
            ep_id = ep.get("endpoint_id") or f"EP-{ep_idx:05d}"
            ep_path = ep.get("path", "")
            norm_path = ep.get("normalized_path", "") or ep_path
            ep_method = ep.get("method", "UNKNOWN")
            ep_domain = ep.get("domain", "")
            direct_source_class = ep.get("source_class", "")
            direct_source_method = ep.get("source_method", "")
            feat_group = ep.get("feature_group") or infer_feature_group(norm_path, direct_source_class)

            sources_for_this_ep: List[EndpointSourceMatch] = []

            # 1. Direct source class from static analysis / Retrofit inspection
            if direct_source_class:
                is_retrofit = any(k in direct_source_class.lower() for k in ["retrofit", "api", "service", "client"])
                comp_type = component_type_by_class.get(direct_source_class, "retrofit_interface" if is_retrofit else "class")
                conf = 0.95 if comp_type == "retrofit_interface" else 0.85
                sources_for_this_ep.append(EndpointSourceMatch(
                    class_name=direct_source_class,
                    method_name=direct_source_method,
                    component_type=comp_type,
                    confidence=conf,
                    evidence=f"Direct static endpoint declaration in {direct_source_class}" + (f".{direct_source_method}" if direct_source_method else ""),
                ))

            # 1b. Scan Dalvik bytecode XRefs (dex-xrefs.json) if available
            if not direct_source_class and self.run_path and isinstance(self.run_path, Path):
                xref_file = self.run_path / "android" / "dex-xrefs.json"
                if xref_file.exists():
                    if not hasattr(self, "_cached_xrefs"):
                        try:
                            with open(xref_file, "r", encoding="utf-8") as xf:
                                self._cached_xrefs = json.load(xf)
                        except Exception:
                            self._cached_xrefs = []
                    xr = match_xref(ep, [(v, x) for x in self._cached_xrefs for v in x.get("strings", [])])
                    if xr and xr.get("class_name"):
                        x_cls, x_meth = xr["class_name"], xr.get("method_name", "")
                        c_type = component_type_by_class.get(x_cls, "class")
                        sources_for_this_ep.append(EndpointSourceMatch(
                            class_name=x_cls,
                            method_name=x_meth,
                            component_type=c_type,
                            confidence=0.85 if c_type != "class" else 0.75,
                            evidence=f"Dalvik bytecode const-string in {x_cls}.{x_meth}()",
                        ))

            # 2. Scan string_matches_by_class for matching URL paths
            target_path_clean = ep_path.lstrip("/").split("?")[0]
            target_norm_clean = norm_path.lstrip("/").split("?")[0]
            
            for cls_name, val_list in string_matches_by_class.items():
                if direct_source_class and cls_name == direct_source_class:
                    continue  # already added with high confidence

                for val, method in val_list:
                    # Check if string contains endpoint path or vice-versa
                    if not val:
                        continue
                    clean_val = val.lstrip("/").split("?")[0]
                    matched = False
                    match_type = ""
                    
                    if target_path_clean and (target_path_clean in clean_val or clean_val == target_path_clean):
                        matched = True
                        match_type = "Exact or substring path match"
                    elif target_norm_clean and (target_norm_clean in clean_val or clean_val == target_norm_clean):
                        matched = True
                        match_type = "Normalized path match"
                    elif len(target_path_clean) > 8 and clean_val in target_path_clean and len(clean_val) > 8:
                        matched = True
                        match_type = "Partial segment path match"

                    if matched:
                        # Determine component type and confidence
                        is_retro = any(k in cls_name.lower() for k in ["retrofit", "api", "service", "client"])
                        comp_type = component_type_by_class.get(cls_name, "retrofit_interface" if is_retro else "class")
                        
                        if comp_type == "retrofit_interface":
                            conf = 0.95
                        elif comp_type in ["activity", "service", "receiver", "provider"]:
                            conf = 0.85
                        elif any(k in cls_name.lower() for k in ["repo", "repository", "datasource", "helper", "viewmodel"]):
                            conf = 0.75
                        else:
                            conf = 0.65

                        # Avoid duplicate match for same class
                        if not any(s.class_name == cls_name for s in sources_for_this_ep):
                            sources_for_this_ep.append(EndpointSourceMatch(
                                class_name=cls_name,
                                method_name=method,
                                component_type=comp_type,
                                confidence=conf,
                                evidence=f"{match_type} in string: '{val}' ({cls_name})",
                            ))
                        break  # move to next class

            # 3. Heuristic matching between component name and endpoint path if no sources found
            if not sources_for_this_ep:
                # Extract significant token from path
                segments = [s.lower() for s in re.split(r"[/_-]", norm_path) if len(s) >= 4 and not s.startswith("{") and s not in ["api", "v1", "v2", "v3", "v4", "rest", "json"]]
                for comp_cls, comp_type in component_type_by_class.items():
                    cls_lower = comp_cls.lower()
                    for seg in segments:
                        if seg in cls_lower:
                            sources_for_this_ep.append(EndpointSourceMatch(
                                class_name=comp_cls,
                                method_name="",
                                component_type=comp_type,
                                confidence=0.50,
                                evidence=f"Heuristic name correlation: segment '{seg}' matched component {comp_cls}",
                            ))
                            break
                    if len(sources_for_this_ep) >= 3:
                        break

            # If still nothing, create an unresolved reference entry
            if not sources_for_this_ep:
                sources_for_this_ep.append(EndpointSourceMatch(
                    class_name="<unresolved_source>",
                    method_name="",
                    component_type="unknown",
                    confidence=0.30,
                    evidence="Discovered from network traffic or standalone string without class reference",
                ))

            # Store in endpoint_sources_map
            endpoint_sources_map[ep_id] = sources_for_this_ep

            # Aggregate into class_endpoints_map
            for src in sources_for_this_ep:
                if src.class_name == "<unresolved_source>":
                    continue
                if src.class_name not in class_endpoints_map:
                    class_endpoints_map[src.class_name] = ClassEndpointMapping(
                        class_name=src.class_name,
                        component_type=src.component_type,
                        feature_group=feat_group,
                        confidence=src.confidence,
                        endpoints=[],
                    )
                mapping_entry = class_endpoints_map[src.class_name]
                # Avoid duplicate endpoint in same class
                if not any(e.get("endpoint_id") == ep_id for e in mapping_entry.endpoints):
                    mapping_entry.endpoints.append({
                        "endpoint_id": ep_id,
                        "method": ep_method,
                        "path": ep_path,
                        "normalized_path": norm_path,
                        "domain": ep_domain,
                        "confidence": src.confidence,
                        "evidence": src.evidence,
                    })

        # Format final JSON structures
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. android-api-map.json
        classes_output = [c.to_dict() for c in class_endpoints_map.values()]
        # Sort by confidence descending, then class name
        classes_output.sort(key=lambda x: (-x["confidence"], x["class_name"]))
        android_api_map = {
            "generated_at": now_iso,
            "session_id": self.session_id,
            "total_mapped_classes": len(classes_output),
            "classes": classes_output,
        }

        # 2. endpoint-sources.json
        endpoints_output = []
        for ep_idx, ep in enumerate(endpoints_list, start=1):
            ep_id = ep.get("endpoint_id") or f"EP-{ep_idx:05d}"
            sources = [s.to_dict() for s in endpoint_sources_map.get(ep_id, [])]
            # Best confidence
            best_conf = max((s["confidence"] for s in sources), default=0.0)
            endpoints_output.append({
                "endpoint_id": ep_id,
                "domain": ep.get("domain", ""),
                "path": ep.get("path", ""),
                "normalized_path": ep.get("normalized_path", ""),
                "method": ep.get("method", "UNKNOWN"),
                "feature_group": ep.get("feature_group") or infer_feature_group(ep.get("path", "")),
                "confidence": round(best_conf, 2),
                "sources": sources,
            })

        endpoints_output.sort(key=lambda x: x["endpoint_id"])
        endpoint_sources = {
            "generated_at": now_iso,
            "session_id": self.session_id,
            "total_mapped_endpoints": len(endpoints_output),
            "endpoints": endpoints_output,
        }

        # Persist to mapping directory
        target_dir = output_dir
        if target_dir is None and self.run_path and isinstance(self.run_path, Path):
            target_dir = self.run_path / "mapping"

        if target_dir is not None:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                map_file = target_dir / "android-api-map.json"
                with open(map_file, "w", encoding="utf-8") as f:
                    json.dump(android_api_map, f, indent=2)
                logger.info("Saved %s", map_file)

                sources_file = target_dir / "endpoint-sources.json"
                with open(sources_file, "w", encoding="utf-8") as f:
                    json.dump(endpoint_sources, f, indent=2)
                logger.info("Saved %s", sources_file)
            except Exception as e:
                logger.error("Failed to write mapping files to %s: %s", target_dir, e)

        return MappingResult(android_api_map=android_api_map, endpoint_sources=endpoint_sources)


def map_android_to_apis(session: Any = None, **kwargs) -> MappingResult:
    """Convenience functional wrapper for AndroidApiMapper."""
    mapper = AndroidApiMapper(session=session)
    return mapper.map_endpoints(**kwargs)
