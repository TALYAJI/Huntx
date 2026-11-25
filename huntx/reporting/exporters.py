"""HUNTX Bug Bounty & Toolchain Exporters.

Generates clean, ready-to-use wordlists and API collections from passive
reconnaissance artifacts:
  - exports/domains.txt
  - exports/endpoints.txt
  - exports/params.txt
  - exports/deep_links.txt
  - exports/postman_collection.json
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

from huntx.engines.android.config_findings import config_findings


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _one_line(text: Any) -> str:
    """Strip control characters so manifest values cannot inject extra lines."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).replace("`", "'")


def export_bug_bounty_artifacts(run_path: Path) -> Dict[str, Path]:
    """Export bug bounty wordlists and Postman collections for a completed run.

    Args:
        run_path: Path to the session RUN_YYYYMMDD_HHMMSS directory.

    Returns:
        Dictionary mapping export type to generated file Path.
    """
    exports_dir = run_path / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Path] = {}

    # 1. Load source artifacts
    apk_info = _load_json(run_path / "android" / "apk-info.json", {})
    pkg_name = apk_info.get("package_name") or "target_app"
    app_name = apk_info.get("application_name") or apk_info.get("app_name") or pkg_name

    domains_data = _load_json(run_path / "api" / "domains.json", {})
    if isinstance(domains_data, dict):
        domains_list = domains_data.get("domains", [])
    elif isinstance(domains_data, list):
        domains_list = domains_data
    else:
        domains_list = []

    endpoints_data = _load_json(run_path / "api" / "endpoints.json", [])
    if isinstance(endpoints_data, dict):
        endpoints_list = endpoints_data.get("endpoints", [])
    elif isinstance(endpoints_data, list):
        endpoints_list = endpoints_data
    else:
        endpoints_list = []

    passports_data = _load_json(run_path / "mapping" / "endpoint-passports.json", {})
    passports_list = passports_data.get("passports", []) if isinstance(passports_data, dict) else []

    params_data = _load_json(run_path / "api" / "parameters.json", {})
    if isinstance(params_data, dict):
        params_list = params_data.get("parameters", [])
    elif isinstance(params_data, list):
        params_list = params_data
    else:
        params_list = []

    components_data = _load_json(run_path / "android" / "components.json", {})
    components_list = components_data.get("components", []) if isinstance(components_data, dict) else []

    # 2. Export domains.txt
    noise_domains = {
        "schemas.android.com",
        "www.w3.org",
        "xml.org",
        "xmlpull.org",
        "purl.org",
        "apache.org",
    }
    clean_domains: Set[str] = set()
    for d in domains_list:
        dom = (d.get("domain") or d.get("value") or "").strip().lower()
        if dom and dom not in noise_domains and "." in dom:
            clean_domains.add(dom)

    domains_file = exports_dir / "domains.txt"
    domains_file.write_text("\n".join(sorted(clean_domains)) + ("\n" if clean_domains else ""), encoding="utf-8")
    results["domains"] = domains_file

    # 3. Export endpoints.txt (both raw and normalized routes)
    clean_routes: Set[str] = set()
    for ep in endpoints_list:
        path = (ep.get("path") or "").strip()
        norm = (ep.get("normalized_path") or "").strip()
        if path and path != "/":
            clean_routes.add(path)
        if norm and norm != "/" and norm != path:
            clean_routes.add(norm)

    endpoints_file = exports_dir / "endpoints.txt"
    endpoints_file.write_text("\n".join(sorted(clean_routes)) + ("\n" if clean_routes else ""), encoding="utf-8")
    results["endpoints"] = endpoints_file

    # 4. Export params.txt
    clean_params: Set[str] = set()
    for p in params_list:
        name = (p.get("name") or "").strip()
        if name:
            clean_params.add(name)
    for ep in endpoints_list:
        for qp in ep.get("query_params", []):
            q_name = (qp.get("name") or "") if isinstance(qp, dict) else str(qp)
            if q_name:
                clean_params.add(q_name.strip())
        for pp in ep.get("path_params", []):
            p_name = (pp.get("name") or "") if isinstance(pp, dict) else str(pp)
            if p_name:
                clean_params.add(p_name.strip())

    params_file = exports_dir / "params.txt"
    params_file.write_text("\n".join(sorted(clean_params)) + ("\n" if clean_params else ""), encoding="utf-8")
    results["params"] = params_file

    # 5. Export deep_links.txt
    deep_links: Set[str] = set()
    for comp in components_list:
        comp_name = comp.get("name", "")
        for flt in comp.get("intent_filters", []):
            for data in flt.get("data", []):
                scheme = data.get("scheme", "")
                host = data.get("host", "")
                path_prefix = data.get("pathPrefix", "") or data.get("path", "") or data.get("pathPattern", "")
                if scheme:
                    uri = f"{scheme}://{host}{path_prefix}" if host else f"{scheme}://{path_prefix}"
                    deep_links.add(_one_line(f"{uri}  # Component: {comp_name}"))

    deep_links_file = exports_dir / "deep_links.txt"
    deep_links_file.write_text("\n".join(sorted(deep_links)) + ("\n" if deep_links else ""), encoding="utf-8")
    results["deep_links"] = deep_links_file

    # 6. Export postman_collection.json (Postman v2.1)
    target_items = passports_list if passports_list else endpoints_list
    postman_items: List[Dict[str, Any]] = []
    for idx, item in enumerate(target_items, start=1):
        ep_id = item.get("endpoint_id") or f"EP-{idx:05d}"
        route = item.get("path") or "/"
        method = (item.get("method") or "GET").upper()
        if method in ("UNKNOWN", ""):
            method = "GET"
        dom = (item.get("domain") or "").strip()

        clean_route = route.lstrip("/")
        path_parts = [seg for seg in clean_route.split("/") if seg]
        # Relative routes get a variable: guessing a host would aim the analyst's
        # requests at an unrelated third party.
        base = f"https://{dom}" if dom else "{{baseUrl}}"
        raw_url = f"{base}/{clean_route}"
        url_obj: Dict[str, Any] = {"raw": raw_url, "host": dom.split(".") if dom else ["{{baseUrl}}"], "path": path_parts}
        if dom:
            url_obj["protocol"] = "https"

        req_entry = {
            "name": f"[{ep_id}] {method} {route}",
            "request": {
                "method": method,
                "header": [
                    {"key": "Accept", "value": "application/json"},
                    {"key": "User-Agent", "value": "HUNTX-Recon"},
                ],
                "url": url_obj,
                "description": f"Discovered by HUNTX static reconnaissance.\nConfidence: {item.get('confidence', 0.6)}\nEvidence: {item.get('evidence', '')}",
            },
            "response": [],
        }
        postman_items.append(req_entry)

    postman_collection = {
        "info": {
            "_postman_id": f"huntx-{pkg_name}",
            "name": f"HUNTX Recon - {app_name} ({pkg_name})",
            "description": f"Automatically generated passive API reconnaissance collection for {pkg_name}.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": postman_items,
        "variable": [{"key": "baseUrl", "value": "https://CHANGE-ME.invalid"}],
    }

    postman_file = exports_dir / "postman_collection.json"
    with open(postman_file, "w", encoding="utf-8") as f:
        json.dump(postman_collection, f, indent=2)
    results["postman"] = postman_file

    # 7. Export Security Audit artifacts (secrets, cloud_assets, adb_pocs, bounty_drafts)
    audit_data = _load_json(run_path / "android" / "security-audit.json", {})
    manifest_data = _load_json(run_path / "android" / "manifest-analysis.json", {})

    secrets = audit_data.get("secrets", [])
    secrets_lines = [f"[{s.get('type', 'secret')}] {s.get('value', '')}  (source: {s.get('source', '')})" for s in secrets]
    secrets_file = exports_dir / "secrets.txt"
    secrets_file.write_text("\n".join(secrets_lines) + ("\n" if secrets_lines else ""), encoding="utf-8")
    results["secrets"] = secrets_file

    cloud_assets = audit_data.get("cloud_assets", [])
    cloud_lines = [f"[{c.get('type', 'cloud')}] {c.get('value', '')}  (source: {c.get('source', '')})" for c in cloud_assets]
    cloud_file = exports_dir / "cloud_assets.txt"
    cloud_file.write_text("\n".join(cloud_lines) + ("\n" if cloud_lines else ""), encoding="utf-8")
    results["cloud_assets"] = cloud_file

    adb_pocs = audit_data.get("adb_pocs", [])
    poc_lines = [f"# {p.get('type', '')} — {_one_line(p.get('component', ''))}\n{p.get('command', '')}\n" for p in adb_pocs]
    adb_file = exports_dir / "adb_pocs.txt"
    adb_file.write_text("\n".join(poc_lines), encoding="utf-8")
    results["adb_pocs"] = adb_file

    # 8. Export bounty_drafts.md
    sha256 = apk_info.get("sha256", "N/A")
    ver_name = apk_info.get("version_name", "N/A")
    ver_code = apk_info.get("version_code", "N/A")
    nsc = _load_json(run_path / "android" / "resources.json", {}).get("network_security_config", {})

    drafts: List[str] = [
        f"# Bug Bounty Triage Drafts — {app_name} (`{pkg_name}`)",
        f"- **Version:** {ver_name} (Code: {ver_code})",
        f"- **APK SHA-256:** `{sha256}`",
        "",
        "> **Note:** These are evidence-backed passive findings requiring manual verification before submission.",
        "",
    ]

    for item in config_findings(manifest_data, nsc, apk_info):
        drafts.append(f"## {item['title']} [{item['severity']}]")
        if item["cwe"]:
            drafts.append(f"- **CWE:** {item['cwe']}")
        drafts.extend([
            f"- **Evidence:** {_one_line(item['evidence'])}",
            f"- **Verify:** {_one_line(item['verify'])}",
            "",
        ])

    if adb_pocs:
        drafts.extend([
            "## Unprotected Exported Android Components",
            "- **CWE:** CWE-926 (Improper Export of Android Application Components)",
            f"- **Count:** {len(adb_pocs)} exported component(s) without permission barriers or with exposed deep links.",
            "- **ADB Verification Commands:**",
            "  ```bash",
        ])
        for p in adb_pocs[:10]:
            drafts.append(f"  # {p.get('type')}: {_one_line(p.get('component', ''))}")
            drafts.append(f"  {p.get('command')}")
        drafts.extend(["  ```", ""])

    if secrets:
        drafts.extend([
            "## Candidate Hardcoded Secrets",
            "- **CWE:** CWE-798 (Use of Hard-coded Credentials), if confirmed live and sensitive",
            f"- **Findings:** {len(secrets)} candidate(s). See `exports/secrets.txt`.",
            "",
        ])

    if cloud_assets:
        drafts.extend([
            "## Cloud Endpoints to Review (not a vulnerability by itself)",
            "- **Check:** access rules, only where in scope. A URL or bucket name is not a credential.",
            *(f"- `{_one_line(c.get('value', ''))}` ({_one_line(c.get('source', ''))})" for c in cloud_assets[:20]),
            "",
        ])

    drafts_file = exports_dir / "bounty_drafts.md"
    drafts_file.write_text("\n".join(drafts), encoding="utf-8")
    results["bounty_drafts"] = drafts_file

    return results
