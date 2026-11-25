"""The passive analysis pipeline behind ``huntx scan`` and the menu's "all"."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from huntx.core.logger import get_logger
from huntx.core.session import Session, SessionManager

logger = get_logger("core.pipeline")


class ScanError(RuntimeError):
    """A scan could not be started; the message is safe to show to the user."""


def write_dex_xrefs(apks: List[Path], run_path: Path) -> int:
    """Write ``android/dex-xrefs.json`` for every APK/split; returns the method count."""
    from huntx.engines.android.dex_xref import extract_apk_xrefs

    xrefs = [asdict(x) for x in extract_apk_xrefs(apks)]
    out = run_path / "android" / "dex-xrefs.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(xrefs), encoding="utf-8")
    return len(xrefs)


def open_session(target_dir: Path, sources: List[Path]) -> tuple[Session, List[Path]]:
    """Create a session, copy/unpack *sources* into it and return the analysable APKs."""
    from huntx.core.safezip import is_apk

    manager = SessionManager(target_dir)
    session = manager.create_session(sources)
    apks = [a for a in manager.copy_input_apks(session, sources) if is_apk(a)]
    if not apks:
        names = ", ".join(s.name for s in sources)
        raise ScanError(f"No valid Android package found in: {names}")
    return session, apks


def run_pipeline(
    session: Session,
    apks: List[Path],
    traffic: Optional[List[Path]] = None,
    filter_noise: Optional[bool] = None,
    progress: Callable[[str], None] = lambda _: None,
) -> Dict[str, Any]:
    """Run every passive engine in dependency order and return their results."""
    from huntx.engines.android.apk_info import extract_apk_info
    from huntx.engines.android.components import enumerate_components
    from huntx.engines.android.manifest import analyze_manifest
    from huntx.engines.android.permissions import analyze_permissions
    from huntx.engines.android.resources import analyze_resources
    from huntx.engines.android.security_audit import run_security_audit
    from huntx.engines.android.strings import extract_strings
    from huntx.engines.api.domains import run_domain_discovery
    from huntx.engines.api.endpoints import run_endpoint_extraction
    from huntx.engines.api.normalizer import run_normalization
    from huntx.engines.api.parameters import run_parameter_extraction
    from huntx.engines.traffic.parser import run_traffic_analysis
    from huntx.intelligence.android_api_mapper import map_android_to_apis
    from huntx.intelligence.endpoint_passport import generate_endpoint_passports

    run, base = session.run_path, apks[0]
    android, api = run / "android", run / "api"
    r: Dict[str, Any] = {}

    def step(key: str, label: str, fn: Callable[[], Any]) -> None:
        progress(label)
        logger.info("%s", label)
        r[key] = fn()

    step("apk_info", "APK metadata", lambda: extract_apk_info(base, output_dir=android))
    step("manifest", "Manifest", lambda: analyze_manifest(base, output_dir=android))
    step("permissions", "Permissions", lambda: analyze_permissions(r["manifest"], output_dir=android))
    step("components", "Components", lambda: enumerate_components(r["manifest"], output_dir=android, session=session))
    step("strings", "Strings", lambda: extract_strings(apks, output_dir=android))
    step("resources", "Resources", lambda: analyze_resources(base, output_dir=android))
    step("xrefs", "Bytecode cross-references", lambda: write_dex_xrefs(apks, run))
    step("audit", "Security audit", lambda: run_security_audit(apks, run_path=run, output_dir=android))
    if traffic:
        step("traffic", "Traffic import", lambda: run_traffic_analysis(
            session=session, source_files=list(traffic), output_dir=run / "traffic"))
    step("domains", "Domains", lambda: run_domain_discovery(session=session, output_dir=api))
    step("endpoints", "Endpoints", lambda: run_endpoint_extraction(
        session=session, output_dir=api, filter_noise=filter_noise))
    step("parameters", "Parameters", lambda: run_parameter_extraction(session=session, output_dir=api))
    step("normalized", "Normalization", lambda: run_normalization(session=session, output_dir=api))
    # Passports assign the EP ids that the mapping refers to
    step("passports", "Endpoint passports", lambda: generate_endpoint_passports(session=session))
    step("mapping", "Android-to-API mapping", lambda: map_android_to_apis(session=session))

    session.metadata.completed_ops = sorted(
        {*session.metadata.completed_ops, *map(str, (*range(1, 11), 14, 15, 18, 19, 20, 21)), *(["13"] if traffic else [])},
        key=int,
    )
    SessionManager(run.parent).save_metadata(session)
    r["reports"] = write_reports(session, progress)
    return r


def write_reports(session: Session, progress: Callable[[str], None] = lambda _: None) -> Dict[str, Path]:
    """(Re)generate every report and export from the session's stored evidence."""
    from huntx.engines.api.openapi import export_openapi_spec
    from huntx.reporting.csv_report import generate_csv_reports
    from huntx.reporting.exporters import export_bug_bounty_artifacts
    from huntx.reporting.html_report import generate_html_report
    from huntx.reporting.json_report import generate_json_report
    from huntx.reporting.summary_report import generate_summary_report

    progress("Reports")
    data = generate_json_report(session=session)
    paths = {
        "json": session.run_path / "reports" / "huntx-report.json",
        "html": generate_html_report(session=session, report_data=data),
        "summary": generate_summary_report(session=session, report_data=data),
    }
    generate_csv_reports(session=session)
    paths.update(export_bug_bounty_artifacts(session.run_path))

    spec = export_openapi_spec(data["findings"]["endpoints"], title=f"{data['apk_metadata']['package_name']} (discovered)")
    paths["openapi"] = session.run_path / "exports" / "openapi.json"
    paths["openapi"].write_text(json.dumps(spec, indent=2), encoding="utf-8")
    return paths
