"""HUNTX One-Page Technical Reconnaissance Summary Report Generator.

Generates a clean, information-rich, black-and-white, single-page A4 technical report.
Horizontally centred on screen and print, strict typography, evidence-driven,
zero external dependencies or remote CDNs.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntx.engines.android.components import is_unprotected
from huntx.core.config import HUNTX_VERSION
from huntx.core.logger import get_logger
from huntx.reporting.json_report import JSONReportGenerator

logger = get_logger("huntx.reporting.summary_report")


def _esc(val: Any) -> str:
    """Safely escape text for HTML."""
    if val is None:
        return "Not Available"
    s = str(val).strip()
    return html.escape(s) if s else "Not Available"


def _schemes(domain: Any, endpoints: List[Dict[str, Any]]) -> str:
    """URL schemes actually observed for a host; "unknown" when only its name was seen."""
    name = domain.get("domain", "") if isinstance(domain, dict) else str(domain)
    texts = list(domain.get("sample_urls", [])) if isinstance(domain, dict) else []
    texts += [str(e.get("evidence", "")) for e in endpoints if isinstance(e, dict) and e.get("domain") == name]
    return "/".join(x.upper() for x in ("http", "https") if any(f"{x}://{name}" in t for t in texts)) or "unknown"


def generate_summary_report(
    session: Any = None,
    report_data: Optional[Dict[str, Any]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    """Generate the authoritative one-page black-and-white A4 technical summary report.

    Args:
        session: Active HUNTX session instance.
        report_data: Optional pre-compiled JSON report dict.
        output_path: Optional explicit file path for huntx-summary.html.

    Returns:
        Path to the generated huntx-summary.html file.
    """
    logger.info("Generating one-page A4 technical summary report")

    if report_data is None:
        generator = JSONReportGenerator(session=session)
        report_data = generator.generate()

    target = report_data.get("target", {})
    target_name = target.get("name", "Unknown Target")
    session_id = target.get("session_id", "N/A")
    created_at = target.get("created_at", datetime.now(timezone.utc).isoformat())

    apk_meta = report_data.get("apk_metadata", {})
    summary = report_data.get("summary", {})
    findings = report_data.get("findings", {})
    limitations = report_data.get("extraction_limitations", [])

    # Extract application identity fields
    app_name = apk_meta.get("application_name") or target_name
    package_name = apk_meta.get("package_name") or "Not Available"
    version_name = apk_meta.get("version_name") or "Not Available"
    version_code = apk_meta.get("version_code")
    vc_display = str(version_code) if version_code not in (None, "", "null") else "Not Available"
    min_sdk = str(apk_meta.get("min_sdk") or "Not Available")
    target_sdk = str(apk_meta.get("target_sdk") or "Not Available")
    debuggable = apk_meta.get("debuggable", False)
    cleartext_traffic = apk_meta.get("cleartext_traffic", False)
    sha256_hash = apk_meta.get("sha256") or "Not Available"
    file_size_human = apk_meta.get("size_human") or "Not Available"

    # Summary metrics
    domains = findings.get("domains", [])
    endpoints = findings.get("endpoints", [])
    components = findings.get("components", [])
    permissions = findings.get("permissions", [])
    net_libs = findings.get("networking_libraries", ["HttpURLConnection / Android Networking"])

    total_endpoints = summary.get("total_endpoints", len(endpoints))
    total_domains = summary.get("total_domains", len(domains))
    total_components = summary.get("total_components", len(components))
    total_permissions = summary.get("total_permissions", len(permissions))
    exported_comps = summary.get("exported_components", len([c for c in components if c.get("exported")]))
    unprotected_comps = summary.get("high_risk_exported_components", len([c for c in components if c.get("exported") and not c.get("permission")]))

    # Security review priorities
    priority_items: List[Dict[str, str]] = []

    for cfg in findings.get("configuration", []):
        priority_items.append({
            "category": "Configuration",
            "item": cfg["title"],
            "severity": cfg["severity"],
            "evidence": cfg["evidence"],
        })

    # Exported components without permissions
    raw_unprotected = [
        c for c in components
        if isinstance(c, dict) and is_unprotected(c)
    ]
    for comp in raw_unprotected[:4]:
        c_type = comp.get("component_type", "Component").capitalize()
        priority_items.append({
            "category": f"Exported {c_type}",
            "item": comp.get("name", "Unknown"),
            "severity": "HIGH" if c_type in ("Service", "Receiver", "Provider") else "MEDIUM",
            "evidence": f"Exported {c_type} has no declared permission constraint; callable by third-party apps.",
        })

    # Dangerous permissions
    dangerous_perms = [
        p for p in permissions
        if isinstance(p, dict) and (
            p.get("is_dangerous") or "dangerous" in str(p.get("protection_level", "")).lower()
        )
    ]
    for perm in dangerous_perms[:3]:
        priority_items.append({
            "category": "Permission",
            "item": perm.get("name", "Unknown"),
            "severity": "MEDIUM",
            "evidence": f"Declared runtime/dangerous privilege ({perm.get('protection_level', 'dangerous')}).",
        })

    # Top discovered hostnames
    top_domains = domains[:5] if isinstance(domains, list) else []

    # Sample candidate routes
    sample_endpoints = endpoints[:5] if isinstance(endpoints, list) else []

    # Formatting date
    analysis_date = created_at.replace("T", " ")[:19] if created_at else "Not Available"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HUNTX Reconnaissance Report — {_esc(app_name)}</title>
<style>
/* CSS Reset & Print-Optimized Layout */
*, *::before, *::after {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}

body {{
    background-color: #e5e5e8;
    color: #111111;
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 10px;
    line-height: 1.35;
    margin: 0;
    padding: 20px 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-start;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
}}

.report-page {{
    width: 210mm;
    min-height: 297mm;
    max-width: 210mm;
    background: #ffffff;
    margin: 0 auto;
    padding: 12mm 15mm;
    box-shadow: 0 1px 8px rgba(0, 0, 0, 0.15);
    border: 1px solid #d0d0d0;
    position: relative;
}}

/* Non-printing Control Toolbar */
.control-bar {{
    width: 210mm;
    max-width: 210mm;
    margin: 0 auto 12px auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 12px;
    background: #ffffff;
    border: 1px solid #ccc;
    font-size: 10px;
}}
.control-bar a, .control-bar button {{
    background: #111;
    color: #fff;
    border: none;
    padding: 5px 10px;
    font-size: 10px;
    font-family: inherit;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    border-radius: 2px;
    display: inline-block;
}}
.control-bar a.secondary {{
    background: #f0f0f0;
    color: #111;
    border: 1px solid #999;
    margin-left: 6px;
}}
.control-bar a:hover, .control-bar button:hover {{
    opacity: 0.85;
}}

/* Typography & Tables */
.mono {{
    font-family: 'IBM Plex Mono', 'SF Mono', Consolas, Menlo, Monaco, monospace;
    font-size: 9.5px;
}}

h1.header-title {{
    font-size: 17px;
    font-weight: 800;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: #000;
    line-height: 1.15;
}}
.header-subtitle {{
    font-size: 9.5px;
    font-weight: 600;
    color: #444;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 2px;
}}

.section {{
    margin-bottom: 11px;
}}
.section-title {{
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    border-bottom: 1.5px solid #111;
    padding-bottom: 2px;
    margin-bottom: 5px;
    display: flex;
    justify-content: space-between;
    align-items: baseline;
}}
.section-title span.sub {{
    font-size: 8.5px;
    font-weight: 400;
    color: #555;
    text-transform: none;
    letter-spacing: normal;
}}

table.grid-table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 4px;
}}
table.grid-table th, table.grid-table td {{
    border: 1px solid #222;
    padding: 3.5px 6px;
    font-size: 9.5px;
    text-align: left;
    vertical-align: middle;
}}
table.grid-table th {{
    background-color: #f0f0f0;
    color: #000;
    font-weight: 700;
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}}
table.grid-table td.col-key {{
    width: 26%;
    font-weight: 600;
    background-color: #fbfbfb;
}}
table.grid-table td.col-val {{
    width: 74%;
}}

/* Metric Cards Grid */
.metrics-grid {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 5px;
    margin-bottom: 5px;
}}
.metric-box {{
    border: 1px solid #222;
    background: #fbfbfb;
    padding: 5px 4px;
    text-align: center;
}}
.metric-val {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 15px;
    font-weight: 700;
    color: #000;
    line-height: 1.1;
}}
.metric-label {{
    font-size: 8px;
    font-weight: 600;
    color: #333;
    text-transform: uppercase;
    letter-spacing: 0.2px;
    margin-top: 2px;
}}

/* Severity Badges */
.badge {{
    display: inline-block;
    padding: 1px 4px;
    font-size: 8px;
    font-weight: 700;
    font-family: 'IBM Plex Mono', monospace;
    border: 1px solid #111;
    text-transform: uppercase;
}}
.badge-high {{
    background: #111;
    color: #fff;
}}
.badge-med {{
    background: #fff;
    color: #111;
}}
.badge-low {{
    background: #f0f0f0;
    color: #333;
}}

/* Limitations box */
.limitations-box {{
    border: 1px solid #777;
    background: #fafafa;
    padding: 5px 8px;
    font-size: 8.5px;
    color: #333;
    line-height: 1.3;
}}
.limitations-box ul {{
    margin-left: 14px;
    margin-top: 2px;
}}

/* Footer */
.report-footer {{
    border-top: 1px solid #111;
    padding-top: 4px;
    margin-top: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 8px;
    color: #444;
}}

/* Print Overrides */
@media print {{
    @page {{
        size: A4 portrait;
        margin: 10mm 12mm;
    }}
    body {{
        background: #ffffff !important;
        margin: 0 !important;
        padding: 0 !important;
        display: block !important;
    }}
    .control-bar, .no-print {{
        display: none !important;
    }}
    .report-page {{
        width: 100% !important;
        max-width: 100% !important;
        min-height: auto !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        box-shadow: none !important;
    }}
}}
</style>
</head>
<body>

<!-- Interactive Desktop Action Bar -->
<div class="control-bar no-print">
    <div>
        <strong>HUNTX Executive Assessment Summary</strong> &bull; Black &amp; White Print Ready
    </div>
    <div>
        <button onclick="window.print()">Print / Save PDF</button>
        <a href="huntx-report.html" class="secondary">Open Detailed Inventory Report</a>
        <a href="huntx-report.json" class="secondary" target="_blank">Raw JSON</a>
    </div>
</div>

<div class="report-page">

    <!-- A. Header -->
    <div class="section" style="border-bottom: 2px solid #000; padding-bottom: 8px; margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
                <div class="header-subtitle">HUNTX Android &amp; API Reconnaissance Framework</div>
                <h1 class="header-title">{_esc(app_name)}</h1>
                <div class="mono" style="font-size: 10.5px; font-weight: 600; margin-top: 2px;">
                    {_esc(package_name)} &bull; v{_esc(version_name)} (Build {_esc(vc_display)})
                </div>
            </div>
            <div style="text-align: right; font-size: 9px;">
                <div style="font-weight: 700; text-transform: uppercase;">Assessment Report</div>
                <div>Date: <span class="mono">{_esc(analysis_date)}</span></div>
                <div>Session: <span class="mono">{_esc(session_id)}</span></div>
                <div style="font-size: 8px; color: #555; text-transform: uppercase; margin-top: 1px;">Class: Internal Confidential</div>
            </div>
        </div>
    </div>

    <!-- B. Reconnaissance Summary Metrics -->
    <div class="section">
        <div class="section-title">
            Reconnaissance Summary
            <span class="sub">Total discovered attack surface elements</span>
        </div>
        <div class="metrics-grid">
            <div class="metric-box">
                <div class="metric-val">{total_endpoints}</div>
                <div class="metric-label">Route Candidates</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{total_domains}</div>
                <div class="metric-label">API Domains</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{total_components}</div>
                <div class="metric-label">Components</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{exported_comps}</div>
                <div class="metric-label">Exported Comps</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{unprotected_comps}</div>
                <div class="metric-label">Unprotected Exp.</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{total_permissions}</div>
                <div class="metric-label">Permissions</div>
            </div>
        </div>
    </div>

    <!-- C. Application Information Table -->
    <div class="section">
        <div class="section-title">
            Application Information
            <span class="sub">Static container identity &amp; platform configuration</span>
        </div>
        <table class="grid-table">
            <tbody>
                <tr>
                    <td class="col-key">Application Name</td>
                    <td class="col-val" style="font-weight: 600;">{_esc(app_name)}</td>
                    <td class="col-key" style="width: 20%;">Debuggable</td>
                    <td class="col-val mono" style="width: 30%; font-weight: 600;">{'YES (HIGH RISK)' if debuggable else 'False (Enforced)'}</td>
                </tr>
                <tr>
                    <td class="col-key">Package Name</td>
                    <td class="col-val mono">{_esc(package_name)}</td>
                    <td class="col-key">Cleartext Traffic</td>
                    <td class="col-val mono" style="font-weight: 600;">{'YES (Permitted)' if cleartext_traffic else 'False (Blocked)'}</td>
                </tr>
                <tr>
                    <td class="col-key">Version / Build</td>
                    <td class="col-val mono">v{_esc(version_name)} (Code: {_esc(vc_display)})</td>
                    <td class="col-key">Target SDK</td>
                    <td class="col-val mono">{_esc(target_sdk)} (Min SDK: {_esc(min_sdk)})</td>
                </tr>
                <tr>
                    <td class="col-key">File Size</td>
                    <td class="col-val mono">{_esc(file_size_human)}</td>
                    <td class="col-key">Analysis Timestamp</td>
                    <td class="col-val mono">{_esc(analysis_date)}</td>
                </tr>
                <tr>
                    <td class="col-key">APK SHA-256</td>
                    <td class="col-val mono" colspan="3" style="font-size: 8.5px; word-break: break-all;">{_esc(sha256_hash)}</td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- D. Security Review Priorities -->
    <div class="section">
        <div class="section-title">
            Security Review Priorities
            <span class="sub">High-value attack surface items requiring manual validation</span>
        </div>
        <table class="grid-table">
            <thead>
                <tr>
                    <th style="width: 18%;">Category</th>
                    <th style="width: 32%;">Target Item / Name</th>
                    <th style="width: 12%; text-align: center;">Priority</th>
                    <th style="width: 38%;">Observation &amp; Evidence</th>
                </tr>
            </thead>
            <tbody>
                {"".join(f'''
                <tr>
                    <td style="font-weight: 600;">{_esc(p["category"])}</td>
                    <td class="mono" style="word-break: break-all;">{_esc(p["item"])}</td>
                    <td style="text-align: center;"><span class="badge badge-{p['severity'].lower()[:4]}">{_esc(p["severity"])}</span></td>
                    <td style="font-size: 8.5px;">{_esc(p["evidence"])}</td>
                </tr>''' for p in priority_items) if priority_items else '''
                <tr>
                    <td colspan="4" style="text-align: center; color: #555; padding: 6px;">
                        No immediate high-risk exposures identified in static reconnaissance.
                    </td>
                </tr>'''}
            </tbody>
        </table>
    </div>

    <!-- E. API & Network Reconnaissance Footprint -->
    <div class="section">
        <div class="section-title">
            API &amp; Network Reconnaissance Footprint
            <span class="sub">Candidate endpoints, hostnames &amp; client network stack</span>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
            <div>
                <table class="grid-table">
                    <thead>
                        <tr>
                            <th>Discovered API Hostnames</th>
                            <th style="width: 30%; text-align: right;">Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f'''
                        <tr>
                            <td class="mono" style="word-break: break-all;">{_esc(d.get("domain") if isinstance(d, dict) else d)}</td>
                            <td class="mono" style="text-align: right; font-size: 8px;">{_esc(_schemes(d, endpoints))}</td>
                        </tr>''' for d in top_domains) if top_domains else '''
                        <tr><td colspan="2" style="color: #666; font-size: 8.5px;">No external domains discovered in inspection.</td></tr>'''}
                    </tbody>
                </table>
            </div>
            <div>
                <table class="grid-table">
                    <thead>
                        <tr>
                            <th style="width: 25%;">Method</th>
                            <th>Sample Route Candidates</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f'''
                        <tr>
                            <td class="mono" style="font-weight: 700;">{_esc((ep.get("method") or "UNKNOWN").upper())}</td>
                            <td class="mono" style="word-break: break-all; font-size: 8.5px;">{_esc((ep.get("domain") or "") + (ep.get("path") or ep.get("url") or "N/A"))}</td>
                        </tr>''' for ep in sample_endpoints) if sample_endpoints else '''
                        <tr><td colspan="2" style="color: #666; font-size: 8.5px;">No candidate HTTP routes mapped.</td></tr>'''}
                    </tbody>
                </table>
            </div>
        </div>
        <div style="margin-top: 3px; font-size: 8.5px; color: #333;">
            <strong>Detected Client Networking Technologies:</strong>
            <span class="mono" style="margin-left: 4px;">{', '.join(_esc(lib) for lib in net_libs)}</span>
            <span style="color: #666; margin-left: 8px;">(Static Bytecode Pattern Matching)</span>
        </div>
    </div>

    <!-- F. Methodology & Limitations -->
    <div class="section" style="margin-bottom: 6px;">
        <div class="section-title">
            Methodology &amp; Assessment Scope Limitations
        </div>
        <div class="limitations-box">
            <div>This document reflects automated static reconnaissance performed by HUNTX. Key parameters include:</div>
            <ul>
                {"".join(f'<li>{_esc(lim)}</li>' for lim in limitations) if limitations else '''
                <li>Scope covers static Android manifest parsing, decompiled bytecode inspection, and imported network captures.</li>
                <li>Live active probing or intrusive network validation was not performed.</li>
                '''}
                <li>Native shared libraries (.so) and runtime reflection were inspected statically without execution hooks.</li>
            </ul>
        </div>
    </div>

    <!-- G. Footer -->
    <div class="report-footer">
        <div>HUNTX v{HUNTX_VERSION} &bull; Automated Reconnaissance Engine</div>
        <div class="mono">CONFIDENTIAL &bull; AUTHORIZED ASSESSMENT ONLY</div>
        <div class="mono">ID: {_esc(session_id)}</div>
    </div>

</div>

</body>
</html>
"""

    dest_path = output_path
    if dest_path is None and session and hasattr(session, "run_path") and session.run_path:
        dest_path = session.run_path / "reports" / "huntx-summary.html"

    if dest_path is not None:
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("Saved one-page summary report to %s", dest_path)
        except Exception as e:
            logger.error("Failed writing summary report to %s: %s", dest_path, e)

    return dest_path if dest_path else Path("huntx-summary.html")
