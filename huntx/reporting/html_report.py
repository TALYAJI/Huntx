"""HUNTX Operational Security Report Generator.

Generates an authoritative, single-file, offline-first technical HTML inventory report
modeled after professional penetration testing and security assessment platforms.
Matches the clean, high-contrast, black-and-white / grayscale A4 engineering theme.
Zero external CDNs or remote dependencies.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from huntx.core.config import HUNTX_VERSION
from huntx.core.logger import get_logger
from huntx.reporting.json_report import JSONReportGenerator

logger = get_logger("huntx.reporting.html_report")


def _badge(text: str, bg_color: str = "#ffffff", text_color: str = "#111111", border_color: str = "#222222") -> str:
    """Render a crisp, monochrome technical badge."""
    return (
        f'<span style="display:inline-flex;align-items:center;padding:1px 5px;border-radius:2px;'
        f'font-size:9.5px;font-weight:700;font-family:\'IBM Plex Mono\',monospace;'
        f'background:{bg_color};color:{text_color};border:1px solid {border_color};margin:1px 2px;letter-spacing:0.2px;">'
        f'{html.escape(str(text))}</span>'
    )


def _method_badge(method: str) -> str:
    """Render a high-contrast HTTP method badge."""
    m = (method or "UNKNOWN").upper()
    configs = {
        "GET": ("#ffffff", "#111111", "#222222"),
        "POST": ("#111111", "#ffffff", "#111111"),
        "PUT": ("#f0f0f0", "#111111", "#222222"),
        "DELETE": ("#222222", "#ffffff", "#000000"),
        "PATCH": ("#ffffff", "#111111", "#444444"),
    }
    bg, fg, border = configs.get(m, ("#ffffff", "#333333", "#888888"))
    return _badge(m, bg, fg, border)


def generate_html_report(
    session: Any = None,
    report_data: Optional[Dict[str, Any]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    """Generate a self-contained interactive technical HTML report."""
    logger.info("Generating professional cybersecurity HTML report")

    if report_data is None:
        generator = JSONReportGenerator(session=session)
        report_data = generator.generate()

    target = report_data.get("target", {})
    target_name = target.get("name", "Unknown Target")
    session_id = target.get("session_id", "N/A")
    generated_at = report_data.get("generated_at", datetime.now(timezone.utc).isoformat())

    apk_meta = report_data.get("apk_metadata", {})
    app_name = apk_meta.get("application_name") or target_name
    package_name = apk_meta.get("package_name") or "Not Available"
    version_name = apk_meta.get("version_name") or "Not Available"
    version_code = apk_meta.get("version_code", "N/A")
    min_sdk = apk_meta.get("min_sdk", "N/A")
    target_sdk = apk_meta.get("target_sdk", "N/A")
    size_human = apk_meta.get("size_human", "N/A")
    sha256_val = apk_meta.get("sha256") or apk_meta.get("hashes", {}).get("sha256") or "N/A"

    summary = report_data.get("summary", {})
    findings = report_data.get("findings", {})

    domains = findings.get("domains", [])
    endpoints = findings.get("endpoints", [])
    components = findings.get("components", [])
    permissions = findings.get("permissions", [])
    limitations = report_data.get("extraction_limitations", [])
    mapping = findings.get("android_api_mapping", [])
    security_audit = findings.get("security_audit", {}) or {}
    sa_fp = security_audit.get("fingerprint", {}) or {}
    sa_frameworks = sa_fp.get("frameworks", [])
    sa_defenses = sa_fp.get("defenses", [])
    sa_webview = sa_fp.get("webview_signals", [])
    sa_secrets = security_audit.get("secrets", [])
    sa_cloud = security_audit.get("cloud_assets", [])
    sa_jwts = security_audit.get("decoded_jwts", [])
    sa_pocs = security_audit.get("adb_pocs", [])
    sa_total = len(sa_secrets) + len(sa_cloud) + len(sa_pocs) + len(sa_webview)

    config_rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(c.get(k, '')))}</td>" for k in ("severity", "title", "evidence", "verify")) + "</tr>"
        for c in findings.get("configuration", [])
    ) or '<tr><td colspan="4">No configuration findings.</td></tr>'

    total_endpoints = summary.get("total_endpoints", len(endpoints))
    total_domains = summary.get("total_domains", len(domains))
    exported_comps = summary.get("exported_components", len([c for c in components if c.get("exported")]))
    unprotected_comps = summary.get("high_risk_exported_components", len([c for c in components if c.get("exported") and not c.get("permission")]))
    dangerous_perms = summary.get("dangerous_permissions", len([p for p in permissions if p.get("is_dangerous")]))
    total_perms = summary.get("total_permissions", len(permissions))

    # HTTP method distribution
    method_counts: Dict[str, int] = {}
    for ep in endpoints:
        m = (ep.get("method") or "UNKNOWN").upper()
        method_counts[m] = method_counts.get(m, 0) + 1

    max_m_count = max(method_counts.values()) if method_counts else 1
    method_bars_svg = []
    x_offset = 16
    for m, cnt in sorted(method_counts.items(), key=lambda x: -x[1]):
        bar_h = max(8, int((cnt / max_m_count) * 75))
        y_pos = 90 - bar_h
        method_bars_svg.append(f"""
            <rect x="{x_offset}" y="{y_pos}" width="42" height="{bar_h}" rx="1" fill="#222222"/>
            <text x="{x_offset + 21}" y="{y_pos - 4}" font-size="10" fill="#000000" font-weight="700" text-anchor="middle" font-family="'IBM Plex Mono', monospace">{cnt}</text>
            <text x="{x_offset + 21}" y="106" font-size="9.5" fill="#333333" font-weight="600" text-anchor="middle" font-family="'IBM Plex Mono', monospace">{html.escape(m)}</text>
        """)
        x_offset += 54

    svg_chart = f"""
    <svg width="{max(260, x_offset + 16)}" height="120" style="background:#fafafa; border:1px solid #222222; border-radius:0px; display:block;">
        {''.join(method_bars_svg)}
    </svg>
    """ if method_bars_svg else '<div style="color:#666666; font-size:11px; padding:20px; text-align:center;">No HTTP methods extracted to chart.</div>'

    json_embedded = json.dumps(report_data).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HUNTX Technical Reconnaissance Inventory — {html.escape(app_name)}</title>
<style>
/* CSS Reset & Professional High-Contrast Theme */
*, *::before, *::after {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}

body {{
    background-color: #e5e5e8;
    color: #111111;
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 11px;
    line-height: 1.4;
    margin: 0;
    padding: 20px 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-start;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
}}

.control-bar {{
    width: 95%;
    max-width: 1400px;
    margin: 0 auto 12px auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 14px;
    background: #ffffff;
    border: 1px solid #c8c8c8;
    font-size: 10.5px;
}}
.control-bar a, .control-bar button {{
    background: #111111;
    color: #ffffff;
    border: 1px solid #111111;
    padding: 5px 11px;
    font-size: 10px;
    font-family: inherit;
    font-weight: 700;
    cursor: pointer;
    text-decoration: none;
    border-radius: 2px;
    display: inline-block;
}}
.control-bar a.secondary {{
    background: #f0f0f0;
    color: #111111;
    border: 1px solid #888888;
    margin-left: 6px;
}}
.control-bar a:hover, .control-bar button:hover {{
    opacity: 0.85;
}}

.container {{
    width: 95%;
    max-width: 1400px;
    margin: 0 auto;
    background: #ffffff;
    padding: 20px 24px;
    box-shadow: 0 1px 8px rgba(0, 0, 0, 0.15);
    border: 1px solid #d0d0d0;
}}

header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid #000000;
    padding-bottom: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 12px;
}}

.brand {{ display: flex; align-items: flex-start; gap: 12px; }}
.brand-badge {{
    background: #111111;
    color: #ffffff;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 800;
    font-size: 13px;
    padding: 4px 8px;
    border: 1px solid #000000;
    border-radius: 2px;
    letter-spacing: 0.05em;
}}

.brand h1 {{
    font-size: 18px;
    font-weight: 800;
    color: #000000;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    line-height: 1.15;
}}
.header-subtitle {{
    font-size: 9.5px;
    color: #444444;
    text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600;
    letter-spacing: 0.6px;
}}

.meta-group {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
.meta-pill {{
    background: #fbfbfb;
    border: 1px solid #222222;
    padding: 4px 9px;
    border-radius: 2px;
    font-size: 10px;
    color: #222222;
    font-family: 'IBM Plex Mono', monospace;
}}
.meta-pill strong {{ color: #000000; }}

/* Metrics Bar */
.metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
    margin-bottom: 16px;
}}

.metric-box {{
    background: #fbfbfb;
    border: 1px solid #222222;
    padding: 10px 14px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    cursor: pointer;
    transition: background 0.15s ease, border-color 0.15s ease;
}}
.metric-box:hover {{
    background: #f2f2f2;
    border-color: #000000;
}}

.metric-label {{
    font-size: 9px;
    text-transform: uppercase;
    font-weight: 700;
    color: #333333;
    letter-spacing: 0.04em;
}}

.metric-num {{
    font-size: 22px;
    font-weight: 800;
    font-family: 'IBM Plex Mono', monospace;
    color: #000000;
    line-height: 1.1;
}}

.metric-context {{
    font-size: 10px;
    color: #555555;
}}

/* Navigation Tabs */
.tabs-nav {{
    display: flex;
    gap: 4px;
    border-bottom: 2px solid #222222;
    margin-bottom: 16px;
    overflow-x: auto;
}}

.tab-btn {{
    background: #f4f4f4;
    border: 1px solid #222222;
    border-bottom: none;
    color: #222222;
    padding: 7px 14px;
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    cursor: pointer;
    transition: all 0.12s ease;
}}
.tab-btn:hover {{
    background: #e6e6e6;
    color: #000000;
}}
.tab-btn.active {{
    background: #111111;
    color: #ffffff;
    border-color: #111111;
}}

.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

/* Technical Cards & Tables */
.card {{
    background: #ffffff;
    border: 1px solid #222222;
    margin-bottom: 16px;
}}

.card-header {{
    padding: 8px 12px;
    background: #f0f0f0;
    border-bottom: 1px solid #222222;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.card-title {{
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #000000;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 10.5px;
    text-align: left;
}}
th {{
    background: #f0f0f0;
    color: #000000;
    font-weight: 700;
    font-size: 9.5px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    padding: 6px 10px;
    border-bottom: 1px solid #222222;
    border-right: 1px solid #e0e0e0;
    white-space: nowrap;
}}
td {{
    padding: 6px 10px;
    border-bottom: 1px solid #e5e5e5;
    border-right: 1px solid #f2f2f2;
    color: #111111;
    vertical-align: top;
}}
tr:hover td {{ background: #f8f8fa; }}

code, .code-font, .mono {{
    font-family: 'IBM Plex Mono', 'SF Mono', Consolas, Menlo, Monaco, monospace;
    font-size: 10px;
    color: #111111;
}}

/* Filter Bar */
.filter-bar {{
    padding: 8px 12px;
    background: #fbfbfb;
    border-bottom: 1px solid #222222;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}}

.input-search, .select-filter {{
    background: #ffffff;
    border: 1px solid #222222;
    padding: 5px 8px;
    color: #111111;
    font-size: 11px;
    font-family: inherit;
    outline: none;
}}
.input-search {{ flex: 1; min-width: 240px; }}
.input-search:focus, .select-filter:focus {{
    outline: 1px solid #000000;
}}

/* Copy button */
.copy-btn {{
    background: #f0f0f0;
    border: 1px solid #888888;
    color: #111111;
    border-radius: 2px;
    padding: 1px 5px;
    font-size: 8.5px;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 700;
    cursor: pointer;
    margin-left: 6px;
}}
.copy-btn:hover {{
    color: #ffffff;
    border-color: #111111;
    background: #111111;
}}

/* Empty States */
.empty-box {{
    padding: 24px 16px;
    text-align: center;
    color: #666666;
    font-size: 11px;
}}

/* Print Styles */
@media print {{
    body {{
        background: #ffffff !important;
        padding: 0 !important;
        margin: 0 !important;
    }}
    .control-bar, .no-print {{
        display: none !important;
    }}
    .container {{
        width: 100% !important;
        max-width: 100% !important;
        box-shadow: none !important;
        border: none !important;
        padding: 0 !important;
    }}
    .tab-content {{
        display: block !important;
        margin-bottom: 24px !important;
    }}
}}
</style>
</head>
<body>

<!-- Interactive Desktop Action Bar -->
<div class="control-bar no-print">
    <div>
        <strong>HUNTX Technical Reconnaissance Inventory</strong> &bull; Black &amp; White Theme
    </div>
    <div>
        <a href="huntx-summary.html">&larr; Back to Executive Summary (A4)</a>
        <button onclick="window.print()" class="secondary">Print / Save PDF</button>
        <a href="huntx-report.json" class="secondary" target="_blank">Raw JSON</a>
    </div>
</div>

<div class="container">
    <header>
        <div class="brand">
            <span class="brand-badge">HUNTX</span>
            <div>
                <div class="header-subtitle">Android &amp; API Reconnaissance Specification</div>
                <h1 class="header-title">{html.escape(app_name)}</h1>
                <div class="mono" style="font-size: 11px; font-weight: 600; margin-top: 2px;">
                    {html.escape(package_name)} &bull; v{html.escape(str(version_name))} (Build {html.escape(str(version_code))})
                </div>
            </div>
        </div>
        <div class="meta-group">
            <div class="meta-pill">Session: <strong>{html.escape(session_id)}</strong></div>
            <div class="meta-pill">Generated: <strong>{html.escape(generated_at[:19].replace("T", " "))} UTC</strong></div>
            <div class="meta-pill" style="font-size: 9px; text-transform: uppercase;">Class: <strong>Internal Confidential</strong></div>
        </div>
    </header>

    <!-- Operational Metrics -->
    <div class="metrics-grid">
        <div class="metric-box" onclick="showTab('endpoints')">
            <div class="metric-label">API Endpoints</div>
            <div class="metric-num">{total_endpoints}</div>
            <div class="metric-context">{len(method_counts)} distinct HTTP methods</div>
        </div>
        <div class="metric-box" onclick="showTab('domains')">
            <div class="metric-label">External Hosts</div>
            <div class="metric-num">{total_domains}</div>
            <div class="metric-context">Identified network domains</div>
        </div>
        <div class="metric-box" onclick="showTab('components')">
            <div class="metric-label">Exported Components</div>
            <div class="metric-num">{exported_comps}</div>
            <div class="metric-context">{unprotected_comps} exported without permissions</div>
        </div>
        <div class="metric-box" onclick="showTab('permissions')">
            <div class="metric-label">Privileged Permissions</div>
            <div class="metric-num">{dangerous_perms}</div>
            <div class="metric-context">Out of {total_perms} declared permissions</div>
        </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-nav no-print">
        <button class="tab-btn active" onclick="showTab('overview')">Overview</button>
        <button class="tab-btn" onclick="showTab('endpoints')">API Endpoints ({len(endpoints)})</button>
        <button class="tab-btn" onclick="showTab('domains')">Domains ({len(domains)})</button>
        <button class="tab-btn" onclick="showTab('components')">Components ({len(components)})</button>
        <button class="tab-btn" onclick="showTab('permissions')">Permissions ({len(permissions)})</button>
        <button class="tab-btn" onclick="showTab('mapping')">Component Mapping ({len(mapping)})</button>
        <button class="tab-btn" onclick="showTab('audit')">Security Audit &amp; PoCs ({sa_total})</button>
        <button class="tab-btn" onclick="showTab('limitations')">Limitations &amp; Evidence</button>
    </div>

    <!-- 1. OVERVIEW TAB -->
    <div id="tab-overview" class="tab-content active">
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 14px;">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Binary &amp; Package Specification</div>
                </div>
                <table>
                    <tbody>
                        <tr><td style="width:180px; font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Application Label</td><td style="font-weight:700;">{html.escape(app_name)}</td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Package Identifier</td><td><span class="code-font">{html.escape(package_name)}</span></td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Version Metadata</td><td>v{html.escape(str(version_name))} (Code: {html.escape(str(version_code))})</td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Platform SDKs</td><td>Min SDK: {html.escape(str(min_sdk))} &bull; Target SDK: {html.escape(str(target_sdk))}</td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Binary Size</td><td><span class="code-font">{html.escape(size_human)}</span></td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Debuggable Flag</td><td>{_badge("DEBUG ENABLED", "#111111", "#ffffff", "#111111") if apk_meta.get("debuggable") else _badge("RESTRICTED", "#f0f0f0", "#333333", "#aaaaaa")}</td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">Cleartext Traffic</td><td>{_badge("CLEARTEXT PERMITTED", "#111111", "#ffffff", "#111111") if apk_meta.get("cleartext_traffic") or apk_meta.get("uses_cleartext_traffic") else _badge("RESTRICTED", "#f0f0f0", "#333333", "#aaaaaa")}</td></tr>
                        <tr><td style="font-weight:700; background:#fbfbfb; text-transform:uppercase; font-size:10px;">SHA-256 Hash</td><td><span class="code-font" style="font-size:9px; word-break:break-all;">{html.escape(sha256_val)}</span> <button class="copy-btn" data-copy="{html.escape(sha256_val)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td></tr>
                    </tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">HTTP Method Distribution</div>
                </div>
                <div style="padding:16px; display:flex; justify-content:center;">
                    {svg_chart}
                </div>
            </div>
        </div>
    </div>

    <!-- 2. ENDPOINTS TAB -->
    <div id="tab-endpoints" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">API Endpoint Inventory</div>
            </div>
            <div class="filter-bar">
                <input type="text" id="endpointSearch" class="input-search" placeholder="Filter route, host, or parameters..." onkeyup="filterEndpoints()">
                <select id="methodFilter" class="select-filter" onchange="filterEndpoints()">
                    <option value="">All HTTP Methods</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                </select>
            </div>
            <div style="overflow-x:auto;">
                <table id="endpointsTable">
                    <thead>
                        <tr>
                            <th style="width:10%;">ID</th>
                            <th style="width:8%;">Method</th>
                            <th style="width:36%;">Endpoint Route</th>
                            <th style="width:24%;">Normalized Route</th>
                            <th style="width:14%;">Target Host</th>
                            <th style="width:8%;">Conf</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    for idx, ep in enumerate(endpoints):
        ep_id = ep.get("endpoint_id") or f"EP-{idx+1:05d}"
        method = ep.get("method", "GET")
        path = ep.get("path", "/")
        norm_path = ep.get("normalized_path", path)
        domain = ep.get("domain", "* (Relative Route)")
        conf = ep.get("confidence", 0.70)
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)

        html_content += f"""
                        <tr class="ep-row" data-method="{html.escape(str(method).upper())}" data-search="{html.escape((path + ' ' + norm_path + ' ' + domain).lower())}">
                            <td><span class="code-font" style="color:#666666;">{html.escape(ep_id)}</span></td>
                            <td>{_method_badge(method)}</td>
                            <td><span class="code-font" style="font-weight:700;">{html.escape(path)}</span> <button class="copy-btn" data-copy="{html.escape(path)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                            <td><span class="code-font" style="color:#444444;">{html.escape(norm_path)}</span></td>
                            <td style="color:#333333;">{html.escape(domain)}</td>
                            <td><span class="code-font" style="font-weight:700;">{conf_str}</span></td>
                        </tr>
        """

    if not endpoints:
        html_content += """
                        <tr><td colspan="6"><div class="empty-box">No API endpoints extracted from APK bytecode or dynamic captures.</div></td></tr>
        """

    html_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 3. DOMAINS TAB -->
    <div id="tab-domains" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Network Hosts &amp; Domains</div>
            </div>
            <table>
                <thead>
                    <tr><th>Domain Name</th><th>Classification</th><th>Discovery Provenance</th><th>First Observed</th></tr>
                </thead>
                <tbody>
    """

    for d in domains:
        if isinstance(d, dict):
            dom_name = d.get("domain", "")
            cat = d.get("category", "General Host")
            srcs = ", ".join(d.get("sources", [])) if d.get("sources") else d.get("source", "dex_strings")
            first_seen = d.get("first_seen", "Static Binary")
        else:
            dom_name = str(d)
            cat = "General Host"
            srcs = "dex_strings"
            first_seen = "Static Binary"

        html_content += f"""
                    <tr>
                        <td><span class="code-font" style="font-weight:700;">{html.escape(dom_name)}</span> <button class="copy-btn" data-copy="{html.escape(dom_name)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                        <td>{_badge(cat, "#f5f5f5", "#333333", "#cccccc")}</td>
                        <td style="color:#444444; font-size:10.5px;">{html.escape(str(srcs))}</td>
                        <td style="color:#666666; font-size:10.5px;">{html.escape(str(first_seen))}</td>
                    </tr>
        """

    if not domains:
        html_content += """
                    <tr><td colspan="4"><div class="empty-box">No external hostnames discovered in application binary.</div></td></tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- 4. COMPONENTS TAB -->
    <div id="tab-components" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Component Attack Surface</div>
            </div>
            <table>
                <thead>
                    <tr><th style="width:12%;">Type</th><th style="width:48%;">Class Name</th><th style="width:20%;">Exposure Status</th><th style="width:20%;">Required Permission</th></tr>
                </thead>
                <tbody>
    """

    for c in components:
        ctype = (c.get("component_type") or "Component").upper()
        cname = c.get("class_name", "N/A")
        exported = bool(c.get("exported", False))
        perm = c.get("permission", "")

        if exported and not perm:
            status_badge = _badge("EXPORTED (UNPROTECTED)", "#111111", "#ffffff", "#111111")
        elif exported and perm:
            status_badge = _badge("EXPORTED (PROTECTED)", "#ffffff", "#111111", "#222222")
        else:
            status_badge = _badge("INTERNAL ONLY", "#f0f0f0", "#444444", "#cccccc")

        perm_disp = f'<span class="code-font" style="font-weight:600;">{html.escape(perm)}</span>' if perm else '<span style="color:#666666;">None required</span>'

        html_content += f"""
                    <tr>
                        <td>{_badge(ctype, "#f0f0f0", "#222222", "#bbbbbb")}</td>
                        <td><span class="code-font">{html.escape(cname)}</span> <button class="copy-btn" data-copy="{html.escape(cname)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                        <td>{status_badge}</td>
                        <td>{perm_disp}</td>
                    </tr>
        """

    if not components:
        html_content += """
                    <tr><td colspan="4"><div class="empty-box">No components enumerated from binary manifest.</div></td></tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- 5. PERMISSIONS TAB -->
    <div id="tab-permissions" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Permission Taxonomy &amp; Classification</div>
            </div>
            <table>
                <thead>
                    <tr><th style="width:45%;">Permission Identifier</th><th style="width:15%;">Protection Level</th><th style="width:15%;">Category</th><th style="width:25%;">Security Assessment</th></tr>
                </thead>
                <tbody>
    """

    for p in permissions:
        pname = p.get("name") or p.get("permission") or (str(p) if not isinstance(p, dict) else "N/A")
        plevel = p.get("protection_level", "normal") if isinstance(p, dict) else "normal"
        cat = p.get("category", "General") if isinstance(p, dict) else "General"
        is_dang = (p.get("is_dangerous", False) or "dangerous" in plevel.lower()) if isinstance(p, dict) else False

        risk_badge = _badge("PRIVILEGED / DANGEROUS", "#111111", "#ffffff", "#111111") if is_dang else _badge("STANDARD", "#f0f0f0", "#444444", "#cccccc")

        html_content += f"""
                    <tr>
                        <td><span class="code-font">{html.escape(pname)}</span> <button class="copy-btn" data-copy="{html.escape(pname)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                        <td>{_badge(plevel, "#f5f5f5", "#333333", "#cccccc")}</td>
                        <td style="color:#333333;">{html.escape(cat)}</td>
                        <td>{risk_badge}</td>
                    </tr>
        """

    if not permissions:
        html_content += """
                    <tr><td colspan="4"><div class="empty-box">No declared permissions found in AndroidManifest.xml.</div></td></tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- 6. MAPPING TAB -->
    <div id="tab-mapping" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Android Code to API Mapping</div>
            </div>
            <table>
                <thead>
                    <tr><th style="width:30%;">Component Class</th><th style="width:12%;">Type</th><th style="width:10%;">Confidence</th><th style="width:48%;">Associated Endpoints</th></tr>
                </thead>
                <tbody>
    """

    for m in mapping:
        cname = m.get("class_name", "N/A")
        ctype = (m.get("component_type") or "Component").upper()
        conf = m.get("confidence", 0.85)
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)
        eps = m.get("endpoints", [])
        ep_links = "<br>".join([f"<code class='mono'>{html.escape(e.get('method', 'GET'))} {html.escape(e.get('path', e.get('normalized_path', '/')))}</code>" for e in eps]) if eps else '<span style="color:#666666;">None associated</span>'

        html_content += f"""
                    <tr>
                        <td><span class="code-font" style="font-weight:700;">{html.escape(cname)}</span> <button class="copy-btn" data-copy="{html.escape(cname)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                        <td>{_badge(ctype, "#f0f0f0", "#222222", "#bbbbbb")}</td>
                        <td><span class="code-font" style="font-weight:700;">{conf_str}</span></td>
                        <td>{ep_links}</td>
                    </tr>
        """

    if not mapping:
        html_content += """
                    <tr><td colspan="4"><div class="empty-box">No component-to-endpoint mappings established. Run Operation 14 to resolve relationships.</div></td></tr>
        """

    html_content += f"""
                </tbody>
            </table>
        </div>
    </div>

    <!-- 6b. SECURITY AUDIT & POCS TAB -->
    <div id="tab-audit" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Framework, SSL Pinning &amp; WebView Signals</div>
            </div>
            <div style="padding:16px; display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px;">
                <div style="border:1px solid #cccccc; padding:10px; background:#fafafa;">
                    <div style="font-size:10px; font-weight:700; text-transform:uppercase; margin-bottom:6px;">Detected Frameworks</div>
                    <div class="mono" style="font-size:11px;">{html.escape(', '.join(sa_frameworks) if sa_frameworks else 'Not Available')}</div>
                </div>
                <div style="border:1px solid #cccccc; padding:10px; background:#fafafa;">
                    <div style="font-size:10px; font-weight:700; text-transform:uppercase; margin-bottom:6px;">Defenses &amp; SSL Pinning</div>
                    <div class="mono" style="font-size:11px;">{'<br>'.join(html.escape(d) for d in sa_defenses) if sa_defenses else 'None detected passively'}</div>
                </div>
                <div style="border:1px solid #cccccc; padding:10px; background:#fafafa;">
                    <div style="font-size:10px; font-weight:700; text-transform:uppercase; margin-bottom:6px;">WebView Risk Signals</div>
                    <div class="mono" style="font-size:11px;">{'<br>'.join(html.escape(w) for w in sa_webview) if sa_webview else 'None detected'}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="card-title">Configuration Findings</div>
            </div>
            <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Verify</th></tr></thead>
                <tbody>{config_rows}</tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="card-title">ADB Verification Commands (Exported Components &amp; Deep Links)</div>
            </div>
            <table>
                <thead>
                    <tr><th style="width:24%;">Exposure Type</th><th style="width:28%;">Component</th><th style="width:48%;">ADB Verification Command</th></tr>
                </thead>
                <tbody>
    """
    for poc in sa_pocs:
        p_type = poc.get("type", "Exported")
        p_comp = poc.get("component", "")
        p_cmd = poc.get("command", "")
        html_content += f"""
                    <tr>
                        <td>{_badge(p_type, "#f0f0f0", "#111111", "#888888")}</td>
                        <td class="code-font">{html.escape(p_comp)}</td>
                        <td><code class="mono" style="font-size:10.5px;">{html.escape(p_cmd)}</code> <button class="copy-btn" data-copy="{html.escape(p_cmd)}" onclick="copyToClipboard(this.dataset.copy)">COPY</button></td>
                    </tr>
        """
    if not sa_pocs:
        html_content += '<tr><td colspan="3"><div class="empty-box">No unprotected exported components or deep-link PoCs generated.</div></td></tr>'

    html_content += """
                </tbody>
            </table>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="card-title">Candidate Secrets, Cloud Assets &amp; Decoded JWTs</div>
            </div>
            <table>
                <thead>
                    <tr><th style="width:20%;">Category / Type</th><th style="width:22%;">Source</th><th style="width:58%;">Value / Decoded Payload</th></tr>
                </thead>
                <tbody>
    """
    for ca in sa_cloud:
        html_content += f"""
                    <tr>
                        <td>{_badge(ca.get('type', 'cloud'), "#e8e8e8", "#111111", "#666666")}</td>
                        <td class="code-font">{html.escape(ca.get('source', ''))}</td>
                        <td class="code-font">{html.escape(ca.get('value', ''))}</td>
                    </tr>
        """
    for sec in sa_secrets:
        html_content += f"""
                    <tr>
                        <td>{_badge(sec.get('type', 'secret'), "#f5f5f5", "#111111", "#999999")}</td>
                        <td class="code-font">{html.escape(sec.get('source', ''))}</td>
                        <td class="code-font">{html.escape(sec.get('value', '')[:140])}</td>
                    </tr>
        """
    for jw in sa_jwts:
        dec_str = json.dumps(jw.get("decoded", {}))[:240]
        html_content += f"""
                    <tr>
                        <td>{_badge("JWT_DECODED", "#111111", "#ffffff", "#111111")}</td>
                        <td class="code-font">{html.escape(jw.get('source', ''))}</td>
                        <td class="code-font">{html.escape(dec_str)}</td>
                    </tr>
        """
    if not sa_cloud and not sa_secrets and not sa_jwts:
        html_content += '<tr><td colspan="3"><div class="empty-box">No hardcoded secrets, cloud buckets, or JWTs discovered.</div></td></tr>'

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- 7. LIMITATIONS TAB -->
    <div id="tab-limitations" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">Operational Limitations &amp; Evidence Provenance</div>
            </div>
            <div style="padding:16px;">
                <div style="font-size:10.5px; font-weight:700; text-transform:uppercase; color:#333333; margin-bottom:8px;">
                    Static Analysis Boundaries &amp; Assessment Scope
                </div>
                <ul style="padding-left:18px; line-height:1.8; color:#333333; font-size:11px;">
    """
    for lim in limitations:
        html_content += f"<li>{html.escape(lim)}</li>"

    if not limitations:
        html_content += "<li>No specific analysis limitations recorded during this run.</li>"

    html_content += f"""
                </ul>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div style="border-top:1px solid #111111; padding-top:8px; margin-top:20px; display:flex; justify-content:space-between; align-items:center; font-size:9.5px; color:#444444;">
        <div>HUNTX v{HUNTX_VERSION} &bull; Automated Reconnaissance Engine</div>
        <div class="mono">CONFIDENTIAL &bull; AUTHORIZED SECURITY ASSESSMENT ONLY</div>
        <div class="mono">ID: {html.escape(session_id)}</div>
    </div>

</div>

<script>
function showTab(tabId) {{
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    const btns = Array.from(document.querySelectorAll('.tab-btn'));
    const targetBtn = btns.find(b => b.getAttribute('onclick')?.includes(tabId));
    if (targetBtn) targetBtn.classList.add('active');

    const targetEl = document.getElementById('tab-' + tabId);
    if (targetEl) targetEl.classList.add('active');
}}

function copyToClipboard(val) {{
    if (!navigator.clipboard) {{
        const ta = document.createElement("textarea");
        ta.value = val;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
    }} else {{
        navigator.clipboard.writeText(val);
    }}
}}

function filterEndpoints() {{
    const searchVal = (document.getElementById('endpointSearch')?.value || '').toLowerCase();
    const methodVal = (document.getElementById('methodFilter')?.value || '').toUpperCase();
    const rows = document.querySelectorAll('.ep-row');
    rows.forEach(r => {{
        const rMethod = r.getAttribute('data-method');
        const rSearch = r.getAttribute('data-search');
        const matchesMethod = !methodVal || rMethod === methodVal;
        const matchesSearch = !searchVal || rSearch.includes(searchVal);
        r.style.display = (matchesMethod && matchesSearch) ? '' : 'none';
    }});
}}

window.__HUNTX_DATA__ = {json_embedded};
</script>
</body>
</html>
"""

    target_file = output_path
    if target_file is None and session is not None:
        run_path = getattr(session, "run_path", None)
        if run_path and isinstance(run_path, Path):
            target_file = run_path / "reports" / "huntx-report.html"

    if target_file is None:
        target_file = Path("huntx-report.html")

    target_file.parent.mkdir(parents=True, exist_ok=True)
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info("HTML report generated at %s", target_file)
    return target_file
