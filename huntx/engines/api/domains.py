"""HUNTX API Engine — Domain Discovery and Extraction.

Extracts, filters, and categorizes domain names from strings, resources,
configurations, and traffic logs.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known System and Standard Namespaces
# ---------------------------------------------------------------------------

SYSTEM_NAMESPACES: Set[str] = {
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "schemas.xmlsoap.org",
    "xmlsoap.org",
    "xmlpull.org",
    "apache.org",
    "www.apache.org",
    "xmlns.com",
    "java.sun.com",
    "sun.com",
    "oracle.com",
    "xml.org",
    "json.org",
    "openmobilealliance.org",
    "google.com/schemas",
}

# Domains considered Android/Google core platform services
GOOGLE_PLATFORM_DOMAINS: Set[str] = {
    "android.com",
    "developer.android.com",
    "source.android.com",
    "play.google.com",
    "market.android.com",
    "google.com",
    "www.google.com",
    "gstatic.com",
    "www.gstatic.com",
    "googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "connectivitycheck.gstatic.com",
}

# Third-party analytics and tracking domains
ANALYTICS_DOMAINS: Set[str] = {
    "crashlytics.com",
    "app-measurement.com",
    "firebaseinstallations.googleapis.com",
    "firebaseremoteconfig.googleapis.com",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "appsflyer.com",
    "branch.io",
    "adjust.com",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "sentry.io",
    "bugsnag.com",
    "onesignal.com",
    "braze.com",
    "appboy.com",
    "flurry.com",
    "facebook.com",
    "graph.facebook.com",
}

# Cloud infrastructure / CDN providers
CLOUD_CDN_DOMAINS: Set[str] = {
    "amazonaws.com",
    "cloudfront.net",
    "akamaized.net",
    "akamai.net",
    "fastly.net",
    "cloudflare.com",
    "azure.com",
    "azureedge.net",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "firebaseio.com",
    "appspot.com",
}

# Common non-domain prefixes / patterns to reject
_REJECT_PREFIXES = (
    "android.permission.",
    "android.intent.",
    "android.widget.",
    "android.view.",
    "android.os.",
    "android.app.",
    "android.content.",
    "androidx.",
    "java.lang.",
    "java.util.",
    "java.io.",
    "java.net.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "junit.",
    "org.junit.",
    "com.google.android.gms.permission",
)

_REJECT_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".xml", ".json", ".txt", ".properties", ".arsc",
    ".dex", ".so", ".jar", ".class", ".java", ".kt",
    ".ttf", ".otf", ".wav", ".mp3", ".ogg",
)

# Regex to detect full URLs
_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>{}|\^`\\]+",
    re.IGNORECASE,
)

# Regex to detect plausible domain names in text
_DOMAIN_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|ai|co|app|dev|me|info|biz|tv|cc|xyz|tech|online|store|site|club|cloud|pro|mobi|asia|int|eu|us|uk|ca|de|fr|in|jp|cn|au|br|ru|nl|ch|se|no|es|it|kr|za|sg|nz|mx|ru)(?::\d{1,5})?\b",
    re.IGNORECASE,
)

# IPv4 regex
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b"
)


# ---------------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------------

def is_system_namespace(domain: str) -> bool:
    """Check whether a domain is a known system/XML schema namespace.

    Args:
        domain: Hostname or domain string.

    Returns:
        True if the domain is a schema/XML namespace, False otherwise.
    """
    domain = clean_domain(domain).lower()
    if not domain:
        return False
    if domain in SYSTEM_NAMESPACES:
        return True
    for sys_ns in SYSTEM_NAMESPACES:
        if domain.endswith("." + sys_ns) or domain == sys_ns:
            return True
    return False


def categorize_domain(domain: str) -> str:
    """Categorize a domain into its operational role.

    Categories:
        - "system": XML schemas and platform namespaces
        - "google_service": Google and Android official services
        - "analytics_tracking": Telemetry, crash reporting, ads, tracking
        - "cloud_cdn": Cloud hosting and CDN distribution
        - "local_test": Localhost and test loopbacks
        - "target": Target API or business logic domain

    Args:
        domain: Cleaned domain string.

    Returns:
        String category name.
    """
    domain = clean_domain(domain).lower()
    if not domain:
        return "unknown"

    if is_system_namespace(domain):
        return "system"

    if domain in ("localhost", "127.0.0.1", "::1") or domain.endswith(".local"):
        return "local_test"

    for d in GOOGLE_PLATFORM_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "google_service"

    for d in ANALYTICS_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "analytics_tracking"

    for d in CLOUD_CDN_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "cloud_cdn"

    return "target"


def clean_domain(raw_domain: str) -> str:
    """Clean and normalize a domain string.

    Strips protocols, credentials, ports, paths, leading/trailing punctuation.

    Args:
        raw_domain: Raw domain or URL candidate.

    Returns:
        Normalized lower-case domain name or IP string, or empty string.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        return ""

    raw = raw_domain.strip().strip("'\"<>[](){},;*")

    # If it contains scheme, parse with urlparse
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            host = parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            host = raw.split("://", 1)[1].split("/")[0]
    else:
        host = raw.split("/")[0].split("?")[0].split("#")[0]

    # Remove user:pass@ if present
    if "@" in host:
        host = host.split("@", 1)[1]

    # Remove port
    if ":" in host:
        host = host.split(":", 1)[0]

    host = host.strip(".").lower()

    # Reject obvious non-domains
    if not host or len(host) < 3 or len(host) > 253:
        return ""

    for prefix in _REJECT_PREFIXES:
        if host.startswith(prefix):
            return ""

    for ext in _REJECT_EXTENSIONS:
        if host.endswith(ext):
            return ""

    # Disallow invalid characters
    if not re.match(r"^[a-z0-9.-]+$", host):
        return ""

    # Must contain at least one dot (unless localhost)
    if "." not in host and host != "localhost":
        return ""

    # Cannot have consecutive dots
    if ".." in host:
        return ""

    return host


# ---------------------------------------------------------------------------
# Extraction Functions
# ---------------------------------------------------------------------------

def extract_domains_from_urls(
    urls: Iterable[str], source: str = "url"
) -> List[Dict[str, Any]]:
    """Extract and categorize unique domains from a list of URLs.

    Args:
        urls: Collection of URL strings.
        source: Discovery source label.

    Returns:
        List of domain record dictionaries.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for url in urls:
        if not url or not isinstance(url, str):
            continue
        cleaned = clean_domain(url)
        if not cleaned:
            continue

        if cleaned not in seen:
            seen[cleaned] = {
                "domain": cleaned,
                "category": categorize_domain(cleaned),
                "is_system": is_system_namespace(cleaned),
                "sources": [source],
                "sample_urls": [url[:200]] if len(url) <= 200 else [url[:197] + "..."],
                "first_seen": now,
            }
        else:
            if source not in seen[cleaned]["sources"]:
                seen[cleaned]["sources"].append(source)
            if len(seen[cleaned]["sample_urls"]) < 5 and url not in seen[cleaned]["sample_urls"]:
                seen[cleaned]["sample_urls"].append(url[:200])

    return list(seen.values())


def extract_domains_from_strings(
    strings: Iterable[Any], default_source: str = "strings"
) -> List[Dict[str, Any]]:
    """Extract domains from raw string lists, string dumps, or string dicts.

    Args:
        strings: List of string values, or list of dicts with 'value'/'string' and 'source_location'.
        default_source: Fallback source name.

    Returns:
        List of domain record dictionaries.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for item in strings:
        if isinstance(item, dict):
            text = str(item.get("value") or item.get("string") or "")
            src = str(item.get("source_location") or item.get("source") or default_source)
        elif isinstance(item, str):
            text = item
            src = default_source
        else:
            text = str(item)
            src = default_source

        if not text:
            continue

        # 1. Check full URLs
        for match in _URL_PATTERN.finditer(text):
            url = match.group(0)
            cleaned = clean_domain(url)
            if cleaned:
                _record_domain(seen, cleaned, src, url, now)

        # 2. Check candidate domains
        for match in _DOMAIN_PATTERN.finditer(text):
            cand = match.group(0)
            cleaned = clean_domain(cand)
            if cleaned:
                _record_domain(seen, cleaned, src, cand, now)

        # 3. Check IPv4 addresses
        for match in _IPV4_PATTERN.finditer(text):
            ip = match.group(0)
            cleaned = clean_domain(ip)
            if cleaned:
                _record_domain(seen, cleaned, src, ip, now)

    return list(seen.values())


def extract_domains_from_traffic(
    traffic_requests: Iterable[Dict[str, Any]], source: str = "traffic"
) -> List[Dict[str, Any]]:
    """Extract domains from captured traffic requests.

    Args:
        traffic_requests: List of traffic request dicts with 'host' and/or 'url'.
        source: Discovery source label.

    Returns:
        List of domain record dictionaries.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for req in traffic_requests:
        host = req.get("host") or ""
        url = req.get("url") or ""
        src_file = req.get("source_file") or source

        cleaned = clean_domain(host) or clean_domain(url)
        if cleaned:
            sample = url or host
            _record_domain(seen, cleaned, f"traffic:{src_file}", sample, now)

    return list(seen.values())


def _record_domain(
    seen: Dict[str, Dict[str, Any]],
    domain: str,
    source: str,
    sample: str,
    timestamp: str,
) -> None:
    if domain not in seen:
        seen[domain] = {
            "domain": domain,
            "category": categorize_domain(domain),
            "is_system": is_system_namespace(domain),
            "sources": [source],
            "sample_urls": [sample[:200]],
            "first_seen": timestamp,
        }
    else:
        if source not in seen[domain]["sources"]:
            seen[domain]["sources"].append(source)
        if len(seen[domain]["sample_urls"]) < 5 and sample not in seen[domain]["sample_urls"]:
            seen[domain]["sample_urls"].append(sample[:200])


# ---------------------------------------------------------------------------
# High-Level Orchestrator
# ---------------------------------------------------------------------------

def run_domain_discovery(
    session: Optional[Any] = None,
    strings: Optional[List[Any]] = None,
    traffic: Optional[List[Dict[str, Any]]] = None,
    output_dir: Optional[Path] = None,
    filter_system: bool = False,
) -> Dict[str, Any]:
    """Execute domain discovery and write outputs.

    Outputs written to ``output_dir`` (or ``session.run_path / "api"``):
        - ``domains.json``: Complete structured list of discovered domains.
        - ``domains.txt``: Plaintext list of unique domain names (one per line).

    Args:
        session: Optional HUNTX Session instance.
        strings: Optional pre-loaded strings collection.
        traffic: Optional pre-loaded traffic requests.
        output_dir: Optional explicit output directory.
        filter_system: Whether to exclude system namespaces from output files.

    Returns:
        Dictionary with discovery statistics and domain records.
    """
    all_domains_map: Dict[str, Dict[str, Any]] = {}

    # 1. Ingest strings
    input_strings: List[Any] = []
    if strings is not None:
        input_strings.extend(strings)
    elif session is not None and hasattr(session, "run_path"):
        # Check android/strings.json or android/strings.txt
        str_json = session.run_path / "android" / "strings.json"
        if str_json.exists():
            try:
                with str_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        input_strings.extend(data)
                    elif isinstance(data, dict):
                        for k in ("strings", "all_strings", "raw_strings", "urls", "domains", "api_paths"):
                            if k in data and isinstance(data[k], list):
                                input_strings.extend(data[k])
            except Exception as exc:
                logger.warning("Skipped unreadable data: %s", exc)

    if input_strings:
        for rec in extract_domains_from_strings(input_strings, default_source="android_strings"):
            d = rec["domain"]
            if d not in all_domains_map:
                all_domains_map[d] = rec
            else:
                for s in rec["sources"]:
                    if s not in all_domains_map[d]["sources"]:
                        all_domains_map[d]["sources"].append(s)

    # 2. Ingest traffic
    input_traffic: List[Dict[str, Any]] = []
    if traffic is not None:
        input_traffic.extend(traffic)
    elif session is not None and hasattr(session, "run_path"):
        traffic_json = session.run_path / "traffic" / "requests.json"
        if traffic_json.exists():
            try:
                with traffic_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        input_traffic.extend(data)
            except Exception as exc:
                logger.warning("Skipped unreadable data: %s", exc)

    if input_traffic:
        for rec in extract_domains_from_traffic(input_traffic, source="traffic"):
            d = rec["domain"]
            if d not in all_domains_map:
                all_domains_map[d] = rec
            else:
                for s in rec["sources"]:
                    if s not in all_domains_map[d]["sources"]:
                        all_domains_map[d]["sources"].append(s)

    # Filter if requested
    results = list(all_domains_map.values())
    if filter_system:
        results = [r for r in results if not r["is_system"]]

    # Sort deterministically
    results.sort(key=lambda x: (x["is_system"], x["category"], x["domain"]))

    # Determine destination directory
    dest_dir = output_dir
    if dest_dir is None and session is not None and hasattr(session, "run_path"):
        dest_dir = session.run_path / "api"
    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)

        json_path = dest_dir / "domains.json"
        txt_path = dest_dir / "domains.txt"

        with json_path.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        with txt_path.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(r["domain"] + "\n")

    # Persist to repository/database if session provided
    if session is not None and hasattr(session, "db_path"):
        try:
            from huntx.storage.repository import Repository
            with Repository(session) as repo:
                for r in results:
                    repo.save_domain({
                        "domain": r["domain"],
                        "source": ",".join(r["sources"]),
                        "session_id": getattr(session.metadata, "session_id", ""),
                        "first_seen": r["first_seen"],
                    })
        except Exception as exc:
            logger.warning("Skipped unreadable data: %s", exc)

    # Summary counts
    categories: Dict[str, int] = {}
    for r in results:
        cat = r["category"]
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_domains": len(results),
        "target_domains": categories.get("target", 0),
        "system_domains": categories.get("system", 0),
        "analytics_domains": categories.get("analytics_tracking", 0),
        "cloud_cdn_domains": categories.get("cloud_cdn", 0),
        "categories": categories,
        "domains": results,
    }
