"""HUNTX Android String Extraction Engine.

Extracts strings from:
- classes*.dex (Dalvik bytecode string pool)
- AndroidManifest.xml
- Resource files (res/**/*.xml, resources.arsc)
- Assets and configuration files (assets/**/*.json, xml, properties)

Identifies:
- Candidate URLs (http://, https://)
- Domains and FQDNs
- API paths (/api/v1/..., /graphql, etc.)
- Email addresses
- IPv4 addresses
- Tokens, secrets, and cloud references (AWS keys, Google API keys, Firebase URLs, JWTs)

Preserves original string and its source location/file.

Outputs:
- android/strings.json
- android/strings.txt
"""
from __future__ import annotations

import json
import logging
import re
import struct
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from huntx.core.safezip import read_member
from huntx.engines.android.arsc import parse_arsc
from huntx.engines.android.axml import AXMLParser

logger = logging.getLogger(__name__)

# Regular expressions for string identification
RE_URL = re.compile(
    r"https?://(?:[a-zA-Z0-9_\-\.]+(?::[0-9]+)?)(?:/[^\s\"'<>{}\\|^`\x00-\x1f]*)?",
    re.IGNORECASE,
)
RE_DOMAIN = re.compile(
    # not the host of an email, nor the middle of a dotted code name (libcore.io.Disk)
    r"(?<![@\w.$%+-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|ai|co|dev|app|info|biz|me|cc|tv|us|uk|ca|de|jp|fr|au|ru|ch|it|nl|se|no|es|br|in|cn)(?!\.?[\w@$-])",
    re.IGNORECASE,
)
# The lookbehind keeps "Landroid/support/v4/..." and the path half of full URLs out.
RE_API_PATH = re.compile(
    r"(?<![\w.$/:}-])(?:/[a-zA-Z0-9_\-\.]+)?/(?:api|v[0-9]+|rest|graphql|oauth|auth|users?|account|service|endpoint)/[a-zA-Z0-9_\-\./{}]+",
    re.IGNORECASE,
)
# Whole-string relative routes without a leading slash ("api/v1/users")
RE_BARE_API_PATH = re.compile(r"(?:api|rest|graphql|oauth2?|v\d+)/[\w\-./{}]+(?:\?\S*)?", re.IGNORECASE)
RE_ANDROID_R = re.compile(r"r\.(?:string|id|layout|drawable|color|style|xml|raw|menu|attr|array|dimen)\.")
# Reverse-DNS package names ("com.example.app") look like domains but are not
_REVERSE_DNS_ROOTS = {
    "com", "org", "net", "io", "android", "androidx", "java", "javax", "kotlin",
    "kotlinx", "dalvik", "sun", "okhttp3", "retrofit2", "dagger",
}
# Cheap gate: no token pattern can match without one of these literals
RE_TOKEN_HINT = re.compile(
    r"AKIA|amazonaws|s3://|googleapis|blob\.core|AIza|firebase|[sr]k_(?:live|test)_|SG\.|pk\.eyJ"
    r"|\bSK[0-9a-f]|PRIVATE KEY|eyJ|bearer|api_?key|secret_key|client_secret|auth_token|xox|gh[pousr]_",
    re.IGNORECASE,
)
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Token and Cloud Reference patterns
TOKEN_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_s3_bucket", re.compile(r"(https?://[a-zA-Z0-9.\-_]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com(?:/[^\s\"'<>]*)?|s3://[a-zA-Z0-9.\-_]+)", re.IGNORECASE)),
    ("gcs_bucket", re.compile(r"(https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?)", re.IGNORECASE)),
    ("azure_blob", re.compile(r"(https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?)", re.IGNORECASE)),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b")),
    ("firebase_db", re.compile(r"(https?://[a-zA-Z0-9\-]+\.(?:firebaseio\.com|firebaseapp\.com))", re.IGNORECASE)),
    ("stripe_key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b")),
    ("sendgrid_key", re.compile(r"\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b")),
    ("mapbox_token", re.compile(r"\b(pk\.eyJ1[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b")),
    ("twilio_key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("private_key", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")),
    ("jwt_token", re.compile(r"\b(eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*)\b")),
    ("bearer_token", re.compile(r"\bBearer\s+([a-zA-Z0-9\-._~+/]{20,}=*)", re.IGNORECASE)),
    ("generic_secret", re.compile(r'(?:api_key|apikey|secret_key|client_secret|auth_token)["\'\s:=]+([a-zA-Z0-9_\-]{20,})', re.IGNORECASE)),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("github_token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36})\b")),
]

# Excluded domain suffixes/extensions to prevent false positives from code/file names
EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".xml", ".so", ".dex", ".class", ".java",
    ".kt", ".json", ".properties", ".txt", ".ttf", ".webp", ".html", ".css", ".js",
}


@dataclass
class StringFinding:
    """A classified string discovery."""

    value: str
    category: str  # url, domain, api_path, email, ip, token
    source: str
    token_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.token_type is None:
            del d["token_type"]
        return d


def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    """Read an unsigned LEB128 integer from data starting at pos."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_dex_strings(data: bytes) -> List[str]:
    """Extract all strings from a Dalvik DEX file buffer."""
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        return []

    try:
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        results: List[str] = []

        for i in range(string_ids_size):
            off_pos = string_ids_off + (i * 4)
            if off_pos + 4 > len(data):
                break

            str_off = struct.unpack_from("<I", data, off_pos)[0]
            if str_off >= len(data):
                continue

            # Read uleb128 character count
            _, str_data_pos = _read_uleb128(data, str_off)

            # Null-terminated UTF-8 / MUTF-8
            end = data.find(b"\x00", str_data_pos)
            if end != -1:
                raw_bytes = data[str_data_pos:end]
                try:
                    s = raw_bytes.decode("utf-8", errors="replace")
                    if s:
                        results.append(s)
                except Exception as exc:
                    logger.debug("Skipped malformed value: %s", exc)

        return results
    except Exception as e:
        logger.debug("Error parsing DEX strings: %s", e)
        return []


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Fallback extraction of printable ASCII strings."""
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    matches = pattern.findall(data)
    results = []
    for m in matches:
        try:
            results.append(m.decode("ascii"))
        except Exception as exc:
            logger.debug("Skipped malformed value: %s", exc)
    return results


def extract_strings_from_bytes(data: bytes, source: str) -> List[Tuple[str, str]]:
    """Extract strings from raw file bytes with associated source filename."""
    found: List[Tuple[str, str]] = []

    # If it is a DEX file
    if data.startswith(b"dex\n"):
        for s in parse_dex_strings(data):
            found.append((s, source))
        return found

    # Compiled resource table: real values, labelled with their resource name
    if source.endswith("resources.arsc"):
        table = parse_arsc(data)
        if table:
            return [
                (f"{r.name}={r.value}" if r.type == "string" else r.value, f"{source}:{r.type}/{r.name}")
                for r in table.values()
            ]

    # Binary XML: use its string pool rather than raw bytes
    if data[:4] == b"\x03\x00\x08\x00":
        parser = AXMLParser(data)
        parser.parse()
        return [(s, source) for s in parser.strings if len(s) >= 3]

    # Other binary blobs (e.g. Hermes bundles)
    if b"\x00" in data[:4096]:
        return [(s, source) for s in _extract_ascii_strings(data)]

    # If it is plaintext or JSON
    try:
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line_str = line.strip()
            if len(line_str) >= 4:
                found.append((line_str, source))
    except Exception:
        for s in _extract_ascii_strings(data, min_len=4):
            found.append((s, source))

    return found


def _is_descriptor(s: str) -> bool:
    """Dalvik type descriptors and method signatures are code, never endpoints."""
    return s.startswith(("L", "[", "(")) and ";" in s and "/" in s and " " not in s and "://" not in s


_CHUNK = 4096


def _chunks(raw: Iterable[Tuple[str, str]]) -> Iterator[Tuple[str, str]]:
    """Bound regex work on huge lines (minified bundles, hostile strings)."""
    for s, source in raw:
        if len(s) <= _CHUNK:
            yield s, source
        else:
            i = 0
            while i < len(s):
                end = min(i + _CHUNK, len(s))
                if end < len(s):  # cut at a delimiter so URLs stay whole
                    cut = max(s.rfind(c, i + _CHUNK // 2, end) for c in " \"'`\n;,")
                    end = cut if cut > 0 else end
                yield s[i:end], source
                i = end


def classify_strings(raw_strings: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Classify and deduplicate extracted strings into target categories."""
    urls_seen: Set[str] = set()
    domains_seen: Set[str] = set()
    api_paths_seen: Set[str] = set()
    emails_seen: Set[str] = set()
    ips_seen: Set[str] = set()
    tokens_seen: Set[str] = set()

    urls: List[Dict[str, Any]] = []
    domains: List[Dict[str, Any]] = []
    api_paths: List[Dict[str, Any]] = []
    emails: List[Dict[str, Any]] = []
    ips: List[Dict[str, Any]] = []
    tokens: List[Dict[str, Any]] = []

    seen_strings: Set[str] = set()
    for s, source in _chunks(raw_strings):
        if not s or len(s) < 3 or s in seen_strings:
            continue
        seen_strings.add(s)
        if source.endswith(".dex") and _is_descriptor(s):
            continue
        has_dot, has_slash = "." in s, "/" in s

        # 1. URLs
        for m in RE_URL.findall(s) if "://" in s else ():
            url_clean = m.strip().rstrip(".)'\">];")
            if url_clean and url_clean not in urls_seen:
                urls_seen.add(url_clean)
                urls.append({"value": url_clean, "source": source, "category": "url"})

                # Extract host/domain from URL
                try:
                    host_part = url_clean.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                    if host_part and host_part not in domains_seen and "." in host_part:
                        domains_seen.add(host_part)
                        domains.append({"value": host_part, "source": source, "category": "domain"})
                except IndexError:
                    logger.debug("No host in URL %r", url_clean)

        # 2. Standalone domains
        for m in RE_DOMAIN.findall(s) if has_dot else ():
            if not m.rsplit(".", 1)[1].islower():  # TextAppearance.Foo.Info
                continue
            dom = m.strip().lower()
            if RE_ANDROID_R.match(dom):  # R.string.no
                continue
            if dom.split(".", 1)[0] in _REVERSE_DNS_ROOTS:
                continue
            # Verify not an excluded file extension
            if not any(dom.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                if dom not in domains_seen:
                    domains_seen.add(dom)
                    domains.append({"value": dom, "source": source, "category": "domain"})

        # 3. API Paths
        bare = RE_BARE_API_PATH.fullmatch(s) if has_slash else None
        for m in ["/" + s] if bare else (RE_API_PATH.findall(s) if has_slash else ()):
            path_clean = m.strip().rstrip(".)'\">];")
            if path_clean and path_clean not in api_paths_seen:
                api_paths_seen.add(path_clean)
                api_paths.append({"value": path_clean, "source": source, "category": "api_path"})

        # 4. Emails
        for m in RE_EMAIL.findall(s) if "@" in s else ():
            em = m.strip().lower()
            if em not in emails_seen and not any(em.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                emails_seen.add(em)
                emails.append({"value": em, "source": source, "category": "email"})

        # 5. IPv4
        for m in RE_IPV4.findall(s) if s.count(".") >= 3 else ():
            ip = m.strip()
            # Basic sanity check
            octets = ip.split(".")
            if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                if ip not in ips_seen:
                    ips_seen.add(ip)
                    ips.append({"value": ip, "source": source, "category": "ip"})

        # 6. Tokens & Cloud references
        for t_type, pattern in TOKEN_PATTERNS if RE_TOKEN_HINT.search(s) else ():
            for m in pattern.findall(s):
                tok_val = m.strip() if isinstance(m, str) else m[0].strip()
                if tok_val and tok_val not in tokens_seen:
                    tokens_seen.add(tok_val)
                    tokens.append(
                        {
                            "value": tok_val,
                            "token_type": t_type,
                            "source": source,
                            "category": "token",
                        }
                    )

    # Sort each list by value
    urls.sort(key=lambda x: x["value"])
    domains.sort(key=lambda x: x["value"])
    api_paths.sort(key=lambda x: x["value"])
    emails.sort(key=lambda x: x["value"])
    ips.sort(key=lambda x: x["value"])
    tokens.sort(key=lambda x: (x["token_type"], x["value"]))

    summary = {
        "urls_count": len(urls),
        "domains_count": len(domains),
        "api_paths_count": len(api_paths),
        "emails_count": len(emails),
        "ips_count": len(ips),
        "tokens_count": len(tokens),
        "total_classified": (
            len(urls) + len(domains) + len(api_paths) + len(emails) + len(ips) + len(tokens)
        ),
    }

    return {
        "summary": summary,
        "urls": urls,
        "domains": domains,
        "api_paths": api_paths,
        "emails": emails,
        "ips": ips,
        "tokens": tokens,
    }


def extract_strings(
    apk_path: str | Path | List[Path],
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Extract and classify all strings from one or more APKs or an unpacked directory.

    Args:
        apk_path: Path to an APK file, directory, or list of split APK Paths.
        output_dir: Optional destination directory (e.g. session/android/).
            If provided, writes `strings.json` and `strings.txt`.

    Returns:
        Dict of classified strings and counts.
    """
    if isinstance(apk_path, (list, tuple)):
        paths = [Path(p) for p in apk_path]
        if not paths or not any(p.exists() for p in paths):
            raise FileNotFoundError(f"Targets not found: {apk_path}")
    else:
        single = Path(apk_path)
        if not single.exists():
            raise FileNotFoundError(f"Target not found: {single}")
        paths = [single]

    raw_strings: List[Tuple[str, str]] = []
    files_inspected = 0
    multi_apk = len(paths) > 1

    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    for name in zf.namelist():
                        # Filter target files
                        is_dex = name.startswith("classes") and name.endswith(".dex")
                        is_manifest = name == "AndroidManifest.xml"
                        is_asset = name.startswith("assets/") and (
                            name.endswith(".json")
                            or name.endswith(".xml")
                            or name.endswith(".properties")
                            or name.endswith(".txt")
                            or name.endswith(".conf")
                            or name.endswith(".js")
                            or name.endswith(".bundle")
                        )
                        is_res = (
                            name.startswith("res/values/") and name.endswith(".xml")
                        ) or name.startswith("res/xml/") or name == "resources.arsc"

                        if is_dex or is_manifest or is_asset or is_res:
                            try:
                                data = read_member(zf, name)
                                src_label = f"{path.name}:{name}" if multi_apk else name
                                extracted = extract_strings_from_bytes(data, src_label)
                                raw_strings.extend(extracted)
                                files_inspected += 1
                            except Exception as e:
                                logger.debug("Failed reading %s: %s", name, e)

            except zipfile.BadZipFile:
                logger.warning("Target is not a valid zip archive: %s", path)

        elif path.is_dir():
            for file_p in path.rglob("*"):
                if file_p.is_file():
                    rel_name = file_p.relative_to(path).as_posix()
                    if (
                        rel_name.endswith(".dex")
                        or rel_name.endswith(".xml")
                        or rel_name.endswith(".json")
                        or rel_name.endswith(".properties")
                    ):
                        try:
                            data = file_p.read_bytes()
                            extracted = extract_strings_from_bytes(data, rel_name)
                            raw_strings.extend(extracted)
                            files_inspected += 1
                        except Exception as e:
                            logger.debug("Failed reading file %s: %s", file_p, e)

    classified = classify_strings(raw_strings)
    classified["files_inspected"] = files_inspected
    classified["raw_strings_count"] = len(raw_strings)
    classified["total_extracted"] = len(raw_strings)

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Output 1: strings.json
        json_file = out_path / "strings.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(classified, f, indent=2)

        # Output 2: strings.txt
        txt_file = out_path / "strings.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(format_strings_txt(classified))

    return classified


def format_strings_txt(data: Dict[str, Any]) -> str:
    """Format extracted strings into a clean human-readable text report."""
    summary = data.get("summary", {})
    lines = [
        "=" * 80,
        "HUNTX - ANDROID STRING EXTRACTION REPORT",
        "=" * 80,
        f"Files Inspected   : {data.get('files_inspected', 0)}",
        f"Raw Strings Read  : {data.get('raw_strings_count', 0):,}",
        f"Classified Items  : {summary.get('total_classified', 0):,}",
        "",
        "SUMMARY BREAKDOWN",
        "-" * 80,
        f"  Candidate URLs      : {summary.get('urls_count', 0)}",
        f"  Candidate Domains   : {summary.get('domains_count', 0)}",
        f"  Candidate API Paths : {summary.get('api_paths_count', 0)}",
        f"  Email Addresses     : {summary.get('emails_count', 0)}",
        f"  IP Addresses        : {summary.get('ips_count', 0)}",
        f"  Tokens & Cloud Refs : {summary.get('tokens_count', 0)}",
        "",
    ]

    # Sections
    sections = [
        ("CANDIDATE URLS", data.get("urls", [])),
        ("CANDIDATE DOMAINS", data.get("domains", [])),
        ("CANDIDATE API PATHS", data.get("api_paths", [])),
        ("EMAIL ADDRESSES", data.get("emails", [])),
        ("IP ADDRESSES", data.get("ips", [])),
    ]

    for title, items in sections:
        lines.append(title)
        lines.append("-" * 80)
        if not items:
            lines.append("  (none discovered)")
        else:
            for item in items:
                lines.append(f"  • {item['value']}  [{item.get('source', '')}]")
        lines.append("")

    # Tokens section
    tokens = data.get("tokens", [])
    lines.append("TOKENS & CLOUD REFERENCES")
    lines.append("-" * 80)
    if not tokens:
        lines.append("  (none discovered)")
    else:
        for item in tokens:
            t_type = item.get("token_type", "token")
            lines.append(f"  • [{t_type}] {item['value']}  [{item.get('source', '')}]")
    lines.append("")

    lines.append("=" * 80)
    lines.append("")
    return "\n".join(lines)
