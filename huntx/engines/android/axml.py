"""HUNTX Android Binary XML (AXML) parser.

Pure Python, zero external dependencies.
Converts Android Binary XML (AXML) into an xml.etree.ElementTree.Element tree or XML string.
Also handles plaintext XML transparently (e.g. from decompiled APKs or test fixtures).
"""
from __future__ import annotations

import logging
import re
import struct
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# AXML chunk types
CHUNK_AXML_FILE = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104

# TypedValue types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F


# Framework attribute ids: shrinkers may blank the names but the ids are authoritative.
_ATTR_IDS: Dict[int, str] = {
    0x01010001: "label", 0x01010003: "name", 0x01010006: "permission",
    0x01010007: "readPermission", 0x01010008: "writePermission",
    0x01010009: "protectionLevel", 0x0101000E: "enabled", 0x0101000F: "debuggable",
    0x01010010: "exported", 0x01010018: "authorities", 0x0101001B: "grantUriPermissions",
    0x01010026: "mimeType", 0x01010027: "scheme", 0x01010028: "host", 0x01010029: "port",
    0x0101002A: "path", 0x0101002B: "pathPrefix", 0x0101002C: "pathPattern",
    0x0101020C: "minSdkVersion", 0x0101021B: "versionCode", 0x0101021C: "versionName",
    0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion", 0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
}


class AXMLParser:
    """Parser for Android Binary XML documents."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.strings: List[str] = []
        self.resource_map: Tuple[int, ...] = ()
        self.namespaces: Dict[str, str] = {
            "http://schemas.android.com/apk/res/android": "android",
            "http://schemas.android.com/apk/res-auto": "app",
            "http://schemas.android.com/tools": "tools",
        }
        self.prefix_to_uri: Dict[str, str] = {v: k for k, v in self.namespaces.items()}

    def parse(self) -> Optional[ET.Element]:
        """Parse raw AXML or plaintext XML data into an ElementTree Element."""
        if not self.data:
            return None

        # Check for plaintext XML first
        stripped = self.data.lstrip()
        if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
            try:
                if b"<!ENTITY" in self.data:
                    raise ValueError("XML entity declarations are not allowed")
                return ET.fromstring(self.data.decode("utf-8", errors="replace"))
            except Exception as e:
                logger.debug("Plaintext XML parse failed, trying AXML: %s", e)

        # Validate minimum AXML file header
        if len(self.data) < 8:
            return self._fallback_parse()

        chunk_type, header_size, total_size = struct.unpack_from("<HHI", self.data, 0)
        if chunk_type != CHUNK_AXML_FILE:
            return self._fallback_parse()

        offset = header_size
        file_len = min(len(self.data), total_size if total_size > 0 else len(self.data))

        root: Optional[ET.Element] = None
        stack: List[ET.Element] = []

        try:
            while offset + 8 <= file_len:
                c_type, c_hdr_sz, c_size = struct.unpack_from("<HHI", self.data, offset)
                if c_size <= 0 or offset + c_size > len(self.data) + 16:
                    break

                chunk_data = self.data[offset : offset + c_size]

                if c_type == CHUNK_STRING_POOL:
                    self._parse_string_pool(chunk_data)

                elif c_type == CHUNK_RESOURCE_MAP:
                    n = (len(chunk_data) - c_hdr_sz) // 4
                    self.resource_map = struct.unpack_from(f"<{n}I", chunk_data, c_hdr_sz)

                elif c_type == CHUNK_START_NAMESPACE:
                    self._parse_start_namespace(chunk_data)

                elif c_type == CHUNK_START_ELEMENT:
                    elem = self._parse_start_element(chunk_data)
                    if elem is not None:
                        if stack:
                            stack[-1].append(elem)
                        else:
                            root = elem
                        stack.append(elem)

                elif c_type == CHUNK_END_ELEMENT:
                    if stack:
                        stack.pop()

                elif c_type == CHUNK_CDATA:
                    if stack and len(chunk_data) >= 28:
                        data_idx = struct.unpack_from("<i", chunk_data, 16)[0]
                        if 0 <= data_idx < len(self.strings):
                            stack[-1].text = (stack[-1].text or "") + self.strings[data_idx]

                offset += c_size

        except Exception as exc:
            logger.debug("AXML parsing encountered error: %s, attempting recovery", exc)

        if root is not None:
            return root

        return self._fallback_parse()

    def _parse_string_pool(self, chunk: bytes) -> None:
        """Parse string pool chunk."""
        if len(chunk) < 28:
            return

        scount, style_count, flags, str_start, _ = struct.unpack_from("<IIIII", chunk, 8)
        is_utf8 = bool(flags & 0x100)

        offsets: List[int] = []
        for i in range(scount):
            off_pos = 28 + (i * 4)
            if off_pos + 4 <= len(chunk):
                offsets.append(struct.unpack_from("<I", chunk, off_pos)[0])

        strings: List[str] = []
        for off in offsets:
            pos = str_start + off
            if pos >= len(chunk):
                strings.append("")
                continue

            try:
                if is_utf8:
                    # UTF-8: skip uleb128 char length and uleb128 byte length
                    if pos >= len(chunk):
                        strings.append("")
                        continue
                    b1 = chunk[pos]
                    pos += 2 if (b1 & 0x80) else 1
                    if pos >= len(chunk):
                        strings.append("")
                        continue
                    b2 = chunk[pos]
                    if b2 & 0x80 and pos + 1 < len(chunk):
                        b_len = ((b2 & 0x7F) << 8) | chunk[pos + 1]
                        pos += 2
                    else:
                        b_len = b2
                        pos += 1

                    s = chunk[pos : pos + b_len].decode("utf-8", errors="replace")
                    strings.append(s)
                else:
                    # UTF-16: 1 or 2 16-bit units length
                    if pos + 2 > len(chunk):
                        strings.append("")
                        continue
                    u1 = struct.unpack_from("<H", chunk, pos)[0]
                    if u1 & 0x8000 and pos + 4 <= len(chunk):
                        u2 = struct.unpack_from("<H", chunk, pos + 2)[0]
                        u_len = ((u1 & 0x7FFF) << 16) | u2
                        pos += 4
                    else:
                        u_len = u1
                        pos += 2

                    end_pos = pos + (u_len * 2)
                    s = chunk[pos:end_pos].decode("utf-16le", errors="replace")
                    strings.append(s)
            except Exception:
                strings.append("")

        self.strings = strings

    def _parse_start_namespace(self, chunk: bytes) -> None:
        """Record namespace prefix and uri."""
        if len(chunk) < 24:
            return
        prefix_idx, uri_idx = struct.unpack_from("<ii", chunk, 16)
        prefix = self.strings[prefix_idx] if 0 <= prefix_idx < len(self.strings) else ""
        uri = self.strings[uri_idx] if 0 <= uri_idx < len(self.strings) else ""
        if uri:
            self.namespaces[uri] = prefix or "ns"
            if prefix:
                self.prefix_to_uri[prefix] = uri

    def _parse_start_element(self, chunk: bytes) -> Optional[ET.Element]:
        """Parse start element and its attributes."""
        if len(chunk) < 36:
            return None

        ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<iiHHH", chunk, 16)
        tag_name = self.strings[name_idx] if 0 <= name_idx < len(self.strings) else "unknown"

        elem = ET.Element(tag_name)

        # Attribute starting position relative to chunk start
        attr_offset = 16 + 20
        if attr_start > 0:
            attr_offset = 16 + attr_start

        if attr_size < 20:
            attr_size = 20

        for i in range(attr_count):
            cur_pos = attr_offset + (i * attr_size)
            if cur_pos + 20 > len(chunk):
                break

            a_ns, a_name, a_raw, a_sz, a_res0, a_type, a_data = struct.unpack_from(
                "<iiiHBBI", chunk, cur_pos
            )

            attr_name = self.strings[a_name] if 0 <= a_name < len(self.strings) else f"attr_{i}"
            ns_uri = self.strings[a_ns] if 0 <= a_ns < len(self.strings) else ""

            if 0 <= a_name < len(self.resource_map):
                known = _ATTR_IDS.get(self.resource_map[a_name])
                if known:
                    attr_name = known
                    ns_uri = ns_uri or "http://schemas.android.com/apk/res/android"

            if ns_uri:
                prefix = self.namespaces.get(ns_uri, "android")
                attr_key = f"{prefix}:{attr_name}"
            else:
                attr_key = attr_name

            # Resolve value
            val = self._decode_attr_value(a_raw, a_type, a_data)
            elem.set(attr_key, val)

        return elem

    def _decode_attr_value(self, raw_idx: int, val_type: int, data: int) -> str:
        """Decode an attribute value based on its type and string pool index."""
        if 0 <= raw_idx < len(self.strings):
            return self.strings[raw_idx]

        if val_type == TYPE_STRING:
            if 0 <= data < len(self.strings):
                return self.strings[data]
            return ""

        if val_type == TYPE_INT_BOOLEAN:
            return "true" if data != 0 else "false"

        if val_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            return str(data)

        if val_type == TYPE_REFERENCE:
            return f"@0x{data:08x}"

        if val_type == TYPE_ATTRIBUTE:
            return f"?0x{data:08x}"

        if val_type in (
            TYPE_INT_COLOR_ARGB8,
            TYPE_INT_COLOR_RGB8,
            TYPE_INT_COLOR_ARGB4,
            TYPE_INT_COLOR_RGB4,
        ):
            return f"#{data:08x}"

        if val_type == TYPE_NULL:
            return ""

        return str(data)

    def _fallback_parse(self) -> ET.Element:
        """Failsafe fallback: extract visible strings and synthesize a manifest element."""
        root = ET.Element("manifest")

        # Try to locate strings in data using regex
        text = self.data.decode("utf-8", errors="ignore")
        pkg_match = re.search(r'package[=\s"]+([a-zA-Z0-9_\.]+)', text)
        if pkg_match:
            root.set("package", pkg_match.group(1))
        else:
            root.set("package", "com.unknown.package")

        vc_match = re.search(r'versionCode[=\s"]+(\d+)', text)
        if vc_match:
            root.set("android:versionCode", vc_match.group(1))

        vn_match = re.search(r'versionName[=\s"]+([^\s"<>]+)', text)
        if vn_match:
            root.set("android:versionName", vn_match.group(1))

        app = ET.SubElement(root, "application")
        app_match = re.search(r'android:name[=\s"]+([a-zA-Z0-9_\.]+)', text)
        if app_match:
            app.set("android:name", app_match.group(1))

        return root


def parse_axml(data: bytes) -> ET.Element:
    """Parse raw bytes (AXML binary or plaintext XML) into an ElementTree Element."""
    parser = AXMLParser(data)
    elem = parser.parse()
    if elem is None:
        elem = ET.Element("manifest")
        elem.set("package", "unknown")
    return elem


def axml_to_xml(data: bytes) -> str:
    """Convert raw AXML or plaintext XML bytes into a formatted XML string.

    Rewrites ``prefix:attr`` attribute keys that the AXML parser emits as plain
    strings into Clark-notation ``{uri}attr`` keys, then registers the well-known
    Android namespace prefixes so that ``ET.tostring`` emits proper
    ``xmlns:android="..."`` declarations.  The result is accepted by any
    conformant XML parser.
    """
    _NS_MAP = {
        "android": "http://schemas.android.com/apk/res/android",
        "app":     "http://schemas.android.com/apk/res-auto",
        "tools":   "http://schemas.android.com/tools",
    }
    # Register *before* serialisation so ET uses canonical prefixes instead of
    # auto-generated ``ns0:`` ones.
    for prefix, uri in _NS_MAP.items():
        ET.register_namespace(prefix, uri)

    elem = parse_axml(data)

    # The AXML parser stores attributes as plain ``"android:name"`` strings.
    # ET.tostring only emits xmlns declarations for Clark-form ``{uri}name``
    # keys, so we must rewrite the keys before serialising.
    _PREFIX_TO_URI: Dict[str, str] = {pfx: uri for pfx, uri in _NS_MAP.items()}

    def _to_clark(tree: ET.Element) -> None:
        """Recursively rewrite prefix:local attribute keys to {uri}local form."""
        rewritten: Dict[str, str] = {}
        for key, val in list(tree.attrib.items()):
            if ":" in key and not key.startswith("{"):
                pfx, local = key.split(":", 1)
                uri = _PREFIX_TO_URI.get(pfx)
                if uri:
                    rewritten[f"{{{uri}}}{local}"] = val
                    continue
            rewritten[key] = val
        tree.attrib.clear()
        tree.attrib.update(rewritten)
        for child in tree:
            _to_clark(child)

    _to_clark(elem)

    try:
        ET.indent(elem, space="  ")
    except Exception as exc:
        logger.debug("Skipped malformed value: %s", exc)

    xml_bytes = ET.tostring(elem, encoding="unicode", xml_declaration=False)
    xml_str = '<?xml version="1.0" encoding="utf-8"?>\n' + xml_bytes
    return xml_str
