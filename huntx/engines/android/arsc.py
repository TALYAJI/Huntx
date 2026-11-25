"""Minimal ``resources.arsc`` reader: resource id -> (type, name, string value).

Only simple string values are returned, which is what label, network security
config and secret discovery need. Malformed tables yield whatever was readable.
"""
from __future__ import annotations

import logging
import struct
import zipfile
from typing import Dict, List, NamedTuple, Optional, Tuple

from huntx.core.safezip import read_member
from huntx.engines.android.axml import TYPE_REFERENCE, TYPE_STRING, AXMLParser

logger = logging.getLogger(__name__)

_STRING_POOL, _TABLE, _PACKAGE, _TYPE = 0x0001, 0x0002, 0x0200, 0x0201
_NO_ENTRY = 0xFFFFFFFF


class Resource(NamedTuple):
    type: str
    name: str
    value: str


def _pool(data: bytes, off: int) -> List[str]:
    ctype, _, size = struct.unpack_from("<HHI", data, off)
    if ctype != _STRING_POOL:
        return []
    p = AXMLParser(b"")
    p._parse_string_pool(data[off : off + size])
    return p.strings


def _entry_offsets(data: bytes, off: int, hdr: int, flags: int, count: int) -> List[Tuple[int, int]]:
    base = off + hdr
    if flags & 0x01:  # sparse
        return [(i, o * 4) for i, o in (struct.unpack_from("<HH", data, base + k * 4) for k in range(count))]
    if flags & 0x02:  # 16-bit offsets
        raw = struct.unpack_from(f"<{count}H", data, base)
        return [(i, o * 4) for i, o in enumerate(raw) if o != 0xFFFF]
    raw = struct.unpack_from(f"<{count}I", data, base)
    return [(i, o) for i, o in enumerate(raw) if o != _NO_ENTRY]


def parse_arsc(data: bytes) -> Dict[int, Resource]:
    """Parse a resource table, preferring default-configuration values."""
    out: Dict[int, Resource] = {}
    refs: Dict[int, Tuple[str, str, int]] = {}
    from_default: set[int] = set()
    try:
        if len(data) < 12 or struct.unpack_from("<H", data, 0)[0] != _TABLE:
            return out
        pos, values = struct.unpack_from("<H", data, 2)[0], []
        while pos + 8 <= len(data):
            ctype, _, size = struct.unpack_from("<HHI", data, pos)
            if size < 8:
                break
            if ctype == _STRING_POOL and not values:
                values = _pool(data, pos)
            elif ctype == _PACKAGE:
                _parse_package(data, pos, min(pos + size, len(data)), values, out, refs, from_default)
            pos += size
    except (struct.error, IndexError) as exc:
        logger.debug("Truncated resource table: %s", exc)

    for rid, (rtype, name, target) in refs.items():
        seen = {rid}
        while target in refs and target not in out and target not in seen:
            seen.add(target)
            target = refs[target][2]
        if rid not in out and target in out:
            out[rid] = Resource(rtype, name, out[target].value)
    return out


def _parse_package(data, start, end, values, out, refs, from_default) -> None:
    hdr = struct.unpack_from("<H", data, start + 2)[0]
    pkg_id = struct.unpack_from("<I", data, start + 8)[0]
    type_off, _, key_off = struct.unpack_from("<III", data, start + 268)
    types, keys = _pool(data, start + type_off), _pool(data, start + key_off)

    pos = start + hdr
    while pos + 8 <= end:
        ctype, chdr, size = struct.unpack_from("<HHI", data, pos)
        if size < 8:
            return
        if ctype == _TYPE:
            type_id, flags, _, count, entries_start = struct.unpack_from("<BBHII", data, pos + 8)
            cfg_size = struct.unpack_from("<I", data, pos + 20)[0]
            is_default = not any(data[pos + 24 : pos + 20 + cfg_size])
            tname = types[type_id - 1] if 0 < type_id <= len(types) else ""
            if count * (2 if flags & 0x02 else 4) > size:
                return
            for idx, eoff in _entry_offsets(data, pos, chdr, flags, count):
                e = pos + entries_start + eoff
                if e + 8 > end:
                    continue
                esize, eflags, key = struct.unpack_from("<HHI", data, e)
                if eflags & 0x08:  # compact entry
                    key, vtype, vdata = esize, eflags >> 8, key
                elif eflags & 0x01 or e + esize + 8 > end:  # complex (bag) or truncated
                    continue
                else:
                    vtype, vdata = struct.unpack_from("<BI", data, e + esize + 3)
                rid = (pkg_id << 24) | (type_id << 16) | idx
                name = keys[key] if key < len(keys) else ""
                if vtype == TYPE_STRING and vdata < len(values):
                    if rid not in out or (is_default and rid not in from_default):
                        out[rid] = Resource(tname, name, values[vdata])
                        if is_default:
                            from_default.add(rid)
                elif vtype == TYPE_REFERENCE:
                    refs.setdefault(rid, (tname, name, vdata))
        pos += size


def load_arsc(zf: zipfile.ZipFile) -> Dict[int, Resource]:
    """Read and parse ``resources.arsc`` from an open APK (empty when absent)."""
    if "resources.arsc" not in zf.namelist():
        return {}
    return parse_arsc(read_member(zf, "resources.arsc"))


def resolve_reference(value: Optional[str], table: Dict[int, Resource]) -> Optional[str]:
    """Resolve ``@0x7f...`` to its string value; other values are returned unchanged."""
    if value and value.startswith("@0x"):
        try:
            res = table.get(int(value[1:], 16))
        except ValueError:
            return value
        return res.value if res else value
    return value
