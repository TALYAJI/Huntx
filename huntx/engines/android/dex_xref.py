"""HUNTX Pure-Python Dalvik Bytecode Cross-Reference & HTTP Method Inference.

Parses DEX class_defs, method_ids, and Dalvik bytecode code_items without
external Java/APKTool dependencies to:
  1. Map string constants (URLs, API paths) to exact calling Class & Method.
  2. Infer HTTP methods from concrete networking invocations in the same method
     (e.g., OkHttp Request$Builder.post(), HttpPost, HttpURLConnection.setRequestMethod).
     Preserves UNKNOWN whenever inference is inconclusive.
"""
from __future__ import annotations

import logging
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from huntx.core.safezip import read_member
from huntx.engines.android.strings import RE_BARE_API_PATH

logger = logging.getLogger(__name__)

# Dalvik instruction lengths in 16-bit code units for all 256 opcodes (0x00 - 0xFF)
# Standard Android Dalvik bytecode format specification:
_INSN_WIDTH: Dict[int, int] = {
    0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 1,
    0x08: 2, 0x09: 3, 0x0A: 1, 0x0B: 1, 0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1D: 1, 0x1E: 1, 0x1F: 2,
    0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3, 0x2D: 2, 0x2E: 2, 0x2F: 2,
    0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
    0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 2,
    # 0x3E..0x43 unused
    0x44: 2, 0x45: 2, 0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4A: 2, 0x4B: 2,
    0x4C: 2, 0x4D: 2, 0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2,
    0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2, 0x5A: 2, 0x5B: 2,
    0x5C: 2, 0x5D: 2, 0x5E: 2, 0x5F: 2,
    0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2,
    0x68: 2, 0x69: 2, 0x6A: 2, 0x6B: 2, 0x6C: 2, 0x6D: 2,
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3, 0x72: 3,
    0x74: 3, 0x75: 3, 0x76: 3, 0x77: 3, 0x78: 3,
    0x7B: 1, 0x7C: 1, 0x7D: 1, 0x7E: 1, 0x7F: 1,
    0x80: 1, 0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1, 0x85: 1, 0x86: 1, 0x87: 1,
    0x88: 1, 0x89: 1, 0x8A: 1, 0x8B: 1, 0x8C: 1, 0x8D: 1, 0x8E: 1, 0x8F: 1,
    0x90: 2, 0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2, 0x95: 2, 0x96: 2, 0x97: 2,
    0x98: 2, 0x99: 2, 0x9A: 2, 0x9B: 2, 0x9C: 2, 0x9D: 2, 0x9E: 2, 0x9F: 2,
    0xA0: 2, 0xA1: 2, 0xA2: 2, 0xA3: 2, 0xA4: 2, 0xA5: 2, 0xA6: 2, 0xA7: 2,
    0xA8: 2, 0xA9: 2, 0xAA: 2, 0xAB: 2, 0xAC: 2, 0xAD: 2, 0xAE: 2, 0xAF: 0x2,
    0xB0: 1, 0xB1: 1, 0xB2: 1, 0xB3: 1, 0xB4: 1, 0xB5: 1, 0xB6: 1, 0xB7: 1,
    0xB8: 1, 0xB9: 1, 0xBA: 1, 0xBB: 1, 0xBC: 1, 0xBD: 1, 0xBE: 1, 0xBF: 1,
    0xC0: 1, 0xC1: 1, 0xC2: 1, 0xC3: 1, 0xC4: 1, 0xC5: 1, 0xC6: 1, 0xC7: 1,
    0xC8: 1, 0xC9: 1, 0xCA: 1, 0xCB: 1, 0xCC: 1, 0xCD: 1, 0xCE: 1, 0xCF: 1,
    0xD0: 2, 0xD1: 2, 0xD2: 2, 0xD3: 2, 0xD4: 2, 0xD5: 2, 0xD6: 2, 0xD7: 2,
    0xD8: 2, 0xD9: 2, 0xDA: 2, 0xDB: 2, 0xDC: 2, 0xDD: 2, 0xDE: 2, 0xDF: 2,
    0xE0: 2, 0xE1: 2, 0xE2: 2,
    0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2,
}

_RETROFIT = "Lretrofit2/http/"
_HTTP_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")


@dataclass
class MethodXRef:
    """Represents a Dalvik method's string references and inferred HTTP verb."""

    class_name: str
    method_name: str
    dex_source: str
    strings: List[str] = field(default_factory=list)
    invoked_methods: List[str] = field(default_factory=list)
    inferred_http_method: Optional[str] = None
    inference_evidence: str = ""
    retrofit: bool = False  # declared by a Retrofit annotation, not inferred
    params: List[Dict[str, str]] = field(default_factory=list)


def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
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


def _dalvik_descriptor_to_dot(desc: str) -> str:
    """Convert `Lcom/example/Foo;` -> `com.example.Foo`."""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def _infer_http_method_from_calls(
    strings_in_method: List[str],
    invoked_sigs: List[str],
) -> Tuple[Optional[str], str]:
    """Infer HTTP verb strictly from concrete networking calls in the same method."""
    found_verbs: Set[str] = set()
    evidences: List[str] = []

    for sig in invoked_sigs:
        sig_lower = sig.lower()
        # 1. OkHttp Request$Builder.get() / post() / put() / delete() / patch() / head()
        if "request$builder;->" in sig_lower:
            m_name = sig.split("->")[-1].upper()
            if m_name in _HTTP_VERBS:
                found_verbs.add(m_name)
                evidences.append(f"OkHttp {sig}")
            elif m_name == "METHOD":
                for s in strings_in_method:
                    su = s.strip().upper()
                    if su in _HTTP_VERBS:
                        found_verbs.add(su)
                        evidences.append(f"OkHttp Request$Builder.method('{su}')")

        # 2. Apache HttpClient classes (HttpGet, HttpPost, HttpPut, HttpDelete, HttpPatch)
        for verb in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            target = f"http{verb.lower()};-><init>"
            if target in sig_lower:
                found_verbs.add(verb)
                evidences.append(f"Apache {sig}")

        # 3. HttpURLConnection.setRequestMethod("POST")
        if "httpurlconnection;->setrequestmethod" in sig_lower:
            for s in strings_in_method:
                su = s.strip().upper()
                if su in _HTTP_VERBS:
                    found_verbs.add(su)
                    evidences.append(f"HttpURLConnection.setRequestMethod('{su}')")

    # Only return an inferred verb if it is unambiguous (exactly 1 verb found)
    if len(found_verbs) == 1:
        return next(iter(found_verbs)), "; ".join(evidences[:2])
    return None, ""


def _parse_dex_strings_table(data: bytes) -> List[str]:
    """Extract ordered string table from DEX bytes."""
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return []
    str_size, str_off = struct.unpack_from("<II", data, 0x38)
    strings: List[str] = []
    for i in range(str_size):
        off_pos = str_off + i * 4
        if off_pos + 4 > len(data):
            break
        (s_off,) = struct.unpack_from("<I", data, off_pos)
        if s_off >= len(data):
            strings.append("")
            continue
        length, cur = _read_uleb128(data, s_off)
        end = data.find(b"\x00", cur, min(len(data), cur + length * 3 + 4))
        if end == -1:
            end = min(len(data), cur + length)
        strings.append(data[cur:end].decode("utf-8", errors="replace"))
    return strings


class _Annotations:
    """Reads the two DEX annotation shapes Retrofit needs: method and parameter sets."""

    def __init__(self, data: bytes, strings: List[str], get_type: Callable[[int], str]) -> None:
        self.data, self.strings, self.get_type = data, strings, get_type

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _value(self, pos: int, depth: int = 0) -> Tuple[Any, int]:
        if depth > 8:
            raise ValueError("annotation nesting too deep")
        head = self.data[pos]
        pos += 1
        vtype, arg = head & 0x1F, head >> 5
        if vtype in (0x1E, 0x1F):  # null / boolean carry no payload
            return (bool(arg) if vtype == 0x1F else None), pos
        if vtype == 0x1C:  # array
            size, pos = _read_uleb128(self.data, pos)
            items = []
            for _ in range(min(size, 256)):
                v, pos = self._value(pos, depth + 1)
                items.append(v)
            return items, pos
        if vtype == 0x1D:  # nested annotation
            _, values, pos = self._encoded(pos, depth + 1)
            return values, pos
        raw = self.data[pos : pos + arg + 1]
        pos += arg + 1
        if vtype == 0x17:  # string
            idx = int.from_bytes(raw, "little")
            return (self.strings[idx] if idx < len(self.strings) else ""), pos
        return None, pos

    def _encoded(self, pos: int, depth: int = 0) -> Tuple[str, Dict[str, Any], int]:
        type_idx, pos = _read_uleb128(self.data, pos)
        size, pos = _read_uleb128(self.data, pos)
        values: Dict[str, Any] = {}
        for _ in range(min(size, 64)):
            name_idx, pos = _read_uleb128(self.data, pos)
            val, pos = self._value(pos, depth)
            if name_idx < len(self.strings):
                values[self.strings[name_idx]] = val
        return self.get_type(type_idx), values, pos

    def read_set(self, off: int) -> List[Tuple[str, Dict[str, Any]]]:
        if not off:
            return []
        out = []
        for i in range(min(self._u32(off), 64)):
            item = self._u32(off + 4 + i * 4)
            desc, values, _ = self._encoded(item + 1)  # skip the visibility byte
            out.append((desc, values))
        return out

    def class_methods(self, directory: int) -> Iterator[Tuple[int, int, int]]:
        """Yield (method_idx, annotation_set_off, parameter_ref_list_off)."""
        _, fields, methods, params = struct.unpack_from("<IIII", self.data, directory)
        pos = directory + 16 + fields * 8
        param_offs = dict(
            struct.unpack_from("<II", self.data, pos + methods * 8 + i * 8) for i in range(min(params, 65536))
        )
        for i in range(min(methods, 65536)):
            idx, off = struct.unpack_from("<II", self.data, pos + i * 8)
            yield idx, off, param_offs.get(idx, 0)

    def read_param_sets(self, off: int) -> List[Tuple[str, Dict[str, Any]]]:
        if not off:
            return []
        out = []
        for i in range(min(self._u32(off), 256)):
            out.extend(self.read_set(self._u32(off + 4 + i * 4)))
        return out


def _retrofit_methods(
    ann: _Annotations, directory: int, class_dot: str, method_name: Callable[[int], str], dex_source: str
) -> Iterator[MethodXRef]:
    """Yield a confirmed endpoint for each Retrofit-annotated interface method."""
    for m_idx, set_off, param_off in ann.class_methods(directory):
        verb, path = None, ""
        for desc, values in ann.read_set(set_off):
            if not desc.startswith(_RETROFIT):
                continue
            name = desc[len(_RETROFIT) : -1]
            if name in _HTTP_VERBS:
                verb, path = name, values.get("value") or ""
            elif name == "HTTP":
                verb, path = str(values.get("method") or "").upper() or None, values.get("path") or ""
        if not verb or not isinstance(path, str):
            continue
        params = []
        for desc, values in ann.read_param_sets(param_off):
            kind, val = desc[len(_RETROFIT) : -1], values.get("value")
            if desc.startswith(_RETROFIT) and isinstance(val, str) and val:
                params.append({"name": val, "type": kind.lower()})
        yield MethodXRef(
            class_name=class_dot,
            method_name=method_name(m_idx),
            dex_source=dex_source,
            strings=[path],
            inferred_http_method=verb,
            inference_evidence=f'Retrofit @{verb}("{path}")',
            retrofit=True,
            params=params,
        )


def analyze_dex_xrefs(dex_bytes: bytes, dex_source: str = "classes.dex") -> List[MethodXRef]:
    """Parse DEX class_defs & code_items to extract method-level string & call cross-references."""
    if len(dex_bytes) < 0x70 or dex_bytes[:4] != b"dex\n":
        return []

    strings = _parse_dex_strings_table(dex_bytes)
    if not strings:
        return []

    type_size, type_off = struct.unpack_from("<II", dex_bytes, 0x40)
    meth_size, meth_off = struct.unpack_from("<II", dex_bytes, 0x58)
    cls_size, cls_off = struct.unpack_from("<II", dex_bytes, 0x60)

    def _get_type(idx: int) -> str:
        if idx < 0 or idx >= type_size or type_off + idx * 4 + 4 > len(dex_bytes):
            return ""
        (s_idx,) = struct.unpack_from("<I", dex_bytes, type_off + idx * 4)
        return strings[s_idx] if 0 <= s_idx < len(strings) else ""

    def _get_method_sig(idx: int) -> Tuple[str, str]:
        if idx < 0 or idx >= meth_size or meth_off + idx * 8 + 8 > len(dex_bytes):
            return "", ""
        c_idx, _p_idx, name_idx = struct.unpack_from("<HHI", dex_bytes, meth_off + idx * 8)
        c_desc = _get_type(c_idx)
        m_name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
        return c_desc, m_name

    results: List[MethodXRef] = []
    uses_retrofit = any(s.startswith(_RETROFIT) for s in strings)
    annotations = _Annotations(dex_bytes, strings, _get_type)

    for i in range(cls_size):
        c_pos = cls_off + i * 32
        if c_pos + 32 > len(dex_bytes):
            break
        class_idx, _acc, _sup, _ifaces, _src, ann_off, class_data_off, _sval = struct.unpack_from("<IIIIIIII", dex_bytes, c_pos)
        class_dot = _dalvik_descriptor_to_dot(_get_type(class_idx))

        # Skip standard Android/Java framework packages to keep cross-ref fast and focused
        if class_dot.startswith(("android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.")):
            continue

        if ann_off and uses_retrofit:
            try:
                results.extend(
                    _retrofit_methods(annotations, ann_off, class_dot, lambda m: _get_method_sig(m)[1], dex_source)
                )
            except (struct.error, IndexError, ValueError) as exc:
                logger.debug("Bad annotations on %s: %s", class_dot, exc)

        if class_data_off == 0 or class_data_off >= len(dex_bytes):
            continue

        pos = class_data_off
        sf_cnt, pos = _read_uleb128(dex_bytes, pos)
        if_cnt, pos = _read_uleb128(dex_bytes, pos)
        dm_cnt, pos = _read_uleb128(dex_bytes, pos)
        vm_cnt, pos = _read_uleb128(dex_bytes, pos)

        # Skip fields
        for _ in range(sf_cnt + if_cnt):
            if pos >= len(dex_bytes):  # hostile counts
                break
            _, pos = _read_uleb128(dex_bytes, pos)
            _, pos = _read_uleb128(dex_bytes, pos)

        # Parse direct & virtual methods
        for count in (dm_cnt, vm_cnt):
            m_idx = 0
            for _ in range(count):
                if pos >= len(dex_bytes):
                    break
                diff, pos = _read_uleb128(dex_bytes, pos)
                _m_acc, pos = _read_uleb128(dex_bytes, pos)
                code_off, pos = _read_uleb128(dex_bytes, pos)
                m_idx += diff
                if code_off == 0 or code_off + 16 > len(dex_bytes):
                    continue

                _, m_name = _get_method_sig(m_idx)
                (insns_size,) = struct.unpack_from("<I", dex_bytes, code_off + 12)
                insns_start = code_off + 16
                insns_end = insns_start + insns_size * 2
                if insns_size == 0 or insns_end > len(dex_bytes):
                    continue

                # Walk Dalvik instructions in code units
                m_strings: List[str] = []
                m_invokes: List[str] = []
                cu = 0
                while cu < insns_size:
                    byte_pos = insns_start + cu * 2
                    opcode = dex_bytes[byte_pos]
                    # Handle payload pseudo-opcodes (packed-switch, sparse-switch, fill-array-data)
                    if opcode == 0x00 and byte_pos + 1 < insns_end:
                        ident = dex_bytes[byte_pos + 1]
                        if ident == 0x01 and byte_pos + 4 <= insns_end:  # packed-switch-payload
                            (sz,) = struct.unpack_from("<H", dex_bytes, byte_pos + 2)
                            cu += sz * 2 + 4
                            continue
                        elif ident == 0x02 and byte_pos + 4 <= insns_end:  # sparse-switch-payload
                            (sz,) = struct.unpack_from("<H", dex_bytes, byte_pos + 2)
                            cu += sz * 4 + 2
                            continue
                        elif ident == 0x03 and byte_pos + 8 <= insns_end:  # fill-array-data-payload
                            ew, sz = struct.unpack_from("<HI", dex_bytes, byte_pos + 2)
                            cu += (sz * ew + 1) // 2 + 4
                            continue

                    width = _INSN_WIDTH.get(opcode, 1)
                    if opcode == 0x1A and cu + 1 < insns_size:  # const-string
                        (s_idx,) = struct.unpack_from("<H", dex_bytes, byte_pos + 2)
                        if 0 <= s_idx < len(strings):
                            m_strings.append(strings[s_idx])
                    elif opcode == 0x1B and cu + 2 < insns_size:  # const-string/jumbo
                        (s_idx,) = struct.unpack_from("<I", dex_bytes, byte_pos + 2)
                        if 0 <= s_idx < len(strings):
                            m_strings.append(strings[s_idx])
                    elif opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78) and cu + 1 < insns_size:
                        (called_idx,) = struct.unpack_from("<H", dex_bytes, byte_pos + 2)
                        c_d, c_m = _get_method_sig(called_idx)
                        if c_d and c_m:
                            m_invokes.append(f"{c_d}->{c_m}")

                    cu += width

                # Only record methods that contain URL/path-like string constants
                relevant_strings = [
                    s for s in m_strings
                    if s.startswith(("http://", "https://", "/")) or "/api" in s.lower() or RE_BARE_API_PATH.fullmatch(s)
                ]
                if relevant_strings:
                    verb, ev = _infer_http_method_from_calls(m_strings, m_invokes)
                    results.append(
                        MethodXRef(
                            class_name=class_dot,
                            method_name=m_name,
                            dex_source=dex_source,
                            strings=relevant_strings,
                            invoked_methods=m_invokes,
                            inferred_http_method=verb,
                            inference_evidence=ev,
                        )
                    )

    return results


def extract_apk_xrefs(apk_paths: Iterable[Path]) -> List[MethodXRef]:
    """Extract Dalvik method cross-references across one or more APKs."""
    all_xrefs: List[MethodXRef] = []
    for apk_path in apk_paths:
        if not apk_path.exists() or not apk_path.is_file():
            continue
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.startswith("classes") and name.endswith(".dex"):
                        dex_data = read_member(zf, name)
                        src_label = f"{apk_path.name}:{name}"
                        try:
                            all_xrefs.extend(analyze_dex_xrefs(dex_data, dex_source=src_label))
                        except (struct.error, IndexError) as exc:
                            logger.warning("Malformed DEX %s: %s", src_label, exc)
        except Exception as exc:
            logger.warning("Failed DEX xref analysis on %s: %s", apk_path, exc)
    return all_xrefs
