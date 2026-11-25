"""APK signature discovery: JAR (v1) and APK Signing Block (v2 / v3 / v3.1).

Reports which schemes are *present* and the real X.509 signer certificates.
It does not cryptographically verify the signatures.
"""
from __future__ import annotations

import hashlib
import logging
import re
import struct
import warnings
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from huntx.core.safezip import read_member

logger = logging.getLogger(__name__)

_MAGIC = b"APK Sig Block 42"
_V2_ID, _V3_IDS = 0x7109871A, (0xF05368C0, 0x1B93AD61)
_MAX_BLOCK = 64 * 1024 * 1024


def read_signing_block(path: Path) -> Dict[int, bytes]:
    """Return the ID -> value pairs of the APK Signing Block (empty when absent)."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        tail_len = min(size, 65557)  # EOCD + maximum ZIP comment
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd < 0 or eocd + 20 > len(tail):
            return {}
        cd_offset = struct.unpack_from("<I", tail, eocd + 16)[0]
        if cd_offset < 32 or cd_offset > size:
            return {}
        fh.seek(cd_offset - 24)
        footer = fh.read(24)
        if footer[8:] != _MAGIC:
            return {}
        block_size = struct.unpack_from("<Q", footer)[0]
        if not 24 <= block_size <= min(_MAX_BLOCK, cd_offset - 8):
            return {}
        fh.seek(cd_offset - block_size)
        body = fh.read(block_size - 24)

    pairs: Dict[int, bytes] = {}
    pos = 0
    while pos + 12 <= len(body):
        length, pair_id = struct.unpack_from("<QI", body, pos)
        if length < 4 or pos + 8 + length > len(body):
            break
        pairs[pair_id] = body[pos + 12 : pos + 8 + length]
        pos += 8 + length
    return pairs


def _prefixed(data: bytes) -> Iterator[bytes]:
    """Iterate uint32-length-prefixed items."""
    pos = 0
    while pos + 4 <= len(data):
        n = struct.unpack_from("<I", data, pos)[0]
        if pos + 4 + n > len(data):
            return
        yield data[pos + 4 : pos + 4 + n]
        pos += 4 + n


def _block_certs(value: bytes) -> List[bytes]:
    """signers -> signer -> signed data -> [digests, certificates, ...]."""
    certs: List[bytes] = []
    for signers in _prefixed(value):
        for signer in _prefixed(signers):
            signed_data = next(_prefixed(signer), b"")
            parts = list(_prefixed(signed_data))
            if len(parts) >= 2:
                certs.extend(_prefixed(parts[1]))
    return certs


def _describe(cert: x509.Certificate) -> Dict[str, Any]:
    der = cert.public_bytes(Encoding.DER)

    def fp(algo: str) -> str:
        return hashlib.new(algo, der, usedforsecurity=False).digest().hex(":").upper()

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": f"{cert.serial_number:x}",
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": fp("sha256"),
        "sha1_fingerprint": fp("sha1"),
        "md5_fingerprint": fp("md5"),
    }


def inspect_signing(zf: zipfile.ZipFile, path: Path) -> Dict[str, Any]:
    """Return scheme flags and the distinct signer certificates of an APK."""
    blocks: Dict[int, bytes] = {}
    try:
        blocks = read_signing_block(path)
    except (OSError, struct.error) as exc:
        logger.debug("Signing block unreadable in %s: %s", path, exc)

    sig_files = [n for n in zf.namelist() if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", n, re.I)]
    found: Dict[str, Dict[str, Any]] = {}

    def add(load) -> None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # old signers trip RFC strictness warnings
                for cert in load():
                    info = _describe(cert)
                    found.setdefault(info["sha256_fingerprint"], info)
        except Exception as exc:  # cryptography raises many types on hostile DER
            logger.warning("Unparseable signer certificate in %s: %s", path.name, exc)

    for block_id in (*reversed(_V3_IDS), _V2_ID):
        for der in _block_certs(blocks.get(block_id, b"")):
            add(lambda der=der: [x509.load_der_x509_certificate(der)])
    for name in sig_files:
        add(lambda name=name: pkcs7.load_der_pkcs7_certificates(read_member(zf, name)))

    return {
        "v1_signed": bool(sig_files),
        "v2_signed": _V2_ID in blocks,
        "v3_signed": any(i in blocks for i in _V3_IDS),
        "certificates": list(found.values()),
    }
