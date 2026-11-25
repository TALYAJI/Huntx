"""Bounded, hostile-input-aware ZIP member access.

APKs are attacker-controlled: never inflate a member without checking its
declared size first (``zipfile`` never yields more than the declared size).
"""
from __future__ import annotations

import zipfile

MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_APK_MEMBER_BYTES = 4 * 1024 * 1024 * 1024


class UnsafeArchiveError(ValueError):
    """Raised when an archive member exceeds the allowed size."""


def check_member(zf: zipfile.ZipFile, name: str, limit: int = MAX_MEMBER_BYTES) -> None:
    size = zf.getinfo(name).file_size
    if size > limit:
        raise UnsafeArchiveError(f"{name!r} expands to {size} bytes (limit {limit})")


def read_member(zf: zipfile.ZipFile, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
    """Read *name* from *zf*, refusing members larger than *limit*."""
    check_member(zf, name, limit)
    return zf.read(name)


def is_apk(path) -> bool:
    """True if *path* is a readable ZIP holding an Android manifest."""
    try:
        with zipfile.ZipFile(path) as zf:
            return "AndroidManifest.xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
