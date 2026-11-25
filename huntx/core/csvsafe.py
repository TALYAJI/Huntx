"""Neutralise spreadsheet formulas in CSV cells built from untrusted APK data."""
from __future__ import annotations

from typing import Any, Iterable, List


def safe_row(row: Iterable[Any]) -> List[Any]:
    """Prefix cells a spreadsheet would execute (``=``, ``+``, ``-``, ``@``, tab, CR)."""
    return ["'" + c if isinstance(c, str) and c.startswith(("=", "+", "-", "@", "\t", "\r")) else c for c in row]
