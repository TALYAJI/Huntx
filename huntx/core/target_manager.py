"""HUNTX target directory manager."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from huntx.core.config import SUPPORTED_APK_EXTENSIONS

# Pattern for valid target names
_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class APKFile:
    """Represents a single APK file found on disk.

    Attributes:
        path: Absolute :class:`~pathlib.Path` to the APK.
        filename: Base filename without directory.
        size_bytes: File size in bytes.
        size_human: Human-readable size string, e.g. ``"12.5 MB"``.
    """

    path: Path
    filename: str
    size_bytes: int
    size_human: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_size(num_bytes: int) -> str:
    """Convert *num_bytes* to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0  # type: ignore[assignment]
    return f"{num_bytes:.1f} PB"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class TargetManager:
    """Manages the per-target directory tree under *base_path*.

    Args:
        base_path: Root directory where all target subdirectories live.
    """

    def __init__(self, base_path: Path) -> None:
        self.base_path = base_path

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_targets(self) -> List[str]:
        """Return names of non-hidden subdirectories of :attr:`base_path`.

        Returns:
            Sorted list of target names (directory basenames).
        """
        if not self.base_path.exists():
            return []
        return sorted(
            d.name
            for d in self.base_path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )

    def get_target_path(self, name: str) -> Path:
        """Return the absolute path for target *name*.

        Args:
            name: Target name (not validated here).

        Returns:
            :class:`~pathlib.Path` to the target directory.
        """
        return self.base_path / name

    # ------------------------------------------------------------------
    # Creation / validation
    # ------------------------------------------------------------------

    def create_target(self, name: str, overwrite_info: bool = False) -> Path:
        """Create the target directory and write a ``target-info.txt``.

        Args:
            name: Target name; must pass :meth:`sanitize_name`.
            overwrite_info: If ``True``, overwrite an existing
                ``target-info.txt``; otherwise leave it intact.

        Returns:
            Absolute path to the target directory.

        Raises:
            ValueError: If *name* contains invalid characters.
        """
        self.sanitize_name(name)
        target_path = self.get_target_path(name)
        target_path.mkdir(parents=True, exist_ok=True)

        info_file = target_path / "target-info.txt"
        if not info_file.exists() or overwrite_info:
            now = datetime.now(tz=timezone.utc).isoformat()
            info_file.write_text(
                f"HUNTX Target Information\n"
                f"=========================\n"
                f"Target Name: {name}\n"
                f"Created: {now}\n",
                encoding="utf-8",
            )

        return target_path

    def validate_target(self, name: str) -> bool:
        """Return ``True`` when target *name* exists as a directory.

        Args:
            name: Target name to look up.
        """
        return self.get_target_path(name).is_dir()

    def find_apks(self, target_path: Path) -> List[APKFile]:
        """Recursively find all ``.apk`` files under *target_path*.

        Args:
            target_path: Root directory to search.

        Returns:
            List of :class:`APKFile` objects, sorted by filename.
        """
        results: list[APKFile] = []
        for ext in SUPPORTED_APK_EXTENSIONS:
            for apk_path in sorted(target_path.rglob(f"*{ext}")):
                # Copies inside previous RUN_* sessions are outputs, not inputs.
                if not apk_path.is_file() or any(
                    part.startswith("RUN_") for part in apk_path.relative_to(target_path).parts[:-1]
                ):
                    continue
                size = apk_path.stat().st_size
                results.append(
                    APKFile(
                        path=apk_path,
                        filename=apk_path.name,
                        size_bytes=size,
                        size_human=_human_size(size),
                    )
                )
        return results

    # ------------------------------------------------------------------
    # Name sanitization
    # ------------------------------------------------------------------

    @staticmethod
    def name_from_file(path: Path) -> str:
        """Derive a valid target name from a package filename (``a.b-1.0.apk`` -> ``a_b-1_0``)."""
        return re.sub(r"[^A-Za-z0-9_-]+", "_", path.stem).strip("_").lower() or "target"

    @staticmethod
    def sanitize_name(name: str) -> str:
        """Validate and return *name* if it contains only safe characters.

        Allowed characters: letters (a-z, A-Z), digits (0-9), dashes (``-``),
        and underscores (``_``).

        Args:
            name: Candidate target name.

        Returns:
            *name* unchanged if valid.

        Raises:
            ValueError: If *name* contains any disallowed characters.
        """
        if not _VALID_NAME_RE.match(name):
            raise ValueError(
                f"Invalid target name {name!r}. "
                "Only alphanumeric characters, dashes, and underscores are allowed."
            )
        return name
