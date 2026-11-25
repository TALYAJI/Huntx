"""HUNTX session management."""
from __future__ import annotations

import hashlib
import json
import shutil
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from huntx.core.config import (
    DB_FILENAME,
    LOG_FILENAME,
    SESSION_DIR_FORMAT,
    SESSION_SUBDIRS,
    load_config,
)
from huntx.core.logger import get_logger, setup_logger
from huntx.core.safezip import MAX_APK_MEMBER_BYTES, check_member

logger = get_logger("core.session")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SessionMetadata:
    """Serialisable metadata stored alongside every session.

    Attributes:
        session_id: UUID-style unique identifier.
        target_name: Name of the target directory.
        run_dir: Basename of the ``RUN_*`` directory (not full path).
        apk_files: List of dicts with ``filename``, ``size_bytes``, ``sha256``.
        created_at: ISO 8601 creation timestamp.
        completed_ops: Names of operations that have finished in this session.
    """

    session_id: str
    target_name: str
    run_dir: str
    apk_files: List[dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    completed_ops: List[str] = field(default_factory=list)


@dataclass
class Session:
    """Runtime representation of an active HUNTX session.

    Attributes:
        metadata: Serialisable :class:`SessionMetadata`.
        run_path: Absolute path to the ``RUN_*`` directory.
        db_path: Absolute path to the SQLite database file.
        log_path: Absolute path to the session log file.
    """

    metadata: SessionMetadata
    run_path: Path
    db_path: Path
    log_path: Path


# ---------------------------------------------------------------------------
# Standalone utility
# ---------------------------------------------------------------------------


def compute_sha256(path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of the file at *path*.

    Args:
        path: Path to any readable file.

    Returns:
        Lower-case hex string of the SHA-256 digest.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SessionManager:
    """Creates and loads sessions within a target directory.

    Args:
        target_path: Absolute path to the target directory
            (e.g. ``~/tools/TARGET/my-app``).
    """

    def __init__(self, target_path: Path) -> None:
        self.target_path = target_path

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_session(self, apk_paths: List[Path]) -> Session:
        """Create a new ``RUN_*`` session directory with all standard subdirs.

        A fresh :class:`SessionMetadata` is written to ``session.json``.
        APK files are *not* copied here; call :meth:`copy_input_apks` after.

        Args:
            apk_paths: Paths to the APK files selected for this session.

        Returns:
            A fully initialised :class:`Session`.
        """
        now = datetime.now(tz=timezone.utc)
        run_dir_name = now.strftime(SESSION_DIR_FORMAT)
        run_path = self.target_path / run_dir_name
        n = 1
        while run_path.exists():  # two sessions within the same second
            n += 1
            run_dir_name = f"{now.strftime(SESSION_DIR_FORMAT)}_{n}"
            run_path = self.target_path / run_dir_name

        # Create all subdirectories
        for subdir in SESSION_SUBDIRS:
            (run_path / subdir).mkdir(parents=True, exist_ok=True)

        apk_dicts = [
            {
                "filename": p.name,
                "size_bytes": p.stat().st_size if p.exists() else 0,
                "sha256": compute_sha256(p) if p.exists() else "",
            }
            for p in apk_paths
        ]

        metadata = SessionMetadata(
            session_id=str(uuid.uuid4()),
            target_name=self.target_path.name,
            run_dir=run_dir_name,
            apk_files=apk_dicts,
            created_at=now.isoformat(),
        )

        db_path = run_path / DB_FILENAME
        log_path = run_path / "logs" / LOG_FILENAME

        session = Session(
            metadata=metadata,
            run_path=run_path,
            db_path=db_path,
            log_path=log_path,
        )
        self.save_metadata(session)
        self._start_logging(session)
        return session

    @staticmethod
    def _start_logging(session: Session) -> None:
        setup_logger(session.log_path, load_config().log_level)

    # ------------------------------------------------------------------
    # Listing / loading
    # ------------------------------------------------------------------

    def list_sessions(self) -> List[SessionMetadata]:
        """Return metadata for all existing ``RUN_*`` directories, newest first.

        Returns:
            List of :class:`SessionMetadata`, or empty list if none found.
        """
        sessions: list[SessionMetadata] = []
        if not self.target_path.exists():
            return sessions

        for run_dir in sorted(self.target_path.glob("RUN_*"), reverse=True):
            if not run_dir.is_dir():
                continue
            meta_file = run_dir / "session.json"
            if meta_file.exists():
                try:
                    data = json.loads(meta_file.read_text(encoding="utf-8"))
                    sessions.append(SessionMetadata(**data))
                except (OSError, json.JSONDecodeError, TypeError, KeyError) as exc:
                    logger.warning("Skipping unreadable session %s: %s", run_dir, exc)
        return sessions

    def load_session(self, run_dir_name: str) -> Session:
        """Load an existing session from disk.

        Args:
            run_dir_name: Basename of the ``RUN_*`` directory.

        Returns:
            Reconstructed :class:`Session`.

        Raises:
            FileNotFoundError: If the directory or ``session.json`` is missing.
        """
        run_path = self.target_path / run_dir_name
        meta_file = run_path / "session.json"

        if not meta_file.exists():
            raise FileNotFoundError(f"session.json not found in {run_path}")

        data = json.loads(meta_file.read_text(encoding="utf-8"))
        metadata = SessionMetadata(**data)

        session = Session(
            metadata=metadata,
            run_path=run_path,
            db_path=run_path / DB_FILENAME,
            log_path=run_path / "logs" / LOG_FILENAME,
        )
        self._start_logging(session)
        return session

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save_metadata(self, session: Session) -> None:
        """Write ``session.json`` into the session's run directory.

        Args:
            session: The session whose metadata should be persisted.
        """
        meta_file = session.run_path / "session.json"
        meta_file.write_text(
            json.dumps(asdict(session.metadata), indent=2),
            encoding="utf-8",
        )

    def copy_input_apks(self, session: Session, sources: Optional[List[Path]] = None) -> List[Path]:
        """Copy and prepare APK files in ``session/input/``.

        If an input file is an ``.xapk`` or ``.apks`` bundle, it is automatically
        and safely unpacked into ``session/input/`` so that all constituent split
        APKs (e.g. ``base.apk``) are extracted and ready for automated inspection.

        Original files are never modified.

        Args:
            session: Active :class:`Session` whose input files should be copied.
            sources: Exact files to copy. When omitted they are looked up by
                name under the target directory.

        Returns:
            List of concrete :class:`Path` objects for inspectable ``.apk`` files.
        """
        input_dir = session.run_path / "input"
        input_dir.mkdir(parents=True, exist_ok=True)
        ready_apks: list[Path] = []

        if sources is None:
            sources = []
            for apk_info in session.metadata.apk_files:
                candidates = [
                    c for c in sorted(self.target_path.rglob(apk_info["filename"]))
                    if not any(p.startswith("RUN_") for p in c.relative_to(self.target_path).parts[:-1])
                ]
                sources.extend(candidates[:1])

        for src in sources:
            dst = input_dir / src.name

            if not dst.exists():
                shutil.copy2(src, dst)

            # Native XAPK / APKS Automatic Container Handling
            ext = src.suffix.lower()
            if ext in (".xapk", ".apks"):
                extracted_splits = unpack_xapk(dst, input_dir)
                ready_apks.extend(extracted_splits)
            elif ext == ".apk":
                ready_apks.append(dst)

        # One file is self-ordered by unpack_xapk; several are sorted base-first.
        return ready_apks if len(sources) == 1 else sort_apks(ready_apks)


def unpack_xapk(archive_path: Path, destination_dir: Path) -> List[Path]:
    """Safely unpack an XAPK/APKS container into target directory.

    Extracts all embedded ``*.apk`` files (like ``base.apk`` and split APKs)
    as well as ``manifest.json`` and OBB files.

    Args:
        archive_path: Path to the .xapk or .apks file.
        destination_dir: Directory where components should be extracted.

    Returns:
        List of paths to extracted ``.apk`` files, with ``base.apk`` first if present.
    """
    extracted_apks: list[Path] = []
    if not archive_path.exists():
        return extracted_apks

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for item in zf.infolist():
                name = item.filename
                # Prevent zip slip path traversal
                if ".." in name or name.startswith("/") or name.startswith("\\"):
                    continue

                if name.lower().endswith(".apk"):
                    target_file = destination_dir / Path(name).name
                    if not target_file.exists():
                        check_member(zf, name, MAX_APK_MEMBER_BYTES)
                        with zf.open(item) as src_f, open(target_file, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f)
                    extracted_apks.append(target_file)
                elif name.lower() in ("manifest.json", "icon.png"):
                    target_file = destination_dir / name
                    if not target_file.exists():
                        with zf.open(item) as src_f, open(target_file, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f)

    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        logger.error("Could not unpack %s: %s", archive_path, exc)

    # Detect package name from manifest.json if present
    pkg_name = ""
    manifest_path = destination_dir / "manifest.json"
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                pkg_name = str(json.load(f).get("package_name", ""))
        except (OSError, ValueError, AttributeError) as exc:
            logger.debug("Ignoring bad bundle manifest %s: %s", manifest_path, exc)

    return sort_apks(extracted_apks, pkg_name)


def sort_apks(apks: List[Path], pkg_name: str = "") -> List[Path]:
    """Order APKs so the base / primary code APK comes first and config splits last."""
    def _key(p: Path) -> Any:
        nl = p.name.lower()
        sz = p.stat().st_size if p.exists() else 0
        if nl.startswith(("config.", "split_")):
            return (2, -sz)
        if "base" in nl or (pkg_name and pkg_name.lower() in nl):
            return (0, -sz)
        return (1, -sz)

    return sorted(apks, key=_key)

