"""HUNTX Phase 1 test suite.

All tests use ``tmp_path`` and never write to the real filesystem.
No external packages (androguard, rich, etc.) are required to run these tests.
"""
from __future__ import annotations

import hashlib
import sys
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure HUNTX package is importable when running from the HUNTX root dir.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))


# ===========================================================================
# Config
# ===========================================================================


def test_config_defaults() -> None:
    """HuntxConfig has correct defaults and HUNTX_VERSION is defined."""
    from huntx.core.config import HUNTX_VERSION, HuntxConfig, load_config, DEFAULT_TARGET_BASE

    assert re.fullmatch(r"\d+\.\d+\.\d+", HUNTX_VERSION)

    cfg = HuntxConfig()
    assert cfg.target_base == DEFAULT_TARGET_BASE
    assert cfg.log_level == "DEBUG"

    # load_config() should return a HuntxConfig instance
    result = load_config()
    assert isinstance(result, HuntxConfig)


# ===========================================================================
# TargetManager
# ===========================================================================


def test_target_manager_list_empty(tmp_path: Path) -> None:
    """list_targets() returns [] on an empty directory."""
    from huntx.core.target_manager import TargetManager

    tm = TargetManager(tmp_path)
    assert tm.list_targets() == []


def test_target_manager_create(tmp_path: Path) -> None:
    """create_target() creates the directory and target-info.txt."""
    from huntx.core.target_manager import TargetManager

    tm = TargetManager(tmp_path)
    target_path = tm.create_target("my-target")

    assert target_path.is_dir()
    info_file = target_path / "target-info.txt"
    assert info_file.exists()
    content = info_file.read_text(encoding="utf-8")
    assert "HUNTX Target Information" in content
    assert "my-target" in content


def test_target_manager_find_apks(tmp_path: Path) -> None:
    """find_apks() locates .apk files recursively."""
    from huntx.core.target_manager import TargetManager

    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "app.apk").write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    (sub / "debug.apk").write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    (tmp_path / "readme.txt").write_text("not an apk")

    tm = TargetManager(tmp_path)
    apks = tm.find_apks(tmp_path)
    names = {a.filename for a in apks}
    assert "app.apk" in names
    assert "debug.apk" in names
    assert "readme.txt" not in names
    assert len(apks) == 2


def test_target_manager_ignores_hidden(tmp_path: Path) -> None:
    """list_targets() does not include directories starting with '.'."""
    from huntx.core.target_manager import TargetManager

    (tmp_path / "visible-target").mkdir()
    (tmp_path / ".hidden-target").mkdir()

    tm = TargetManager(tmp_path)
    targets = tm.list_targets()
    assert "visible-target" in targets
    assert ".hidden-target" not in targets


def test_sanitize_name_valid() -> None:
    """sanitize_name() accepts valid names."""
    from huntx.core.target_manager import TargetManager

    assert TargetManager.sanitize_name("my-target") == "my-target"
    assert TargetManager.sanitize_name("MyTarget_1") == "MyTarget_1"


def test_sanitize_name_invalid() -> None:
    """sanitize_name() raises ValueError on names with spaces or special chars."""
    from huntx.core.target_manager import TargetManager

    with pytest.raises(ValueError):
        TargetManager.sanitize_name("my target!")

    with pytest.raises(ValueError):
        TargetManager.sanitize_name("bad/name")


# ===========================================================================
# Session
# ===========================================================================


def test_session_create(tmp_path: Path) -> None:
    """create_session() creates a RUN_* directory with all 7 standard subdirs."""
    from huntx.core.session import SESSION_SUBDIRS, SessionManager

    sm = SessionManager(tmp_path)
    session = sm.create_session([])

    assert session.run_path.is_dir()
    assert session.run_path.name.startswith("RUN_")
    for subdir in SESSION_SUBDIRS:
        assert (session.run_path / subdir).is_dir(), f"Missing subdir: {subdir}"


def test_session_metadata_roundtrip(tmp_path: Path) -> None:
    """save_metadata() and load_session() produce identical metadata."""
    from huntx.core.session import SessionManager

    sm = SessionManager(tmp_path)
    session = sm.create_session([])

    loaded = sm.load_session(session.metadata.run_dir)
    assert loaded.metadata.session_id == session.metadata.session_id
    assert loaded.metadata.target_name == session.metadata.target_name
    assert loaded.metadata.run_dir == session.metadata.run_dir


def test_sha256_correctness(tmp_path: Path) -> None:
    """compute_sha256() produces the expected hex digest."""
    from huntx.core.session import compute_sha256

    test_file = tmp_path / "test.bin"
    content = b"hello huntx"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert compute_sha256(test_file) == expected


# ===========================================================================
# Database
# ===========================================================================


def test_database_initialize(tmp_path: Path) -> None:
    """initialize() creates all tables without error."""
    from huntx.storage.database import Database

    db_path = tmp_path / "huntx.db"
    with Database(db_path) as db:
        db.initialize()

    assert db_path.exists()


def test_database_insert_and_query(tmp_path: Path) -> None:
    """insert() and query_all() round-trip a domain row."""
    from huntx.storage.database import Database

    db_path = tmp_path / "huntx.db"
    with Database(db_path) as db:
        db.initialize()
        row_id = db.insert(
            "domains",
            {
                "domain": "example.com",
                "source": "test",
                "session_id": "sess-001",
                "first_seen": "2024-01-01T00:00:00Z",
            },
        )
        assert isinstance(row_id, int)
        assert row_id > 0

        rows = db.query_all("domains")
        assert len(rows) == 1
        assert rows[0]["domain"] == "example.com"


def test_database_search(tmp_path: Path) -> None:
    """search_text() finds a matching domain row."""
    from huntx.storage.database import Database

    db_path = tmp_path / "huntx.db"
    with Database(db_path) as db:
        db.initialize()
        db.insert(
            "domains",
            {
                "domain": "api.target.com",
                "source": "test",
                "session_id": "sess-001",
                "first_seen": "2024-01-01T00:00:00Z",
            },
        )
        results = db.search_text("target")

    assert len(results) >= 1
    assert any(r["domain"] == "api.target.com" for r in results)


# ===========================================================================
# DependencyReport
# ===========================================================================


def test_dependency_report_structure() -> None:
    """DependencyReport has all required fields and check_all() populates them."""
    from huntx.core.dependency_checker import DependencyReport, check_all

    report = check_all()
    assert isinstance(report, DependencyReport)
    assert isinstance(report.python_ok, bool)
    assert isinstance(report.missing_required, list)
    assert isinstance(report.missing_optional, list)
    assert isinstance(report.available_optional, list)
    assert isinstance(report.install_commands, list)

    # Python 3.9+ should be true in the test environment
    assert report.python_ok is True


# ===========================================================================
# LogContext
# ===========================================================================


def test_logcontext(tmp_path: Path) -> None:
    """LogContext.start(), end(), and fail() do not raise exceptions."""
    import logging

    from huntx.core.logger import LogContext, setup_logger

    log_path = tmp_path / "logs" / "huntx.log"
    setup_logger(log_path, log_level=logging.DEBUG)

    ctx = LogContext()
    ctx.start("test-operation")
    ctx.end("test-operation", success=True)
    ctx.end("test-operation", success=False)
    ctx.fail("test-operation", RuntimeError("boom"))


# ===========================================================================
# XAPK Container Support
# ===========================================================================


def test_xapk_auto_discovery_and_unpack(tmp_path: Path) -> None:
    """Verify that TargetManager discovers .xapk and SessionManager unpacks split APKs."""
    import zipfile
    from huntx.core.target_manager import TargetManager
    from huntx.core.session import SessionManager

    target_dir = tmp_path / "my_xapk_app"
    target_dir.mkdir()

    # Create a mock .xapk containing base.apk and config.arm64.apk
    xapk_file = target_dir / "bundle.xapk"
    with zipfile.ZipFile(xapk_file, "w") as zf:
        zf.writestr("base.apk", b"PK\x03\x04" + b"\x00" * 50)
        zf.writestr("config.arm64_v8a.apk", b"PK\x03\x04" + b"\x00" * 50)
        zf.writestr("manifest.json", '{"package_name": "com.test.bundle"}')

    tm = TargetManager(tmp_path)
    found = tm.find_apks(target_dir)
    assert any(f.filename == "bundle.xapk" for f in found)

    sm = SessionManager(target_dir)
    session = sm.create_session([xapk_file])
    ready_apks = sm.copy_input_apks(session)

    # Check that base.apk and config APK were extracted into input/
    input_dir = session.run_path / "input"
    assert (input_dir / "bundle.xapk").exists()
    assert (input_dir / "base.apk").exists()
    assert (input_dir / "config.arm64_v8a.apk").exists()
    assert (input_dir / "manifest.json").exists()

    assert any(p.name == "base.apk" for p in ready_apks)
    assert ready_apks[0].name == "base.apk"  # base.apk prioritized first

