"""Tests for HUNTX Redesigned Presentation Layer and CLI Commands."""
from __future__ import annotations

from typer.testing import CliRunner

from huntx.cli.commands import cli_app
from huntx.cli.doctor import run_doctor
from huntx.cli.theme import get_console, make_header_panel, make_metrics_table, make_status_bar

runner = CliRunner()


def test_theme_components():
    """Verify theme elements render without raising exceptions."""
    console = get_console()
    assert console is not None

    header = make_header_panel(target_name="test-target", apk_name="app.apk", session_id="RUN_123")
    assert header is not None

    status = make_status_bar()
    assert status is not None

    metrics = make_metrics_table({
        "total_endpoints": 10,
        "total_domains": 5,
        "exported_components": 3,
        "unprotected_components": 1,
        "dangerous_perms": 2,
        "total_perms": 8,
    })
    assert metrics is not None


def test_doctor_command():
    """Verify huntx doctor executes and returns complete diagnostics."""
    res = run_doctor()
    assert "python_ok" in res
    assert "target_base" in res
    assert "missing_packages" in res

    # CLI Typer execution
    result = runner.invoke(cli_app, ["doctor"])
    assert result.exit_code == 0
    assert "HUNTX ENVIRONMENT & SYSTEM DOCTOR" in result.output


def test_targets_command():
    """Verify huntx targets lists discovered projects."""
    from huntx.core.config import load_config

    (load_config().target_base / "demo").mkdir()
    result = runner.invoke(cli_app, ["targets"])
    assert result.exit_code == 0
    assert "AVAILABLE TARGET WORKSPACES" in result.output
