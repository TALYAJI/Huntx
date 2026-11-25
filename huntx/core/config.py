"""HUNTX central configuration module."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from huntx import __version__

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HUNTX_VERSION: str = __version__

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent


def _default_target_base() -> Path:
    """$HUNTX_TARGETS, else <checkout>/Target, else ~/.huntx/targets when pip-installed."""
    env = os.environ.get("HUNTX_TARGETS")
    if env:
        return Path(env).expanduser()
    if (PROJECT_ROOT / "pyproject.toml").exists():
        return PROJECT_ROOT / "Target"
    return Path.home() / ".huntx" / "targets"


DEFAULT_TARGET_BASE: Path = _default_target_base()

SESSION_DIR_FORMAT: str = "RUN_%Y%m%d_%H%M%S"

SESSION_SUBDIRS: list[str] = [
    "input",
    "android",
    "api",
    "traffic",
    "mapping",
    "reports",
    "logs",
]

DB_FILENAME: str = "huntx.db"
LOG_FILENAME: str = "huntx.log"

SUPPORTED_APK_EXTENSIONS: list[str] = [".apk", ".xapk", ".apks"]

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class HuntxConfig:
    """Runtime configuration for HUNTX."""

    target_base: Path = field(default_factory=lambda: DEFAULT_TARGET_BASE)
    log_level: str = "DEBUG"
    filter_sdk_noise: bool = True


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_config() -> HuntxConfig:
    """Load configuration from ~/.huntx/config.json if present.

    Returns a :class:`HuntxConfig` with defaults for any missing keys.
    """
    config_path = Path.home() / ".huntx" / "config.json"
    if not config_path.exists():
        return HuntxConfig()

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data: dict = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return HuntxConfig()

    if not isinstance(data, dict):
        return HuntxConfig()

    target_base_raw = data.get("target_base")
    target_base = Path(target_base_raw).expanduser() if target_base_raw else DEFAULT_TARGET_BASE
    if os.environ.get("HUNTX_TARGETS"):  # environment wins over the config file
        target_base = DEFAULT_TARGET_BASE

    return HuntxConfig(
        target_base=target_base,
        log_level=data.get("log_level", "DEBUG"),
        filter_sdk_noise=bool(data.get("filter_sdk_noise", True)),
    )
