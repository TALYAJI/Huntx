"""Keep every test away from the developer's real targets and config."""
import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    from huntx.core import config

    home = tmp_path_factory.mktemp("home")
    (home / "targets").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(config, "DEFAULT_TARGET_BASE", home / "targets")
