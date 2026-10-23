import pytest

from cui_guard.policy import loader


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Point config and state at tmp dirs and make sure no org policy is read."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(loader, "org_policy_path", lambda: tmp_path / "no-org-policy.toml")
    return tmp_path
