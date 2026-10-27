"""Make the leak-suite fixtures (`upstream`, `gateways`) available to the red-team suite."""

import importlib.util
import sys
from pathlib import Path

import pytest

_LEAK = Path(__file__).resolve().parents[1] / "leak"
sys.path.insert(0, str(_LEAK))  # the leak conftest imports `harness` by plain name

# Load by path under a unique name: other test dirs also have a plain `conftest` module.
_spec = importlib.util.spec_from_file_location("leak_conftest", _LEAK / "conftest.py")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["leak_conftest"] = _mod
_spec.loader.exec_module(_mod)

upstream = _mod.upstream
gateways = _mod.gateways
_reset_upstream = _mod._reset_upstream

from canaries import FORMATS


@pytest.fixture(params=FORMATS)
def fmt(request):
    return request.param
