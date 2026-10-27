"""Property-based fuzzing. Profiles are chosen with HYPOTHESIS_PROFILE (default: ci)."""

from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile("ci", max_examples=200, deadline=None)
settings.register_profile("nightly", max_examples=20000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
