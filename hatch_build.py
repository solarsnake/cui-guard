"""Hatch build hook: embed the SBOM in the wheel when one has been generated.

Release builds run `scripts/security/sbom.py build` first, so release wheels carry
`.dist-info/sboms/cui-guard.cdx.json`. A plain `pip install .` or `uv build` from a fresh
clone has no SBOM and still builds.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

SBOM = "build/sbom/cui-guard.cdx.json"


class SbomHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        if (Path(self.root) / SBOM).is_file():
            build_data["sbom_files"].append(SBOM)
