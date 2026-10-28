"""The crypto inventory (design 8.1) is pinned: new crypto use is a reviewed decision."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
ALLOWED = {("hashlib", "sha256"), ("hmac", "compare_digest"), ("secrets", "token_hex"), ("secrets", "token_urlsafe")}  # fmt: skip
PINNED = {"hashlib", "hmac", "secrets"}
# TLS and OpenSSL internals: only the FIPS module may touch them.
FIPS_ONLY = {"ssl", "_ssl", "_hashlib"}
FIPS_MODULE = SRC / "cui_guard" / "fips.py"


def _violations(path: Path, fips_module: Path = FIPS_MODULE) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    fips_ok = path == fips_module
    aliases: dict[str, str] = {}
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in FIPS_ONLY and not fips_ok:
                    out.append(f"{rel}:{node.lineno}: import {a.name}")
                if top in PINNED:
                    aliases[a.asname or top] = top
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in FIPS_ONLY and not fips_ok:
                out.append(f"{rel}:{node.lineno}: from {node.module} import ...")
            if top in PINNED:
                for a in node.names:
                    if (top, a.name) not in ALLOWED:
                        out.append(f"{rel}:{node.lineno}: from {top} import {a.name}")
    # Every use of a pinned module must be an allowed attribute access; passing the
    # module around (getattr, aliasing) would hide what it is used for.
    allowed_names: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
        ):
            allowed_names.add(id(node.value))
            mod = aliases[node.value.id]
            if (mod, node.attr) not in ALLOWED:
                out.append(f"{rel}:{node.lineno}: {mod}.{node.attr}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in aliases
            and id(node) not in allowed_names
        ):
            out.append(f"{rel}:{node.lineno}: bare use of {aliases[node.id]}")
    return out


def test_crypto_inventory_is_pinned():
    files = sorted(SRC.rglob("*.py"))
    assert FIPS_MODULE in files
    found = [v for f in files for v in _violations(f)]
    assert found == []


def test_inventory_check_catches_new_crypto(tmp_path):
    bad = tmp_path / "src" / "cui_guard" / "x.py"
    bad.parent.mkdir(parents=True)
    bad.write_text(
        "import hashlib\nimport ssl\nimport secrets as s\nfrom hmac import new\n"
        "hashlib.md5()\nf = getattr(hashlib, 'sha1')\ns.randbits(8)\n"
    )
    joined = "\n".join(_violations(bad))
    for needle in ("hashlib.md5", "import ssl", "secrets.randbits", "import new", "bare use of hashlib"):  # fmt: skip
        assert needle in joined, needle
