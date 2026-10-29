"""ReDoS regression: every built-in detector stays linear on adversarial input.

CPython's `re` holds the GIL for a whole match, so one super-linear rule
freezes the gateway's event loop; the pipeline timeout cannot fire. Each
target runs over hostile fillers at n and 2n characters (n about 20k) and
the growth ratio time(2n) / time(n), median of 3, must stay below 3.

Below NOISE_FLOOR (20 ms) the ratio only measures timer noise, so a cheap
target is re-tried at 4n characters until its 2n run clears the floor; only a
target still under the floor at 160k characters is accepted unmeasured (a
quadratic rule cannot stay that fast at that size).
"""

from __future__ import annotations

import functools
import statistics
import time

import pytest

from cui_guard.detect.heuristics import controlled_content_hits
from cui_guard.detect.identifiers import IdentifierConfig, identifier_hits
from cui_guard.detect.rules import load_builtin_rules

# Timing-based: runs in the single `perf` job, not on the shared CI matrix.
pytestmark = pytest.mark.perf

N = 20_000
MAX_RATIO = 3.0
NOISE_FLOOR = 0.020

RULES = load_builtin_rules()
CFG = IdentifierConfig(
    domains=("example.mil", "corp.example"),
    ip_ranges=("10.0.0.0/8",),
    codenames=("Blue Falcon",),
    jira_projects=("PROJ",),
    people=("Jane Q Example",),
)

# Markers that start a rule's match; each is followed by a long run that the
# rule's repeated class accepts and then a character that makes it fail.
MARKERS = (
    "CUI//",
    "CONTROLLED//",
    "CUI//SP-",
    "CUI//SP-A//A",
    "(CUI//",
    "SECRET//",
    "TOP SECRET//",
    "(S//",
    "(TS//",
    "REL TO ",
    "//REL TO ",
    "DISPLAY ONLY ",
    "Reason:",
    "Declassify On:",
    "WARNING",
    "password",
    "token=",
    "x://a:",
    "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5,
    "Plugin ID",
    "CVE-2099-12345 ",
    "PORT STATE SERVICE",
    "iptables ",
)
# The markers the identifier and heuristic scans start at (the rule markers are scanned by them
# too, through the plain runs and repeated units).
SCAN_MARKERS = (
    "Plugin ID",
    "CVE-2099-12345 ",
    "PORT STATE SERVICE",
    "iptables ",
    "a@",
    "Blue ",
)
RUNS = (
    " ",
    "\t",
    "\n",
    "A",
    "a",
    "0",
    "-",
    "/",
    ".",
    ",",
    "_",
    "A ",
    "A-",
    "a.",
    "/SP-A",
)
UNITS = (
    "\n",
    " \n",
    "\r\n",
    "A-",
    "a_",
    "a.",
    "a:",
    "a@",
    "@[",
    "x://",
    "x://a:",
    "a:b@",
    "//",
    "CUI//",
    "CUI// \n",
    "sk-",
    "eyJa.",
    "REL TO ",
    "password_",
    "-" * 5 + "BEGIN A PRIVATE KEY" + "-" * 5 + "\n",
    "10.0.0.",
    "1.",
    "a.example.mil.",
    "V-12345 ",
    "CVE-2099-12345\n",
    "iptables 10.0.0.1\n",
    "Blue ",
)


def _fill(unit: str, n: int) -> str:
    return unit * max(1, n // len(unit))


def _builders(markers):
    out = []
    for unit in UNITS:
        out.append((f"repeat:{unit!r}", lambda n, u=unit: _fill(u, n)))
    for run in RUNS:
        out.append((f"run:{run!r}", lambda n, r=run: _fill(r, n) + "\x00_"))
    for marker in markers:
        for run in RUNS:
            out.append(
                (
                    f"{marker!r}+run:{run!r}",
                    lambda n, m=marker, r=run: m + _fill(r, n) + "\x00_",
                )
            )
        # The same near miss on many lines: per-line anchors restart each line.
        out.append(
            (
                f"lines:{marker!r}",
                lambda n, m=marker: _fill(m + " " * 200 + "_\n", n),
            )
        )
    return out


RULE_BUILDERS = _builders(MARKERS)
SCAN_BUILDERS = _builders(SCAN_MARKERS)


def _targets():
    out = [
        (f"rule:{r.id}", lambda s, p=r.pattern: list(p.finditer(s)), RULE_BUILDERS)
        for r in RULES
    ]
    out.append(("identifier_hits", lambda s: identifier_hits(s, CFG), SCAN_BUILDERS))
    out.append(
        (
            "controlled_content_hits",
            lambda s: controlled_content_hits(s, CFG),
            SCAN_BUILDERS,
        )
    )
    return out


TARGETS = _targets()


@functools.cache
def _text(label: str, n: int) -> str:
    return dict(RULE_BUILDERS + SCAN_BUILDERS)[label](n)


def _time(fn, text: str) -> float:
    start = time.perf_counter()
    fn(text)
    return time.perf_counter() - start


def _median_time(fn, text: str) -> float:
    return statistics.median(_time(fn, text) for _ in range(3))


@pytest.mark.parametrize("name,fn,builders", TARGETS, ids=[t[0] for t in TARGETS])
def test_target_is_linear_on_adversarial_input(name, fn, builders):
    slow = []
    for label, _ in builders:
        # Grow n until the 2n run clears the noise floor (noise only slows a run).
        for n in (N, 4 * N):
            small, large = _text(label, n), _text(label, 2 * n)
            if _time(fn, large) >= NOISE_FLOOR:
                break
        else:
            continue
        t_small, t_large = _median_time(fn, small), _median_time(fn, large)
        ratio = t_large / max(t_small, 1e-9)
        if ratio >= MAX_RATIO:
            # Re-measure once: a single scheduler stall must not fail the gate.
            t_small, t_large = _median_time(fn, small), _median_time(fn, large)
            ratio = t_large / max(t_small, 1e-9)
        if ratio >= MAX_RATIO:
            slow.append(f"{label}: x{ratio:.1f} ({t_small:.3f}s -> {t_large:.3f}s)")
    assert not slow, f"{name} grows super-linearly:\n" + "\n".join(slow)


def test_every_builtin_rule_is_covered():
    assert {f"rule:{r.id}" for r in RULES} <= {t[0] for t in TARGETS}
    assert len(RULES) >= 30
