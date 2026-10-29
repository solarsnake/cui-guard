"""Controlled-content heuristics: structural signatures, never single keywords."""

from __future__ import annotations

import bisect
import ipaddress
import re

from cui_guard.detect.identifiers import (
    BUILTIN_DOMAINS,
    IdentifierConfig,
    _host_pattern,
)
from cui_guard.detect.normalize import normalize
from cui_guard.model import DetClass, Hit

_NESSUS_FIELDS = (
    re.compile(r"\bPlugin[ _]?ID\b", re.IGNORECASE),
    re.compile(r"\bRisk[ _]?Factor\b", re.IGNORECASE),
    re.compile(r"\bPlugin[ _]?Output\b", re.IGNORECASE),
)
_NESSUS_XML = re.compile(r"<ReportHost\b")

_NMAP_REPORT = re.compile(r"Nmap scan report for\b")
# Leading space is matched within one line (`[^\S\n]`): `^\s*` ran across blank lines from every
# line start, which was quadratic on a run of empty lines.
_NMAP_HEADER = re.compile(r"^[^\S\n]*PORT\s+STATE\s+SERVICE\b", re.MULTILINE)
_NMAP_ROW = re.compile(
    r"^[^\S\n]*\d{1,5}/(?:tcp|udp)\s+(?:open|closed|filtered)\S*\s+\S+", re.MULTILINE
)

_STIG_STRONG = re.compile(r"<CHECKLIST>|<VULN>|\bxccdf:\w|\bSV-\d+r\d+_rule\b")
_STIG_VID = re.compile(r"(?<![\w-])V-\d{5,6}(?!\w)")

_POAM_TERMS = (
    "weakness",
    "poc",
    "scheduled completion",
    "milestone",
    "resources required",
    "status",
)
_POAM_TERM_RES = tuple(
    re.compile(rf"\b{re.escape(t)}\b", re.IGNORECASE) for t in _POAM_TERMS
)

_FW_LINE = re.compile(r"\b(?:iptables|ip6tables|nft|access-list)\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d])")

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_CVE_WINDOW = 5


def _lines(norm: str) -> list[tuple[int, int, str]]:
    """(start, end, text) per line, offsets into `norm`."""
    out = []
    pos = 0
    for line in norm.split("\n"):
        out.append((pos, pos + len(line), line))
        pos += len(line) + 1
    return out


def _make_hit(rule_id: str, text: str, index_map: list[int], s: int, e: int) -> Hit:
    start = index_map[s]
    end = index_map[e - 1] + 1
    return Hit(
        rule_id=rule_id,
        cls=DetClass.CONTROLLED_CONTENT,
        start=start,
        end=end,
        value=text[start:end],
    )


def _span(matches: list[tuple[int, int]]) -> tuple[int, int]:
    return min(s for s, _ in matches), max(e for _, e in matches)


def _nessus(norm: str) -> tuple[int, int] | None:
    m = _NESSUS_XML.search(norm)
    if m:
        return m.start(), m.end()
    found = [fm for p in _NESSUS_FIELDS if (fm := p.search(norm))]
    if len(found) >= 2:
        return _span([(f.start(), f.end()) for f in found])
    return None


def _nmap(norm: str) -> tuple[int, int] | None:
    m = _NMAP_REPORT.search(norm)
    if m:
        return m.start(), m.end()
    header = _NMAP_HEADER.search(norm)
    if header:
        rows = [r for r in _NMAP_ROW.finditer(norm) if r.start() > header.start()]
        if rows:
            return header.start(), rows[-1].end()
    return None


def _stig(norm: str) -> tuple[int, int] | None:
    strong = [(m.start(), m.end()) for m in _STIG_STRONG.finditer(norm)]
    vids = [m for m in _STIG_VID.finditer(norm)]
    distinct = {m.group() for m in vids}
    if strong or len(distinct) >= 2:
        spans = strong + [(m.start(), m.end()) for m in vids]
        return _span(spans)
    return None


def _header_cells(line: str) -> list[str] | None:
    """Cells of a table-header-shaped line, or None if not table-shaped."""
    for delim in ("|", "\t"):
        if delim in line:
            return line.split(delim)
    if line.count(",") >= 2:
        cells = line.split(",")
        if all(len(c.strip()) <= 40 for c in cells):
            return cells
    return None


def _poam(norm: str) -> tuple[int, int] | None:
    for start, end, line in _lines(norm):
        cells = _header_cells(line)
        if cells is None:
            continue
        terms = {
            i for i, p in enumerate(_POAM_TERM_RES) if any(p.search(c) for c in cells)
        }
        if len(terms) >= 3:
            return start, end
    return None


def _networks(cfg: IdentifierConfig) -> list[ipaddress.IPv4Network]:
    nets = []
    for r in cfg.ip_ranges:
        try:
            n = ipaddress.ip_network(r, strict=False)
        except ValueError as e:
            raise ValueError(f"invalid ip_ranges entry {r!r}: {e}") from e
        if n.version == 4:
            nets.append(n)
    return nets


def _fw_dump(norm: str, cfg: IdentifierConfig) -> tuple[int, int] | None:
    nets = _networks(cfg)
    if not nets:
        return None
    matched: list[tuple[int, int]] = []
    for start, end, line in _lines(norm):
        if not _FW_LINE.search(line):
            continue
        for m in _IPV4.finditer(line):
            octets = [int(o) for o in m.group().split("/")[0].split(".")]
            if any(o > 255 for o in octets):
                continue
            addr = ipaddress.IPv4Address(bytes(octets))
            if any(addr in n for n in nets):
                matched.append((start, end))
                break
    return _span(matched) if matched else None


def _cve_internal_host(norm: str, cfg: IdentifierConfig) -> tuple[int, int] | None:
    cves = list(_CVE.finditer(norm))
    if not cves:
        return None
    # Same host pattern identifier_hits uses for kind="host", run on normalized text.
    host_pat = _host_pattern(BUILTIN_DOMAINS + cfg.domains)
    if host_pat is None:
        return None
    host_matches = list(host_pat.finditer(norm))
    if not host_matches:
        return None
    line_starts = [m.end() for m in re.finditer("\n", norm)]  # starts of lines 1..

    def line_of(pos: int) -> int:
        return bisect.bisect_right(line_starts, pos)

    hosts = sorted((line_of(m.start()), m.start(), m.end()) for m in host_matches)
    host_lines = [h[0] for h in hosts]
    spans: list[tuple[int, int]] = []
    for m in cves:
        cve_line = line_of(m.start())
        i = bisect.bisect_left(host_lines, cve_line - _CVE_WINDOW)
        if i < len(hosts) and hosts[i][0] <= cve_line + _CVE_WINDOW:
            _, ns, ne = hosts[i]
            spans.append((min(m.start(), ns), max(m.end(), ne)))
    return _span(spans) if spans else None


def controlled_content_hits(text: str, cfg: IdentifierConfig) -> list[Hit]:
    norm, index_map = normalize(text)
    found: list[tuple[str, tuple[int, int] | None]] = [
        ("cc.nessus", _nessus(norm)),
        ("cc.nmap", _nmap(norm)),
        ("cc.stig", _stig(norm)),
        ("cc.poam", _poam(norm)),
        ("cc.fw_dump", _fw_dump(norm, cfg)),
        ("cc.cve_internal_host", _cve_internal_host(norm, cfg)),
    ]
    hits = [
        _make_hit(rule_id, text, index_map, span[0], span[1])
        for rule_id, span in found
        if span
    ]
    hits.sort(key=lambda h: (h.start, h.end))
    return hits
