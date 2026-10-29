"""Identifier detection: hosts, IPs, emails, Jira keys, codenames, people."""

from __future__ import annotations

import ipaddress
import re
import string
from dataclasses import dataclass

from cui_guard.detect.normalize import normalize
from cui_guard.model import DetClass, Hit

BUILTIN_DOMAINS = ("mil", "gov")
BUILTIN_IP_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
# An email is a run of _EMAIL_LOCAL characters, then _EMAIL_AT_DOMAIN. `_emails` finds them
# from each '@' rather than with one regex: `[...]+@` restarted at every character of a long
# run with no '@', which was quadratic.
_EMAIL_LOCAL = frozenset(string.ascii_letters + string.digits + "._%+-")
_EMAIL_AT_DOMAIN = re.compile(r"@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_JIRA = re.compile(r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]{1,9})-\d+(?![A-Za-z0-9])")


def _emails(norm: str):
    """(start, end) of each email, as `[A-Za-z0-9._%+-]+@<domain>` finditer would report them.

    The scan back from each '@' stops at the previous match's end or a non-local character
    ('@' is one), so no character is scanned twice.
    """
    pos = 0
    at = norm.find("@")
    while at >= 0:
        start = at
        while start > pos and norm[start - 1] in _EMAIL_LOCAL:
            start -= 1
        if start < at and (m := _EMAIL_AT_DOMAIN.match(norm, at)):
            yield start, m.end()
            pos = m.end()
        at = norm.find("@", max(at + 1, pos))


@dataclass(frozen=True)
class IdentifierConfig:
    domains: tuple[str, ...] = ()
    ip_ranges: tuple[str, ...] = ()
    codenames: tuple[str, ...] = ()
    jira_projects: tuple[str, ...] = ()
    people: tuple[str, ...] = ()


def _host_pattern(domains: tuple[str, ...]) -> re.Pattern[str] | None:
    names = [d.strip(".") for d in domains if d.strip(".")]
    if not names:
        return None
    alt = "|".join(re.escape(d) for d in sorted(set(names), key=len, reverse=True))
    return re.compile(
        rf"(?<![A-Za-z0-9.\-])(?:{_LABEL}\.)+(?:{alt})(?![A-Za-z0-9\-]|\.[A-Za-z0-9])",
        re.IGNORECASE,
    )


def _words(terms: tuple[str, ...], flags: int) -> re.Pattern[str] | None:
    parts = [
        r"\s+".join(re.escape(tok) for tok in t.split()) for t in terms if t.strip()
    ]
    if not parts:
        return None
    return re.compile(rf"(?<!\w)(?:{'|'.join(parts)})(?!\w)", flags)


def identifier_hits(text: str, cfg: IdentifierConfig) -> list[Hit]:
    norm, index_map = normalize(text)
    hits: list[Hit] = []

    def add(kind: str, m: re.Match[str] | tuple[int, int]) -> None:
        lo, hi = (m.start(), m.end()) if isinstance(m, re.Match) else m
        start = index_map[lo]
        end = index_map[hi - 1] + 1
        hits.append(
            Hit(
                rule_id=f"id.{kind}",
                cls=DetClass.IDENTIFIER,
                start=start,
                end=end,
                value=text[start:end],
                kind=kind,
            )
        )

    host_pat = _host_pattern(BUILTIN_DOMAINS + cfg.domains)
    if host_pat:
        for m in host_pat.finditer(norm):
            add("host", m)

    networks = []
    for r in BUILTIN_IP_RANGES + cfg.ip_ranges:
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError as e:
            raise ValueError(f"invalid ip_ranges entry {r!r}: {e}") from e
    for m in _IPV4.finditer(norm):
        # Parse octets as ints so leading zeros (010.001.002.003) cannot evade.
        octets = [int(o) for o in m.group().split(".")]
        if any(o > 255 for o in octets):
            continue
        addr = ipaddress.IPv4Address(bytes(octets))
        if any(addr in n for n in networks if n.version == 4):
            add("ip", m)

    for span in _emails(norm):
        add("email", span)

    any_key = bool(host_pat and host_pat.search(norm))
    projects = set(cfg.jira_projects)
    for m in _JIRA.finditer(norm):
        if m.group(1) in projects or any_key:
            add("jira", m)

    codename_pat = _words(cfg.codenames, re.IGNORECASE)
    if codename_pat:
        for m in codename_pat.finditer(norm):
            add("term", m)

    people_pat = _words(cfg.people, 0)
    if people_pat:
        for m in people_pat.finditer(norm):
            add("person", m)

    hits.sort(key=lambda h: (h.start, h.end))
    return hits
