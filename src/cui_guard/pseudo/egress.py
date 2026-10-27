"""Egress-aware rehydration: a tool-call string that names an outside host keeps its placeholders."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from cui_guard.detect.identifiers import (
    BUILTIN_DOMAINS,
    BUILTIN_IP_RANGES,
    IdentifierConfig,
)
from cui_guard.detect.normalize import normalize

if TYPE_CHECKING:
    from cui_guard.pseudo.mapper import SessionMap

# TLDs that a bare `name.tld` token (no scheme, no `@`) is taken to end in: a curated list of
# clearly-domain TLDs. Codes that are also file extensions (`main.py`, `Dockerfile.dev`) or
# common code identifiers (`user.name`, `self.host`, `df.info()`, `obj.pk`, `self.lr`,
# `torch.lt`, `plt.cm`) are left out, as is `invalid`, the TLD of every guard placeholder.
# URLs with a scheme, hosts after `@` and IP literals count whatever their TLD.
COMMON_TLDS = frozenset(
    {
        # generic
        "com", "net", "org", "edu", "gov", "mil", "int", "biz", "xyz", "icu", "buzz", "cyou",
        "sbs", "cfd", "mobi", "aero", "asia", "coop", "museum", "xxx", "guru", "lol", "monster",
        "quest", "accountant", "cricket",
        # country codes
        "ae", "af", "ao", "aq", "ar", "au", "aw", "az", "ba", "bd", "be", "bh", "bi", "bj", "bo",
        "bq", "br", "bt", "bw", "by", "bz", "cd", "cg", "ch", "ck", "cn", "co", "cr", "cw", "cz",
        "de", "dj", "dk", "dm", "ec", "ee", "eg", "er", "et", "eu", "fi", "fj", "fm", "fo", "fr",
        "gb", "gf", "gg", "gh", "gi", "gn", "gq", "gr", "gu", "gw", "gy", "hk", "hm", "hn",
        "hr", "ht", "hu", "ie", "il", "io", "iq", "ir", "je", "jm", "jo", "jp", "ke", "kg", "kh",
        "ki", "km", "kn", "kr", "kw", "ky", "kz", "lb", "lc", "li", "lk", "lu", "lv", "ly", "mc",
        "mf", "mg", "mn", "mq", "mr", "mw", "mx", "my", "mz", "nf", "ng", "ni",
        "nl", "np", "nr", "nz", "om", "pa", "pf", "pg", "ph", "pn", "pr", "qa", "ro", "ru", "rw",
        "sa", "sb", "sg", "si", "sk", "sl", "sm", "sn", "ss", "st", "su", "sx", "sy", "sz", "tc",
        "td", "tg", "th", "tj", "tl", "tm", "tn", "tr", "tt", "tv", "tw", "ua", "ug", "uk", "uy",
        "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ye", "yt", "za", "zm", "zw",
    }
)  # fmt: skip

_LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
# scheme://authority — the authority ends at a path, query, fragment, quote or backslash.
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://([^\s/?#\\'\"`<>]*)")
# URL userinfo that holds spaces or quotes (`http://x.mil @evil.app/`): HTTP libraries take
# the host after the last '@' before the path, so that host is the destination.
_URL_AT = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^/?#\n]*@(\[[^\]\n]+\]|[\w\-]+(?:\.[\w\-]+)*)")
# A scheme-URL token as a URL parser may read it: tabs and line breaks do not end it (WHATWG
# URL parsing deletes them, and requests/urllib3/urlsplit read across them).
_URL_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^ \"'`<>\x0b\x0c]*")
_TAB_NL = re.compile(r"[\t\r\n]")
_URL_LINE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\n]*")
# user@host, optionally followed by ':' (the scp / git form). Any non-space character before
# '@' counts, so a quote or backslash (`"http://x.mil"@evil.app`) cannot hide the host.
_AT = re.compile(r"(?<=\S)@(\[[0-9A-Fa-f:.%\w]+\]|[\w\-]+(?:\.[\w\-]+)*)(:?)")
# A maximal dotted token: `a.b`, `x.y.z` (labels are Unicode word characters or '-').
_DOTTED = re.compile(r"(?<![\w\-.])[\w\-]+(?:\.[\w\-]+)+(?![\w\-]|\.[\w\-])")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![\w:])")
_CLEAN_HOST = re.compile(r"[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*")
_DIGEST = re.compile(r"sha\d+|md5|blake\w*")  # `image@sha256:...` is not an scp target
_HOST_OR_IP_PLACEHOLDER = re.compile(r"host-\d+\.cg\.invalid|198\.18\.\d{1,3}\.\d{1,3}")


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An IP literal, or None. Octets with a leading zero are refused (resolvers may read octal)."""
    h = host.split("%", 1)[0]
    if re.fullmatch(r"[\d.]+", h) and any(len(o) > 1 and o[0] == "0" for o in h.split(".")):
        return None
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _at_destination(host: str, colon: bool) -> bool:
    """Whether the host of a `user@host` (or `user@host:`) form is a destination."""
    labels = host.strip("[]").split(".")
    if labels[-1].lower() == "invalid":
        return False  # RFC 6761: never resolves; the guard's email placeholders end in it
    if host.startswith("[") or _ip(host) is not None:
        return True
    if len(labels) >= 2:
        return any(c.isalpha() for c in labels[-1])  # `pkg@1.2.3` is a version, not a host
    return colon and not _DIGEST.fullmatch(host.lower())  # scp `u@box:`, not `img@sha256:`


class EgressGuard:
    """Decides whether a tool-call string names a destination outside the user's own network."""

    def __init__(self, identifiers: IdentifierConfig, mode: Literal["withhold", "allow"]) -> None:
        if mode not in ("withhold", "allow"):
            raise ValueError(f"unknown egress_rehydration mode {mode!r}")
        self.mode = mode
        self._domains = tuple(
            d.strip(".").lower() for d in BUILTIN_DOMAINS + identifiers.domains if d.strip(".")
        )
        nets = []
        for r in BUILTIN_IP_RANGES + identifiers.ip_ranges:
            try:
                nets.append(ipaddress.ip_network(r, strict=False))
            except ValueError as e:
                raise ValueError(f"invalid ip_ranges entry {r!r}: {e}") from e
        self._nets = tuple(nets)

    def _internal_ip(self, raw: str, smap: SessionMap) -> bool:
        addr = _ip(raw)
        if addr is None:
            return False
        if any(addr in n for n in _LOOPBACK_NETS if n.version == addr.version):
            return True
        if _HOST_OR_IP_PLACEHOLDER.fullmatch(raw) and smap.knows(raw):
            return True
        return any(addr in n for n in self._nets if n.version == addr.version)

    def _internal(self, host: str, smap: SessionMap) -> bool:
        h = host.lower()
        if h.startswith("[") and h.endswith("]"):
            return self._internal_ip(h[1:-1], smap)
        h = h.rstrip(".")
        if _ip(h) is not None:
            return self._internal_ip(h, smap)
        if not _CLEAN_HOST.fullmatch(h):
            return False
        if h == "invalid" or h.endswith(".invalid"):
            return True  # RFC 6761: never resolves; every guard placeholder ends in it  # percent-encoded, odd or non-ASCII hosts are never taken as internal
        if h == "localhost":
            return True
        if _HOST_OR_IP_PLACEHOLDER.fullmatch(h) and smap.knows(h):
            return True
        return any(h == d or h.endswith("." + d) for d in self._domains)

    def _destinations(self, text: str):
        """Every host the text names, in any of the destination forms."""
        for m in _URL.finditer(text):
            authority = m.group(1).rpartition("@")[2]
            if authority.startswith("["):
                host = authority[: authority.find("]") + 1] if "]" in authority else authority
            else:
                host = authority.split(":", 1)[0]
            if host:
                yield host
        for m in _URL_AT.finditer(text):
            if m.group(1).strip("[]").split(".")[-1].lower() != "invalid":  # RFC 6761, as below
                yield m.group(1)
        for m in _AT.finditer(text):
            if _at_destination(m.group(1), bool(m.group(2))):
                yield m.group(1)
        for m in _DOTTED.finditer(text):
            tld = m.group(0).rsplit(".", 1)[1].lower()
            if tld in COMMON_TLDS or tld.startswith("xn--") or (not tld.isascii() and tld.isalpha()):
                yield m.group(0)
        for m in _IPV4.finditer(text):
            yield m.group(0)
        for m in _IPV6.finditer(text):
            cand = m.group(0)
            if any(c.isdigit() for c in cand) and _ip(cand) is not None:
                yield cand

    def _url_parser_hosts(self, text: str):
        """The host a URL parser takes for each scheme URL (urlsplit, as requests/urllib do)."""
        for m in _URL_LINE.finditer(text):
            try:
                host = urlsplit(m.group(0)).hostname
            except ValueError:
                continue
            if host:
                yield host

    def is_outbound(self, text: str, smap: SessionMap) -> bool:
        """True when `text` names a destination (URL, user@host, name.tld, IP) that is not internal.

        The passes run over the text and over a copy whose scheme URLs have tabs and line breaks
        removed, the way URL parsers read them; the text itself is never changed.
        """
        norm, _ = normalize(text)
        joined = _URL_TOKEN.sub(lambda m: _TAB_NL.sub("", m.group(0)), norm)
        copies = (norm,) if joined == norm else (norm, joined)
        return any(
            not self._internal(h, smap)
            for c in copies
            for gen in (self._destinations(c), self._url_parser_hosts(c))
            for h in gen
        )
