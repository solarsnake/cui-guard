"""Egress-aware rehydration: a tool-call string that names an outside host keeps its placeholders."""

from __future__ import annotations

import ipaddress
import re
import string
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from cui_guard.detect.identifiers import IdentifierConfig
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
# A call whose decision text is longer than this is outbound without being read (fail closed).
MAX_DECISION_CHARS = 1_048_576

# Every pattern here runs in linear time on any input. Each one starts at a literal or behind a
# left boundary, no repeated group holds an unbounded quantifier, and an unbounded run is one
# character class that a later start never scans again. The URL passes are plain scans from
# each scheme's '://' (`_url_starts`, `_url_hosts`).
_AUTH_END = re.compile(r"[\s/?#\\'\"`<>]")  # the authority ends at a path, quote or backslash
_NETLOC_END = re.compile(r"[/?#\n]")  # where a URL parser's authority ends (spaces do not end it)
_TOKEN_END = re.compile(r"[ \"'`<>\x0b\x0c]")  # a URL token: tabs and line breaks do not end it
_TAB_NL = re.compile(r"[\t\r\n]")
_LETTERS = frozenset(string.ascii_letters)
_SCHEME_TAIL = frozenset(string.digits + "+.-")  # scheme characters other than letters
_SPLIT = r"[\t\r\n]*+"  # WHATWG URL parsing deletes tabs and line breaks anywhere in a URL
# A network scheme, ':' and any run of '/' or '\' (none included) starts a URL: WHATWG (Node,
# Deno and Bun fetch, browsers) sends `http:/h`, `http:///h`, `http:h` and `https:\\h` to `h`.
# When no host can follow (a space, quote, '#', '?', ':', ...) it is a scheme name, not a URL.
_SPECIAL = re.compile(
    r"(?<![A-Za-z0-9+.\-])((?:"
    + "|".join(_SPLIT.join(s) for s in ("https", "http", "wss", "ws", "ftps", "ftp"))
    + ")"
    + _SPLIT
    + r":[/\\\t\r\n]*+)(?![\s\"'`<>#?:^|\]*),;]|\Z)",
    re.IGNORECASE,
)
# The host after a URL's '@': a bracketed literal, or a run of labels (cut by `_labels`).
_URL_AT_HOST = re.compile(r"\[[^\]\n@\[]{1,256}\]|[\w\-][\w\-.]*")
# user@host, optionally followed by ':' (the scp / git form). Any non-space character before
# '@' counts, so a quote or backslash (`"http://x.mil"@evil.app`) cannot hide the host.
_AT = re.compile(r"(?<=\S)@(\[[0-9A-Fa-f:.%\w]{1,256}\]|[\w\-][\w\-.]*)(:?)")
# A maximal dotted token: `a.b`, `x.y.z` (labels are Unicode word characters or '-').
_DOTTED = re.compile(r"(?<![\w\-.])[\w\-]++\.[\w\-.]*")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w{1,64})?(?![\w:])")
_CLEAN_HOST = re.compile(r"[a-z0-9_\-.]+")  # with `_clean`: dot-separated, no empty label
_DIGEST = re.compile(r"sha\d{1,4}|md5|blake\w{0,16}")  # `image@sha256:...` is not an scp target
_HOST_OR_IP_PLACEHOLDER = re.compile(r"host-\d{1,9}\.cg\.invalid|198\.18\.\d{1,3}\.\d{1,3}")


def _labels(run: str) -> str:
    """The dot-separated labels a `[\\w\\-.]` run starts with: it ends at an empty label."""
    return run.split("..", 1)[0].rstrip(".")


def _clean(host: str) -> bool:
    return bool(_CLEAN_HOST.fullmatch(host)) and host[0] != "." and ".." not in host


def _canonical(m: re.Match[str]) -> str:
    return _TAB_NL.sub("", m.group(1)).split(":", 1)[0].lower() + "://"


def _url_starts(text: str):
    """The index of each '://' that ends a scheme: a letter, then letters, digits, '+', '.', '-'.

    The scan back from each '://' stops at its nearest letter and cannot pass an earlier '://',
    so no character is scanned twice.
    """
    i = text.find("://")
    while i >= 0:
        k = i - 1
        while k >= 0 and text[k] in _SCHEME_TAIL:
            k -= 1
        if k >= 0 and text[k] in _LETTERS:
            yield i
        i = text.find("://", i + 3)


def _join_url_tokens(text: str) -> str:
    """`text` with tabs and line breaks deleted inside each URL token, as URL parsers read it."""
    out, pos = [], 0
    for i in _url_starts(text):
        if i < pos:
            continue
        m = _TOKEN_END.search(text, i + 3)
        end = m.start() if m else len(text)
        out += (text[pos:i], _TAB_NL.sub("", text[i:end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


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
    if host.startswith("["):
        return True
    if len(labels) == 1:  # a single label is never an IP literal
        return colon and not _DIGEST.fullmatch(host.lower())  # scp `u@box:`, not `img@sha256:`
    # `pkg@1.2.3` is a version, not a host; `u@203.0.113.9` is an IP literal
    return any(c.isalpha() for c in labels[-1]) or _ip(host) is not None


class EgressGuard:
    """Decides whether a tool-call string names a destination outside the user's own network."""

    def __init__(self, identifiers: IdentifierConfig, mode: Literal["withhold", "allow"]) -> None:
        if mode not in ("withhold", "allow"):
            raise ValueError(f"unknown egress_rehydration mode {mode!r}")
        self.mode = mode
        # Internal is only what the user or organization configured: the detector's built-in
        # `mil`/`gov` domains and private IP ranges are a detection aid, never a trust grant.
        self._domains = tuple(d.strip(".").lower() for d in identifiers.domains if d.strip("."))
        nets = []
        for r in identifiers.ip_ranges:
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
        if not _clean(h):
            return False  # percent-encoded, odd or non-ASCII hosts are never taken as internal
        if h == "invalid" or h.endswith(".invalid"):
            return True  # RFC 6761: never resolves; every guard placeholder ends in it
        if h == "localhost":
            return True
        if _HOST_OR_IP_PLACEHOLDER.fullmatch(h) and smap.knows(h):
            return True
        return any(h == d or h.endswith("." + d) for d in self._domains)

    def _url_hosts(self, text: str):
        """The hosts each '://' names, read three ways.

        1. The authority up to a path, space or quote, after its last '@'.
        2. The host after the last '@' before the path. Userinfo may hold spaces or quotes
           (`http://x.mil @evil.app/`), and HTTP libraries take the host after it.
        3. The host urlsplit takes, as requests and urllib do.
        """
        for i in _url_starts(text):
            j = i + 3
            m = _AUTH_END.search(text, j)
            authority = text[j : m.start() if m else len(text)].rpartition("@")[2]
            if authority.startswith("["):
                host = authority[: authority.find("]") + 1] if "]" in authority else authority
            else:
                host = authority.split(":", 1)[0]
            if host:
                yield host
            m = _NETLOC_END.search(text, j)
            end = m.start() if m else len(text)
            k = text.rfind("@", j, end)
            while k >= 0:
                h = _URL_AT_HOST.match(text, k + 1)
                if h:
                    host = h.group(0) if h.group(0)[0] == "[" else _labels(h.group(0))
                    if host.strip("[]").split(".")[-1].lower() != "invalid":  # RFC 6761
                        yield host
                    break
                k = text.rfind("@", j, k)
            try:
                host = urlsplit("x" + text[i:end]).hostname  # the scheme does not change the host
            except ValueError:
                host = None
            if host:
                yield host

    def _destinations(self, text: str):
        """Every host the text names, in any of the destination forms."""
        yield from self._url_hosts(text)
        for m in _AT.finditer(text):
            host = m.group(1) if m.group(1)[0] == "[" else _labels(m.group(1))
            if _at_destination(host, bool(m.group(2)) and host == m.group(1)):
                yield host
        for m in _DOTTED.finditer(text):
            host = _labels(m.group(0))
            if "." not in host:
                continue
            tld = host.rsplit(".", 1)[1].lower()
            if tld in COMMON_TLDS or tld.startswith("xn--") or (not tld.isascii() and tld.isalpha()):
                yield host
        for m in _IPV4.finditer(text):
            yield m.group(0)
        for m in _IPV6.finditer(text):
            cand = m.group(0)
            if any(c.isdigit() for c in cand) and _ip(cand) is not None:
                yield cand

    def is_outbound(self, text: str, smap: SessionMap) -> bool:
        """True when `text` names a destination (URL, user@host, name.tld, IP) that is not internal.

        The passes run over the text and over a URL-reading copy. In the copy, a network scheme
        followed by ':' and any slashes or backslashes is written `scheme://`, and tabs and line
        breaks inside each URL are removed, the way URL parsers read them. The text itself is
        never changed. Text over MAX_DECISION_CHARS is outbound without being read.
        """
        if len(text) > MAX_DECISION_CHARS:
            return True
        norm, _ = normalize(text)
        if len(norm) > MAX_DECISION_CHARS:
            return True
        canon = _SPECIAL.sub(_canonical, norm)
        copies = dict.fromkeys((norm, canon, _join_url_tokens(canon)))
        return any(not self._internal(h, smap) for c in copies for h in self._destinations(c))
