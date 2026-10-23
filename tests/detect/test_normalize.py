from cui_guard.detect.normalize import normalize


def test_strips_zero_width():
    assert normalize("C\u200bUI")[0] == "CUI"


def test_fullwidth_nfkc():
    assert normalize("ＣＵＩ")[0] == "CUI"


def test_cyrillic_homoglyph():
    assert normalize("СUI")[0] == "CUI"


def test_index_map_round_trip():
    t = "a\u200bCUI b"
    norm, imap = normalize(t)
    s = norm.index("CUI")
    e = s + 3
    assert t[imap[s] : imap[e]] == "CUI"
    assert len(imap) == len(norm) + 1
    assert imap[-1] == len(t)
