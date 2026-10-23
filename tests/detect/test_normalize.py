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


def test_ascii_fast_path_identity():
    t = "plain ascii\ntext"
    norm, imap = normalize(t)
    assert norm == t
    assert imap == list(range(len(t) + 1))


def test_line_separators_become_newline():
    assert normalize("a\rb\u2028c\u2029d\u0085e")[0] == "a\nb\nc\nd\ne"


def test_combining_marks_dropped_with_map():
    t = "x\u0106UI"
    norm, imap = normalize(t)
    assert norm == "xCUI"
    assert t[imap[1] : imap[4]] == "\u0106UI"
