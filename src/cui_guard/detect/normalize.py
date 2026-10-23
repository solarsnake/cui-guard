"""Text normalization so markings survive obfuscation, with an offset map."""

from __future__ import annotations

import unicodedata

# Cyrillic/Greek lookalikes of ASCII letters.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic upper
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H",
    "І": "I", "Ј": "J", "К": "K", "М": "M", "О": "O",
    "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y",
    # Cyrillic lower
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p",
    "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    # Greek upper
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Greek lower
    "ο": "o",
}  # fmt: skip


def normalize(text: str) -> tuple[str, list[int]]:
    """NFKC, drop format (Cf) chars, fold homoglyphs.

    Returns (normalized, index_map). index_map[i] is the original index of
    normalized char i; a final sentinel equals len(text).
    """
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        for c in unicodedata.normalize("NFKC", ch):
            if unicodedata.category(c) == "Cf":
                continue
            out.append(_HOMOGLYPHS.get(c, c))
            index_map.append(i)
    index_map.append(len(text))
    return "".join(out), index_map
