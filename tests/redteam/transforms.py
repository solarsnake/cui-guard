"""Evasion transforms for the red-team corpus.

Text transforms map a canary string to an obfuscated string (carried in the usual
`carrier` text). `json_u_escape` maps the raw request body. Request builders take
(canary, fmt) and return a request body. `EXPECTED` pins each (transform, kind) outcome.
"""

from __future__ import annotations

import base64 as _b64
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "leak"))
from canaries import build

_HOMO = {"A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М", "O": "О",
         "P": "Р", "T": "Т", "X": "Х", "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",
         "x": "х", "y": "у", "i": "і", "I": "І", "S": "Ѕ", "s": "ѕ"}  # fmt: skip


def identity(s: str) -> str:
    return s


def homoglyph(s: str) -> str:
    return "".join(_HOMO.get(c, c) for c in s)


def zero_width(s: str) -> str:
    return "\u200b".join(s)


def fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


def combining(s: str) -> str:
    return "".join(c + "́" if c.isalnum() else c for c in s)


def mixed_case(s: str) -> str:
    return "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(s))


def nbsp(s: str) -> str:
    return s.replace(" ", " ")


def line_wrap(s: str) -> str:
    mid = len(s) // 2
    return s[:mid] + "\n" + s[mid:]


def percent(s: str) -> str:
    return "".join(f"%{b:02X}" for b in s.encode())


def html_entity(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def base64(s: str) -> str:
    return _b64.b64encode(s.encode()).decode()


def hex_(s: str) -> str:
    return s.encode().hex()


def json_in_string(s: str) -> str:
    """Applied to the whole carrier: the text becomes a JSON document inside a string."""
    return json.dumps({"payload": s, "note": "embedded"})


def json_u_escape(raw: str) -> str:
    """Applied to the raw request body: every ASCII alphanumeric becomes a \\uXXXX escape."""
    return re.sub(r"[A-Za-z0-9]", lambda m: f"\\u{ord(m.group()):04x}", raw)


def halves(s: str) -> tuple[str, str]:
    mid = len(s) // 2
    return s[:mid], s[mid:]


def _text_block(fmt: str, text: str) -> dict:
    return {"type": "input_text" if fmt == "openai-responses" else "text", "text": text}


def split_blocks(s: str, fmt: str) -> dict:
    a, b = halves(s)
    body = build(fmt, "user", "x", False)
    parts = [_text_block(fmt, f"note: {a}"), _text_block(fmt, f"{b} end")]
    if fmt == "anthropic" or fmt == "openai-chat":
        body["messages"] = [{"role": "user", "content": parts}]
    else:
        body["input"] = [{"role": "user", "content": parts}]
    return body


def split_messages(s: str, fmt: str) -> dict:
    a, b = halves(s)
    body = build(fmt, "user", "x", False)
    msgs = [{"role": "user", "content": f"note: {a}"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": f"{b} end"}]  # fmt: skip
    body["input" if fmt == "openai-responses" else "messages"] = msgs
    return body


def split_tool_args(s: str, fmt: str) -> dict:
    a, b = halves(s)
    args = {"command": a, "extra": b}
    body = build(fmt, "tool_use_input", "x", False)
    if fmt == "anthropic":
        body["messages"][1]["content"][0]["input"] = args
    elif fmt == "openai-responses":
        body["input"][1]["arguments"] = json.dumps(args)
    else:
        body["messages"][1]["tool_calls"][0]["function"]["arguments"] = json.dumps(args)
    return body


def tool_schema_description(s: str, fmt: str) -> dict:
    body = build(fmt, "tool_description", "run a command", False)
    tool = body["tools"][0]
    schema = tool["function"]["parameters"] if fmt == "openai-chat" else (
        tool["parameters"] if fmt == "openai-responses" else tool["input_schema"])  # fmt: skip
    schema["properties"]["command"]["description"] = f"note: {s} end"
    return body


def file_path(s: str, fmt: str) -> dict:
    return build(fmt, "tool_use_input", f"cat /srv/data/{s}/notes.txt", False)


def document_title(s: str, fmt: str) -> dict:
    body = build(fmt, "user", "summarize", False)
    if fmt == "anthropic":
        doc = {"type": "document", "title": s,
               "source": {"type": "text", "media_type": "text/plain", "data": "hello"}}  # fmt: skip
        body["messages"] = [
            {"role": "user", "content": [doc, {"type": "text", "text": "summarize"}]}
        ]
    elif fmt == "openai-chat":
        doc = {
            "type": "file",
            "file": {"filename": s, "file_data": "data:text/plain;base64,aGVsbG8="},
        }
        body["messages"] = [
            {"role": "user", "content": [doc, {"type": "text", "text": "summarize"}]}
        ]
    else:
        doc = {
            "type": "input_file",
            "filename": s,
            "file_data": "data:text/plain;base64,aGVsbG8=",
        }
        body["input"] = [
            {
                "role": "user",
                "content": [doc, {"type": "input_text", "text": "summarize"}],
            }
        ]
    return body


TRANSFORMS: dict[str, Callable] = {
    "identity": identity, "homoglyph": homoglyph, "zero_width": zero_width,
    "fullwidth": fullwidth, "combining": combining, "mixed_case": mixed_case, "nbsp": nbsp,
    "line_wrap": line_wrap, "json_u_escape": json_u_escape, "percent": percent,
    "html_entity": html_entity,
    "split_blocks": split_blocks, "split_messages": split_messages,
    "split_tool_args": split_tool_args,
    "json_in_string": json_in_string, "tool_schema_description": tool_schema_description,
    "file_path": file_path, "document_title": document_title,
    "base64": base64, "hex": hex_,
}  # fmt: skip

# Text transforms applied to the canary only (and substituted into the carrier).
NEEDLE_TRANSFORMS = {
    "identity", "homoglyph", "zero_width", "fullwidth", "combining", "mixed_case", "nbsp",
    "line_wrap", "percent", "html_entity", "base64", "hex",
}  # fmt: skip
# Request builders: (canary, fmt) -> body.
BUILDER_TRANSFORMS = {
    "split_blocks", "split_messages", "split_tool_args", "tool_schema_description",
    "file_path", "document_title",
}  # fmt: skip
SPLIT = {"split_blocks", "split_messages", "split_tool_args"}

# Known evasion gaps, pinned by tests/redteam/test_evasion.py (strict xfail).
# Fixing one flips its test: update this table and docs/LIMITS.md together.
EXPECTED: dict[tuple[str, str], Literal["CAUGHT", "KNOWN_GAP"]] = {
    # base64
    ("base64", "classified"): "KNOWN_GAP",
    ("base64", "codename"): "KNOWN_GAP",
    ("base64", "cui"): "KNOWN_GAP",
    ("base64", "email"): "KNOWN_GAP",
    ("base64", "host"): "KNOWN_GAP",
    ("base64", "ip"): "KNOWN_GAP",
    ("base64", "person"): "KNOWN_GAP",
    ("base64", "secret_anthropic"): "KNOWN_GAP",
    ("base64", "secret_aws"): "KNOWN_GAP",
    # hex
    ("hex", "classified"): "KNOWN_GAP",
    ("hex", "codename"): "KNOWN_GAP",
    ("hex", "cui"): "KNOWN_GAP",
    ("hex", "email"): "KNOWN_GAP",
    ("hex", "host"): "KNOWN_GAP",
    ("hex", "ip"): "KNOWN_GAP",
    ("hex", "person"): "KNOWN_GAP",
    ("hex", "secret_anthropic"): "KNOWN_GAP",
    ("hex", "secret_aws"): "KNOWN_GAP",
    # html_entity
    ("html_entity", "classified"): "KNOWN_GAP",
    ("html_entity", "codename"): "KNOWN_GAP",
    ("html_entity", "cui"): "KNOWN_GAP",
    ("html_entity", "email"): "KNOWN_GAP",
    ("html_entity", "host"): "KNOWN_GAP",
    ("html_entity", "ip"): "KNOWN_GAP",
    ("html_entity", "person"): "KNOWN_GAP",
    ("html_entity", "secret_anthropic"): "KNOWN_GAP",
    ("html_entity", "secret_aws"): "KNOWN_GAP",
    # json_in_string
    ("json_in_string", "controlled"): "KNOWN_GAP",
    # line_wrap
    ("line_wrap", "codename"): "KNOWN_GAP",
    ("line_wrap", "cui"): "KNOWN_GAP",
    ("line_wrap", "host"): "KNOWN_GAP",
    ("line_wrap", "ip"): "KNOWN_GAP",
    ("line_wrap", "person"): "KNOWN_GAP",
    ("line_wrap", "secret_anthropic"): "KNOWN_GAP",
    ("line_wrap", "secret_aws"): "KNOWN_GAP",
    # mixed_case
    ("mixed_case", "classified"): "KNOWN_GAP",
    ("mixed_case", "cui"): "KNOWN_GAP",
    ("mixed_case", "person"): "KNOWN_GAP",
    ("mixed_case", "secret_anthropic"): "KNOWN_GAP",
    ("mixed_case", "secret_aws"): "KNOWN_GAP",
    # percent
    ("percent", "classified"): "KNOWN_GAP",
    ("percent", "codename"): "KNOWN_GAP",
    ("percent", "cui"): "KNOWN_GAP",
    ("percent", "email"): "KNOWN_GAP",
    ("percent", "host"): "KNOWN_GAP",
    ("percent", "ip"): "KNOWN_GAP",
    ("percent", "person"): "KNOWN_GAP",
    ("percent", "secret_anthropic"): "KNOWN_GAP",
    ("percent", "secret_aws"): "KNOWN_GAP",
    # split_blocks
    ("split_blocks", "codename"): "KNOWN_GAP",
    ("split_blocks", "cui"): "KNOWN_GAP",
    ("split_blocks", "host"): "KNOWN_GAP",
    ("split_blocks", "ip"): "KNOWN_GAP",
    ("split_blocks", "person"): "KNOWN_GAP",
    ("split_blocks", "secret_anthropic"): "KNOWN_GAP",
    ("split_blocks", "secret_aws"): "KNOWN_GAP",
    # split_messages
    ("split_messages", "codename"): "KNOWN_GAP",
    ("split_messages", "cui"): "KNOWN_GAP",
    ("split_messages", "host"): "KNOWN_GAP",
    ("split_messages", "ip"): "KNOWN_GAP",
    ("split_messages", "person"): "KNOWN_GAP",
    ("split_messages", "secret_anthropic"): "KNOWN_GAP",
    ("split_messages", "secret_aws"): "KNOWN_GAP",
    # split_tool_args
    ("split_tool_args", "codename"): "KNOWN_GAP",
    ("split_tool_args", "cui"): "KNOWN_GAP",
    ("split_tool_args", "host"): "KNOWN_GAP",
    ("split_tool_args", "ip"): "KNOWN_GAP",
    ("split_tool_args", "person"): "KNOWN_GAP",
    ("split_tool_args", "secret_anthropic"): "KNOWN_GAP",
    ("split_tool_args", "secret_aws"): "KNOWN_GAP",
}
