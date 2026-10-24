"""Synthetic canaries and request builders for the leak suite.

Every value here is invented. Secret-shaped canaries are assembled at runtime so no
literal key shape appears in source.
"""

from __future__ import annotations

import base64
import json

# Needles: the exact bytes that must (or must not) reach an upstream.
CANARIES: dict[str, str] = {
    "cui": "CUI//SP-CTI",
    "classified": "SECRET//NOFORN",
    "controlled": "NessusCanary-7731",  # carried inside a Nessus-shaped export
    "host": "jira.canary.example.mil",
    "ip": "10.99.88.77",
    "email": "canary.person@example.mil",
    "codename": "BLUEFALCONCANARY",
    "person": "Zelda Canaryname",
    "secret_anthropic": "sk-" + "ant-api03-" + "CANARY" + "A" * 30,
    "secret_aws": "AKIA" + "CANARY" + "2345672345",
}

# Detection class by canary kind (spec 3.4).
KIND_CLASS: dict[str, str] = {
    "cui": "cui-marking",
    "classified": "classified-marking",
    "controlled": "controlled-content",
    "host": "identifier",
    "ip": "identifier",
    "email": "identifier",
    "codename": "identifier",
    "person": "identifier",
    "secret_anthropic": "secret",
    "secret_aws": "secret",
}

USER_POLICY_IDENTIFIERS = {
    "codenames": [CANARIES["codename"]],
    "people": [CANARIES["person"]],
}

PATHS = {
    "anthropic": "/v1/messages",
    "openai-responses": "/v1/responses",
    "openai-chat": "/v1/chat/completions",
}
FORMATS = tuple(PATHS)
LOCATIONS = (
    "system", "user", "tool_result", "tool_use_input", "assistant_text", "tool_description",
)  # fmt: skip


def carrier(kind: str) -> str:
    """Text that carries the canary the way real content would."""
    needle = CANARIES[kind]
    if kind == "controlled":
        return f"Scanner export (fake)\nPlugin ID: 99999\nRisk Factor: High\nPlugin Output:\n  {needle} finding\n"
    if kind in ("cui", "classified"):
        return f"{needle}\nSynthetic paragraph for the canary suite.\n"
    return f"note: {needle} end"


def image_b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _tool_schema() -> dict:
    return {"type": "object", "properties": {"command": {"type": "string"}}}


def build(fmt: str, location: str, text: str, stream: bool) -> dict:
    """A request in `fmt` wire shape with `text` at `location`."""
    return _BUILDERS[fmt](location, text, stream)


def _anthropic(loc: str, text: str, stream: bool) -> dict:
    body: dict = {
        "model": "claude-test", "max_tokens": 64, "stream": stream,
        "messages": [{"role": "user", "content": "hello"}],
    }  # fmt: skip
    tu = {"type": "tool_use", "id": "toolu_1", "name": "run", "input": {"command": "ls"}}
    if loc == "system":
        body["system"] = text
    elif loc == "user":
        body["messages"] = [{"role": "user", "content": text}]
    elif loc == "tool_result":
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [tu]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": text}]},
        ]  # fmt: skip
    elif loc == "tool_use_input":
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{**tu, "input": {"command": text}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]},
        ]  # fmt: skip
    elif loc == "assistant_text":
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "text", "text": text}]},
            {"role": "user", "content": "continue"},
        ]  # fmt: skip
    elif loc == "tool_description":
        body["tools"] = [{"name": "run", "description": text, "input_schema": _tool_schema()}]
    elif loc == "image":
        body["messages"] = [{"role": "user", "content": [
            {"type": "image", "source": {
                "type": "base64", "media_type": "image/png", "data": image_b64(text)}}]}]  # fmt: skip
    else:
        raise ValueError(loc)
    return body


def _responses(loc: str, text: str, stream: bool) -> dict:
    body: dict = {"model": "gpt-test", "stream": stream, "input": "hello"}
    call = {"type": "function_call", "call_id": "c1", "name": "run", "arguments": '{"command":"ls"}'}
    if loc == "system":
        body["instructions"] = text
    elif loc == "user":
        body["input"] = text
    elif loc == "tool_result":
        body["input"] = [
            {"role": "user", "content": "go"}, call,
            {"type": "function_call_output", "call_id": "c1", "output": text},
        ]  # fmt: skip
    elif loc == "tool_use_input":
        body["input"] = [
            {"role": "user", "content": "go"},
            {**call, "arguments": json.dumps({"command": text})},
            {"type": "function_call_output", "call_id": "c1", "output": "ok"},
        ]  # fmt: skip
    elif loc == "assistant_text":
        body["input"] = [
            {"role": "user", "content": "go"},
            {"type": "message", "role": "assistant",
             "content": [{"type": "output_text", "text": text}]},
            {"role": "user", "content": "continue"},
        ]  # fmt: skip
    elif loc == "tool_description":
        body["tools"] = [
            {"type": "function", "name": "run", "description": text, "parameters": _tool_schema()}
        ]
    elif loc == "image":
        body["input"] = [{"role": "user", "content": [
            {"type": "input_image", "image_url": "data:image/png;base64," + image_b64(text)}]}]  # fmt: skip
    else:
        raise ValueError(loc)
    return body


def _chat(loc: str, text: str, stream: bool) -> dict:
    body: dict = {
        "model": "gpt-test", "stream": stream,
        "messages": [{"role": "user", "content": "hello"}],
    }  # fmt: skip
    call = {"id": "call_1", "type": "function",
            "function": {"name": "run", "arguments": '{"command":"ls"}'}}  # fmt: skip
    if loc == "system":
        body["messages"] = [{"role": "system", "content": text},
                            {"role": "user", "content": "hello"}]  # fmt: skip
    elif loc == "user":
        body["messages"] = [{"role": "user", "content": text}]
    elif loc == "tool_result":
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": None, "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "call_1", "content": text},
        ]  # fmt: skip
    elif loc == "tool_use_input":
        c = {**call, "function": {"name": "run", "arguments": json.dumps({"command": text})}}
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": None, "tool_calls": [c]},
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
        ]  # fmt: skip
    elif loc == "assistant_text":
        body["messages"] = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": text},
            {"role": "user", "content": "continue"},
        ]  # fmt: skip
    elif loc == "tool_description":
        body["tools"] = [{"type": "function", "function": {
            "name": "run", "description": text, "parameters": _tool_schema()}}]  # fmt: skip
    elif loc == "image":
        body["messages"] = [{"role": "user", "content": [
            {"type": "image_url",
             "image_url": {"url": "data:image/png;base64," + image_b64(text)}}]}]  # fmt: skip
    else:
        raise ValueError(loc)
    return body


_BUILDERS = {"anthropic": _anthropic, "openai-responses": _responses, "openai-chat": _chat}
