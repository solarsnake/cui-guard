"""Emit organization configuration for the agents' managed-settings mechanisms."""

from __future__ import annotations

from cui_guard.launch.claude import DENY_TOOLS, LOCKDOWN_ENV


def emit_claude_managed_settings(gateway_url: str) -> dict:
    """Managed settings that pin Claude Code to the gateway and turn off bypass paths.

    The Claude in Chrome server is denied through `permissions.deny`. The
    `deniedMcpServers` entry shape is not confirmed in the research notes, so it is not emitted.
    The per-user Edit/Write denies on the cui-guard config and state directories are omitted
    because those paths differ for every user; the launcher adds them to each session.
    """
    return {
        "allowedProviders": ["customEndpoint"],
        "env": {"ANTHROPIC_BASE_URL": gateway_url, **LOCKDOWN_ENV},
        "skipWebFetchPreflight": True,
        "allowManagedHooksOnly": True,
        "allowManagedMcpServersOnly": True,
        "allowManagedPermissionRulesOnly": True,
        "permissions": {
            "disableBypassPermissionsMode": "disable",
            "deny": list(DENY_TOOLS),
        },
    }


def emit_codex_requirements() -> str:
    """requirements.toml content. Only keys named in the Codex managed-configuration docs."""
    return """\
# Codex requirements.toml emitted by cui-guard.
# Key names: https://learn.chatgpt.com/docs/enterprise/managed-configuration
# Install at /etc/codex/requirements.toml (Linux, macOS) or deploy through MDM
# (macOS domain com.openai.codex, key requirements_toml_base64).
#
# requirements.toml has no model-provider allowlist key. Pinning Codex to the
# cui-guard gateway therefore relies on the cui-guard launcher, not on this file.
#
# Precedence (low to high): system file, cloud requirements, legacy
# managed_config.toml, macOS MDM. A higher layer overrides scalars and lists.
# Review your provider's terms of service before relying on any of these settings.

allow_managed_hooks_only = true
# "api" only: this blocks use of Codex with a ChatGPT login.
allowed_login_methods = ["api"]
"""
