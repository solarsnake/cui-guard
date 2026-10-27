# cui-guard

`cui-guard` is a local, open-source gateway that sits between an AI agent (Claude Code, Codex CLI, or any agent that accepts a custom base URL) and an LLM endpoint. It inspects every outbound request, blocks or pseudonymizes what your policy forbids, and logs each decision without recording the matched content. Design spec: [docs/superpowers/specs/2026-10-23-cui-guard-design.md](docs/superpowers/specs/2026-10-23-cui-guard-design.md). Known limits: [docs/LIMITS.md](docs/LIMITS.md).

## Install

```
pipx install cui-guard
pipx install "cui-guard[ner]"     # optional: name detection (Presidio, spaCy)
pipx install "cui-guard[macos]"   # macOS: Touch ID / password prompts for overrides and approvals
```

Supported platforms: macOS and Linux (including WSL2). Python 3.11 or newer.

## Development

```
pip install uv
uv sync --group dev               # or: pip install -e . --group dev  (pip 25.1 or newer)
scripts/check all                 # lint, test, lock
```

## Quick start

```
cui-guard claude                  # Claude Code through the gateway
cui-guard codex                   # Codex CLI through the gateway
cui-guard run -- my-agent --flag  # any agent that honors a base-URL variable
cui-guard scan notes.txt          # check a file; prints rule IDs, never matched values
cui-guard lanes                   # list configured lanes
cui-guard log                     # recent audit records
cui-guard policy                  # effective policy and where each setting came from
```

The launcher starts a gateway on `127.0.0.1` (random port, per-session token), points the agent at it, and shuts it down when the agent exits.

The launchers accept `--profile`, but only `cui` is honored, and in v1 it is a no-op: the session uses the profile from your policy layers. Any other value is ignored with a warning.

## Lanes and trust

A lane is an upstream endpoint with a trust level that you declare:

| Trust | Meaning |
|---|---|
| `public` | A public LLM service. Strictest handling. |
| `approved` | An endpoint authorized for CUI by your organization. You declare this; cui-guard cannot check it. |
| `local` | A model on this machine (the URL must be loopback). |

Built-in lanes: `anthropic` and `openai` (public) and `ollama` (local). Add your own in the user config.

Default handling (spec 3.4): classified markings and unparseable requests are always blocked, on every lane, and nothing can change that. On a public lane CUI markings and controlled content are blocked, identifiers (hosts, IPs, emails, ticket keys, codenames, names) are replaced with reversible placeholders, secrets are replaced with placeholders, and images and other opaque content are replaced with a short notice. On approved and local lanes CUI is allowed; secrets in text are still replaced. Exception: images and other opaque content cannot be read, so on approved and local lanes they are forwarded uninspected (an image containing a secret is not caught).

## Profiles and policy layers

Profile `cui` is the default. Profile `general` additionally allows controlled-content heuristics (for ordinary development work). Settings come from three layers, later ones winning where allowed:

1. Built-in defaults.
2. User config at `~/.config/cui-guard/config.toml` (lanes, identifiers, extra patterns, actions).
3. Organization policy (`/etc/cui-guard/policy.toml`, or `/Library/Application Support/cui-guard/policy.toml` on macOS), which can lock lanes and profile, disable overrides, set a minimum version and ship an audit sink.

There is no project-level layer. The user config can be edited by the agent, so whenever it loosens the built-in defaults (for example a higher-trust lane, the `general` profile, a lane that is given a credential, or a default lane you defined yourself), every launch asks for OS authentication before continuing, and `--headless` launches are refused. The prompt also lists what changed since your last approval. See [docs/LIMITS.md](docs/LIMITS.md).

`egress_rehydration = "withhold" | "allow"` (default `withhold`, set in the built-in layer; the strictest value across layers wins): placeholders in a tool-call string that names an outside host (a URL, `user@host`, a `name.tld` with a common TLD, or an IP literal that is not loopback, a session placeholder, or one of your identifier domains and IP ranges) are not rehydrated, so a hostile model cannot get the agent to send real values out. Each such response adds a `rehydrate.withheld` audit record with a count. Setting `allow` is a loosening and needs OS authentication. See [docs/LIMITS.md](docs/LIMITS.md).

## Overrides

A blocked request can sometimes be overridden by a person at the keyboard: the gateway shows an on-screen warning, asks for a typed justification, and requires OS authentication (Touch ID or password on macOS, which needs the `[macos]` extra; on Linux a zenity or kdialog dialog for the justification and `pkexec` for authentication, with no terminal prompt). There is no CLI command and no HTTP route that grants an override, so the agent cannot approve its own. Classified markings and unparseable content cannot be overridden. Organizations can disable overrides entirely. Each override is written to the audit log with its justification.

## Credential modes

- `gateway`: the gateway holds the upstream API key (from the environment or the OS keychain). The agent only receives the session token.
- `passthrough`: the agent keeps its own login and the gateway forwards it. The guard does not hold the credential, so it cannot stop the agent from reaching the provider by a route that skips the gateway. See [docs/LIMITS.md](docs/LIMITS.md).
- `none`: for local servers that need no credential.

## Audit log

One JSON line per request in `~/.local/state/cui-guard/audit.jsonl`, plus a `withheld` line when tool-call placeholders were withheld: rule IDs, counts and hashes (plus override justifications). It never contains matched values, placeholder IDs or raw content. The local file is always written; organizations can add a syslog sink, the only other sink in v1.

## What this is not

cui-guard does not make CUI safe to send to a public LLM.

- It is not a tool for classified information. It refuses classified markings and does nothing else with them.
- It does not decide what is or is not CUI, and never says that something "is not CUI". It reports that a rule matched.
- It does not replace your organization's authorization, FedRAMP or CMMC processes.
- It cannot stop a determined user with administrator rights on their own machine. It protects honest people from mistakes, and it limits what a prompt-injected agent can send through the gateway. It does not contain the agent: an agent running as you with a shell can still read or kill local processes, including the gateway (see [docs/LIMITS.md](docs/LIMITS.md)).
- It is not a guarantee. Detection is heuristic; read [docs/LIMITS.md](docs/LIMITS.md) before relying on it.
- It makes no statement about whether any LLM use is permitted for your data. That is a decision for you and your organization.

## License

Apache-2.0.
