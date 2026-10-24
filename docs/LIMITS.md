# Limits of cui-guard

cui-guard is a technical control that reduces mistakes. It makes no statement about whether any use of an LLM is permitted for your data. Read this before relying on it.

## What it cannot promise

- **Pseudonymization is not anonymization.** Replacing a host, address, name or ticket key with a placeholder hides the value, but the surrounding text, the pattern of placeholders, and the structure of your work can still let someone re-identify what you are working on. Treat placeholders as a mistake-reducer, not as a privacy guarantee.
- **Short mapped values can be over-masked.** If a very short value is in the session map, it can be replaced inside longer words or numbers that merely contain it, and the model sees a garbled prompt.
- **Placeholders the model transforms are not restored.** If the model rewrites a placeholder (lowercases it, splits it, hashes it, or builds a new string from it), the reply is shown with the placeholder, or a mangled form of it, and the real value is not substituted back. Leftover placeholders in a reply raise a notice.
- **Marking rules are not all verified.** Detection patterns for CUI and classified markings are written from public guidance. Rules marked unverified have not been checked against primary sources (DoDI 5200.48, DoDI 5230.24, DoDM 5200.01). A missing or unusual marking will not be seen. Content with no marking and no recognizable pattern passes through.
- **Heuristics make mistakes both ways.** Controlled-content heuristics (scanner exports, firewall dumps, POA&M tables, STIG data) can miss real material and can flag harmless text. Identifier detection covers IPv4 only; IPv6 addresses and ranges are not handled. Slack `xoxe`/`xapp` tokens and secrets glued onto a name (`dbpassword=...`) are not recognized.
- **Line-start "(C) option" list items hard-block.** A list item such as `(C) option three` looks like a classified portion mark, and classified markings cannot be overridden. Reword the list item.
- **Authority phrases can hard-block ordinary prose.** "Classified by: the committee" blocks, because the colon form is treated as a classification authority line.
- **`fw_dump` is IPv4-only.** The firewall-dump heuristic ignores IPv6 ranges.
- **Headers and query strings are not scanned.** Only the request body is inspected. Agent-controlled headers (for example `ANTHROPIC_CUSTOM_HEADERS`) or URL query strings could carry a value past the guard.
- **Images and other opaque content are replaced, not read.** On public lanes they are removed and a notice is sent instead. On approved and local lanes they are forwarded without inspection.

## Credentials and the agent

- **Passthrough trade-off.** In passthrough mode the agent keeps its own login and the gateway forwards it. The guard does not hold the credential, so it cannot stop the agent from reaching the provider by some route that skips the gateway. Use gateway credential mode when you need the guard to be the only path. In gateway mode the agent never sees the upstream key.
- **Consumer-plan data use.** Conversations on consumer plans may be used for model training under the provider's data-use terms. Check your plan settings before using passthrough with a consumer login.
- **A keyring-stored Codex ChatGPT login cannot be detected.** The launcher refuses when it finds a ChatGPT login in Codex's file store, but it cannot see one kept in the OS keyring.
- **Background agents cannot reach the gateway.** The session token is passed through the environment only and is never written to disk, so Claude Code background agents that do not inherit the shell environment get a 401 (the request fails closed). They are unusable under cui-guard in v1.
- **Organization pinning needs a fixed-port gateway.** The emitted Claude Code managed settings pin a fixed gateway URL, but v1 gateways use a random per-session port. Organizations cannot yet use provider pinning with the v1 launcher; this is planned for phase 2. Codex has no provider allowlist in its requirements file, so for Codex the provider can only be pinned by using the cui-guard launcher.

## Data on disk

- **Agent transcripts stay on disk.** Claude Code and Codex write full conversation transcripts to the user's disk (for example under `~/.claude`). These hold the real values from before pseudonymization. cui-guard does not manage or encrypt them. The guard's own session map is kept in memory only.
- **The audit log holds no matched values**, but it records rule IDs, counts, hashes and override justifications. Written justifications are typed by a person, so do not put sensitive details in them.
- **UDP syslog delivery cannot be confirmed.** If an organization sink uses UDP, the guard cannot tell whether a record arrived.

## Availability and robustness

- **A pathological user regex can stall a session.** Python's regex engine cannot be interrupted. A catastrophic (ReDoS-prone) pattern in your own config makes scans time out. The request then fails closed (nothing is forwarded), but a worker thread stays busy, and repeated runaway scans can exhaust the worker pool. One gateway serves one session, so other sessions are not affected.
- **Latency.** The target is under 50 ms added per request on cached history, excluding optional name detection.

## Not supported

- **Cursor** is not supported. It does not let the user route model traffic through a local base URL in a way the guard can enforce.
- Native Windows is out of scope. WSL2 works.
- Per-project mapping persistence is not implemented; the map is in memory for the session.

## Provider notes

- **Department of War contractors.** The Department of War has restricted Anthropic products (designated a supply-chain risk in March 2026; reportedly covering contractors on DoW work, subject to contract modification). cui-guard is provider-neutral and this does not change the tool, but check with your contracting officer before using any Anthropic endpoint for contract work.
- **Declared trust is yours.** An `approved` lane is whatever you declare. cui-guard does not check it.

## What was tested

The release gate is the canary suite in `tests/leak` (real gateway process, real HTTP, a recording fake upstream, synthetic canaries only). It covers the three wire formats, streaming and not, and public/approved/local lanes, plus tamper tests. The results of the real-agent smoke tests (`CUI_GUARD_REAL_AGENTS=1 pytest tests/integration`), run on macOS with Claude Code 2.1.309:

| Check | Result |
|---|---|
| `cui-guard claude -- -p ...` in passthrough mode reaches the gateway lane and exits 0 | Passed |
| No connection to `api.anthropic.com`, `statsig`, `datadoghq` or `sentry` during that run, observed through a recording `HTTPS_PROXY` (loopback excluded by `NO_PROXY`) | Passed; the proxy saw no targets at all. This shows no proxy-aware bypass traffic. Traffic that ignores proxy variables was not observed. |
| A project `.claude/settings.json` setting `ANTHROPIC_BASE_URL` does not override the launcher's `--settings` value | Passed (the request still reached the gateway) |
| The same with a user `~/.claude/settings.json` in an isolated temporary `HOME` | Not verified: an isolated `HOME` hides the macOS login keychain, so Claude Code could not log in. The project-level result above is the closest check. |
| Codex routing, and whether a custom provider bypasses a stored ChatGPT login | Not run: `codex` is not installed on the test machine. The Task 15 refusal remains in place and spec section 13 is unchanged. |

Also seen during the Claude run: Claude Code warns that the `Write(...)` deny rules the launcher puts in its settings file "are not matched by file permission checks" and that only `Edit(path)` rules apply. The `Edit(...)` rules are present, so the protection is in effect; the warning is noise.
