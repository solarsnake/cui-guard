# Security policy

cui-guard sits on the path of every prompt an agent sends, so a flaw in it can leak the data it is meant to protect. We want to hear about problems. This policy says how to report them and what to expect. It is a statement of intent by volunteers, not a contract.

## Reporting

Report vulnerabilities privately. Never put vulnerability details in a public issue.

- Use GitHub's "Report a vulnerability" button on the repository's Security tab (private vulnerability reporting).
- If you cannot use private reporting, open a public issue that says only that you need a private channel to report a security problem, with no details.

Please include the version, what you did, what you expected and what happened. Use synthetic data only. Never send real controlled data, real credentials or real personal data in a report.

## Supported versions

Only the latest minor release of cui-guard receives security fixes.

Supported Python versions are the CPython versions under upstream security support. `cui-guard doctor` reports `end-of-life` when the running interpreter is past end of life.

Vulnerabilities in the interpreter or OpenSSL are outside what the dependency audit can see, so keep your interpreter current.

## Response targets

These are targets, not guarantees.

- We acknowledge a report within 3 business days.
- A Critical or High vulnerability in a runtime dependency (`starlette`, `uvicorn`, `httpx`, or anything they pull in) gets a patch release within 7 days.
- Other vulnerabilities are fixed within 30 days.

## Disclosure

We follow 90-day coordinated disclosure: the report stays private while we fix it, and we publish the advisory when a fixed release is available or 90 days after the report, whichever comes first. If a fix needs longer, we will agree a date with the reporter. We request CVE identifiers through GitHub's CNA and credit reporters who want credit.

## Scope

In scope, as described in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md):

- Anything that lets real values (canaries, credentials, controlled content) reach the upstream, a log, the audit log, an error body, a header, a URL or a temporary file when policy says they should not.
- The gateway's HTTP surface: DNS rebinding, cross-origin requests, token handling, request-size and framing attacks, redirects, cleartext upstreams.
- A hostile model response that gets rehydration to put real values into a tool call that sends them out.
- Detection evasion that is not already a listed known gap (see [docs/LIMITS.md](docs/LIMITS.md)).
- Supply-chain and release problems: a tampered or unattested release, a dependency or build-tool compromise, a typosquat of `cui-guard`.
- Weaknesses in the CI and release workflows (injection, token theft, cache poisoning).

Out of scope:

- A malicious process running as the same user, including an agent with a shell. It can read the gateway's memory or kill it; see [docs/LIMITS.md](docs/LIMITS.md).
- An administrator or root user on the machine.
- Evasion forms already listed as known gaps in [docs/LIMITS.md](docs/LIMITS.md) and [docs/SECURITY-ASSURANCE.md](docs/SECURITY-ASSURANCE.md).
- Questions of whether a given use of an LLM is permitted for your data. cui-guard makes no statement about that.
- Vulnerabilities in the agents, LLM providers, or the operating system themselves.
- Denial of service by a user against their own local gateway.

## Safe harbor

If you make a good-faith effort to follow this policy, we will not pursue or support legal action against you for your research. Good faith means: test only against your own installation with synthetic data, do not access or keep other people's data, do not degrade services you do not own, report promptly, and give us a reasonable time to fix before disclosing. If you are unsure whether something is covered, ask first through the private channel above.
