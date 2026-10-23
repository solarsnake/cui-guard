# cui-guard

`cui-guard` is a local, open-source gateway that sits between an AI agent and an LLM endpoint and makes sure controlled material only goes where it is allowed to go. It inspects outbound requests, blocks or pseudonymizes what policy forbids, and logs decisions without ever recording the matched content. It is a technical control, not a compliance determination. Design spec: [docs/superpowers/specs/2026-10-23-cui-guard-design.md](docs/superpowers/specs/2026-10-23-cui-guard-design.md).
