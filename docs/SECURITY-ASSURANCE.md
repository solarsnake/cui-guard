# Security assurance

This document says what each release carries, how to verify it, what the test suites cover, and what is known not to work. It publishes evidence. It makes no statement that cui-guard meets any government program's requirements; others judge that.

## What every release carries

- The wheel and the sdist, with the CycloneDX SBOM embedded in the wheel at `.dist-info/sboms/cui-guard.cdx.json`.
- The SBOM as a release asset (`cui-guard.cdx.json`), the subject of no attestation itself; its SBOM attestation binds it to the wheel and sdist. It loads directly into OWASP Dependency-Track and similar tools, so you can monitor the runtime set for new vulnerabilities.
- The security report (`summary.md` and `report.json`): dependency audit with VEX status, static-analysis, secret and workflow gate results, suite pass counts, the KNOWN_GAP list, the SBOM digest, the reproducible-build digests and tool versions. It never contains matched values.
- `vex.cdx.json`: the reviewed list of dismissed findings, each with a justification and a review-by date.
- `runtime.lock.txt`: the hash-locked runtime dependency set.
- GitHub attestations: build provenance for the wheel and sdist, and an SBOM attestation (`actions/attest`).
- PyPI attestations (PEP 740), published automatically through Trusted Publishing.

## Verifying a release

Download the release assets, then:

```
# Build provenance attestation (needs the GitHub CLI)
gh attestation verify cui_guard-<version>-py3-none-any.whl --repo <owner>/cui-guard

# SBOM attestation (binds the SBOM to the wheel; a different predicate type)
gh attestation verify cui_guard-<version>-py3-none-any.whl --repo <owner>/cui-guard --predicate-type https://cyclonedx.org/bom

# PyPI attestation: the project page shows the provenance for each file. To check it from
# the command line, query the PyPI integrity API and compare the file's digest
curl -s https://pypi.org/integrity/cui-guard/<version>/cui_guard-<version>-py3-none-any.whl/provenance

# Install exactly the locked runtime set, with hashes enforced
pip install --require-hashes -r runtime.lock.txt
pip install --no-deps cui_guard-<version>-py3-none-any.whl

# Extract the SBOM embedded in the wheel
unzip -p cui_guard-<version>-py3-none-any.whl '*.dist-info/sboms/cui-guard.cdx.json' > sbom.cdx.json
```

`runtime.lock.txt` is the release asset of that name.

## What the suites cover

| Suite | Files | Covers |
|---|---|---|
| Egress oracle | `tests/leak/test_egress_oracle.py` | Canaries never appear in any outbound byte, log, audit record or created file, on any route and error path; the only network destination is the configured upstream |
| Leak and tamper | `tests/leak/test_leak.py`, `tests/leak/test_tamper.py` | End-to-end masking and blocking by lane; config and state tampering |
| HTTP attack surface | `tests/pentest/test_http_surface.py` | Rebinding hosts, Origin and Sec-Fetch headers, token handling, oversize and malformed bodies, hop-by-hop headers, redirects, file modes |
| Hostile upstream | `tests/pentest/test_hostile_upstream.py`, `tests/pseudo/test_egress.py` | Rehydration exfiltration attempts, floods, invalid UTF-8, truncated streams |
| Evasion corpus | `tests/redteam/test_evasion.py` | Obfuscations crossed with canary types and wire formats; outcomes in `tests/redteam/transforms.py` |
| Fuzzing | `tests/fuzz/test_adapters_fuzz.py`, `tests/fuzz/test_mapper_fuzz.py`, `tests/fuzz/test_stream_fuzz.py` | Coverage invariant, chunking-independent SSE rehydration, pseudonymize/rehydrate round trip |
| Supply chain and CI | `tests/security/` | Lock integrity, VEX expiry and matching, SBOM schema and minimum elements, reproducible build, workflow rules, report contents, these documents |

## Known gaps

Each evasion transform below is pinned as a strict expected failure in `tests/redteam/test_evasion.py`, so a fix flips the test and forces this list and [LIMITS.md](LIMITS.md) to be updated. Details are in LIMITS under "Known evasion gaps".

- `base64`
- `hex`
- `html_entity`
- `json_in_string`
- `line_wrap`
- `mixed_case`
- `percent`
- `split_blocks`
- `split_messages`
- `split_tool_args`

Other residual risks are listed in [LIMITS.md](LIMITS.md) and the [threat model](THREAT-MODEL.md).

## NIST evidence mappings

Mappings from cui-guard features and project practices to NIST SSDF, SP 800-171 and SP 800-53 are in [docs/compliance/](compliance/README.md). They are evidence maps. They do not certify, assess or authorize anything.

## Provenance level

SLSA Build Level 2 as GitHub implements it; no claim beyond that.

## What is not done yet

- **External audit.** The project will ask OSTIF for an independent audit, scoped from the threat model. It is a gate for 1.0 and has not happened.
- **OpenSSF Best Practices badge.** The project will self-certify once the repository is public. A self-certification is the project's own answer to a questionnaire, not an independent review.
