# SSDF (NIST SP 800-218 v1.1) evidence map

This maps cui-guard features and project practices to NIST requirements as evidence. It does not certify, assess or authorize anything.

Catalog: SP 800-218 v1.1 (final). IDs and titles were checked against NIST's published SSDF table on 2026-10-29; see `docs/compliance/README.md` for the source. Version 1.2 (SP 800-218 Rev 1) was only an initial public draft of 2025-12-17, as of 2026-10-29, so draft practices are not cited here.

This is input for the CISA Secure Software Development Attestation Form. A software producer signs that form, not this project.

Responsibility values:

- `project`: the repository itself carries the evidence.
- `maintainer`: a person with repository admin rights has to do or configure it. See `docs/MAINTAINER-SECURITY.md`.
- `producer`: the organization that ships software built on or with cui-guard owns it.

| Practice | Title | Project evidence | Responsibility |
|---|---|---|---|
| PO.1 | Define Security Requirements for Software Development | `docs/THREAT-MODEL.md` (assets, adversaries, controls), `docs/LIMITS.md`, `SECURITY.md` | project |
| PO.2 | Implement Roles and Responsibilities | `docs/MAINTAINER-SECURITY.md` (maintainer checklist). Staffing and training of people are not repository artifacts. | maintainer |
| PO.3 | Implement Supporting Toolchains | `scripts/check` (one entry point for lock, audit, sbom, build and other gates), `.github/workflows/ci.yml`, `.github/zizmor.yml`, `.gitleaks.toml` | project |
| PO.4 | Define and Use Criteria for Software Security Checks | `scripts/check`, `security/vex.cdx.json` (the only way to dismiss a finding, with a justification and a review-by date), `scripts/security/vex.py`, `scripts/security/report.py` | project |
| PO.5 | Implement and Maintain Secure Environments for Software Development | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/zizmor.yml`. Hardening of developer endpoints and repository settings is outside the repository. | maintainer |
| PS.1 | Protect All Forms of Code from Unauthorized Access and Tampering | `.gitleaks.toml`, `.github/workflows/scorecard.yml`, `docs/MAINTAINER-SECURITY.md` (branch protection and access settings are on the checklist) | maintainer |
| PS.2 | Provide a Mechanism for Verifying Software Release Integrity | `.github/workflows/release.yml`, `scripts/security/sbom.py`, `docs/SECURITY-ASSURANCE.md` (how to verify a release) | project |
| PS.3 | Archive and Protect Each Software Release | `.github/workflows/release.yml`, `scripts/security/sbom.py`, `uv.lock`, `docs/SECURITY-ASSURANCE.md` (provenance level: SLSA Build Level 2 as GitHub implements it; no claim beyond that) | project |
| PW.1 | Design Software to Meet Security Requirements and Mitigate Security Risks | `docs/THREAT-MODEL.md`, `src/cui_guard/gateway/app.py`, `src/cui_guard/pipeline.py`, `src/cui_guard/policy/` | project |
| PW.2 | Review the Software Design to Verify Compliance with Security Requirements and Risk Information | `docs/THREAT-MODEL.md` (each threat names the tests that pin its controls). An independent design review has not happened; see `docs/SECURITY-ASSURANCE.md`. | maintainer |
| PW.4 | Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality | `DEPENDENCIES.md`, `uv.lock`, `.github/dependabot.yml`, `scripts/security/vex.py` | project |
| PW.5 | Create Source Code by Adhering to Secure Coding Practices | `src/cui_guard/audit.py` (the audit log never holds real values), `src/cui_guard/fips.py`, `.github/workflows/codeql.yml`, `tests/security/` | project |
| PW.6 | Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security | `hatch_build.py`, `scripts/check` (build gate), `.github/workflows/release.yml`, `tests/security/` | project |
| PW.7 | Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | `.github/workflows/codeql.yml`, `.github/zizmor.yml`, `.gitleaks.toml`, `scripts/check`, `docs/MAINTAINER-SECURITY.md` (human review is a checklist item) | maintainer |
| PW.8 | Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | `tests/leak/`, `tests/pentest/`, `tests/redteam/`, `tests/fuzz/`, `tests/security/`, `tests/fips/`, `docs/SECURITY-ASSURANCE.md` (what the suites cover and the known gaps) | project |
| PW.9 | Configure Software to Have Secure Settings by Default | `src/cui_guard/policy/`, `src/cui_guard/override/` (loosening needs OS authentication), `src/cui_guard/gateway/app.py` (loopback only), `docs/LIMITS.md` | project |
| RV.1 | Identify and Confirm Vulnerabilities on an Ongoing Basis | `.github/workflows/nightly.yml` (re-audit of the unchanged lock), `scripts/check` (audit gate), `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, `.github/dependabot.yml`, `SECURITY.md` (reporting) | project |
| RV.2 | Assess, Prioritize, and Remediate Vulnerabilities | `security/vex.cdx.json`, `scripts/security/vex.py`, `scripts/security/report.py`, `SECURITY.md` (response targets), `.github/dependabot.yml` | project |
| RV.3 | Analyze Vulnerabilities to Identify Their Root Causes | `tests/redteam/` and `tests/leak/` (a found bypass becomes a regression test), `docs/SECURITY-ASSURANCE.md` (known gaps), `docs/THREAT-MODEL.md`. Root-cause review over time is a maintainer activity. | maintainer |

## What this project cannot provide

- The attestation itself. The producer signs it and answers for it.
- Evidence about the producer's own build environment, staff and release process if they repackage cui-guard.
- Any practice marked `maintainer` until the maintainer has done the work. `docs/MAINTAINER-SECURITY.md` lists the open items.
