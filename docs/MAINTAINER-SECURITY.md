# Maintainer security checklist

Controls that need a GitHub remote and a PyPI project. Apply them on first publish, then re-check them when ownership or settings change.

## Accounts

- [ ] Turn on two-factor authentication (hardware key or passkey preferred) for every maintainer on GitHub.
- [ ] Turn on two-factor authentication for every maintainer on PyPI.

## Repository

- [ ] Create branch rulesets for `main` with required status checks (the `scripts/check` gates run by `ci.yml`), required review, and signed commits.
- [ ] Add a CODEOWNERS file covering `.github/`, `security/` and `src/cui_guard/{gateway,policy,pseudo}`.
- [ ] Turn on private vulnerability reporting.
- [ ] Turn on secret scanning with push protection.
- [ ] Turn on Dependabot alerts.
- [ ] Enable Dependabot security updates (exempt from the 7-day cooldown).
- [ ] Fill in the maintainer contact in `SECURITY.md` (the placeholder must not ship).

## Release

- [ ] Create the protected `release` environment with required reviewers, and restrict it to `v*` tags.
- [ ] Configure the Trusted Publisher on PyPI for `release.yml` and the `release` environment. Do not create API tokens.
- [ ] Reserve confusable PyPI names for `cui-guard`.
- [ ] Before each release, check that `security/vex.cdx.json` has no entry past its review-by date and that `scripts/check all` passes.
