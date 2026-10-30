# NIST evidence mappings

This maps cui-guard features and project practices to NIST requirements as evidence. It does not certify, assess or authorize anything.

These documents help a customer, assessor or software producer find the repository artifacts that relate to a NIST requirement. A mapping row says what the project provides. It does not say a requirement is met. Whether a requirement is met depends on how the customer deploys and operates cui-guard inside their own system.

| Document | Maps | Catalog version used |
|---|---|---|
| [SSDF.md](SSDF.md) | The 19 practices of NIST SP 800-218 | SSDF v1.1 (final) |
| [800-171.md](800-171.md) | NIST SP 800-171 requirements, Rev 2 IDs leading and Rev 3 IDs alongside | Rev 2 (Update 1) and Rev 3 (OSCAL catalog 1.1.0) |
| [800-53.md](800-53.md) | NIST SP 800-53 controls | Rev 5 (OSCAL catalog 5.2.0) |

## Where the IDs came from

IDs and titles were checked programmatically against NIST's published catalogs on 2026-10-29. The downloads went to a scratch directory outside the repository.

| Source | URL | Retrieved | Result |
|---|---|---|---|
| SP 800-53 Rev 5 OSCAL catalog (5.2.0) | https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json | 2026-10-29 | All 14 control IDs and titles in 800-53.md match. |
| SP 800-171 Rev 3 OSCAL catalog (1.1.0) | https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json | 2026-10-29 | All Rev 3 IDs and titles in 800-171.md match. |
| SP 800-171 Rev 2 (Update 1) requirements spreadsheet | https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/sp800-171r2-security-reqs.xlsx | 2026-10-29 | All 8 Rev 2 IDs exist, and their requirement text matches the topic of the row. Rev 2 has no requirement titles, so the Title column uses the Rev 3 title. |
| SP 800-218 SSDF v1.1 table | https://csrc.nist.gov/files/pubs/sp/800/218/final/docs/nist.sp.800-218.ssdf-table.xlsx | 2026-10-29 | All 19 practice IDs and titles in SSDF.md match. v1.1 has no PW.3. |

No row is marked "(ID unverified)", because every source above could be fetched.

## Status notes (they go stale)

- SSDF v1.1 is the final version, as of 2026-10-29. Version 1.2 (SP 800-218 Rev 1) was released only as an initial public draft on 2025-12-17, and no final was found as of 2026-10-29. Draft practices are not cited here.
- DFARS 252.204-7012 and CMMC Level 2 use SP 800-171 Rev 2 under class deviation 2024-O0013, as of 2026-07-20 (the latest secondary report found). Rev 3 is final but is not what the deviation requires.
- The CMMC Phase 2 suspension was announced on 2026-07-13, as of 2026-10-29 with no published review outcome found.

These notes are dated snapshots, not legal guidance. Check the primary sources before citing them in a plan or an attestation.

## How to use these documents

- Treat the "Suggested SSP statement" text as a draft that describes a configuration. Edit it to match your system, then have your own assessor review it.
- The producer's own attestation, such as the CISA Secure Software Development Attestation Form, is signed by the producer. This project does not sign it.
- Assurance details and known gaps are in `docs/SECURITY-ASSURANCE.md`. Residual risks are in `docs/LIMITS.md` and `docs/THREAT-MODEL.md`.
