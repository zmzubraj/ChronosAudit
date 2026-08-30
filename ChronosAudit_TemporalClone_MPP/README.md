# Auditing Temporal and Identity Dependence in SCONE-bench

## Dual-Provider Historical State Reconstruction of 417 Smart-Contract Incidents

This repository contains the complete Minimum Publishable Prototype (MPP), reproducible analysis, manuscript sources, figures, tables, algorithms, and submission artifacts for a finite-cohort benchmark-validity audit of 417 SCONE-bench smart-contract incidents.

## Main findings

- All 417 cases existed at least 1 hour and 24 hours before the recorded incident.
- 352/417 cases (84.4%) existed at least 7 days before the incident.
- 275/417 cases (65.9%) existed at least 30 days before the incident.
- Duplicate-group membership changes from 14 rows under address identity to 46 rows under exact runtime identity and 56 rows after Solidity metadata stripping.
- 67/417 cases (16.1%) expose at least one specified ERC-1967 or ERC-1167 proxy-linkage indicator.

These results characterize temporal eligibility and identity dependence within the frozen SCONE-bench cohort. They do not establish detector performance, causal vulnerability risk, ecosystem prevalence, semantic bytecode equivalence, complete proxy enumeration, or external field effectiveness.

## Start here

- [Project index](INDEX.md)
- [Execution plan and timeline](MPP_EXECUTION_PLAN.md)
- [Final mechanically checked PDF](09-submission/ChronosAudit_TemporalClone_MPP_draft.pdf)
- [Editable DOCX](09-submission/ChronosAudit_TemporalClone_MPP_draft.docx)
- [LaTeX manuscript](07-manuscript/main.tex)
- [Markdown manuscript](07-manuscript/manuscript.md)
- [Canonical results summary](05-analysis/results/results-summary.json)
- [Review package](09-submission/ChronosAudit_TemporalClone_review-package.zip)
- [arXiv source package](09-submission/ChronosAudit_TemporalClone_arxiv-source.zip)
- [Acceptance-readiness decision](09-submission/acceptance-readiness.md)
- [Accountable human approval gate](09-submission/human-approval.md)

## Repository map

| Path | Contents |
|---|---|
| `00-governance/` | Intake, provenance, verification, decisions, and program controls |
| `01-novelty/` | Search protocol, prior-art evidence, novelty matrix, and independent challenge |
| `02-feasibility/` | Feasibility decision, maturity ladder, risks, and pilot records |
| `03-design/` | Protocol, estimands, algorithms, analysis plan, and precision rationale |
| `04-data/` | Evidence status, source rights, and provenance manifests |
| `05-analysis/` | Deterministic analysis code, tests, results, and validation records |
| `06-visuals/` | Editable diagrams, figure sources, tables T1-T8, and visual provenance |
| `07-manuscript/` | Manuscript sources, bibliography, generated figures, and compiled draft |
| `08-validation/` | Killer-question ledger, independent review surfaces, and remediation log |
| `09-submission/` | PDF, DOCX, arXiv/review bundles, venue checks, and submission QA |

## Reproduce the analysis

The analysis is deterministic, uses Python's standard library, and performs no network requests.

```bash
python3 -m unittest discover -s 05-analysis/code -p 'test_*.py'
python3 05-analysis/code/derive_mpp_results.py \
  --cases-dir <frozen-cases-directory> \
  --output-dir 05-analysis/results \
  --provenance-manifest 04-data/provenance-manifest.csv
python3 05-analysis/code/build_tables.py \
  --summary 05-analysis/results/results-summary.json \
  --output-dir 06-visuals/tables \
  --results-dir 05-analysis/results
python3 05-analysis/code/build_figures.py \
  --summary 05-analysis/results/results-summary.json \
  --cases 05-analysis/results/analysis_cases.csv \
  --output-dir 06-visuals/figures
```

The row-level upstream case envelopes are referenced by the provenance manifest but are not redistributed here while the source-rights gate remains open. See [the reproducibility report](05-analysis/reproducibility-report.md) and [analysis replay report](09-submission/analysis-replay-report.md) for the exact evidence boundary and recorded checks.

## Current release status

The analysis, manuscript, figures, tables, algorithms, PDF, DOCX, and submission bundles are mechanically complete. The research program intentionally remains at `INTAKE`, and the package is not yet authorized for public release or journal submission. Independent novelty challenge, independent clean-machine reproduction, author metadata and declarations, redistribution-rights review, license selection, and accountable human approval remain open. See [acceptance readiness](09-submission/acceptance-readiness.md) for the authoritative disposition.

No license is granted by the presence of this private repository. A public-release license must be selected only after the recorded rights review and accountable-author approval.
