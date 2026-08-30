# Minimum Publishable Prototype Execution Plan

## Frozen working title

**Auditing Temporal and Identity Dependence in SCONE-bench: Dual-Provider Historical State Reconstruction of 417 Smart-Contract Incidents**

## Publishable unit

This MPP is a retrospective benchmark-validity measurement study. It does not claim to predict exploits, estimate causal risk, validate a detector, or compare exploited contracts with matched controls. Its minimum publishable contribution is the joint audit of:

1. whether each benchmark contract existed at four prespecified pre-incident landmarks (1 hour, 24 hours, 7 days, and 30 days);
2. how apparent sample independence changes under chain-address, address-only, exact runtime-bytecode, and metadata-stripped runtime-bytecode identities; and
3. how often observable ERC-1967 implementation/beacon slots or ERC-1167 minimal-proxy targets reveal additional implementation linkage.

The 20,000-deployment denominator, unfinished 4,170 controls, AI adjudication, human review, and R0-R5 detector artifacts are excluded from the primary evidence. They may be mentioned only as provenance or future work.

## Minimum artifact bundle

| Bundle element | Required output | Acceptance condition |
| --- | --- | --- |
| Frozen input | `04-data/provenance-manifest.csv` | Exactly 417 unique verified cases; SHA-256 per source envelope |
| Protocol | `03-design/protocol.md` and `analysis-plan.md` | Outcomes, identity rules, estimands, exclusions, and stop rules fixed |
| Executable analysis | `05-analysis/code/derive_mpp_results.py` plus tests | Standard-library derivation; invalid evidence fails closed; fresh tests pass |
| Primary results | CSV and JSON under `05-analysis/results/` | Deterministic rerun yields identical hashes |
| Tables | Editable T1-T8 CSV/TeX sources | Units, denominators, uncertainty, and claim boundary explicit |
| Figures | PDF/SVG/PNG plus source CSV and code | Vector master, accessible redundant encoding, inspected at final size |
| Diagrams/algorithms | Mermaid source and LaTeX pseudocode | Source-controlled, legible, no evidentiary overclaim |
| Manuscript | Venue-neutral LaTeX and PDF | Claims trace to tables/figures; citations resolve; limitations explicit |
| Review package | Killer-question and claim-evidence ledgers | Critical unknowns and human/venue gates visible |
| Submission package | Checksums, README, cover letter, checklist | Mechanically complete; human approval still required |

## Ten-working-day route

| Day | Output | Go/no-go gate |
| --- | --- | --- |
| 1 | Scope/title freeze, source manifest, deterministic test harness | All 417 inputs validate; otherwise stop and repair provenance |
| 2 | Frozen temporal/identity/proxy definitions and primary derivation | Rerun hashes identical; otherwise no manuscript numbers |
| 3 | Prior-art search, strongest-predecessor matrix, claim narrowing | No direct predecessor defeats the joint measurement contribution |
| 4 | Feasibility, rights, ethics, and data-release disposition | No blocked data-rights or integrity gate for the chosen release scope |
| 5 | Primary, robustness, negative-result, and boundary tables | Every value machine-derived from frozen inputs |
| 6 | Figures, workflow, architecture, and algorithms | Source data and transformation provenance preserved |
| 7 | Full manuscript draft and verified bibliography | Every central claim maps to evidence and a limitation |
| 8 | Adversarial review, statistical and reproducibility audit | No unresolved critical scientific failure in the narrow claim |
| 9 | Venue-format adaptation, PDF and anonymity QA | Current official venue rules checked and mechanical checks pass |
| 10 | Accountable author review and upload rehearsal | Human authorship, declarations, licensing, and portal preview approved |

## Accelerated calendar used for this bundle

| Date | Deliverable | State at handoff |
| --- | --- | --- |
| 28 Aug 2026 | Scope freeze and isolated schema-v4 case | Complete locally |
| 29 Aug 2026 | Analysis, tests, T1--T8, figures, diagrams, algorithms | Complete locally |
| 29--30 Aug 2026 | Full manuscript, citations, PDF, review and submission ledgers | Complete locally on 29 Aug |
| 31 Aug--1 Sep 2026 | Independent search challenge and clean-machine replay | External gate; not completed by Codex |
| 1--2 Sep 2026 | Author metadata, declarations, rights, license, final content approval | Human gate |
| 3 Sep 2026 | Platform preview and human upload | Human action; not performed |

The accelerated path does not compress or waive scientific independence, rights, or accountable-author decisions.

## Fastest responsible submission route

1. Produce a venue-neutral archival preprint package first.
2. After accountable-author review, submit the same evidence-bounded manuscript to arXiv (`cs.CR`, with a suitable secondary category if permitted).
3. Select the peer-reviewed venue from the dated venue portfolio only after checking article fit, length, open-access charge, anonymity, and artifact rules.

An AI-generated package is not itself authorized for upload. Author identity, authorship order, affiliation, conflicts, funding, AI-use disclosure, venue choice, and the final submit action remain human decisions.

## Stop rules

- Stop or reframe if a direct predecessor already reports the same joint audit on the same 417-case cohort.
- Stop publication claims if the 417-case input manifest or deterministic rerun fails.
- Narrow to an internal technical report if source redistribution rights do not cover the proposed bundle.
- Do not introduce the unfinished controls or AI reliability results merely to make the paper look larger.
- Do not claim independent replication, causal validity, exploit prediction, or field effectiveness.
