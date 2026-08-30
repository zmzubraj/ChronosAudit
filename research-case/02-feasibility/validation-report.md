# FEASIBILITY_GATE validation report

- Run ID: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Date: `2026-08-01`
- Integrated benchmark-core decision: `PILOT_FIRST`
- Current phase after cycle-3 outcome binding: `FEASIBILITY_GATE`, attempt 6
- Prospective extension: `BLOCKED`

## Independent review history

| Attempt | Verification ID | Verdict | Disposition |
|---|---|---|---|
| 1 | `FEAS-A1-INDEPENDENT-CHALLENGE-001` | `REMEDIATE` | Decision-target, status-vocabulary, and cross-scope criteria defects corrected. |
| 2 | `FEAS-A2-INDEPENDENT-CHALLENGE-002` | `PASS` | Remediated pre-pilot package passed; pilot execution remained required. |
| 3 | `FEAS-A3-PILOT-REASSESSMENT-001` | `PASS WITH AMBER HOLD` | Executed public-data pilot supports continued benchmark-core feasibility work, but not promotion to `STUDY_DESIGN`. |
| 4 | `FEAS-A4-CYCLE2-REASSESSMENT-001` | `REMEDIATE / PILOT_FIRST` | Cycle-2 claims are proportionate, but `0/5` real cases are split-eligible, no mature-negative case is directly demonstrated, and archive routes remain unexecuted. |
| 5 | `FEAS-A5-CYCLE3-REASSESSMENT-001` | `REMEDIATE / PILOT_FIRST` | The route was executed unsuccessfully, `CA-P04` remains incomplete, and `CA-P09` is prespecified but right-censored until follow-up and independent adjudication close. |

Cycle 2 integrated new provenance, formal-binding, and access-cost evidence
into the canonical feasibility package. Cycle 3 then exercised the separately
authorized two-read route, froze `CA-P09`, and obtained an independent bounded
gate check. Root integration retained only evidence-proportionate findings.

## Validation basis through attempt 5

- Canonical pilot evidence:
  - `02-feasibility/pilot-results.md`
  - `02-feasibility/feasibility-report.md`
  - `02-feasibility/pilot-plan.md`
  - `02-feasibility/progression-criteria.csv`
  - `02-feasibility/risk-register.csv`
- Independent bounded challenge:
  - `02-feasibility/support/independent-assignment-rerun-20260801.md`
  - read-only cycle-2 gate recheck by `/root/chronosaudit_cycle2_rapid_gate_check`
- Cycle-2 evidence:
  - `02-feasibility/support/pilot-cycle2-public-provenance.md`
  - `02-feasibility/support/admissibility-manifest-pilot-cycle2.csv`
  - `02-feasibility/support/archive-access-cost-envelope-20260801.csv`
- Cycle-3 evidence:
  - `02-feasibility/support/pilot-cycle3-archive-access.md`
  - `02-feasibility/support/archive-test-ca-p04-cutoff.json`
  - `02-feasibility/support/archive-test-ca-p04-latest.json`
  - `02-feasibility/support/admissibility-manifest-pilot-cycle3.csv`
  - `02-feasibility/support/mature-negative-trial-cycle3.md`
  - `02-feasibility/support/mature-negative-candidate-binding.json`
  - `02-feasibility/support/independent-cycle3-gate-check-20260801.md`
- Governance chronology:
  - `00-governance/decision-log.md`

## Current benchmark-core criterion audit

| Criterion | Verdict | Direct evidence | Challenge note |
|---|---|---|---|
| `pilot_scope_freeze` | `GREEN` | bounded authority and exclusions are explicit in `pilot-plan.md` and `decision-log.md` | no scope drift found |
| `rights_ledger_coverage` | `GREEN FOR INTERNAL PILOT ONLY` | `pilot-results.md` limits use to metadata, local analysis, or repository-contained material and preserves unresolved redistribution rights | do not translate this to release rights or corpus-sharing rights |
| `manifest_completeness` | `AMBER` | cycle-3 manifest retains `3/8` complete for restricted fixture role, `0/5` split-eligible real incidents, and one status-trial-only row | `CA-P04` remains incomplete; benchmark-core green is blocked until a representative real-case slice closes all prediction-time fields |
| `split_rerun_stability` | `GREEN` | independent rerun leaves split eligibility unchanged for `8/8` rows | no stop condition triggered |
| `clone_pipeline_reproducibility` | `GREEN` | lexical clone rerun succeeds `2/2` with stable normalized hash | still narrower than benchmark-grade semantic source/bytecode cloning |
| `mechanism_status_rubric_operability` | `AMBER` | `CA-P08` remains right-censored; cycle 3 genuinely prespecifies `CA-P09`, but its earliest possible mature-negative adjudication is `2027-08-01T19:28:31Z` | prespecification is demonstrated, but mature-negative completion is not |
| `baseline_reproducibility` | `GREEN FOR SUBSTITUTE BASELINE ONLY` | `pilot-results.md` records `5/5` reproduced Slither stages | this is not a verified MANDO-LLM reproduction and cannot be described as equivalent |
| `cost_access_envelope` | `AMBER` | cycle 3 executed exactly two authorized public RPC reads; both failed at DNS before any HTTP or JSON-RPC response | execution status is measured, but operational historical-state access is still unproved |

## Prospective-extension audit

| Surface | Verdict | Basis |
|---|---|---|
| authority, partner, adjudication, freeze, and follow-up package | `BLOCKED` | `feasibility-report.md` and `risk-register.csv` keep the extension preregistration, disclosure, adjudication, and event-yield prerequisites unresolved |

## Material objections and corrections

1. Rights wording must stay narrow. The current evidence supports internal bounded pilot use only. It does not yet support blanket redistribution or public release of a mixed contract-source corpus.
2. The reproduced baseline is a lawful public substitute, not the intended frozen MANDO-LLM comparator. Any text implying baseline equivalence would overclaim.
3. `CA-P08` must remain `RIGHT_CENSORED_UNRESOLVED`. The formal proof targets Solidity `0.6.8`, the deployed exact-match artifact uses `0.6.11`, and no prospective follow-up window was frozen. The next cycle should use a genuinely prespecified mature-negative example rather than relabel this case.
4. Benchmark-core green is not established while real-case manifest completeness remains `0/5`, even though the pilot successfully demonstrated a restricted-role manifest and stable split rerun.
5. Cycle-2 support evidence narrows uncertainty and documents bounded access
   routes, but the independent attempt-4 recheck promotes no amber criterion to
   green and does not reopen `STUDY_DESIGN`.

## Mechanical checks

| Check | Result |
|---|---|
| Structural checker | `PASS` at `FEASIBILITY_GATE` |
| Strict checker after assurance-schema migration | `FAIL` for exactly four transparent blockers: one open `PILOT_FIRST` invalidation plus the three explicitly `MISSING` historical novelty-assurance artifacts |
| Canonical registry contract | `PASS` after removing eight noncanonical support-file rows; the support evidence itself remains preserved and indexed |
| Progression criteria parse | `9` rows; `8` benchmark-core blockers; `1` prospective-only criterion |
| Risk register parse | `23` rows |

## Lowest defensible decision

- Benchmark core: `PILOT_FIRST`
  - reason: the three pilot cycles demonstrate bounded feasibility, but three benchmark-core blockers remain below green: `manifest_completeness`, `mechanism_status_rubric_operability`, and `cost_access_envelope`
- Prospective extension: `BLOCKED`
  - reason: no partner, adjudication, disclosure, follow-up, or freeze package exists

## Cycle-2 independent recheck

- Integrated cycle-2 evidence: `support/pilot-cycle2-public-provenance.md`,
  `support/admissibility-manifest-pilot-cycle2.csv`,
  `support/archive-access-cost-envelope-20260801.csv`
- Root interpretation: cycle 2 improved provenance specificity and bounded the
  access-cost question, but left all five real cases `HOLD_RECOVERABLE` and
  resolved `CA-P08` conservatively to `RIGHT_CENSORED_UNRESOLVED`
- Attempt-4 result: `REMEDIATE / PILOT_FIRST`; criterion states are
  `AMBER`, `GREEN`, `AMBER`, and `AMBER` for manifest completeness, split
  rerun, mechanism/status, and cost/access respectively.
- The reviewer noted that the manifest-completeness row in
  `progression-criteria.csv` states the green target while observed evidence is
  only `3/8` restricted-role complete and `0/5` real-case split-eligible. This
  is not an evidence contradiction: the criteria file is the frozen threshold
  contract, while `pilot-results.md` records the observed amber result.
- Consequence: the integrated feasibility decision stays `PILOT_FIRST`.

## Orchestration-schema migration audit

The local schema-v2 checker now requires assurance fields and canonical cells/artifacts that were added after this run was initially scaffolded. The run was migrated by adding the non-weakenable assurance policy, `solution_viability_status=ASSERTED_ONLY`, `acceptance_readiness=NOT_ASSESSABLE`, `postdoctoral_ai_audit=UNASSESSED`, the four newly required cells, and explicit registry rows for all newly canonical artifacts.

- Structural validation: `PASS`.
- Strict validation: `FAIL` for four transparent reasons only:
  - an open `PILOT_FIRST` invalidation is expected while feasibility remains in progress;
  - `01-novelty/novelty-claim-specification.md` is `MISSING`;
  - `01-novelty/search-coverage.csv` is `MISSING`;
  - `01-novelty/independent-search-challenge.md` is `MISSING`.
- The missing novelty-assurance artifacts were not retroactively fabricated or relabeled from older evidence.
- Current-phase solution-viability artifacts were added as `DRAFT`; their status remains `ASSERTED_ONLY` and they do not promote feasibility.

## Smallest next evidence cycle

1. Under separate authority, exercise one lawful fallback archive or equivalent historical binding and complete at least one representative real-case manifest without post-cutoff leakage.
2. Keep `CA-P09` frozen; collect only its prespecified evidence snapshots and require independent adjudication after the full follow-up window. Do not relabel `CA-P08` or prematurely mature `CA-P09`.
3. Replace the measured DNS failure with measured historical-state coverage, runtime, units, terms, and explicit exclusions only if a separately authorized route succeeds.

## Conclusion

The bounded public-data pilot cycles succeeded as feasibility probes and should be preserved. They do not justify promotion to `STUDY_DESIGN`, and they do not reopen the prospective extension.

## Cycle-3 independent recheck

- Independent artifact: `support/independent-cycle3-gate-check-20260801.md`
- Verification ID: `FEAS-A5-CYCLE3-REASSESSMENT-001`
- Verdict: `REMEDIATE`
- Criterion states: `AMBER`, `GREEN`, `AMBER`, `AMBER` for manifest
  completeness, split rerun, mechanism/status, and cost/access respectively.
- Required challenge findings:
  - the DNS failures are `EXECUTED_UNSUCCESSFUL`, not successful RPC evidence;
  - `CA-P04` is not complete and remains `HOLD_RECOVERABLE`;
  - `CA-P09` is genuinely prespecified but cannot be called mature before
    `2027-08-01T19:28:31Z` plus independent closeout.
- Denominator ruling: while right-censored, `CA-P09` is status-trial-only and is
  excluded from benchmark-core manifest-completeness and mature-negative
  denominators.
- Bound outcome: `PILOT_FIRST`; `STUDY_DESIGN` remains closed and the
  prospective extension remains `BLOCKED`.
