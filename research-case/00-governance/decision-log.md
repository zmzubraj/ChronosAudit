# Decision Log

Append decisions; never overwrite history. Record timestamp, owner, phase, decision, evidence hashes, alternatives, consequence, rollback condition, and human authority when required.

## 2026-08-01T11:00:00Z — Intake authority and confidentiality boundary

- Owner: root-integration-owner
- Phase: INTAKE
- Decision: Accept the six-field intake as the sole revision-1 contract and authorize public-source, read-only research plus local artifact creation. Preserve novelty and feasibility as `E1 ASSERTED`.
- Evidence: `00-governance/intake-original.md`; `00-governance/intake.json`; `00-governance/program-charter.md` (hashes recorded in the artifact registry after mechanical verification).
- Alternatives considered: treat all authority as unresolved and stop; authorize live-chain scanning or prospective deployment. Both were rejected because the user's request authorizes a research program but does not provide the separate institutional, disclosure, data-rights, or operational authority needed for irreversible execution.
- Consequence: novelty and feasibility phases may use public sources. No scraping, live target scanning, exploit execution against third parties, nonpublic-data processing, prospective deployment, recruitment, procurement, external sharing of sensitive material, or submission is authorized.
- Rollback condition: any material intake revision, newly identified confidential source, credible legal or safety restriction, or user withdrawal of authority invalidates the earliest affected phase.
- Human authority: the requesting user retains final approval; identity and institutional authority are not independently verified.

## 2026-08-01T11:15:40Z — INTAKE

- Owner: root-integration-owner
- Decision: PROCEED
- Evidence: 00-governance/intake-original.md [sha256:e7e2c21c831851cf40b800af2b7ab3a3a621cf6b7820ba392604de18aa80e7f1], 00-governance/intake.json [sha256:c7d5bbee1eb0bbaf8c770b621df898cd459c99b2cf1cb9ba73054eae2e8a3737], 00-governance/program-charter.md [sha256:80726a8931b7c9d342070e9f55b53e130dd7b006a7e66ff2f53abf0ec2bbc7d6]
- Consequence: Advanced to NOVELTY_AUDIT.

## 2026-08-01T16:13:49Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; downstream gates and evidence are stale. Reason: NOVELTY_UNRESOLVED: The bounded search defeats most component-level novelty but leaves the joint-protocol claim only potentially differentiating. Required independent citation challenge could not complete after preserved model, non-productivity, and account-usage-limit failures; patent/standards and alternate-vocabulary coverage remain open. Do not advance.

## 2026-08-01T16:13:49Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/causal-model.mmd [sha256:eb7826a0c7e3fb576480e3923ea6e33b785650b605c4d956a68e4a15595e9d34], 01-novelty/problem-investigation.md [sha256:9f2a33dbd9bdb2c0f6bb18670b8138b8ace5281bad4c8205222501e09d6ec56c]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T16:29:33Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; downstream gates and evidence are stale. Reason: NOVELTY_UNRESOLVED: Attempt-2 independent citation challenge found one material overclaim (PA029), several metadata corrections, and unresolved patent/standards/proprietary coverage. Preserve only the narrow joint-protocol hypothesis and reopen novelty for targeted remediation and independent recheck.

## 2026-08-01T16:29:33Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/citation-audit.md [sha256:28cd486c5df64cd66832f88da3ddc72ff22e2601b71d3dd9a6439836160cee67]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T16:46:04Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; downstream gates and evidence are stale. Reason: NOVELTY_UNRESOLVED: Attempt-3 independent audit found the narrow joint hypothesis provisionally survives, but PA031 and PA032 misclassify standards as S8 prospective evidence and PA033 uses a dead URL with unsupported version-history wording. Correct and independently recheck before advancement.

## 2026-08-01T16:46:04Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/citation-audit.md [sha256:ce9f292f8b02bc7f8204ee0503d3fd99de75438b343031c24aaf78cd84c67f98]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T16:49:56Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_SURVIVES
- Evidence: 01-novelty/candidate-portfolio.md [sha256:24cd1d665f06f695b44bea4c90e3b39b6e8a86cea1ba28b5ed92633875070d04], 01-novelty/causal-model.mmd [sha256:eb7826a0c7e3fb576480e3923ea6e33b785650b605c4d956a68e4a15595e9d34], 01-novelty/citation-audit.md [sha256:ee1b4263074f83e2b6caa63dd5ba006c94eb2fc7b300d6afe106b6a52822897e], 01-novelty/evidence-ledger.csv [sha256:808d58f83426a94608f36bbe289b42cafc717724ebe4b647a888407ac6a13615], 01-novelty/novelty-matrix.csv [sha256:9b59e0c274df26caf6e1101a6019531da81cbb63740ceb82bc265299af6805da], 01-novelty/problem-investigation.md [sha256:9f2a33dbd9bdb2c0f6bb18670b8138b8ace5281bad4c8205222501e09d6ec56c], 01-novelty/search-protocol.md [sha256:2973369f415ccdcd28c631a423473d26925f6f35652d71e95773941d2cdb1061]
- Consequence: Advanced to FEASIBILITY_GATE.

## 2026-08-01T17:19:28Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from FEASIBILITY_GATE; downstream gates and evidence are stale. Reason: PILOT_FIRST: Independent challenge FEAS-A2-INDEPENDENT-CHALLENGE-002 passes the remediated gate package. The retrospective benchmark core still lacks direct pilot evidence for admissibility-manifest rerunnability, source-rights coverage, maturity-rule operability, archival provenance, and frozen-baseline reproduction. The prospective extension remains blocked by authority, disclosure, adjudication, yield, freeze, and governance prerequisites. Pilot execution is not authorized by the current charter.

## 2026-08-01T17:19:28Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: PILOT_FIRST
- Evidence: 02-feasibility/feasibility-report.md [sha256:8502b431ad4e00259849b1a67988a4a0d6772f704be0970377c6c673d86cf7f5], 02-feasibility/pilot-plan.md [sha256:5d9c545a6611f7d33b7ed030c1f57dd6932e92a0b4cdfad8c852fff539009d95], 02-feasibility/progression-criteria.csv [sha256:781765af65733f7f30653cda792c9e750009f6ea5af19a3496b0e3000c5dfc04], 02-feasibility/risk-register.csv [sha256:fe0948e49ba494676426b7b34deb74c7f9c2277aabf249feb52508ca1b0d5756]
- Consequence: Freeze pilot authority, protocol, and green/amber/red criteria; run only the authorized feasibility pilot, then reassess feasibility.

## 2026-08-01T19:45:56Z — CONTROL POINTER CORRECTION

- Owner: root-integration-owner
- Decision: ADMINISTRATIVE_CORRECTION; no scientific gate change
- Evidence: `program-state.json` remains at `FEASIBILITY_GATE`, attempt 6, with `last_gate_outcome=PILOT_FIRST`
- Correction: the auto-generated consequence in the immediately preceding entry is superseded only for next-action wording. The valid next action is to await separate authority for one lawful fallback archive or equivalent historical binding while keeping `CA-P09` frozen for its prespecified snapshots and independent closeout. `STUDY_DESIGN` remains closed and the prospective extension remains `BLOCKED`.

## 2026-08-01T19:58:20Z — Continuation authority and novelty-assurance reopening

- Owner: root-integration-owner
- Authority interpretation: the user authorized continued autonomous work inside the existing public-source research program but did not authorize another archive, RPC, paid-provider, account, transaction, exploit, scan, disclosure, or prospective-deployment action.
- Preserved boundary: `CA-P09` remains byte-for-byte frozen under its existing target, properties, evidence snapshots, follow-up window, endpoints, denominators, and independent-adjudication contract.
- Decision: invalidate from `NOVELTY_AUDIT` solely to complete the schema-v2 assurance artifacts honestly: an explicitly retrospective claim specification, an evidence-preserving search-coverage reconstruction, and a newly independent public-source search challenge.
- Consequence: downstream feasibility evidence is preserved but `STALE`; the inherited `PILOT_FIRST` result and prospective `BLOCKED` boundary are not promoted or weakened. No archive access is attempted in this cycle.

## 2026-08-01T18:04:08Z — Assurance-schema migration disposition

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: migrate the continuing schema-v2 run to the orchestrator's current non-weakenable assurance contract without manufacturing retroactive evidence.
- Added state controls: `solution_viability_status=ASSERTED_ONLY`, `acceptance_readiness=NOT_ASSESSABLE`, `postdoctoral_ai_audit=UNASSESSED`, and the current assurance policy.
- Added orchestration cells: independent prior-art search challenge, solution viability, postdoctoral-standards challenge, and acceptance readiness.
- Added registry rows: all newly canonical artifacts, explicitly `MISSING` where the historical run did not produce them. Current-phase solution-viability artifacts were created as `DRAFT` and do not promote the gate.
- Validation: the structural checker passes. Strict validation remains intentionally open because `PILOT_FIRST` preserves one current invalidation and three newly required novelty-assurance artifacts remain `MISSING` rather than being retroactively fabricated.
- Consequence: scientific disposition remains `PILOT_FIRST`; the migration does not upgrade novelty, feasibility, maturity, validation, or acceptance readiness.

## 2026-08-01T17:29:07Z — Public-data feasibility-pilot authority

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: Accept the requesting user's explicit confirmation as human authorization to execute the already frozen, bounded, public-data-only benchmark-core feasibility pilot and as an `E1 ASSERTED` confirmation that ordinary local compute and public-source access may be used.
- Evidence: user continuation instruction dated 2026-08-01; `02-feasibility/pilot-plan.md`; `02-feasibility/progression-criteria.csv`.
- Scope: manual public-source retrieval and local analysis needed to test source/access coverage, manifest completeness, split rerun stability, clone-pipeline reproducibility, mechanism/status rubric operability, baseline reproducibility, and the cost/access envelope.
- Source-rights rule: authorization does not establish third-party ownership or redistribution rights. Every source must receive a source-specific rights/access disposition before use; unresolved rights exclude that source or limit it to link-and-metadata citation.
- Resource rule: the user's confirmation is not evidence that a paid archive endpoint, proprietary dataset, disclosure partner, adjudicator, or specialist is available. Actual tools, disk, compute, provider access, and cost assumptions must be measured or remain `AT RISK`/`BLOCKED`.
- Exclusions: no automated scraping; no live-target scanning; no transaction submission; no exploit against a third party; no nonpublic vulnerability material; no private keys; no partner data; no disclosure outreach; no human-participant activity; no prospective cohort or shadow deployment; no submission.
- Stop conditions: preserve the existing green/amber/red criteria; stop any source or execution slice with unresolved critical rights, unsafe code, unavailable provenance, nonpublic dependency, or material scope drift.
- Consequence: the benchmark-core feasibility pilot may run. `STUDY_DESIGN` remains closed until pilot results and the pilot plan are independently verified and the feasibility gate advances with `GO`.
- Rollback condition: user withdrawal, new legal/security restrictions, unavailable critical sources, failed independent rerun, or a red progression criterion.

## 2026-08-01T18:02:49Z — Pilot wave 1 rights/access/resource disposition

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: keep the benchmark-core feasibility pilot `IN PROGRESS`, but do not advance to executable corpus assembly or baseline reproduction yet.
- Evidence: `02-feasibility/pilot-results.md`; public primary sources checked on 2026-08-01 for Sourcify, SmartBugs Curated, DeFiHackLabs, Slither, Foundry, the public MANDO-LLM repository, and GitHub's licensing guidance.
- Findings:
  - public metadata, docs, and some repository-contained artifacts are usable under the bounded pilot authority
  - contract-source redistribution rights remain mixed and source-specific
  - the public MANDO-LLM repository does not yet provide a verified executable-baseline path with a clear retrievable license from the checked sources
  - local compute/storage are adequate for a small pilot, but `slither` and `solc` are not currently installed and archival-access cost remains unresolved
- Consequence:
  - first-wave status is `pilot_scope_freeze=GREEN`, `rights_ledger_coverage=AMBER`, `cost_access_envelope=AMBER`
  - no exact pilot cohort is frozen yet
  - no shareable benchmark corpus, no broad contract-source ingestion, and no MANDO-LLM baseline execution are currently authorized
- Next smallest responsible step: freeze an exact lawful cohort using metadata-only or individually license-cleared cases, then run codebase security preflight before any newly cloned/downloaded repository is executed.

## 2026-08-01T17:52:10Z — Pilot evidence integration and chronology correction

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: accept the independently rechecked evidence content from the source-rights, risk, and assignment specialists into the canonical pilot package, while preserving the root integration owner as the sole phase-decision authority.
- Chronology correction: the preceding wave-1 entry carries `2026-08-01T18:02:49Z`, a specialist-supplied timestamp that is later than the actual integration time. It is retained because the decision log is append-only. This entry records the authoritative integration chronology.
- Lease correction: the source-rights specialist and the assignment-rerun specialist wrote supporting material outside their read-only return contracts. Root inspected the resulting changes, retained only evidence that matched primary-source or local execution checks, and integrated the accepted content. No specialist decision independently promoted the gate.
- Superseded provisional findings: the wave-1 statements that no exact cohort and no executable substitute baseline were frozen are historical first-wave findings only. Pilot cycle 1 subsequently froze an eight-case cohort and reproduced a pinned Slither substitute baseline after static preflight.
- Independent rerun: split eligibility remained unchanged for `8/8`; `CA-P08` was conservatively reassigned from `MATURE_INVESTIGATED_NEGATIVE` to `RIGHT_CENSORED_UNRESOLVED` in the bounded evidence packet, without changing its `HOLD_RECOVERABLE` split status.
- Consequence: the benchmark-core gate remains `PILOT_FIRST`. `STUDY_DESIGN` stays closed because manifest completeness, mechanism/status operability, and archive cost/access remain amber. The prospective extension remains blocked.

## 2026-08-01T17:49:55Z — Pilot wave 2 execution and independent rerun disposition

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: keep `PILOT_FIRST` in force after bounded public-data pilot execution and independent reassessment.
- Evidence: `02-feasibility/pilot-results.md`; `02-feasibility/feasibility-report.md`; `02-feasibility/pilot-plan.md`; `02-feasibility/support/independent-assignment-rerun-20260801.md`.
- Findings:
  - a frozen eight-case information-sufficiency cohort, restricted-role admissibility manifest, narrow lexical clone rerun, and public substitute baseline were all executed under the authorized public-only boundary
  - split eligibility remained unchanged for `8/8` rows under independent rerun
  - real-case manifest completeness remains `0/5`, so no real observation is yet split-eligible
  - `CA-P08` remains the only localized independent disagreement: the bounded packet does not yet justify `MATURE_INVESTIGATED_NEGATIVE`, so the safer challenge status is `RIGHT_CENSORED_UNRESOLVED`
  - `manifest_completeness`, `mechanism_status_rubric_operability`, and `cost_access_envelope` remain below green
- Consequence:
  - benchmark-core `STUDY_DESIGN` remains closed
  - the smallest responsible next cycle is archival provenance and version-binding recovery for the five real cases plus a narrow follow-up rerun on the affected `CA-P08` status slice
  - the prospective extension remains blocked and was not reconsidered here
- Rollback condition: any newly recovered archival evidence that changes split eligibility or resolves the `CA-P08` status dispute reopens only the affected feasibility slice; any new rights, safety, or provenance blocker reopens the earliest affected feasibility surface.

## 2026-08-01T17:55:46Z — FEASIBILITY_GATE pilot-cycle integration decision

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 2
- Decision: reaffirm `PILOT_FIRST` for the benchmark core and keep the prospective extension `BLOCKED`.
- Evidence: `02-feasibility/feasibility-report.md`; `02-feasibility/pilot-plan.md`; `02-feasibility/pilot-results.md`; `02-feasibility/progression-criteria.csv`; `02-feasibility/risk-register.csv`; `02-feasibility/validation-report.md`; `02-feasibility/support/independent-assignment-rerun-20260801.md`.
- Findings:
  - the pilot produced positive feasibility evidence for scope freeze, split-rerun stability, clone-rerun stability, and a lawful substitute baseline path
  - the pilot did not produce benchmark-core green because real-case manifest completeness remains `0/5`, `CA-P08` remains unresolved for mature-negative proof, and archival cost/access remains only partially measured
  - rights coverage remains green only for the internal bounded pilot path and must not be restated as a corpus-release right
  - the substitute Slither baseline must not be described as equivalent to the intended MANDO-LLM comparator
- Consequence:
  - `STUDY_DESIGN` remains closed
  - the next evidence cycle is limited to archival provenance recovery for the five real cases, `CA-P08` version-binding and follow-up-evidence recovery, and a rerun of only the affected status slice
  - the prospective extension remains outside the authorized serial path
- Rollback condition: any recovered prediction-time provenance or mature-negative binding that changes split eligibility or closes the `CA-P08` objection reopens only the smallest affected feasibility slice.

## 2026-08-01T17:58:52Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from FEASIBILITY_GATE; downstream gates and evidence are stale. Reason: PILOT_FIRST: Executed public-data pilot cycle 1 demonstrates bounded benchmark-core feasibility but does not establish benchmark-core green: manifest completeness remains 0/5 for real observations, CA-P08 remains unresolved for mature-negative proof, and archival cost/access remains only partially measured. The prospective extension remains blocked by partner, adjudication, disclosure, freeze, and follow-up prerequisites.

## 2026-08-01T17:58:52Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: PILOT_FIRST
- Evidence: 02-feasibility/feasibility-report.md [sha256:293acebaa7c9c84acbea99557545a1419bd8314e9b964345c215e6b90f5d1c33], 02-feasibility/pilot-plan.md [sha256:20867c150af54090d5a00ae68013d9f315f591c7926106f7be2304f19e2c41ff], 02-feasibility/pilot-results.md [sha256:076d9385142678c6b707f5e8abc16ab499b31486268e7578fc61135430da15f7], 02-feasibility/progression-criteria.csv [sha256:781765af65733f7f30653cda792c9e750009f6ea5af19a3496b0e3000c5dfc04], 02-feasibility/risk-register.csv [sha256:55731ab4de71ee629dedf8f146aee9029cdc888ddf65d82c4ddfbb5c548463c8]
- Consequence: Freeze pilot authority, protocol, and green/amber/red criteria; run only the authorized feasibility pilot, then reassess feasibility.

## 2026-08-01T18:03:43Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from FEASIBILITY_GATE; downstream gates and evidence are stale. Reason: PILOT_FIRST: Pilot cycle 1 and independent challenge FEAS-A3 show bounded benchmark-core feasibility but not green: 0/5 real observations are split-eligible, CA-P08 remains right-censored unresolved in the independent packet, and archival access/cost remains only partially measured. The next cycle is limited to public prediction-time provenance, CA-P08 evidence binding, and measured archival access. The prospective extension remains blocked.

## 2026-08-01T18:03:43Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: PILOT_FIRST
- Evidence: 02-feasibility/feasibility-report.md [sha256:293acebaa7c9c84acbea99557545a1419bd8314e9b964345c215e6b90f5d1c33], 02-feasibility/pilot-plan.md [sha256:20867c150af54090d5a00ae68013d9f315f591c7926106f7be2304f19e2c41ff], 02-feasibility/pilot-results.md [sha256:9bb63cdccf7df5546bb76e3efb8eb2e6add1c4e3efc48d3fb4cf66f148d22299], 02-feasibility/progression-criteria.csv [sha256:781765af65733f7f30653cda792c9e750009f6ea5af19a3496b0e3000c5dfc04], 02-feasibility/risk-register.csv [sha256:55731ab4de71ee629dedf8f146aee9029cdc888ddf65d82c4ddfbb5c548463c8]
- Consequence: Freeze pilot authority, protocol, and green/amber/red criteria; run only the authorized feasibility pilot, then reassess feasibility.

## 2026-08-01T18:04:08Z — Assurance-migration chronology note

- Owner: root-integration-owner
- Note: the full assurance-schema migration entry with this timestamp appears earlier in this append-only document because it was inserted beside an older matching gate-consequence line. No earlier decision text was deleted or rewritten. This trailing note preserves the actual integration order.

## 2026-08-01T18:30:24Z — Pilot cycle 2 evidence integration and independent recheck

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE, attempt 4
- Decision: accept the authorized public-data-only cycle-2 evidence package and retain `PILOT_FIRST`; keep the prospective extension `BLOCKED`.
- Evidence: `02-feasibility/pilot-results.md`; `02-feasibility/feasibility-report.md`; `02-feasibility/support/pilot-cycle2-public-provenance.md`; `02-feasibility/support/admissibility-manifest-pilot-cycle2.csv`; `02-feasibility/support/archive-access-cost-envelope-20260801.csv`; independent recheck `FEAS-A4-CYCLE2-REASSESSMENT-001`.
- Findings:
  - pre-cutoff deployment or primary documentation evidence was recovered for `CA-P04`–`CA-P07`, but none closes all source, bytecode-to-source, proxy, implementation, compiler, and lineage fields
  - `CA-P08` has strong pre-cutoff public provenance, but the formal proof targets Solidity `0.6.8` while the deployed exact-match artifact uses `0.6.11`; no prospective follow-up window was frozen, so it is `RIGHT_CENSORED_UNRESOLVED`
  - the cycle-2 manifest retains `0/5` split-eligible real observations and all five real cases as `HOLD_RECOVERABLE`
  - current free, trial, and paid archive routes are documented, but no account, API, RPC, BigQuery, replay, live-chain, or transaction action was executed
  - independent criterion disposition is `AMBER`, `GREEN`, `AMBER`, `AMBER` for manifest completeness, split rerun, mechanism/status, and cost/access respectively
- Contract correction: `/root/chronosaudit_cycle2_gate_reviewer` wrote a canonical refresh to `pilot-results.md` and `validation-report.md` outside its read-only return contract before being interrupted. Root inspected those changes, corrected superseded reviewer-status text, and retained only evidence-consistent, non-promoting content. The rapid replacement reviewer was read-only and completed the independent recheck.
- Consequence: no efficacy, utility, release-readiness, mature-negative, or prospective claim advances. `STUDY_DESIGN` remains closed.
- Smallest next cycle: exercise one separately authorized archive or equivalent public-data route; complete one representative real-case manifest end to end; and independently test a genuinely prespecified mature-negative example rather than relabeling `CA-P08`.
- Rollback condition: any new rights, safety, provenance, cost, or status-reproducibility blocker reopens only the smallest affected feasibility surface; any material cohort or rule change invalidates dependent evidence.

## 2026-08-01T18:12:34Z — Cycle-2 canonical feasibility-package refresh

- Owner: root-integration-owner
- Phase: FEASIBILITY_GATE
- Decision: preserve `PILOT_FIRST` and refresh the canonical feasibility package with cycle-2 support evidence only.
- Evidence: `02-feasibility/support/pilot-cycle2-public-provenance.md`; `02-feasibility/support/admissibility-manifest-pilot-cycle2.csv`; `02-feasibility/support/archive-access-cost-envelope-20260801.csv`; `02-feasibility/pilot-results.md`; `02-feasibility/validation-report.md`.
- Findings:
  - cycle 2 recovered bounded pre-cutoff deployment or documentation evidence for `CA-P04` through `CA-P07`, but no real case became split-eligible
  - `CA-P08` remains conservatively `RIGHT_CENSORED_UNRESOLVED` because the related formal artifact is pinned to Solidity `0.6.8` while the deployed exact-match artifact is Solidity `0.6.11`, and no prospectively frozen follow-up packet exists
  - archive/provider evidence now bounds the access-cost question, but no account, API, RPC, or BigQuery route was exercised
  - no differently owned cycle-2 gate reviewer completed a promotion-grade verdict before this refresh, so the latest completed independent feasibility verification remains `FEAS-A3-PILOT-REASSESSMENT-001`
- Consequence:
  - `STUDY_DESIGN` remains closed
  - benchmark-core blockers remain `manifest_completeness`, `mechanism_status_rubric_operability`, and `cost_access_envelope`
  - the prospective extension remains `BLOCKED`

## 2026-08-01T18:31:00Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from FEASIBILITY_GATE; downstream gates and evidence are stale. Reason: PILOT_FIRST: Pilot cycle 2 and independent recheck FEAS-A4-CYCLE2-REASSESSMENT-001 improve provenance specificity and bound archive-access options but do not establish benchmark-core green: 0/5 real observations remain split-eligible, CA-P08 is right-censored because the 0.6.8 proof does not exactly bind to the 0.6.11 deployed artifact and no follow-up was prospectively frozen, and all archive-provider routes remain unexecuted. The next cycle must complete one representative real-case manifest, exercise an authorized archive or equivalent public-data route, and independently test a genuinely prespecified mature-negative example. The prospective extension remains blocked.

## 2026-08-01T18:31:00Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: PILOT_FIRST
- Evidence: 02-feasibility/feasibility-report.md [sha256:a2db45e5c0be47a4368365c4fea5bc955b6f446b2071484ddc0afc364a9e8fae], 02-feasibility/pilot-results.md [sha256:b490cf0242e4c61ecb2d816ae8549ed2631862cfff7684980c6112be971cc0b2], 02-feasibility/progression-criteria.csv [sha256:781765af65733f7f30653cda792c9e750009f6ea5af19a3496b0e3000c5dfc04]
- Consequence: Freeze pilot authority, protocol, and green/amber/red criteria; run only the authorized feasibility pilot, then reassess feasibility.

## 2026-08-01T19:24:45Z — Pilot cycle 3 bounded authorization

- Owner: root-integration-owner
- Phase: `FEASIBILITY_GATE`, attempt 5
- Authority: the user separately authorized one minimal archive or equivalent public-data access test, followed by one representative end-to-end real-case manifest attempt and one genuinely prespecified mature-negative trial.
- Permitted scope: exactly two read-only `eth_getCode` requests for the known historical `CA-P04` address at cutoff block `4043798` and `latest` through one public/no-key route; preservation of the raw public responses and request provenance; integration of that evidence into a new immutable manifest revision; and design/freezing of one bounded public-data-only negative-status trial.
- Exclusions retained: no transaction submission or signing, private keys, live-target scanning, exploit execution or replay, broad or automated scraping, paid procurement, provider-account creation, proprietary or nonpublic data, outreach, partner workflow, human participants, responsible-disclosure execution, or prospective shadow deployment.
- Interpretation: this authority permits a feasibility observation and a prespecified trial protocol. It does not convert a newly frozen negative candidate into a mature negative before its follow-up window closes, establish source redistribution rights, or authorize phase promotion.
- Gate rule: `STUDY_DESIGN` remains closed unless every benchmark-core blocking criterion independently reaches green; the prospective extension remains `BLOCKED`.

## 2026-08-01T19:31:00Z — Pilot cycle 3 evidence integration and independent recheck

- Owner: root-integration-owner
- Phase: `FEASIBILITY_GATE`, attempt 5
- Decision: accept the bounded cycle-3 evidence and retain `PILOT_FIRST`; keep the prospective extension `BLOCKED`.
- Evidence: `02-feasibility/support/pilot-cycle3-archive-access.md`; two raw request/error JSON records; `02-feasibility/support/admissibility-manifest-pilot-cycle3.csv`; `02-feasibility/support/mature-negative-trial-cycle3.md`; `02-feasibility/support/mature-negative-candidate-binding.json`; independent recheck `FEAS-A5-CYCLE3-REASSESSMENT-001`.
- Findings:
  - both authorized `CA-P04` `eth_getCode` requests were attempted once and failed DNS before any HTTP or RPC response
  - the route is `EXECUTED_UNSUCCESSFUL`; the result measures this environment and does not imply general archive unavailability
  - `CA-P04` remains incomplete and `HOLD_RECOVERABLE`; real-incident split eligibility remains `0/5`
  - `CA-P09` freezes a deterministic target, three properties, four evidence snapshots, a 365-day window, outcome rules, and independent adjudication, but remains `RIGHT_CENSORED_UNRESOLVED` until at least `2027-08-01T19:28:31Z`
  - while right-censored, `CA-P09` is status-trial-only and excluded from benchmark-core completeness and mature-negative denominators
  - independent criterion disposition is `AMBER`, `GREEN`, `AMBER`, `AMBER` for manifest completeness, split rerun, mechanism/status, and cost/access respectively
- Consequence: no efficacy, utility, mature-negative, real-case completeness, release-readiness, or prospective claim advances. `STUDY_DESIGN` remains closed.
- Smallest next responsible actions: obtain separate authority for one lawful fallback or equivalent historical binding; complete one representative real-case manifest; execute the frozen `CA-P09` evidence snapshots and independent closeout without protocol changes.
- Rollback condition: any target, property, window, endpoint, denominator, rights, or adjudication change invalidates only the affected cycle-3 evidence and reopens the earliest affected feasibility surface.

## 2026-08-01T19:40:04Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from FEASIBILITY_GATE; downstream gates and evidence are stale. Reason: PILOT_FIRST: Pilot cycle 3 and independent recheck FEAS-A5-CYCLE3-REASSESSMENT-001 replace unexecuted assumptions with direct but non-promoting evidence: the authorized CA-P04 two-read route failed DNS before any RPC response, 0/5 real incidents remain split-eligible, and CA-P09 is genuinely prespecified but remains right-censored until at least 2027-08-01 plus independent adjudication. Manifest completeness, mechanism/status operability, and operational cost/access remain AMBER; the prospective extension remains BLOCKED.

## 2026-08-01T19:40:04Z — FEASIBILITY_GATE

- Owner: root-integration-owner
- Decision: PILOT_FIRST
- Evidence: 02-feasibility/pilot-results.md [sha256:05d80ac666f706ea26611edc6ecf193bfc23882ab127a006aae78f1943d7ce41], 02-feasibility/support/admissibility-manifest-pilot-cycle3.csv [sha256:cb84033c510ff38b02784ef0d507edd706819e02a53feda4a0bdfafe0befee73], 02-feasibility/support/independent-cycle3-gate-check-20260801.md [sha256:5dc9fdc9a2967da83cb06b54c882800297987aa2e879b24733d0ee21023fd0d8], 02-feasibility/support/mature-negative-trial-cycle3.md [sha256:1381d052635d80144c7e9811c04e9fccdb2b686e7a9b61c6e58f6e59e43f9ef5], 02-feasibility/support/pilot-cycle3-archive-access.md [sha256:89c2ef78ad021d07bdb1a024ebf294a54e87cd060f464dc3827d56d0c95081a4]
- Consequence: Freeze pilot authority, protocol, and green/amber/red criteria; run only the authorized feasibility pilot, then reassess feasibility.

## 2026-08-01T19:53:39Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; downstream gates and evidence are stale. Reason: Schema-v2 assurance migration requires an evidence-preserving, explicitly retrospective claim specification and search-coverage reconstruction plus a newly independent blinded search challenge. Existing feasibility evidence and CA-P09 remain preserved but cannot support downstream promotion until novelty assurance is rechecked.

## 2026-08-01T20:00:35Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-f42be3719557:REASSIGN
- Evidence: NONE
- Consequence: Execute recovery attempt 1 for REC-f42be3719557, then verify or replan.

## 2026-08-01T20:05:41Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-f42be3719557:REDESIGN
- Evidence: NONE
- Consequence: Execute recovery attempt 2 for REC-f42be3719557, then verify or replan.

## 2026-08-01T20:17:01Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; downstream gates and evidence are stale. Reason: NOVELTY_UNRESOLVED: Attempt-5 schema-v2 assurance cannot support progression. Two delegated discovery attempts failed with preserved recovery evidence; the successful specialist independently adjudicated only a root-authored six-query packet and explicitly could not certify independent search ownership. PA036-PA040 are verified new nonmaterial predecessors, and no equivalent joint protocol was found, so C001-JOINT remains POTENTIALLY_DIFFERENTIATING only as a bounded hypothesis. Historical screening counts and query attribution remain unreconstructable; citation-chain saturation, correction/retraction/contradictory-evidence search, patent-family, proprietary, subscription-index, and non-English coverage remain incomplete.

## 2026-08-01T20:17:01Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/citation-audit.md [sha256:3fce53f23b931a8562306d8a5608dc7cd9513d138c10d573c20285ba3a654eba], 01-novelty/evidence-ledger.csv [sha256:f7259654d8159a3d6caeb3e5e90ec16b28e12dd27debb448077527232d76d15d], 01-novelty/independent-search-challenge.md [sha256:f121d072fcb9993ee5f6d6e44a06e4f149a4236f183c7c3225889a6a4ed31c79], 01-novelty/novelty-claim-specification.md [sha256:cf8d0108445c57b406421d7fd593f76f2259b43efc81a3e2c2b6a2741a21bdc6], 01-novelty/novelty-matrix.csv [sha256:f9e98c47c6deaa5737a9850be93725c7ed32ee640cfe0e28e80757d1f303115e], 01-novelty/search-coverage.csv [sha256:b3023e7727606fa15a397e1e41179bc27857fc70cd21084432951bd9f0bc0d20]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T20:20:12Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-69793bc9f23c:WAIT_EXTERNAL
- Evidence: NONE
- Consequence: Wait for the named external condition, then resume REC-69793bc9f23c with verified evidence.

## 2026-08-01T20:24:05Z — NOVELTY_AUDIT

- Owner: user-authority
- Decision: AUTHORIZED_NOVELTY_SEARCH_RECOVERY
- Evidence: current task authorization recorded verbatim in the conversation context
- Authority granted: resume the materially different, independently owned scholarly and patent prior-art search; preserve exact queries, screening decisions, citation-chain and known-item checks, access limits, immutable logs, and independent adjudication
- Authority withheld: archive or RPC testing remains subject to separate authorization; no accounts, paid access, transactions, exploit execution, outreach, disclosure, or prospective deployment are authorized
- Consequence: record this authorization as canonical governance evidence, resume `REC-69793bc9f23c`, and execute the novelty recovery under a new bounded search and challenge ownership design

## 2026-08-01T20:24:29Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_EXTERNAL_CONDITION_RESOLVED:REC-69793bc9f23c
- Evidence: 00-governance/decision-log.md [sha256:fee81d7da39f0d2af49b4778c266edbc7a0acb95d40e99c9307d2795b899b550]
- Consequence: Execute resumed cell recovery REC-69793bc9f23c and verify its acceptance criteria.

## 2026-08-01T20:28:22Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-69793bc9f23c:REDESIGN
- Evidence: 00-governance/decision-log.md [sha256:2836ec032b9c0c9a4c059c7dc146cbfea15b47610904eac36f466628e78e93e5]
- Consequence: Execute recovery attempt 2 for REC-69793bc9f23c, then verify or replan.

## 2026-08-01T20:48:34Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; affected evidence is stale. Reason: NOVELTY_UNRESOLVED: Attempt-7 completed the canonical independently owned five-query scholarly/patent challenge with immutable counts-or-UNAVAILABLE, screening and retention logs, ten known-item recoveries, two-seed citation/author traversal, and reconciliation against PA001-PA040. No single equivalent joint protocol was verified, but every major ingredient has strong public precedent, the obvious-recombination and joint-nonredundancy objections remain unresolved, A7Q2/A7Q3/A7Q5 yielded no direct predecessor from their exact phrasing, PA014 remains metadata/abstract-bounded, and formal correction/retraction, subscription citation, patent-family, non-English, private, and proprietary coverage remains incomplete. C001-JOINT therefore remains POTENTIALLY_DIFFERENTIATING only; NOVELTY_SURVIVES is not supported.

## 2026-08-01T20:48:34Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/citation-audit.md [sha256:0436d13cadd3e6f1c76887968f4bf9550c0907d84dabc672e972b8bceecb881d], 01-novelty/independent-search-challenge.md [sha256:ab58cf4f3d3f2192a6d640a7d24867e42d316869af63871043580e3d2551fccc], 01-novelty/search-coverage.csv [sha256:3546b669af8797048ae5cdbed6cadbca3300a4bc1e393990a9ca5788dfa6c2d0], 01-novelty/search-protocol.md [sha256:8e431d4fb3e449ab56e34a6524063a316735fbee0037ce23c326bb85a70ff277]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T20:49:09Z — NOVELTY_AUDIT validation closeout

- Owner: root-integration-owner
- Independent search owner: `/root/chronosaudit_attempt7_canonical_challenge`
- Verification events: `NOV-A7-INDEPENDENT-SEARCH-VERIFY-001`, `NOV-A7-SEARCH-PROTOCOL-INTEGRATION-001`, `NOV-A7-SEARCH-COVERAGE-INTEGRATION-001`, `NOV-A7-CITATION-AUDIT-INTEGRATION-001`
- Recovery: `REC-69793bc9f23c` resolved by checkpoint `CP-89661137c017`; the failed broad-search checkpoint `CP-57947071f7cd` remains preserved.
- Schema migration: case migrated explicitly to schema v3, intake and study-profile semantics independently revalidated, and `migration_semantic_revalidation_required` cleared without scientific promotion.
- Structural checker: `PASS` at phase `NOVELTY_AUDIT` after the gate decision.
- Strict checker: one expected failure remains because the unresolved novelty decision intentionally leaves an open invalidation queue; no other strict issue remained.
- Authority boundary: public scholarly, patent-discovery, and standards evidence only. Archive/RPC access remained unauthorized and was not performed.
- Scientific disposition: `NOVELTY_UNRESOLVED`; `C001-JOINT` remains at most `POTENTIALLY_DIFFERENTIATING`.

## 2026-08-01T21:00:00Z — NOVELTY_AUDIT

- Owner: user-authority
- Decision: AUTHORIZED_C001_MEASUREMENT_REFRAME_AND_EXACT_MATCH_AUDIT
- Evidence: current task authorization recorded verbatim in the conversation context
- Authorized claim: A preregistered measurement study testing how much apparent exploit-detection capability survives the joint application of temporal, lineage, clone-family, mechanism-family, censoring, and operational-workload controls.
- Authority granted: reframe `C001` as a joint capability-survival measurement contribution and conduct one bounded, independently owned, public-source exact-match novelty audit with immutable query and screening logs.
- Authority withheld: no archive or RPC testing; no exploit execution, accounts, paid access, transactions, outreach, disclosure, private sources, or prospective deployment.
- Consequence: freeze the attempt-8 claim before search, run the independent audit, reconcile the result, rerun the research-case checker, and decide `NOVELTY_SURVIVES`, `NOVELTY_UNRESOLVED`, `REFRAME`, or `STOP`.

## 2026-08-01T21:07:42Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-5f3a50baa0d3:RETRY
- Evidence: NONE
- Consequence: Execute recovery attempt 1 for REC-5f3a50baa0d3, then verify or replan.

## 2026-08-01T21:09:54Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-5f3a50baa0d3:STOP
- Evidence: 01-novelty/independent-search-challenge.md [sha256:ab58cf4f3d3f2192a6d640a7d24867e42d316869af63871043580e3d2551fccc]
- Consequence: Preserve recovery REC-5f3a50baa0d3 and stop the affected scope.

## 2026-08-01T21:15:00Z — Control-state correction

- Owner: root-integration-owner
- Phase: NOVELTY_AUDIT
- Correction: the `STOP` mode chosen for cell recovery `REC-5f3a50baa0d3` correctly stops further autonomous exact-match search retries, but the recovery helper also set the entire program status to `STOPPED`. That program-wide effect was broader than the user-authorized and prespecified stop rule, which applied only to the affected search recovery.
- Existing authority: the current user instruction explicitly authorizes continuation of the same run for the reframed `C001-MEASUREMENT` audit and its gate decision. No new research scope is inferred.
- State correction: restore program status to `ACTIVE`; leave recovery `REC-5f3a50baa0d3` and cell `prior_art_search_challenge` stopped or blocked; proceed only to evidence integration, `NOVELTY_UNRESOLVED`, and case checking.
- Authority boundary: no further autonomous novelty search and no archive/RPC testing.

## 2026-08-01T21:16:21Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: INVALIDATED
- Evidence: NONE
- Consequence: Resume from NOVELTY_AUDIT; affected evidence is stale. Reason: NOVELTY_UNRESOLVED: Attempt-8 validly reframed C001 as a joint capability-survival measurement contribution and recovered no equivalent single predecessor, but the independently owned bounded audit failed its frozen reconstruction contract: query-level UTC/count/screened/retained/exclusion fields were missing, FinSurvival was unrecovered, one closest-work traversal and patent coverage were incomplete, and the pre-ledger freeze was not timestamped. Strong component precedents and obvious-recombination risk therefore remain. The prespecified stop rule prohibits another autonomous retry under this authorization.

## 2026-08-01T21:16:21Z — NOVELTY_AUDIT

- Owner: root-integration-owner
- Decision: NOVELTY_UNRESOLVED
- Evidence: 01-novelty/citation-audit.md [sha256:ba2a79b7acd63ec83511c007b4f09d55ddf2a6430ca9ab7b2e74b83fd25a1b73], 01-novelty/independent-search-challenge.md [sha256:d73eb3f3ad641c4323ceb59809c791669e153ce0267d39af05ab6e55432dc5b0], 01-novelty/novelty-claim-specification.md [sha256:7a073ad97300a9ec8bcf4fa528951799aaa3828e8970b2e9893011826486de91], 01-novelty/novelty-matrix.csv [sha256:5c84430a94dfaf6dd26a073b4dd0bf949d2f4483e5c4dc9cfc4575c63d261a72], 01-novelty/search-coverage.csv [sha256:b882f0afa6beaaefe0d2d7cc088a569a26f310d04f403d2c76a374755bcb2be0], 01-novelty/search-protocol.md [sha256:8b728842ad1aa4561479373b930fcc09f5f0ca7aae7e00e6920ce1a4242f8fcb]
- Consequence: Extend the reproducible prior-art search or obtain missing sources, then rerun the novelty audit.

## 2026-08-01T21:16:45Z — NOVELTY_AUDIT attempt-8 validation closeout

- Owner: root-integration-owner
- Authorized claim: `C001-MEASUREMENT`, the joint capability-survival measurement contribution.
- Independent search owner: `/root/chronosaudit_attempt8_exact_match_search`
- Independent verification owner: `/root/chronosaudit_attempt7_canonical_challenge`
- Search-evidence verification: `NOV-A8-INCOMPLETE-SEARCH-EVIDENCE-001`; full acceptance `FAIL`, faithful incomplete negative evidence `PASS`.
- Integration verification: `NOV-A8-SEARCH-PROTOCOL-INTEGRATION-001`, `NOV-A8-CITATION-AUDIT-INTEGRATION-001`, `NOV-A8-CANDIDATE-PORTFOLIO-INTEGRATION-001`, `NOV-A8-SEARCH-COVERAGE-INTEGRATION-001`, and `NOV-A8-NOVELTY-MATRIX-INTEGRATION-002` all passed.
- Recovery: first context-failure checkpoint `CP-e399c6186a58`; retry checkpoint `CP-bd718fa668d5`; recovery `REC-5f3a50baa0d3` stopped after its prespecified retry stop rule. No further autonomous novelty-search retry is authorized in this revision.
- Structural checker: `PASS` at `NOVELTY_AUDIT` after the attempt-8 gate decision.
- Strict checker: one expected failure, `strict validation forbids an open invalidation queue`, because `NOVELTY_UNRESOLVED` intentionally leaves the novelty phase open and downstream evidence stale.
- Authority boundary: public scholarly and patent-discovery surfaces only. Archive/RPC access was not used; CA-P09 and feasibility evidence were not modified.
- Scientific disposition: `NOVELTY_UNRESOLVED` for `C001-MEASUREMENT`; neither `NOVELTY_SURVIVES`, `REFRAME`, nor `STOP` is supported by the completed evidence.

## 2026-08-02T01:46:10Z — INTAKE

- Owner: root-integration-owner
- Decision: RECOVERY_PLANNED:REC-7601a088ae72:WAIT_EXTERNAL
- Evidence: 00-governance/program-charter.md [sha256:56a6aa4f9519e7edeb20ad1dee155a04b559cb102c276e9c8a7c5ce266fd927c], 00-governance/study-profile.json [sha256:3cffaa6660d4bcb2e203636b75a6f22d435159c85d73edddf3bcba27bea2c92d]
- Consequence: Wait for the named external condition, then resume REC-7601a088ae72 with verified evidence.

## 2026-08-02T02:47:04Z — INTAKE

- Owner: root-integration-owner
- Decision: RECOVERY_EXTERNAL_ROUTE_REROUTED:REC-7601a088ae72:NARROW_CLAIM
- Evidence: 00-governance/program-charter.md [sha256:56a6aa4f9519e7edeb20ad1dee155a04b559cb102c276e9c8a7c5ce266fd927c], 00-governance/study-profile.json [sha256:3cffaa6660d4bcb2e203636b75a6f22d435159c85d73edddf3bcba27bea2c92d]
- Consequence: Execute the NARROW_CLAIM safe-route recovery for REC-7601a088ae72; verify that no retained claim depends on the abandoned external authority.
