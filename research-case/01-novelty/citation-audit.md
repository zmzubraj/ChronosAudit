# ChronosAudit Independent Citation Audit — Attempt 4

## Boundary and integrity

- Lease: `LEASE-96487e1eff5f`
- Claim: `C001`
- Review type: correction-only independent recheck; no new discovery or broad search
- Authority: citation challenge only; no shared-state or phase-promotion authority

All fixed inputs matched their assigned SHA-256 values before review and remained unchanged:

| Input | Verified SHA-256 |
| --- | --- |
| `01-novelty/search-protocol.md` | `2973369f415ccdcd28c631a423473d26925f6f35652d71e95773941d2cdb1061` |
| `01-novelty/evidence-ledger.csv` | `808d58f83426a94608f36bbe289b42cafc717724ebe4b647a888407ac6a13615` |
| `01-novelty/novelty-matrix.csv` | `9b59e0c274df26caf6e1101a6019531da81cbb63740ceb82bc265299af6805da` |
| `01-novelty/candidate-portfolio.md` | `24cd1d665f06f695b44bea4c90e3b39b6e8a86cea1ba28b5ed92633875070d04` |

## Correction verification

| Check | Status | Evidence |
| --- | --- | --- |
| PA031 scope | PASS | `scope_codes` is now `S4;S5;S9`; `S8` is absent. The row describes OWASP SCSVS as a verification standard and explicitly denies sealed prospective evaluation. |
| PA032 scope | PASS | `scope_codes` is now `S5;S9`; `S8` is absent. The row describes EEA EthTrust as tiered audit assurance and explicitly denies prospective-study coverage. |
| PA033 URL | PASS | The row now uses `https://www.first.org/epss/`; a fresh direct request returned HTTP 200. |
| PA033 claim boundary | PASS | The contribution is limited to daily 0–1 probabilities of exploitation activity in the next 30 days, open data, and prioritization. The unsupported historical-version claim is removed. |
| PA014 evidence ceiling | PASS | The row remains publisher-metadata/abstract only, explicitly limits unverified methods, and remains `E1`. |
| PA028 limitation | PASS | The row retains the requirement to verify inventor-name romanization against an authoritative family record before publication and does not overstate family-complete patent coverage. |

## Independent novelty challenge

The attempt-3 adversarial finding remains unchanged after correction. SCONE is the strongest single predecessor: it defeats novelty claims for real incidents, executable grading, post-cutoff evaluation, a mostly-negative recent-contract scan, previously unknown findings, cost/revenue accounting, and disclosure coordination.

The strongest composite—SCONE and real-incident executable benchmarks, leakage/clone studies, temporal censored Web3 benchmarks, duplicate/state-space/exploit-likelihood patents, OWASP and EEA assurance standards, EPSS operational prioritization, and attacker/campaign analyses—defeats novelty of every major ChronosAudit ingredient.

Within the documented bounded public evidence, no checked single predecessor was verified to combine and measure all of the following in one auditable smart-contract benchmark contract:

1. prediction-time machine-verifiable information admissibility;
2. simultaneous temporal, protocol/entity, source/bytecode, proxy, attacker, and mechanism-family independence;
3. exploit-specific confirmed, mature-negative, and right-censored population states;
4. executable evidence grading;
5. a prespecified capability-survival split ladder;
6. calibrated abstention and measured analyst workload at realistic base rates; and
7. a longitudinal sealed cohort with frozen retrieval/thresholds, preserved predictions and abstentions, follow-up, and independent adjudication.

This is a high-burden interaction claim, not component novelty. It survives only if the protocol is preregistered and the study demonstrates that the joint controls materially change the capability estimate or its uncertainty. Failure to show that interaction should narrow the contribution to benchmark engineering.

## Residual objections

- Public-source absence is not universal absence; proprietary audit systems, confidential deployments, private corpora, embargoed studies, and inaccessible sources remain unknown.
- Patent review remains targeted rather than family-complete or a legal freedom-to-operate analysis.
- PA014 remains abstract-only, and PA028 inventor romanization remains non-publication-grade.
- Every individual ingredient has precedent. ChronosAudit may not claim novelty for temporal control, clone filtering, censoring, executable grading, selective prediction, workload prioritization, proxy review, attacker analysis, campaign separation, one-time prospective scanning, or disclosure coordination.
- A later predecessor implementing the complete measurement contract would reopen this gate.

## Recommendation

**`NOVELTY_SURVIVES`**

This means only evidence-bounded survival of the narrow joint interaction-and-measurement hypothesis within the recorded public search. It is not a universal first-of-kind claim, component-novelty finding, patentability opinion, top-journal-readiness assessment, or authorization for data collection or prospective deployment.

---

# ChronosAudit Novelty Assurance Backfill — Attempt 5

## Superseding boundary

Attempt 5 is a retrospective schema-v2 assurance reconstruction. It does not
retroactively convert attempts 1–4 into a preregistered search. Two newly
delegated search attempts failed before producing a valid artifact; those
failures remain preserved in the checkpoint, handoff, and recovery histories.
The root integration owner then executed and froze six public web queries in
`attempt5-root-search-packet.md`. That packet is discovery evidence but is not
an independently owned search.

The bounded adjudicator independently reviewed the frozen packet and canonical
novelty artifacts, but did not execute or claim a new search. Its full-file
SHA-256 is
`f121d072fcb9993ee5f6d6e44a06e4f149a4236f183c7c3225889a6a4ed31c79`.

## New primary-record checks

| Source ID | Primary or official record checked on 2026-08-02 | Verification result | Novelty effect |
|---|---|---|---|
| `PA036` | `https://arxiv.org/abs/2404.18186` | Verified 788 files, 10,394 vulnerabilities, eight SAST tools, and reported precision no higher than 10%. | Strengthens taxonomy, false-positive, and workload precedent; nonmaterial to `C001-JOINT`. |
| `PA037` | `https://link.springer.com/article/10.1007/s10207-026-01287-1` | Verified the enhanced SDB test suite, detector evaluation, and consideration of fixed versions for false-positive analysis. The checked record does **not** establish a balanced mature-negative cohort. | Strengthens negative/fixed-version benchmark precedent; nonmaterial to `C001-JOINT`. |
| `PA038` | `https://eips.ethereum.org/EIPS/eip-1167` | Verified final minimal-proxy bytecode standard, fixed implementation delegation, and tool-identifiable implementation address. | Defeats novelty of minimal-proxy family recognition itself. |
| `PA039` | `https://arxiv.org/abs/2605.29059` | Verified 600 real-world contracts with paired bytecode/source and replayable semantic checkpoints. | Strengthens replayable benchmark provenance; nonmaterial to exploit-protocol equivalence. |
| `PA040` | `https://arxiv.org/abs/2410.06176` | Verified 5,377 real contracts, 15,975 ERC-rule violations, and strong scaffold/oracle sensitivity. | Strengthens large-scale and scaffold-sensitive auditing precedent; nonmaterial to the joint protocol. |

These records are integrated into `evidence-ledger.csv` and the affected rows
of `novelty-matrix.csv`. None was adjudicated as an equivalent joint protocol.

## Unrepaired assurance gaps

- discovery ownership is not independent;
- historical per-query result totals, screening counts, and query attribution
  cannot be reconstructed;
- the attempt-5 interface did not expose reliable per-query totals;
- no distinct correction/retraction/contradictory-evidence database search was
  executed;
- backward and forward citation-chain saturation remains partial;
- patent-family, proprietary, confidential, embargoed, subscription-index,
  and non-English coverage remains incomplete.

## Superseding recommendation

**`NOVELTY_UNRESOLVED`**

The lowest defensible novelty stage remains
`POTENTIALLY_DIFFERENTIATING` for `C001-JOINT` only. No equivalent joint
protocol was verified, but the independent-search contract is unsatisfied and
the obvious-recombination objection remains live. This attempt therefore
supersedes the attempt-4 `NOVELTY_SURVIVES` recommendation for progression
purposes without deleting its historical evidence.

---

# ChronosAudit Independent Search Challenge — Attempt 7

## Verification boundary

- Independent owner: `/root/chronosaudit_attempt7_canonical_challenge`
- Lease: `LEASE-0efb9a5c257c`
- Verification owner: `root-integration-owner`
- Verification ID: `NOV-A7-INDEPENDENT-SEARCH-VERIFY-001`
- Verified challenge SHA-256:
  `ab58cf4f3d3f2192a6d640a7d24867e42d316869af63871043580e3d2551fccc`
- Authority: public scholarly, patent-discovery, and standards surfaces only;
  archive/RPC access was not authorized and was not used.

The challenge preserves five exact query logs plus one standards traversal,
counts as `UNAVAILABLE` when the interface did not expose corpus totals,
visible screening and retention counts, exclusions, ten known-item
recoveries, two-seed public citation/author traversal, and reconciliation to
the existing `PA001`–`PA040` ledger, with direct crosswalk to `PA010`,
`PA012`, `PA013`, `PA014`, `PA026`, `PA027`, `PA031`, `PA033`, `PA038`,
`PA039`, and `PA040`. Root independently recomputed the file hash and checked the
named primary or official records; the ScienceDirect record was also verified
through its indexed primary-result metadata and DOI
`10.1016/j.icte.2026.02.002` when the direct page did not render.

## Independent decision

**`NOVELTY_UNRESOLVED`**

No checked single predecessor was verified to implement the complete joint
ChronosAudit protocol. That bounded negative finding is insufficient for
`NOVELTY_SURVIVES`, because the challenge did not resolve the strongest
objection that the proposal is an obvious recombination of established real-
incident benchmarks, executable grading, temporal evaluation, clone and
campaign dependence controls, right-censored Web3 analysis, selective
prediction, workload prioritization, standards, and benchmark packaging.

The lowest defensible stage remains `POTENTIALLY_DIFFERENTIATING` for
`C001-JOINT` only. Formal correction/retraction searching, subscription-index
forward-citation saturation, patent-family and non-English coverage, and
private/proprietary protocols remain outside the verified evidence boundary.
Exact queries A7Q2, A7Q3, and A7Q5 produced no direct predecessor from their
exact phrasing, and `PA014` remained metadata/abstract-bounded.

---

# ChronosAudit Exact-Match Citation Audit — Attempt 8

## Reframed boundary

The active claim is `C001-MEASUREMENT`, not the historical broader joint-
protocol claim. Prospective shadow deployment is a later validation surface and
does not contribute to the attempt-8 novelty decision.

## Independent-evidence verification

- Search owner: `/root/chronosaudit_attempt8_exact_match_search`
- Independent verifier: `/root/chronosaudit_attempt7_canonical_challenge`
- Verification ID: `NOV-A8-INCOMPLETE-SEARCH-EVIDENCE-001`
- Challenge hash: `d73eb3f3ad641c4323ceb59809c791669e153ce0267d39af05ab6e55432dc5b0`
- Full contract: `FAIL`
- Fidelity as incomplete negative evidence: `PASS`

The append-only challenge contains exactly four scholarly queries and one
patent query, recovers five of six named anchors, explicitly fails to recover
FinSurvival, contains two traversal sketches, preserves the public-only and
no-archive/RPC boundary, and reaches the proportional allowed verdict
`NOVELTY_UNRESOLVED`.

It does not preserve the required query-level UTC timestamps, result counts or
`UNAVAILABLE`, screened and retained counts, exclusions, or a timestamped
pre-ledger freeze. The CyberChainBench author/citation traversal is incomplete.
These are decision-bearing reconstruction failures, not cosmetic defects.

## Decision

**`NOVELTY_UNRESOLVED`**

No checked source was verified as an equivalent study of the full joint
capability-survival estimand. However, strong component precedents, the live
obvious-recombination objection, incomplete FinSurvival and patent coverage,
partial citation traversal, and non-reconstructable query screening logs prevent
evidence-bounded novelty survival. The prespecified recovery stop rule prohibits
another autonomous retry in this authorization.
