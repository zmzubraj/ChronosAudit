# ChronosAudit Problem Investigation

## Scope and phase boundary

- Claim ID: `C001`
- Phase: `NOVELTY_AUDIT`
- Purpose: define the problem, causal bottleneck, estimands, candidate solution families, and falsification path before the reproducible strongest-prior-art search.
- Status boundary: this document does not claim novelty survival. The current novelty stage remains `UNRESOLVED`.

## Decision-bearing question

ChronosAudit asks whether apparent exploit-detection performance for smart contracts survives when evaluation is restricted to information that would have been admissible before the incident and when separation is enforced jointly across time, lineage, clone structure, and exploit mechanism. For the attempt-8 novelty audit, the target is the prespecified retrospective capability-survival profile plus its censoring, precision, coverage, and workload consequences. A sealed prospective setting remains a later validation surface for operational claims, not part of the active novelty claim.

## Bounded solution contract

ChronosAudit should count as a valid contribution only if all of the following are simultaneously true:

1. The evaluation population is defined at prediction time, with immutable case-level provenance and an explicit admissibility manifest.
2. Performance is reported after joint separation by deployment time, protocol/entity lineage, normalized source and bytecode clone family, proxy implementation family where relevant, attacker-contract clone family where relevant, and exploit-mechanism family.
3. Contracts without mature resolution are not silently treated as negatives; they are represented as unresolved or right-censored observations.
4. The benchmark reports calibrated selective prediction, including abstention, precision-coverage, alert budget, and analyst workload consequences at realistic base rates.
5. The strongest claim about operational usefulness is reserved for a frozen, sealed prospective or shadow deployment with preregistered thresholds and adjudication.

If any of these are absent, the work may still be useful, but it no longer instantiates the full ChronosAudit hypothesis as stated in the intake.

## Operational phenomenon

The target phenomenon is apparent exploit-detection capability inflation caused by evaluation contamination rather than by true pre-incident vulnerability recognition. In this project, contamination means any pathway by which training data, retrieval context, split construction, labeling, or benchmark composition allows a model or pipeline to benefit from information that would not have been admissible at the stated prediction time for the evaluated contract.

## Primary estimands

### E1. Capability-survival estimand

The primary retrospective estimand is the change in detector performance across a split ladder:

`random split -> time-only split -> time+lineage split -> time+lineage+clone split -> joint independence control`

The core quantity is the survival profile, not a single score:

- absolute and relative decay in ranking or classification performance as contamination controls are added;
- the remaining performance under the strictest admissibility regime;
- uncertainty around that remaining performance.

A sealed prospective cohort may later test transport and operational durability,
but it is not a step in the attempt-8 novelty-bearing estimand.

### E2. Selective-operations estimand

For a fixed alert budget or analyst budget, the project needs the achievable precision, recall or coverage, calibration, and workload under realistic exploit base rates. The main operational question is whether a frozen system can remain useful after abstention and triage are priced in.

### E3. Population-status estimand

The benchmark population must distinguish:

- confirmed positives;
- mature investigated negatives, if a defensible maturity rule can be defined;
- unresolved contracts that are still at risk of future positive revelation.

This implies censor-aware evaluation rather than naive closed-world binary labeling.

## Causal bottleneck

The hard scientific bottleneck is not only detector quality. It is identification of performance that is attributable to genuine pre-incident vulnerability recognition rather than to shortcut transfer from:

- temporal leakage;
- protocol or organizational lineage;
- source or bytecode clone reuse;
- repeated exploit-mechanism families;
- artifact contamination from post-incident discourse, tool outputs, labels, or benchmark assembly choices;
- unrealistic negative sampling that makes the benchmark easier than real deployment.

If these channels are not jointly controlled, measured performance may mostly reflect family resemblance and post hoc contamination rather than the claimed ability to surface unknown or not-yet-exploited contracts.

## Causal threat inventory

### Verified from the intake and charter

- The original research question includes a later sealed prospective test, while the user-authorized attempt-8 novelty claim is explicitly limited to the joint capability-survival measurement contribution.
- The charter restricts the current program to public-source, read-only research and local artifact creation.
- The charter already narrows the contribution toward benchmark and methodology science rather than requiring a new detector.

### Inference grounded in the stated problem

- Smart-contract exploit datasets are likely to exhibit repeated families of code, protocol forks, shared libraries, proxies, and attacker behaviors; otherwise the user's requested joint separation policy would not matter.
- A time-only split can still leak through clones, lineages, and mechanism recurrence when these structures straddle the cutoff.
- Post-incident public artifacts can create indirect contamination even when on-chain timestamps are historical, because retrieval corpora, labels, or feature engineering may embed future knowledge.
- Operational utility depends on base rates and analyst budgets, so retrospective discrimination metrics alone are insufficient.

### Assumptions requiring later verification

- Source and bytecode normalization can be made stable enough to support clone-family assignment at benchmark scale.
- Protocol/entity lineage can be defined reproducibly enough to survive independent audit.
- Exploit-mechanism families can be labeled with acceptable inter-rater reliability or machine-checkable rules.
- Historical chain-state and provenance timestamps can be reconstructed with sufficient fidelity for prediction-time admissibility checks.
- A frozen baseline such as MANDO-LLM can be reproduced fairly enough to serve as a first-stage reference auditor.

### Current unknowns

- Which prior benchmarks already implement some subset of these controls.
- Whether any existing benchmark already combines all required controls in a way that would defeat the claimed differentiator.
- Which admissibility-policy representation is most auditable in practice.
- Whether mature-negative and right-censoring rules are operationally defensible for smart-contract incidents.
- Whether prospective incident rates and adjudication latency make a shadow deployment scientifically informative within the available time window.

## Threats-to-validity model

### T1. Temporal leakage

Features, labels, retrieval material, exploit writeups, patched code, postmortem analyses, or benchmark inclusion rules may encode future information unavailable at the prediction time.

### T2. Lineage leakage

A model may effectively memorize a protocol family, entity family, deployment factory, upgrade lineage, or common maintainer ecosystem rather than detect unseen vulnerability structure.

### T3. Clone leakage

Near-duplicate or mechanically transformed source and bytecode artifacts can create trivial train-test transfer even when contract addresses differ.

### T4. Mechanism leakage

Exploit classes may repeat in ways that allow a detector to recognize a familiar mechanism family without demonstrating broader pre-incident discovery capability.

### T5. Attacker-side leakage

Attacker contracts, scripts, or exploit traces may reveal reusable patterns tied to specific victim families and thereby contaminate case representations.

### T6. Negative-sampling distortion

Choosing easy negatives or treating unresolved contracts as negatives can inflate precision and suppress uncertainty.

### T7. Label-confirmation bias

Cases with public incidents may be overrepresented because they are observable, profitable, or document-rich, while silent failures and unresolved at-risk contracts remain weakly labeled.

### T8. Prospective scaffold leakage

If the prospective deployment is not truly sealed, retrieval growth, threshold tuning, or post-freeze adaptations can undermine the interpretation of prospective performance.

## Minimum admissibility conditions implied by the question

To answer the research question honestly, each evaluated prediction needs:

- a declared prediction timestamp;
- admissible data sources frozen to that timestamp;
- provenance showing when the contract, associated artifacts, and labels became observable;
- declared exclusions for any post-cutoff or unresolved information;
- clone and lineage assignment rules that can be rerun independently;
- exploit-mechanism assignment rules and uncertainty handling;
- explicit handling of unresolved or censored cases;
- a frozen selective-prediction policy if workload claims are made.

## Candidate solution families

These are competing design families for solving the measurement problem. They are candidate families, not validated contributions.

### Family A: retrospective split-ladder benchmark only

Mechanism:

- Build a historical benchmark with progressively stricter split controls.
- Measure decay from random cross-validation to the strictest retrospective independence split.
- Stop before any prospective deployment.

Strengths:

- Lowest operational burden.
- Most feasible path to a benchmark-science paper if the data pipeline is tractable.
- Directly tests whether apparent performance collapses under stricter contamination control.

Hard limitations:

- Cannot by itself support strong claims about sustained operational usefulness.
- Vulnerable to disagreement about whether retrospective admissibility rules are sufficient.

Defeating evidence:

- If strict retrospective performance remains high but cannot be trusted because unresolved negatives and future-label contamination remain dominant.

### Family B: censor-aware historical surveillance benchmark

Mechanism:

- Treat contracts as entries into a risk set over time.
- Use confirmed positives, mature investigated negatives where justified, and unresolved right-censored observations.
- Evaluate selective prediction and alert budgets in a historical surveillance framing rather than a static benchmark.

Strengths:

- Better alignment with the open-world nature of pre-incident discovery.
- Directly engages the unresolved-negative problem.
- More faithful to operational workload accounting.

Hard limitations:

- Requires a defensible maturity rule and censoring framework.
- More complex statistical design and potentially weaker data availability.

Defeating evidence:

- If case follow-up quality is too inconsistent to distinguish mature negatives from unresolved cases, making censor-aware inference unstable or non-auditable.

### Family C: hybrid benchmark plus sealed prospective shadow deployment

Mechanism:

- Use the retrospective split ladder to estimate capability survival.
- Freeze model, retrieval process, thresholds, and admissibility scaffold.
- Run a sealed prospective shadow cohort with adjudication and responsible-disclosure controls.

Strengths:

- Strongest answer to the operational-utility question.
- Separates historical benchmark science from forward-looking deployment evidence.
- Best fit to the user-stated target contribution.

Hard limitations:

- Highest dependency on time, incident rate, disclosure coordination, and independent adjudication.
- Easily invalidated by any leak in the sealed scaffold.

Defeating evidence:

- If the prospective system cannot remain sealed or if the follow-up window yields too little adjudicable signal to support the operational claim.

## Hard-gate comparison across candidate families

| Gate | Family A | Family B | Family C |
| --- | --- | --- | --- |
| Tests contamination-control decay | Yes | Yes | Yes |
| Handles unresolved cases explicitly | Weak | Strong | Strong |
| Supports operational workload claims | Partial | Moderate | Strong |
| Requires prospective operations | No | No | Yes |
| Dependent on maturity-rule validity | Low | High | High |
| Dependent on sealed deployment integrity | No | No | High |
| Minimum publishable benchmark-science path | Strong | Moderate | Moderate |
| Strongest support for sustained usefulness claim | Weak | Moderate | Strong |

Current design implication:

- Family C best matches the full intake ambition.
- Family A is the minimum fallback if prospective execution remains unauthorized or infeasible.
- Family B may be required regardless, because the unresolved-case issue affects both retrospective and prospective interpretation.

## Falsification-first test sequence

### F1. Falsifiability check

Question:

- Can the claimed capability-survival construct be reduced to a measurable retrospective split-ladder estimand with explicit admissibility, censoring, and workload rules?

Failure condition:

- If the retrospective construct remains too vague to operationalize, the question needs reframing before prior-art search. Prospective validation is evaluated later and cannot rescue an undefined measurement estimand.

### F2. Prior-art defeat test

Question:

- Does a searched predecessor already implement the same joint independence-control and censor-aware operational evaluation bundle?

Failure condition:

- If yes, ChronosAudit loses its claimed methodological differentiator and must reframe around a narrower contribution.

### F3. Admissibility-audit test

Question:

- Can prediction-time admissibility be represented in a machine-verifiable manifest for each case without relying on hidden judgment?

Failure condition:

- If not, the central auditability claim weakens materially.

### F4. Clone and lineage reliability test

Question:

- Can source, bytecode, proxy, and protocol-lineage families be assigned reproducibly enough to support exclusion rules?

Failure condition:

- If family assignment is unstable, the joint-separation policy may not be defensible.

### F5. Censoring necessity test

Question:

- Do unresolved cases materially change estimated performance relative to naive negative labeling?

Failure condition:

- If unresolved-case handling has negligible impact, the censor-aware layer may not be central to the contribution.

### F6. Operational calibration test

Question:

- Under realistic base rates and alert budgets, does any surviving signal remain useful after calibration and abstention?

Failure condition:

- If surviving precision collapses at practical workloads, the result may still be a valid negative finding, but the operational-usefulness claim fails.

### F7. Sealed prospective integrity test

Question:

- Can the prospective shadow deployment keep model, retrieval, thresholds, cohort, and adjudication frozen enough to support forward-looking interpretation?

Failure condition:

- If the scaffold cannot be sealed, Family C cannot support the full claim set.

## Strongest alternative explanations to test later

The project must distinguish its target explanation from these alternatives:

1. Most measured gains come from clone or lineage memorization rather than novel vulnerability recognition.
2. Most measured gains come from exploit-mechanism recurrence rather than broader pre-incident discovery.
3. Reported calibration gains come from selective abstention that simply suppresses coverage below practical usefulness.
4. Prospective signal, if any, reflects retrieval or curation leakage rather than true frozen-model capability.
5. Apparent degradation across stricter splits is caused by sample-size collapse alone rather than contamination removal.

## Negative-result value

ChronosAudit remains scientifically valuable even if the strictest controls reduce performance to near-random or operationally unusable levels. A negative result would still establish:

- which contamination controls materially reduce apparent performance;
- whether current smart-contract exploit-detection claims survive auditable independence constraints;
- whether operational deployment claims should be narrowed;
- what future detector research would need to prove rather than assume.

## Earliest phase decisions supported by this artifact

- Supported now: the research question is falsifiable enough to proceed to the strongest-prior-art search, subject to later verification.
- Not supported now: any claim that ChronosAudit is materially novel, feasible to execute end-to-end, or operationally effective.

## Direct evidence used

1. `intake.md` revision 1, preserved in `00-governance/intake-original.md`
2. `00-governance/program-charter.md`
3. Orchestration contract files:
   - `references/artifact-contract.md`
   - `references/capability-routing.md`
   - `references/orchestration-protocol.md`
   - `references/research-cell-roster.md`
   - `references/single-input-contract.md`
   - `references/state-and-recovery.md`

No external prior-art or benchmark sources were used in this artifact. That search remains a separate required novelty task.

## Residual risks handed to the next novelty step

- The central differentiator may be defeated by prior work once the strongest-predecessor search is executed.
- The clone, lineage, and mechanism-family definitions may prove less reproducible than assumed here.
- The censor-aware framing may require a different estimand once the available incident and non-incident data are inspected.
- The full Family C ambition may later need to narrow to Family A or B if prospective execution remains unauthorized or scientifically underpowered.
