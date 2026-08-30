# ChronosAudit: A Preregistered Protocol for Measuring Smart-Contract Exploit-Detection Capability After Joint Leakage Control

> **Human-review draft — concept only.** Novelty is `UNRESOLVED`; feasibility is `PILOT_FIRST`; the protocol is not independently schema-v4 verified or preregistered; detector-performance and prospective results are `NOT RUN`; no submission is authorized.

Draft author and repository public-release authority: **Zubaer Mahmood Zubraj**
([`@zmzubraj`](https://github.com/zmzubraj)). Final publication byline order,
affiliations, CRediT roles, declarations, and submission approval remain open.

## Abstract

Smart-contract exploit-detection benchmarks can overstate capability when evaluation cases share time-dependent information, protocol lineage, source or bytecode clones, proxy implementations, attacker infrastructure, or exploit mechanisms with training and retrieval material. ChronosAudit is a proposed measurement protocol for asking how much apparent capability survives when these dependencies are controlled jointly rather than one at a time. The protocol defines case-level prediction-time admissibility manifests, a split ladder from random evaluation to joint independence control, an open-population outcome model that preserves unresolved contracts as right-censored, and selective-prediction summaries tied to frozen alert budgets. The central object is a capability-survival profile, not a new detector. Existing design-stage work shows that restricted pilot plumbing can be rerun, but it has not established a complete representative real-case manifest, an admissible cohort, a mature-negative example, a strong baseline portfolio, or operational usefulness. The proposed study therefore remains a preregistration blueprint. A sealed prospective shadow deployment is excluded until separate authority, disclosure governance, adjudication, follow-up, and partner requirements are met. [claim:C001] [evidence:E-LOCAL-PROBLEM,E-LOCAL-VIABILITY]

## Introduction

Evaluation of exploit detection is vulnerable to a basic identification problem: a detector may appear to recognize pre-incident vulnerabilities while actually benefiting from information that became available after the prediction time, or from related protocols, cloned code, repeated exploit mechanisms, and curated negatives. The ChronosAudit case ledger records strong precedents for real-incident benchmarks, executable replay, post-cutoff evaluation, clone-overlap control, right-censored Web3 evaluation, selective prediction, and operational prioritization. It does not establish that any one component is new, and its bounded attempt-8 search did not meet the reconstruction standard required to resolve the remaining joint-measurement novelty claim. [claim:C001] [evidence:E-LOCAL-NOVELTY,E-PA010,E-PA012,E-PA013,E-PA014,E-PA026]

The proposed contribution is therefore deliberately narrow: a preregistered measurement study of the performance and workload changes induced by jointly applying temporal, lineage, clone-family, mechanism-family, censoring, and alert-budget controls. A negative result—such as collapse of apparent performance under strict separation—would still be informative because it would identify which claims do not survive auditable evaluation.

## Research question and contribution boundary

The research question is: among prediction-time-eligible smart contracts, how much apparent exploit-detection performance survives the transition from weak random evaluation to joint independence control, and what precision–coverage–workload profile remains at frozen alert budgets?

The protocol does not claim that ChronosAudit is the first real-incident benchmark, the first executable exploit benchmark, the first post-cutoff study, the first clone-controlled split, the first censor-aware Web3 evaluation, or the first selective-prediction framework. It also does not claim that operational usefulness has been demonstrated. Novelty remains `UNRESOLVED` until a reproducible strongest-prior-art audit and authenticated independent review close the documented gaps.

## Methods

### Unit, population, and admissibility

The primary unit is a `contract_at_cutoff` record consisting of a target contract or proxy root, prediction timestamp or block, and immutable admissibility-manifest revision. Every critical input must have evidence that it existed and was publicly available by the cutoff. Post-incident reports, exploit traces, patched code, later verification, and replay artifacts may support outcome adjudication but may not enter prediction inputs.

Fixture contracts are limited to pipeline tests. Scientific denominators require real cases with a lawful-use path and complete critical provenance. A missing critical field yields a recoverable hold or exclusion, not imputation.

### Independence split ladder

The proposed ladder is `R0_RANDOM`, `R1_TIME`, `R2_TIME_LINEAGE`, `R3_TIME_LINEAGE_CLONE`, and `R4_JOINT`. The strict rung adds normalized source and bytecode clone groups, proxy/implementation families, attacker families where relevant, and exploit-mechanism-family holdout. Group definitions and ontology versions must be frozen before scoring, and an independent rerun must reproduce split eligibility on an audit sample.

### Outcome states and censoring

The population distinguishes confirmed positives, mature investigated negatives, and right-censored unresolved contracts. A mature negative requires a property-bounded claim, frozen follow-up horizon, and independent adjudication; unresolved cases are never forced into the negative class. If censoring assumptions support inverse-probability weighting, the analysis may use horizon-specific weighted precision. Otherwise it reports partial-identification bounds and does not claim a point-identified operational effect.

### Baselines, scoring, and abstention

All baselines receive the same admissible information budget and frozen adapter contract. The intended structural/LLM comparator has not been reproduced and cannot yet anchor a fair comparison. A Slither-based substitute tested limited plumbing only. The definitive baseline portfolio, score mapping, abstention rule, alert budget `b*`, follow-up horizon `H*`, and review-time constant `tau_review` require accountable freezing before evaluation.

### Primary estimand

Let `M_r(b,H)` be censor-aware `Precision@Budget` for rung `r`. The primary object is `Theta = {M_R0, M_R1, M_R2, M_R3, M_R4}`. The primary contrast is `Delta_joint = M_R4(b*,H*) - M_R1(b*,H*)`; the descriptive survival ratio is `M_R4/M_R1` when defined. Secondary summaries include coverage or recall among adjudicated positives, calibration among non-abstained alerts, alerts per period, and workload `b* × tau_review`.

### Uncertainty, multiplicity, and sensitivity

Uncertainty is clustered by joint independence blocks rather than rows. The primary contrast is evaluated before adjacent rung contrasts; any retained hypothesis tests use Holm correction. Mechanism, chain, proxy, family, and threshold analyses remain exploratory. Required sensitivities vary censoring assumptions, follow-up windows, clone thresholds, lineage and mechanism granularity, negative frames, calibration mappings, and sample-size matching across rungs to distinguish contamination removal from sample collapse.

## Preregistration and execution gates

Before confirmatory data access, accountable owners must freeze the cohort, manifests, cutoffs, family ontologies, outcome contract, baseline portfolio, model and retrieval versions, alert and follow-up parameters, estimands, uncertainty method, sensitivity set, and stop rules. Execution stops or narrows if representative real manifests remain incomplete, split eligibility is unstable, mature-negative rules cannot be reproduced, lawful baselines cannot be frozen, or strict grouping leaves too few independent blocks for decision-relevant precision.

The prospective shadow extension is a separate study. It requires institutional and legal review, a disclosure partner, independent adjudicators, a yield and follow-up model, a sealed cohort and prediction record, and an incident-response plan. None of those prerequisites is established here.

## Design-stage evidence and non-results

The existing feasibility work exercised bounded public-data plumbing. It reported stable restricted clone reruns, a reproducible substitute baseline path, and stable pilot split assignments, but no representative real case was fully split-eligible after three cycles. Historical-state access failed before returning the required evidence, the prespecified `CA-P09` status trial remains right-censored until follow-up and independent adjudication, and the intended MANDO-LLM baseline was not reproduced. These are feasibility observations, not detector-performance results. [claim:C002] [evidence:E-LOCAL-FEASIBILITY,E-LOCAL-PILOT,E-LOCAL-VIABILITY]

Accordingly, no precision, recall, coverage, calibration, workload, capability-survival, or prospective estimate is reported. The benchmark-core gate remains `PILOT_FIRST`, and the prospective extension remains blocked.

## Expected contribution and falsification

The study is useful if it produces an auditable estimate of how conclusions change under joint leakage control. It is falsified or narrowed if the manifest cannot be instantiated lawfully, family assignments are unstable, censoring cannot be modeled defensibly, strong baselines cannot be frozen, the joint controls are empirically redundant, or an equivalent predecessor defeats the measurement claim. A null or adverse result remains reportable and may be more valuable than an inflated detector score.

## Limitations

This draft has no authenticated independent schema-v4 scientific verification, no resolved reporting route or target venue, no resolved novelty verdict, no complete representative real-case cohort, no mature-negative demonstration, no strong reproduced baseline portfolio, no confirmatory analysis, no external validation, and no submission package. The prior-art record is bounded to public surfaces and includes explicit reconstruction and access gaps. Operational claims are prohibited. The protocol's statistical choices remain conditional on the eventual cohort and censoring process.

## Ethics, governance, and dual use

Current activity is public-source, non-interventional computational methods work. No live target testing, private vulnerability processing, analyst-participant research, archive/RPC collection, coordinated disclosure, or prospective deployment is authorized. Future work must minimize disclosure of actionable vulnerabilities, document data and code rights, and preserve accountable human and institutional oversight.

## Data, code, and materials availability

The versioned research case is publicly hosted in the owner-authorized ChronosAudit repository. Repository-wide reuse rights, long-term archival preservation, executable-environment capture, and independent replication remain unresolved.

## Authorship, funding, conflicts, and AI use

Zubaer Mahmood Zubraj is identified as the draft author and repository owner. Final publication byline order, CRediT roles, funding, sponsor role, conflicts, acknowledgements, and permissions remain unresolved and must not be inferred. AI systems assisted with evidence organization, protocol drafting, and adversarial review; accountable humans must verify all affected content and prepare the venue-specific disclosure. AI is not an author.

## Conclusion

ChronosAudit is presently a falsifiable benchmark-measurement protocol, not an established benchmark result or operational auditor. Its defensible next contribution is a rigorously frozen retrospective capability-survival study. Until representative admissibility, outcome, baseline, novelty, and governance gates close, the correct scientific status is concept only, with empirical and prospective claims explicitly withheld.
