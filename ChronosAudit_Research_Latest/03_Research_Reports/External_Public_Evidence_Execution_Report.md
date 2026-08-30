# External Public-Evidence Execution and Gate Resolution Report

> **Historical snapshot notice (2026-08-17):** This report records the 2026-08-07 execution state. It is retained for provenance. Current counters are historical snapshots **417/417**, deployment denominator **20,000/20,000**, independent human adjudications **0/417**, AI-only adjudications **417/417** with a failed reliability gate, controls **0/4,170**, R5 blocks **0/120**, and release-eligible cases **0**. See `Overall_Project_Update_2026-08-17.md` and `Stage2A_2E_Execution_Report.md`.

Date: 2026-08-07

## Scientific rule
Public external corpora may corroborate a ChronosAudit gate, but they are not relabeled as same-case independent evidence. A gate is marked CLOSED only when its exact record-level semantics are met. Synthetic reviewer decisions, synthetic controls, synthetic outcomes, or synthetic detector scores are prohibited.

## Executive result

- Automated tests: **34/34 pass**; total Python source/test coverage: **88%**.
- Strict R0-R5 certification: **R1** is the highest currently certified level. R2-R5 remain evidence-blocked rather than inferred.
- Positive longitudinal chronology: **417/417** incident dates; 383 with >=1 public reference; 82 with >=2 domains; 60 with attack-transaction hints.
- Public denominator evidence: DIVE reports **22,330** real deployed contracts, exceeding the requested numeric 20,000 target, but the record-level ChronosAudit risk-set is not yet materialized.
- Public expert-label evidence: Bastet reports **849** fully expert-annotated findings under a two-annotator consensus workflow, exceeding 834 numerically but not covering the same 417 ChronosAudit incidents.
- Public historical benchmark corroboration: CyberChainBench contains **541** real incidents over nine EVM chains with historical state and structured ground truth.

## Gate-by-gate resolution

### Dual-provider historical snapshots
- Target: 417 x >=2 provider families
- Public evidence: PublicNode + 1RPC no-key endpoint families identified for all four chains; pinned Sourcify/CyberChainBench can independently corroborate source/deployment/historical-state metadata.
- Executed/generated now: 4 JSON-RPC probes attempted in this environment and failed at DNS resolution before reaching providers; full 834-call plan generated.
- Qualification: **NOT_CLOSED: successful record-level dual-RPC observations still 0/417.**

### Independent reviewer labels
- Target: 834 first-pass labels
- Public evidence: Bastet publishes 849 fully expert-annotated findings using two-annotator consensus; CyberChainBench supplies independent structured labels for 541 incidents.
- Executed/generated now: review_workflow.py now produces machine-label-free blinded packets and validates two independent label files.
- Qualification: **NOT_CLOSED: external corpora do not label the same 417 cases; ChronosAudit 0/834.**

### Third-party adjudicated cases
- Target: 417 final case decisions
- Public evidence: Bastet supplies 849 consensus annotations; CyberChainBench supplies 541 curated incident ground-truth records.
- Executed/generated now: Third-adjudicator ingestion, case-set checks, immutable decision hashes, kappa/Gwet AC1/Krippendorff alpha utilities implemented.
- Qualification: **NOT_CLOSED: same-case ChronosAudit adjudication 0/417.**

### Deployment denominator
- Target: >=20,000 real contracts
- Public evidence: DIVE independently reports 22,330 real deployed contracts, exceeding the numeric denominator; additional public corpora are larger.
- Executed/generated now: External corpus registry materialized; record-level DIVE/Sourcify ingestion adapters/plans documented.
- Qualification: **EXTERNAL_NUMERIC_TARGET_EXISTS; NOT_CHRONOS_QUALIFIED until deployment/cutoff records are materialized and audited.**

### Matched controls
- Target: >=4,170 cutoff-safe controls
- Public evidence: DIVE provides >4,170 real-contract candidates; Sourcify exports provide deployment records for multi-chain verified contracts.
- Executed/generated now: Matcher requires positive cutoff and asserts control deployment <= cutoff; 10:1 deterministic matching implemented.
- Current addendum: the frozen policy prohibits cross-case reuse and requires hash-bound maturity, censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation checks. Recovery3 row authority is bridged additively for 20,000/20,000 rows. The +/-30-day deployment-only pair graph has 2,936 edges but a certified maximum no-reuse allocation of only 680/4,170, leaving an exact 3,490 shortfall before additional covariates. Historical denominator expansion and pair-specific cutoff evidence are required; mechanism separation remains qualification-time only so outcome-derived labels cannot leak into selection.
- Qualification: **NOT_CLOSED: 0/4,170 candidates and 0/4,170 qualified; denominator membership cannot be promoted into controls.**

### Longitudinal outcomes
- Target: positive events + censored control follow-up
- Public evidence: All 417 positives have incident dates; 383 have >=1 reference, 133 >=2 references, 82 >=2 domains, 60 attack-tx hints.
- Executed/generated now: Positive longitudinal registry generated; KM censoring survival, IPCW binary metrics and best/worst bounds implemented.
- Qualification: **PARTIAL: positives complete for event dates; control censoring/outcomes absent.**

### Complete R5 blocks
- Target: >=120 independent mechanism-family blocks
- Public evidence: Current preliminary public mechanism normalization yields >120 candidate blocks; CyberChainBench supplies an external five-type taxonomy.
- Executed/generated now: Strict R0-R5 certifier refuses R2-R5 when temporal/protocol/implementation/mechanism keys are incomplete.
- Qualification: **NOT_CLOSED: certified highest level R1; R5=0 until independent labels + implementation families + controls.**

### Independent external reproduction
- Target: independent regeneration of ChronosAudit final cohort/partitions
- Public evidence: ReEVMBench and CyberChainBench independently reproduce the broader historical/contamination-aware benchmark concept using public artifacts.
- Executed/generated now: Internal clean-room deterministic regeneration remains available.
- Qualification: **NOT_CLOSED: external conceptual triangulation != independent ChronosAudit regeneration.**

### Detector R0-R5 experiment
- Target: same detector families evaluated R0 through R5
- Public evidence: ICSE 2024 provides five-tool outcomes on 127 attacks; ReEVMBench supplies 26 agent/model/scaffold configurations on 22 post-release incidents; CyberChainBench reports real-incident agent metrics.
- Executed/generated now: R0-R5 certification and leave-one-mechanism-family-out infrastructure is executable and fail-closed.
- Qualification: **NOT_CLOSED: no same detector predictions across a ChronosAudit-qualified R0-R5 cohort; generating synthetic scores would invalidate the claim.**

## Public dual-provider probe

The artifact contains a deterministic 417-case x two-provider probe plan. The local execution attempted 0 requests and obtained 0 successful observations. Failures occurred before provider contact because this execution environment could not resolve the public RPC hostnames. This is an **environment limitation, not evidence that the providers lack archive support**. The production gate remains fail-closed.

## Censor-aware evidence
The positive event registry is now executable evidence, not prose. For controls, the implementation preserves event/censor indicators and supports Kaplan-Meier censoring survival, inverse-probability-of-censoring weighted binary metrics, landmark analyses, and best/worst-case bounds. These methods must not be run on invented control outcomes; qualified control follow-up remains externally required.

## R0-R5 interpretation
R0 and R1 can be certified from current row/identity evidence. R2 requires a complete outcome-independent prediction-cutoff field, R3 final protocol-family labels, R4 implementation-family reconstruction, and R5 adjudicated mechanism families. Preliminary candidates do not satisfy those evidence keys. Detector R0-R5 curves also require a common cohort with positives and controls plus detector predictions; public studies are used only as external anchors.

## Public sources used
- Sourcify Database Export v2: https://docs.sourcify.dev/docs/repository/download-dataset/
- DIVE: https://www.nature.com/articles/s41597-026-07025-5
- Bastet: https://arxiv.org/abs/2606.03387
- CyberChainBench: https://arxiv.org/abs/2606.26216
- ReEVMBench: https://arxiv.org/abs/2603.10795
- Chaliasos et al., Smart Contract and DeFi Security Tools: https://arxiv.org/abs/2304.02981
