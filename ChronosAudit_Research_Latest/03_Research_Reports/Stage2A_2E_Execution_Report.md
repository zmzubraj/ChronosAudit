# ChronosAudit Stage 2A–2E Execution Report

**Snapshot:** 2026-08-17
**Artifact version:** 0.4.0 plus evidence revisions through `public-acquisition-historical-revision-v4`
**Decision:** `IMPLEMENTATION_COMPLETE_PARTIAL_EVIDENCE_CLOSURE_FAIL_CLOSED`

## Executive result

Stage 2 now has authoritative historical-snapshot coverage for **417/417** cases and a verified four-chain deployment denominator of **20,000/20,000** records. The historical counter comprises **360 retained authoritative rows plus 57 deterministic replacements**. The denominator contains **5,000** verified rows each for Ethereum, BSC, Base, and Arbitrum.

A separately named AI-only track completed **417/417** cases using two blinded primary runs, a distinct disagreement adjudicator, frozen prompts/model identifiers, timestamps, packet and decision hashes, confidence, agreement metrics, sensitivity analysis, and author sign-off. It is not human review, does not increment the independent-human counter, and failed its preregistered reliability threshold. Consequently it grants no internal progression permission in its current form.

The release remains fail-closed because independent human adjudication, matched controls, qualified controls, independent R5 blocks, and case-level release predicates remain incomplete. This report certifies the current evidence state; it does not certify detector effectiveness or submission readiness.

## Canonical counters

| Gate | Observed | Required | Status |
|---|---:|---:|---|
| Historical snapshot authority | 417 | 417 | PASS |
| Deployment denominator | 20,000 | 20,000 | PASS |
| Independent human adjudications | 0 | 417 | OPEN |
| Independently AI-adjudicated cases | 417 | 417 | COMPLETE, separate non-human track |
| Control candidates | 0 | 4,170 | OPEN |
| Qualified controls | 0 | 4,170 | OPEN |
| Independent R5 blocks | 0 | 120 | OPEN |
| Release-eligible cases | 0 | >0 after full conjunction | OPEN |

## Stage decisions

### Stage 2A — Temporal and provenance reconstruction

**Current state:** historical snapshot counter authority is **417/417** with zero verifier integrity errors and no scientific blockers in the authoritative historical projection. Chain coverage is Ethereum 181, BSC 226, Base 9, and Arbitrum 1.

**Boundary:** the current public-acquisition revision still lacks its own append-only public-RPC scientific ledger and raw RPC response receipts. The historical projection is authoritative for the snapshot counter, but those missing acquisition artifacts remain an independent reproducibility gap.

### Stage 2B — Code and deployment identity

The original seed audit still records **408** unique chain-address identities and **9** repeated groups covering **18** rows. Group-aware five-fold splitting has zero exact-identity crossings. Broader source-clone, proxy, shared-library, and implementation-family leakage remain unqualified until their corresponding evidence graphs are complete.

### Stage 2C — Protocol and mechanism adjudication

The canonical independent-human counter remains **0/417**. The AI-only track completed 417 valid cases with zero validation errors: two primaries agreed on 274 cases and disagreed on 143, all of which were resolved by a distinct adjudicator run. Alternate-prompt stability was **0.7866**. Protocol raw agreement was **0.6667** and mechanism raw agreement **0.6763**, below the frozen **0.80** reliability threshold. There were no high-confidence final cases; **335** final decisions were `UNKNOWN_INSUFFICIENT_EVIDENCE`.

**Decision:** `FAIL_RELIABILITY_THRESHOLD`. AI outputs remain suitable only as disclosed developmental evidence and cannot be represented as human adjudication, external validation, release clearance, or submission readiness.

### Stage 2D — Controls and censor-aware outcomes

The prevalence-preserving deployment denominator is now **20,000/20,000**, with exact per-chain quotas satisfied. Matched control candidates and qualified controls remain **0/4,170**. No control outcome or longitudinal follow-up is inferred from denominator membership.

The control-selection policy freezes ten unique, non-reused controls per positive; deterministic cutoff-safe matching; and explicit maturity, censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation checks. Recovery3 row authority is bridged additively for 20,000/20,000 rows. An offline evidence-bounded projection materializes complete positive deployment/cutoff time, code size, exact identity, and clone family for 417/417, while standard proxy evidence is available for 67/417. A deployment-only feasibility audit found 2,936 +/-30-day pair edges and only 1,161 unique control identities. Deterministic maximum flow equals the minimum cut at 680/4,170: only 37 cases can receive ten non-reused controls and the exact pre-covariate shortfall is 3,490. Historical denominator expansion is therefore required before pair-specific covariate acquisition or the pilot. The raw-receipt/pair-cutoff import verifier and hash-chained acceptance writer are implemented and fail-closed, but no batch has been accepted. A deterministic plan partitions all 380 deficit cases into 16 non-overlapping chunks while preserving the exact 3,490-slot minimum. The exact 43-object query plan and v2 source-acquisition request are frozen; the request remains `AWAITING_ACCOUNTABLE_SIGNED_APPROVAL` and is structurally unable to authorize RPC. The source-import, tenfold globally no-reuse reserve-queue, and separate queue-hash-bound RPC-activation verifiers are implemented. The live provider readiness decision is `RPC_PROVIDER_IDENTITY_NOT_READY` with 36 blockers because configured PublicNode/1RPC identities lack evidence and do not match the available Alchemy/Infura report. A separate OpenSSH-signed horizon verifier is implemented, but the live 417-case request remains `AWAITING_ACCOUNTABLE_METHODS_OWNER_DECISION`; it grants no selection, qualification, or counter authority. Mechanism remains qualification-time only to prevent selection leakage. This advances governance safeguards, not the control counter.

### Stage 2E — Leakage audit and release

All 1,000/1,000 row-random five-fold simulations leak an exact identity family; group-aware splitting reduces exact-identity crossings to zero. Independent R5 blocks remain **0/120** and release-eligible cases remain **0** because the release predicate is conjunctive.

## Current closure conditions

1. Complete 417 same-case independent human adjudications with two conflict-cleared reviewers and third-party resolution of disagreements, or explicitly retain the human gate as unavailable for any claim that requires it.
2. Revise and rerun the AI-only protocol if it is to serve as an internal progression gate; the current run failed reliability and grants no permissions.
3. Materialize and qualify at least 4,170 cutoff-safe matched controls with a frozen censoring horizon and independently checked outcomes.
4. Complete source-clone, bytecode, proxy, protocol, mechanism, and attacker-family leakage graphs and retain at least 120 independent R5 blocks.
5. Restore a complete append-only public-RPC ledger and raw response receipts for the current public-acquisition revision.
6. Obtain independent external regeneration before making external reproducibility claims.

## Claim boundary

**Defensible now:** the current artifact has authoritative historical snapshots for all 417 cases, a verified 20,000-record four-chain denominator, a fully traceable but reliability-failing AI-only adjudication experiment, exact-identity leakage evidence, and fail-closed release logic.

**Not defensible now:** completed independent human adjudication, qualified controls, strict R5 evaluation, a release cohort, detector-effectiveness results, scientific completion, production qualification, or submission readiness.
