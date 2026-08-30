# ChronosAudit Full-Program Public-Evidence Qualification Report

**Snapshot:** 2026-08-17
**Canonical public-acquisition revision:** `public-acquisition-historical-revision-v4`
**Qualification:** `NOT_PRODUCTION_QUALIFIED`

## Executive result

The project has closed two previously open Stage 2 counters without relaxing their definitions: historical snapshot authority is **417/417**, and the four-chain deployment denominator is **20,000/20,000**. The current public verifier reports `structure_valid=true`, no integrity failures, `scientifically_complete=false`, and `release_ready=false`.

The project also completed a separate **AI-only** adjudication experiment for all 417 cases. It is traceable and structurally valid, but its reliability threshold failed and its output does not count as independent human adjudication. The canonical human counter remains **0/417**.

## Program-wide status

| Program surface | Current verified state | Decision |
|---|---|---|
| Seed incident cohort | 417 cases | Retained |
| Historical snapshot authority | 417/417 | PASS |
| Deployment denominator | 20,000/20,000 | PASS |
| AI-only adjudication | 417/417; zero validation errors | COMPLETE, reliability failed |
| Human adjudication | 0/417 | OPEN |
| Controls | 0/4,170 candidates; 0/4,170 qualified | OPEN |
| R5 blocks | 0/120 | OPEN |
| Release-eligible cases | 0 | OPEN |
| Public package structure | Valid; zero integrity failures | PASS |
| Scientific completion | False | FAIL-CLOSED |
| Production qualification | False; qualifier exits 3 | FAIL-CLOSED |
| Submission readiness | Not established | NOT READY |

## Evidence revisions that advanced

### Historical authority

The authoritative historical projection contains 417 selected cases: 360 retained rows and 57 deterministic replacements. The verifier reports `counter_authority=true`, `passed=true`, zero integrity errors, and no scientific blockers. Verified chain counts are Ethereum 181, BSC 226, Base 9, and Arbitrum 1.

### Deployment denominator

The counter manifest reports 20,000 verified records, with exactly 5,000 each for Ethereum, BSC, Base, and Arbitrum. This satisfies the denominator counter only; it does not create matched controls or outcome evidence.

### AI-only adjudication

`AI_ONLY_TRIANGULATION_V1` completed 417 cases. Two blinded primaries produced 274 agreements and 143 disagreements; a distinct adjudicator resolved every disagreement. Protocol raw agreement was 0.6667, mechanism raw agreement 0.6763, and alternate-prompt stability 0.7866. The frozen 0.80 reliability gate failed. There were zero high-confidence final cases and 335 `UNKNOWN_INSUFFICIENT_EVIDENCE` outcomes.

## Binding limitations

- AI outputs are not human adjudications and have no effect on the human counter.
- Model-run separation does not establish institutional or real-world reviewer independence.
- Denominator membership is not control qualification or longitudinal follow-up.
- Historical counter authority does not repair missing public-RPC ledger/receipt artifacts in the current revision.
- Exact-identity leakage control does not prove source-clone, proxy, implementation, protocol, mechanism, or attacker-family independence.
- Internal verification does not equal external replication or journal acceptance.

## Current blockers

1. Public-RPC append-only scientific ledger and raw response receipts are absent from the current revision.
2. Independent human adjudications remain 0/417.
3. The AI-only internal progression gate failed reliability and grants no permissions.
4. Control candidates and qualified controls remain 0/4,170. Recovery3 row-level denominator authority is bridged for 20,000/20,000, but the prespecified +/-30-day deployment graph has a certified maximum no-reuse allocation of only 680/4,170 with an exact 3,490 pre-covariate shortfall. A deterministic plan partitions the 380 deficit cases into 16 zero-overlap chunks. The frozen 43-object query plan, source-only v2 approval contract, reserve-queue verifier, and queue-hash-bound RPC activation contract are implemented, but the approval remains unsigned, no source or queue exists, and provider readiness is `RPC_PROVIDER_IDENTITY_NOT_READY` with 36 blockers. Historical denominator expansion, pair-specific cutoff evidence, and the follow-up horizon remain open; no candidate count is inferred from denominator membership, pair-scope rows, plans, or requests.
5. Independent R5 blocks remain 0/120.
6. Release predicates are unsatisfied and release-eligible cases remain 0.
7. External regeneration and venue-specific submission QA remain open.

## Overall decision

The current project is a materially advanced, evidence-gated research artifact with two major Stage 2 counters closed. It is not scientifically complete, production-qualified, release-ready, or submission-ready. Those labels remain blocked by the named non-compensating gates above.
