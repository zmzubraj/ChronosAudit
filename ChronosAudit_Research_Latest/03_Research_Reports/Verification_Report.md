# ChronosAudit Current Verification Report

**Snapshot:** 2026-08-17

| Check | Fresh authoritative result |
|---|---|
| Historical snapshot verifier | 417/417; `counter_authority=true`; zero integrity errors |
| Historical composition | 360 retained + 57 deterministic replacements |
| Historical chain counts | Ethereum 181; BSC 226; Base 9; Arbitrum 1 |
| Deployment denominator | 20,000/20,000; 5,000 on each target chain |
| AI-only adjudication | 417/417; zero validation errors |
| AI disagreement resolution | 143/143 resolved by distinct adjudicator run |
| AI reliability gate | FAIL: protocol 0.6667; mechanism 0.6763; required 0.80 |
| Independent human adjudications | 0/417 |
| Controls | 0/4,170 candidates; 0/4,170 qualified |
| Control design feasibility | REDESIGN REQUIRED: +/-30-day pair graph has 2,936 edges, 1,161 unique controls, and certified max-flow/min-cut 680/4,170; exact pre-covariate shortfall 3,490 is partitioned into 16 zero-overlap chunks; the 43-object query plan and v2 source-acquisition request are frozen, the latter awaits signature, no source batch or reserve queue exists, and RPC provider identity is not ready (36 blockers) |
| Control input preflight | BLOCKED: pair-specific cutoff evidence and follow-up horizon remain incomplete; flat present-day denominator values cannot authorize selection |
| Independent R5 blocks | 0/120 |
| Release-eligible cases | 0 |
| Public acquisition verifier | `structure_valid=true`; `integrity_failures=[]` |
| Scientific completion | false |
| Release readiness | false |
| Production qualification | false; expected exit 3 |

## Interpretation

The historical and denominator counters pass. The AI-only track is complete but fails reliability and cannot be promoted into human review. The package remains fail-closed because controls, human adjudication, R5 blocks, release predicates, and public-RPC ledger/receipt evidence remain incomplete.

## Authoritative artifacts

- `02_Executable_Artifact/reports/historical-snapshots-417-revised-v4-verification/historical_snapshot_verification_report.json`
- `02_Executable_Artifact/reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/public_acquisition_counters.json`
- `02_Executable_Artifact/reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/ai_only_adjudication/ai_adjudication_summary.json`
- `02_Executable_Artifact/reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/verification.json`
- `02_Executable_Artifact/reports/production_qualification.json`
- `02_Executable_Artifact/reports/stage2_control_preflight.json`
- `02_Executable_Artifact/reports/stage2_controls/2026-08-17/pair-scope/control_pair_acquisition_scope_manifest.json`
- `02_Executable_Artifact/reports/stage2_controls/2026-08-17/expansion-chunks/control_historical_expansion_query_plan_verification.json`
- `02_Executable_Artifact/reports/stage2_controls/2026-08-17/expansion-chunks/control_acquisition_approval_request.json`
- `02_Executable_Artifact/reports/stage2_controls/2026-08-17/expansion-chunks/control_candidate_rpc_provider_readiness.json`
