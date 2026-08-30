# ChronosAudit Stage-2 Top-Journal Revision and Qualification Report

> **Current qualification addendum (2026-08-17):** Historical snapshot authority is now **417/417** and the four-chain deployment denominator is **20,000/20,000**. Independent human adjudication remains **0/417**. The separate AI-only track completed **417/417** but failed its frozen reliability threshold and grants no progression, release, or submission permission. Controls remain **0/4,170**, independent R5 blocks **0/120**, and release-eligible cases **0**. Earlier percentage readiness scores below are legacy assessments and have not been recalibrated; current gate status is authoritative.

## Revision outcome

This release upgrades the Stage-2 evidence/cohort paper and implementation without converting missing external evidence into false PASS results.

### Fixed in code/methodology

- Outcome-independent prediction cutoff: primary deployment +24h; sensitivity +1h/+7d/+30d.
- Cutoff-safe controls: a control must exist by the positive case cutoff.
- Split audit: independent random, balanced shuffled K-fold, chain-stratified K-fold, identity-group K-fold, plus closed-form duplicate-pair expectation.
- Blinded reviewer packets: machine protocol/mechanism candidates removed from first pass.
- Complete adjudication ingestion: third adjudicator can supply final protocol/root-cause labels and rationale; final decisions are hashed.
- Reviewer statistics: raw agreement, Cohen kappa, Gwet AC1, deterministic bootstrap 95% CIs.
- Deployment trace portability: Parity `trace_block` and Geth `debug_traceBlockByNumber`/`callTracer` adapters.
- Provider-family independence: two URLs are insufficient; operational qualification requires two verified operator families.
- RPC resilience: retry/exponential backoff on transient and rate-limit failures.
- Statistical utilities: Wilson intervals, precision-based sample-size helper, cluster bootstrap, IPCW weights.
- Detector-specific admissibility cohorts: bytecode, source, state, and source+state.
- Manuscript: inline numbered citations, expanded recent related work, explicit estimands, power/precision rationale, production qualification table, threats to validity, and point-by-point reviewer resolution.
- Accessibility: revised DOCX audit reports 0 high / 0 medium / 0 low issues.

### Executed verification

- Public incident chronology: 417/417.
- Exact identities: 408 unique; 9 repeated groups covering 18 rows.
- Row-level split leakage: 100% for 1,000 independent-random, balanced K-fold, and chain-stratified K-fold simulations.
- Identity-group K-fold leakage: 0 crossings.
- Automated test suite: 27/27 passing; overall source coverage 84%, including 93% deployment-stream and 88% source-history coverage.
- Internal fail-closed release: retained.

### External gates that remain scientifically unclosed

These cannot be truthfully completed through code or manuscript editing alone:

1. 417/417 live historical identity/source observations from at least two verified archive-provider families per represented chain.
2. Two genuinely independent reviewer label sets plus third-party adjudication of disagreements.
3. >=20,000 real deployment records with complete top-level and internal CREATE/CREATE2 evidence.
4. >=4,170 cutoff-safe matched controls.
5. Frozen longitudinal outcome follow-up and censoring evidence.
6. Complete bytecode/proxy/protocol/mechanism contamination graph and >=120 independent R5 blocks.
7. Independent external regeneration by another researcher/group.
8. Live operational qualification: provider failover, rate-limit/fault injection, immutable container digest, SBOM/vulnerability scan, SLO/monitoring, disaster recovery, credential rotation, and disclosure drill.

## Readiness after revision

| Dimension | Revised readiness |
|---|---:|
| Related work / scholarly positioning | 90/100 |
| Statistical methodology | 90/100 |
| Cutoff/control methodology | 94/100 |
| Review/adjudication implementation | 92/100 |
| Historical reconstruction implementation | 90/100 |
| Deployment-stream implementation | 85/100 |
| R0-R5 methodology | 88/100 |
| Artifact/reproducibility engineering | 90/100 |
| Manuscript/submission structure | 91/100 |
| Executed Stage-2 empirical evidence | 31/100 |
| Actual live production qualification | 55/100 |
| Stage-2 top-journal paper readiness | 82/100 |
| Full detector-effectiveness article readiness | 48/100 |

The Stage-2 paper is now much stronger as a measurement/evidence contribution, but the full pre-incident detector-effectiveness claim still requires the external gates above.
