# ChronosAudit independent assignment rerun

## Record

- Run: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Phase: `FEASIBILITY_GATE`
- Artifact purpose: preserve the bounded independent challenge to the frozen pilot admissibility assignment
- Evidence boundary: `support/pilot-rules.md`, `support/pilot-cohort.csv`, `support/admissibility-manifest-pilot.csv`, locally inspected public-source files already frozen for the public-data pilot
- Produced at: `2026-08-01T17:49:55Z`

## Outcome

The independent rerun leaves split eligibility unchanged for all `8/8` pilot rows. One localized disagreement remains: `CA-P08` is not independently supportable as `MATURE_INVESTIGATED_NEGATIVE` from the bounded packet alone and is safer as `RIGHT_CENSORED_UNRESOLVED` until the formal-verification artifact is bound to deployed bytecode and the follow-up search is frozen.

## Case table

| Case | Rerun mechanism family | Rerun outcome status | Rights mode | Split status | Critical gap | Disagreement |
|---|---|---|---|---|---|---|
| `CA-P01` | `reentrancy` | fixture-confirmed-positive | SmartBugs metadata/local-analysis only | `FIXTURE_ONLY` | synthetic fixture only | none |
| `CA-P02` | `unchecked-low-level-call` | fixture-confirmed-positive | SmartBugs metadata/local-analysis only | `FIXTURE_ONLY` | synthetic fixture only | none |
| `CA-P03` | `unrestricted-delegatecall` | fixture-confirmed-positive | SmartBugs metadata/local-analysis only | `FIXTURE_ONLY` | synthetic fixture only | none |
| `CA-P04` | `unprotected-initialization` | `CONFIRMED_POSITIVE` | DeFiHackLabs post-cutoff label-only | `HOLD_RECOVERABLE` | missing prediction-time source/bytecode/proxy binding | none |
| `CA-P05` | `message-validation-bypass` | `CONFIRMED_POSITIVE` | DeFiHackLabs post-cutoff label-only | `HOLD_RECOVERABLE` | missing prediction-time source/bytecode/upgrade binding | contextual nuance only |
| `CA-P06` | `donation-accounting-liquidation` | `CONFIRMED_POSITIVE` | DeFiHackLabs post-cutoff label-only | `HOLD_RECOVERABLE` | missing prediction-time source/bytecode/lineage binding | none |
| `CA-P07` | `reentrancy` | `CONFIRMED_POSITIVE` | DeFiHackLabs post-cutoff label-only | `HOLD_RECOVERABLE` | missing prediction-time source/bytecode/compiler provenance | contextual nuance only |
| `CA-P08` | `enumerated-deposit-contract-properties` | `RIGHT_CENSORED_UNRESOLVED` | metadata-link-and-citation-only | `HOLD_RECOVERABLE` | version-binding and frozen follow-up evidence absent | clear disagreement with primary manifest |

## Criterion implication

- `split_rerun_stability`: `GREEN`
  - denominator: `8/8` unchanged split-eligibility outcomes
- `mechanism_status_rubric_operability`: `AMBER`
  - denominator: `7/8` rows remain operational without a consequential disagreement; `CA-P08` remains unresolved for mature-negative proof
- Disagreements that change split eligibility: `0`
- Disagreements that require rule refinement or stronger evidence binding: `1`

## Interpretation

The independent challenge supports the current pilot rules strongly enough to keep the benchmark-core pilot alive, but not strongly enough to promote the real-case status rubric to `GREEN`. The next smallest responsible evidence step is to recover or bind the missing `CA-P08` formal-verification and follow-up artifacts, then rerun only the affected status slice.
