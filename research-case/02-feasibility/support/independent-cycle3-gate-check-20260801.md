# Independent pilot-cycle-3 gate check

- Verification ID: `FEAS-A5-CYCLE3-REASSESSMENT-001`
- Reviewer: `/root/chronosaudit_cycle3_independent_gate_check`
- Contract: read-only, bounded to the cycle-3 support packet and frozen progression criteria
- Verdict: `REMEDIATE`
- Lowest defensible gate decision: `PILOT_FIRST`

## Criterion verdicts

| Criterion | Verdict | Independent basis |
|---|---|---|
| `manifest_completeness` | `AMBER` | `CA-P04` remains `HOLD_RECOVERABLE`; the DNS failure retrieved no historical bytecode and `0/5` real incidents remain split eligible. |
| `split_rerun_stability` | `GREEN` | No existing split disposition changed; the previous independent rerun remains `8/8`, and `CA-P09` is status-trial-only. |
| `mechanism_status_rubric_operability` | `AMBER` | The `CA-P09` rule is genuinely frozen, but no mature-negative result exists before its follow-up and independent adjudication close. |
| `cost_access_envelope` | `AMBER` | The route was exercised at zero incremental cost but failed DNS; usable access remains unproven rather than unbounded or impossible. |

## Required challenge findings

1. The two Cloudflare requests count as `EXECUTED_UNSUCCESSFUL`, not as a
   successful archive read. Both ended before HTTP or JSON-RPC response.
2. `CA-P04` is not a complete real-case manifest. Prediction-time source,
   bytecode-to-source, proxy-family, compiler, clone, and lineage bindings remain
   incomplete.
3. `CA-P09` may not be called mature. It is
   `PREREGISTERED — RIGHT_CENSORED_UNRESOLVED`; the earliest possible
   mature-negative adjudication is `2027-08-01T19:28:31Z` and still requires the
   four evidence snapshots plus independent review.

## Denominator clarification

The reviewer identified one non-outcome-changing ambiguity: whether a
`STATUS_TRIAL_ONLY` row should enter manifest-completeness denominators before
its follow-up closes. Root resolves this prospectively as follows: `CA-P09` is
excluded from benchmark-core manifest-completeness and mature-negative
denominators while right-censored; it enters only the status-trial registry.
This preserves the real-incident denominator at `0/5` and does not promote any
criterion.

## Conclusion

Cycle 3 replaces unexecuted assumptions with a measured access failure and a
properly frozen but unfinished status trial. The evidence is internally
proportionate and should be preserved, but it requires remediation and does not
open `STUDY_DESIGN`.
