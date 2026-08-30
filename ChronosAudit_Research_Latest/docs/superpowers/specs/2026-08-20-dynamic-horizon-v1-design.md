# ChronosAudit DYNAMIC_HORIZON_V1 Design

Status: USER-APPROVED DESIGN, written specification pending user review  
Design date: 2026-08-20  
System: ChronosAudit Stage 2 control qualification  
Author principal: `zmzubraj`  
Governance label: `AI_DESIGNED_USER_APPROVED`  
Approval statement: `DYNAMIC_HORIZON_V1 approved`  
Outcome-inspection attestation: `NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_HORIZON_FREEZE`

## 1. Decision

The fixed-duration horizon menu is replaced by `DYNAMIC_HORIZON_V1`: an outcome-blind, pair-specific, uncertainty-adjusted hierarchical survival-quantile model. It assigns an integer-day horizon to each frozen positive-control pair using only information available at or before the positive prediction cutoff.

The model may assign values such as 74, 128, or 243 days. It may not select a value because it has already matured, because a control later experienced an incident, or because the value helps fill the 4,170-row target.

This approval authorizes implementation and verification of the dynamic-horizon method. It does not by itself authorize source acquisition, RPC execution, control selection, qualification, Recovery3 mutation, counter increments, or release promotion.

## 2. Scientific boundary

### 2.1 Permitted cutoff-safe inputs

- chain;
- frozen positive mechanism family;
- protocol family;
- cutoff-time proxy or upgradeability family;
- cutoff-time architecture and normalized code-pattern family;
- cutoff-time code size and prespecified complexity class;
- contract age at the prediction cutoff;
- source-verification state at the cutoff;
- latency observations from a frozen reference cohort whose risk-entry, incident/censoring time, and provenance pass the reference-cohort verifier.

### 2.2 Prohibited inputs

- whether a candidate control was exploited after the cutoff;
- post-cutoff activity or last-observed outcome;
- qualification status or evidence-check results;
- a candidate control's future exploit latency;
- availability or maturity as of model-build time;
- target-completion pressure, allocation success, or replacement opportunity.

Any prohibited field in a model input, stratum definition, fallback decision, or assignment hash makes the affected assignment invalid.

## 3. Reference-latency contract

Each reference row records a frozen risk-entry timestamp, event or censoring timestamp, event-observed flag, latency in whole or fractional days before final rounding, source paths and hashes, and the cutoff-safe feature vector.

The preferred risk-entry is the canonical `prediction_cutoff_time` only when it is independently traceable to the frozen landmark policy and occurs before the qualifying incident. Current projections commonly derive this landmark from deployment plus 24 hours, but the verifier must check each row rather than assume that convention.

An incident date without a verified seconds-precision timestamp is not silently promoted to an exact latency. Such a row must either carry a prespecified interval-censoring representation supported by the model or be excluded with an explicit reason. The first implementation will fail closed on interval-censored or unverified incident timing rather than invent precision.

Reference rows must be frozen before candidate-control outcomes are inspected. Candidate controls and selected controls are never members of the reference cohort for the same run.

## 4. Deterministic model

For each eligible pair, the model searches the following hierarchy in order:

1. exact mechanism + protocol + architecture/proxy pattern;
2. broader architecture + protocol pattern;
3. chain-level pattern;
4. global pooled pattern.

The first stratum satisfying the frozen effective-sample-size and event-information thresholds is used. The thresholds, feature normalization, tie-breaking, missing-value rules, and fallback order are part of the signed model specification and cannot change after assignments are generated.

Within the selected stratum:

1. estimate the survival distribution using the frozen reference cohort and its explicit censoring indicators;
2. estimate the upper exploitation-latency quantile at probability 0.95;
3. compute a one-sided uncertainty allowance using the prespecified deterministic inference procedure and seed;
4. calculate `ceil(estimated_quantile_days + uncertainty_allowance_days)`;
5. apply only data-derived lower and upper safety bounds frozen in the model artifact;
6. return `INSUFFICIENT_EVIDENCE` instead of an assignment when the pooled stratum cannot support the quantile or uncertainty calculation.

The implementation plan must freeze the exact estimator, confidence level, resampling or analytic uncertainty method, seed derivation, minimum effective sample size, minimum event count, and safety-bound calculation before production assignments are produced. These are scientific parameters, not implementation defaults.

## 5. Pair assignment and maturity

Every assignment binds:

- positive case ID and positive record hash;
- candidate control chain-address identity and candidate row hash;
- prediction cutoff;
- frozen feature vector and its SHA-256;
- selected stratum and fallback level;
- effective sample size and event count;
- estimated 0.95 quantile;
- uncertainty allowance;
- data-derived lower and upper bounds;
- assigned integer-day horizon;
- maturity timestamp, calculated as cutoff plus assigned horizon;
- model version, model hash, reference-cohort hash, and assignment-record hash.

A control can be evaluated as a mature negative only when the last independently verified observation reaches its maturity timestamp and no qualifying incident occurs first. Incomplete follow-up is `CENSORED_INCOMPLETE`; unresolved evidence is `UNKNOWN`. Neither status is a negative.

The selected cohort is frozen before outcome review. An immature, censored, failed, or incident-positive control cannot be replaced with a more favorable control after selection.

## 6. Artifacts

The implementation produces the following immutable, hash-bound artifacts:

1. `dynamic_horizon_spec.json`;
2. `reference_latency_cohort.csv`;
3. `reference_cohort_manifest.json`;
4. `cutoff_safe_feature_manifest.json`;
5. `dynamic_horizon_model.json`;
6. `dynamic_horizon_assignments.csv`;
7. `dynamic_horizon_verification.json`;
8. `user_approval_record.json`.

The approval record binds principal `zmzubraj`, this specification's SHA-256, the model specification and reference-cohort hashes, the exact attestation, the approval time, and the relevant OpenSSH signature namespace.

## 7. Authority and counters

The dynamic-horizon verifier is non-authorizing. It can prove schema, hashes, cutoff safety, deterministic reconstruction, hierarchy use, assignment math, maturity calculations, and signature validity. It cannot prove real-world author identity from key possession alone.

The author approval is not independent external human review. Therefore:

- `independent_human_adjudications` remains unchanged;
- the model and its assignments may be labeled `AI_DESIGNED_USER_APPROVED`;
- AI-generated or author-approved outcome checks cannot be relabeled as independent human evidence;
- the existing canonical `qualified_controls` counter remains fail-closed unless its separate qualification contract is satisfied;
- an AI/user-approved internal projection, if later desired, must have a separate name and counter and must never be merged into `qualified_controls`.

The current qualification verifier requires human review for maturity, censoring, and mechanism separation and a qualification authority distinct from every human reviewer and owner. This design does not silently weaken that rule. Removing it would be a separate governance change and would reduce the attainable claim to an explicitly non-independent internal result.

## 8. Signing and key handling

The private key is generated and retained outside Codex and outside the repository. Codex may prepare canonical signing payloads and verify signatures, but it may not generate, read, copy, log, or store the private key.

The repository stores only the reviewed public key, allowed-signers entry, public-key fingerprint, identity-binding record, registration decision, and signatures over canonical payloads. Registration must state that key possession is not independent proof of the real-world identity behind `zmzubraj`.

## 9. Failure handling

The system fails closed when:

- reference timing or provenance is incomplete;
- a prohibited post-cutoff field is present;
- a stratum cannot meet frozen information thresholds;
- assignment reconstruction changes a value or fallback level;
- any input, model, approval, signature, or evidence hash mismatches;
- a maturity evaluation occurs before the assigned timestamp;
- incomplete follow-up is presented as incident-free maturity;
- assignment or evidence rows are replaced after outcome inspection;
- an AI/user-approved result is presented as independent human review.

No failure triggers automatic relaxation, shorter horizons, favorable replacement, stage promotion, or Recovery3 mutation.

## 10. Verification plan

Implementation follows test-driven development. Required tests include:

- deterministic model and assignment regeneration;
- exact hierarchy and fallback behavior;
- rejection of every prohibited post-cutoff field;
- rejection of unverified or imprecise reference timing;
- sparse-stratum fallback and pooled `INSUFFICIENT_EVIDENCE`;
- uncertainty and data-derived bound reconstruction;
- pair-specific maturity calculation;
- no-replacement enforcement after cohort freeze;
- signature, principal, artifact-hash, and namespace binding;
- separation between dynamic-horizon approval and qualification/counter authority;
- preservation of independent-human counters at zero absent real independent review.

Focused tests must be followed by the full relevant control/public-acquisition regression suite and fresh counter projection verification. Passing tests do not themselves authorize acquisition or change a scientific counter.

## 11. Implementation sequence

1. Freeze schemas and write failing tests for the reference cohort, model, assignments, and signed approval.
2. Implement deterministic reference-cohort validation and cutoff-safe feature extraction.
3. Implement the frozen hierarchical survival-quantile estimator and uncertainty calculation.
4. Implement assignment and verification artifacts.
5. Replace the fixed-duration horizon request/decision path with the dynamic model while retaining historical compatibility only as non-current evidence.
6. Register the reviewed public key and verify the author signature.
7. Rebuild the control prespecification and source-acquisition requests against the new horizon contract.
8. Stop before network acquisition unless every narrow signed gate verifies.

## 12. Residual scientific limits

- The current reference cohort may be too small within exact strata and may lack sufficiently precise, independently corroborated incident timestamps.
- A 0.95 upper quantile can be unstable under sparse events or heavy censoring; uncertainty must lengthen the horizon or yield `INSUFFICIENT_EVIDENCE`.
- Dynamic horizons improve pattern sensitivity but do not prove absence of future exploitation after maturity.
- User approval establishes accountable author direction, not independent validation, external replication, or release qualification.

