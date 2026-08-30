# Stage 2 AI-Only Adjudication Protocol Amendment v1

Effective date: 2026-08-17

## Decision

`AI_ONLY_TRIANGULATION_V1` is a separate non-human analytic track. After all of its own evidence, reliability, sensitivity, and accountable-author sign-off gates pass, it may permit only:

- internal analysis
- engineering
- manuscript-draft preparation

It cannot increment `independent_human_adjudications`, establish human or institutional reviewer independence, satisfy an external release gate, or prove submission readiness.

The canonical human counter remains 0/417 until eligible external human decisions exist. The AI result is reported only through the separate `independently_ai_adjudicated` counter.

## Frozen execution contract

Two primary model runs must process the same hash-bound packet without seeing the peer decision, detector prediction, final benchmark label, or post-incident model output. Every run records:

- run ID, provider, model ID, and model version or provider-resolved snapshot
- prompt ID, exact prompt text, and prompt SHA-256
- temperature, seed, and blinding declaration
- packet SHA-256
- UTC start and completion timestamps
- protocol family, primary root cause, rationale, and evidence references
- confidence and decision SHA-256

The primary decisions are frozen before comparison. Matching protocol and mechanism labels produce `AI_MODEL_CONSENSUS`. A disagreement requires `AI_DISAGREEMENT_ADJUDICATED` and a third frozen model/run distinct from both primaries. The final AI binding covers both primary decision hashes, any adjudicator decision hash, final labels, confidence, timestamp, sensitivity rows, and the explicit `NONE` human-counter effect.

## Reliability and sensitivity

The track reports raw agreement, Cohen kappa, Gwet AC1, and nominal Krippendorff alpha for protocol and mechanism labels. Internal progression additionally requires raw agreement of at least 0.80 on both dimensions, complete case coverage, no validation errors, alternate-prompt stability reporting, high-confidence-only reporting, and hash-bound accountable-author sign-off.

No aggregate statistic repairs invalid packets, missing evidence, unresolved disagreements, low-confidence cases, or model/run reuse.

## Current execution disposition

The v1.1 execution is complete for the separate AI counter. All 417 packets are hash-bound to the frozen positive-case snapshot. A pinned read-only DeFiHackLabs checkout at commit `2c99b565ae24ea2006adf181da20c4419b3edc30` supplied direct exploit-source text for 357 packets; the other 60 packets were required to remain `UNKNOWN_INSUFFICIENT_EVIDENCE` unless their own packet references supported more.

Two blinded primaries completed 417 decisions each. They agreed on 274 cases and disagreed on 143; every disagreement received a distinct third-model adjudication. The alternate-prompt sensitivity run also covered 417/417. Deterministic validation reports zero invalid rows, so `independently_ai_adjudicated` is 417/417. The human counter remains 0/417 with counter effect `NONE`.

The internal progression gate is nevertheless `FAIL_RELIABILITY_THRESHOLD`. Protocol-family raw agreement is 0.6667 and primary-root-cause raw agreement is 0.6763, below the frozen 0.80 minimum. Alternate-prompt stability is 0.7866. Third-model resolution completes case dispositions but does not retroactively improve independent-primary reliability. The failed gate is preserved rather than tuning outputs toward consensus.

## Author sign-off

The accountable-author directive in the current task is preserved as a SHA-256-bound session attestation covering the protocol, results, and reliability/sensitivity summary. Its role identifier is `current_workspace_user_as_accountable_author`; this is not external cryptographic or institutional identity proof. The attestation verifies, but it cannot repair the failed reliability threshold.

## External disclosure

Any external manuscript or submission using this track must disclose that:

- adjudicators were AI models, not people;
- model agreement may reflect shared training data and correlated errors;
- runtime model aliases may drift unless the provider exposes an immutable snapshot;
- the AI track supported internal progression only;
- human adjudication remained incomplete unless separately evidenced; and
- target-venue policies and accountable-human approval remain controlling.

The machine-readable authority is [the versioned amendment YAML](../../config/ai_adjudication_protocol_amendment_v1.yaml).
