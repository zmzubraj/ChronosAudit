# ChronosAudit Protocol Blueprint

> Draft status: concept-only protocol. Not independently verified, not preregistered, not authorized for execution, and not evidence of feasibility `GO`.

## Research question

Among smart-contract exploit detectors evaluated on a prediction-time-eligible population, how much apparent performance survives progressively stricter separation by time, protocol/entity lineage, normalized source and bytecode clones, proxy/implementation family, attacker family where applicable, and exploit-mechanism family, when unresolved contracts remain right-censored and decisions are priced under frozen alert budgets?

The active claim is the retrospective `C001-MEASUREMENT` estimand. A sealed prospective deployment is a future validation surface and is not part of this protocol's executable scope.

## Design

This is a preregistered computational-benchmark design with five evaluation rungs:

1. `R0_RANDOM`: random split, retained only as a weak reference.
2. `R1_TIME`: prediction-time separation.
3. `R2_TIME_LINEAGE`: time plus protocol/entity lineage separation.
4. `R3_TIME_LINEAGE_CLONE`: time, lineage, normalized source/bytecode clone, and proxy/implementation separation.
5. `R4_JOINT`: all prior controls plus attacker-family separation where applicable and exploit-mechanism-family holdout.

Model version, retrieval surface, feature policy, cohort, family assignments, thresholds, and analysis code must be frozen before confirmatory scoring. No current artifact authorizes execution.

## Population or system

The primary unit is one `contract_at_cutoff` tuple: target contract or proxy root, prediction timestamp/block, and immutable admissibility-manifest revision. Fixture contracts may test plumbing but never enter scientific denominators.

Eligible real cases require a lawful-use path and complete prediction-time provenance for every critical manifest field. Outcome states are:

- `CONFIRMED_POSITIVE`;
- `MATURE_INVESTIGATED_NEGATIVE`, only under a frozen property-bounded claim, follow-up window, and independent adjudication;
- `RIGHT_CENSORED_UNRESOLVED`.

Unresolved contracts must never be silently relabeled negative.

## Controls

- prediction-time admissibility for every source and feature;
- group separation by lineage, normalized source clone, bytecode clone, proxy implementation, attacker family, and mechanism family;
- strong frozen baselines evaluated under equal information budgets;
- exclusion of post-incident reports, exploit traces, patches, later verification, and replay artifacts from prediction inputs;
- surveillance-style negatives from the eligible population rather than convenience fixtures;
- immutable decision, exclusion, and family-assignment logs.

## Endpoints

Primary endpoint: the capability-survival profile across `R0`–`R4` at a frozen alert budget `b*` and follow-up horizon `H*`.

Primary contrast: `Delta_joint = Precision_R4(b*,H*) - Precision_R1(b*,H*)`.

Secondary summaries: survival ratio, recall or coverage among adjudicated positives, calibration among non-abstained alerts, alerts per period, and workload `b* × tau_review`. Values for `b*`, `H*`, and `tau_review` are unresolved and require accountable freezing before execution.

## Bias and leakage

The design addresses temporal leakage, lineage leakage, clone leakage, mechanism recurrence, attacker-side reuse, unrealistic negative sampling, label-confirmation bias, and scaffold drift. Remaining threats include unstable family ontologies, informative censoring, sample-size collapse under strict grouping, baseline mismatch, incomplete rights/provenance, and hidden proprietary prior art.

## Stopping rules

Stop or narrow the benchmark if representative real manifests remain incomplete, independent reruns change split eligibility, the mature-negative rule cannot be reproduced, lawful strong baselines cannot be frozen, or the strictest split leaves too few independent blocks for decision-relevant precision. A null or collapsed result is retained as a scientifically useful negative finding.

## Ethics

Current scope is public-source, non-interventional computational methods work. Archive/RPC access, live targets, private vulnerability data, analyst-participant workload measurement, partner data, disclosure operations, and prospective shadow deployment require separate accountable legal, ethics, safety, data, and institutional authority. No actionable vulnerability or exploit recipe is authorized for release.

## Status

`NOT RUN`. This blueprint is a human-reviewable design artifact only and does not advance the schema-v4 `STUDY_DESIGN` gate.
