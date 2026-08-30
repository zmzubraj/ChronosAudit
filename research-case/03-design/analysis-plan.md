# ChronosAudit Analysis Plan Blueprint

> Draft status: proposed analyses only. No confirmatory dataset has been opened under this plan and no result has been produced.

## Estimands

Let `M_r(b,H)` denote horizon-specific precision among alerts at split rung `r`, alert budget `b`, and follow-up horizon `H`, with unresolved outcomes handled under the frozen censoring policy. The primary estimand is `Theta = {M_R0, M_R1, M_R2, M_R3, M_R4}`. The confirmatory contrast is `Delta_joint = M_R4 - M_R1`; the descriptive survival ratio is `SR_joint = M_R4 / M_R1` when the denominator is nonzero.

## Primary analysis

The preferred estimator is horizon precision using inverse-probability-of-censoring weights if censoring assumptions and sample size are defensible. Otherwise the primary analysis is downgraded to partial-identification bounds. Uncertainty uses a cluster bootstrap over frozen joint-independence blocks rather than an IID row bootstrap. Every rung reports independent-block counts, eligible cases, exclusions, confirmed outcomes, unresolved cases, and alert counts.

## Multiplicity

The analysis is estimation-first. If formal tests are retained, `Delta_joint` is tested first; adjacent rung contrasts follow only after the primary test and use Holm familywise correction. Mechanism, chain, proxy, family, and threshold subgroup analyses are exploratory and, if tested, use false-discovery-rate control with transparent multiplicity counts.

## Missing data

Missing cutoff-critical provenance produces `HOLD_RECOVERABLE` or exclusion, never silent imputation. `RIGHT_CENSORED_UNRESOLVED` outcomes remain censored. The report must show missingness and exclusion by rung and test how exclusion changes the eligible population. Any imputation for noncritical covariates must be frozen, nested within training, and sensitivity-tested.

## Sensitivity

Required sensitivities include pessimistic and optimistic bounds for unresolved alerted cases; alternate censoring windows; alternate clone thresholds; coarse versus fine lineage and mechanism ontologies; time-only versus joint grouping; equalized sample-size analyses to distinguish contamination removal from sample collapse; stronger-negative frames; alternate calibration mappings; and leave-one-family-out influence checks.

## Exploratory boundary

Confirmatory elements are cohort eligibility, manifest schema, split ladder, outcome states, `b*`, `H*`, `tau_review`, primary estimand, baseline portfolio, and uncertainty procedure. Any post-freeze change or analysis motivated by observed outcomes is exploratory and must be logged with its timing and consequence.

## Status

`NOT RUN`. All thresholds and ontology versions remain placeholders requiring accountable human freeze and later independent verification.
