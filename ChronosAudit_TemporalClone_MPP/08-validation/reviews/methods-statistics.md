# Methods and statistics review

Status: **INTERNAL SELF-REVIEW**

## Strengths

- Frozen finite cohort and fail-closed envelope checks.
- Prespecified landmark, identity, and proxy-indicator definitions.
- Counts and proportions derived without imputation, model fitting, multiplicity fishing, or causal inference.
- Wilson intervals labeled as descriptive uncertainty aids rather than superpopulation inference.
- Timestamp-rule correction disclosed in the deviation record.
- Deterministic standard-library analysis with unit/integration tests.

## Residual risks

- Deployment and incident timestamps are inherited from upstream envelopes.
- Provider agreement was not independently recreated in this run.
- Exact/stripped runtime equality is a fingerprint family, not semantic equivalence.
- Cluster-adjusted detector evaluation is future work, not an implicit result.

Internal disposition: methods match the narrowed descriptive question; independent reproduction remains required.
