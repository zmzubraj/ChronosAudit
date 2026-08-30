# External-validation disposition

## Decision

External field validation is **N/A for the frozen-cohort descriptive estimands**.
The paper asks what is observable inside the 417 supplied historical case envelopes;
it does not claim prevalence in all smart contracts, detector performance, causal risk,
or deployment benefit. No additional cohort can validate that same finite-population
description more directly than a full deterministic census of the frozen rows.

## Required independent check

An independent reproducer should run the test suite and analysis from a clean checkout,
confirm the input manifest, and compare all result-file SHA-256 values. This is a
reproducibility requirement, not field validation. Until performed by a distinct
qualified reviewer, it remains open and the paper must not claim independent replication.

## Escalation rule

Any expansion to population prevalence, semantic clone detection, vulnerability risk,
or operational effectiveness invalidates this N/A disposition and requires an external
benchmark or field study designed for that claim.
