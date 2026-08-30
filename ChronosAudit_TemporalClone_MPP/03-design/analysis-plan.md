# Frozen Analysis Plan

## Primary estimands

1. `n/N` and Wilson 95% interval for landmark eligibility at 1h, 24h, 7d, and 30d.
2. For each identity abstraction: number of unique identities, duplicate groups, rows in duplicate groups, maximum group size, cross-address duplicate groups/rows, and cross-chain duplicate groups/rows.
3. `n/N` and Wilson 95% interval for ERC-1967 implementation, admin, beacon, ERC-1167 target, and the prespecified any-proxy union.

## Secondary summaries

- chain distribution;
- minimum, 10th, 25th, 50th, 75th, 90th percentile, and maximum cutoff lead;
- minimum, median, and maximum deployment-to-incident age;
- identity-abstraction sensitivity and lower-bound interpretation.

## Uncertainty

Wilson score intervals describe finite-cohort proportions as a communication aid. Because all 417 cohort rows are analyzed, no sampling-based population inference is made. Quantiles use R-7/NumPy-default linear interpolation.

## Multiplicity and hypothesis testing

No null-hypothesis significance tests or multiplicity-adjusted p-values are planned. The paper is a descriptive measurement audit. Differences between identity abstractions are reported as deterministic counts, not stochastic treatment effects.

## Missingness and exclusions

The run fails closed on missing required values. There are no analysis-time exclusions. Unsupported proxy patterns remain undetected rather than imputed.

## Robustness/boundary checks

- compare chain-address with address-only identity;
- compare exact with metadata-stripped runtime identity;
- report cross-address and cross-chain collisions;
- report proxy components separately from the any-proxy union;
- disclose that exact bytecode equality is a lower bound on semantic relatedness.

## Reproducibility

Use only `derive_mpp_results.py`, its unit tests, the frozen manifest, and standard-library Python. Outputs are sorted and omit wall-clock timestamps so reruns are byte-identical.
