# Feasibility-pilot support artifacts

These files support the bounded public-data-only ChronosAudit feasibility pilot.
They are not definitive benchmark data and must not be used for confirmatory
performance claims.

- `pilot-cohort.csv` freezes the smallest heterogeneous trial cohort and records
  where a fixture, label-only incident record, or property-bounded mature
  investigated negative is being used.
- `normalize_solidity.py` implements a pilot-only lexical normalization check.
  It removes comments and whitespace outside quoted strings, hashes the result,
  and makes no semantic-equivalence claim.
- `pilot-cycle2-public-provenance.md` preserves the public prediction-time
  provenance and formal-artifact audit for the five held real cases.
- `admissibility-manifest-pilot-cycle2.csv` is a new cycle-2 revision. The
  frozen cycle-1 manifest remains unchanged for audit history.
- `archive-access-cost-envelope-20260801.csv` records documented provider
  routes, current public limits, rights constraints, and the fact that no
  account, API, BigQuery, or RPC access was exercised in cycle 2.
- `pilot-cycle3-archive-access.md` and the two
  `archive-test-ca-p04-*.json` files preserve the exact authorized method,
  requests, DNS failures, and interpretation for the single exercised route.
- `admissibility-manifest-pilot-cycle3.csv` is the immutable cycle-3 manifest
  attempt; it does not replace either earlier revision.
- `mature-negative-trial-cycle3.md` and
  `mature-negative-candidate-binding.json` freeze the `CA-P09` status trial and
  keep it right-censored until its follow-up and independent adjudication close.

The source repositories remain external and are identified by immutable commit
hash. No third-party source is redistributed in this directory.
