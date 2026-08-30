# Public Acquisition Verification

- Run ID: `public-acquisition-historical-revision-v2`
- Revision: `2026-08-11`
- Structure valid: `True`
- Scientifically complete: `False`
- Release ready: `False`

## Checks
- `queue_rows`: PASS
  required=417
  observed=417
- `pilot_rows`: PASS
  required=9
  observed=9
- `queue_recomputed`: PASS
  required=True
  observed=True
- `pilot_recomputed`: PASS
  required=True
  observed=True
- `arbitrum_shortfall_preserved`: PASS
  required=True
  observed=True
- `evidence_grade_pilot_amendment_a2`: PASS
  required=complete 10-case A2 pilot with chain allocation {'arbitrum': 3, 'base': 1, 'bsc': 3, 'ethereum': 3}
  observed={'amendment_id': 'evidence-grade-pilot-amendment-a2', 'present': True, 'disposition': 'COMPLETE', 'status': 'complete', 'pilot_case_count': 10, 'cases_attempted': 10, 'strict_snapshots_closed': 10, 'queue_rows': 10, 'chain_counts': {'arbitrum': 3, 'base': 1, 'bsc': 3, 'ethereum': 3}, 'release_eligible': False}
- `acquisition_ledger`: PASS
  required=optional until rpc execute
  observed=missing
- `rpc_receipts`: PASS
  required=optional until rpc execute
  observed=missing
- `deployment_denominator`: PASS
  required=manifest-bound denominator without duplicate identities
  observed=0
- `control_candidates`: PASS
  required=deterministic control row revalidation
  observed=empty
- `positive_review_packets`: PASS
  required=deterministic positive packet bundle
  observed=417
- `control_review_packets`: PASS
  required=deterministic control packet bundle
  observed=0
- `reviewer_independence`: PASS
  required=strict accountable reviewer artifacts
  observed=waiting_external
- `counter_projection`: PASS
  required=manifest-bound deterministic counter artifact
  observed={'control_candidates': {'observed': 0, 'passed': False, 'required': 4170}, 'control_review_packets': {'observed': 0, 'passed': True, 'required': 0}, 'deployment_denominator': {'observed': 0, 'passed': False, 'required': 20000}, 'finalized_positive_adjudications': {'observed': 0, 'passed': True, 'required': 0}, 'historical_snapshots': {'observed': 417, 'passed': True, 'required': 417}, 'independent_adjudications': {'observed': 0, 'passed': False, 'required': 417}, 'independent_r5_blocks': {'observed': 0, 'passed': False, 'required': 120}, 'positive_case_review_packets': {'observed': 417, 'passed': True, 'required': 0}, 'qualified_controls': {'observed': 0, 'passed': False, 'required': 4170}, 'release_eligible_cases': 0}

## Integrity Failures
- none

## Scientific Gaps
- public RPC acquisition has not produced an append-only scientific ledger
- public RPC raw response receipts are missing
- deployment denominator shortfall remains unresolved across one or more chains
- control candidate generation remains scientifically incomplete
- reviewer independence artifacts are still waiting on external human review
- release predicates are unsatisfied; no release-eligible cases projected
- R5 prerequisites are not satisfied
- counter regeneration shows the public evidence package is not production-qualified
