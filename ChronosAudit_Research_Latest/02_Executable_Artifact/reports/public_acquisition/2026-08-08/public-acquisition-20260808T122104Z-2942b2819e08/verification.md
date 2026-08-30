# Public Acquisition Verification

- Run ID: `public-acquisition-20260808T122104Z-2942b2819e08`
- Revision: `2026-08-08`
- Structure valid: `False`
- Scientifically complete: `False`
- Release ready: `False`

## Checks
- `queue_rows`: PASS
  required=417
  observed=417
- `pilot_rows`: PASS
  required=9
  observed=9
- `queue_recomputed`: FAIL
  required=True
  observed=False
- `pilot_recomputed`: FAIL
  required=True
  observed=False
- `arbitrum_shortfall_preserved`: PASS
  required=True
  observed=True
- `evidence_grade_pilot_amendment_a2`: PASS
  required=complete 10-case A2 pilot with chain allocation {'arbitrum': 3, 'base': 1, 'bsc': 3, 'ethereum': 3}
  observed={'amendment_id': 'evidence-grade-pilot-amendment-a2', 'present': True, 'disposition': 'COMPLETE', 'status': 'complete', 'pilot_case_count': 10, 'cases_attempted': 10, 'strict_snapshots_closed': 10, 'queue_rows': 10, 'chain_counts': {'arbitrum': 3, 'base': 1, 'bsc': 3, 'ethereum': 3}, 'release_eligible': False}
- `acquisition_ledger`: PASS
  required=schema-valid append-only hash chain
  observed=7506
- `rpc_cases_preserved`: PASS
  required=attempt/failure/terminal rows with explicit closure
  observed=417
- `rpc_receipts`: PASS
  required=manifest-bound raw response receipts
  observed=2362
- `deployment_denominator`: PASS
  required=manifest-bound denominator without duplicate identities
  observed=0
- `control_candidates`: PASS
  required=deterministic control row revalidation
  observed=empty
- `positive_review_packets`: FAIL
  required=deterministic positive packet bundle
  observed=positive_case_review_packets packet payload differs from deterministic bundle
- `control_review_packets`: PASS
  required=deterministic control packet bundle
  observed=0
- `reviewer_independence`: PASS
  required=strict accountable reviewer artifacts
  observed=waiting_external
- `counter_projection`: FAIL
  required=manifest-bound deterministic counter artifact
  observed=counter artifact differs from deterministic regeneration

## Integrity Failures
- case_queue differs from deterministic recomputation
- pilot_case_queue differs from deterministic recomputation
- positive review packet verification failed: positive_case_review_packets packet payload differs from deterministic bundle
- counter artifact verification failed: counter artifact differs from deterministic regeneration

## Scientific Gaps
- public RPC acquisition remains incomplete for at least one pilot case
- deployment denominator shortfall remains unresolved across one or more chains
- control candidate generation remains scientifically incomplete
- reviewer independence artifacts are still waiting on external human review
- AI-only adjudication protocol amendment is missing
