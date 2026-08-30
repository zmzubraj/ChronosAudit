# Public Acquisition Final Verification

Date: 2026-08-08  
Canonical run: `public-acquisition-20260808T122104Z-2942b2819e08`  
Verified subject commit: `b1cbdca1974dceee1edca10cc318dd0b24d8c850`
Disposition: `IMPLEMENTATION_COMPLETE_EVIDENCE_GATES_BLOCKED_FAIL_CLOSED`

## Outcome

The public acquisition workflow, frozen 417-case crawl, receipt recovery, denominator ingest, counter projection, and qualification gate are mechanically verified under the recorded test scope. Structural verification passes. Scientific completion and release readiness remain false.

Activity must not be confused with qualification:

| Measure | Activity observed | Scientifically qualifying |
| --- | ---: | ---: |
| Cases crawled | 417 | 0 historical snapshots |
| RPC receipts | 2,362 | 0 independently sufficient historical snapshots |
| Target-chain deployment candidates parsed | 548,330 | 0 denominator rows |
| Positive review packets prepared | 417 | 0 independent adjudications |
| Control candidates | 0 | 0 qualified controls |
| Independent R5 blocks | 0 | 0 |
| Release-eligible cases | 0 | 0 |

## Fresh verification

- `uv sync --locked`: exit 0; 27 packages resolved and 16 checked.
- `uv run pytest -q`: exit 0; 163 tests passed in 29.83 seconds.
- `uv run python verify_stage2.py`: exit 0; `pass=true`, public acquisition structure valid, scientific evidence gates blocked fail-closed.
- `uv run python independent_regenerate.py`: exit 0; deterministic and all listed outputs passed.
- Canonical `project`: exit 0; incomplete, zero release-eligible cases.
- Explicit and latest public-acquisition verifiers: exit 0; `structure_valid=true`, `scientifically_complete=false`, `release_ready=false`, no integrity failures.
- Run-specific production qualifier: exit 3 by design; `qualified=false`, both manifest and artifact error lists empty, and every failure is an unsatisfied scientific gate.
- Qualification-root fuzz review: approved after invalid UTF-8, invalid JSON, array, null, scalar, boolean, empty-object, and canonical-object tests; malformed roots write structured output and exit 3 without traceback.
- Whole-change review: approved after correcting the top-level release date and stale test-count metadata; the resulting release-manifest hash is recorded in the machine-readable QA artifact.

The machine-readable command ledger, exact artifact hashes, environment versions, and known limitations are in `public_acquisition_final_verification.json`.

## Boundaries

- The nine-case pilot preserves the one-case Arbitrum shortfall; no case was duplicated or relabeled to reach ten.
- Executed RPC observations used the configured public `publicnode-*` and `one-rpc-*` endpoints. Their operator identity and independence remain unverified.
- The parsed Sourcify deployment rows did not carry the required creation-proof fields; strict denominator qualification therefore stayed at zero for every target chain.
- Independent adjudication remains `WAITING_EXTERNAL`; AI-generated or internal packets do not count.
- Public accessibility is not redistribution-rights clearance. No licensing or terms artifact was captured.
- The large raw/processed evidence package remains a distribution risk. The active manifests no longer depend on the retired feature worktree: 7,148 run-owned references were rebased to output-root-relative paths under a recorded path-only migration, with no scientific counter advancement.
- No new archive/RPC query, human-review impersonation, release promotion, or research-phase promotion occurred during final QA.

## Scientific counters

- Historical snapshots: **0/417**
- Independent adjudications: **0/417**
- Deployment denominator: **0/20,000**
- Control candidates: **0/4,170**
- Qualified controls: **0/4,170**
- Independent R5 blocks: **0/120**
- Release-eligible cases: **0**

This is the intended fail-closed result. The system now preserves and distinguishes real acquisition activity from the evidence required for scientific qualification.
