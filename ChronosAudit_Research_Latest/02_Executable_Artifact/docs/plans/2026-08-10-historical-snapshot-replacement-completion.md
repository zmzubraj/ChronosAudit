# Historical Snapshot Replacement Completion Plan

## Global Constraints

- Preserve the sealed parent 360/417 run byte-for-byte; never overwrite or relabel its 57 temporal exclusions.
- Treat the authoritative candidate acquisition run as evidence input, not counter authority.
- Fail closed on any path escape, symlink, hash mismatch, schema mismatch, provider-family/endpoint non-independence, receipt disagreement, incomplete strict snapshot, or population drift.
- Never persist or print provider credentials or full secret-bearing URLs.
- Final scientific advancement requires an offline verifier with `counter_authority=true`; acquisition summaries alone cannot advance counters.
- The revised cohort must contain exactly 417 cases: the 360 verified parent cases plus exactly 57 independently verified replacements, with quotas Ethereum 16, BSC 38, Base 3.
- Selection must use the frozen chain-global candidate order and must not optimize on detector outcomes.

## Task 1: Candidate archive offline verifier

Implement an offline-only verifier and CLI for a sealed candidate qualification run. Recompute every candidate disposition from preserved run inputs, case envelopes, provider identity, raw receipt paths and hashes, two-family/two-endpoint agreement, canonical incident-block proof, and referenced strict historical case artifacts. Emit a deterministic verification report and 145-row projection. `counter_authority` is true only when all integrity checks pass. Verify the authoritative run reports 116 eligible candidates with chain counts Ethereum 56, BSC 49, Base 11.

## Task 2: Deterministic replacement finalization

Implement a finalizer and CLI that requires a valid candidate-verifier report/projection with counter authority. Select the first verified candidates in the frozen chain-global order for quotas Ethereum 16, BSC 38, Base 3; bind them one-to-one to the sorted 57 excluded parent slots; emit a replacement mapping, revised 417-case population, provenance manifest, and recursive hashes. Preserve all parent and candidate evidence links.

## Task 3: Revised historical snapshot evidence assembly

Implement an immutable revision-run assembler that combines the 360 independently verified parent case artifacts with the 57 selected verified candidate strict-snapshot artifacts without new RPC calls. Normalize evidence into a new sealed run root, preserve source-run bindings, regenerate aggregate receipt/provider/qualification manifests, and emit a run manifest compatible with the existing historical snapshot verifier.

## Task 4: Independent verification and counter projection

Run the existing historical-snapshot verifier against the revised sealed run. Require exactly 417/417 observed, no integrity errors, and `counter_authority=true` before projecting the historical-snapshot counter. Preserve all reports and hashes. Do not advance any other scientific counter.

## Task 5: Integrated QA and adversarial review

Run focused and full tests, compile checks, diff checks, sealed-artifact hash checks, secret-safety checks, and an independent final code/evidence review. Report residual scientific gates separately.
