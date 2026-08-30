# Stage 2 dynamic follow-up horizon: accountable author kit

Current method: `DYNAMIC_HORIZON_V1`  
Author principal: `zmzubraj`  
Governance: `AI_DESIGNED_USER_APPROVED`  
Attestation: `NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_HORIZON_FREEZE`

The historical fixed-duration workflow is preserved for verification of old evidence only. It is not the current method and must not be used to authorize acquisition, selection, qualification, counters, RPC, or Recovery3 mutation.

## 1. Prepare the two scientific inputs

The reference cohort must contain verified seconds-precision risk-entry and event/censoring times, explicit censoring indicators, provenance hashes, and cutoff-safe features. Candidate controls cannot be members of the reference cohort for the same run.

The pair-feature CSV may contain only the approved cutoff-safe fields. Outcome, incident, post-cutoff activity, last observation, maturity, qualification, allocation pressure, replacement state, and future-latency fields make the entire input invalid.

The approved reference identity rule is `REFERENCE_IDENTITY_DEDUP_V1`: use one row per normalized chain-address, choose the earliest frozen risk-entry, then the first qualifying incident strictly afterward, with ascending case ID as the deterministic tie-break. Cutoff-safe protocol, proxy, or complexity values that are unavailable use the canonical explicit category `unknown`; source verification that is not established at the cutoff is `false`.

## 1A. Build the reference-side package

The current 417 verified snapshots deterministically assemble to 410 unique chain-address identities:

```bash
./.venv/bin/python build_stage2_control_dynamic_horizon_reference.py \
  --positive-projection processed/stage2_controls/2026-08-17/covariate-inventory/positive_control_covariate_projection.csv \
  --verified-projection reports/historical-snapshots-417-revised-v4-verification/historical_snapshot_verified_projection.csv \
  --snapshot-root raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v4 \
  --output-dir '<new-empty-reference-package-directory>'
```

This writes the cohort, its full assembly-lineage manifest, the deterministic reference-side model, and a package manifest. It is non-authorizing because pair features and assignments do not yet exist.

## 2. Build the unsigned artifacts

Run from `02_Executable_Artifact`:

```bash
./.venv/bin/python build_stage2_control_dynamic_horizon.py \
  --reference-cohort '<frozen-reference-latency-cohort.csv>' \
  --pair-features '<frozen-cutoff-safe-pair-features.csv>' \
  --design-spec '../docs/superpowers/specs/2026-08-20-dynamic-horizon-v1-design.md' \
  --output-dir '<new-empty-artifact-directory>'
```

The builder validates the cohort and feature contracts, fits the frozen hierarchical Kaplan–Meier model, assigns integer-day horizons, calculates maturity timestamps, and writes six immutable artifacts. It refuses to overwrite an existing output directory. Every authority flag remains false.

## 3. Build the canonical approval record

```bash
./.venv/bin/python build_stage2_control_dynamic_horizon_approval.py \
  --artifact-dir '<artifact-directory>' \
  --design-spec '../docs/superpowers/specs/2026-08-20-dynamic-horizon-v1-design.md' \
  --principal 'zmzubraj' \
  --approved-at-utc '<canonical-UTC-approval-time>'
```

This writes `user_approval_record.json`. It binds the principal, exact approval and outcome-inspection statements, design/spec/reference/model hashes, namespace, and non-authorizing flags.

## 4. Sign outside Codex

Complete the public registration package in `docs/authorities/zmzubraj-key-registration/`. Generate and retain the private key outside Codex and outside the repository. Sign the canonical record yourself:

```bash
/usr/bin/ssh-keygen -Y sign \
  -f '[private-location]/chronosaudit-zmzubraj-ed25519' \
  -n chronosaudit-stage2-control-dynamic-horizon-v1 \
  '<artifact-directory>/user_approval_record.json'
```

Return only the public registration artifacts and detached `.sig`. Never provide the private key or passphrase. Key possession alone does not prove real-world identity and is not independent human review.

For local testing only, the user authorized Codex to generate and use a dedicated key outside the repository. The 2026-08-20 reference package was signed as principal `zmzubraj-local-test` under the separate namespace `chronosaudit-stage2-control-dynamic-horizon-reference-local-test-v1`. That cryptographic test does not satisfy the production author-approval record, identity binding, independent review, selection, qualification, or counter gates.

## 5. Verify

```bash
./.venv/bin/python verify_stage2_control_dynamic_horizon.py \
  --artifact-dir '<artifact-directory>' \
  --design-spec '../docs/superpowers/specs/2026-08-20-dynamic-horizon-v1-design.md' \
  --signature '<artifact-directory>/user_approval_record.json.sig' \
  --allowed-signers '<reviewed-allowed-signers-file>' \
  --expected-principal 'zmzubraj'
```

A success writes `dynamic_horizon_verification.json`, completing the required eight-artifact set. It independently reconstructs the model, hierarchy, assignments, uncertainty, bounds, maturity timestamps, hashes, and detached signature. The terminal decision is `DYNAMIC_HORIZON_GATE_VERIFIED_NON_AUTHORIZING`.

## Stop boundary

Even a successful dynamic-horizon verification does not authorize source acquisition, RPC, control selection, qualification, counter increments, or Recovery3 mutation. Those gates remain separate. `qualified_controls` also continues to require all eight evidence checks, conflict-cleared human review where prescribed, and the separate signed qualification authority.
