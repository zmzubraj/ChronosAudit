# ChronosAudit Stage 2 Live Evidence Execution Runbook

**Purpose:** execute the external evidence gates that cannot be satisfied by offline code or manuscript editing.

## 1. Credentials and provider independence

Configure **two independent archive-RPC provider families per represented chain**. Do not count two endpoints from the same vendor as independent evidence. For the approved local-test trace/state path, use the existing Alchemy and Infura managed templates and provide only these two runtime variables:

```bash
export CHRONOS_ALCHEMY_API_KEY='...'
export CHRONOS_INFURA_API_KEY='...'
```

Keep these values in `/Users/rainbow/.codex/public-apis/.env` with mode `600`; never copy them into the repository or a generated artifact. The frozen registry stores only the environment-variable names and `{api_key}` templates. The current scope is Base, BSC, and Ethereum; Arbitrum is not represented among the 558 frozen unresolved identities. Provider documentation and identity binding do not establish trace/archive capability, so the frozen capability probe remains mandatory.

## 2. Capability check

```bash
cd artifact
python run_live_stage2_evidence.py
```

The dry run must report at least two configured archive provider URLs for each represented chain before live collection is accepted.

## 3. Pilot live collection

```bash
python run_live_stage2_evidence.py --execute --limit 10 --sleep 0.25
python production_qualification.py
```

Inspect `raw/live_observations/` before scaling. Provider disagreements must remain visible; never overwrite a disagreeing observation with a majority value.

## 4. Full 417-case historical reconstruction

```bash
python run_live_stage2_evidence.py --execute --sleep 0.25
```

For each case, retain raw responses and hashes for:

- canonical cutoff block hash;
- historical runtime bytecode;
- EIP-1967 implementation/admin/beacon slots;
- historical beacon `implementation()` when applicable;
- deployment transaction locator and creation block;
- Sourcify verification metadata including `verifiedAt`;
- independent source/compiler cross-check;
- attack/incident transaction evidence where available.

## 5. Independent protocol/mechanism review

Distribute these files to two reviewers independently:

- `artifact/review/reviewer_A.csv`
- `artifact/review/reviewer_B.csv`

Reviewers must be blind to detector predictions. Original reviewer judgments must remain immutable. If preregistered agreement is not met, revise/freeze the taxonomy before confirmatory R5 analysis rather than adjudicating until the number becomes acceptable.

## 6. Deployment denominator and matched controls

The deployment denominator is complete at **20,000/20,000**, exactly 5,000 per chain. Preserve its sealed Recovery3 authority; do not reacquire or rewrite it for the control gate.

The original denominator cannot support ten controls per case: the frozen deployment-only graph has certified max-flow/min-cut 680/4,170 and an exact 3,490 shortfall. The local-test expansion has now verified the exact 43-object/43,000,000-row source batch and constructed the full deterministic 34,900-row tenfold reserve queue with global chain-address capacity one and zero reserve shortfall. This closes reserve capacity only; do not run selection yet.

The active local-test queue-bound activation covers two verified operator families per chain and only `eth_chainId`, `eth_getTransactionReceipt`, and `eth_getBlockByHash`. Its eight endpoints passed the frozen capability probe. The resumable checkpoint has 1,366 dual-provider-complete observations across all 380 deficit cases: 808 top-level CREATE proofs and 558 internal/factory rows that still require trace evidence. Source approval does not authorize RPC, and RPC activation does not authorize selection.

Use the hash-chained ledger at `raw/stage2_controls/2026-08-21/control-candidate-rpc-acquisition-v1/` for every resume. Completed assignments are immutable and skipped. Continue with bounded retry/backoff and round-robin case ordering; do not repeat the earlier 16-worker rate-limit pattern. The signed checkpoint at `reports/stage2_controls/2026-08-21/local-test-rpc-acquisition-checkpoint-v1/` is integrity evidence only.

Internal/factory creations cannot be promoted from receipt agreement alone. Either obtain a separately scoped activation for trace evidence and verify the created address, or preserve the row as trace-required and move to the next frozen reserve. Historical code/storage, proxy, clone, source-at-cutoff, and protocol evidence also require their own frozen scope and authorization before pair enrichment.

The trace and cutoff-state executors are now implemented. They remain non-authorizing and must be run only against an exact activation whose method scope covers their target files:

The exact unresolved identity scope is frozen at `02_Executable_Artifact/reports/stage2_controls/2026-08-21/local-test-trace-target-identities-v1/control_trace_target_identities.json` with 558 rows and internal hash `2ef4fc32c5f1734a2b8f20f553ab6f2c6057b7a8da15fce2b20df3ff06fecd32`. The current trace/state capability report is intentionally incomplete: the first Base provider rejected both trace backends, and the current registry does not provide two trace-capable families on Base, BSC, and Ethereum. Do not build or sign the activation shown below until a provider revision passes the frozen known-creation and cutoff-state capability probe. Provider replacement must preserve the identity scope; it must not change reserve order or silently exclude the 558 rows.

The managed Alchemy/Infura provider projection is at `reports/stage2_controls/2026-08-21/local-test-managed-provider-identity-v1/`. Its current capability artifact is also incomplete because the two runtime API-key variables are missing; that failure occurs before any RPC call. Once both variables are present, rerun `preflight_stage2_control_trace_state_capability.py` against this projection and the existing frozen fixtures. A complete result is still non-authorizing and must precede any exact activation.

```bash
./.venv/bin/python run_stage2_control_trace_acquisition.py \
  --activation-verification '<verified-trace-activation.json>' \
  --trace-targets '<frozen-trace-targets.csv>' \
  --provider-registry '<provider-registry.json>' \
  --output-root '<new-trace-output-root>' \
  --now-utc '<seconds-precision-UTC>' \
  --checkpoint-signing-key '<protected-local-test-key>' \
  --checkpoint-signer-principal '<local-test-principal>' \
  --checkpoint-allowed-signers '<allowed-signers>'

./.venv/bin/python run_stage2_control_cutoff_state_acquisition.py \
  --activation-verification '<verified-state-activation.json>' \
  --state-targets '<frozen-state-targets.csv>' \
  --provider-registry '<provider-registry.json>' \
  --output-root '<new-state-output-root>' \
  --now-utc '<seconds-precision-UTC>' \
  --checkpoint-signing-key '<protected-local-test-key>' \
  --checkpoint-signer-principal '<local-test-principal>' \
  --checkpoint-allowed-signers '<allowed-signers>'
```

Resume only with `--resume-checkpoint` from the same scope. Never expose the private key, and never treat the local checkpoint signature as scientific, selection, qualification, or counter authority.

After both batches verify, construct the cutoff-safe projection and bind it into the final horizon package:

```bash
./.venv/bin/python build_stage2_control_pair_features.py \
  --pair-scope '<frozen-pair-scope.csv>' \
  --denominator '<authorized-denominator.csv>' \
  --trace-results '<trace-results.jsonl>' \
  --trace-checkpoint '<trace-checkpoint.json>' \
  --state-results '<state-results.jsonl>' \
  --state-checkpoint '<state-checkpoint.json>' \
  --dynamic-horizon-spec '<dynamic-horizon-spec.json>' \
  --output-root '<new-pair-feature-root>'

./.venv/bin/python build_stage2_control_dynamic_horizon.py \
  --reference-cohort '<reference-latency-cohort.csv>' \
  --pair-features '<control-pair-features.csv>' \
  --pair-feature-manifest '<pair-feature-manifest.json>' \
  --design-spec '../docs/superpowers/specs/2026-08-20-dynamic-horizon-v1-design.md' \
  --output-dir '<new-final-horizon-root>'
```

After verified imports, rerun `preflight_stage2_controls.py` and the deployment/pair-evidence audits. Require every case to support at least ten edges and certified no-reuse allocation 4,170, then require `READY_FOR_CANDIDATE_SELECTION`. Select exactly ten unique, non-reused controls per positive under `config/stage2_control_selection_policy_v1.yaml` using the deterministic global allocator; do not substitute a sequential case-greedy loop. Before either counter passes, require exact 417-case membership, ranks 1-10 for every case, 4,170 unique chain-address identities, one match set per case, and no match-set reuse. Future outcomes and post-cutoff activity are prohibited from selection.

Each qualified row must carry passing, hash-bound maturity, censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation checks plus independent human outcome review. A selected row may remain a valid candidate while outcome-dependent mechanism separation is pending; never promote that candidate to qualified status. Preserve underfilled match sets as shortfalls; the freeze API must emit no cohort unless all 4,170 ranks are present. After `FROZEN_COMPLETE`, replacement is permanently forbidden.

Prepare and verify the eight-check evidence package using `docs/stage2_control_qualification_evidence_kit.md`:

```bash
./.venv/bin/python verify_stage2_control_qualification_evidence.py \
  --candidates '<frozen-selected-control-candidates.csv>' \
  --checks '<control-qualification-checks.csv>' \
  --evidence-root '<control-qualification-evidence-root>' \
  --output-report '<control-qualification-evidence-verification.json>'
```

The verifier requires exactly eight semantic check records per candidate, validates both the evidence JSON and its referenced source artifact, and requires a human reviewer for maturity, censoring, and mechanism separation. `QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING` validates the package only; it grants no qualification, counter, stage-promotion, or Recovery3 authority.

For signature-path testing, build the approval as `LOCAL_TEST_MECHANICAL`; the verifier must return `CONTROL_QUALIFICATION_MECHANICS_VERIFIED_NON_AUTHORIZING`. Only a separately identity-bound `ACCOUNTABLE_HUMAN` approval may authorize the qualification projection and counter, and that approval still cannot authorize selection, stage promotion, or Recovery3 mutation.

## 7. Longitudinal follow-up

Freeze the primary outcome horizon before inspecting control outcomes. The signed decision must bind three real ordinary files—an outcome-source plan, censoring rules, and a pre-freeze outcome-inspection attestation—and `verify_stage2_control_follow_up_horizon.py` must recompute and match all three hashes. Store last-observed timestamps, evidence sources, censoring state, and evidence hashes. Do not label merely unexploited contracts as universally safe.

## 8. Rebuild and qualify

```bash
python run_stage2_enrichment.py
python run_stage2.py
pytest -q
python verify_stage2.py
python independent_regenerate.py
python production_qualification.py
```

The Stage-2 completion gate passes only when `production_qualification.py` returns `qualified: true`, the release cohort is non-empty, and all preregistered leakage/adjudication/control requirements pass.

## 9. External regeneration

A different person or group must regenerate the final cohort/partitions from the frozen raw inputs and compare content digests. The included `independent_regenerate.py` proves internal deterministic regeneration only; it is not a substitute for independent external replication.
