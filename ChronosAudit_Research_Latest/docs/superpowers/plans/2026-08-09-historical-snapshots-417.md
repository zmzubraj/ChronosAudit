# ChronosAudit 417 Historical Snapshots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Each implementation task uses TDD and must pass spec-compliance review before code-quality review.

**Goal:** Scale the evidence-grade pilot contract to all 417 canonical incident cases and count only complete pre-incident snapshots that satisfy independent provider-family, timestamp, schema, receipt-binding, and SHA-256 requirements.

**Architecture:** Preserve the existing append-only crawler as an acquisition layer, but add one shared strict snapshot contract used by pilot and full-corpus execution. A revisioned full-corpus runner derives deployment and 24-hour prediction cutoffs, independently brackets timestamps, acquires EIP-1898 hash-pinned identity state from two verified operator families, validates every required state cell and receipt, and writes per-case content-addressed artifacts. The offline verifier revalidates schemas, hashes, provider independence, and receipt paths before projecting qualified rows into the canonical counter. DeFiHackLabs remains an incident metadata/provenance source and never substitutes for archive RPC state or independent adjudication.

**Tech Stack:** Python 3.13, pandas, PyYAML, jsonschema, existing ChronosAudit public-acquisition/onchain modules, pytest, uv.

## Frozen Qualification Contract

- Canonical population is exactly the 417 rows in `processed/stage2b_onchain_query_queue.csv`; no discovered incident may silently replace or add a program case.
- A historical snapshot counts only when its deployment transition is verified, the prediction target is deployment time plus 24 hours, the adjacent cutoff-block timestamp bracket agrees across two independent verified provider families, the incident lead is at least one hour, and the snapshot is complete.
- Required state cells are `block_capability`, `runtime_code`, `eip1967_implementation_slot`, `eip1967_beacon_slot`, `eip1967_admin_slot`, `beacon_implementation_call`, and `implementation_runtime_code`. Explicit protocol-valid `not_applicable` is allowed only where the existing strict pilot contract permits it.
- Every decision-bearing observation must bind a request SHA-256, response SHA-256, content-addressed raw receipt path within the run root, provider family, provider identity evidence, method, block selector, and UTC observation time.
- Two URLs, regions, products, or accounts operated by one provider family count as one family. Alchemy and Infura may be reused across supported network hostnames, but only exact endpoint templates verified by configuration are eligible.
- DeFiHackLabs fields may supply incident date, chain, attack transaction, vulnerable address, and reproducible public provenance. They cannot establish deployment time, prediction-time state, provider independence, or snapshot qualification.
- The system remains fail-closed. Attempts, HTTP success, receipt count, partial cells, and schema-valid but incomplete artifacts do not increment `historical_snapshots`.
- Secrets remain local environment values. Tracked files may contain variable names and hostname templates but never API keys or secret-bearing URLs.

---

### Task 1: Managed provider templates and exact independent-family identity

**Owned files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/managed_providers.py`
- Create: `02_Executable_Artifact/config/managed_archive_provider_templates.yaml`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_managed_providers.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/onchain.py`
- Modify: `02_Executable_Artifact/config/public_provider_registry.yaml`
- Modify: `02_Executable_Artifact/.env.example`

**Interfaces:**
- `load_managed_provider_templates(path) -> ManagedProviderTemplateRegistry`
- `providers_for_chain_from_managed_env(chain, *, templates, env, artifact_root, timeout, retries) -> list[JsonRpcProvider]`
- Environment inputs use secret tokens, not full tracked URLs: `CHRONOS_ALCHEMY_API_KEY`, `CHRONOS_INFURA_API_KEY`.
- Supported hostname templates are frozen per chain and provider family. Unsupported provider/chain combinations return a typed configuration blocker.

- [ ] Write failing tests for Ethereum, BSC, Base, and Arbitrum hostname expansion; exact family identity; missing keys; unsupported combinations; URL/key redaction; and two-family enforcement.
- [ ] Implement schema-validated managed provider templates using current official endpoint documentation and live `eth_chainId`/historical capability preflight. Never infer archive qualification from marketing text alone.
- [ ] Preserve compatibility with explicit `CHRONOS_<CHAIN>_ARCHIVE_RPC_URLS` and matching family lists. Managed templates are used only when explicit lists are absent.
- [ ] Require provider identity evidence records with distinct `operator_family` values and non-secret endpoint-template hashes. Runtime secret-bearing endpoint hashes may be stored only through the existing redacted endpoint identity mechanism.
- [ ] Add `.env.example` names and comments without values. Confirm `.env` remains ignored.
- [ ] Run `uv run pytest -q tests/test_public_acquisition_managed_providers.py tests/test_public_acquisition_rpc.py tests/test_onchain.py`.
- [ ] Commit as `feat: add managed archive provider templates`.

---

### Task 2: Shared strict full-corpus snapshot contract and schemas

**Owned files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/strict_snapshot.py`
- Create: `02_Executable_Artifact/schemas/strict_historical_snapshot.schema.json`
- Create: `02_Executable_Artifact/schemas/rpc_receipt_manifest.schema.json`
- Create: `02_Executable_Artifact/tests/test_public_acquisition_strict_snapshot.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/pilot.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/rpc.py`
- Modify: `02_Executable_Artifact/run_evidence_grade_pilot.py`

**Interfaces:**
- `acquire_strict_historical_snapshot(case, *, providers, policy, receipt_root, cached_artifact=None) -> dict`
- `validate_strict_historical_snapshot(snapshot, *, schema, receipt_root, provider_identity) -> StrictSnapshotValidation`
- `snapshot_counter_projection(snapshot, case_artifact_path, case_artifact_sha256) -> dict`

- [ ] Write failing tests that transplant the successful pilot contract to an arbitrary case and reject same-family providers, wrong chain, wrong target timestamp, non-adjacent bracket, insufficient lead, unpinned block selectors, missing state cells, missing request/response hashes, path escape, tampered receipt bytes, schema drift, and self-hash mismatch.
- [ ] Move the pilot deployment-transition, cutoff search/bracket, incident consensus, identity snapshot, state-cell projection, and receipt-binding logic into the shared module without weakening any rule.
- [ ] Make `rpc.acquire_case_snapshot` use the shared contract for qualification. Capability-only observations may still be recorded but must return `strict_snapshot_closed: false`.
- [ ] Add deterministic case-artifact hashing, schema version, input queue row hash, policy hash, provider identity hash, complete blocker list, and resumable cached-artifact verification.
- [ ] Keep pilot outputs backward compatible and prove the existing 10 pilot cases still validate under the shared contract.
- [ ] Run `uv run pytest -q tests/test_public_acquisition_strict_snapshot.py tests/test_public_acquisition_pilot.py tests/test_public_acquisition_rpc.py tests/test_onchain.py`.
- [ ] Commit as `feat: share strict historical snapshot contract`.

---

### Task 3: Revisioned 417-case runner, DeFiHackLabs provenance, and offline verifier

**Owned files:**
- Create: `02_Executable_Artifact/run_historical_snapshots_417.py`
- Create: `02_Executable_Artifact/verify_historical_snapshots_417.py`
- Create: `02_Executable_Artifact/tests/test_historical_snapshots_417.py`
- Create: `02_Executable_Artifact/tests/test_historical_snapshots_417_verifier.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/evidence_sources.py`
- Modify: `02_Executable_Artifact/run_public_evidence_acquisition.py`
- Modify: `02_Executable_Artifact/verify_public_evidence_acquisition.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/counters.py`

**Interfaces and artifacts:**
- Runner inputs: canonical queue snapshot, frozen incident metadata/provenance snapshot, strict policy, managed provider templates, and local secret environment.
- Runner outputs under a revisioned run root: `cases/<case_id>.json`, `rpc_receipts/`, `rpc_receipt_manifest.json`, `case_qualification.csv`, `blocker_ledger.csv`, `provider_identity_verification.json`, `run_manifest.json`, and `historical_snapshot_closure_report.json`.
- Verifier output: `historical_snapshot_verification_report.json` plus a deterministic counter projection with required 417 and observed equal only to fully revalidated rows.

- [ ] Write failing tests for exactly 417 canonical rows, immutable input snapshots, deterministic case IDs, resume without reissuing valid receipts, targeted retry of incomplete cells, bounded concurrency, atomic per-case writes, interrupted-run recovery, and no counter change for partial cases.
- [ ] Freeze or ingest DeFiHackLabs public incident metadata with source URL, retrieval UTC, raw SHA-256, normalized row SHA-256, attack transaction, incident date, chain, and address where available. Preserve conflicts and missing fields; never overwrite canonical fields silently.
- [ ] Implement the full runner using the shared strict contract. Emit progress and blocker counts by chain while keeping credentials redacted from console, artifacts, exceptions, and hashes exposed in reports.
- [ ] Implement an offline verifier that reads only preserved bytes and rejects altered schemas, manifests, case files, queue rows, provider identity, receipt paths/hashes, timestamp brackets, cell completeness, or duplicate/missing case IDs.
- [ ] Connect verified case projections to `historical_snapshots`. Remove the current blank-seed disconnect, but leave every other scientific counter unchanged.
- [ ] Make the existing public-evidence verifier cross-check the revisioned strict-snapshot artifact when present; absence remains a valid zero-counter state.
- [ ] Run `uv run pytest -q tests/test_historical_snapshots_417.py tests/test_historical_snapshots_417_verifier.py tests/test_public_acquisition_cli.py tests/test_public_acquisition_counters.py tests/test_public_acquisition_qualification.py`.
- [ ] Commit as `feat: add verified 417 snapshot workflow`.

---

### Task 4: Operator runbook, live execution, and final evidence gate

**Owned files:**
- Create: `02_Executable_Artifact/HISTORICAL_SNAPSHOTS_417_RUNBOOK.md`
- Create: `03_Research_Reports/HISTORICAL_SNAPSHOTS_417_STATUS.md`
- Modify only generated revisioned acquisition/report artifacts produced by the runner and verifier.

- [ ] Document plan, preflight, execute, resume, targeted retry, verify, and counter-project commands; provider-chain support limits; budgets; key rotation; secret handling; and fail-closed meanings.
- [ ] Run an offline `--plan` and verify canonical queue cardinality/hash, chain distribution, DeFiHackLabs provenance availability, required environment names, disk budget, and provider matrix.
- [ ] Run non-secret live preflight for each provider/chain pair: `eth_chainId`, historical block retrieval, EIP-1898 `eth_getCode`, and `eth_getStorageAt` at representative old blocks. Record all responses and blockers. A provider is eligible only for chains it actually passes.
- [ ] Execute/resume all 417 cases with bounded concurrency and content-addressed receipts. Do not substitute a same-family endpoint when a second family is unavailable.
- [ ] Run the offline verifier and regenerate the counter artifact from verified rows. Report exact counts by chain and blocker class.
- [ ] Run full regression: `uv run pytest -q`.
- [ ] Run a tracked/untracked secret scan that reports only filenames/counts, never matched secret values. Confirm no credential appears in Git history or generated artifacts.
- [ ] Commit source/runbook changes and only scientifically valid, policy-permitted evidence artifacts. Do not commit `.env`, API keys, or secret-bearing raw URLs.

## Final Review Gate

- [ ] Dispatch an independent final reviewer over all changes and the live verification report.
- [ ] Confirm every implementation task passed separate spec-compliance and code-quality reviews.
- [ ] Confirm `historical_snapshots.observed` equals the number of independently revalidated complete case artifacts and never the number of attempts or receipts.
- [ ] If fewer than 417 close, preserve all evidence and name the exact external provider, missing-history, timestamp, incident-metadata, or protocol blocker for every unclosed case. Do not claim completion of 417.
- [ ] Finish the feature branch using the configured branch-completion workflow; do not merge without explicit user direction.
