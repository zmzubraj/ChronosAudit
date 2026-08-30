# Public Evidence Acquisition Report

> **Historical snapshot notice (2026-08-17):** This dated report preserves the 2026-08-08 run and must not be read as the current counter state. Current counters are maintained in `Overall_Project_Update_2026-08-17.md`, `Stage2A_2E_Execution_Report.md`, and the revision-v4 machine-readable artifacts.

Date: August 8, 2026  
Canonical live run ID: `public-acquisition-20260808T122104Z-2942b2819e08`  
Receipt-recovery provenance: the successful command ran while Git reported HEAD `862688dbad938bbece277dddfc4c6c893e4d163a`, with the request-only error support later committed as `ee1f8f473cdb3d9a9fc8ec493a2aece1f4b23ab1`; `862688d` alone must not be treated as the complete recovery implementation.
Overall status: `FAIL_CLOSED_PARTIAL_EVIDENCE_PRESERVED`

## Scope

This report preserves the authorized public-data execution for the ChronosAudit public-evidence acquisition task using only public sources and public RPC endpoints. No paid, authenticated, private, or bypassed source was used.

The on-disk plan history contains three same-input revisions under `02_Executable_Artifact/{raw,reports}/public_acquisition/2026-08-08/`:

1. `public-acquisition-20260808T122042Z-2942b2819e08`
2. `public-acquisition-20260808T122054Z-2942b2819e08`
3. `public-acquisition-20260808T122104Z-2942b2819e08`

The first two are offline preflight plan revisions only. The third revision was frozen as the sole live Task 6 revision and all subsequent mutable stages were executed against that run ID.

## Public Sources

- AWS Open Data registry: `https://registry.opendata.aws/aws-public-blockchain/`
- AWS public blockchain prefixes:
  - `v1.0/eth/`
  - `v1.1/bnb/`
  - `v1.1/sonarx/base/`
  - `v1.1/sonarx/arbitrum/`
- Sourcify dataset docs: `https://docs.sourcify.dev/docs/repository/download-dataset/`
- Sourcify listing root: `https://export.sourcify.dev/?prefix=v2/`
- Sourcify contract deployments listing: `https://export.sourcify.dev/?prefix=v2/contract_deployments/`
- Chainlist discovery JSON: `https://chainlist.org/rpcs.json`

Source-role and rights boundary:

- Chainlist was used for endpoint discovery and inventory preservation. The actual crawl observations were produced only by the configured `publicnode-*` and `one-rpc-*` endpoints.
- Both executed provider families remain labeled `unverified:publicnode` and `unverified:1rpc`; their operator identity and archival independence were not established.
- No user-owned credentials, paid services, authenticated services, or private endpoints were used. The captured Chainlist inventory may nevertheless contain public URLs with embedded access-looking tokens supplied by that upstream dataset; those unevaluated entries are discovery evidence, not executed-provider evidence.
- Public accessibility was verified for the acquired pages and object. Redistribution, licensing, and terms-of-use clearance were not established, and no source-rights artifact was captured. The evidence package therefore must not be treated as cleared for public redistribution.

## Executed Commands

The evidence tree preserves command logs in `02_Executable_Artifact/reports/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/command_logs/`.

Key command outputs and hashes:

- `plan`:
  - log dir: `chronosaudit-task6-plan-20260808T122104Z`
  - stdout sha256: `507c2e07d67b658ae36105174a3b2c504955a4691161050e3677f6f6753ec19a`
- `inventory --execute --max-pages 200 --max-bytes 2147483648 --deadline-seconds 3600`:
  - log dir: `chronosaudit-task6-inventory-20260808T122732Z`
  - stdout sha256: `c719d295f4fb44925bc58355bcfb18fed82c4b329df6a5ca4fc5f5f231fdf35c`
- initial live `rpc --execute --max-cases 417 --max-bytes 2147483648 --deadline-seconds 21600`:
  - log dir: `chronosaudit-task6-rpc-20260808T122749Z`
  - stdout sha256: `6b5b4e88fdff55045057d7bce5883820ca66a936f301488427e687c6b4b5eda4`
- strict denominator attempt against the hexified four-chain CSV:
  - log dir: `chronosaudit-task6-denominator-hexcsv-20260808T123719Z`
  - stdout sha256: `95da2a7a3e6c6de5ba4d64f1953c56754ff172592e3444924aa388bb8d6a15e4`
- successful offline receipt recovery rerun while Git reported HEAD `862688d`, with request-only error support subsequently committed as `ee1f8f4`:
  - log dir: `chronosaudit-task6-rpc-recovery-rerun-20260808T144306Z`
  - stdout sha256: `09166420c7a2c828c62a10b01dd075a9c3cbb84575b9c2c0e0d46d58a6fe0f91`
- final explicit verifier:
  - log dir: `chronosaudit-task6-verify-explicit-postrecovery-20260808T144339Z`
  - stdout sha256: `888a9e7cb3e61641a9957a5557e3d2fcb84377198ac7843f819460803b07181d`
- final `verify_stage2.py`:
  - log dir: `chronosaudit-task6-verify-stage2-postrecovery-20260808T144342Z`
  - stdout sha256: `850bced6b26fcfb65c2495703f8b434d57ef765d4535d81f480d61d98d6af120`
- final `pytest -q`:
  - log dir: `chronosaudit-task6-pytest-20260808T144050Z`
  - stdout sha256: `38ceb00b6bda6e7df863fbd18872921c7280656a4718e7d04511a97e02f9f489`
- final `independent_regenerate.py`:
  - log dir: `chronosaudit-task6-independent-regenerate-20260808T144054Z`
  - stdout sha256: `7d9079a6b06b14f88fae093343d46924c21c2d25bc27f53ac725d2fd87100ac8`
- final `production_qualification.py`:
  - log dir: `chronosaudit-task6-production-qualification-postrecovery-20260808T144342Z`
  - stdout sha256: `c19a58aca3e178466642062e1839492dac831a22782a2a5e51acd687b379a6ee`
  - exit code: `3`

## Inventory Capture

Captured inputs are stored under `02_Executable_Artifact/raw/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/captured_inputs/`.

Inventory capture totals:

- Chainlist: 1 page, 2,183,244 bytes
- AWS listings: 20 pages, 7,528,197 bytes
- Sourcify listings: 2 pages, 295,910 bytes
- Total captured listing pages: 23
- Total captured listing bytes: 10,007,351
- Inventory spec sha256: `54f362e3981ce1299e85df29061ee09ef62e554a4d3d3e6d7eaeddd44c411108`

Inventory normalization completed successfully. The live inventory run remained bounded and source-only. No deployment-export source was injected at the inventory stage.

## Live RPC Crawl

Initial live RPC execution summary:

- planned cases: 417
- processed cases: 417
- case status distribution: 417 `PARTIAL`
- blocked reason distribution: 417 `insufficient_independent_provider_families`
- initial `rpc_receipts.json` manifest count: 0
- raw response files preserved from live crawl: 986
- raw response bytes preserved: 8,272,302
- append-only acquisition ledger events: 7,506

Scientific status did not advance to verified historical snapshots. All 417 cases remained partial because the public provider families were insufficient for the strict independent-family historical proof requirement.

## Receipt Defect And Offline Recovery

### Original defect

The original live RPC crawl preserved nested provider observations and raw response files, but the initial `rpc_receipts.json` manifest remained empty. This was a binding defect, not an absence-of-evidence event.

The first post-fix recovery attempt was preserved in `chronosaudit-task6-rpc-recovery-20260808T143835Z` and failed with:

- stdout payload: `{"command":"rpc","error":"path outside run root: None","status":"error"}`
- stderr: `path outside run root: None`

That failed attempt revealed an unhandled case in nested observations where `request_sha256` existed but `response_sha256` and `raw_response_path` were null.

### Recovery diagnosis

Nested observation audit on the frozen live run before successful recovery showed:

- total nested observations: 2,362
- observations with bindable request+response+raw artifact: 2,348
- request-only error observations: 14
- nested observations missing request sha256: 0
- unique raw response paths referenced in nested observations: 986
- orphan raw response files versus nested observations: 0

The 14 request-only observations were HTTP error cases from `one-rpc-ethereum` with preserved request hashes but no response artifact:

- HTTP 429: rate-limited request-only failures
- HTTP 503: service-unavailable request-only failures

### Successful deterministic offline recovery

The second recovery invocation completed successfully without a new network crawl. Git reported HEAD `862688d` during that command, while the then-uncommitted request-only error support was subsequently committed as `ee1f8f4`; reproducing recovery therefore requires at least the later committed implementation, not `862688d` alone. The recovery path executed before provider setup and rebuilt receipts directly from the nested observations already stored in `rpc_case_results.json`.

Evidence of offline recovery:

- `rpc_receipt_recovery_audit.json` created and hash-bound to the pre-recovery `rpc_case_results.json`
- pre-recovery `rpc_case_results.json` sha256: `d70f0f96c7eeba5dcf454d1a51d49cc271fb29016e4cbcbb7565d32726e2f09e`
- post-recovery `rpc_case_results.json` sha256: `dbc6ac922f07f1e87270ec9e5d5c67cd5f0f260b029d5232819f73a7907d0e46`
- post-recovery `rpc_receipts.json` sha256: `5ecb5fa1acf300d40bf0b5301bb29c196ca1d3d65507be8c9ee753d0cb78ae00`
- response file count remained 986 before and after recovery
- request artifacts were deterministically materialized from method+params hashes under `raw/.../requests/`

Post-recovery receipt state:

- total recovered receipts: 2,362
- bindable response-backed receipts: 2,348
- request-only error receipts: 14
- raw request files present after recovery: 480
- final verifier integrity failures after recovery: 0

This recovery advanced the structural state only. It did not change the scientific result that all 417 cases remain partial and fail the strict independent-provider-family threshold.

## Denominator Attempt

Public denominator acquisition used a bounded Sourcify contract-deployments shard.

Downloaded object:

- URL: `https://export.sourcify.dev/v2/contract_deployments/contract_deployments_43000000_44000000.parquet`
- bytes: 104,255,062
- sha256: `f16b40e5dec4a5ecc735851f29335ffe8910b4b2ad55ebb7b02f8ef91fd8faa5`
- ETag: `"691d4df3a3e69ee0cdb422f512753aa1"`
- Last-Modified: `Sat, 08 Aug 2026 02:08:32 GMT`

Observed shard schema:

- columns: `id`, `chain_id`, `address`, `transaction_hash`, `block_number`, `transaction_index`, `deployer`, `contract_id`, `created_at`, `updated_at`, `created_by`, `updated_by`
- rows: 959,738

Target-chain rows present in the shard:

- Ethereum (`1`): 45,802
- BSC (`56`): 12,691
- Base (`8453`): 455,042
- Arbitrum (`42161`): 34,795
- Total four-chain rows after filtering: 548,330

Three denominator ingest attempts were preserved:

1. direct parquet ingest:
   - failed because the denominator CLI path expected text/CSV rather than parquet
2. first CSV conversion (`001-contract_deployments_43000000_44000000.csv`, 959,738 rows, sha256 `c655add2be044f4062f3936891bd4e4d19c3dcffd1b1e127699efa7364d118a9`):
   - failed because binary address/transaction fields were not hexified
3. second CSV conversion (`002-contract_deployments_43000000_44000000-targetchains-hex.csv`, 548,330 rows, sha256 `fce364f85d89175528d1186e461091b82e718d1b04c3ac9bbfc32d5c740ef9a5`):
   - parsed successfully
   - still yielded `0` verified denominator rows because every row was strictly excluded for missing creation-proof evidence

Final strict denominator audit:

- Ethereum: 45,802 parsed, 0 verified, shortfall 5,000
- BSC: 12,691 parsed, 0 verified, shortfall 5,000
- Base: 455,042 parsed, 0 verified, shortfall 5,000
- Arbitrum: 34,795 parsed, 0 verified, shortfall 5,000

Conclusion: the public shard was numerically adequate for the four target chains, but scientifically inadequate for the strict denominator because the schema lacked creation-proof fields required by the Stage-2 admissibility rules. No synthetic rows were introduced.

## Controls, Review Packets, And Release Projection

Controls:

- `controls` status: `scientifically_incomplete`
- blocking reason: positive-case rows still lack required columns:
  - `clone_family`
  - `code_size`
  - `deployment_time`
  - `follow_up_horizon`
  - `identity_group`
  - `prediction_cutoff_time`
  - `protocol_family`
  - `proxy_family`
  - `proxy_status`
  - `source_verified_at_cutoff`
  - `mechanism_family`
  - `positive_record_sha256`

Current 2026-08-17 addendum: sealed Recovery3 row authority is bound additively for 20,000/20,000 rows. The frozen +/-30-day deployment graph has certified max-flow/min-cut 680/4,170 with an exact 3,490 pre-covariate shortfall, so historical denominator expansion is required before pair-specific code, proxy, source-verification, clone, and protocol evidence can enter selection. Mechanism is qualification-time only. See `Stage2_Control_Prespecification_and_Preflight.md`; counters remain 0/4,170.

Review packets:

- positive review packets prepared: 417
- control review packets prepared: 0
- finalized positive adjudications: 0
- reviewer independence status: `waiting_external`

Release projection counters:

- historical snapshots observed: 0 / required 417
- independent adjudications observed: 0 / required 417
- deployment denominator observed: 0 / required 20,000, with 5,000 required per chain
- control candidates observed: 0 / required 4,170
- qualified controls observed: 0 / required 4,170
- independent R5 blocks observed: 0 / required 120
- release-eligible cases: 0

The 417 prepared positive review packets are administrative work products only. They do not count as independent adjudications, R5 evidence, or release-eligible cases.

## Final Verification State

Explicit verifier (`--run-id ... --revision 2026-08-08`) and latest verifier (`--latest`) both ended with:

- `structure_valid: true`
- `scientifically_complete: false`
- `release_ready: false`
- `integrity_failures: []`

Remaining scientific gaps:

- pilot remains scientifically incomplete: 9 cases selected with one Arbitrum shortfall
- public RPC acquisition remains scientifically incomplete for all 417 cases because the required independent provider-family evidence was not obtained
- deployment denominator shortfall remains 5,000 on each of the four target chains
- control candidate generation remains scientifically incomplete
- reviewer independence artifacts are still waiting on external human review
- release predicates are unsatisfied; no release-eligible cases projected
- R5 prerequisites are not satisfied
- counter regeneration shows the public evidence package is not production-qualified

Verification and regression results are preserved in `06_QA_Reproducibility/public_acquisition_final_verification.json` and `.md`. The run-specific production qualifier exits `3`, reports `counter_artifact_errors: []`, and remains unqualified solely because the seven scientific gates above are unsatisfied. An earlier default-path invocation that reported a missing top-level manifest was superseded and is not the canonical qualification result for this run.

## What Genuinely Advanced

The Task 6 run did not achieve scientific completion, but it did advance the evidence package in a real way:

- the live 417-case crawl was preserved with a complete append-only ledger
- the public raw response corpus remained bound to the frozen run
- receipt binding advanced from `0` to `2,362`
- structural verification advanced from failing on missing/unbound receipts to `structure_valid: true`
- `verify_stage2.py` advanced from a blocked `public_acquisition_structure_valid: false` state to `public_acquisition_structure_valid: true`

These are evidence-integrity improvements only. They do not upgrade the scientific gate.

## Storage And Portability Boundary

The canonical run preserves approximately 529 MB of raw evidence, 291 MB of processed evidence, and 58 MB of reports. Some public source bytes are duplicated across raw and processed roots to preserve stage-local provenance. This improves auditability but creates a large-repository and distribution burden. After the feature branch was merged, a verified path-only migration rebased 7,148 run-owned manifest references from the retired worktree to output-root-relative paths. The migration audit records before/after hashes, structural verification passes from `main`, and no scientific counter advanced. Historical command logs retain original execution paths as provenance rather than active artifact references.

## Remaining External Dependencies

The run remains fail-closed until at least the following external or nonlocal dependencies are resolved:

- an authorized, scientifically complete pilot selection satisfying the Arbitrum allocation requirement
- two independent, historically capable public provider families per required chain and method, or a policy-approved alternative evidence path
- a public deployment inventory source that carries admissible creation-proof fields for strict denominator qualification
- human independent reviewer identities, conflict checks, and finalized adjudications
- completed qualified control generation and independent R5 block adjudication

## Preserved Artifact Roots

- raw root: `02_Executable_Artifact/raw/public_acquisition/2026-08-08/`
- processed root: `02_Executable_Artifact/processed/public_acquisition/2026-08-08/`
- reports root: `02_Executable_Artifact/reports/public_acquisition/2026-08-08/`

Canonical live artifact root:

- `02_Executable_Artifact/reports/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/`

No scientific promotion is warranted from this run. The correct final interpretation is: public acquisition pilot and full crawl preserved, structural integrity repaired, scientific completion still blocked.
