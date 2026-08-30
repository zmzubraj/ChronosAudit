# ChronosAudit Stage-2 Enriched Research Release

**Release date:** 2026-08-08  
**Research target:** information-admissible evidence infrastructure for pre-incident smart-contract exploit detection.

## Included

- Submission-oriented Stage-2 research manuscript (`paper/ChronosAudit_PreIncident_Stage2_Research_Article.docx`).
- Frozen public SCONE and DeFiHackLabs inputs used by the enrichment pipeline.
- 417/417 public incident chronology enrichment and provenance hashes.
- Historical identity/source/deployment adapters (EIP-1898, EIP-1967, EIP-1167, Sourcify v2, Etherscan V2).
- CREATE/CREATE2 deployment-stream collector.
- Two 417-case independent-review packets and adjudication workflow.
- Deterministic cutoff-safe 10:1 control matcher.
- 100-question adversarial audit, release gating, append-only registry, clean-room regeneration.
- Current verification and production-qualification outputs; the final public-acquisition suite records 161 passing tests in `06_QA_Reproducibility/public_acquisition_final_verification.json`.

## Scientific boundary

The software/evidence workflow is mechanically functional and fail-closed under the current test scope, but it is not a scientifically qualified or distribution-cleared release. The Stage-2 scientific/production completion gate remains fail-closed because qualifying dual-provider historical evidence, independent reviewer judgments, the >=20,000-contract denominator, >=4,170 controls, longitudinal outcome follow-up, and external replication have not been completed. No missing evidence is imputed.

## Full-program public-evidence revision (2026-08-07)
- Added `paper/ChronosAudit_PreIncident_FullProgram_PublicEvidence_Submission.docx` and PDF.
- Added executed provisional R0–R5 public-evidence stress test and strict R0–R5 certifier output.
- Added public evidence registry/corroboration for SCONE, CyberChainBench, DIVE, Bastet, Anthropic recent-contract screening, Sourcify and AWS public blockchain data.
- Added reviewer-independence and same-case gate utilities; pinned source/deployment export utilities.
- Test suite: 38/38 passing; aggregate source coverage 87%.
- Production qualifier remains intentionally fail-closed: strict empirical evidence completion 31/100; software/workflow completion 94/100.

## Public acquisition pilot and full crawl preservation (2026-08-08)
- Canonical live run ID: `public-acquisition-20260808T122104Z-2942b2819e08`
- Frozen live evidence roots:
  - `02_Executable_Artifact/raw/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/`
  - `02_Executable_Artifact/processed/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/`
  - `02_Executable_Artifact/reports/public_acquisition/2026-08-08/public-acquisition-20260808T122104Z-2942b2819e08/`
- Preserved preflight plan-only revisions:
  - `public-acquisition-20260808T122042Z-2942b2819e08`
  - `public-acquisition-20260808T122054Z-2942b2819e08`
- Inventory capture:
  - captured pages: 23
  - captured bytes: 10,007,351
  - inventory spec sha256: `54f362e3981ce1299e85df29061ee09ef62e554a4d3d3e6d7eaeddd44c411108`
- Live RPC preservation:
  - 417/417 cases processed, all remaining `PARTIAL`
  - append-only acquisition ledger events: 7,506
  - initial raw response corpus: 986 files, 8,272,302 bytes
  - post-recovery receipt manifest count: 2,362
  - receipt recovery audit:
    - pre-recovery rpc_case_results sha256: `d70f0f96c7eeba5dcf454d1a51d49cc271fb29016e4cbcbb7565d32726e2f09e`
    - post-recovery rpc_case_results sha256: `dbc6ac922f07f1e87270ec9e5d5c67cd5f0f260b029d5232819f73a7907d0e46`
    - post-recovery rpc_receipts sha256: `5ecb5fa1acf300d40bf0b5301bb29c196ca1d3d65507be8c9ee753d0cb78ae00`
    - bindable response receipts: 2,348
    - request-only error receipts: 14
    - orphan raw response files versus nested observations: 0
- Denominator attempt:
  - downloaded public Sourcify shard: `contract_deployments_43000000_44000000.parquet`
  - shard sha256: `f16b40e5dec4a5ecc735851f29335ffe8910b4b2ad55ebb7b02f8ef91fd8faa5`
  - strict prepared four-chain CSV sha256: `fce364f85d89175528d1186e461091b82e718d1b04c3ac9bbfc32d5c740ef9a5`
  - denominator audit sha256: `ca57ebbf196a5ea4a2f138fb9390ad89f2c2c265e9c01be1d20580e5c3fe54fd`
  - strict qualified denominator rows: 0
- Counter state after post-recovery projection:
  - historical snapshots: 0 / 417
  - independent adjudications: 0 / 417
  - deployment denominator: 0 / 20,000, with 5,000 required per target chain
  - positive review packets: 417
  - finalized adjudications: 0
  - control candidates: 0 / 4,170
  - qualified controls: 0 / 4,170
  - release-eligible cases: 0
  - independent R5 blocks: 0 / 120
- Final verification status:
  - explicit verifier: `structure_valid=true`, `scientifically_complete=false`, `release_ready=false`
  - `verify_stage2.py`: pass `true`, decision `IMPLEMENTATION_COMPLETE_EVIDENCE_GATES_BLOCKED_FAIL_CLOSED`
  - fresh command results and hashes: `06_QA_Reproducibility/public_acquisition_final_verification.json`
  - run-specific `production_qualification.py`: exit `3`, `counter_artifact_errors=[]`, fail-closed on unsatisfied scientific gates
- Research report added:
  - `03_Research_Reports/Public_Evidence_Acquisition_2026-08-08.md`
- Source and packaging boundary:
  - executed observations came from the configured `publicnode-*` and `one-rpc-*` public endpoints; both provider families remain operator-unverified
  - Chainlist was discovery inventory only and may contain upstream public URLs with embedded access-looking tokens that were not execution evidence
  - public accessibility was observed, but redistribution, licensing, and terms-of-use clearance were not established and no source-rights artifact was captured
  - the run preserves large duplicated raw/processed public artifacts and absolute worktree paths, creating portability and distribution risk
- Scientific release status remains fail-closed. This revision preserves public execution evidence and receipt binding integrity; it does not certify scientific completion, reviewer independence, denominator sufficiency, qualified controls, release eligibility, source rights, or public redistribution readiness.
