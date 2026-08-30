# ChronosAudit Stage-2 Top-Journal Revision (v0.5.0)

**Primary manuscript:** `paper/ChronosAudit_PreIncident_TopJournal_Stage2_Revised.docx`  
**Revision report:** `Revision_Qualification_Report.md`

This release fixes the major methodological/code issues identified in the prior audit: outcome-independent cutoff policy, cutoff-safe controls, blinded review, third adjudicator ingestion, Gwet AC1/bootstrap reliability, multi-backend trace collection, provider-family independence, split-strategy audits, retry/backoff, and expanded statistical methods. The test suite passes **27/27** with **84%** overall source coverage.

The release remains scientifically **fail-closed** for detector-effectiveness claims until the documented live external evidence gates are actually executed.

---


This workspace implements a fail-closed, reproducible evidence pipeline for **pre-incident smart-contract exploit detection**. The current execution starts from 417 historical exploit tasks and refuses to release a detector-evaluation cohort until deployment-time provenance, historical code/source availability, proxy lineage, independent review, controls, censoring, and leakage gates are satisfied.

## Current executed state (2026-08-07)

- 417/417 cases linked to a content-hashed DeFiHackLabs incident record.
- 398/417 matched by exact incident-file basename, 16 by a frozen date override, and 3 by normalized-title fallback; all match decisions are logged.
- 383/417 cases have at least one public incident reference URL.
- 60 cases include public incident transaction hashes (63 hashes total) and are queued for archive-RPC reconstruction.
- 408 unique chain-address identities; 9 duplicate identity groups cover 18 rows.
- 1,000/1,000 row-random five-fold assignments leak at least one exact identity group; deterministic identity-grouped folds leak zero exact identities.
- 417 public mechanism labels receive an auditable preliminary classifier output; 385 map to a defined candidate family and 32 remain `unclassified_public_label`. No candidate is treated as adjudicated ground truth.
- Historical identity code supports EIP-1898 canonical block-hash pinning, EIP-1967 implementation/admin/beacon slots, historical beacon `implementation()`, EIP-1167 proxies, response hashes, and multi-provider consensus.
- Source-history code supports Sourcify v2 `verifiedAt`/exact-match evidence and Etherscan V2 current-source cross-checks. Etherscan V2 contract-creation lookup is implemented as a locator that still requires dual archive-RPC confirmation.
- Deployment-stream code captures top-level CREATE and traced internal CREATE/CREATE2, with a fail-closed incomplete status when two independent trace providers are unavailable.
- Deterministic cutoff-safe control matching is implemented at 10:1 without using future outcomes/activity.
- Two 417-case reviewer packets are generated; independent human reviews are not fabricated.
- 27/27 automated tests pass.
- Clean-room deterministic regeneration reproduces all tracked scientific outputs (ignoring only the observational build timestamp).
- The 1,264-record append-only registry verifies as a chained hash.
- Release remains **fail-closed** because live archive/source history, 20,000+ deployment stream, 4,170 controls, independent reviewers, longitudinal outcomes, and external replication have not been executed in this credential-free environment.

## Production-capable execution

```bash
cd artifact
python enrich_public_evidence.py
python run_stage2.py
pytest -q
python verify_stage2.py
python independent_regenerate.py
python production_qualification.py   # exits non-zero until every real evidence gate passes
```

Live evidence is resumable and reads secrets only from environment variables:

```bash
export CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS='https://provider-family-A,...,https://provider-family-B,...'
export CHRONOS_BSC_ARCHIVE_RPC_URLS='...,...'
export CHRONOS_BASE_ARCHIVE_RPC_URLS='...,...'
export CHRONOS_ARBITRUM_ARCHIVE_RPC_URLS='...,...'
export ETHERSCAN_API_KEY='...'
python run_live_stage2_evidence.py --execute
```

For scientific release, endpoint URLs must represent **independent provider families**, not merely two URLs from the same operator.

## Claim boundary

The implementation is production-capable as a deterministic Stage-2 evidence collector, but the **real Stage-2 cohort is not yet scientifically or operationally qualified**. No manuscript or report in this workspace claims that missing independent evidence has already been collected.
