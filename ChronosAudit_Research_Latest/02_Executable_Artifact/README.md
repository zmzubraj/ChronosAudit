# ChronosAudit - Stage 2 evidence/cohort qualification workspace

This workspace implements a fail-closed, reproducible evidence pipeline for **pre-incident smart-contract exploit detection**. The current execution starts from 417 historical exploit tasks and refuses to release a detector-evaluation cohort until deployment-time provenance, historical code/source availability, proxy lineage, independent review, controls, censoring, and leakage gates are satisfied.

## Current verified evidence addendum (2026-08-21)

- Historical snapshot authority is **417/417**, not 360/417. The sealed revised-v4 verifier reports `counter_authority=true`, zero integrity errors, 360 retained parent cases, and 57 deterministic replacement mappings.
- The public counter projection now binds that sealed historical verifier and reports historical snapshots **417/417**.
- The deployment denominator is **20,000/20,000**, with exactly 5,000 qualified rows for each of Ethereum, BSC, Base, and Arbitrum.
- Independent human adjudications remain **0/417**. The separate non-human `AI_ONLY_TRIANGULATION_V1` track is complete at **417/417** after two blinded primaries, 143 distinct third-model disagreement resolutions, and 417 alternate-prompt runs; its human-counter effect is `NONE`.
- The AI internal-progression gate is **FAIL_RELIABILITY_THRESHOLD**: protocol-family agreement is 0.6667 and root-cause agreement is 0.6763 versus the frozen 0.80 minimum. The AI counter is complete, but it does not currently authorize internal progression and never proves release or submission readiness.
- A manifest-bound two-reviewer handoff package is ready at `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/human_adjudication_handoff_manifest.json`; it requires real independently owned human reviewers and third-party disagreement resolution.
- Controls remain **0/4,170**, independent R5 blocks remain **0/120**, and release-eligible cases remain **0**. The local-test control track has verified the 43-object/43,000,000-row historical source batch, built a 34,900-row globally no-reuse reserve queue with zero shortfall, activated and capability-tested two operator families per chain, and checkpointed 1,366 dual-provider-complete reserve observations across all 380 deficit cases. Of those, 808 have complete top-level CREATE deployment classification and 558 require internal/factory trace evidence. These are acquisition artifacts, not selected or qualified controls.
- The accountable follow-up-horizon handoff is documented in `docs/stage2_control_follow_up_horizon_methods_owner_kit.md`. Its builder creates the exact unsigned decision and canonical signing payload only after validating the three request-bound scientific evidence documents; it neither chooses the horizon nor grants selection, qualification, or counter authority.
- The source, provider-identity, capability, activation, and current RPC checkpoint artifacts are local-test signed and explicitly non-authorizing. The checkpoint is at `reports/stage2_controls/2026-08-21/local-test-rpc-acquisition-checkpoint-v1/`; it keeps selection, qualification, counter, stage-promotion, scientific-authority, and Recovery3 permissions false.
- The eight-check control evidence and signed qualification contract is documented in `docs/stage2_control_qualification_evidence_kit.md`. The evidence verifier requires exactly one semantic, candidate-hash-bound maturity, censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation record per candidate and verifies the referenced source artifacts. Its report remains non-authorizing. Canonical counter projection now accepts one portable bundle manifest and independently rehashes the original inputs, reruns the semantic evidence and OpenSSH-signature checks, regenerates the exact projection, and rejects absent, tampered, or mismatched bundles.
- The authoritative audit and hash ledger for this update is `docs/status/2026-08-17-stage2-latest-evidence-audit.md`.

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
- Final candidate allocation is global rather than case-greedy: augmenting paths enforce maximum-cardinality assignment with chain-address capacity one. Counter promotion separately requires the exact 417-case x 10-control cohort, unique identities, ranks 1-10 per case, and match-set integrity.
- Candidate and qualification states are separated: deferred outcome-based mechanism review does not invalidate a provenance-valid selected candidate, but maturity, censoring, mechanism separation, and independent human outcome review still block qualification.
- Two 417-case reviewer packets are generated; independent human reviews are not fabricated.
- 27/27 automated tests pass.
- Clean-room deterministic regeneration reproduces all tracked scientific outputs (ignoring only the observational build timestamp).
- The 1,264-record append-only registry verifies as a chained hash.
- Release remains **fail-closed** because the historical-control expansion, 4,170 controls, independent reviewers, longitudinal outcomes, and external replication have not been completed. The 20,000-row denominator counter is complete, but it cannot be promoted into controls.

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
export CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES='provider-family-a,provider-family-b'
export CHRONOS_BSC_ARCHIVE_RPC_URLS='...,...'
export CHRONOS_BSC_ARCHIVE_RPC_PROVIDER_FAMILIES='provider-family-a,provider-family-b'
export CHRONOS_BASE_ARCHIVE_RPC_URLS='...,...'
export CHRONOS_BASE_ARCHIVE_RPC_PROVIDER_FAMILIES='provider-family-a,provider-family-b'
export CHRONOS_ARBITRUM_ARCHIVE_RPC_URLS='...,...'
export CHRONOS_ARBITRUM_ARCHIVE_RPC_PROVIDER_FAMILIES='provider-family-a,provider-family-b'
export ETHERSCAN_API_KEY='...'
python run_live_stage2_evidence.py --execute
```

Every explicit URL list requires a same-length `CHRONOS_<CHAIN>_ARCHIVE_RPC_PROVIDER_FAMILIES` list. Each URL/family pair must resolve to the exact verified endpoint identity in the provider registry, and at least two distinct operator families must remain after resolution. Two endpoints, regions, accounts, or products from one operator do not establish independence.

As an alternative to explicit URLs, set both `CHRONOS_ALCHEMY_API_KEY` and `CHRONOS_INFURA_API_KEY`. ChronosAudit expands these values only through the frozen per-network templates in `config/managed_archive_provider_templates.yaml`; each provider/chain pair must still pass the preserved live archive-capability preflight before it becomes eligible.

**Migration from URL-only configuration:** add the matching provider-family variable for every existing URL list, or replace the URL list with both managed API-key variables. URL-only configuration now fails closed per case as `WAITING_EXTERNAL`; it never falls back to an `unverified` family and never increments a historical-snapshot counter.

## Public-only acquisition workflow

The public acquisition workflow is revisioned, resumable, and dry-run by default. It never overwrites an existing run root, and it keeps the public acquisition ledger append-only.

```bash
uv sync --locked
uv run python run_public_evidence_acquisition.py plan
uv run python run_public_evidence_acquisition.py run-public --execute \
  --max-cases 417 --deadline-seconds 21600
uv run python verify_public_evidence_acquisition.py --latest
```

Available subcommands:

- `plan`
- `inventory`
- `rpc`
- `denominator`
- `controls`
- `review-packets`
- `project`
- `verify`
- `run-public`

The canonical public queue still contains only one Arbitrum case, so the verifier must treat the resulting 9-case pilot plus `allocation_satisfied: false` as structurally valid but scientifically incomplete. See [PUBLIC_ACQUISITION_RUNBOOK.md](./PUBLIC_ACQUISITION_RUNBOOK.md) for exact resume commands, rate-limit handling, endpoint removal guidance, and external-review handoff.

## Claim boundary

The implementation is production-capable as a deterministic Stage-2 evidence collector, but the **real Stage-2 cohort is not yet scientifically or operationally qualified**. No manuscript or report in this workspace claims that missing independent evidence has already been collected.
