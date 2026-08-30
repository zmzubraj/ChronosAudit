# Stage 2 Control Prespecification and Input Preflight

**Snapshot:** 2026-08-21
**Target:** 417 positive cases x 10 unique controls = 4,170 control rows
**Decision:** `PIPELINE_IMPLEMENTED_LIVE_PAIR_FEATURE_SELECTION_AND_QUALIFICATION_BLOCKED`

## Result

The denominator counter is complete and its sealed Recovery3 row authority is exposed through a separate additive control-input projection. An offline evidence-bounded projection materializes every locally supported covariate. A new deployment-only, cutoff-safe pair-scope audit then tested whether the frozen denominator could support ten unique, non-reused controls per positive before acquiring any additional covariates.

It cannot. The +/-30-day scope contains 2,936 positive-control pair edges but only 1,161 unique control identities. A deterministic maximum-flow calculation with a matching minimum-cut certificate proves that at most **680/4,170** controls can be allocated without reuse: only 37/417 cases can receive ten, 380 cases retain a shortfall, and the exact deployment-only shortfall is 3,490. Additional code-size, proxy, source-verification, clone, and protocol filters can only reduce this number. Therefore historical denominator expansion is required before enrichment or the 10-case pilot. Control candidates and qualified controls correctly remain **0/4,170**.

This was the design-feasibility blocker that triggered the historical expansion. The current local-test track has since filled the prespecified reserve capacity, but it has not yet produced a 4,170-row selected cohort. No synthetic values, report-level authority inference, post-cutoff features, guessed family labels, silent caliper relaxation, or control reuse may be used to bridge the remaining gates.

The approved 2026-08-21 implementation now supplies exact-scope dual-provider trace acquisition, EIP-1898 cutoff-state reconstruction, deterministic cutoff-safe pair-feature projection, final dynamic-horizon binding, and an all-or-nothing cohort freeze. This closes the software path, not the evidence gate: no production trace/state/pair-feature batch or frozen 4,170-row cohort was created by the implementation tests.

## Frozen selection contract

- Ten controls per positive case; 4,170 rows and 4,170 unique control contracts.
- No control reuse across positive cases.
- Deterministic positive ordering and SHA-256 tie-breaking.
- Same chain, deployed by the positive cutoff, deployment-time caliper of +/-30 days, code-size ratio 0.5-2.0, exact proxy-status match, and exact source-verified-at-cutoff match.
- No post-cutoff activity or outcome may influence selection.
- Positive addresses and same identity, clone, proxy/implementation, or protocol family are excluded during frozen selection.
- Mechanism family is outcome-derived and prohibited from candidate selection. Mechanism separation is assessed only after frozen selection as a qualification-time check with independent outcome evidence.
- Underfilled match sets remain explicit shortfalls; no adaptive relaxation after outcome inspection.

The implemented final allocator is a deterministic global maximum-cardinality flow, not a sequential per-case greedy selector. This distinction is necessary because an early case can otherwise consume a scarce control that is the only admissible option for a later case. Separately, counter projection revalidates the full cohort: exact positive-case membership, exactly ten controls and ranks 1-10 per case, 4,170 globally unique chain-address identities, one match set per case, and no match-set reuse. Individual row validity or a raw count of 4,170 cannot promote either counter.

The freeze boundary is all-or-nothing: insufficient maximum flow produces `VERIFIED_SHORTFALL` and deliberately writes no cohort. Once `FROZEN_COMPLETE` exists, replacement is prohibited even if later outcome review fails a candidate. The failed row remains failed and the cohort cannot be repaired after outcomes are visible.

The machine-readable policy is `02_Executable_Artifact/config/stage2_control_selection_policy_v1.yaml`, SHA-256 `4603d85139483db1b69c374c84603cfb83dabc2a93b6e310cab2f4226cebf871`.

## Eight non-compensating row checks

Every qualified control must carry both a passing value and a SHA-256 evidence binding for:

1. maturity;
2. censoring;
3. temporal eligibility;
4. identity/lineage separation;
5. clone separation;
6. proxy/implementation separation;
7. protocol separation;
8. mechanism separation.

Independent, conflict-cleared human outcome review remains an additional qualification gate. AI output, a public label, denominator membership, or absence from a public incident list cannot satisfy it.

A locally generated key can test OpenSSH signing and verification only. It must be labeled `LOCAL_TEST_MECHANICAL`, projects `counter_authority: false`, and cannot impersonate the accountable human qualification authority. The authorizing path additionally requires a distinct `ACCOUNTABLE_HUMAN` principal and an explicit external identity-binding hash.

The row validator and cohort validator are necessary mechanical gates, not independent evidence verification. Before qualification, every named check hash and human decision hash must resolve to the exact ordinary evidence artifact or signed review event it claims to bind and must pass the corresponding semantic verifier. Hash-shaped placeholders, self-authored booleans, and a self-consistent control-row hash cannot establish a qualified control.

## Current input preflight

Input hashes:

- Positive v4 snapshot: `5164a40ccdef04f3edb1555758b133cc28fec89571858c1bdacbba542962e824`.
- Materialized v4 denominator, retained as a distinct counter artifact: `566d3080ebe8eaf0483ab349270e2eec8ac2aa406b8356245376c38b4cb1d503`.
- Sealed Recovery3 verified projection: `7ca635fdc92978cf3feaf570981c8c50c550cf5b6bd0e10b0a41c11b98b9accc`.
- Additive control denominator authority projection: `a574b5a865b02d4628b0f35768c7e7cb78878b1bd051260f3c787a320cbbf870`.
- Authority bridge manifest: `f28fe3cdca5b0f502f5dc12849198ed99bdbd0a6cd9d07b7f9a270f710eea0a0`.
- Positive covariate projection: `412e3ad2681ebf54f2c2cd9f6a5bf4f088c09171c9cf70a1eec4795edc40161d`.
- Denominator covariate projection: `d553fb0be59538306b0eb6d76393838371fafa97e450ea8b05fe288a289c975e`.
- Covariate projection manifest: `d66fbd2546416b999ac55375661eb776d86bc6445fd2494e0274aafe70ca1015`.
- Current flat-inventory preflight report: `c67a1c048345c375a6f12cdeb9490201ac3b412241f59e9b031bab2ae146d63a`.
- Pair acquisition scope: `5650fd11486d7ff7c26142e9af052b0882cefa9507821d44aa110ee2310dfc41`.
- Historical denominator expansion requirements: `b20780e7e4dd3a7a0410d9df66bd57cfcd341ab65e273b1ef7bb3e8b3efe82dc`.
- Pair-scope and expansion manifest: `8d5288b7195eb77423a5e141910eb5e55c626d6ca724861d7accdd9353c40c04`.
- Bounded expansion chunk plan: `42fe130de9af198ad9208fc7c7cf42cb43a9f4548357bcedb4bd628759a385eb`.
- Bounded expansion chunk manifest: `511206fabb669f2a8584fb641d52a04ba9a8ab65fa1210eb98649e48efa54aa3`.
- Non-authorizing source-acquisition approval request artifact: `ec18ea4e6e89a75f120547525652c1bd14dc1bead4c47575e6eba801dc971575` (internal request hash `0cccdc430c3ba18127bbca13ba17ed6dd42e95a3fbbc50e0bb06da8ed005e38e`).
- Non-authorizing RPC-provider readiness artifact: `177e7984f65800cb884064b6036ecc392d0c81bf7bbaa72c7a9090a8d11fb9f7` (internal readiness hash `45c06037d2087bb6d3903ab52c25d212b643ba78758eac0aabd05149b277cae1`).
- Non-authorizing provider-documentation review packet: `050d0af2f2ed70429db3a12544b715b912ebb8c78dd52adb0a634741363b7673` (internal review-payload hash `56e7aa0525a0ff9b8b3dc27fa75da3bb68f0d77d5b0be6b7b593b130b173cf4e`).
- Non-authorizing provider-identity approval request: `a42315030e9b7b5a0cf3e3ecd06d44c01f50aa3a0ed6a08024a0265e03d5ec3c` (internal request hash `8e4128cad12acff73ca8192b53649c867d6dbf14b3e0013f7b929249ba4ef1c0`).
- Historical non-authorizing fixed-duration follow-up-horizon request artifact: `8759c200fdbded2b34fbb5b4621e22f35224d19ebd45111d04f8feb84def9161`.

Positive coverage from frozen evidence:

- Complete 417/417: deployment time, prediction cutoff time, code size, exact identity group, metadata-stripped bytecode clone family, and positive record hash.
- Partial 67/417: standard proxy status and proxy family; 350 remain unresolved because the frozen snapshots do not rule out non-standard or diamond proxy structure.
- Unresolved 0/417: source-verification status at cutoff and protocol family. The dynamic-horizon method is implemented, but production reference/pair inputs, public registration, offline signature, and verified assignments remain absent.
- Mechanism family remains intentionally blank because it is not a selection covariate.

Denominator coverage from frozen evidence:

- Complete 20,000/20,000: exact chain-address identity group plus the previously bridged authority and source hashes.
- Unresolved 0/20,000: runtime code size, cutoff-safe proxy status, cutoff-safe source-verification status, clone family, proxy/implementation family, and protocol family.

The current flat-inventory preflight reports `positive_incomplete_values`, `denominator_incomplete_values`, and missing pair-specific evidence columns. The required pair columns bind every denominator covariate record to a case, the exact positive cutoff, the frozen pair-scope row, per-covariate evidence hashes, and a pair-covariate record hash. A flat present-day denominator table can no longer authorize selection.

## Deployment risk-set feasibility

The pair scope uses only prespecified, outcome-independent fields: same chain, positive and control deployment times, positive prediction cutoff, the +/-30-day deployment caliper, positive-address exclusion, and Recovery3 authority hashes. It deliberately ignores runtime code, proxy state, source verification, protocol, activity, mechanism, and outcome.

- Positive cases: 417.
- Authorized denominator rows assessed: 20,000.
- Pair edges: 2,936.
- Unique eligible chain-address control identities: 1,161.
- Cases with zero pair edges: 154.
- Cases with fewer than ten pair edges: 326.
- Exact maximum no-reuse allocation: 680.
- Minimum-cut capacity: 680; max-flow/min-cut equality verified.
- Fully allocatable cases: 37.
- Cases with an allocation shortfall: 380.
- Exact minimum additional distinct deployment-scope slots: 3,490.

The 3,490 figure is necessary but not sufficient. It is the exact deficit before the remaining matching and separation covariates are applied. The case-level additive acquisition windows and deficits are preserved in `control_denominator_expansion_requirements.csv`; they do not authorize selection or overwrite Recovery3.

## Pair-evidence import boundary

The pair-covariate import verifier is implemented but no evidence batch has been accepted. It requires a batch manifest bound to the frozen pair-scope file, exact case/cutoff/authority bindings, a hashed raw-evidence manifest, ordinary non-symlink receipt files, query-plan evidence, per-field evidence hashes, canonical pair-covariate record hashes, and an optional accepted-import ledger. It rejects cutoff drift, after-cutoff evidence, receipt tampering, path escape, malformed source-verification semantics, duplicate pairs, repeated batch/evidence hashes, and pair replay. A verified batch still records `selection_authorized: false`; ledger acceptance and a full pair-evidence preflight remain separate gates.

The executable entrypoints are `02_Executable_Artifact/verify_stage2_control_pair_covariate_import.py` and `02_Executable_Artifact/accept_stage2_control_pair_covariate_import.py`. The latter appends only a previously verified, non-replayed batch to a hash-chained review ledger and refuses to overwrite its inputs. No evidence batch has been accepted, so the accepted-pair count remains zero and no ledger artifact is promoted as live evidence.

The deterministic expansion plan in `processed/stage2_controls/2026-08-17/expansion-chunks/control_denominator_expansion_chunk_plan.csv` partitions all 380 deficit cases across 16 disjoint chunks of at most 25 cases. It preserves the exact 3,490-slot minimum, has zero case or requirement overlap, and binds the Recovery3 authority projection, frozen pair-scope manifest, expansion-requirements ledger, and selection policy by SHA-256. Its manifest records `acquisition_authorized: false`, `rpc_authorized: false`, and `selection_authorized: false`. It is a bounded work plan awaiting accountable acquisition approval, not chunk authority and not permission to call RPCs.

The historical query plan is now frozen in `reports/stage2_controls/2026-08-17/expansion-chunks/control_historical_expansion_query_plan.json`. It binds the complete frozen Sourcify inventory, all 43 historical objects spanning rows 0-43,000,000, their exact keys, ETags, byte sizes, the 5,024,970,903-byte ceiling, the 380 case-bound windows, outcome-blind exclusion/deduplication/ranking rules, and the allowed deployment-verification methods. It also freezes a ten-fold reserve target per missing slot, global chain-address capacity one, a deterministic capacity-Dinic allocation, a 1,000-edge scan ceiling per deficit case, queue hashing before RPC, and mandatory re-planning rather than relaxation if the reserve cannot be filled. The persisted-plan verifier independently checks the schema, internal and file hashes, source-range continuity, download ceiling, chunk bindings, transformation and reserve-queue rules, RPC method allowlist, and all non-authorizing flags; its live report is `control_historical_expansion_query_plan_verification.json` with decision `QUERY_PLAN_VERIFIED_NON_AUTHORIZING`. The already-downloaded 43,000,000-44,000,000 object covers only 2026-07-16 through 2026-08-08 and overlaps zero deficit windows, so it cannot contribute a historical candidate.

The v2 signed source-acquisition verifier binds the frozen query-plan file hash, all 43 source objects through their query-plan commitment, the exact 5,024,970,903-byte download ceiling, the full ordered chunk-scope list, chain allowlist, validity window, mandatory raw receipts, mandatory accepted-import ledger use, and a detached OpenSSH signature from the expected allowed-signers principal. The local-test approval was signed and verified for that exact scope and the corresponding acquisition/import completed. The verifier continued to reject RPC, selection, stage-promotion, and Recovery3 authority. This establishes reproducible local-test acquisition, not accountable production identity or scientific authority.

The post-download source-import verifier accepted the exact 43 ordered objects and 5,024,970,903 bytes, with exact keys, ETags, response-header receipts, and SHA-256 values. Its decision is `SOURCE_BATCH_VERIFIED_FOR_LOCAL_TRANSFORM`; RPC, selection, stage promotion, and Recovery3 mutation remain false.

The historical reserve-queue builder streamed all 43,000,000 source rows and produced 6,710,828 unique eligible candidates after deterministic deduplication. It allocated the full 34,900-row tenfold reserve across all 3,490 missing slots with global chain-address capacity one and zero reserve shortfall. The queue SHA-256 is `89057a27cb2fbaeba93cf74ba55b2133ab816b2d0b66d6a89e8a596ca1d21ec9`; the manifest SHA-256 is `7c86f3747dc381eba9b31934d2c76f5f3f6dfed30b796725b45e90e61b588978`. This remains a non-authorizing reserve, not 4,170 selected or qualified controls.

The separate RPC-activation request builder and signed verifier are implemented in `build_stage2_control_candidate_rpc_activation_request.py` and `verify_stage2_control_candidate_rpc_activation.py`. They require a complete verified reserve queue, bind its queue and manifest hashes, require exactly two independently identified operator families per represented chain, bind the provider-registry and provider-identity-report hashes, allow only `eth_chainId`, `eth_getTransactionReceipt`, and `eth_getBlockByHash`, and calculate a hard request ceiling as two candidate methods at two providers plus one chain-identity call per provider and chain. A valid activation grants only bounded RPC: acquisition, control selection, stage promotion, and Recovery3 mutation remain false. Raw request/response receipts and a hash-chained no-repeat ledger are mandatory.

The superseded 36-blocker PublicNode/1RPC readiness report is retained as failed history. The active local-test provider set uses PublicNode plus BlockReq for Ethereum, Base official plus BlockReq for Base, BNB official plus NodeReal for BSC, and Arbitrum official plus dRPC for Arbitrum. Official operator evidence is hash-bound, the v5 provider identity packet is signed and verified under the local-test boundary, and the v4 queue-bound activation is verified. All eight endpoints passed `eth_chainId`, frozen historical receipt, matching block-by-hash, and exact within-chain agreement probes. These checks establish the bounded local acquisition path only; they do not establish production scientific authority or authorize selection.

The resumable acquisition ledger now records 1,366 `COMPLETE` observations spanning all 380 deficit cases. Every complete result is rehashed during summary rebuild. Exactly 808 are `TOP_LEVEL_CREATE_RECEIPT_PROVEN` and temporally pre-cutoff; 558 are `INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED`. The current checkpoint is locally signed at `02_Executable_Artifact/reports/stage2_controls/2026-08-21/local-test-rpc-acquisition-checkpoint-v1/` and explicitly keeps selection, qualification, counter, stage-promotion, scientific-authority, and Recovery3 permissions false. Earlier 16-worker attempts generated 683 rate-limit partial events; bounded retry/backoff and round-robin case ordering were added, and the final successful batch introduced no new rate-limit failures.

The 558 unresolved identities are now deterministically frozen from that signed checkpoint and its validated event-ledger membership at `02_Executable_Artifact/reports/stage2_controls/2026-08-21/local-test-trace-target-identities-v1/control_trace_target_identities.json` (file SHA-256 `6173a07ba902c0b76adb29d5793b84ccedff605bd6c49656ab99c70a171bb270`; internal target hash `2ef4fc32c5f1734a2b8f20f553ab6f2c6057b7a8da15fce2b20df3ff06fecd32`). The frozen capability fixtures cover Base, BSC, and Ethereum, the three chains represented in this set. The first live capability probe failed closed: the first Base provider returned HTTP 403 for both `trace_transaction` and `debug_traceTransaction`. A bounded diagnostic confirmed that the current registry has 0/2 trace-capable families for Base, 0/2 for Ethereum, and 1/2 for BSC. No exact activation may be signed or executed until two independently verified families pass known-creation recovery and cutoff-state checks on all three chains.

The written specification is approved and its managed-provider implementation is now complete at the local-test boundary. Current official Alchemy and Infura endpoint documentation was captured for all three represented chains, and the signed projection carries credential-free endpoint templates bound to `CHRONOS_ALCHEMY_API_KEY` and `CHRONOS_INFURA_API_KEY`. Runtime resolution never writes those values to registry, identity, capability, or checkpoint artifacts. The first managed preflight failed deterministically before network access because both variables are absent. This is an operational credential blocker, not evidence that either provider lacks trace or archive capability; capability remains unestablished until the frozen fixtures pass for both families.

## Follow-up-horizon decision boundary

The historical deterministic request in `reports/stage2_controls/2026-08-17/follow-up-horizon/control_follow_up_horizon_request.json` binds the frozen policy, all 417 positive records, the latest positive cutoff (`2026-05-27T16:20:45Z`), the 4,170-row target, and the required `INVESTIGATED_NEGATIVE_MATURE` and `FROZEN_COMPLETE` statuses. It is retained as historical fixed-duration evidence and is not the current method.

The current policy names `DYNAMIC_HORIZON_V1`: the user-approved, outcome-blind, pair-specific hierarchical Kaplan–Meier quantile method. The implementation validates seconds-precision reference latency and provenance, rejects prohibited post-cutoff fields, enforces candidate/reference disjointness, uses the frozen exact-to-global fallback, requires at least 30 rows and 20 events, applies 1,000 deterministic PCG64 bootstrap replicates with at least 900 usable estimates, derives pooled safety bounds, assigns integer-day horizons, and reconstructs every maturity timestamp and hash. The required eight-artifact and detached-signature flow is documented in `02_Executable_Artifact/docs/stage2_control_follow_up_horizon_methods_owner_kit.md`. The production reference-side cohort and model now exist, but the pair-feature cohort, production author approval record/signature, and verified production assignment set do not; maturity and censoring therefore remain unresolved and both control counters stay zero.

The reference source has 417/417 counter-authorized v4 snapshots with exact deployment, cutoff, and incident timestamps and no incident at or before its cutoff. Under the explicitly approved `REFERENCE_IDENTITY_DEDUP_V1` rule, it produces 410 unique chain-address rows: the earliest frozen risk-entry and first later qualifying incident are selected per identity, with ascending case ID as the tie-break. Seven excess duplicate rows across seven identity groups are removed without inspecting control outcomes. Unavailable cutoff-safe protocol, proxy, and complexity fields use the canonical `unknown` category, while unestablished source verification is `false`. The resulting non-authorizing package is at `02_Executable_Artifact/reports/stage2_controls/2026-08-20/dynamic-horizon-reference-v1/`; its model uses 410 observed events, has 269 strata of which 6 are estimable, and derives global bounds of 48,544,308 to 185,547,217 seconds. A dedicated external local-test key successfully signed and verified the package manifest under a test-only namespace; this is not the final production approval signature or independent human review.

## Denominator authority bridge

The bridge is `AUTHORITY_BRIDGE_VERIFIED` for exactly 20,000 rows, exactly 5,000 per chain. It binds each additive output row to the sealed Recovery3 verified projection, verification report, final seal, source-record hash, and row-evidence hash. The three Recovery3 inputs remained byte-identical after materialization. The bridge explicitly records `selection_authorized: false` because it establishes denominator authority only; it does not supply the missing matching covariates.

A direct v4-to-Recovery3 authority join was rejected: only 3,272 chain-address identities overlap, while 16,728 identities are unique to each side; the overlapping rows also differ in block/time/source fields. The independently reselected v4 denominator therefore cannot silently inherit Recovery3 row authority. Controls must use the sealed Recovery3-derived authority projection unless a separately verified revision bridge is produced.

## Smallest responsible execution sequence

1. Freeze and verify the reference-latency and cutoff-safe pair-feature cohorts, build all `DYNAMIC_HORIZON_V1` artifacts, register the reviewed public key, and verify the offline author signature before candidate selection or outcome inspection. Until then, the censoring/maturity portion of the prespecification is blocked.
2. Preserve the frozen 558-row trace identity hash. Replace or credential provider families and rerun only the non-authorizing frozen capability probe until all three represented chains pass two-family known-creation and historical-state agreement. Do not sign an activation or reacquire completed receipt assignments before that gate passes.
3. Re-run the deployment-only pair-scope audit only after enough deployment-classification-complete rows exist. Require every case to have at least its missing slot count and certified no-reuse allocation to reach 4,170. This is necessary, not sufficient.
4. After the deployment-scope gate passes, acquire pair-specific runtime, proxy, source-verification, clone, and protocol evidence at each positive prediction cutoff. Every import must bind the case, cutoff, pair-scope row, authority record, raw evidence hashes, and no-repeat ledger.
5. Re-run the pair-evidence preflight; require zero missing, incomplete, hash-invalid, cutoff-mismatched, duplicate, replayed, or unauthorized records.
6. Run a frozen 10-case pilot. Green requires exactly 100 unique candidates and all five selection-time checks (temporal, lineage, clone, proxy, and protocol) hash-bound; any shortfall is preserved and triggers redesign, not relaxation. Mechanism separation remains pending until qualification-time outcome review.
7. Only after the pilot gate passes, generate the 4,170 unique candidate rows.
8. Complete the frozen follow-up, censoring, investigated-negative maturity, mechanism separation, and independent human outcome review before any row becomes `QUALIFIED_CONTROL`.

No additional RPC method or endpoint is authorized by this report. Continuation under the existing local-test activation must remain within its exact queue, provider, method, request-ceiling, raw-receipt, and no-repeat bindings. Trace, historical code/storage, or other pair-covariate RPC requires a new separately verified activation.

## Verification command

```bash
cd 02_Executable_Artifact
./.venv/bin/python preflight_stage2_controls.py \
  --positives processed/stage2_controls/2026-08-17/covariate-inventory/positive_control_covariate_projection.csv \
  --denominator processed/stage2_controls/2026-08-17/covariate-inventory/denominator_control_covariate_projection.csv \
  --output reports/stage2_controls/2026-08-17/covariate-inventory/stage2_control_preflight.json
```

Exit `3` is expected until the historical-denominator redesign, pair-specific evidence, and follow-up-horizon gates close.

Deployment-scope audit:

```bash
./.venv/bin/python build_stage2_control_pair_scope.py \
  --positives processed/stage2_controls/2026-08-17/covariate-inventory/positive_control_covariate_projection.csv \
  --authority-denominator processed/stage2_controls/2026-08-17/recovery3-authority-bridge/control_denominator_authority_projection.csv \
  --deployment-window-days 30 \
  --controls-per-positive 10 \
  --output-csv processed/stage2_controls/2026-08-17/pair-scope/control_pair_acquisition_scope.csv \
  --output-expansion-requirements processed/stage2_controls/2026-08-17/pair-scope/control_denominator_expansion_requirements.csv \
  --output-manifest reports/stage2_controls/2026-08-17/pair-scope/control_pair_acquisition_scope_manifest.json
```

Superseded provider-identity failure reproduction (exit `3` is expected only for this retained historical input pair):

```bash
./.venv/bin/python preflight_stage2_control_candidate_rpc_providers.py \
  --provider-registry config/public_provider_registry.yaml \
  --provider-identity-verification raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v4/provider_identity_verification.json \
  --required-chain ethereum \
  --required-chain bsc \
  --required-chain base \
  --required-chain arbitrum \
  --output-report reports/stage2_controls/2026-08-17/expansion-chunks/control_candidate_rpc_provider_readiness.json
```
