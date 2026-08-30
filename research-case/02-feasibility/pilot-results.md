# ChronosAudit feasibility pilot results

## Status

- Run: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Phase: `FEASIBILITY_GATE`
- Pilot status: `CYCLE 2 COMPLETED AND INDEPENDENTLY RECHECKED`
- Latest completed independent feasibility verification: `FEAS-A4-CYCLE2-REASSESSMENT-001`
- Evidence status: `PUBLIC-DATA PILOT CYCLES 1-2 EXECUTED; BENCHMARK-CORE GREEN NOT ESTABLISHED; NO CYCLE-2 DECISION PROMOTION`

## Explanation

The requesting user explicitly authorized the bounded public-data feasibility pilot on `2026-08-01`. The first wave audited source rights, access, resources, and cohort options. The second wave froze an eight-case cohort, instantiated a pilot admissibility manifest, reproduced a narrow clone check, and ran a public static-analysis substitute baseline after static security preflight.

Only sources and tools that pass the frozen authority, rights, safety, and resource checks may enter later manifest, rerun, clone, mechanism/status, or baseline slices.

## Consequence

- No `GO TO STUDY_DESIGN` claim may be made from this file.
- Pilot measures below are feasibility measures only. They are not exploit-detection performance results and do not support operational utility claims.
- The execution wave has now been challenged independently and remains below the threshold for `GO TO STUDY_DESIGN`.

## First-wave evidence

### Source-rights and access matrix

| Source or tool | Public accessibility checked `2026-08-01` | License / terms evidence | Lawful bounded pilot use now | Blocked or unresolved use | First-wave disposition |
|---|---|---|---|---|---|
| Sourcify docs, API, and Parquet export | Public docs and export endpoints are reachable. Sourcify states the project is open-source, open-data, and that it daily shares the whole dataset. The v2 export is append-oriented, timestamped, and exposes `LastModified`, `ETag`, and file metadata. | Sourcify project repo is public and MIT-licensed; docs describe public dataset access. These sources do not by themselves grant ChronosAudit blanket redistribution rights to every underlying contract source file. | Use public metadata, verification records, timestamps, hashes, and link-level provenance. | Treat per-contract source redistribution as unresolved unless the contract itself has an explicit original license that is independently verified. | `AMBER` |
| SmartBugs Curated | Public repository reachable. README states the dataset is a curated vulnerable-contract corpus. | Repository wrapper is Apache-2.0, but the README states all contracts retain their original licenses and only the other repository files are covered by the repository LICENSE. | Use dataset metadata, taxonomy, and only contract files whose original licenses are individually verified. | Do not assume bulk redistribution rights for all contract sources in the dataset. | `AMBER` |
| DeFiHackLabs | Public repository reachable. | Repository page and LICENSE show Apache-2.0. | Use repository-contained materials as a public pilot source, subject to case-level provenance checks. | If a later release package needs copied third-party protocol code or artifacts whose upstream rights are unclear, those items need separate review. | `GREEN` for repository-contained pilot use; `AMBER` for downstream redistribution assumptions |
| Slither | Public repository reachable. | Repository page states Slither is licensed and distributed under AGPLv3. | Local bounded use is legally plausible for internal pilot reproduction once security preflight is completed. | Redistribution, hosted/network service use, or modified public packaging would trigger AGPL obligations that are not yet planned. | `GREEN` for local bounded use |
| Foundry | Public repository reachable; local `forge` binary already present. | Repository page states Foundry is available under Apache-2.0 or MIT at the user's option. | Local bounded use is legally plausible for internal pilot reproduction. | No rights blocker identified at the tool-license level; runtime safety review is still required before using untrusted repositories. | `GREEN` |
| MANDO-LLM (`MANDO-Project/ge-sc-llm`) | Public repository page reachable. Repository points to Google Drive assets/checkpoints. | No retrievable LICENSE file was found in the checked public repository snapshot, unlike the other tool repositories above. The public page exposes code and requirements, but no clear redistribution grant was verified from the checked sources. | Metadata-only review of the public repository and paper-level claims. | Do not use as an executable or redistributable baseline until a verifiable license and reproducible asset path are established. | `RED` for executable baseline use |

### Local resource envelope

| Check | Result | Consequence |
|---|---|---|
| `docker` | `/usr/local/bin/docker` | Container-based reproduction is mechanically possible if later authorized and preflighted. |
| `forge` | `/Users/rainbow/.foundry/bin/forge` | Foundry is already installed locally. |
| `git` | `/opt/homebrew/bin/git` | Repository inspection and cloning are mechanically possible once lawful and preflight-approved. |
| `python3` | `/opt/homebrew/bin/python3` (`Python 3.14.6`) | Python-based local tooling is available. |
| `slither` | not found | Slither reproduction is not immediately runnable without a separate installation or isolated environment. |
| `solc` | not found | Solidity compiler availability is not yet confirmed outside tool-managed flows. |
| Platform | `Darwin arm64` | Any frozen baseline must tolerate Apple Silicon or use an isolated environment. |
| Free disk | `179 GiB` on the workspace volume | Local storage is not the immediate bottleneck for a small pilot. |

### First-wave cohort disposition

- Before execution wave 2, a lawful next slice could only draw from:
  - Sourcify cases whose provenance timestamps are publicly visible and whose contract-level source rights are explicit or unnecessary because the slice uses metadata only
  - DeFiHackLabs cases fully represented inside the Apache-2.0 repository and still compatible with the prediction-time provenance contract
  - SmartBugs entries whose original contract licenses can be verified case by case
- The following remained excluded from cohort freeze:
  - any case that requires nonpublic provenance, post-cutoff facts, or private incident confirmation for a critical manifest field
  - any contract source whose redistribution path is unclear
  - any executable baseline path that depends on unlicensed or inaccessible MANDO-LLM assets

### First-wave criterion status

| Criterion | Status after wave 1 | Basis |
|---|---|---|
| `pilot_scope_freeze` | `GREEN` | The scope note and authorization boundary are recorded in `pilot-plan.md` and `decision-log.md`. |
| `rights_ledger_coverage` | `AMBER` | A lawful path exists for metadata-only use and some repository-contained sources, but not yet for a mixed contract-source corpus. |
| `cost_access_envelope` | `AMBER` | Local compute and storage are adequate for a small pilot, but compiler/tool gaps and archival-access costs remain unresolved. |
| `baseline_reproducibility` | `NOT YET EVALUATED` | MANDO-LLM is not cleared for executable use; no substitute baseline has been preflighted or run. |
| All other pilot criteria | `NOT YET EVALUATED` | They depend on the still-unfrozen lawful cohort and later rerun slices. |

## First-wave implication

- The benchmark-core pilot may continue only in a narrower form: metadata-first and license-cleared source slices only.
- No shareable benchmark corpus, no MANDO-LLM executable baseline, and no broad contract-source ingestion is currently justified.
- Before any further execution beyond documentation and manual source review, the next slice must:
  - freeze an exact lawful cohort
  - select a baseline that is both licensed and reproducible under the bounded authority
  - run codebase security preflight before any newly cloned or downloaded repository is executed

## Second-wave bounded execution

### Frozen cohort and role boundaries

The cohort in `support/pilot-cohort.csv` contains eight cases. It is an information-sufficiency sample, not an efficacy sample:

- `CA-P01`–`CA-P03`: public SmartBugs fixtures used only to test clone, proxy, mechanism, and static-analysis plumbing. They are never counted as real pre-incident protocol observations.
- `CA-P04`–`CA-P07`: public DeFiHackLabs incident replays used only as post-cutoff label evidence. The replay files are inadmissible prediction inputs.
- `CA-P08`: the Ethereum deposit contract used only as a property-bounded mature-investigated-negative trial. It is not a global safety claim, and its formal-verification artifact still requires bytecode-version binding.

The exact source revisions are frozen in `support/pilot-cohort.csv`. No third-party source file is copied into the research package; the package preserves paths, revisions, hashes, public metadata, and derived outputs.

### Static security preflight and execution boundary

Before any cloned repository code was executed, the following repositories were reviewed statically at their frozen commits:

- DeFiHackLabs `311184fef6b995be019f6729c2bae279228ae5e8`
- SmartBugs Curated `230e649123477eff332742a59a1c7cc6dc286cab`
- Slither `050cc0a094e77bfd58e8228ae3bb6aa15c65edb4`

The review found repository surfaces that must remain blocked in this pilot: submodules, Foundry replay tests, public RPC calls, Docker builds, CI helpers, download-and-execute paths, and repository scripts. The only allowed execution was a pinned, isolated Slither CLI against selected local fixture files. No live-chain call, transaction, exploit replay, submodule, container, repository test, or third-party target was executed.

### Environment capture

| Component | Frozen pilot value |
|---|---|
| Host | macOS arm64 |
| Free workspace disk at start | approximately `179 GiB` |
| Slither source revision | `050cc0a094e77bfd58e8228ae3bb6aa15c65edb4` |
| Slither version | `0.11.6` |
| Isolated Python | CPython `3.13.13` managed by `uv` |
| Solidity compilers | `0.4.19` and `0.4.24` via `solc-select 1.2.0` |
| Docker | binary present; daemon unavailable and not used |
| Foundry | `1.5.1-stable`; not used for replay execution |

### Admissibility-manifest result

The frozen rules are in `support/pilot-rules.md`, and the case-level trial output is in `support/admissibility-manifest-pilot.csv`.

- All three fixture rows are complete for their restricted tooling role and are marked `FIXTURE_ONLY`.
- All five real-case rows are `HOLD_RECOVERABLE` rather than split-eligible.
- `CA-P04`–`CA-P07` lack one or more prediction-time source, bytecode, proxy, compiler, or lineage artifacts.
- `CA-P08` lacks a frozen binding between the formally verified bytecode version and deployed bytecode, plus a prespecified follow-up-search record.
- Therefore, manifest completeness for real benchmark observations is `0/5`; overall row-level completeness for the declared restricted role is `3/8`.

This is an `AMBER`, not a `RED`, result because each gap has a named archival or version-binding route. It is not `GREEN` because the benchmark-core criterion requires all critical fields without post-cutoff leakage.

### Public metadata timing check

The manual Sourcify v2 lookups are preserved verbatim in `support/sourcify-metadata-20260801.jsonl`:

| Case | Result | Prediction-time consequence |
|---|---|---|
| `CA-P04` Parity | HTTP `404` | No current Sourcify match; no prediction-time source path established. |
| `CA-P05` Nomad proxy and logic | HTTP `200`; both verified `2024-08-08` | Verification postdates the 2022 incident and is label-side only. |
| `CA-P06` Euler | HTTP `200`; verified `2024-08-08` | Verification postdates the 2023 incident and is label-side only. |
| `CA-P07` Curve pETH pool | HTTP `404` | No current Sourcify match; no prediction-time source path established. |
| `CA-P08` deposit contract | HTTP `200`; exact match verified `2024-08-08` | Verification postdates the 2021 cutoff; independent formal-artifact/version binding is still required. |

Current Sourcify metadata therefore does not establish prediction-time source availability for any of the five real-case trials. This directly validates the need for a historical provenance layer.

### Clone-pipeline result

`support/normalize_solidity.py` is a pilot-only lexical normalizer. It removes comments and whitespace outside strings and makes no semantic-equivalence claim.

- The two SmartBugs TokenBank category fixtures have different raw files but yielded the same normalized SHA-256 in two independent runs: `7128a161d626f9cf1c033252250e7e55a0d56559bc910525ba858e2ba654c50e`.
- Both normalized outputs were `1000` bytes.
- Planned clean reruns: `2`; successful deterministic reruns: `2/2`.

This is `GREEN` for the narrow lexical pilot pipeline. It does not establish source-semantic, bytecode-semantic, proxy-family, or attacker-contract clone detection.

### Substitute baseline result

MANDO-LLM remained metadata-only because a retrievable license and frozen artifact path were not verified. Slither was used as the prespecified auditable public substitute to test whether a frozen comparator pipeline could run reproducibly.

| Stage | Result | Preserved output SHA-256 |
|---|---|---|
| SimpleDAO first run | `success=true`; four findings | `8ec971c332de8ed017e08843d01e4b388b87b3c6f4a81ca9511164d096c92171` |
| SimpleDAO clean rerun | byte-identical to first run | `8ec971c332de8ed017e08843d01e4b388b87b3c6f4a81ca9511164d096c92171` |
| TokenBank reentrancy path | `success=true`; 23 findings | `bd5f07e350044bba1c80240b83e85a6e95e189cd70f460550fb32a8e7f3de878` |
| TokenBank unchecked-call path | `success=true`; 23 findings | `e4c3aec10e65306633fa91d9e53d13ce39b406dd8c64f4911a1d491721fdde0f` |
| Proxy fixture | `success=true`; six findings | `9886ad3c6214891fa9eb6e5a2d3fad8e283b7b7ab247dc9ece99ea1e14f96c63` |

The Slither process exits nonzero when findings exist, but every preserved JSON file reports `success=true`. Planned stages reproduced: `5/5`. This is `GREEN` for a narrow structural public baseline and environment-capture path. It is not evidence that Slither or ChronosAudit detects unknown exploits or supports the proposed capability-survival estimand.

### Independent reassessment result

The independent challenge is preserved in `support/independent-assignment-rerun-20260801.md`.

- Split eligibility remained unchanged for all `8/8` pilot rows.
- One localized disagreement was preserved for `CA-P08`.
- The disagreement does not alter split eligibility because `CA-P08` remains `HOLD_RECOVERABLE` either way.
- The disagreement does prevent the status-rubric surface from reaching `GREEN` because the bounded packet does not independently justify `MATURE_INVESTIGATED_NEGATIVE`.

| Surface | Independent result | Direct implication |
|---|---|---|
| Split rerun stability | `8/8` unchanged split-eligibility outcomes | `GREEN` |
| Mechanism/status rubric | `1/8` clear disagreement; `0/8` split changes | `AMBER` |
| Localized disagreement | `CA-P08` primary manifest says `MATURE_INVESTIGATED_NEGATIVE`; independent rerun says `RIGHT_CENSORED_UNRESOLVED` | recover or bind the formal-verification and frozen follow-up evidence before promotion |

### Execution-wave progression status

| Criterion | Status | Direct denominator and implication |
|---|---|---|
| `pilot_scope_freeze` | `GREEN` | `1/1`; the bounded authority and exclusions were preserved. |
| `rights_ledger_coverage` | `GREEN` for this internal pilot; not for release | Every selected source has a local-analysis, derived-output, or metadata/link-only path. Per-contract redistribution remains unresolved and cannot be promoted to a dataset-release right. |
| `manifest_completeness` | `AMBER` | `3/8` complete for declared restricted role; `0/5` real observations split-eligible. Gaps are explicit and potentially recoverable. |
| `split_rerun_stability` | `GREEN` | `8/8` unchanged split-eligibility outcomes under independent rerun. |
| `clone_pipeline_reproducibility` | `GREEN` | `2/2` deterministic lexical-normalization reruns. |
| `mechanism_status_rubric_operability` | `AMBER` | `7/8` overall and `4/5` real-case rows retain the primary status assignment; `CA-P08` needs stronger mature-negative evidence binding. Mechanisms were assignable for `8/8`, with contextual nuance on `CA-P05` and `CA-P07`. |
| `baseline_reproducibility` | `GREEN` for substitute baseline | `5/5` planned stages; scope limited to reproducible structural analysis. |
| `cost_access_envelope` | `AMBER` | Local pilot tasks fit current resources; archival reconstruction costs and access paths for real cases remain unresolved. |
| `extension_authority_package` | `RED/BLOCKED` | Prospective prerequisites remain absent; this does not determine benchmark-core green. |

### Support-artifact integrity ledger

| Artifact | SHA-256 |
|---|---|
| `support/pilot-cohort.csv` | `d307cb3d1c330f4dc9695382e1af7cc65e5a26b4bdac1ca31ca3ef55e3d2ecd2` |
| `support/pilot-rules.md` | `6ebd7aaad5bf603a316ab7d730c2bcf635463e4d3c2542081b1df543dda3223c` |
| `support/admissibility-manifest-pilot.csv` | `5db74b02ff8c563be416de599fe04a75f2c32642226c4d5834754a217ccfdd77` |
| `support/normalize_solidity.py` | `4945bc3e676d4cb559cd882273455074f1f8652bfa6ecde5c8d169c7c273a799` |
| `support/sourcify-metadata-20260801.jsonl` | `85b32422c60f1fc2034c87a7e37c6d02978fb2a9cf353ffb2551c4c876249445` |
| `support/slither-simple-dao.json` | `8ec971c332de8ed017e08843d01e4b388b87b3c6f4a81ca9511164d096c92171` |
| `support/slither-simple-dao-rerun.json` | `8ec971c332de8ed017e08843d01e4b388b87b3c6f4a81ca9511164d096c92171` |
| `support/slither-tokenbank-reentrancy.json` | `bd5f07e350044bba1c80240b83e85a6e95e189cd70f460550fb32a8e7f3de878` |
| `support/slither-tokenbank-unchecked.json` | `e4c3aec10e65306633fa91d9e53d13ce39b406dd8c64f4911a1d491721fdde0f` |
| `support/slither-proxy.json` | `9886ad3c6214891fa9eb6e5a2d3fad8e283b7b7ab247dc9ece99ea1e14f96c63` |
| `support/independent-assignment-rerun-20260801.md` | `d980b79b9fae8b0a16a01fdaaf7ea5f0cc7ed78a2c4270d83283f5e5c1a56e8c` |
| `support/execution-ledger.md` | `6928d6d01f4dccc31d93753e25914de671ada65a2c4b7742a79afd49d117bb67` |

### Current gate implication

The execution wave does not satisfy all benchmark-core green criteria. `manifest_completeness`, `mechanism_status_rubric_operability`, and `cost_access_envelope` remain below green even after independent reassessment. The smallest responsible next cycle is archival provenance and version-binding work for the five real cases, plus a narrow evidence-binding rerun for `CA-P08`. `STUDY_DESIGN` remains closed, and the prospective extension remains blocked.

## Pilot cycle 2: public provenance, formal binding, and access-cost envelope

### Scope

Cycle 2 executed only the previously authorized recovery slice:

- public prediction-time provenance review for `CA-P04`–`CA-P07`;
- formal-artifact and deployed-bytecode binding review for `CA-P08`;
- provider-level archive-access and cost documentation;
- a new manifest revision that preserves the frozen cycle-1 manifest unchanged.

No provider account was created. No API, RPC, BigQuery, live-chain, replay, or
transaction call was made. No source code was redistributed.

### Prediction-time provenance recovery

The cycle-2 evidence is preserved in
`support/pilot-cycle2-public-provenance.md`, and the revised case output is
`support/admissibility-manifest-pilot-cycle2.csv`.

| Case | Recovered public evidence | Remaining admissibility failure | Cycle-2 result |
|---|---|---|---|
| `CA-P04` | pre-cutoff creation transaction | no pre-cutoff source, bytecode-to-source, or proxy-family binding | `HOLD_RECOVERABLE` |
| `CA-P05` | pre-cutoff creation transaction and primary Nomad Replica documentation | no pre-cutoff proxy-to-implementation and upgrade-timestamp binding | `HOLD_RECOVERABLE` |
| `CA-P06` | pre-cutoff creation transaction and present deployed-bytecode surface | no proof of pre-cutoff source publication or official lineage binding | `HOLD_RECOVERABLE` |
| `CA-P07` | pre-cutoff creation transaction and present proxy-style surface | no pre-cutoff Curve lineage, implementation, or compiler binding | `HOLD_RECOVERABLE` |

Review denominator: `4/4`; promoted to split-eligible: `0/4`; retained as
recoverable holds: `4/4`.

### `CA-P08` binding and censoring disposition

Cycle 2 recovered strong pre-cutoff evidence for the Solidity deposit-contract
source, mainnet address, production bytecode, and a closely related formal
verification. The artifacts do not form an exact proof-to-deployment binding:

- Runtime Verification's bytecode artifact records Solidity `0.6.8` with
  optimizer runs `5,000,000`;
- the production v1.0 JSON and exact-match deployed record identify Solidity
  `0.6.11`, also with optimizer runs `5,000,000`;
- the negative follow-up window and search were not prospectively frozen.

The cycle-1 manifest remains immutable. The cycle-2 manifest adopts the
independent reassessment and assigns `CA-P08` as
`RIGHT_CENSORED_UNRESOLVED`, still `HOLD_RECOVERABLE`. This resolves the
annotation disagreement conservatively but does not demonstrate the
`MATURE_INVESTIGATED_NEGATIVE` class required for a green status-rubric test.

### Archive access and cost

The measured documentation envelope is preserved in
`support/archive-access-cost-envelope-20260801.csv`.

| Route | Documented feasibility | Execution status | Criterion effect |
|---|---|---|---|
| Sourcify and Etherscan | useful for present verification, compiler, creation, proxy, and link-level metadata | manual public pages only | insufficient alone |
| BigQuery Blockchain Analytics | official low-cost SQL corroboration route; first `1 TiB` per month documented as free at audit time | not executed | feasible candidate |
| Alchemy archive RPC | free plan and `20 CU` `eth_getCode` unit documented; a two-call historical/latest probe would be `40 CU` | not executed | feasible candidate |
| Infura archive RPC | free archive-capable account path documented | not executed | feasible candidate |
| QuickNode archive RPC | free trial and paid archive route documented | not executed | feasible candidate |
| Chainstack archive RPC | archive starts on the checked paid tier | not executed | bounded paid candidate |

This moves the access question from unbounded unknown to bounded `AMBER`.
It does not reach `GREEN` because credentials, provider terms, case coverage,
runtime, and actual query success were not tested under the current authority.
Public current metadata alone still leaves every real case ineligible.

### Cycle-2 denominators and progression status

| Criterion | Cycle-2 status | Evidence and consequence |
|---|---|---|
| `manifest_completeness` | `AMBER` | overall restricted-role completeness remains `3/8`; real split-eligible observations remain `0/5` |
| `split_rerun_stability` | `GREEN` retained | no cycle-2 evidence changes split eligibility; all eight rows keep the cycle-1 disposition |
| `mechanism_status_rubric_operability` | `AMBER` | the `CA-P08` disagreement is resolved by conservative right-censoring, but no mature-negative example is now directly demonstrated |
| `cost_access_envelope` | `AMBER`, better bounded | documented free or low-cost paths exist, but none was exercised |
| `extension_authority_package` | `RED/BLOCKED` retained | cycle 2 did not request or supply prospective authority, partners, adjudication, disclosure, or follow-up infrastructure |

### Cycle-2 gate implication

The feasibility decision remains `PILOT_FIRST`. Cycle 2 makes the failure mode
more precise: deployment provenance is often recoverable, but the strict
prediction-time source, proxy/implementation, compiler, and formal-binding
requirements remain unsatisfied. `STUDY_DESIGN` therefore remains closed. The
prospective extension remains `BLOCKED` and was not reopened.

The read-only attempt-4 gate recheck returned `REMEDIATE / PILOT_FIRST` and
confirmed the observed criterion states as `AMBER`, `GREEN`, `AMBER`, and
`AMBER` for manifest completeness, split rerun, mechanism/status, and
cost/access. It promotes no criterion and preserves `PILOT_FIRST`.

### Cycle-2 support-artifact integrity ledger

| Artifact | SHA-256 |
|---|---|
| `support/pilot-cycle2-public-provenance.md` | `072d06ce5f85af49a76d8c7803aa664610f4ff2baee44a3415b2e03cffb67b0a` |
| `support/admissibility-manifest-pilot-cycle2.csv` | `4e0d704089946a63ccf41c5265d58d9ad9e093cc5cb7f0a6e4610a4a30a0eb31` |
| `support/archive-access-cost-envelope-20260801.csv` | `7e1cfbf5817b9c5cf4ed841101d1a181ac62c59836c25804be54dd48ea8f0227` |

## Pilot cycle 3: exercised access failure, real-case attempt, and frozen status trial

### Authorized historical-state test

The cycle exercised exactly one documented public route with the two frozen
`CA-P04` reads. Both the cutoff request at `0x3db416` and the `latest` request
failed with curl exit code `6`, HTTP status `000`, and DNS error
`Could not resolve host: web3-trial.cloudflare-eth.com`. No RPC body was
received. The raw request/error records and method basis are preserved in
`support/archive-test-ca-p04-cutoff.json`,
`support/archive-test-ca-p04-latest.json`, and
`support/pilot-cycle3-archive-access.md`.

This is a measured access failure, not evidence that archive data do not exist.
The path is now `EXECUTED_UNSUCCESSFUL`; cost was zero, but usable access and
coverage were not established.

### Representative manifest attempt

The cycle-3 manifest is
`support/admissibility-manifest-pilot-cycle3.csv`. It preserves the prior eight
rows and adds only the new evidence state plus `CA-P09` as a status-trial-only
row. `CA-P04` remains `HOLD_RECOVERABLE`: the exercised route returned no
historical bytecode, so prediction-time source, bytecode-to-source, proxy,
compiler, clone, and lineage bindings remain incomplete.

Real-incident denominator: `0/5` split eligible; `5/5` remain
`HOLD_RECOVERABLE`. The end-to-end attempt was completed procedurally but failed
scientifically at the access/binding step. It must not be reported as a complete
real-case manifest.

### Prespecified mature-negative trial

`support/mature-negative-trial-cycle3.md` freezes `CA-P09`, the official
Ethereum Uniswap v4 `PoolManager`, with three enumerated properties, a
deterministic selection rule, four evidence snapshots, a 365-day window, explicit
positive and mature-negative endpoints, and independent adjudication. The public
binding packet is `support/mature-negative-candidate-binding.json`.

The trial is genuinely prespecified but not mature. Its current status is
`RIGHT_CENSORED_UNRESOLVED`; the earliest possible mature-negative decision is
`2027-08-01T19:28:31Z`. The current cycle therefore demonstrates that the rule
can be frozen without relabeling `CA-P08`, but does not directly demonstrate a
mature-negative example.

### Cycle-3 criterion disposition

| Criterion | Cycle-3 status | Evidence and consequence |
|---|---|---|
| `manifest_completeness` | `AMBER` | one representative real-case attempt was executed, but `0/5` real incidents remain split eligible |
| `split_rerun_stability` | `GREEN` retained | no existing split disposition changed; `CA-P09` is status-trial-only |
| `mechanism_status_rubric_operability` | `AMBER`, protocol improved | a genuine status trial is frozen, but its 365-day follow-up and independent adjudication are incomplete |
| `cost_access_envelope` | `AMBER`, measured failure | one no-cost route was exercised; DNS failure prevented usable access and no fallback was authorized |
| `extension_authority_package` | `RED/BLOCKED` retained | no prospective, partner, disclosure, adjudication-service, or shadow-deployment package was authorized |

### Cycle-3 gate implication

The decision remains `PILOT_FIRST`. The new evidence replaces two
documented-but-unexecuted assumptions with direct outcomes: one unsuccessful
access test and one prespecified but still right-censored status trial. It does
not satisfy the manifest, mature-negative, or access green thresholds.
`STUDY_DESIGN` remains closed and the prospective extension remains `BLOCKED`.

The independent attempt-5 gate check,
`FEAS-A5-CYCLE3-REASSESSMENT-001`, returned `REMEDIATE / PILOT_FIRST` and
confirmed `AMBER`, `GREEN`, `AMBER`, `AMBER` for manifest completeness, split
rerun, mechanism/status, and cost/access. It independently rejected treating
the DNS failures as successful RPC evidence, rejected calling `CA-P04`
complete, and rejected calling `CA-P09` mature.

### Cycle-3 support-artifact integrity ledger

| Artifact | SHA-256 |
|---|---|
| `support/pilot-cycle3-archive-access.md` | `89c2ef78ad021d07bdb1a024ebf294a54e87cd060f464dc3827d56d0c95081a4` |
| `support/archive-test-ca-p04-cutoff.json` | `4211291cb6c0998f8d4f49dd7f78a1ccbd225301266e0bb5ceefbacd5dae0d7b` |
| `support/archive-test-ca-p04-latest.json` | `81da4f01e9efa95e888df43ca276ffe58256a65aa98ecc4d70cf5b09210f5212` |
| `support/admissibility-manifest-pilot-cycle3.csv` | `cb84033c510ff38b02784ef0d507edd706819e02a53feda4a0bdfafe0befee73` |
| `support/mature-negative-trial-cycle3.md` | `1381d052635d80144c7e9811c04e9fccdb2b686e7a9b61c6e58f6e59e43f9ef5` |
| `support/mature-negative-candidate-binding.json` | `f3bed43ad08c50f116f2d2ad42ed33411ddc7d40673c455a6aee4612514958d6` |
| `support/independent-cycle3-gate-check-20260801.md` | `5dc9fdc9a2967da83cb06b54c882800297987aa2e879b24733d0ee21023fd0d8` |
