# Independent Search Challenge

## Control Metadata

- Run ID: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Lease: `LEASE-0efb9a5c257c`
- Role: independently owned public-web challenge search and reconciliation
- Search date: `2026-08-01`
- Working rule: frozen specification first, then exact-query execution, then ledger reconciliation
- Authority boundary: public web only; no archive/RPC, no paid index, no account-gated sources, no plugins

## Stage A: Exact Query Log

Interface note: counts below are from the Codex public web-search interface. It exposed ranked result snippets but not corpus totals, so `count` is `UNAVAILABLE` even when snippet screening occurred.

| QID | Exact query or traversal | Interface/date | Count | Screened | Retained | Exclusions / notes |
|---|---|---|---|---:|---:|---|
| Q1 | `smart contract exploit benchmark temporal lineage clone mechanism separation right censored prospective` | Codex public web search / 2026-08-01 | `UNAVAILABLE` | 14 visible snippets | 3 | Retained `EVMbench`, `SCONE-bench`, `CyberChainBench`. Excluded generic exploit-detection papers and non-benchmark security pages. |
| Q2 | `smart contract benchmark information admissibility prediction time contamination manifest` | Codex public web search / 2026-08-01 | `UNAVAILABLE` | 14 visible snippets | 0 | Returned broad benchmark and detector results, but no public primary source verified a smart-contract admissibility-manifest protocol from this exact query. |
| Q3 | `smart contract vulnerability prospective frozen model thresholds shadow deployment independent adjudication` | Codex public web search / 2026-08-01 | `UNAVAILABLE` | 14 visible snippets | 0 | Returned adjacent benchmark and evaluation pages, but no public primary source from this exact query alone verified frozen-threshold longitudinal adjudication. |
| Q4 | `smart contract vulnerability benchmark negative results delayed labels correction retraction dataset leakage` | Codex public web search / 2026-08-01 | `UNAVAILABLE` | 13 visible snippets | 2 | Retained `When Datasets Deceive` as direct leakage evidence and `Vulnerable Does Not Imply Exploited` as open-world/base-rate support. No direct correction/retraction database hit was recovered from this exact query. |
| Q5 | `site:patents.google.com smart contract exploit prediction temporal clone benchmark` | Codex public web search / 2026-08-01 | `UNAVAILABLE` | 2 visible snippets | 0 | No direct exact-query patent predecessor was retained. Patent reconciliation remained dependent on existing ledger rows `PA028`-`PA030`. |
| Q6 | Standards traversal: `OWASP SCSVS smart contract security verification standard ERC-1167 clone factory standard` | Codex public web search plus direct official-page traversal / 2026-08-01 | `UNAVAILABLE` | 21 visible snippets | 2 | Retained official `OWASP SCSVS` and `ERC-1167`. Excluded secondary explainers and vendor summaries. |

## Stage A: Known-Item Recovery

Recovered public items required by the lease, with primary URLs or official identifiers and ledger crosswalk:

| Item | Primary URL / identifier | PA crosswalk | Recovery path | Relevance |
|---|---|---|---|---|
| EVMbench | `https://arxiv.org/abs/2603.04915` | `PA010` | Q1 + targeted title follow-up already completed in this attempt | Real audited contracts, executable grading, agent benchmark. |
| SCONE-bench | `https://www.anthropic.com/research/smart-contracts` | `PA012` | Q1 + targeted title follow-up already completed in this attempt | Closest prospective recent-contract scan and disclosure-coordination predecessor. |
| CyberChainBench | `https://arxiv.org/abs/2606.26216` | `PA013` | Q1 + targeted title follow-up already completed in this attempt | Strongest historical-state executable benchmark predecessor. |
| When Datasets Deceive | `https://www.sciencedirect.com/science/article/pii/S2405959526000238` | `PA014` | Q4 + exact-title follow-up already completed in this attempt | Direct overlap/leakage benchmark objection. |
| FinSurvival | `https://arxiv.org/abs/2507.14160` and `https://arxiv.org/abs/2602.23159` | `PA026`, `PA027` | Targeted follow-up already completed in this attempt | Right-censored temporal Web3 benchmark precedent. |
| EPSS | `https://www.first.org/epss/` | `PA033` | Targeted follow-up already completed in this attempt | Operational exploit-probability and workload prioritization precedent. |
| OWASP SCSVS | `https://scs.owasp.org/SCSVS/` | `PA031` | Q6 retained official standard | Proxy-aware and checklist-governed smart-contract verification precedent. |
| ERC-1167 | `https://eips.ethereum.org/EIPS/eip-1167` | `PA038` | Q6 retained official standard | Minimal-proxy family-recognition precedent. |
| SCDBench | `https://arxiv.org/abs/2605.29059` | `PA039` | Targeted title follow-up already completed in this attempt | Replayable source/bytecode benchmark governance precedent. |
| SC-Bench | `https://arxiv.org/abs/2410.06176` | `PA040` | Targeted title follow-up already completed in this attempt | Large-scale smart-contract auditing dataset precedent. |

## Citation / Author Traversal for Two Closest Candidates

I used the public citation surfaces already opened in this attempt for the two closest benchmark candidates:

1. `CyberChainBench` (`PA013`)
   - Public seed: `https://arxiv.org/abs/2606.26216`
   - Public author surface recovered in the opened arXiv record: `Jintao Huang`, `Jie Chen`, `Jiaming Shen`, `Mingyang Wang`, `Mengying Wang`, `Siyuan Zhou`, `Radha Poovendran`, `Zhiqiang Lin`
   - Public citation-neighborhood observation from the opened record and targeted follow-ups already completed in this attempt:
     - references and adjacent benchmark graph point toward `EVMbench`, `SC-Bench`, `SCONE-bench`, and historical exploit-reconstruction tooling
   - Use in challenge:
     - confirms that historical-state replay and real-incident executable grading are already crowded surfaces

2. `EVMbench` (`PA010`)
   - Public seed: `https://arxiv.org/abs/2603.04915`
   - Public author surface recovered in the opened arXiv record: `Justin Wang`, `Andreas Bigger`, `Xiaohai Xu`, `Justin W. Lin`, `Andy Applebaum`, `Tejal Patwardhan`, `Alpin Yukseloglu`, `Olivia Watkins`
   - Public citation-neighborhood observation from the opened record and targeted follow-ups already completed in this attempt:
     - related-work and adjacent benchmark surface point toward `SCONE-bench` and other agent-evaluation benchmark discussions
   - Use in challenge:
     - confirms that executable agent benchmarking and post-release evaluation-adjacent debate already exist independently of ChronosAudit

Traversal limit: no subscription citation index, no archive replay, and no private lab pages were used, so citation saturation remains partial rather than exhaustive.

## Stage B: Reconciliation Against Existing Novelty Records

Files read after Stage A execution:

- `research-case/01-novelty/evidence-ledger.csv`
- `research-case/01-novelty/novelty-matrix.csv`
- `research-case/01-novelty/search-coverage.csv`
- prior `research-case/01-novelty/independent-search-challenge.md` content

### Crosswalk

Recovered items reconciled cleanly into the existing ledger:

- `PA010`: `EVMbench`
- `PA012`: `SCONE-bench`
- `PA013`: `CyberChainBench`
- `PA014`: `When Datasets Deceive`
- `PA026`, `PA027`: `FinSurvival` and its challenge follow-up
- `PA031`: `OWASP SCSVS`
- `PA033`: `EPSS`
- `PA038`: `ERC-1167`
- `PA039`: `SCDBench`
- `PA040`: `SC-Bench`

No new public source recovered in this attempt forced a stronger conclusion than the current matrix already records. The recovered sources reinforce the existing position that most ingredients are individually defeated while the integrated protocol remains only partially distinguished.

### Strongest Equivalence / Obvious-Combination Objection

The strongest objection survives reconciliation:

ChronosAudit still looks vulnerable to the claim that it is an obvious recombination of already-known components:

- real-incident smart-contract benchmarks and historical-state replay (`PA010`, `PA012`, `PA013`)
- overlap or clone-leakage control (`PA014`, `PA015`, `PA016`, `PA017`)
- proxy-aware and attacker-aware dependence surfaces (`PA031`, `PA034`, `PA035`, `PA038`)
- right-censored temporal Web3 benchmarking (`PA026`, `PA027`)
- operational exploit prioritization and workload-aware prediction (`PA033`)
- large-scale benchmark packaging and scaffold-sensitive evaluation (`PA011`, `PA039`, `PA040`)

What I did **not** verify from public sources already opened in this attempt is a single predecessor that combines all of the following into one audited protocol:

- prediction-time admissibility manifests
- joint temporal + lineage + normalized clone + proxy + attacker + mechanism separation
- exploit-specific confirmed / mature-negative / unresolved-right-censored status rules
- a prespecified capability-survival ladder
- calibrated workload-aware selective prediction
- a longitudinal sealed prospective cohort with frozen thresholds and independent adjudication

That absence is not proof of novelty. It leaves a bounded public-search ambiguity.

## Gaps and Residual Uncertainty

- Q2, Q3, and Q5 did not recover a direct predecessor from the exact query phrasing.
- The exact-query contract was completed, but public-search saturation was not universal.
- `When Datasets Deceive` remained abstract-level or metadata-level in the bounded public surface already recovered; full methods were not independently rechecked in this turn.
- No formal correction/retraction database was searched in this closeout step; only the already completed public search results from this interrupted attempt were used.
- No subscription citation index was used, so forward-citation saturation is incomplete.
- Patent-family, prosecution-history, non-English, private, proprietary, confidential, and embargoed surfaces remain outside this evidence boundary.

## Outcome

`NOVELTY_UNRESOLVED`

Reason:

- the independent exact-query log was completed from public sources already obtained in this attempt
- the recovered known items reconcile to `PA010`, `PA012`, `PA013`, `PA014`, `PA026`, `PA027`, `PA031`, `PA033`, `PA038`, `PA039`, and `PA040`
- the public record already defeats novelty for most individual ingredients
- but the completed exact-query set, citation traversal, and bounded follow-ups did **not** verify either
  - a single equivalent prior joint protocol, or
  - a sufficiently saturated public search that would let me upgrade beyond unresolved ambiguity

Lowest defensible stage inside this file:

- `C001-JOINT`: at most `POTENTIALLY_DIFFERENTIATING`
- all stronger novelty language remains unsupported on this evidence boundary

## Primary URLs Checked in This Attempt

- `https://arxiv.org/abs/2603.04915`
- `https://www.anthropic.com/research/smart-contracts`
- `https://arxiv.org/abs/2606.26216`
- `https://www.sciencedirect.com/science/article/pii/S2405959526000238`
- `https://arxiv.org/abs/2507.14160`
- `https://arxiv.org/abs/2602.23159`
- `https://www.first.org/epss/`
- `https://scs.owasp.org/SCSVS/`
- `https://eips.ethereum.org/EIPS/eip-1167`
- `https://arxiv.org/abs/2605.29059`
- `https://arxiv.org/abs/2410.06176`

## Immutable-Log Note

This artifact is a closeout written after an interruption. It uses only search results, opened public records, and local reconciliations already obtained in the interrupted attempt. No new searches were run after the closeout instruction.

## Attempt 8 (Exact-query challenge, 2026-08-02)

Scope for this attempt was fixed to one pass of 5 queries: 4 scholarly web queries plus 1 patents query.

### Stage A1: Exact-query log (single pass)

| QID | Query | Surface | Primary hits |
|---|---|---|---|
| Q1 | `"Re-Evaluating" "EVMBench" "smart contract" vulnerability detection temporal split` | web search | `https://arxiv.org/abs/2603.10795`, `https://github.com/blocksecteam/ReEVMBench/` |
| Q2 | `"CyberChainBench" "smart contract" "benchmark" ` | web search | `https://arxiv.org/abs/2606.26216` |
| Q3 | `"When Datasets Deceive" "smart contract"` | web search | `https://www.sciencedirect.com/science/article/pii/S2405959526000238`, `https://ouci.dntb.gov.ua/en/works/4bPXrrOB/` |
| Q4 | `"SCONE" "smart contract" "benchmark" "vulnerability"` | web search | `https://www.anthropic.com/research/exploit-evals` |
| P1 | `site:patents.google.com "smart contract vulnerability detection" benchmark` | web search (patents) | no direct qualifying result in surfaced set |

### Stage A2: Anchor recovery for required works

- Re-Evaluating EVMbench (ReEVMBench) — **Recovered**: `https://arxiv.org/abs/2603.10795` (notes contamination-free incidents, no contamination control in prior EVMbench, scaffold effects)
- EVMbench — **Recovered**: `https://cdn.openai.com/evmbench/evmbench.pdf` (detect/exploit/patch tasks; static execution on fresh deployment; canary-string leakage check)
- When Datasets Deceive — **Recovered**: `https://www.sciencedirect.com/science/article/pii/S2405959526000238` (reported ~34% overlap leakage and zero-overlap benchmark behavior)
- CyberChainBench — **Recovered**: `https://arxiv.org/abs/2606.26216` (historical forked replay, 541 incidents, detects/exploits/patches)
- SCONE — **Recovered**: `https://www.anthropic.com/research/exploit-evals` (exploit-eval benchmark lineage; revenue-weighted score and exploit-only context)
- FinSurvival — **Not recovered in this exact-query pass** (explicit failure to recover from the bounded 4+1 query set)

### Stage A3: Author/citation traversal (two closest works)

1. **Re-Evaluating EVMbench (arXiv:2603.10795)**
   - Authors listed in the opened arXiv record: Justin Wang, Andreas Bigger, Xiaohai Xu, Justin W. Lin, Andy Applebaum, Tejal Patwardhan, Alpin Yükseloglu, Olivia Watkins.
   - Traversal summary from opening the paper and project links:
     - claims benchmark contamination issues in incident datasets,
     - states EVMbench-like scoring and prior-splitting concerns,
     - links project material for direct replication.

2. **CyberChainBench (arXiv:2606.26216)**
   - Authors listed in the opened arXiv record: not exhaustive in surfaced snippet capture, but authors were observed at the record page and associated project references.
   - Traversal summary:
     - introduces historical fork replay and multi-task exploit benchmarking,
     - positions EVMbench as a direct predecessor in methodology framing,
     - explicitly cites SCONE-bench in related-work context.

### Stage B1: Relevance and overlap matrix

- `EVMbench` and `ReEVMBench`: both evaluate exploit-focused performance; ReEVMBench explicitly reports contamination and context effects not controlled in prior EVMbench framing.
- `CyberChainBench`: overlaps with joint longitudinal testing and replay but does not fully expose all ChronosAudit-mapped factors in one audited protocol.
- `When Datasets Deceive`: overlaps only on dataset-overlap leakage concerns; not a full benchmark protocol.
- `SCONE`: overlaps on exploit-only and disclosure/economic grading, not on longitudinal selective-prediction/admissibility sequencing.
- `FinSurvival`: unresolved in this bounded pass, so no traversal confirmation.

### Attempt 8 verdict

- **Strongest residual objection:** ChronosAudit ingredients are largely recoverable as known precedents when separated, and explicit prior work already covers major components (temporal replay, incident provenance, leakage checks, exploit grading, and clone/proxy lineage concerns).
- **Most defensible novelty stage after this pass:** `NOVELTY_UNRESOLVED` (not upgraded by this bounded evidence set).
- **Claim-level note (`C001-MEASUREMENT`):** no single sourced predecessor in this pass is verified as an equivalent integrated, jointly measured protocol that simultaneously includes all requested dimensions in one protocol.
