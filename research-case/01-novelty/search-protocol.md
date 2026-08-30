# ChronosAudit Strongest-Prior-Art Search Protocol

## Purpose and decision boundary

- Run ID: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Claim under audit: `C001`
- Search date and cutoff: `2026-08-01`
- Search owner: `root-integration-owner`, after two preserved specialist attempts failed without producing evidence artifacts.
- Scope: public, read-only sources concerning smart-contract security benchmarks, temporal or contamination controls, code-clone controls, historical-chain or executable grading, exploit-mechanism taxonomies, prospective evaluation, censor-aware population evaluation, and selective prediction.
- Decision boundary: this search can identify strong predecessors and bound a novelty claim. It cannot prove universal absence. ChronosAudit remains `UNRESOLVED` until the novelty matrix and an independent citation challenge are complete.

## Reproducible search surfaces

The search used public web discovery to locate records, then relied on opened primary records wherever accessible:

- arXiv abstract and PDF records;
- ACM, IEEE, Springer, ScienceDirect, USENIX, JMLR, TMLR, and conference or author-hosted primary pages;
- official project repositories and official benchmark announcements when they were the primary public artifact;
- backward and forward terminology expansion from an updated systematic literature review.

Search-result snippets were used only for discovery. They were not treated as evidence unless the corresponding primary record was opened and its relevant claim verified. One MANDO-LLM entry is explicitly limited to publisher metadata and abstract-level information because the full primary text was not available in the reviewed public surface.

## Exact query log

The following queries were executed on `2026-08-01`:

1. `site:arxiv.org smart contract vulnerability benchmark temporal split leakage dataset clones MANDO-LLM SmartBugs`
2. `site:dl.acm.org smart contract vulnerability dataset benchmark SmartBugs SolidiFI DAppSCAN MANDO`
3. `site:github.com smart contract vulnerability benchmark dataset SmartBugs Wild DAppSCAN MANDO-LLM`
4. `smart contract vulnerability detection benchmark historical chain state prospective evaluation executable exploit replay paper`
5. `MANDO-LLM smart contract vulnerability detection paper arxiv official repository`
6. `SmartBugs framework empirical analysis smart contract security tools ICSE 2020 DOI`
7. `SolidiFI automated bug injection smart contracts benchmark ICSE official paper`
8. `DAppSCAN smart contract dataset official paper arxiv`
9. `smart contract clone detection dataset benchmark source bytecode clones paper arxiv`
10. `smart contract vulnerability dataset temporal split train test leakage duplicates clones paper`
11. `smart contract security benchmark post knowledge cutoff exploit benchmark official paper EVMbench SCONE`
12. `smart contract vulnerability benchmark prospective shadow deployment calibration abstention selective prediction`
13. `"When datasets deceive: Exposing overlap in smart contract vulnerability detection" DOI authors`
14. `site:arxiv.org "When datasets deceive" smart contract`
15. `"CyberChainBench" arxiv 2606.26216`
16. `site:arxiv.org smart contract benchmark historical blockchain state real incidents exploit replay 2026`
17. `smart contract vulnerability right-censored contracts survival analysis exploit prediction`
18. `blockchain smart contract exploit prediction survival analysis time-to-event vulnerability`
19. `selective prediction abstention calibration security vulnerability detection benchmark workload`
20. `security vulnerability detection realistic base rates false positives analyst workload benchmark paper`
21. `"Dos and Don'ts of Machine Learning in Computer Security" USENIX Security 2022 DOI authors`
22. `site:usenix.org "Dos and Don'ts of Machine Learning in Computer Security"`
23. `"Machine Learning in Computer Security" pitfalls base rate false positives paper 2022`
24. `selective classification risk coverage benchmark Geifman El-Yaniv 2017 paper`

## Screening contract

### Include

A source was included when it provided direct evidence for at least one of these surfaces:

- `S1` real smart-contract incidents, audit findings, or deployed-contract corpora;
- `S2` executable exploit, invariant, counterexample, or chain-state grading;
- `S3` temporal or post-knowledge-cutoff evaluation;
- `S4` protocol, entity, source-code, bytecode, proxy, attacker, or clone-family separation;
- `S5` exploit-mechanism or root-cause family treatment;
- `S6` realistic negatives, open-world status, follow-up, censoring, or surveillance framing;
- `S7` calibration, abstention, precision-coverage, alert budget, analyst workload, or base-rate evaluation;
- `S8` frozen prospective or sealed shadow evaluation;
- `S9` reproducible benchmark provenance, historical state, containers, or independent replication support.

### Exclude

- unverified marketing claims, reposts, aggregators, social posts, and search snippets without a reviewed primary record;
- detector papers with no material benchmark or evaluation-method contribution;
- generic blockchain vulnerability surveys that did not inform the strongest-predecessor comparison;
- sources for which authorship, identifier, or substantive claim could not be verified;
- operational security instructions or live-target testing, which are outside the authorized public-source research boundary.

## Screening and extraction procedure

1. Discover candidate records with the exact query log.
2. Open the primary paper, proceedings page, official repository, or official benchmark page.
3. Verify title, year, identifier, study population, and the exact evaluation control relevant to ChronosAudit.
4. Record the strongest overlap and the controls that remain absent or unverified.
5. Give greatest novelty-defeating weight to a source that already combines multiple ChronosAudit surfaces, rather than to a source that merely mentions one component.
6. Preserve access limitations and avoid upgrading abstract- or metadata-level evidence.
7. Treat absence from this bounded search as residual uncertainty, not proof of novelty.

## Strongest partial predecessors identified

### Historical incident and executable-evidence axis

- **CyberChainBench** is the strongest located historical-execution predecessor: it uses hundreds of real incidents across multiple EVM chains, block-anchored historical forks, and executable exploit or proxy-patch grading.
- **EVMbench** supplies real audited repositories and programmatic detect/patch/exploit grading.
- **SCONE-bench** supplies real-world vulnerable contracts, local execution, and a post-knowledge-cutoff subset.

These works materially narrow any claim that ChronosAudit is the first real-incident, historical-state, or executable smart-contract benchmark.

### Temporal and scaffold-control axis

- **Re-Evaluating EVMbench** directly tests a post-model-release incident set and shows that scaffold choice materially changes apparent capability.

This defeats any broad claim that post-cutoff evaluation or scaffold sensitivity is novel by itself.

### Clone and dataset-overlap axis

- **When Datasets Deceive** reports substantial train-test function overlap in smart-contract vulnerability data and constructs a zero-function-overlap evaluation.
- **Clone Detection for Smart Contracts: How Far Are We?**, the semantic-clone benchmark, and Ethereum clone-characterization studies demonstrate that clone-family construction is a mature and technically nontrivial problem.

These works defeat any claim that clone leakage in smart-contract evaluation is newly recognized.

### Population and operational-evaluation axis

- **Vulnerable Does Not Imply Exploited** directly distinguishes tool-flagged vulnerability from observed exploitation and demonstrates the low realized-exploitation fraction in its historical population.
- General security-ML methodology identifies temporal snooping, data snooping, base-rate errors, and inappropriate metrics.
- Selective-classification literature provides established risk-coverage and calibrated-abstention methods.

These works defeat any claim that open-world status, base rates, or selective prediction are new concepts. The bounded search did not identify a smart-contract benchmark that operationalizes unresolved contracts as right-censored observations and combines that treatment with the full joint independence policy.

## Preliminary feature-bundle comparison

No reviewed source was verified as jointly implementing all of the following in one benchmark protocol:

1. prediction-time, machine-verifiable information admissibility;
2. simultaneous temporal, protocol/entity-lineage, normalized source/bytecode clone, proxy-family, attacker-clone, and exploit-mechanism separation;
3. confirmed-positive, mature-negative, and unresolved right-censored population states;
4. executable evidence grading;
5. a contamination-control performance-survival ladder;
6. calibrated abstention and workload at realistic base rates; and
7. a frozen sealed prospective shadow deployment.

That bounded negative finding supports only a hypothesis of a potentially differentiating *joint protocol*. It does not establish novelty of the individual components, and it does not yet establish that the joint bundle is scientifically coherent or feasible.

## Access limits and residual search risk

- No subscription-only Scopus or Web of Science index was available.
- Patent and standards searches were not completed; this is a material gap for universal novelty claims.
- Citation chaining was bounded and not an exhaustive forward-citation graph.
- Some recent 2026 records were available only as preprints or publisher metadata and require later version checks.
- MANDO-LLM was verified only at metadata and abstract level in the accessible publisher surface.
- No private audit corpus, proprietary benchmark, embargoed paper, or nonpublic incident database was searched.
- The search did not verify a prior sealed prospective smart-contract shadow deployment, but absence in these sources is not proof that none exists.
- Terminology may differ across security surveillance, exploit forecasting, incident prediction, clone detection, and benchmark contamination literatures.

The independent citation challenge must therefore test the strongest joint-protocol claim, extend terminology and patent/standards coverage if possible, and downgrade or reframe the claim if a closer predecessor is found.

## Attempt-2 targeted extension

The `NOVELTY_UNRESOLVED` loop reopened this phase. On `2026-08-01`, the search was extended only across the gaps named by the first audit; the original query log and evidence were preserved.

### Additional exact queries

25. `smart contract exploit prediction survival analysis right censored vulnerability benchmark`
26. `smart contract vulnerability detection positive unlabeled delayed labels open world evaluation`
27. `smart contract vulnerability benchmark protocol lineage proxy family attacker contract clone split`
28. `smart contract security prospective shadow deployment frozen model benchmark`
29. `FinSurvival benchmark DeFi survival analysis arxiv Seneviratne 2026`
30. `site:arxiv.org DeFi survival analysis benchmark right censoring 2026`
31. `site:patents.google.com smart contract vulnerability detection benchmark temporal`
32. `site:patents.google.com smart contract exploit prediction machine learning`

### Material findings

1. **SCONE is a closer prospective predecessor than recorded in attempt 1.** Its official report states that, on October 3, 2025, two frozen contemporary agents were evaluated in simulation against 2,849 recently deployed contracts without known vulnerabilities. The experiment found two previously unknown vulnerabilities, recorded cost and simulated revenue, contacted developers where possible, and coordinated asset rescue through a security partner. This defeats novelty of a one-time recent-contract zero-day scan, simulated profitable-exploit evidence, cost-per-alert-style accounting, and responsible-disclosure coordination. It does not verify a longitudinal preregistered cohort, joint lineage/clone/mechanism independence, right-censor-aware population inference, frozen retrieval and thresholds over follow-up, or independent outcome adjudication.
2. **FinSurvival defeats novelty of right-censored Web3 benchmarking.** The 2025 benchmark derives sixteen time-to-event tasks from public DeFi lending transactions, and the 2026 challenge paper explicitly frames censoring and non-stationarity as temporal Web3 benchmark requirements. These works are not smart-contract exploit-discovery benchmarks, but they make right-censor-aware Web3 evaluation an established adjacent method rather than a new ChronosAudit ingredient.
3. **Patent coverage found adjacent smart-contract and general exploit-prediction claims.** `CN110737899A` filters smart-contract source-code samples using a code-content duplication threshold before training a vulnerability detector. `US20210312472A1` describes state-space-based smart-contract violation prediction and alerting; the checked record does **not** establish a machine-learning method. General exploit-prediction patents such as `WO2018022321A1` predict exploitation likelihood using historical vulnerability information, an ensemble, thresholds, and periodic retraining. None of the reviewed patent records was verified to claim the complete ChronosAudit benchmark protocol, but patents materially narrow novelty language around duplicate filtering, state-transition prediction, and exploit forecasting.
4. **Delayed-label evaluation is established in adjacent security ML.** The targeted search located malware-pipeline work explicitly measuring evaluation distortion from delayed labels and finite analysis queues. This supports the operational motivation but weakens any broad novelty claim for delayed or unresolved labels in security evaluation.
5. **No targeted result verified the full joint bundle.** In particular, no reviewed source jointly required prediction-time admissibility manifests; temporal, protocol/entity, source/bytecode/proxy/attacker/mechanism independence; right-censored exploit outcomes; a prespecified performance-survival ladder; calibrated analyst workload; and a sealed longitudinal prospective shadow cohort.

### Attempt-2 scope correction

The supportable novelty hypothesis must be narrowed from “censor-aware evaluation plus prospective shadow deployment” to the *measured interaction* of:

- joint prediction-time contamination controls;
- exploit-specific open-population status;
- a prespecified capability-survival ladder; and
- a longitudinal sealed operational study whose freeze and adjudication contract exceeds SCONE's documented one-time recent-contract experiment.

Component novelty remains defeated. The targeted extension still cannot prove universal absence, and an independent citation challenge remains required.

### Updated residual limits

- Patent coverage is now targeted but not exhaustive across jurisdictions, families, prosecution history, or non-English claims.
- Standards coverage found the OWASP Smart Contract Top 10 treatment of proxy and upgradeability vulnerabilities, but no benchmark-independence standard; a broader standards-body review remains open.
- FinSurvival and the SCONE official report must be included in the decision-bearing predecessor challenge.
- Proprietary security-vendor shadow deployments and confidential audit workflows remain outside accessible evidence.

## Attempt 3 — targeted remediation search

The attempt-2 independent citation challenge found a material overclaim in `PA029`, metadata defects, and four remaining evidence gaps: standards, patent-family adjacency, alternative terminology, and inaccessible proprietary deployments. On `2026-08-01`, the public search was extended only across the first three. Proprietary evidence remained outside the authorized and accessible boundary and is retained as an explicit residual limitation.

### Additional exact queries

33. `site:scs.owasp.org Smart Contract Security Verification Standard proxy upgradeability benchmark`
34. `site:entethalliance.org smart contract security levels specification EthTrust PDF`
35. `smart contract vulnerability benchmark delayed labels open population evaluation exploit prediction`
36. `smart contract exploit campaign clustering attacker contract clone trace reuse benchmark`
37. `site:arxiv.org smart contract exploit campaign clustering attacker addresses contracts clone`
38. `site:dl.acm.org smart contract attacker contract clone exploit campaign`
39. `site:usenix.org smart contract exploit campaign clustering transaction traces`
40. `site:first.org EPSS model specification delayed label exploit prediction probability 30 days`
41. `"When Datasets Deceive" smart contract vulnerability detection pdf`

### Corrective findings

1. **`PA029` was materially overstated and is corrected.** The patent describes control-flow graphs, blockchain-variable state, dynamic state-space-tree updates, checks against predefined violation requirements, and alert generation. It does not establish machine learning. The ledger and novelty matrix now treat it only as state-transition/state-space violation-prediction precedent.
2. **Standards defeat several checklist-level novelty claims.** OWASP SCSVS defines smart-contract verification controls, including proxy and upgrade-management requirements. EEA EthTrust Security Levels v3 defines tiered baseline audit requirements. Neither is a predictive benchmark or supplies the ChronosAudit independence, censoring, capability-survival, or prospective-study contract.
3. **Attacker and campaign dependence are established phenomena.** BlockWatchdog analyzes attacker-contract logic and cross-contract call chains. *Evil Under the Sun* documents exploit-contract reuse, propagation to similar DApps, campaign structure, and transaction clustering by execution-trace similarity and time. ChronosAudit therefore cannot claim novelty for recognizing attacker contracts, exploit reuse, or campaign dependence; its narrower hypothesis is that explicit attacker-family separation materially changes estimated pre-incident detector performance.
4. **Operational exploit prediction and workload prioritization are established outside smart contracts.** FIRST EPSS issues daily, prediction-time probabilities for exploitation activity in the following 30 days and exposes historical model outputs and prioritization trade-offs. This defeats broad novelty claims for pre-outcome exploit prediction, rolling operational scoring, low-base-rate prioritization, or time-indexed feature discipline.
5. **The function-overlap predecessor remains abstract-verified.** The accessible publisher abstract for `PA014` explicitly reports over 34% train-test function overlap and a zero-function-overlap benchmark. The full methods and dataset definitions were not independently accessible, so the record is retained at `E1` and used only to defeat component-level claims.
6. **No public source located in the bounded extension implements the full joint protocol.** The strongest composite objection is now SCONE + Re-Evaluating EVMBench + function/semantic-clone work + FinSurvival + EPSS + OWASP/EEA standards + attacker/campaign analysis. The remaining possible contribution is the measured interaction of all controls, not any individual ingredient.

### Attempt-3 residual limits

- Patent review remains targeted rather than a legal freedom-to-operate search: families, non-English claims, prosecution history, claim construction, and all jurisdictions were not exhaustively reviewed.
- Standards coverage now includes OWASP SCSVS and EEA EthTrust Security Levels v3. No checked standard was a contamination-controlled predictive benchmark, but this cannot prove that no other public or private governance protocol exists.
- `PA014` is supported at publisher-abstract level only; full-text construction details remain unavailable in the bounded public surface.
- Proprietary vendor deployments, confidential audit workflows, private incident corpora, and embargoed studies remain inaccessible and are explicitly excluded from any universal first-of-kind claim.
- The only defensible novelty formulation is evidence-bounded: within the documented public search, no single predecessor was verified to combine machine-verifiable prediction-time admissibility; temporal, lineage, source/bytecode/proxy/attacker/mechanism independence; exploit-specific right-censoring; a capability-survival ladder; calibrated workload-aware abstention; and a longitudinal sealed cohort with independent adjudication.

## Attempt 4 — correction-only closure

No new discovery query was run. The independent attempt-3 audit identified three ledger defects and requested a correction-only recheck:

1. `S8` was removed from `PA031` because OWASP SCSVS is a verification standard, not prospective evidence.
2. `S8` was removed from `PA032` because EEA EthTrust defines tiered audit assurance, not a prospective study.
3. `PA033` now uses the live official FIRST EPSS landing page and is limited to claims directly supported there: daily 0–1 probabilities of exploitation activity in the next 30 days, open data, and prioritization use. The unsupported historical-version wording was removed.

The attempt-3 audit's other restrictions remain binding: `PA014` stays abstract-only `E1`; `PA028` inventor romanization remains non-publication-grade; patents remain targeted rather than family-complete; and inaccessible proprietary deployments remain a residual limit rather than positive novelty evidence.

## Attempt 7 — independently owned canonical recovery challenge

The user authorized a materially different public-data-only novelty recovery on
`2026-08-01`; archive and RPC testing remained explicitly excluded. After a
failed broad delegated search was preserved as `CP-57947071f7cd`, an
independent search owner executed the smaller frozen contract recorded in
`independent-search-challenge.md` under `LEASE-0efb9a5c257c`.

The independent challenge executed five exact scholarly/patent queries and one
standards traversal. Because the public-search interface exposed ranked
snippets but not corpus totals, every result count is recorded as
`UNAVAILABLE`; visible screened and retained counts, exclusions, known-item
recoveries, and citation/author traversals are preserved in the challenge
artifact rather than inferred retrospectively.

The challenge recovered and reconciled `EVMbench`, `SCONE-bench`,
`CyberChainBench`, `When Datasets Deceive`, `FinSurvival`, `EPSS`, OWASP
SCSVS, ERC-1167, `SCDBench`, and `SC-Bench` against `PA010`, `PA012`,
`PA013`, `PA014`, `PA026`, `PA027`, `PA031`, `PA033`, `PA038`, `PA039`, and
`PA040`. It found no new source requiring a ledger row and did not verify a
single equivalent joint protocol.

The independent outcome is `NOVELTY_UNRESOLVED`, not `NOVELTY_SURVIVES`:

- every major ingredient has a strong public predecessor;
- the obvious-recombination objection remains live;
- the bounded search did not establish that the joint bundle produces a
  nonredundant scientific or decision consequence;
- exact queries A7Q2, A7Q3, and A7Q5 produced no direct predecessor from
  their exact phrasing;
- `PA014` remained metadata/abstract-bounded in the accessible public
  surface;
- citation saturation, formal correction/retraction coverage, patent-family
  and non-English coverage, subscription indexes, and proprietary/private
  protocols remain incomplete.

The full-file SHA-256 of the independently owned challenge is
`ab58cf4f3d3f2192a6d640a7d24867e42d316869af63871043580e3d2551fccc`.
Root independently recomputed that hash and checked the named primary or
official URLs before canonical registration. No archive/RPC evidence was
collected or used.

## Attempt 8 — measurement-claim exact-match audit

The user narrowed `C001` before search to the capability-survival measurement
claim frozen in `novelty-claim-specification.md`. A distinct owner attempted a
bounded four-scholarly-query plus one-patent-query exact-match audit. The first
execution exhausted its context without producing evidence; checkpoint
`CP-e399c6186a58` preserves that failure. The retry produced the append-only
Attempt-8 section in `independent-search-challenge.md`, hash
`d73eb3f3ad641c4323ceb59809c791669e153ce0267d39af05ab6e55432dc5b0`.

The retry recovered EVMbench, Re-Evaluating EVMbench, When Datasets Deceive,
CyberChainBench, and SCONE, but did not recover FinSurvival within the bounded
query pass. It also omitted per-query UTC timestamps, counts or explicit
`UNAVAILABLE`, screened and retained counts, exclusion decisions, and an
explicit pre-ledger freeze event. One of the two closest-work traversals was
incomplete. Independent verification therefore failed the full search contract
but verified the artifact as faithful incomplete negative evidence.

The recovery stop rule triggered. No further autonomous search retry is
permitted under this authorization. The attempt-8 outcome is
`NOVELTY_UNRESOLVED` for `C001-MEASUREMENT`: no equivalent single predecessor
was verified, but the bounded search is not complete enough to support
`NOVELTY_SURVIVES`. Archive/RPC access was not used.
