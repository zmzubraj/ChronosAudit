# Research Program Charter

## Identity

- System: ChronosAudit
- Research topic: ChronosAudit: Leakage-Audited Prospective Benchmarking of Pre-Incident Smart-Contract Exploit Discovery
- Target venue/article type: UNDECIDED
- Program owner: root integration owner
- Accountable human decision authority: The requesting user retains final authority for scope, any institutional or legal approvals, release of nonpublic security information, prospective deployment, and submission. Identity and institutional capacity are not independently verified.
- Confidentiality class: PUBLIC-RESEARCH-ONLY for the present program. No confidential exploit reports, private keys, embargoed vulnerabilities, participant data, proprietary datasets, or export-controlled material are authorized inputs.
- External-processing permission: AUTHORIZED FOR PUBLIC SOURCES ONLY. Nonpublic vulnerability details, live target data, proprietary artifacts, and sealed prospective predictions may not be sent to external services without separate explicit informed authorization.

## User-asserted starting contract

These items are intake assertions (`E1 ASSERTED`), not verified novelty, feasibility, or evidence.

- Core research question: Under a preregistered and machine-verifiable information-admissibility policy, how much apparent smart-contract exploit-detection performance survives joint separation by deployment time, protocol lineage, normalized code-clone family and exploit mechanism, and what calibrated precision–coverage–workload trade-off can be sustained in a sealed prospective deployment?
- Novelty statement: Recent smart-contract security benchmarks increasingly offer real incidents, executable grading, historical chain state or post-cutoff evaluation. Those controls do not, by themselves, establish independence from protocol lineage, source and bytecode clones, previously observed exploit mechanisms, indirect model contamination or unrealistic negative sampling. ChronosAudit introduces a continuously versioned, machine-verifiable information-admissibility protocol that jointly enforces temporal, protocol-family, code-clone and exploit-mechanism separation; models unresolved contracts as right-censored observations; evaluates calibrated abstention and analyst workload under realistic base rates; and culminates in a frozen, sealed prospective shadow deployment. The central contribution is not another detector, but an auditable method for determining which apparent exploit-detection capabilities survive contamination control and remain operationally useful. This deliberately measures capability survival rather than assuming that unknown-exploit detection has already been achieved, making the research question falsifiable, operationally relevant and valuable even if the result is negative.
- Target contribution: A versioned pre-incident smart-contract security benchmark and auditable evaluation methodology comprising:
- Immutable case-level provenance, historical chain-state snapshots and a machine-readable information-admissibility manifest for every case and prediction time.
- A joint contamination-control protocol separating deployment time, protocol and entity lineage, normalized source and bytecode clones, proxy implementation families, attacker-contract clones and exploit-mechanism families.
- A censor-aware population-evaluation framework that distinguishes confirmed positives, mature investigated negatives and unresolved right-censored contracts.
- An executable evidence framework grading evidence from profitable exploit replay through invariant violations, symbolic or fuzzing counterexamples and static causal paths.
- A performance-survival study showing performance decay across a split ladder from random cross-validation to joint independence control and sealed prospective testing.
- Calibrated selective prediction covering abstention, precision–coverage, reliability, alert budgets, analyst workload and cost-sensitive false-positive evaluation.
- A frozen prospective shadow study with a preregistered cohort, frozen model, scaffold, retrieval process and thresholds, responsible-disclosure procedures and independent adjudication.
- A reproducibility package containing containers, dataset cards, case-level provenance, exclusion reports, model cards and an independent replication protocol.
- Possible feasibility: The overall assessment is CONDITIONAL GO. The research-design feasibility is high because the central contribution is a protocol, benchmark and measurement study rather than a requirement to invent a breakthrough detector; its critical dependency is a formal and reproducible definition of admissibility, clone lineage and exploit-mechanism families. Data-construction feasibility is medium because historical chain state, public incident records and open-source analysis tools support a staged corpus; critical dependencies include trustworthy provenance timestamps, proxy resolution, archival-chain access, label adjudication and data rights. Reference-auditor feasibility is medium–high because MANDO-LLM can serve as an existing structural baseline and first-stage ranker, reducing the need to construct every component from zero; this depends on reliable reproduction, a stable adapter interface and fair frozen-model evaluation. Prospective-study feasibility is medium because a shadow deployment is operationally possible without publicly exposing exploit details; it requires sufficient follow-up time, an adequate incident rate, a responsible-disclosure partner and independent evaluators. Top-tier novelty is conditional because the unified evaluation protocol appears differentiated from detector-centric work, but requires reproducible evidence that no prior benchmark jointly implements the complete protocol. A minimum benchmark-science paper appears achievable before a full production auditor, provided the project maintains benchmark-first scope discipline and preregisters explicit progression and stop conditions. Available resources include public incident records, historical chain data, archival-node access where obtainable, open-source smart-contract analysis tools, reproducible compute containers and an existing MANDO-LLM baseline. Remaining constraints include data rights, provenance quality, compute and archival-access costs, specialist expertise, independent adjudication, disclosure coordination, follow-up duration and any required institutional, legal or ethics approvals.
- External or real-world validation requirement: REQUIRED for any claim about sustained operational usefulness, generalization, or prospective capability; otherwise the claim must be narrowed to retrospective benchmark methodology.
- Exploratory versus confirmatory analysis boundary: To be frozen in the study protocol before any confirmatory dataset is opened. Current novelty and feasibility work is design-stage evidence gathering, not empirical performance analysis.
- Feasibility-pilot status and authority: NOT AUTHORIZED. A pilot may be designed, but execution requires a frozen plan, public-data or separately approved inputs, resource confirmation, and explicit progression criteria.

## Authorized reframed novelty claim — attempt 8

The accountable user authority authorized the following narrower `C001`
novelty hypothesis on `2026-08-01T21:00:00Z`:

> A preregistered measurement study testing how much apparent exploit-detection
> capability survives the joint application of temporal, lineage, clone-family,
> mechanism-family, censoring, and operational-workload controls.

This supersedes the broader joint-protocol novelty hypothesis for all attempt-8
search and gate decisions. It does not claim that any individual control is new,
that ChronosAudit is the first smart-contract benchmark with real incidents or
prospective evaluation, or that the later sealed shadow deployment is itself
novel. The claimed differentiator is the prespecified *capability-survival
measurement estimand* and the decision consequence of applying the controls
jointly. Archive and RPC testing are outside the authorization for this attempt.

## Claim ladder

| Claim ID | Exact claim | Type | Required evidence | Current evidence | Stage | Falsifier | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C001 | A preregistered measurement study testing how much apparent exploit-detection capability survives the joint application of temporal, lineage, clone-family, mechanism-family, censoring, and operational-workload controls. | novelty hypothesis | frozen estimand and control ladder; bounded exact-match prior-art audit; evidence that the joint measurement produces a nonredundant scientific or operational decision consequence | E1 ASSERTED; authorized reframe | UNRESOLVED | a credible predecessor that prespecifies and measures an equivalent joint capability-survival/degradation estimand, or evidence that only implementation, packaging, or scale differs | novelty_synthesis |
| C002 | The overall assessment is CONDITIONAL GO. The research-design feasibility is high because the central contribution is a protocol, benchmark and measurement study rather than a requirement to invent a breakthrough detector; its critical dependency is a formal and reproducible definition of admissibility, clone lineage and exploit-mechanism families. Data-construction feasibility is medium because historical chain state, public incident records and open-source analysis tools support a staged corpus; critical dependencies include trustworthy provenance timestamps, proxy resolution, archival-chain access, label adjudication and data rights. Reference-auditor feasibility is medium–high because MANDO-LLM can serve as an existing structural baseline and first-stage ranker, reducing the need to construct every component from zero; this depends on reliable reproduction, a stable adapter interface and fair frozen-model evaluation. Prospective-study feasibility is medium because a shadow deployment is operationally possible without publicly exposing exploit details; it requires sufficient follow-up time, an adequate incident rate, a responsible-disclosure partner and independent evaluators. Top-tier novelty is conditional because the unified evaluation protocol appears differentiated from detector-centric work, but requires reproducible evidence that no prior benchmark jointly implements the complete protocol. A minimum benchmark-science paper appears achievable before a full production auditor, provided the project maintains benchmark-first scope discipline and preregisters explicit progression and stop conditions. Available resources include public incident records, historical chain data, archival-node access where obtainable, open-source smart-contract analysis tools, reproducible compute containers and an existing MANDO-LLM baseline. Remaining constraints include data rights, provenance quality, compute and archival-access costs, specialist expertise, independent adjudication, disclosure coordination, follow-up duration and any required institutional, legal or ethics approvals. | feasibility hypothesis | access, resource, safety, ethics, validity, and pilot evidence | E1 ASSERTED | UNRESOLVED | a blocking feasibility gate | feasibility_science |

## Authority, safety, and execution bounds

- Ethics or IRB status: Public-document novelty research is not human-subjects research on the available facts. Any analyst study, private disclosure workflow, partner data, or prospective intervention requires institutional determination before execution.
- Consent status: Not applicable to public-document review; unresolved for analyst workload studies or partner-supplied data.
- Data rights and privacy status: Public-source metadata review is authorized. Dataset redistribution, archival-node terms, proprietary labels, and private incident material require a source-by-source rights ledger before collection or release.
- Safety, biosafety, security, or dual-use status: Cybersecurity dual-use risk is material. The program may analyze public methods and benchmark governance, but may not publish live exploit recipes, target-specific actionable vulnerabilities, private keys, or uncoordinated zero-day details.
- Legal or regulatory status: Public scholarly research is permitted within the current scope; automated collection, sanctions/export-control exposure, contractual data restrictions, and responsible-disclosure obligations remain unresolved until assessed for the chosen sources and jurisdictions.
- Required qualified experts: Smart-contract security researcher; benchmark/data-governance lead; statistician familiar with censoring and selective prediction; responsible-disclosure partner; independent adjudicators; and institutional/legal review where triggered.
- Irreversible collection, recruitment, intervention, scraping, procurement, or external sharing: NOT AUTHORIZED

## Zero-interaction safe-route disposition — 2026-08-02

Recovery `REC-7601a088ae72` abandons, but does not resolve, the external-verifier and institutional-authority route for this autonomous delivery. The deliverable is narrowed to a public-evidence methods and preregistration draft centered on the retrospective `C001-MEASUREMENT` capability-survival estimand.

- Novelty remains `UNRESOLVED`.
- Feasibility remains `PILOT_FIRST`; this document does not authorize `STUDY_DESIGN` promotion.
- Detector performance, precision, coverage, calibration, workload, and cost results are `NOT RUN`.
- Archive/RPC access, live-target testing, private vulnerability handling, analyst-participant research, disclosure operations, sealed prospective deployment, and submission remain excluded.
- Draft protocol, manuscript, audit, and human-review artifacts may be produced for accountable review, but they remain nonfinal and cannot substitute for externally rooted scientific verification, institutional authority, or empirical evidence.
