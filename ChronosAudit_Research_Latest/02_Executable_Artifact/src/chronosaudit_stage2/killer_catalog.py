from __future__ import annotations

from typing import Any


def comprehensive_killer_questions(stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the frozen 100-question Stage 2A-2E adversarial audit.

    Final statuses distinguish controls that were actually executed (PASS), controls
    implemented and tested in the workflow but awaiting real evidence
    (PASS_BY_DESIGN), partial public evidence (PARTIAL), and external evidence gates
    that cannot be truthfully closed in the current environment (BLOCKED).
    """
    rows: list[dict[str, Any]] = []

    def add(
        stage: str,
        category: str,
        question: str,
        initial: str,
        action: str,
        final: str,
        evidence: str,
        owner: str,
    ) -> None:
        rows.append(
            {
                "question_id": f"{stage}-KQ-{sum(1 for r in rows if r['stage'] == stage) + 1:02d}",
                "stage": stage,
                "category": category,
                "killer_question": question,
                "initial_status": initial,
                "fix_or_control": action,
                "final_status": final,
                "required_or_produced_evidence": evidence,
                "blocking_owner": owner,
            }
        )

    # Stage 2A - temporal/provenance admissibility (20)
    add("2A", "chronology", "Is the deployment transaction independently known for every retained case?", "UNRESOLVED", "Add archive/indexer deployment-transaction resolver with provider consensus.", "BLOCKED", "Deployment transaction hash, block number, timestamp, and two-source corroboration.", "data-operations")
    add("2A", "chronology", "Is the deployment block earlier than the prediction cutoff?", "UNCONTROLLED", "Encode deploy < cutoff as a mandatory fail-closed predicate.", "PASS_BY_DESIGN", "Schema predicate and exclusion reason code; real values still required.", "pipeline")
    add("2A", "chronology", "Is the incident block or timestamp independently corroborated?", "UNRESOLVED", "Seed public incident dates and require attack-transaction or second-source confirmation.", "PARTIAL", "417/417 incident dates recovered from frozen hashed DeFiHackLabs history; 60 cases include transaction-hash hints; independent second-source/receipt corroboration remains required.", "data-operations")
    add("2A", "chronology", "Is the cutoff strictly earlier than the incident and all prohibited disclosures?", "UNCONTROLLED", "Freeze a case-specific cutoff after chronology reconstruction and test ordering.", "PASS_BY_DESIGN", "Cutoff-order predicate implemented; case values unavailable.", "pipeline")
    add("2A", "chronology", "Is the meaning of prediction cutoff consistent across all cases?", "AMBIGUOUS", "Freeze cutoff policy: latest finalized block before first incident transaction, with sensitivity windows.", "PASS_BY_DESIGN", "Versioned cutoff policy YAML.", "methodology")
    add("2A", "source availability", "Is the first defensible public availability time of verified source code known?", "MISSING", "Implement explorer-history, repository-commit, and archival-snapshot adapters.", "BLOCKED", "First-publication timestamp plus source snapshot hash.", "data-operations")
    add("2A", "bytecode availability", "Is runtime bytecode available at the exact cutoff block?", "MISSING", "Query eth_getCode at historical block from two archive providers.", "BLOCKED", "Provider responses, block hash, bytecode hash, and consensus result.", "data-operations")
    add("2A", "provenance", "Does every local input and generated output have a cryptographic content hash?", "PARTIAL", "Hash both raw sources and all append-only registry records.", "PASS", "SHA-256 source hashes and 1,264-record valid hash chain.", "pipeline")
    add("2A", "provenance", "Are retrieval query, endpoint, response time, and provider identity retained?", "NOT_RECORDED", "Define provider-observation records and append-only query logs.", "PASS_BY_DESIGN", "Provider observation schema and on-chain query queue.", "pipeline")
    add("2A", "provider disagreement", "Are conflicting provider observations preserved rather than overwritten?", "RISK", "Store every observation and require explicit consensus/adjudication status.", "PASS_BY_DESIGN", "Multi-provider evidence model; external observations pending.", "pipeline")
    add("2A", "chain finality", "Are chain reorganizations and block finality handled before evidence is frozen?", "NOT_SPECIFIED", "Add chain-specific finality depths and block-hash pinning.", "PASS_BY_DESIGN", "Policy fields defined; live chain exercise pending.", "production")
    add("2A", "timestamp integrity", "Are timestamps normalized to UTC and checked against canonical block timestamps?", "UNCONTROLLED", "Normalize to UTC and validate date/block consistency.", "PASS_BY_DESIGN", "Normalization rule; real block timestamps pending.", "pipeline")
    add("2A", "information separation", "Can post-incident reports, exploit writeups, or later labels enter detector-visible inputs?", "LEAKAGE_RISK", "Separate detector and evaluator planes and deny later artifacts to detector adapters.", "PASS_BY_DESIGN", "Separate schemas, release fields, and access policy.", "pipeline")
    add("2A", "legal provenance", "Are license, terms-of-use, and redistribution permissions recorded per artifact?", "MISSING", "Create artifact-level rights ledger and legal review state.", "PASS", "Rights ledger records the redistributed SCONE-bench and DeFiHackLabs inputs as Apache-2.0 and keeps future service-response rights as explicit per-retrieval gates.", "governance")
    add("2A", "immutability", "Are evidence versions immutable and superseded rather than edited in place?", "MUTATION_RISK", "Use append-only SQLite records protected by update/delete triggers.", "PASS", "Delete/update attempts blocked; registry chain verified.", "pipeline")
    add("2A", "independent reproduction", "Can an independent reviewer reconstruct at least 10% of timelines?", "NOT_TESTED", "Prepare blinded re-retrieval package and discrepancy protocol.", "BLOCKED", "Independent timeline-reconstruction report.", "external-review")
    add("2A", "missing evidence", "Does any missing mandatory field result in exclusion rather than imputation?", "SILENT_IMPUTATION_RISK", "Encode mandatory fields and machine-readable reason codes.", "PASS", "417/417 cases fail closed; no case falsely certified.", "pipeline")
    add("2A", "source identity", "Can a source row be traced to its exact upstream dataset version?", "PARTIAL", "Record upstream URL, retrieval date, and source SHA-256.", "PASS", "SCONE cohort plus six frozen DeFiHackLabs snapshots and 417 incident records are content-hashed and provenance-linked.", "pipeline")
    add("2A", "sensitivity", "Will conclusions be stable to alternate cutoff windows?", "NOT_DEFINED", "Prespecify primary cutoff and -1/-7/-30-day sensitivity windows where meaningful.", "PASS_BY_DESIGN", "Analysis plan; completed timelines required.", "methodology")
    add("2A", "eligibility", "Can a case with only a historical fork block be mislabeled as fully pre-incident admissible?", "MISCLASSIFICATION_RISK", "Treat fork block as an anchor only, never as sufficient chronology.", "PASS", "Zero cases certified from benchmark metadata alone.", "pipeline")

    # Stage 2B - identity, code, proxy, clone lineage (20)
    add("2B", "canonical identity", "Are chain identifiers normalized consistently?", "INCONSISTENT", "Apply frozen chain alias mapping.", "PASS", "417 rows normalized to canonical chain labels.", "pipeline")
    add("2B", "canonical identity", "Are EVM addresses validated and normalized without lossy guessing?", "UNVALIDATED", "Require 20-byte hexadecimal addresses and lowercase canonical form.", "PASS", "All 417 target addresses passed strict validation.", "pipeline")
    add("2B", "duplicates", "Are exact chain-address duplicate families detected?", "UNKNOWN", "Group by canonical chain-address identity.", "PASS", "408 unique identities; 9 duplicate groups containing 18 rows.", "pipeline")
    add("2B", "historical code", "Is runtime bytecode captured at the cutoff, not at present day?", "MISSING", "Historical eth_getCode adapter with block-hash pinning.", "BLOCKED", "Archive RPC responses for 417 cases.", "data-operations")
    add("2B", "code semantics", "Are empty-code, self-destructed, and redeployed addresses distinguished?", "NOT_HANDLED", "Track code presence over time and creation/destruction/redeployment events.", "BLOCKED", "Historical code timeline and creation traces.", "data-operations")
    add("2B", "normalization", "Is Solidity metadata stripped before semantic bytecode hashing?", "NOT_IMPLEMENTED", "Implement metadata trailer parsing and preserve raw plus normalized hashes.", "BLOCKED", "Historical bytecode corpus and parser validation fixtures.", "pipeline")
    add("2B", "compiler provenance", "Are compiler version, optimizer settings, and linked libraries captured when available?", "MISSING", "Enrich from verified-source metadata and compiler artifacts.", "BLOCKED", "Explorer/Sourcify metadata snapshots.", "data-operations")
    add("2B", "proxy lineage", "Are EIP-1967 transparent/UUPS implementation slots resolved at cutoff?", "MISSING", "Historical eth_getStorageAt reads for implementation/admin slots.", "BLOCKED", "Slot values pinned to cutoff block.", "data-operations")
    add("2B", "proxy lineage", "Are beacon proxies resolved through the beacon implementation at cutoff?", "MISSING", "Resolve beacon slot then implementation() at historical state.", "BLOCKED", "Historical beacon and implementation evidence.", "data-operations")
    add("2B", "proxy lineage", "Are EIP-1167 minimal proxies and clones detected?", "MISSING", "Match minimal-proxy bytecode patterns and resolve target implementation.", "BLOCKED", "Runtime bytecode at cutoff.", "pipeline")
    add("2B", "proxy lineage", "Are diamond/facet relationships represented?", "MISSING", "Resolve loupe functions/events and build facet-set identities.", "BLOCKED", "Historical calls, events, and facet code hashes.", "data-operations")
    add("2B", "metamorphic contracts", "Are CREATE2, metamorphic, and address-reuse cases treated as time-indexed identities?", "NOT_HANDLED", "Key code identity by chain, address, and validity interval.", "BLOCKED", "Creation traces and code-history observations.", "data-operations")
    add("2B", "libraries", "Are shared linked libraries represented as dependency edges?", "MISSING", "Parse link references and verified source dependencies.", "BLOCKED", "Compiler metadata and code hashes.", "data-operations")
    add("2B", "implementation history", "Are proxy upgrades between deployment and cutoff reconstructed?", "MISSING", "Replay upgrade events and confirm storage at cutoff.", "BLOCKED", "Event logs plus historical storage consensus.", "data-operations")
    add("2B", "source clones", "Are exact normalized-source clones grouped?", "MISSING_CORPUS", "Canonicalize source bundles and hash normalized AST/text representations.", "BLOCKED", "Verified source snapshots.", "pipeline")
    add("2B", "near clones", "Is the near-clone metric validated for Solidity and frozen before outcome inspection?", "UNFROZEN", "Preregister metric, threshold, and 0.85/0.90/0.95 sensitivity analysis.", "BLOCKED", "Source/bytecode corpus and manual validation sample.", "methodology")
    add("2B", "provider consensus", "Do independent providers agree on cutoff bytecode and storage?", "NOT_TESTED", "Require two observations or explicit disagreement adjudication.", "BLOCKED", "Provider comparison report.", "data-operations")
    add("2B", "fail closed", "Can unresolved proxy or code identity be guessed into a family?", "GUESSING_RISK", "Represent unresolved lineage explicitly and block release eligibility.", "PASS", "All unresolved code/proxy fields remain unresolved; release stays empty.", "pipeline")
    add("2B", "partition integrity", "Does exact-identity grouping eliminate cross-fold leakage?", "LEAKING_BASELINE", "Use deterministic group-aware fold assignment.", "PASS", "Zero exact-identity crossings; balanced folds 84/84/83/83/83.", "pipeline")
    add("2B", "sensitivity", "Will code-family conclusions be rerun across normalization and clone thresholds?", "NOT_DEFINED", "Freeze primary and sensitivity configurations before Stage-2 release.", "PASS_BY_DESIGN", "Policy YAML; code evidence pending.", "methodology")

    # Stage 2C - protocol, mechanism, attacker and review adjudication (20)
    add("2C", "protocol family", "Are protocol-family labels supported by official deployment/governance evidence rather than names alone?", "NAME_HEURISTIC_ONLY", "Dual-review codebook using deployer, governance, repository, and upgrade evidence.", "BLOCKED", "Signed reviewer decisions and source citations.", "external-review")
    add("2C", "organization", "Are organization and protocol identities separated where brands, forks, or operators differ?", "AMBIGUOUS", "Define distinct organization, codebase, and protocol-lineage entities.", "PASS_BY_DESIGN", "Versioned entity ontology; real adjudication pending.", "methodology")
    add("2C", "authority", "Are common deployers, upgrade admins, multisigs, and governance controllers captured?", "MISSING", "Build authority graph from deployment and governance evidence.", "BLOCKED", "On-chain authority records and reviewer validation.", "data-operations")
    add("2C", "mechanism taxonomy", "Are mechanism labels cause-level rather than broad categories such as 'flash loan'?", "TECHNIQUE_LABELS", "Map public labels to a draft cause taxonomy and require root-cause review.", "PARTIAL", "417 preliminary mechanism candidates; 385 map to the frozen candidate taxonomy; independent root-cause review pending.", "external-review")
    add("2C", "cause vs technique", "Are enabling techniques distinguished from the underlying vulnerability?", "CONFLATED", "Store primary root cause, exploit technique, and contributing conditions separately.", "PASS_BY_DESIGN", "Codebook fields defined; reviewer decisions pending.", "methodology")
    add("2C", "multi-mechanism", "Can an incident have one primary cause and multiple contributing mechanisms?", "SINGLE_LABEL_RISK", "Use one primary cause plus ordered secondary contributors.", "PASS_BY_DESIGN", "Adjudication schema.", "pipeline")
    add("2C", "attacker family", "Are attacker-family links evaluator-only and prevented from entering detector inputs?", "LEAKAGE_RISK", "Restrict attacker links to evaluator metadata tables.", "PASS_BY_DESIGN", "Information-plane policy.", "pipeline")
    add("2C", "reviewer independence", "Are two reviewers independent and blind to detector outputs?", "NO_REVIEWERS", "Assign independent reviewers and hide model predictions during labeling.", "BLOCKED", "Reviewer roster, conflicts, and blind-review logs.", "governance")
    add("2C", "conflicts", "Are reviewer conflicts of interest declared and managed?", "NOT_DEFINED", "Add conflict declaration and reassignment rule.", "PASS_BY_DESIGN", "Governance form; reviewers pending.", "governance")
    add("2C", "codebook version", "Is the taxonomy/codebook version frozen before confirmatory analysis?", "UNVERSIONED", "Version and hash the protocol/mechanism codebook.", "PASS_BY_DESIGN", "Codebook version policy; final codebook pending.", "methodology")
    add("2C", "reviewer training", "Are reviewers calibrated on common examples before formal labeling?", "NOT_PLANNED", "Run training set, discussion, then freeze instructions before blinded work.", "PASS_BY_DESIGN", "Training protocol; execution pending.", "external-review")
    add("2C", "agreement", "Does protocol-family agreement meet kappa >= 0.80?", "NOT_MEASURED", "Calculate agreement before adjudication.", "BLOCKED", "Two independent protocol label sets.", "external-review")
    add("2C", "agreement", "Does mechanism-family agreement meet kappa/alpha >= 0.80?", "NOT_MEASURED", "Calculate Cohen kappa or Krippendorff alpha as appropriate.", "BLOCKED", "Two independent mechanism label sets.", "external-review")
    add("2C", "adjudication", "Are disagreements resolved by a third reviewer without overwriting original labels?", "MUTATION_RISK", "Append all decisions and adjudication outcome to immutable registry.", "PASS_BY_DESIGN", "Append-only schema and triggers; adjudications pending.", "pipeline")
    add("2C", "blinded rereview", "Is at least 10% of resolved cases blindly re-reviewed?", "NOT_EXECUTED", "Sample after adjudication using frozen seed.", "BLOCKED", "Blinded re-review report.", "external-review")
    add("2C", "confidence", "Are low-confidence labels excluded from strict family splits?", "LOW_CONFIDENCE_RISK", "Require adjudicated confidence threshold for release eligibility.", "PASS", "Current heuristic candidates cannot enter release cohort.", "pipeline")
    add("2C", "evidence citations", "Does every family assignment cite evidence rather than a reviewer assertion alone?", "NOT_ENFORCED", "Require evidence URI/hash fields in review form.", "PASS_BY_DESIGN", "Adjudication queue schema; evidence pending.", "pipeline")
    add("2C", "taxonomy drift", "Can later taxonomy changes silently alter previous split assignments?", "DRIFT_RISK", "Version taxonomies and rebuild cohorts under explicit versions.", "PASS_BY_DESIGN", "Versioning policy.", "pipeline")
    add("2C", "public labels", "Can public incident 'type' labels be mistaken for verified root causes?", "MISUSE_RISK", "Mark them preliminary and source-specific.", "PASS", "All 417 seeded labels carry single-source/review-required status.", "pipeline")
    add("2C", "release gate", "Can a case enter R5 without completed protocol and mechanism adjudication?", "LEAKAGE_RISK", "Make both adjudications mandatory release gates.", "PASS", "Zero release-eligible cases while adjudication is absent.", "pipeline")

    # Stage 2D - controls, outcomes, censoring, prevalence (20)
    add("2D", "controls", "Does the cohort contain contemporaneous control contracts?", "POSITIVE_ONLY", "Collect matched deployment-time controls from the same chains and periods.", "BLOCKED", "At least 4,170 matched controls under current 10:1 plan.", "data-operations")
    add("2D", "denominator", "Is there a prevalence-preserving deployment-stream denominator?", "NO_DENOMINATOR", "Collect at least 20,000 qualifying deployments.", "BLOCKED", "Versioned deployment stream and inclusion log.", "data-operations")
    add("2D", "temporal matching", "Are controls deployed before or at the positive case cutoff?", "NOT_APPLICABLE_YET", "Match using only deployment-time covariates and cutoff-consistent snapshots.", "PASS_BY_DESIGN", "Matching specification; controls pending.", "methodology")
    add("2D", "matching", "Are matching variables selected without outcome knowledge?", "BIAS_RISK", "Freeze chain, period, code size, proxy status, source verification, activity, and application category.", "PASS_BY_DESIGN", "Control collection manifest.", "methodology")
    add("2D", "negative labels", "Are unexploited contracts automatically labeled safe?", "FALSE_NEGATIVE_RISK", "Preserve unresolved/right-censored states and prohibit universal-safe labels.", "PASS", "Outcome schema and empty control table prevent false negatives.", "pipeline")
    add("2D", "property bounds", "Are negative claims limited to explicitly tested properties?", "NO_PROPERTY_EVIDENCE", "Require property identifier, tool/version, scope, and successful test evidence.", "BLOCKED", "Property-bounded negative records.", "data-operations")
    add("2D", "outcome states", "Are confirmed positive, property-bounded negative, unresolved, censored, and excluded states distinct?", "CONFLATED", "Use a five-state censor-aware outcome model.", "PASS_BY_DESIGN", "Outcome schema; real controls pending.", "pipeline")
    add("2D", "follow-up", "Is the follow-up horizon frozen before outcome inspection?", "UNFROZEN", "Preregister primary horizon and sensitivity horizons.", "BLOCKED", "Dated preregistration before collection.", "methodology")
    add("2D", "observability", "Are outcome-observation sources and last-seen times recorded?", "MISSING", "Add longitudinal observation service and evidence log.", "BLOCKED", "Observation timestamps and source hashes.", "data-operations")
    add("2D", "censoring", "Is the censoring indicator derived reproducibly?", "NOT_DEFINED", "Define C_i(H) from frozen follow-up and observability rules.", "PASS_BY_DESIGN", "Analysis specification; observations pending.", "methodology")
    add("2D", "positivity", "Are IPCW positivity diagnostics prespecified?", "NOT_DEFINED", "Report propensity range, extreme weights, and overlap diagnostics.", "PASS_BY_DESIGN", "Statistical analysis plan.", "methodology")
    add("2D", "weights", "Are stabilized censoring weights fully specified?", "UNDER_SPECIFIED", "Freeze numerator/denominator models and covariates.", "PASS_BY_DESIGN", "Statistical analysis plan.", "methodology")
    add("2D", "truncation", "Are weight-truncation thresholds prespecified and sensitivity-tested?", "UNFROZEN", "Use frozen primary quantiles plus sensitivity alternatives.", "PASS_BY_DESIGN", "Analysis protocol.", "methodology")
    add("2D", "effective sample size", "Will weighted effective sample size be reported?", "NOT_PLANNED", "Calculate ESS=(sum w)^2/sum(w^2) globally and by chain.", "PASS_BY_DESIGN", "Analysis protocol.", "methodology")
    add("2D", "negative verification", "Are property-bounded negatives independently checked?", "NOT_AVAILABLE", "Dual-review negative evidence and replay artifacts.", "BLOCKED", "Independent replay/adjudication records.", "external-review")
    add("2D", "control contamination", "Are controls included in the same identity, clone, proxy, protocol, and mechanism graph?", "LEAKAGE_RISK", "Apply one unified contamination graph to positives and controls.", "PASS_BY_DESIGN", "Graph policy; controls pending.", "pipeline")
    add("2D", "sampling reproducibility", "Can the exact control sample be regenerated?", "NOT_AVAILABLE", "Use immutable candidate stream, deterministic seed, and match-set manifest.", "PASS_BY_DESIGN", "Control collection manifest.", "pipeline")
    add("2D", "chain representation", "Are chain-specific inclusion rates and attrition reported?", "NOT_AVAILABLE", "Report numerator/denominator and exclusions per chain.", "PASS_BY_DESIGN", "Reporting template; stream pending.", "methodology")
    add("2D", "prevalence", "Can precision and workload be estimated at realistic prevalence?", "NO_DENOMINATOR", "Use the deployment stream rather than balanced-only evaluation.", "BLOCKED", "At least 20,000 deployment records with outcomes/follow-up.", "data-operations")
    add("2D", "outcome review", "Are positive and control outcomes independently adjudicated?", "SINGLE_SOURCE", "Require dual review plus third-reviewer resolution.", "BLOCKED", "Outcome adjudication records and agreement statistics.", "external-review")

    # Stage 2E - full graph, leakage audit and release (20)
    add("2E", "exact identity", "Is exact chain-address identity leakage zero?", "LEAKING_RANDOM_SPLITS", "Assign all members of an exact identity to one fold.", "PASS", "Zero crossings in grouped folds.", "pipeline")
    add("2E", "source clone", "Is exact/near source-clone leakage zero?", "UNKNOWN", "Build source clone components and group partitions.", "BLOCKED", "Verified source corpus and clone audit.", "data-operations")
    add("2E", "bytecode clone", "Is raw and normalized bytecode-family leakage zero?", "UNKNOWN", "Group raw and metadata-stripped code components.", "BLOCKED", "Historical bytecode corpus.", "data-operations")
    add("2E", "proxy family", "Is proxy/implementation-family leakage zero?", "UNKNOWN", "Group all proxies and implementations in connected components.", "BLOCKED", "Historical proxy graph.", "data-operations")
    add("2E", "library dependency", "Do shared library dependencies remain inside one partition when required?", "UNKNOWN", "Include linked-library edges under frozen dependency policy.", "BLOCKED", "Compiler/source dependency evidence.", "data-operations")
    add("2E", "protocol family", "Is adjudicated protocol-family leakage zero?", "UNKNOWN", "Group protocol components after dual review.", "BLOCKED", "Adjudicated protocol labels.", "external-review")
    add("2E", "mechanism family", "Is cause-level exploit-mechanism leakage zero for R5?", "UNKNOWN", "Group mechanism families after dual review.", "BLOCKED", "Adjudicated mechanism labels.", "external-review")
    add("2E", "attacker family", "Is attacker-family dependence audited without leaking into detector inputs?", "UNKNOWN", "Build evaluator-only attacker components and compare operational vs oracle partitions.", "BLOCKED", "Post-outcome attribution with evidence and access controls.", "external-review")
    add("2E", "component logic", "Are transitive dependencies closed through connected components rather than pairwise checks only?", "PAIRWISE_RISK", "Use typed graph connected components for prohibited edges.", "PASS_BY_DESIGN", "Graph algorithm specification; full edges pending.", "pipeline")
    add("2E", "effective sample", "Are at least 120 independent R5 blocks retained?", "UNKNOWN", "Count final connected components after all evidence is complete.", "BLOCKED", "Final R5 cohort with >=120 blocks.", "data-operations")
    add("2E", "class support", "Are there at least 40 positive and 40 control independent blocks?", "UNKNOWN", "Enforce minimum block counts or redesign claims.", "BLOCKED", "Final positive/control R5 counts.", "data-operations")
    add("2E", "attrition", "Are all exclusions and losses at each rung reported?", "HIDDEN_ATTRITION_RISK", "Emit reason codes and rung-by-rung cohort counts.", "PASS", "417 cases have machine-readable reasons; no silent release.", "pipeline")
    add("2E", "matched size", "Are stricter-rung comparisons repeated on matched sample sizes?", "CONFOUNDING_RISK", "Prespecify matched-size resampling and report both full/matched analyses.", "PASS_BY_DESIGN", "Analysis protocol; final graph pending.", "methodology")
    add("2E", "determinism", "Are split assignments deterministic and seed/version controlled?", "NONREPRODUCIBLE_RISK", "Use deterministic group balancing and frozen seeds.", "PASS", "Rebuild yields the same exact-identity folds.", "pipeline")
    add("2E", "validation isolation", "Are calibration and hyperparameter-tuning cases independent of the final test components?", "NOT_DEFINED", "Create group-aware train/calibration/test partitions.", "PASS_BY_DESIGN", "Partition policy; complete graph pending.", "methodology")
    add("2E", "retrieval contamination", "Are detector retrieval stores and demonstrations screened against test components and cutoff?", "LEAKAGE_RISK", "Hash/index retrieval corpora and exclude related/post-cutoff records.", "PASS_BY_DESIGN", "Information-plane policy; detector stage pending.", "pipeline")
    add("2E", "independent regeneration", "Can an independent party regenerate the release from manifests?", "NOT_EXTERNALLY_TESTED", "Release deterministic code, manifests, hashes, and a reconstruction checklist.", "PARTIAL", "Internal verification passes; external replication pending.", "external-review")
    add("2E", "versioning", "Can later evidence updates silently change an existing cohort version?", "DRIFT_RISK", "Issue immutable semantic versions and rebuild as a new release.", "PASS_BY_DESIGN", "Append-only registry and version policy.", "pipeline")
    add("2E", "release gate", "Does any failed mandatory Stage 2A-2D gate prevent release?", "FALSE_RELEASE_RISK", "Use a conjunctive fail-closed release predicate.", "PASS", "Release cohort has zero rows while mandatory evidence is incomplete.", "pipeline")
    add("2E", "claim discipline", "Can an empty or incomplete cohort be presented as a completed pre-incident benchmark?", "OVERCLAIM_RISK", "Publish explicit decision and blocker report; prohibit effectiveness claims.", "PASS", "Decision is FAIL_CLOSED_NO_STAGE2_RELEASE.", "governance")

    assert len(rows) == 100, len(rows)
    return rows
