from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ExternalEvidenceSource:
    source_id: str
    name: str
    year: int
    url: str
    doi: str | None
    evidence_type: str
    record_count: int | None
    chains: str
    independence_scope: str
    chronosaudit_role: str
    qualification_status: str
    notes: str


def default_external_sources() -> list[ExternalEvidenceSource]:
    """Published/public sources used for triangulation, not silent gate substitution."""
    return [
        ExternalEvidenceSource(
            "scone_2025_2026", "SCONE-bench / Anthropic smart-contract exploitation study", 2026,
            "https://www.anthropic.com/research/smart-contracts", None,
            "historical_fork_benchmark_and_recent_contract_scan", 405, "ethereum,bsc,base",
            "independent_benchmark_curation_with_three_model_council_and_manual_resolution",
            "external target-address/scope curation; historical fork execution; detector feasibility",
            "external_corroboration_only",
            "Published construction used three-model council and manual resolution; benchmark forks historical chain state. Separate scan evaluated 2,849 recently deployed BSC contracts and found two novel vulnerabilities in simulation."
        ),
        ExternalEvidenceSource(
            "anthropic_recent_2849", "Anthropic recent-contract zero-day scan", 2025,
            "https://www.anthropic.com/research/smart-contracts", None,
            "prospective_like_recent_contract_scan", 2849, "bsc",
            "independent_external_research_execution",
            "external prospective detector feasibility and background-risk evidence",
            "external_corroboration_only",
            "2,849 recently deployed BSC contracts selected from 9,437,874 deployments; two previously unknown vulnerabilities were found in simulation on 2025-10-03."
        ),
        ExternalEvidenceSource(
            "dive_2026", "DIVE: A Multi-Label Smart Contract Vulnerability Dataset", 2026,
            "https://www.nature.com/articles/s41597-026-07025-5", "10.1038/s41597-026-07025-5",
            "public_real_contract_corpus", 22330, "ethereum",
            "independent_research_group_and_dataset_pipeline",
            "external deployment/control sampling frame; detector-label triangulation",
            "external_corroboration_only",
            "22,330 labeled contracts; public machine-readable dataset; duplicate opcode structures explicitly documented.",
        ),
        ExternalEvidenceSource(
            "cyberchainbench_2026", "CyberChainBench", 2026,
            "https://arxiv.org/abs/2606.26216", "10.48550/arXiv.2606.26216",
            "curated_historical_incident_benchmark", 541,
            "ethereum,bsc,arbitrum,base,polygon,optimism,avalanche,fantom,blast",
            "independent_curator_and_manual_verification_but_incident_source_overlap",
            "external root-cause/localization/historical-state corroboration",
            "external_corroboration_only",
            "541 DeFiHackLabs-derived incidents with structured ground truth; all 541 were manually reviewed and 141 function/type inconsistencies corrected; historical fork evaluation.",
        ),
        ExternalEvidenceSource(
            "reevmbench_2026", "ReEVMbench", 2026,
            "https://arxiv.org/abs/2603.10795", "10.48550/arXiv.2603.10795",
            "post_release_contamination_resistant_incident_benchmark", 22, "evm_multi_chain",
            "independent_research_group",
            "external temporal-generalization/reproduction triangulation",
            "external_corroboration_only",
            "22 incidents selected to postdate evaluated model releases; useful external temporal stress test, not ChronosAudit partition regeneration.",
        ),
        ExternalEvidenceSource(
            "sc_benchmark_suites", "Smart-Contract-Benchmark-Suites", 2021,
            "https://github.com/renardbebe/Smart-Contract-Benchmark-Suites", None,
            "public_real_and_vulnerable_contract_corpus", 46186, "ethereum",
            "independent_public_repository",
            "secondary deployment/control sampling frame",
            "external_corroboration_only",
            "Repository states 46,186 contracts across unlabeled real-world, injected-bug, and confirmed-vulnerable categories.",
        ),
        ExternalEvidenceSource(
            "slither_audited", "Slither Audited Smart Contracts", 2022,
            "https://huggingface.co/datasets/mwritescode/slither-audited-smart-contracts", None,
            "public_static_analysis_corpus", 113000, "ethereum",
            "independent_public_dataset",
            "secondary control/detector corpus",
            "external_corroboration_only",
            "Large real-world Solidity corpus with Slither-derived labels; not an outcome-certified non-exploit cohort.",
        ),
        ExternalEvidenceSource(
            "sourcify_exports", "Sourcify database exports", 2026,
            "https://docs.sourcify.dev/docs/repository/database-export/", None,
            "append_only_source_and_deployment_exports", None, "multi_chain",
            "independent_verification_infrastructure",
            "source-at-cutoff and deployment corroboration",
            "eligible_when_record_level_export_is_ingested",
            "Append-only Parquet exports include verified contracts/deployments and timestamps; record-level ingestion is required for case qualification.",
        ),
    ]


def write_registry(path: Path, sources: Iterable[ExternalEvidenceSource] | None = None) -> dict:
    sources = list(sources or default_external_sources())
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(x) for x in sources]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    raw = path.read_bytes()
    return {"rows": len(rows), "sha256": hashlib.sha256(raw).hexdigest(), "path": str(path)}


def gate_assessment() -> list[dict]:
    """Strict gate map: public evidence may corroborate a gate but never manufacture independence."""
    return [
        {"gate":"dual_provider_historical_snapshots","target":"417 cases x >=2 independent provider families","public_evidence":"PublicNode/1RPC endpoints + Sourcify/CyberChainBench historical-state evidence","status":"LIVE_RECORD_LEVEL_EXECUTION_REQUIRED","can_generate":False},
        {"gate":"independent_reviewer_labels","target":"834 blinded labels","public_evidence":"CyberChainBench independent curator taxonomy/manual verification","status":"EXTERNAL_CORROBORATION_AVAILABLE_INTERNAL_834_STILL_REQUIRED","can_generate":False},
        {"gate":"third_party_adjudication","target":"417 final case decisions","public_evidence":"CyberChainBench curated root-cause/localization labels","status":"PARTIAL_EXTERNAL_ADJUDICATION_CORROBORATION_NOT_CASEWISE_COMPLETE","can_generate":False},
        {"gate":"deployment_denominator","target":">=20,000 real contracts","public_evidence":"DIVE 22,330; Smart-Contract-Benchmark-Suites 46,186; Slither corpus >100k","status":"PUBLIC_DENOMINATOR_CORPORA_EXIST_RECORD_LEVEL_ASSIMILATION_REQUIRED","can_generate":False},
        {"gate":"matched_controls","target":">=4,170 cutoff-safe controls","public_evidence":"Candidate controls can be sampled from public denominators after deployment/cutoff fields are available","status":"CANNOT_SYNTHESIZE_REAL_CONTROLS_WITHOUT_RECORD_LEVEL_RISK_SET","can_generate":False},
        {"gate":"longitudinal_outcomes","target":"event/censoring follow-up for positives and controls","public_evidence":"Incident dates available for 417 positives; control non-events require prospective/public follow-up","status":"POSITIVE_EVENTS_AVAILABLE_CONTROL_FOLLOWUP_REQUIRED","can_generate":False},
        {"gate":"r5_blocks","target":">=120 independent mechanism blocks","public_evidence":"CyberChainBench five-type taxonomy; ChronosAudit preliminary candidate labels","status":"REQUIRES_FINAL_ADJUDICATED_MECHANISM_AND_CONTROLS","can_generate":False},
        {"gate":"independent_external_reproduction","target":"independent regeneration of ChronosAudit partitions","public_evidence":"ReEVMbench/CyberChainBench independently reproduce historical benchmark concepts","status":"EXTERNAL_TRIANGULATION_AVAILABLE_EXACT_REGENERATION_NOT_DONE","can_generate":False},
        {"gate":"detector_r0_r5","target":">=3 detector families across R0-R5","public_evidence":"DIVE multi-tool labels; CyberChainBench agent results; published detector benchmarks","status":"PUBLIC_DETECTOR_EVIDENCE_AVAILABLE_BUT_NO_SAME_DETECTOR_R0_R5_CURVE_YET","can_generate":False},
    ]


def write_gate_assessment(path: Path) -> dict:
    rows = gate_assessment(); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    return {"rows": len(rows), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
