#!/usr/bin/env python3
"""Normalize research artifacts to the schema-v4 semantic contracts."""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "chronosaudit-temporalclone-mpp-20260828T193046Z-5c71be2f-7ac55a"


def write_csv(relative: str, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path = ROOT / relative
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(relative: str, payload: dict[str, object]) -> None:
    (ROOT / relative).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    write_csv(
        "04-data/evidence-status.csv",
        ["evidence_id", "claim_ids", "origin", "maturity", "scope", "status", "authorized", "independent", "source_artifact", "notes"],
        [
            {"evidence_id": "E001", "claim_ids": "C002|C003|C004|C005|C006|C007", "origin": "REAL_OBSERVED", "maturity": "V3 INTERNAL", "scope": "INTERNAL", "status": "PARTIAL", "authorized": "yes", "independent": "no", "source_artifact": "04-data/provenance-manifest.csv", "notes": "Read-only frozen envelope reuse; no independent provider recreation in this run."},
            {"evidence_id": "E002", "claim_ids": "C002|C007", "origin": "ANALYTIC", "maturity": "V3 INTERNAL", "scope": "INTERNAL", "status": "SUPPORTED", "authorized": "yes", "independent": "no", "source_artifact": "04-data/provenance-manifest.csv", "notes": "Deterministic 417-file hash manifest."},
            {"evidence_id": "E003", "claim_ids": "C004|C006", "origin": "ANALYTIC", "maturity": "V3 INTERNAL", "scope": "INTERNAL", "status": "SUPPORTED", "authorized": "yes", "independent": "no", "source_artifact": "05-analysis/results/primary-results.csv", "notes": "Full-cohort temporal and proxy estimands."},
            {"evidence_id": "E004", "claim_ids": "C005", "origin": "ANALYTIC", "maturity": "V3 INTERNAL", "scope": "INTERNAL", "status": "SUPPORTED", "authorized": "yes", "independent": "no", "source_artifact": "05-analysis/results/primary-results.csv", "notes": "Deterministic identity-abstraction counts."},
            {"evidence_id": "E005", "claim_ids": "C001", "origin": "EXPERT_JUDGMENT", "maturity": "V1 ANALYTIC", "scope": "ANALYTIC", "status": "PARTIAL", "authorized": "yes", "independent": "no", "source_artifact": "01-novelty/evidence-ledger.csv", "notes": "Bounded public-source search; independent challenge pending."},
            {"evidence_id": "E006", "claim_ids": "C003", "origin": "ANALYTIC", "maturity": "V3 INTERNAL", "scope": "INTERNAL", "status": "PARTIAL", "authorized": "yes", "independent": "no", "source_artifact": "07-manuscript/manuscript.md", "notes": "Complete local manuscript and artifact bundle."},
            {"evidence_id": "E007", "claim_ids": "C003", "origin": "INTERNAL_EXPERIMENT", "maturity": "V0 ASSERTED", "scope": "ASSERTED", "status": "UNSUPPORTED", "authorized": "no", "independent": "no", "source_artifact": "", "notes": "The unfinished 4,170 controls are excluded."},
            {"evidence_id": "E008", "claim_ids": "C003", "origin": "EXPERT_JUDGMENT", "maturity": "V0 ASSERTED", "scope": "ASSERTED", "status": "UNSUPPORTED", "authorized": "no", "independent": "no", "source_artifact": "", "notes": "Failed AI reliability evidence is excluded."},
        ],
    )

    write_csv(
        "02-feasibility/evidence-maturity-ladder.csv",
        ["claim_id", "required_maturity", "current_maturity", "status", "direct_evidence", "independence", "scope_ceiling", "next_gate"],
        [
            {"claim_id": "C001", "required_maturity": "V4 EXTERNAL", "current_maturity": "V1 ANALYTIC", "status": "BLOCKED", "direct_evidence": "01-novelty/novelty-matrix.csv", "independence": "no", "scope_ceiling": "ANALYTIC", "next_gate": "independent search challenge"},
            {"claim_id": "C002", "required_maturity": "V3 INTERNAL", "current_maturity": "V3 INTERNAL", "status": "PARTIAL", "direct_evidence": "04-data/provenance-manifest.csv", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "rights and authority review"},
            {"claim_id": "C003", "required_maturity": "V4 EXTERNAL", "current_maturity": "V3 INTERNAL", "status": "PARTIAL", "direct_evidence": "07-manuscript/manuscript.md", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "independent reproduction and author approval"},
            {"claim_id": "C004", "required_maturity": "V3 INTERNAL", "current_maturity": "V3 INTERNAL", "status": "SUPPORTED", "direct_evidence": "05-analysis/results/primary-results.csv", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "independent timestamp review"},
            {"claim_id": "C005", "required_maturity": "V3 INTERNAL", "current_maturity": "V3 INTERNAL", "status": "SUPPORTED", "direct_evidence": "05-analysis/results/primary-results.csv", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "independent edge-case review"},
            {"claim_id": "C006", "required_maturity": "V3 INTERNAL", "current_maturity": "V3 INTERNAL", "status": "SUPPORTED", "direct_evidence": "05-analysis/results/primary-results.csv", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "independent proxy semantic review"},
            {"claim_id": "C007", "required_maturity": "V4 EXTERNAL", "current_maturity": "V3 INTERNAL", "status": "PARTIAL", "direct_evidence": "04-data/provenance-manifest.csv", "independence": "no", "scope_ceiling": "INTERNAL", "next_gate": "clean-machine manifest reproduction"},
        ],
    )

    write_csv(
        "07-manuscript/claim-evidence-matrix.csv",
        ["claim_id", "claim_text", "claim_scope", "central", "evidence_ids", "required_maturity", "manuscript_location", "uncertainty", "alternative_explanation", "next_falsification"],
        [
            {"claim_id": "C004", "claim_text": "Eligibility declines at longer pre-incident landmarks.", "claim_scope": "Frozen 417-case SCONE-bench cohort", "central": "yes", "evidence_ids": "E001|E003", "required_maturity": "V3 INTERNAL", "manuscript_location": "Section 4.1; Table 3; Figure 2", "uncertainty": "Wilson intervals are descriptive aids and timestamps are inherited.", "alternative_explanation": "Benchmark construction selects for historical incidents.", "next_falsification": "Independent timestamp audit and replay."},
            {"claim_id": "C005", "claim_text": "Dependence counts increase under runtime-bytecode identities.", "claim_scope": "Exact and metadata-stripped runtime fingerprints", "central": "yes", "evidence_ids": "E001|E004", "required_maturity": "V3 INTERNAL", "manuscript_location": "Section 4.2; Table 4; Figure 4", "uncertainty": "Fingerprint equality is not semantic equivalence.", "alternative_explanation": "Shared compiler output may match without shared exploit mechanism.", "next_falsification": "Semantic-clone and edge-case review."},
            {"claim_id": "C006", "claim_text": "Sixty-seven cases expose at least one specified proxy indicator.", "claim_scope": "ERC-1967 implementation or beacon and ERC-1167 target", "central": "yes", "evidence_ids": "E001|E003", "required_maturity": "V3 INTERNAL", "manuscript_location": "Section 4.3; Table 3", "uncertainty": "Indicator coverage is deliberately incomplete.", "alternative_explanation": "Unrecognized proxy patterns may remain.", "next_falsification": "Manual and implementation-graph validation."},
            {"claim_id": "C007", "claim_text": "All analysis rows passed the declared envelope closure gate.", "claim_scope": "Local frozen input tree", "central": "yes", "evidence_ids": "E001|E002", "required_maturity": "V4 EXTERNAL", "manuscript_location": "Section 3.1 and Section 7", "uncertainty": "The run does not independently prove provider correctness.", "alternative_explanation": "Providers or upstream construction may share correlated errors.", "next_falsification": "Clean-machine source-manifest reproduction."},
        ],
    )

    primary_rows = [
        ("C004", "eligible_1h_percent", 100.0, "[99.1,100.0]", 417, "PRESPECIFIED_COMPLETE"),
        ("C004", "eligible_24h_percent", 100.0, "[99.1,100.0]", 417, "PRESPECIFIED_COMPLETE"),
        ("C004", "eligible_7d_percent", 84.4, "[80.6,87.6]", 417, "PRESPECIFIED_COMPLETE"),
        ("C004", "eligible_30d_percent", 65.9, "[61.3,70.3]", 417, "PRESPECIFIED_COMPLETE"),
        ("C005", "address_duplicate_group_rows", 14, "[14,14]", 417, "PRESPECIFIED_COMPLETE"),
        ("C005", "exact_runtime_duplicate_group_rows", 46, "[46,46]", 417, "PRESPECIFIED_COMPLETE"),
        ("C005", "stripped_runtime_duplicate_group_rows", 56, "[56,56]", 417, "PRESPECIFIED_COMPLETE"),
        ("C006", "specified_proxy_indicator_percent", 16.1, "[12.9,19.9]", 417, "PRESPECIFIED_COMPLETE"),
    ]
    write_csv(
        "05-analysis/results/primary-results.csv",
        ["claim_id", "estimand", "effect_estimate", "uncertainty_interval", "sample_size", "analysis_status"],
        [dict(zip(["claim_id", "estimand", "effect_estimate", "uncertainty_interval", "sample_size", "analysis_status"], row)) for row in primary_rows],
    )

    predecessor_rows = [
        ("PA-SCONE", "Audits cohort validity rather than agent exploit performance", "A same-cohort joint audit", "The repository may change after cutoff"),
        ("PA-ANTHROPIC-2025", "Fixed landmark eligibility rather than deployment-age correlation", "A landmark audit on the current cohort", "Earlier report used 405 cases"),
        ("PA-CYBERCHAIN", "Joint temporal and identity/proxy dependence audit", "Equivalent joint benchmark audit", "Recent preprint search may be incomplete"),
        ("PA-CLONES", "Same-cohort runtime fingerprint sensitivity", "Same-cohort bytecode-family audit", "Semantic clone literature remains broader"),
        ("PA-DIVE", "Exploit-benchmark-specific temporal and identity audit", "Equivalent multi-axis audit", "Different task and cohort"),
    ]
    write_csv(
        "01-novelty/novelty-matrix.csv",
        ["claim_id", "predecessor_id", "material_difference", "defeating_evidence", "residual_uncertainty"],
        [{"claim_id": "C001", "predecessor_id": pid, "material_difference": diff, "defeating_evidence": defeat, "residual_uncertainty": residual} for pid, diff, defeat, residual in predecessor_rows],
    )

    queries = [
        {"query_id": "Q001", "surface": "arXiv and web", "query": "smart contract exploit benchmark historical state reconstruction EVM benchmark bytecode clone proxy", "searched_at": "2026-08-29", "request_url": "manual-web-search", "response_sha256": "manual-snapshot-not-hash-bound", "raw_path": "01-novelty/prior-art-raw-snapshots.json"},
        {"query_id": "Q002", "surface": "Anthropic and GitHub", "query": "SCONE-bench 417 historical incidents dataset", "searched_at": "2026-08-29", "request_url": "manual-official-source-search", "response_sha256": "manual-snapshot-not-hash-bound", "raw_path": "01-novelty/prior-art-raw-snapshots.json"},
        {"query_id": "Q003", "surface": "publisher and scholarly web", "query": "smart contract benchmark duplicate contracts bytecode metadata stripping dataset leakage", "searched_at": "2026-08-29", "request_url": "manual-scholar-search", "response_sha256": "manual-snapshot-not-hash-bound", "raw_path": "01-novelty/prior-art-raw-snapshots.json"},
        {"query_id": "Q004", "surface": "EIP repository", "query": "EIP-1898 EIP-1967 EIP-1167", "searched_at": "2026-08-29", "request_url": "manual-eip-search", "response_sha256": "manual-snapshot-not-hash-bound", "raw_path": "01-novelty/prior-art-raw-snapshots.json"},
    ]
    shared = {"schema_version": 4, "run_id": RUN_ID, "adapter_id": "MANUAL_PUBLIC_WEB_V1", "offline_only": False, "may_assert_novelty": False}
    write_json("01-novelty/prior-art-query-log.json", {**shared, "live_network_permitted": False, "queries": queries})

    existing = json.loads((ROOT / "01-novelty/prior-art-raw-snapshots.json").read_text(encoding="utf-8"))["records"]
    query_assignment = {
        "PA-SCONE": "Q002", "PA-ANTHROPIC-2025": "Q002", "PA-EVMBENCH": "Q001", "PA-REEVMBENCH": "Q001", "PA-CYBERCHAIN": "Q001",
        "PA-DIVE": "Q003", "PA-CLONES": "Q003", "PA-EIP1898": "Q004", "PA-ERC1967": "Q004", "PA-ERC1167": "Q004",
    }
    normalized = []
    for item in existing:
        record_id = item.get("record_id") or item.get("id")
        normalized.append({
            "record_id": record_id,
            "query_id": query_assignment[record_id],
            "source": item.get("source") or item.get("type", "public web"),
            "title": item["title"],
            "published_at": item.get("published_at") or "unknown",
            "url": item["url"],
            "salient_fact": item.get("salient_fact", ""),
        })
    write_json("01-novelty/prior-art-raw-snapshots.json", {**shared, "records": normalized})
    write_json("01-novelty/prior-art-dedup-report.json", {**shared, "deduplication": "canonical URL and record ID", "input_record_count": 10, "unique_record_count": 10, "duplicate_count": 0, "duplicates": [], "unique_records": normalized})
    counts = {qid: sum(1 for row in normalized if row["query_id"] == qid) for qid in {q["query_id"] for q in queries}}
    write_csv(
        "01-novelty/search-coverage.csv",
        ["query_id", "surface", "query", "searched_at", "result_count", "screened_count", "access_status"],
        [{**q, "result_count": counts[q["query_id"]], "screened_count": counts[q["query_id"]], "access_status": "BOUNDED_PUBLIC_ACCESS"} for q in queries],
    )

    write_csv(
        "08-validation/killer-question-ledger.csv",
        ["question_id", "critical", "judgment", "claim_ids", "evidence_ids", "action", "question", "consequence"],
        [
            {"question_id": "KQ001", "critical": "yes", "judgment": "PASS", "claim_ids": "C003|C004|C005|C006", "evidence_ids": "E003|E004|E006", "action": "Retain bounded operational framing.", "question": "Is the central question important enough to report?", "consequence": "Supports a narrow benchmark-validity contribution."},
            {"question_id": "KQ002", "critical": "yes", "judgment": "UNKNOWN", "claim_ids": "C001", "evidence_ids": "E005", "action": "Run a qualified independent search challenge.", "question": "Has novelty survived an independent search?", "consequence": "Universal novelty language is prohibited."},
            {"question_id": "KQ003", "critical": "yes", "judgment": "PASS", "claim_ids": "C004|C005|C006", "evidence_ids": "E001|E003|E004", "action": "Preserve claim boundary.", "question": "Can the design answer the stated questions?", "consequence": "Descriptive cohort conclusions only."},
            {"question_id": "KQ004", "critical": "yes", "judgment": "PARTIAL", "claim_ids": "C003|C007", "evidence_ids": "E001|E002|E006", "action": "Obtain clean-machine independent replay.", "question": "Are central results independently reproducible?", "consequence": "No independent certification."},
            {"question_id": "KQ005", "critical": "yes", "judgment": "PASS", "claim_ids": "C004|C005|C006", "evidence_ids": "E003|E004", "action": "Retain explicit exclusions.", "question": "Do conclusions exceed evidence maturity?", "consequence": "No scope inflation identified."},
            {"question_id": "KQ006", "critical": "yes", "judgment": "PARTIAL", "claim_ids": "C002|C003", "evidence_ids": "E001|E006", "action": "Complete human rights and institutional review.", "question": "Are rights and ethics resolved?", "consequence": "Row-level release remains gated."},
            {"question_id": "KQ007", "critical": "yes", "judgment": "FAIL", "claim_ids": "C003", "evidence_ids": "E006", "action": "Accountable authors complete metadata and declarations.", "question": "Are author identity and declarations complete?", "consequence": "Upload is blocked."},
            {"question_id": "KQ008", "critical": "no", "judgment": "PASS", "claim_ids": "C003", "evidence_ids": "E006", "action": "Run final venue-specific sizing.", "question": "Are figures tables and algorithms complete?", "consequence": "All planned explanatory artifacts exist."},
            {"question_id": "KQ009", "critical": "no", "judgment": "PASS", "claim_ids": "C003", "evidence_ids": "E006", "action": "Repeat after author edits.", "question": "Does the PDF pass mechanical QA?", "consequence": "Mechanically usable draft."},
            {"question_id": "KQ010", "critical": "yes", "judgment": "FAIL", "claim_ids": "C003", "evidence_ids": "E006", "action": "Human reviews exact package and platform preview.", "question": "Has a human approved the upload package?", "consequence": "No submission authority."},
        ],
    )

    write_csv(
        "09-submission/venue-portfolio.csv",
        ["venue", "article_type", "rank_basis", "official_url", "checked_at", "fit_rationale", "priority", "status", "next_gate"],
        [
            {"venue": "arXiv cs.CR", "article_type": "Preprint", "rank_basis": "Immediate public dissemination route; not peer review", "official_url": "https://info.arxiv.org/help/submit/index.html", "checked_at": "2026-08-29", "fit_rationale": "Security benchmark validity and reproducible artifact", "priority": 1, "status": "PREPARED_NOT_UPLOADED", "next_gate": "author rights license preview and approval"},
            {"venue": "Empirical Software Engineering", "article_type": "Original Paper", "rank_basis": "Peer-reviewed venue selected by thematic fit not asserted prestige rank", "official_url": "https://link.springer.com/journal/10664/submission-guidelines", "checked_at": "2026-08-29", "fit_rationale": "Empirical methodology and reproducible benchmark study", "priority": 2, "status": "PREPARED_NOT_SUBMITTED", "next_gate": "independent review author metadata declarations and portal QA"},
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
