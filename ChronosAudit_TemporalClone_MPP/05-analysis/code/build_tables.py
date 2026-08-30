#!/usr/bin/env python3
"""Build editable manuscript tables from the deterministic result summary."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def proportion_row(section: str, metric: str, record: dict[str, Any], interpretation: str) -> dict[str, Any]:
    return {
        "section": section,
        "metric": metric,
        "n": int(record["n"]),
        "denominator": int(record["denominator"]),
        "percent": f"{100.0 * float(record['proportion']):.1f}",
        "wilson_95_low_percent": f"{100.0 * float(record['wilson_95_low']):.1f}",
        "wilson_95_high_percent": f"{100.0 * float(record['wilson_95_high']):.1f}",
        "interpretation": interpretation,
    }


def build_tables(summary_path: Path, output_dir: Path, *, results_dir: Path | None = None) -> None:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    n_cases = int(summary["cohort"]["n_cases"])

    prior_art = [
        {"predecessor": "SCONE-bench", "historical_incident_benchmark": "yes", "historical_state": "fork block", "duplicate_identity_audit": "not located", "temporal_landmark_audit": "not located", "proxy_linkage_audit": "not located", "relation": "audited cohort"},
        {"predecessor": "Re-Evaluating EVMbench", "historical_incident_benchmark": "yes", "historical_state": "evaluation dependent", "duplicate_identity_audit": "training-data contamination focus", "temporal_landmark_audit": "no", "proxy_linkage_audit": "no", "relation": "benchmark-validity precedent"},
        {"predecessor": "CyberChainBench", "historical_incident_benchmark": "yes", "historical_state": "historical forks", "duplicate_identity_audit": "not located", "temporal_landmark_audit": "not located", "proxy_linkage_audit": "proxy subset for patching", "relation": "larger adjacent benchmark"},
        {"predecessor": "DIVE", "historical_incident_benchmark": "no", "historical_state": "lifecycle features", "duplicate_identity_audit": "duplicates removed", "temporal_landmark_audit": "no", "proxy_linkage_audit": "not central", "relation": "dataset-validity precedent"},
        {"predecessor": "This MPP", "historical_incident_benchmark": "yes; 417 SCONE rows", "historical_state": "dual-provider EIP-1898 evidence", "duplicate_identity_audit": "address/exact/stripped runtime", "temporal_landmark_audit": "1h/24h/7d/30d", "proxy_linkage_audit": "ERC-1967/beacon/ERC-1167 indicators", "relation": "joint bounded audit"},
    ]
    write_csv(output_dir / "t1-strongest-prior-art.csv", prior_art, list(prior_art[0]))

    comparison = [
        {"approach": "row count only", "temporal_eligibility": "no", "code_family_dependence": "no", "proxy_linkage": "no", "historical_read_evidence": "not required", "main_failure": "can overstate usable independent units"},
        {"approach": "chain-address deduplication", "temporal_eligibility": "no", "code_family_dependence": "address only", "proxy_linkage": "no", "historical_read_evidence": "optional", "main_failure": "misses cross-address clones"},
        {"approach": "exact bytecode deduplication", "temporal_eligibility": "no", "code_family_dependence": "exact runtime", "proxy_linkage": "partial", "historical_read_evidence": "snapshot dependent", "main_failure": "metadata and implementation layers remain"},
        {"approach": "TemporalClone MPP", "temporal_eligibility": "four landmarks", "code_family_dependence": "address exact and stripped runtime", "proxy_linkage": "specified observable indicators", "historical_read_evidence": "two providers; block-hash pinned upstream", "main_failure": "still a lower bound on semantic dependence"},
    ]
    write_csv(output_dir / "t2-proposed-vs-baselines.csv", comparison, list(comparison[0]))

    chain_rows = [
        {"chain": chain, "n": count, "percent": f"{100.0 * count / n_cases:.1f}", "cohort_denominator": n_cases}
        for chain, count in sorted(summary["cohort"]["chains"].items(), key=lambda item: (-item[1], item[0]))
    ]
    write_csv(output_dir / "t3-data-or-conditions.csv", chain_rows, ["chain", "n", "percent", "cohort_denominator"])

    primary: list[dict[str, Any]] = []
    temporal_labels = {
        "eligible_1h": "contract existed 1 hour before incident",
        "eligible_24h": "contract existed 24 hours before incident",
        "eligible_7d": "contract existed 7 days before incident",
        "eligible_30d": "contract existed 30 days before incident",
    }
    for metric in ("eligible_1h", "eligible_24h", "eligible_7d", "eligible_30d"):
        primary.append(proportion_row("temporal eligibility", metric, summary["temporal_eligibility"][metric], temporal_labels[metric]))
    proxy_labels = {
        "implementation_slot": "non-null ERC-1967 implementation value",
        "admin_slot": "non-null ERC-1967 admin value; reported separately",
        "beacon_slot": "non-null ERC-1967 beacon value",
        "eip1167_target": "recognized ERC-1167 target",
        "any_proxy_indicator": "implementation or beacon or ERC-1167 target",
    }
    for metric in ("implementation_slot", "admin_slot", "beacon_slot", "eip1167_target", "any_proxy_indicator"):
        primary.append(proportion_row("proxy linkage", metric, summary["proxy_linkage"][metric], proxy_labels[metric]))
    write_csv(output_dir / "t4-primary-results.csv", primary, list(primary[0]))
    if results_dir is not None:
        canonical_primary: list[dict[str, Any]] = []
        for metric in ("eligible_1h", "eligible_24h", "eligible_7d", "eligible_30d"):
            record = summary["temporal_eligibility"][metric]
            canonical_primary.append(
                {
                    "claim_id": "C004",
                    "estimand": f"{metric}_percent",
                    "effect_estimate": f"{100.0 * float(record['proportion']):.1f}",
                    "uncertainty_interval": f"[{100.0 * float(record['wilson_95_low']):.1f},{100.0 * float(record['wilson_95_high']):.1f}]",
                    "sample_size": n_cases,
                    "analysis_status": "PRESPECIFIED_COMPLETE",
                }
            )
        for abstraction, label in (
            ("address_only", "address_duplicate_group_rows"),
            ("runtime_bytecode", "exact_runtime_duplicate_group_rows"),
            ("metadata_stripped_bytecode", "stripped_runtime_duplicate_group_rows"),
        ):
            count = int(summary["identity_abstractions"][abstraction]["duplicate_rows"])
            canonical_primary.append(
                {
                    "claim_id": "C005",
                    "estimand": label,
                    "effect_estimate": count,
                    "uncertainty_interval": f"[{count},{count}]",
                    "sample_size": n_cases,
                    "analysis_status": "PRESPECIFIED_COMPLETE",
                }
            )
        proxy = summary["proxy_linkage"]["any_proxy_indicator"]
        canonical_primary.append(
            {
                "claim_id": "C006",
                "estimand": "specified_proxy_indicator_percent",
                "effect_estimate": f"{100.0 * float(proxy['proportion']):.1f}",
                "uncertainty_interval": f"[{100.0 * float(proxy['wilson_95_low']):.1f},{100.0 * float(proxy['wilson_95_high']):.1f}]",
                "sample_size": n_cases,
                "analysis_status": "PRESPECIFIED_COMPLETE",
            }
        )
        write_csv(
            results_dir / "primary-results.csv",
            canonical_primary,
            ["claim_id", "estimand", "effect_estimate", "uncertainty_interval", "sample_size", "analysis_status"],
        )

    identity_rows = []
    for abstraction in ("chain_address", "address_only", "runtime_bytecode", "metadata_stripped_bytecode"):
        record = summary["identity_abstractions"][abstraction]
        identity_rows.append({"identity_abstraction": abstraction, **record})
    identity_fields = ["identity_abstraction"] + list(identity_rows[0].keys())[1:]
    write_csv(output_dir / "t5-ablation-or-mechanism.csv", identity_rows, identity_fields)

    exact = summary["identity_abstractions"]["runtime_bytecode"]
    stripped = summary["identity_abstractions"]["metadata_stripped_bytecode"]
    chain_address = summary["identity_abstractions"]["chain_address"]
    address_only = summary["identity_abstractions"]["address_only"]
    robustness = [
        {"comparison": "chain-address vs address-only", "quantity": "duplicate_rows", "baseline": chain_address["duplicate_rows"], "alternative": address_only["duplicate_rows"], "difference": address_only["duplicate_rows"] - chain_address["duplicate_rows"], "boundary": "same address on different chains is not observed as an added collision here"},
        {"comparison": "exact vs metadata-stripped runtime", "quantity": "duplicate_rows", "baseline": exact["duplicate_rows"], "alternative": stripped["duplicate_rows"], "difference": stripped["duplicate_rows"] - exact["duplicate_rows"], "boundary": "metadata stripping can merge otherwise distinct exact runtimes"},
        {"comparison": "exact vs metadata-stripped runtime", "quantity": "cross_address_duplicate_rows", "baseline": exact["cross_address_duplicate_rows"], "alternative": stripped["cross_address_duplicate_rows"], "difference": stripped["cross_address_duplicate_rows"] - exact["cross_address_duplicate_rows"], "boundary": "still excludes semantic near-clones"},
        {"comparison": "exact vs metadata-stripped runtime", "quantity": "cross_chain_duplicate_rows", "baseline": exact["cross_chain_duplicate_rows"], "alternative": stripped["cross_chain_duplicate_rows"], "difference": stripped["cross_chain_duplicate_rows"] - exact["cross_chain_duplicate_rows"], "boundary": "chain-specific state and configuration can differ"},
    ]
    write_csv(output_dir / "t6-robustness-and-boundaries.csv", robustness, list(robustness[0]))
    if results_dir is not None:
        write_csv(results_dir / "robustness-and-boundaries.csv", robustness, list(robustness[0]))

    feasibility = [
        {"dimension": "new data collection", "status": "N/A", "evidence": "read-only reuse of 417 closed snapshots", "remaining_gate": "none"},
        {"dimension": "deterministic execution", "status": "VERIFIED", "evidence": "standard-library script and passing tests", "remaining_gate": "independent reproduction"},
        {"dimension": "rights", "status": "AT RISK", "evidence": "SCONE Apache-2.0; downstream row-level rights incomplete", "remaining_gate": "human/legal release review"},
        {"dimension": "scientific independence", "status": "BLOCKED", "evidence": "root produced and self-reviewed analysis", "remaining_gate": "qualified independent reviewer"},
        {"dimension": "submission authority", "status": "BLOCKED", "evidence": "author and declarations unresolved", "remaining_gate": "accountable human approval"},
    ]
    write_csv(output_dir / "t7-real-world-feasibility.csv", feasibility, list(feasibility[0]))

    negative = [
        {"finding": "No predictive or causal conclusion", "evidence": "no controls or detector evaluation in scope", "effect_on_claim": "paper is a cohort-validity audit only"},
        {"finding": "Proxy detection is incomplete by construction", "evidence": "only specified ERC-1967/beacon/ERC-1167 indicators", "effect_on_claim": "67 cases is a lower-bound indicator count"},
        {"finding": "Bytecode equality is not semantic equivalence", "evidence": "no normalized control flow or behavioral analysis", "effect_on_claim": "duplicate groups are exact fingerprint families"},
        {"finding": "Cohort is not a probability sample", "evidence": "historical exploited tasks selected by benchmark builders", "effect_on_claim": "no generalization to all contracts"},
        {"finding": "Novelty not independently certified", "evidence": "hostile challenge was performed by root", "effect_on_claim": "readiness remains blocked pending independent search"},
    ]
    write_csv(output_dir / "t8-negative-findings.csv", negative, list(negative[0]))
    if results_dir is not None:
        write_csv(results_dir / "negative-findings.csv", negative, list(negative[0]))
        exploratory = []
        for family in ("cutoff_lead_hours", "deployment_to_incident_hours"):
            for statistic, value in summary.get(family, {}).items():
                exploratory.append(
                    {
                        "variable": family,
                        "statistic": statistic,
                        "value_hours": f"{float(value):.6f}",
                        "status": "DESCRIPTIVE",
                    }
                )
        write_csv(
            results_dir / "exploratory-findings.csv",
            exploratory,
            ["variable", "statistic", "value_hours", "status"],
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--results-dir", type=Path)
    args = parser.parse_args()
    build_tables(args.summary, args.output_dir, results_dir=args.results_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
