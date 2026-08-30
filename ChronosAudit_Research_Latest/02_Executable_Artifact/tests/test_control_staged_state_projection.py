from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_staged_state_projection import (
    project_staged_state_results,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _aggregate(path: Path, rows: list[dict[str, object]]) -> Path:
    payload: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_state_results.v1",
        "activation_verification_sha256": "a" * 64,
        "state_targets_sha256": "b" * 64,
        "target_count": len(rows),
        "processed_target_count": len(rows),
        "completed_target_count": len(rows),
        "dispositions": {"complete": len(rows)},
        "targets": rows,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    payload["results_sha256"] = _canonical_sha(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_projects_hash_bound_legacy_state_from_separate_phases(tmp_path: Path) -> None:
    base: dict[str, object] = {
        "schema_version": "stage2_control_base_state_result.v1",
        "status": "complete",
        "phase": "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY",
        "target_id": "base-state:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "11" * 20,
        "identity_group": "ethereum:0x" + "11" * 20,
        "cutoff_timestamp": 1_600_000_000,
        "evidence_block_number": 100,
        "evidence_block_hash": "0x" + "aa" * 32,
        "evidence_block_timestamp": 1_600_000_000,
        "next_block_number": 101,
        "next_block_hash": "0x" + "bb" * 32,
        "next_block_timestamp": 1_600_000_010,
        "provider_agreement": True,
        "provider_families": ["family-a", "family-b"],
        "eip1898_pinned": True,
        "runtime_code_size": 10,
        "runtime_code_hash": "2" * 64,
        "metadata_stripped_code_hash": "3" * 64,
        "metadata_status": "metadata_absent",
        "direct_implementation_address": "0x" + "22" * 20,
        "beacon_address": None,
        "admin_address": None,
        "eip1167_target": None,
        "pair_scope_record_sha256": "4" * 64,
        "denominator_record_sha256": "5" * 64,
        "deployment_result_sha256": "6" * 64,
        "raw_evidence_hashes": ["7" * 64],
        "raw_evidence": [{"path": "base.json", "sha256": "7" * 64}],
        "derived_address_reads_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    base["result_sha256"] = _canonical_sha(base)
    base_row = {**base, "disposition": "complete"}

    derived: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_result.v1",
        "status": "complete",
        "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
        "target_id": "derived-state:" + "8" * 64,
        "target_sha256": "9" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": base["chain_address"],
        "source_base_state_target_id": base["target_id"],
        "base_state_result_sha256": base["result_sha256"],
        "derived_role": "direct_implementation_runtime_code",
        "derived_address": base["direct_implementation_address"],
        "evidence_block_number": 100,
        "evidence_block_hash": base["evidence_block_hash"],
        "provider_agreement": True,
        "provider_families": ["family-a", "family-b"],
        "eip1898_pinned": True,
        "runtime_code_size": 20,
        "runtime_code_hash": "c" * 64,
        "metadata_stripped_code_hash": "d" * 64,
        "metadata_status": "metadata_absent",
        "raw_evidence_hashes": ["e" * 64],
        "raw_evidence": [{"path": "derived.json", "sha256": "e" * 64}],
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    derived["result_sha256"] = _canonical_sha(derived)
    derived_row = {**derived, "disposition": "complete"}
    base_path = _aggregate(tmp_path / "base-results.json", [base_row])
    derived_path = _aggregate(tmp_path / "derived-results.json", [derived_row])

    output = project_staged_state_results(
        base_state_results_path=base_path,
        derived_state_results_path=derived_path,
        beacon_implementation_results_path=None,
    )

    assert output["decision"] == "STAGED_CUTOFF_STATE_PROJECTED_NON_AUTHORIZING"
    assert output["target_count"] == 1
    row = output["targets"][0]
    assert row["proxy_status"] == "proxy"
    assert row["proxy_family"] == "eip1967_implementation"
    assert row["implementation_address"] == "0x" + "22" * 20
    assert row["implementation_code_hash"] == "c" * 64
    assert row["clone_family"] == "c" * 64
    assert row["raw_evidence_hashes"] == sorted(["7" * 64, "e" * 64])
    assert row["selection_authorized"] is False
