from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd

from chronosaudit_stage2.public_acquisition.control_capacity_audit import (
    build_control_capacity_audit,
    build_effective_control_capacity_audit,
)
from chronosaudit_stage2.public_acquisition.control_trace_targets import (
    build_effective_trace_target_identities,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _candidate(case: str, address_byte: str, assignment: str) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "run_binding_sha256": "a" * 64,
        "reserve_assignment_sha256": assignment,
        "case_name": case,
        "chain": "ethereum",
        "control_address": "0x" + address_byte * 20,
        "creation_tx_hash": "0x" + "1" * 64,
        "deployment_block": 1,
        "deployment_block_hash": "0x" + "2" * 64,
        "control_deployment_time": "2024-01-01T00:00:00Z",
        "deployment_distance_seconds": -1,
        "temporal_pre_cutoff": True,
        "creation_type": "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
        "trace_proof": False,
        "provider_consensus": True,
        "provider_observations": [],
        "rpc_classification_complete": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    row["result_sha256"] = _sha(row)
    return row


def test_capacity_audit_uses_exact_max_flow_and_staged_membership(tmp_path: Path) -> None:
    scope = pd.DataFrame(
        [
            {"case_name": "case-1", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
            {"case_name": "case-2", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
        ]
    )
    scope_path = tmp_path / "scope.csv"
    scope.to_csv(scope_path, index=False)

    requirements = pd.DataFrame(
        [
            {"case_name": "case-1", "controls_required": 1},
            {"case_name": "case-2", "controls_required": 1},
        ]
    )
    requirements_path = tmp_path / "requirements.csv"
    requirements.to_csv(requirements_path, index=False)

    acquisition_root = tmp_path / "acquisition"
    (acquisition_root / "candidates").mkdir(parents=True)
    candidates = [
        _candidate("case-1", "bb", "b" * 64),
        _candidate("case-2", "cc", "c" * 64),
    ]
    previous = "0" * 64
    events = []
    for candidate in candidates:
        event = {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
            "previous_event_sha256": previous,
            "reserve_assignment_sha256": candidate["reserve_assignment_sha256"],
            "status": "COMPLETE",
            "result_sha256": candidate["result_sha256"],
            "result_path": str(
                acquisition_root
                / "candidates"
                / f"{candidate['reserve_assignment_sha256']}.json"
            ),
        }
        event["event_sha256"] = _sha(event)
        previous = str(event["event_sha256"])
        events.append(event)
        (acquisition_root / "candidates" / f"{candidate['reserve_assignment_sha256']}.json").write_text(
            json.dumps(candidate), encoding="utf-8"
        )
    (acquisition_root / "events.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8"
    )
    summary: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": "a" * 64,
        "queue_row_count": 10,
        "completed_count": 2,
        "remaining_count": 8,
        "terminal_rejected_count": 0,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    staged_row = {
        "case_id": "case-1",
        "chain_address": "ethereum:" + "0x" + "bb" * 20,
        "deployment_result_sha256": "d" * 64,
    }
    staged: dict[str, object] = {
        "schema_version": "stage2_control_staged_cutoff_state_results.v1",
        "decision": "STAGED_CUTOFF_STATE_PROJECTED_NON_AUTHORIZING",
        "complete": True,
        "target_count": 1,
        "targets": [staged_row],
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    staged["projection_sha256"] = _sha(staged)
    staged_path = tmp_path / "staged.json"
    staged_path.write_text(json.dumps(staged), encoding="utf-8")

    audit = build_control_capacity_audit(
        original_pair_scope_path=scope_path,
        expansion_requirements_path=requirements_path,
        acquisition_summary_path=summary_path,
        acquisition_root=acquisition_root,
        staged_state_results_path=staged_path,
    )

    assert audit["target_control_rows"] == 2
    assert audit["original_denominator"]["maximum_assignable_controls"] == 1
    assert audit["all_observed_deployments"]["maximum_assignable_controls"] == 2
    assert audit["staged_state_ready"]["maximum_assignable_controls"] == 2
    assert audit["all_observed_deployments"]["total_shortfall"] == 0
    assert audit["observed_complete_count"] == 2
    assert audit["staged_state_ready_observation_count"] == 1
    assert audit["selection_authorized"] is False
    assert audit["counter_authority"] is False
    assert audit["audit_sha256"] == _sha(
        {key: value for key, value in audit.items() if key != "audit_sha256"}
    )


def _effective_source(
    tmp_path: Path,
    *,
    name: str,
    case: str,
    assignment: str,
    address_byte: str,
    trace_required: bool,
) -> tuple[Path, Path]:
    root = tmp_path / name
    root.mkdir()
    result = _candidate(case, address_byte, assignment)
    if trace_required:
        result["creation_type"] = "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED"
        result["rpc_classification_complete"] = False
        result["result_sha256"] = _sha(
            {key: value for key, value in result.items() if key != "result_sha256"}
        )
    result_path = root / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    fields = [
        "case_name", "chain", "control_address", "reserve_assignment_sha256",
        "effective_status", "source_index", "source_run_binding_sha256",
        "source_event_sha256", "result_sha256", "result_file_sha256", "result_path",
    ]
    complete = root / "complete.csv"
    row = {
        "case_name": case,
        "chain": "ethereum",
        "control_address": result["control_address"],
        "reserve_assignment_sha256": assignment,
        "effective_status": "COMPLETE",
        "source_index": "0",
        "source_run_binding_sha256": "a" * 64,
        "source_event_sha256": "b" * 64,
        "result_sha256": result["result_sha256"],
        "result_file_sha256": _file_sha(result_path),
        "result_path": str(result_path),
    }
    with complete.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(row)
    with complete.open(encoding="utf-8", newline="") as handle:
        records = list(csv.DictReader(handle))
    manifest = {
        "schema_version": "chronosaudit.control_candidate_effective_reconciliation.v1",
        "decision": "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED",
        "source_run_count": 1,
        "source_bindings": [{"source_index": 0, "run_binding_sha256": "a" * 64}],
        "effective_complete_count": 1,
        "effective_rejected_count": 0,
        "effective_unresolved_count": 0,
        "complete_output_path": str(complete),
        "complete_output_sha256": _file_sha(complete),
        "complete_records_sha256": _sha(records),
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "independent_review_established": False,
        "r5_authorized": False,
        "release_authorized": False,
        "publication_authorized": False,
    }
    manifest["manifest_sha256"] = _sha(manifest)
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, complete


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_effective_capacity_excludes_unresolved_trace_candidates(tmp_path: Path) -> None:
    scope = pd.DataFrame([
        {"case_name": "case-1", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
        {"case_name": "case-2", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
    ])
    scope_path = tmp_path / "scope.csv"
    scope.to_csv(scope_path, index=False)
    requirements = pd.DataFrame([
        {"case_name": "case-1", "controls_required": 1},
        {"case_name": "case-2", "controls_required": 1},
    ])
    requirements_path = tmp_path / "requirements.csv"
    requirements.to_csv(requirements_path, index=False)
    sources = [
        _effective_source(
            tmp_path, name="classified", case="case-2", assignment="1" * 64,
            address_byte="bb", trace_required=False,
        ),
        _effective_source(
            tmp_path, name="trace", case="case-1", assignment="2" * 64,
            address_byte="cc", trace_required=True,
        ),
    ]
    identities = build_effective_trace_target_identities(sources=sources)
    identities_path = tmp_path / "trace-identities.json"
    identities_path.write_text(json.dumps(identities), encoding="utf-8")

    audit = build_effective_control_capacity_audit(
        original_pair_scope_path=scope_path,
        expansion_requirements_path=requirements_path,
        sources=sources,
        trace_target_identities_path=identities_path,
    )

    assert audit["effective_complete_count"] == 2
    assert audit["evidence_complete_candidate_count"] == 1
    assert audit["unresolved_trace_candidate_count"] == 1
    assert audit["evidence_complete_capacity"]["maximum_assignable_controls"] == 2
    assert audit["evidence_complete_capacity"]["total_shortfall"] == 0
    assert audit["denominator_qualifies"] is True
    assert audit["counter_authority"] is False
    assert audit["audit_sha256"] == _sha(
        {key: value for key, value in audit.items() if key != "audit_sha256"}
    )


def test_effective_capacity_includes_exactly_closed_trace_projection(
    tmp_path: Path,
) -> None:
    scope = pd.DataFrame(
        [
            {
                "case_name": "case-2",
                "chain": "ethereum",
                "control_address": "0x" + "aa" * 20,
            }
        ]
    )
    scope_path = tmp_path / "scope.csv"
    scope.to_csv(scope_path, index=False)
    requirements_path = tmp_path / "requirements.csv"
    pd.DataFrame(
        [
            {"case_name": "case-1", "controls_required": 1},
            {"case_name": "case-2", "controls_required": 1},
        ]
    ).to_csv(requirements_path, index=False)
    trace_source = _effective_source(
        tmp_path,
        name="trace",
        case="case-1",
        assignment="2" * 64,
        address_byte="cc",
        trace_required=True,
    )
    identities = build_effective_trace_target_identities(sources=[trace_source])
    identities_path = tmp_path / "trace-identities.json"
    identities_path.write_text(json.dumps(identities), encoding="utf-8")
    with trace_source[1].open(encoding="utf-8", newline="") as handle:
        effective_row = next(csv.DictReader(handle))
    candidate = json.loads(Path(effective_row["result_path"]).read_text())
    trace_record = {
        "schema_version": "stage2_control_trace_deployment_record.v1",
        "target_id": "trace-" + candidate["reserve_assignment_sha256"],
        "case_id": candidate["case_name"],
        "chain": candidate["chain"],
        "chain_address": (
            f"{candidate['chain']}:{candidate['control_address']}"
        ),
        "control_address": candidate["control_address"],
        "reserve_assignment_sha256": candidate["reserve_assignment_sha256"],
        "reserve_record_sha256": candidate["result_sha256"],
        "temporal_pre_cutoff": True,
        "trace_proof": True,
        "provider_consensus": True,
        "rpc_classification_complete": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    trace_record["record_sha256"] = _sha(trace_record)
    trace_projection = {
        "schema_version": "stage2_control_trace_deployment_projection.v1",
        "record_count": 1,
        "records": [trace_record],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    trace_projection["projection_sha256"] = _sha(trace_projection)
    trace_projection_path = tmp_path / "trace-projection.json"
    trace_projection_path.write_text(json.dumps(trace_projection), encoding="utf-8")

    audit = build_effective_control_capacity_audit(
        original_pair_scope_path=scope_path,
        expansion_requirements_path=requirements_path,
        sources=[trace_source],
        trace_target_identities_path=identities_path,
        trace_deployment_projection_path=trace_projection_path,
    )

    assert audit["trace_closed_candidate_count"] == 1
    assert audit["unresolved_trace_candidate_count"] == 0
    assert audit["evidence_complete_candidate_count"] == 1
    assert audit["evidence_complete_capacity"]["maximum_assignable_controls"] == 2
    assert audit["denominator_qualifies"] is True
    assert audit["denominator_admission_authorized"] is False
    assert audit["counter_authority"] is False


def test_effective_capacity_cli_writes_audit(tmp_path: Path) -> None:
    scope = pd.DataFrame([
        {"case_name": "case-1", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
    ])
    scope_path = tmp_path / "scope.csv"
    scope.to_csv(scope_path, index=False)
    requirements_path = tmp_path / "requirements.csv"
    pd.DataFrame([{"case_name": "case-1", "controls_required": 1}]).to_csv(
        requirements_path, index=False
    )
    source = _effective_source(
        tmp_path, name="classified", case="case-1", assignment="1" * 64,
        address_byte="bb", trace_required=False,
    )
    identities = build_effective_trace_target_identities(sources=[source])
    identities_path = tmp_path / "trace-identities.json"
    identities_path.write_text(json.dumps(identities), encoding="utf-8")
    output = tmp_path / "audit.json"
    script = Path(__file__).resolve().parents[1] / "build_stage2_control_effective_capacity_audit.py"

    completed = subprocess.run(
        [
            sys.executable, str(script),
            "--original-pair-scope", str(scope_path),
            "--expansion-requirements", str(requirements_path),
            "--source", f"{source[0]}::{source[1]}",
            "--trace-target-identities", str(identities_path),
            "--output", str(output),
        ],
        check=False, capture_output=True, text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(output.read_text())["denominator_qualifies"] is True

    help_result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "--trace-deployment-projection" in help_result.stdout
