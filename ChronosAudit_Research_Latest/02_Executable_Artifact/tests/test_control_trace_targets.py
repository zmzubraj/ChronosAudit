from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from chronosaudit_stage2.public_acquisition.control_trace_targets import (
    ControlTraceTargetError,
    build_effective_trace_target_identities,
    build_trace_target_identities,
    materialize_trace_targets,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _effective_source(
    tmp_path: Path,
    *,
    name: str,
    assignment: str,
    address_byte: str,
    creation_type: str = "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED",
) -> tuple[Path, Path]:
    source = tmp_path / name
    source.mkdir()
    result = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "run_binding_sha256": "a" * 64,
        "reserve_assignment_sha256": assignment,
        "case_name": f"case-{name}",
        "chain": "ethereum",
        "control_address": "0x" + address_byte * 20,
        "creation_tx_hash": "0x" + "33" * 32,
        "deployment_block": 10,
        "deployment_block_hash": "0x" + "44" * 32,
        "temporal_pre_cutoff": True,
        "creation_type": creation_type,
        "trace_proof": False,
        "provider_consensus": True,
        "rpc_classification_complete": creation_type
        == "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    result_path = source / f"{assignment}.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    fields = [
        "case_name",
        "chain",
        "control_address",
        "reserve_assignment_sha256",
        "effective_status",
        "source_index",
        "source_run_binding_sha256",
        "source_event_sha256",
        "result_sha256",
        "result_file_sha256",
        "result_path",
    ]
    csv_path = source / "complete.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "case_name": result["case_name"],
                "chain": result["chain"],
                "control_address": result["control_address"],
                "reserve_assignment_sha256": assignment,
                "effective_status": "COMPLETE",
                "source_index": "0",
                "source_run_binding_sha256": result["run_binding_sha256"],
                "source_event_sha256": "b" * 64,
                "result_sha256": result["result_sha256"],
                "result_file_sha256": _file_sha(result_path),
                "result_path": str(result_path),
            }
        )
    with csv_path.open(encoding="utf-8", newline="") as handle:
        records = list(csv.DictReader(handle))
    manifest = {
        "schema_version": "chronosaudit.control_candidate_effective_reconciliation.v1",
        "decision": "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED",
        "source_run_count": 1,
        "source_bindings": [{"source_index": 0, "run_binding_sha256": "a" * 64}],
        "effective_complete_count": 1,
        "effective_rejected_count": 0,
        "effective_unresolved_count": 0,
        "complete_output_path": str(csv_path),
        "complete_output_sha256": _file_sha(csv_path),
        "complete_records_sha256": _canonical_sha(records),
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
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    manifest_path = source / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, csv_path


def test_effective_reconciliation_freezes_trace_rows_across_sources(tmp_path: Path):
    first = _effective_source(
        tmp_path, name="first", assignment="1" * 64, address_byte="11"
    )
    second = _effective_source(
        tmp_path, name="second", assignment="2" * 64, address_byte="22"
    )

    result = build_effective_trace_target_identities(sources=[first, second])

    assert result["schema_version"] == "stage2_control_trace_target_identities.v1"
    assert result["target_count"] == 2
    assert result["chain_target_counts"] == {"ethereum": 2}
    assert result["source_reconciliation_count"] == 2
    assert result["rpc_authorized"] is False
    assert result["selection_authorized"] is False
    assert result["target_identities_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in result.items()
            if key != "target_identities_sha256"
        }
    )


def test_effective_reconciliation_rejects_result_file_tamper(tmp_path: Path):
    manifest, complete = _effective_source(
        tmp_path, name="first", assignment="1" * 64, address_byte="11"
    )
    with complete.open(encoding="utf-8", newline="") as handle:
        row = next(csv.DictReader(handle))
    result_path = Path(row["result_path"])
    payload = json.loads(result_path.read_text())
    payload["control_address"] = "0x" + "99" * 20
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlTraceTargetError, match="effective_result_file_hash_mismatch"):
        build_effective_trace_target_identities(sources=[(manifest, complete)])


def test_effective_reconciliation_rejects_duplicate_chain_address(tmp_path: Path):
    first = _effective_source(
        tmp_path, name="first", assignment="1" * 64, address_byte="11"
    )
    second = _effective_source(
        tmp_path, name="second", assignment="2" * 64, address_byte="11"
    )

    with pytest.raises(ControlTraceTargetError, match="trace_chain_address_duplicate"):
        build_effective_trace_target_identities(sources=[first, second])


def test_effective_trace_target_cli_writes_verified_artifact(tmp_path: Path):
    manifest, complete = _effective_source(
        tmp_path, name="first", assignment="1" * 64, address_byte="11"
    )
    output = tmp_path / "trace-target-identities.json"
    script = Path(__file__).resolve().parents[1] / (
        "build_stage2_control_effective_trace_target_identities.py"
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--source",
            f"{manifest}::{complete}",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text())
    assert payload["target_count"] == 1
    assert payload["target_identities_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in payload.items()
            if key != "target_identities_sha256"
        }
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    run_binding = "a" * 64
    root = tmp_path / "candidates"
    root.mkdir()
    rows = [
        {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
            "run_binding_sha256": run_binding,
            "reserve_assignment_sha256": "1" * 64,
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "22" * 20,
            "creation_tx_hash": "0x" + "33" * 32,
            "deployment_block": 10,
            "deployment_block_hash": "0x" + "44" * 32,
            "temporal_pre_cutoff": True,
            "creation_type": "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED",
            "trace_proof": False,
            "provider_consensus": True,
            "rpc_classification_complete": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
            "run_binding_sha256": run_binding,
            "reserve_assignment_sha256": "2" * 64,
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "55" * 20,
            "creation_tx_hash": "0x" + "66" * 32,
            "deployment_block": 11,
            "deployment_block_hash": "0x" + "77" * 32,
            "temporal_pre_cutoff": True,
            "creation_type": "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
            "trace_proof": False,
            "provider_consensus": True,
            "rpc_classification_complete": True,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
    ]
    for row in rows:
        row["result_sha256"] = _canonical_sha(row)
        (root / f'{row["reserve_assignment_sha256"]}.json').write_text(
            json.dumps(row), encoding="utf-8"
        )

    summary = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run_binding,
        "completed_count": 2,
        "trace_required_count": 1,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _canonical_sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    verification = {
        "decision": "LOCAL_TEST_CHECKPOINT_SIGNATURE_VERIFIED_NON_AUTHORIZING",
        "summary_sha256": _file_sha(summary_path),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    verification_path = tmp_path / "verification.json"
    verification_path.write_text(json.dumps(verification), encoding="utf-8")
    ledger_path = tmp_path / "events.jsonl"
    previous = "0" * 64
    lines = []
    for row in rows:
        event = {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
            "previous_event_sha256": previous,
            "reserve_assignment_sha256": row["reserve_assignment_sha256"],
            "status": "COMPLETE",
            "result_sha256": row["result_sha256"],
            "result_path": str(root / f'{row["reserve_assignment_sha256"]}.json'),
        }
        event["event_sha256"] = _canonical_sha(event)
        previous = event["event_sha256"]
        lines.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary_path, verification_path, ledger_path, root


def test_freezes_only_exact_unresolved_trace_scope(tmp_path: Path):
    summary, verification, ledger, root = _inputs(tmp_path)
    result = build_trace_target_identities(
        acquisition_summary_path=summary,
        signature_verification_path=verification,
        acquisition_ledger_path=ledger,
        candidate_root=root,
    )
    assert result["target_count"] == 1
    assert result["targets"][0]["reserve_assignment_sha256"] == "1" * 64
    assert result["rpc_authorized"] is False
    assert result["selection_authorized"] is False
    assert result["target_identities_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in result.items()
            if key != "target_identities_sha256"
        }
    )


def test_rejects_tampered_candidate(tmp_path: Path):
    summary, verification, ledger, root = _inputs(tmp_path)
    path = root / f'{"1" * 64}.json'
    row = json.loads(path.read_text())
    row["control_address"] = "0x" + "99" * 20
    path.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(ControlTraceTargetError, match="candidate_self_hash_invalid"):
        build_trace_target_identities(
            acquisition_summary_path=summary,
            signature_verification_path=verification,
            acquisition_ledger_path=ledger,
            candidate_root=root,
        )


def test_rejects_summary_count_mismatch(tmp_path: Path):
    summary, verification, ledger, root = _inputs(tmp_path)
    payload = json.loads(summary.read_text())
    payload["trace_required_count"] = 2
    payload["summary_sha256"] = _canonical_sha(
        {key: value for key, value in payload.items() if key != "summary_sha256"}
    )
    summary.write_text(json.dumps(payload), encoding="utf-8")
    signed = json.loads(verification.read_text())
    signed["summary_sha256"] = _file_sha(summary)
    verification.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(ControlTraceTargetError, match="trace_target_count_mismatch"):
        build_trace_target_identities(
            acquisition_summary_path=summary,
            signature_verification_path=verification,
            acquisition_ledger_path=ledger,
            candidate_root=root,
        )


def _materialization_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    summary, verification, ledger, root = _inputs(tmp_path)
    identities = build_trace_target_identities(
        acquisition_summary_path=summary,
        signature_verification_path=verification,
        acquisition_ledger_path=ledger,
        candidate_root=root,
    )
    identities_path = tmp_path / "trace-target-identities.json"
    identities_path.write_text(json.dumps(identities), encoding="utf-8")

    provider_rows = [
        {
            "provider_id": "provider-parity",
            "provider_family": "family-parity",
            "trace_method": "trace_transaction",
            "known_creation_recovered": True,
        },
        {
            "provider_id": "provider-geth",
            "provider_family": "family-geth",
            "trace_method": "debug_traceTransaction",
            "known_creation_recovered": True,
        },
    ]
    capability = {
        "schema_version": "stage2_control_trace_state_capability.v1",
        "complete": True,
        "chain_count": 1,
        "chains": [{
            "chain": "ethereum",
            "complete": True,
            "known_creation_recovered_by_both": True,
            "provider_count": 2,
            "verified_operator_families": ["family-geth", "family-parity"],
            "providers": provider_rows,
            "errors": [],
        }],
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["report_sha256"] = _canonical_sha(capability)
    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")

    capability_verification = {
        "schema_version": "stage2_control_trace_state_capability_verification.v1",
        "complete": True,
        "report_sha256": capability["report_sha256"],
        "report_file_sha256": _file_sha(capability_path),
        "provider_registry_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "errors": [],
    }
    capability_verification["verification_sha256"] = _canonical_sha(
        capability_verification
    )
    capability_verification_path = tmp_path / "capability-verification.json"
    capability_verification_path.write_text(
        json.dumps(capability_verification), encoding="utf-8"
    )
    return identities_path, capability_path, capability_verification_path


def test_materializes_exact_transaction_scoped_calls_without_authority(tmp_path: Path):
    identities, capability, capability_verification = _materialization_inputs(tmp_path)
    result = materialize_trace_targets(
        target_identities_path=identities,
        capability_report_path=capability,
        capability_verification_path=capability_verification,
    )

    assert result["schema_version"] == "stage2_control_trace_targets.v1"
    assert result["target_count"] == 1
    assert result["provider_registry_verified"] is False
    assert result["rpc_authorized"] is False
    assert result["selection_authorized"] is False
    target = result["targets"][0]
    assert [call["method"] for call in target["calls"]] == [
        "debug_traceTransaction",
        "trace_transaction",
    ]
    assert target["calls"][0]["params"] == [
        target["transaction_hash"],
        {"tracer": "callTracer", "timeout": "120s"},
    ]
    assert target["calls"][1]["params"] == [target["transaction_hash"]]
    assert result["trace_targets_sha256"] == _canonical_sha({
        key: value for key, value in result.items()
        if key != "trace_targets_sha256"
    })


def test_materialization_rejects_capability_verification_tamper(tmp_path: Path):
    identities, capability, capability_verification = _materialization_inputs(tmp_path)
    payload = json.loads(capability_verification.read_text())
    payload["provider_registry_verified"] = True
    capability_verification.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlTraceTargetError, match="capability_verification_self_hash_invalid"):
        materialize_trace_targets(
            target_identities_path=identities,
            capability_report_path=capability,
            capability_verification_path=capability_verification,
        )


def test_materialization_rejects_same_family_pair(tmp_path: Path):
    identities, capability, capability_verification = _materialization_inputs(tmp_path)
    report = json.loads(capability.read_text())
    report["chains"][0]["providers"][1]["provider_family"] = "family-parity"
    report["chains"][0]["verified_operator_families"] = ["family-parity"]
    report["report_sha256"] = _canonical_sha({
        key: value for key, value in report.items() if key != "report_sha256"
    })
    capability.write_text(json.dumps(report), encoding="utf-8")
    verified = json.loads(capability_verification.read_text())
    verified["report_sha256"] = report["report_sha256"]
    verified["report_file_sha256"] = _file_sha(capability)
    verified["verification_sha256"] = _canonical_sha({
        key: value for key, value in verified.items()
        if key != "verification_sha256"
    })
    capability_verification.write_text(json.dumps(verified), encoding="utf-8")

    with pytest.raises(ControlTraceTargetError, match="provider_family_independence"):
        materialize_trace_targets(
            target_identities_path=identities,
            capability_report_path=capability,
            capability_verification_path=capability_verification,
        )
