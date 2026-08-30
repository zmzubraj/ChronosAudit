from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pandas as pd

from chronosaudit_stage2.public_acquisition.control_candidate_attrition_extension import (
    build_control_candidate_attrition_extension,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_attrition_extension_is_smallest_remaining_round_robin_prefix(tmp_path: Path) -> None:
    scope = tmp_path / "scope.csv"
    pd.DataFrame(
        [
            {"case_name": "case-1", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
        ]
    ).to_csv(scope, index=False)
    requirements = tmp_path / "requirements.csv"
    pd.DataFrame(
        [
            {"case_name": "case-1", "controls_required": "1"},
            {"case_name": "case-2", "controls_required": "1"},
        ]
    ).to_csv(requirements, index=False)
    attempted_rows = [
        {
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "bb" * 20,
            "reserve_assignment_sha256": "1" * 64,
        },
        {
            "case_name": "case-2",
            "chain": "ethereum",
            "control_address": "0x" + "cc" * 20,
            "reserve_assignment_sha256": "2" * 64,
        },
    ]
    remaining_rows = [
        {
            "case_name": "case-2",
            "chain": "ethereum",
            "control_address": "0x" + "dd" * 20,
            "reserve_assignment_sha256": "3" * 64,
        },
        {
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "ee" * 20,
            "reserve_assignment_sha256": "4" * 64,
        },
    ]
    attempted = tmp_path / "attempted.csv"
    full_queue = tmp_path / "full.csv"
    _write_csv(attempted, attempted_rows)
    _write_csv(full_queue, attempted_rows + remaining_rows)
    evidence_fields = {
        "effective_status": "COMPLETE",
        "source_index": "0",
        "source_run_binding_sha256": "a" * 64,
        "source_event_sha256": "b" * 64,
        "result_sha256": "c" * 64,
        "result_file_sha256": "d" * 64,
        "result_path": "/tmp/result.json",
        "rejection_reason": "",
    }
    complete = tmp_path / "complete.csv"
    rejected = tmp_path / "rejected.csv"
    _write_csv(complete, [{**attempted_rows[0], **evidence_fields}])
    _write_csv(
        rejected,
        [
            {
                **attempted_rows[1],
                **evidence_fields,
                "effective_status": "TERMINAL_REJECTED",
                "rejection_reason": "mismatch",
            }
        ],
    )
    reconciliation: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_effective_reconciliation.v1",
        "decision": "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED",
        "initial_queue_sha256": _file_sha(attempted),
        "initial_row_count": 2,
        "effective_complete_count": 1,
        "effective_rejected_count": 1,
        "effective_unresolved_count": 0,
        "complete_output_sha256": _file_sha(complete),
        "rejected_output_sha256": _file_sha(rejected),
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    reconciliation["manifest_sha256"] = _sha(reconciliation)
    reconciliation_path = tmp_path / "reconciliation.json"
    reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")
    prior_root = tmp_path / "prior"
    prior_root.mkdir()
    (prior_root / "events.jsonl").write_text("", encoding="utf-8")
    prior_run: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v1",
        "queue_sha256": _file_sha(full_queue),
    }
    prior_run["run_binding_sha256"] = _sha(prior_run)
    (prior_root / "run_manifest.json").write_text(
        json.dumps(prior_run), encoding="utf-8"
    )
    prior_summary: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": prior_run["run_binding_sha256"],
        "queue_row_count": 4,
        "completed_count": 0,
        "terminal_rejected_count": 0,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    prior_summary["summary_sha256"] = _sha(prior_summary)
    prior_summary_path = tmp_path / "prior-summary.json"
    prior_summary_path.write_text(json.dumps(prior_summary), encoding="utf-8")

    manifest = build_control_candidate_attrition_extension(
        original_pair_scope_path=scope,
        expansion_requirements_path=requirements,
        full_queue_path=full_queue,
        attempted_queue_path=attempted,
        reconciliation_manifest_path=reconciliation_path,
        effective_complete_path=complete,
        effective_rejected_path=rejected,
        prior_acquisition_summary_path=prior_summary_path,
        prior_acquisition_root=prior_root,
        output_queue_path=tmp_path / "extension.csv",
    )

    assert manifest["current_maximum_assignable_controls"] == 1
    assert manifest["minimum_extension_prefix_row_count"] == 1
    assert manifest["projected_maximum_assignable_controls_if_all_valid"] == 2
    assert manifest["previous_prefix_maximum_assignable_controls"] == 1
    rows = list(csv.DictReader((tmp_path / "extension.csv").open(encoding="utf-8")))
    assert [row["reserve_assignment_sha256"] for row in rows] == ["3" * 64]
    assert manifest["denominator_admission_authorized"] is False
    assert manifest["counter_authority"] is False
