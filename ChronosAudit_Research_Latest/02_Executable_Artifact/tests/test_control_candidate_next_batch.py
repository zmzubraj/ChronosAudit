from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pandas as pd

from chronosaudit_stage2.public_acquisition.control_candidate_next_batch import (
    build_control_candidate_next_batch,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def test_next_batch_is_smallest_round_robin_prefix_reaching_capacity(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.csv"
    pd.DataFrame(
        [
            {"case_name": "case-1", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
            {"case_name": "case-2", "chain": "ethereum", "control_address": "0x" + "aa" * 20},
        ]
    ).to_csv(scope_path, index=False)
    requirements_path = tmp_path / "requirements.csv"
    pd.DataFrame(
        [
            {"case_name": "case-1", "controls_required": 1},
            {"case_name": "case-2", "controls_required": 1},
        ]
    ).to_csv(requirements_path, index=False)
    queue_path = tmp_path / "queue.csv"
    fields = ["case_name", "chain", "control_address", "reserve_assignment_sha256"]
    with queue_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            [
                {
                    "case_name": "case-1",
                    "chain": "ethereum",
                    "control_address": "0x" + "bb" * 20,
                    "reserve_assignment_sha256": "b" * 64,
                },
                {
                    "case_name": "case-2",
                    "chain": "ethereum",
                    "control_address": "0x" + "cc" * 20,
                    "reserve_assignment_sha256": "c" * 64,
                },
            ]
        )
    acquisition_root = tmp_path / "acquisition"
    acquisition_root.mkdir()
    (acquisition_root / "events.jsonl").write_text("", encoding="utf-8")
    run_body: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v1",
        "queue_sha256": hashlib.sha256(queue_path.read_bytes()).hexdigest(),
    }
    run_body["run_binding_sha256"] = _sha(run_body)
    (acquisition_root / "run_manifest.json").write_text(json.dumps(run_body), encoding="utf-8")
    summary: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run_body["run_binding_sha256"],
        "queue_row_count": 2,
        "completed_count": 0,
        "remaining_count": 2,
        "terminal_rejected_count": 0,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    output_csv = tmp_path / "next.csv"

    manifest = build_control_candidate_next_batch(
        original_pair_scope_path=scope_path,
        expansion_requirements_path=requirements_path,
        full_queue_path=queue_path,
        acquisition_summary_path=summary_path,
        acquisition_root=acquisition_root,
        output_queue_path=output_csv,
    )

    rows = list(csv.DictReader(output_csv.open(encoding="utf-8")))
    assert [row["case_name"] for row in rows] == ["case-1"]
    assert manifest["current_maximum_assignable_controls"] == 1
    assert manifest["minimum_pending_prefix_row_count"] == 1
    assert manifest["projected_maximum_assignable_controls_if_all_valid"] == 2
    assert manifest["previous_prefix_maximum_assignable_controls"] == 1
    assert manifest["rpc_authorized"] is False
    assert manifest["selection_authorized"] is False
    assert manifest["manifest_sha256"] == _sha(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
