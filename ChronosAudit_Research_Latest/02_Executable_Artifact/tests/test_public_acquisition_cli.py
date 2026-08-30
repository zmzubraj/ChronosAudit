from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from chronosaudit_stage2.public_acquisition.counters import (
    build_counter_artifact,
    build_review_bundle,
    canonical_manifest_sha256,
    make_independent_adjudication_binding_sha256,
)
from chronosaudit_stage2.public_acquisition.qualification import make_control_row_sha256
from test_historical_snapshots_417_verifier import _build_selected_slice_run

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "run_public_evidence_acquisition.py"
VERIFIER = ROOT / "verify_public_evidence_acquisition.py"
PRODUCTION_QUALIFIER = ROOT / "production_qualification.py"
_RUNNER_SPEC = importlib.util.spec_from_file_location("public_acquisition_runner", RUNNER)
assert _RUNNER_SPEC and _RUNNER_SPEC.loader
public_acquisition_runner = importlib.util.module_from_spec(_RUNNER_SPEC)
sys.modules[_RUNNER_SPEC.name] = public_acquisition_runner
_RUNNER_SPEC.loader.exec_module(public_acquisition_runner)


def _run_cli(
    script: Path,
    *args: str,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, **(env or {})},
    )


def _latest_run(output_root: Path) -> tuple[Path, Path, Path]:
    report_runs = sorted((output_root / "reports" / "public_acquisition").glob("*/*"))
    assert report_runs, "expected at least one report run directory"
    report_run = report_runs[-1]
    revision = report_run.parent.name
    run_id = report_run.name
    return (
        output_root / "raw" / "public_acquisition" / revision / run_id,
        output_root / "processed" / "public_acquisition" / revision / run_id,
        report_run,
    )


def _write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_json(path: Path, payload: object) -> Path:
    return _write_text(path, json.dumps(payload, indent=2, sort_keys=True))


def _read_csv_or_empty(path: str | Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def _resolve_output_path(output_root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else output_root / path


def _make_chainlist_fixture(path: Path) -> Path:
    return _write_json(
        path,
        {
            "chains": [
                {
                    "name": "Ethereum",
                    "chainId": 1,
                    "rpc": [
                        "https://rpc.example/eth",
                        "https://rpc.example/eth?utm_source=tracking",
                    ],
                }
            ]
        },
    )


def _make_s3_page(path: Path, *, key: str, etag: str, size: int = 101) -> Path:
    return _write_text(
        path,
        f"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Contents>
    <Key>{key}</Key>
    <LastModified>2026-08-08T00:00:00Z</LastModified>
    <ETag>"{etag}"</ETag>
    <Size>{size}</Size>
  </Contents>
</ListBucketResult>
""",
    )


def _make_denominator_source(path: Path) -> Path:
    rows = [
        {
            "deployment_id": "dep-eth-1",
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x1111111111111111111111111111111111111111",
            "creation_tx_hash": "0x" + "1" * 64,
            "creation_type": "transaction",
            "deployment_block": 100,
            "deployment_block_hash": "0x" + "2" * 64,
            "deployment_time": "2026-01-01T00:00:00Z",
            "creator_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "runtime_code_sha256": "3" * 64,
            "source_provider": "fixture",
            "source_object_key": "exports/ethereum.csv",
            "source_object_etag": "etag-eth",
            "source_record_sha256": "4" * 64,
            "duplicate_group_id": "5" * 64,
            "admissibility_status": "VERIFIED",
            "exclusion_reason": "",
            "selection_rank_sha256": "6" * 64,
        },
        {
            "deployment_id": "dep-bsc-1",
            "chain": "bsc",
            "chain_id": 56,
            "contract_address": "0x2222222222222222222222222222222222222222",
            "creation_tx_hash": "0x" + "7" * 64,
            "creation_type": "transaction",
            "deployment_block": 200,
            "deployment_block_hash": "0x" + "8" * 64,
            "deployment_time": "2026-01-02T00:00:00Z",
            "creator_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "runtime_code_sha256": "9" * 64,
            "source_provider": "fixture",
            "source_object_key": "exports/bsc.csv",
            "source_object_etag": "etag-bsc",
            "source_record_sha256": "a" * 64,
            "duplicate_group_id": "b" * 64,
            "admissibility_status": "VERIFIED",
            "exclusion_reason": "",
            "selection_rank_sha256": "c" * 64,
        },
        {
            "deployment_id": "dep-base-1",
            "chain": "base",
            "chain_id": 8453,
            "contract_address": "0x3333333333333333333333333333333333333333",
            "creation_tx_hash": "0x" + "d" * 64,
            "creation_type": "transaction",
            "deployment_block": 300,
            "deployment_block_hash": "0x" + "e" * 64,
            "deployment_time": "2026-01-03T00:00:00Z",
            "creator_address": "0xcccccccccccccccccccccccccccccccccccccccc",
            "runtime_code_sha256": "f" * 64,
            "source_provider": "fixture",
            "source_object_key": "exports/base.csv",
            "source_object_etag": "etag-base",
            "source_record_sha256": "1" * 64,
            "duplicate_group_id": "2" * 64,
            "admissibility_status": "VERIFIED",
            "exclusion_reason": "",
            "selection_rank_sha256": "3" * 64,
        },
        {
            "deployment_id": "dep-arb-1",
            "chain": "arbitrum",
            "chain_id": 42161,
            "contract_address": "0x4444444444444444444444444444444444444444",
            "creation_tx_hash": "0x" + "4" * 64,
            "creation_type": "transaction",
            "deployment_block": 400,
            "deployment_block_hash": "0x" + "5" * 64,
            "deployment_time": "2026-01-04T00:00:00Z",
            "creator_address": "0xdddddddddddddddddddddddddddddddddddddddd",
            "runtime_code_sha256": "6" * 64,
            "source_provider": "fixture",
            "source_object_key": "exports/arbitrum.csv",
            "source_object_etag": "etag-arb",
            "source_record_sha256": "7" * 64,
            "duplicate_group_id": "8" * 64,
            "admissibility_status": "VERIFIED",
            "exclusion_reason": "",
            "selection_rank_sha256": "9" * 64,
        },
    ]
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def _make_stringified_bytes_deployment_export(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "chain_id": 1,
            "address": repr(bytes.fromhex("11" * 20)),
            "transaction_hash": repr(bytes.fromhex("aa" * 32)),
            "block_number": 100,
            "created_at": "2026-01-01T00:00:00Z",
            "creation_type": "create",
            "trace_proof": False,
        }
    ]
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def _make_parquet_deployment_export(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.table(
        {
            "chain_id": [1],
            "address": pa.array([bytes.fromhex("11" * 20)], type=pa.binary()),
            "transaction_hash": pa.array([bytes.fromhex("aa" * 32)], type=pa.binary()),
            "block_number": [100],
            "created_at": ["2026-01-01T00:00:00Z"],
            "creation_type": ["create"],
            "trace_proof": [False],
        }
    )
    pq.write_table(table, path)
    return path


def _make_inventory_spec(tmp_path: Path) -> Path:
    chainlist = _make_chainlist_fixture(tmp_path / "fixtures" / "chainlist.json")
    s3_page = _make_s3_page(tmp_path / "fixtures" / "aws-ethereum.xml", key="exports/ethereum.csv", etag="eth-1")
    sourcify_page = _make_s3_page(tmp_path / "fixtures" / "sourcify-full-match.xml", key="full_match/1/metadata.json", etag="src-1")
    denominator_source = _make_denominator_source(tmp_path / "fixtures" / "deployment-source.csv")
    return _write_json(
        tmp_path / "fixtures" / "inventory-spec.json",
        {
            "chainlist": {"source_file": str(chainlist)},
            "s3": [
                {
                    "provider": "fixture_aws",
                    "chain": "ethereum",
                    "prefix": "exports/",
                    "page_files": [str(s3_page)],
                }
            ],
            "sourcify": [
                {
                    "chain": "ethereum",
                    "datasets": {"full_match": [str(sourcify_page)]},
                }
            ],
            "deployment_exports": [
                {
                    "chain": "all",
                    "path": str(denominator_source),
                    "format": "csv",
                }
            ],
        },
    )


def _make_rpc_fixture(path: Path) -> Path:
    return _write_json(
        path,
        {
            "default": {
                "status": "PARTIAL",
                "blocked_reason": "missing_verified_cutoff_evidence",
                "provider_families": ["fixture-a", "fixture-b"],
                "cell_results": {
                    "block_capability": {
                        "status": "VERIFIED",
                        "block_selector": "incident:1",
                        "error_detail": None,
                    },
                    "runtime_code": {
                        "status": "WAITING_EXTERNAL",
                        "block_selector": "prediction:unresolved",
                        "error_detail": "missing_verified_cutoff_evidence",
                    },
                },
                "receipts": [
                    {
                        "method": "eth_getCode",
                        "block_selector": "incident:1",
                        "request": {"method": "eth_getCode", "params": ["0x0", "0x1"]},
                        "response": {"result": "0x6000"},
                    }
                ],
            }
        },
    )


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _request_sha256(method: str, params: list[object]) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _write_response_artifact(raw_run: Path, response_payload: object) -> tuple[str, str]:
    response_bytes = _canonical_json(response_payload).encode("utf-8")
    response_sha256 = hashlib.sha256(response_bytes).hexdigest()
    response_path = raw_run / "responses" / response_sha256[:2] / f"{response_sha256}.json"
    response_path.parent.mkdir(parents=True, exist_ok=True)
    response_path.write_bytes(response_bytes)
    return response_sha256, str(response_path)


def _write_request_artifact(raw_run: Path, method: str, params: list[object]) -> tuple[str, str]:
    request_payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    request_bytes = json.dumps(request_payload, separators=(",", ":")).encode("utf-8")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    request_path = raw_run / "requests" / request_sha256[:2] / f"{request_sha256}.json"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    request_path.write_bytes(request_bytes)
    return request_sha256, str(request_path)


def _cell_results(reason: str = "missing_verified_cutoff_evidence") -> dict[str, dict[str, object]]:
    return {
        "block_capability": {"status": "VERIFIED", "block_selector": "incident:1", "error_detail": None},
        "runtime_code": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "eip1967_implementation_slot": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "eip1967_beacon_slot": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "eip1967_admin_slot": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "beacon_implementation_call": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "implementation_runtime_code": {"status": "WAITING_EXTERNAL", "block_selector": "prediction:unresolved", "error_detail": reason},
        "source_locator": {"status": "WAITING_EXTERNAL", "block_selector": "source", "error_detail": "missing_source_locator"},
        "creation_locator": {"status": "WAITING_EXTERNAL", "block_selector": "creation", "error_detail": "missing_creation_locator"},
    }


def _write_nested_rpc_results_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    plan = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path))
    assert plan.returncode == 0, plan.stderr
    raw_run, processed_run, report_run = _latest_run(tmp_path)
    queue = pd.read_csv(processed_run / "case_queue.csv")
    case = queue.iloc[0].to_dict()

    block_response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"number": "0x1", "hash": "0x" + "a" * 64},
    }
    code_response = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32000, "message": "historical state unavailable"},
    }
    block_sha, block_path = _write_response_artifact(raw_run, block_response)
    code_sha, code_path = _write_response_artifact(raw_run, code_response)
    block_params = [hex(int(case["incident_block"])), False]
    code_params = [str(case["address"]).lower(), {"blockHash": "0x" + "a" * 64, "requireCanonical": True}]
    rate_limit_params = [str(case["address"]).lower(), "latest"]
    nested_row = {
        "case_id": case["case_id"],
        "case_name": case["case_name"],
        "chain": case["chain"],
        "address": str(case["address"]).lower(),
        "incident_block": int(case["incident_block"]),
        "status": "PARTIAL",
        "blocked_reason": "missing_verified_cutoff_evidence",
        "provider_families": [],
        "cell_results": _cell_results(),
        "capability_snapshot": {
            "status": "partial_or_disputed",
            "block": {
                "status": "consensus",
                "value": {"hash": "0x" + "a" * 64},
                "observations": [
                    {
                        "provider_family": "unverified:publicnode",
                        "provider_id": "publicnode-ethereum",
                        "method": "eth_getBlockByNumber",
                        "params": block_params,
                        "request_sha256": _request_sha256("eth_getBlockByNumber", block_params),
                        "response_sha256": block_sha,
                        "raw_response_path": block_path,
                        "http_status": 200,
                        "attempt": 1,
                        "error": None,
                        "observed_at_utc": "2026-08-08T12:27:50Z",
                        "observed_at_unix": 1754656070,
                        "result": block_response["result"],
                    }
                ],
            },
            "code": {
                "status": "partial_or_disputed",
                "observations": [
                    {
                        "provider_family": "unverified:publicnode",
                        "provider_id": "publicnode-ethereum",
                        "method": "eth_getCode",
                        "params": code_params,
                        "request_sha256": _request_sha256("eth_getCode", code_params),
                        "response_sha256": code_sha,
                        "raw_response_path": code_path,
                        "http_status": 200,
                        "attempt": 2,
                        "error": json.dumps(code_response["error"], sort_keys=True),
                        "observed_at_utc": "2026-08-08T12:27:52Z",
                        "observed_at_unix": 1754656072,
                        "result": None,
                    }
                ],
            },
            "rate_limit_probe": {
                "status": "partial_or_disputed",
                "observations": [
                    {
                        "provider_family": "unverified:one-rpc",
                        "provider_id": "one-rpc-ethereum",
                        "method": "eth_getCode",
                        "params": rate_limit_params,
                        "request_sha256": _request_sha256("eth_getCode", rate_limit_params),
                        "response_sha256": None,
                        "raw_response_path": None,
                        "http_status": 429,
                        "attempt": 1,
                        "error": "rate_limited",
                        "observed_at_utc": "2026-08-08T12:27:53Z",
                        "observed_at_unix": 1754656073,
                        "result": None,
                    }
                ],
            },
        },
        "prediction_snapshot": None,
        "receipts": [],
    }
    rpc_results = {
        "summary": {
            "command": "rpc",
            "status": "partial",
            "execute": True,
            "run_id": report_run.name,
            "revision": report_run.parent.name,
            "cases_processed": 1,
            "cases_planned": 1,
            "receipt_count": 0,
            "deadline_seconds": None,
            "ledger_path": str(raw_run / "acquisition_events.jsonl"),
        },
        "results": [nested_row],
    }
    (report_run / "rpc_case_results.json").write_text(json.dumps(rpc_results, indent=2, sort_keys=True), encoding="utf-8")
    (report_run / "rpc_receipts.json").write_text(json.dumps({"summary": rpc_results["summary"], "receipts": []}, indent=2, sort_keys=True), encoding="utf-8")
    run_state_path = report_run / "run_state.json"
    run_state = json.loads(run_state_path.read_text(encoding="utf-8"))
    run_state["cells"]["rpc"] = {"status": "partial", "updated_at_utc": "2026-08-08T12:30:00Z", "details": dict(rpc_results["summary"])}
    run_state_path.write_text(json.dumps(run_state, indent=2, sort_keys=True), encoding="utf-8")
    return raw_run, processed_run, report_run, nested_row


def _make_control_row() -> dict[str, object]:
    row: dict[str, object] = {
        "case_name": "control-case-001",
        "incident_name": "Control Incident",
        "chain": "ethereum",
        "target_contract_address": "0x5555555555555555555555555555555555555555",
        "incident_date": "2026-01-05",
        "candidate_status": "QUALIFIED_CONTROL",
        "match_set_id": "match-set-001",
        "control_rank": 1,
        "positive_prediction_cutoff_time": "2026-01-05T00:00:00Z",
        "deterministic_rank_sha256": "1" * 64,
        "denominator_record_sha256": "2" * 64,
        "source_manifest_sha256": "3" * 64,
        "deployed_by_positive_cutoff": True,
        "identity_linkage_free": True,
        "clone_linkage_free": True,
        "proxy_linkage_free": True,
        "protocol_linkage_free": True,
        "mechanism_separation_free": True,
        "follow_up_start": "2026-01-05T00:00:00Z",
        "follow_up_horizon": "30d",
        "censoring_status": "FROZEN_COMPLETE",
        "investigated_negative_status": "INVESTIGATED_NEGATIVE_MATURE",
        "independent_outcome_review_status": "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
        "independent_outcome_reviewer_identity": "reviewer-c",
        "independent_outcome_reviewer_owner": "owner-c",
        "independent_outcome_reviewer_conflict_clear": True,
        "independent_outcome_reviewer_confidence": "high",
        "independent_outcome_decision_sha256": "4" * 64,
        "maturity_check_passed": True,
        "maturity_check_sha256": "5" * 64,
        "censoring_check_passed": True,
        "censoring_check_sha256": "6" * 64,
        "temporal_check_passed": True,
        "temporal_check_sha256": "7" * 64,
        "lineage_check_passed": True,
        "lineage_check_sha256": "8" * 64,
        "clone_check_passed": True,
        "clone_check_sha256": "9" * 64,
        "proxy_check_passed": True,
        "proxy_check_sha256": "a" * 64,
        "protocol_check_passed": True,
        "protocol_check_sha256": "b" * 64,
        "mechanism_separation_check_passed": True,
        "mechanism_separation_check_sha256": "c" * 64,
    }
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row


def _make_reviewer_row(case_name: str, packet_sha256: str = "d" * 64) -> dict[str, object]:
    row: dict[str, object] = {
        "case_name": case_name,
        "review_decision_status": "FINALIZED_INDEPENDENT_ADJUDICATION",
        "decision_schema_valid": True,
        "decision_hash_bound": True,
        "reviewer_a_identity": "reviewer-a",
        "reviewer_a_owner": "owner-a",
        "reviewer_a_conflict_clear": True,
        "reviewer_a_confidence": "high",
        "reviewer_a_started_at_utc": "2026-08-17T08:00:00Z",
        "reviewer_a_completed_at_utc": "2026-08-17T08:30:00Z",
        "reviewer_a_packet_sha256": packet_sha256,
        "reviewer_a_decision_sha256": "a" * 64,
        "reviewer_b_identity": "reviewer-b",
        "reviewer_b_owner": "owner-b",
        "reviewer_b_conflict_clear": True,
        "reviewer_b_confidence": "very_high",
        "reviewer_b_started_at_utc": "2026-08-17T08:05:00Z",
        "reviewer_b_completed_at_utc": "2026-08-17T08:40:00Z",
        "reviewer_b_packet_sha256": packet_sha256,
        "reviewer_b_decision_sha256": "b" * 64,
        "review_agreement_status": "REVIEWER_CONSENSUS",
        "final_decision_sha256": "c" * 64,
        "final_decision_completed_at_utc": "2026-08-17T08:45:00Z",
        "decision_case_schema_valid": True,
        "decision_case_hash_bound": True,
        "decision_case_stale": False,
        "third_adjudicator_identity": "",
        "third_adjudicator_owner": "",
        "third_adjudicator_conflict_clear": False,
        "third_adjudicator_confidence": "",
        "third_adjudicator_started_at_utc": "",
        "third_adjudicator_completed_at_utc": "",
        "third_adjudicator_packet_sha256": "",
        "third_adjudicator_decision_sha256": "",
    }
    row["final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(row)
    return row


def _latest_run_id(output_root: Path) -> str:
    _raw_run, _processed_run, report_run = _latest_run(output_root)
    return report_run.name


def _run_public_execute(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    inventory_spec = _make_inventory_spec(tmp_path)
    rpc_fixture = _make_rpc_fixture(tmp_path / "fixtures" / "rpc-fixture.json")
    return _run_cli(
        RUNNER,
        "run-public",
        "--output-root",
        str(tmp_path),
        "--execute",
        "--inventory-spec-file",
        str(inventory_spec),
        "--rpc-fixture-file",
        str(rpc_fixture),
        "--max-cases",
        "2",
        "--deadline-seconds",
        "60",
    )


def test_normalize_deployment_export_frame_marks_sourcify_transaction_rows_verified(tmp_path: Path) -> None:
    export_path = _make_stringified_bytes_deployment_export(tmp_path / "fixtures" / "deployment-export.csv")

    normalized = public_acquisition_runner._normalize_deployment_export_frame(
        pd.DataFrame(),
        source_provider="fixture_sourcify",
        source_object_key=str(export_path),
    )

    assert len(normalized) == 1
    assert normalized.loc[0, "contract_address"] == "0x" + "11" * 20
    assert normalized.loc[0, "creation_tx_hash"] == "0x" + "aa" * 32
    assert normalized.loc[0, "source_object_key"] == export_path.name
    assert normalized.loc[0, "admissibility_status"] == "VERIFIED"
    assert pd.isna(normalized.loc[0, "exclusion_reason"])


def test_normalize_deployment_export_frame_fast_path_canonicalizes_stringified_bytes() -> None:
    frame = pd.DataFrame(
        [
            {
                "deployment_id": "dep-fast-1",
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": repr(bytes.fromhex("11" * 20)),
                "creation_tx_hash": repr(bytes.fromhex("aa" * 32)),
                "creation_type": "create",
                "deployment_block": 100,
                "deployment_block_hash": None,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": repr(bytes.fromhex("22" * 20)),
                "runtime_code_sha256": None,
                "source_provider": "preloaded_fixture",
                "source_object_key": "exports/fast-path.csv",
                "source_object_etag": "",
                "source_record_sha256": "d" * 64,
                "duplicate_group_id": "placeholder",
                "admissibility_status": "VERIFIED",
                "exclusion_reason": None,
                "selection_rank_sha256": None,
                "creation_proof_type": "transaction",
            }
        ]
    )

    normalized = public_acquisition_runner._normalize_deployment_export_frame(
        frame,
        source_provider="fallback_fixture",
        source_object_key="ignored.csv",
    )

    assert len(normalized) == 1
    assert normalized.loc[0, "contract_address"] == "0x" + "11" * 20
    assert normalized.loc[0, "creation_tx_hash"] == "0x" + "aa" * 32
    assert normalized.loc[0, "creator_address"] == "0x" + "22" * 20
    assert normalized.loc[0, "source_provider"] == "preloaded_fixture"
    assert normalized.loc[0, "admissibility_status"] == "VERIFIED"


def test_denominator_cli_accepts_parquet_deployment_export(tmp_path: Path) -> None:
    plan_result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), "--run-id", "parquet-denominator-001")
    assert plan_result.returncode == 0, plan_result.stderr
    export_path = _make_parquet_deployment_export(tmp_path / "fixtures" / "deployment-export.parquet")

    result = _run_cli(
        RUNNER,
        "denominator",
        "--output-root",
        str(tmp_path),
        "--run-id",
        "parquet-denominator-001",
        "--execute",
        "--source-file",
        str(export_path),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["command"] == "denominator"
    assert payload["source_errors"] == []
    assert payload["denominator_rows"] == 1

    _raw_run, processed_run, report_run = _latest_run(tmp_path)
    denominator = pd.read_csv(processed_run / "deployment_denominator.csv")
    manifest = json.loads((report_run / "denominator_manifest.json").read_text(encoding="utf-8"))

    assert denominator.loc[0, "contract_address"] == "0x" + "11" * 20
    assert denominator.loc[0, "creation_tx_hash"] == "0x" + "aa" * 32
    assert denominator.loc[0, "source_provider"] == "sourcify_pinned_deployments_export"
    assert manifest["source_errors"] == []


def test_run_manifests_are_relative_and_portable_across_output_roots(tmp_path: Path) -> None:
    source_root = tmp_path / "source-output"
    run_result = _run_public_execute(source_root)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, _processed_run, report_run = _latest_run(source_root)
    queue_manifest = json.loads((report_run / "case_queue_manifest.json").read_text(encoding="utf-8"))
    receipt_manifest = json.loads((report_run / "rpc_receipts.json").read_text(encoding="utf-8"))
    counter_manifest = json.loads((report_run / "public_acquisition_counter_inputs.json").read_text(encoding="utf-8"))

    serialized_paths = [
        queue_manifest["queue_csv_path"],
        queue_manifest["pilot_csv_path"],
        queue_manifest["source_snapshot_path"],
        queue_manifest["positive_snapshot_path"],
        queue_manifest["policy_snapshot_path"],
        *(receipt["request_path"] for receipt in receipt_manifest["receipts"]),
        *(receipt["raw_response_path"] for receipt in receipt_manifest["receipts"] if receipt["raw_response_path"]),
        *(spec["path"] for spec in counter_manifest["inputs"].values()),
    ]
    assert serialized_paths
    assert all(not Path(value).is_absolute() for value in serialized_paths)

    moved_root = tmp_path / "moved-output"
    shutil.copytree(source_root, moved_root)
    verification = _run_cli(VERIFIER, "--output-root", str(moved_root), "--latest")

    assert verification.returncode == 0, verification.stderr
    payload = json.loads(verification.stdout)
    assert payload["structure_valid"] is True
    assert payload["scientifically_complete"] is False

    _moved_raw, _moved_processed, moved_report = _latest_run(moved_root)
    qualification_path = moved_report / "production_qualification.json"
    qualification = _run_cli(
        PRODUCTION_QUALIFIER,
        cwd=ROOT,
        env={
            "CHRONOS_COUNTER_ARTIFACT_PATH": str(moved_report / "public_acquisition_counters.json"),
            "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(moved_report / "public_acquisition_counter_inputs.json"),
            "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(qualification_path),
        },
    )
    assert qualification.returncode == 3
    qualification_payload = json.loads(qualification_path.read_text(encoding="utf-8"))
    assert qualification_payload["counter_input_manifest_errors"] == []
    assert qualification_payload["counter_artifact_errors"] == []


def test_migrate_paths_rebases_legacy_run_references_without_advancing_counters(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr
    _raw_run, _processed_run, report_run = _latest_run(tmp_path)
    legacy_root = tmp_path / "retired-worktree" / "02_Executable_Artifact"

    def legacy_absolute(value: object) -> object:
        if isinstance(value, dict):
            return {key: legacy_absolute(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [legacy_absolute(nested) for nested in value]
        if isinstance(value, str) and not Path(value).is_absolute():
            parts = Path(value).parts
            if len(parts) >= 4 and parts[0] in {"raw", "processed", "reports"} and parts[1] == "public_acquisition":
                return str(legacy_root / value)
        return value

    for name in (
        "case_queue_manifest.json",
        "inventory_manifest.json",
        "denominator_manifest.json",
        "rpc_case_results.json",
        "rpc_receipts.json",
        "run_state.json",
    ):
        path = report_run / name
        payload = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(legacy_absolute(payload), indent=2, sort_keys=True), encoding="utf-8")

    migrated = _run_cli(
        RUNNER,
        "migrate-paths",
        "--output-root",
        str(tmp_path),
        "--run-id",
        report_run.name,
        "--revision",
        report_run.parent.name,
        "--execute",
    )
    assert migrated.returncode == 0, migrated.stderr
    migration_payload = json.loads(migrated.stdout)
    assert migration_payload["replacement_count"] > 0
    assert "scientific counters are not upgraded" in migration_payload["semantics"]

    verification = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")
    assert verification.returncode == 0, verification.stderr
    verification_payload = json.loads(verification.stdout)
    assert verification_payload["structure_valid"] is True
    assert verification_payload["scientifically_complete"] is False
    counters = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))["counters"]
    assert counters["historical_snapshots"]["observed"] == 0
    assert counters["release_eligible_cases"] == 0


def test_project_binds_verified_historical_snapshot_run_and_only_moves_historical_counter(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    before_counters = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))["counters"]
    historical_root = tmp_path / "historical-run"
    _prepared_historical_run, historical_run_root, _cases = _build_selected_slice_run(historical_root)

    result = _run_cli(
        RUNNER,
        "project",
        "--output-root",
        str(tmp_path),
        "--latest",
        "--historical-snapshot-run-root",
        str(historical_run_root),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["command"] == "project"

    manifest = json.loads((report_run / "public_acquisition_counter_inputs.json").read_text(encoding="utf-8"))
    assert "historical_snapshot_verification" in manifest

    counters = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))["counters"]
    assert counters["historical_snapshots"]["required"] == 417
    assert counters["historical_snapshots"]["observed"] == 1
    assert counters["historical_snapshots"]["passed"] is False
    for key, value in before_counters.items():
        if key == "historical_snapshots":
            continue
        assert counters[key] == value

    verification = _run_cli(
        RUNNER,
        "verify",
        "--output-root",
        str(tmp_path),
        "--latest",
    )
    assert verification.returncode == 0, verification.stderr
    verification_payload = json.loads(verification.stdout)
    counter_check = next(
        check for check in verification_payload["checks"] if check["name"] == "counter_projection"
    )
    assert counter_check["passed"] is True

    qualification_output = tmp_path / "production-qualification.json"
    qualification_env = os.environ.copy()
    qualification_env.update(
        {
            "CHRONOS_COUNTER_ARTIFACT_PATH": str(report_run / "public_acquisition_counters.json"),
            "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(report_run / "public_acquisition_counter_inputs.json"),
            "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(qualification_output),
        }
    )
    qualification = subprocess.run(
        [sys.executable, str(ROOT / "production_qualification.py")],
        capture_output=True,
        text=True,
        env=qualification_env,
    )
    assert qualification.returncode == 3
    qualification_payload = json.loads(qualification.stdout)
    assert qualification_payload["counter_input_manifest_errors"] == []
    assert qualification_payload["counter_artifact_errors"] == []
    historical_check = next(
        check for check in qualification_payload["checks"] if check["gate"] == "historical_snapshots"
    )
    assert historical_check["observed"] == 1


def test_project_rejects_invalid_historical_snapshot_without_overwriting_counters(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr
    report_run = _latest_run(tmp_path)[2]
    counter_path = report_run / "public_acquisition_counters.json"
    manifest_path = report_run / "public_acquisition_counter_inputs.json"
    before_counter = counter_path.read_bytes()
    before_manifest = manifest_path.read_bytes()

    _prepared, historical_run_root, _cases = _build_selected_slice_run(tmp_path / "historical-invalid")
    historical_manifest_path = historical_run_root / "run_manifest.json"
    historical_manifest = json.loads(historical_manifest_path.read_text(encoding="utf-8"))
    historical_manifest["authoritative_sha256"] = "0" * 64
    historical_manifest_path.write_text(json.dumps(historical_manifest, sort_keys=True), encoding="utf-8")

    result = _run_cli(
        RUNNER,
        "project",
        "--output-root",
        str(tmp_path),
        "--latest",
        "--historical-snapshot-run-root",
        str(historical_run_root),
    )

    assert result.returncode == 1
    assert "historical_snapshot_verification_failed" in result.stdout
    assert counter_path.read_bytes() == before_counter
    assert manifest_path.read_bytes() == before_manifest


def test_public_verify_rejects_tampered_bound_historical_projection(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr
    report_run = _latest_run(tmp_path)[2]
    _prepared, historical_run_root, _cases = _build_selected_slice_run(tmp_path / "historical-bound")
    projected = _run_cli(
        RUNNER,
        "project",
        "--output-root",
        str(tmp_path),
        "--latest",
        "--historical-snapshot-run-root",
        str(historical_run_root),
    )
    assert projected.returncode == 0, projected.stderr

    bound_projection = report_run / "historical_snapshot_verification" / "historical_snapshot_verified_projection.csv"
    bound_projection.write_bytes(bound_projection.read_bytes() + b"\n")
    verification = _run_cli(RUNNER, "verify", "--output-root", str(tmp_path), "--latest")

    assert verification.returncode == 1
    payload = json.loads(verification.stdout)
    counter_check = next(check for check in payload["checks"] if check["name"] == "counter_projection")
    assert counter_check["passed"] is False
    assert payload["release_ready"] is False


def test_plan_is_offline_and_writes_417_case_manifest(tmp_path: Path) -> None:
    result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path))

    assert result.returncode == 0, result.stderr
    raw_run, processed_run, report_run = _latest_run(tmp_path)
    queue = pd.read_csv(processed_run / "case_queue.csv")
    audit = json.loads((report_run / "pilot_shortfall_audit.json").read_text(encoding="utf-8"))
    summary = json.loads(result.stdout)

    assert summary["command"] == "plan"
    assert summary["offline"] is True
    assert queue.shape[0] == 417
    assert audit["full_case_target"] == 417
    assert audit["pilot_selected"] == 9
    assert audit["pilot_shortfall"] == 1
    assert audit["chains"]["arbitrum"]["allocation_satisfied"] is False
    assert (report_run / "run_state.json").exists()
    assert not (raw_run / "acquisition_events.jsonl").exists()


def test_standalone_mutations_require_explicit_run_identity(tmp_path: Path) -> None:
    plan_result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path))
    assert plan_result.returncode == 0, plan_result.stderr

    inventory_spec = _make_inventory_spec(tmp_path)
    result = _run_cli(
        RUNNER,
        "inventory",
        "--output-root",
        str(tmp_path),
        "--execute",
        "--inventory-spec-file",
        str(inventory_spec),
    )

    assert result.returncode != 0
    assert "--run-id" in result.stderr or "--latest" in result.stderr


@pytest.mark.parametrize("bad_value", ["../escape", "nested/run", "/abs", "..", "a\\b"])
def test_invalid_revision_and_run_id_are_rejected(tmp_path: Path, bad_value: str) -> None:
    result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), "--revision", bad_value)
    assert result.returncode != 0

    result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), "--run-id", bad_value)
    assert result.returncode != 0


def test_explicit_resume_and_non_overwrite_rules(tmp_path: Path) -> None:
    first_plan = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), "--run-id", "resume-safe-001")
    assert first_plan.returncode == 0, first_plan.stderr

    second_plan = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), "--run-id", "resume-safe-001")
    assert second_plan.returncode != 0

    inventory_spec = _make_inventory_spec(tmp_path)
    inventory = _run_cli(
        RUNNER,
        "inventory",
        "--output-root",
        str(tmp_path),
        "--run-id",
        "resume-safe-001",
        "--execute",
        "--inventory-spec-file",
        str(inventory_spec),
    )
    assert inventory.returncode == 0, inventory.stderr
    payload = json.loads(inventory.stdout)
    assert payload["run_id"] == "resume-safe-001"
    assert payload["status"] in {"complete", "partial"}


def test_inventory_execute_uses_fixture_spec_and_respects_page_budget(tmp_path: Path) -> None:
    plan_result = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path))
    assert plan_result.returncode == 0, plan_result.stderr
    run_id = _latest_run_id(tmp_path)
    inventory_spec = _make_inventory_spec(tmp_path)

    result = _run_cli(
        RUNNER,
        "inventory",
        "--output-root",
        str(tmp_path),
        "--run-id",
        run_id,
        "--execute",
        "--inventory-spec-file",
        str(inventory_spec),
        "--max-pages",
        "0",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["execute"] is True
    assert payload["status"] == "partial"
    report_run = _latest_run(tmp_path)[2]
    manifest = json.loads((report_run / "inventory_manifest.json").read_text(encoding="utf-8"))
    assert manifest["completed"] is False
    assert "max_pages_exceeded" in json.dumps(manifest)


def test_run_public_execute_runs_real_stages_and_stays_incomplete(tmp_path: Path) -> None:
    result = _run_public_execute(tmp_path)

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["command"] == "run-public"
    assert payload["execute"] is True
    assert payload["status"] == "partial"
    assert payload["verification"]["structure_valid"] is True
    assert payload["verification"]["scientifically_complete"] is False

    raw_run, processed_run, report_run = _latest_run(tmp_path)
    assert (report_run / "inventory_manifest.json").exists()
    assert (report_run / "rpc_receipts.json").exists()
    assert (processed_run / "deployment_denominator.csv").exists()
    assert (report_run / "public_acquisition_counters.json").exists()
    counter_manifest = json.loads((report_run / "public_acquisition_counter_inputs.json").read_text(encoding="utf-8"))
    assert counter_manifest["artifact_schema_version"] == "2026-08-08.task5"
    assert counter_manifest["counter_targets"] == {
        "deployment_denominator_required": 20000,
        "deployment_denominator_per_chain": {
            "arbitrum": 5000,
            "base": 5000,
            "bsc": 5000,
            "ethereum": 5000,
        },
        "control_candidates_required": 4170,
        "qualified_controls_required": 4170,
        "independent_r5_blocks_required": 120,
    }
    assert (raw_run / "acquisition_events.jsonl").exists()


def test_run_public_execute_obeys_deadline_budget(tmp_path: Path) -> None:
    inventory_spec = _make_inventory_spec(tmp_path)
    rpc_fixture = _make_rpc_fixture(tmp_path / "fixtures" / "rpc-fixture.json")

    result = _run_cli(
        RUNNER,
        "run-public",
        "--output-root",
        str(tmp_path),
        "--execute",
        "--inventory-spec-file",
        str(inventory_spec),
        "--rpc-fixture-file",
        str(rpc_fixture),
        "--deadline-seconds",
        "0",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "partial"
    assert payload["stages"]["rpc"]["status"] == "skipped_deadline"


def test_run_public_execute_reports_waiting_external_when_prerequisites_missing(tmp_path: Path) -> None:
    result = _run_cli(
        RUNNER,
        "run-public",
        "--output-root",
        str(tmp_path),
        "--execute",
        "--deadline-seconds",
        "0",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "waiting_external"
    assert payload["stages"]["inventory"]["status"] == "waiting_external"
    assert payload["stages"]["denominator"]["status"] == "waiting_external"


def test_auto_generated_run_id_collision_fails_closed(tmp_path: Path) -> None:
    fixed_env = {"CHRONOSAUDIT_PUBLIC_ACQ_FIXED_UTC_COMPACT": "20260808T120000Z"}

    first = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), env=fixed_env)
    second = _run_cli(RUNNER, "plan", "--output-root", str(tmp_path), env=fixed_env)

    assert first.returncode == 0, first.stderr
    assert second.returncode != 0
    assert "collision" in second.stderr.lower()


def test_verifier_rejects_receipt_hash_tamper(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    receipt_manifest_path = report_run / "rpc_receipts.json"
    receipt_manifest = json.loads(receipt_manifest_path.read_text(encoding="utf-8"))
    receipt_manifest["receipts"][0]["response_sha256"] = "0" * 64
    receipt_manifest_path.write_text(json.dumps(receipt_manifest, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("receipt" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_missing_queued_rpc_result(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    rpc_results_path = report_run / "rpc_case_results.json"
    rpc_results = json.loads(rpc_results_path.read_text(encoding="utf-8"))
    rpc_results["results"] = rpc_results["results"][:-1]
    rpc_results_path.write_text(json.dumps(rpc_results, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("count mismatch" in failure for failure in payload["integrity_failures"])


def test_verifier_accepts_explicit_not_attempted_rpc_rows(tmp_path: Path) -> None:
    result = _run_cli(
        RUNNER,
        "run-public",
        "--output-root",
        str(tmp_path),
        "--execute",
        "--inventory-spec-file",
        str(_make_inventory_spec(tmp_path)),
        "--rpc-fixture-file",
        str(_make_rpc_fixture(tmp_path / "fixtures" / "rpc-fixture.json")),
        "--deadline-seconds",
        "0",
    )
    assert result.returncode == 0, result.stderr

    verification = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")
    assert verification.returncode == 0, verification.stderr
    payload = json.loads(verification.stdout)
    assert payload["structure_valid"] is True
    assert payload["scientifically_complete"] is False


def test_verifier_rejects_unknown_rpc_case_id(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    rpc_results_path = report_run / "rpc_case_results.json"
    rpc_results = json.loads(rpc_results_path.read_text(encoding="utf-8"))
    rpc_results["results"][0]["case_id"] = "unknown-case-id"
    rpc_results_path.write_text(json.dumps(rpc_results, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("unknown rpc case_id" in failure for failure in payload["integrity_failures"])


def test_production_qualification_accepts_cli_generated_manifest_hashes(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, _processed_run, report_run = _latest_run(tmp_path)
    output_path = report_run / "production_qualification.json"
    completed = _run_cli(
        PRODUCTION_QUALIFIER,
        cwd=ROOT,
        env={
            "CHRONOS_COUNTER_ARTIFACT_PATH": str(report_run / "public_acquisition_counters.json"),
            "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(report_run / "public_acquisition_counter_inputs.json"),
            "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
        },
    )

    assert completed.returncode == 3
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["qualified"] is False
    assert not any(error.startswith("input_file_sha256_mismatch:") for error in payload["counter_artifact_errors"])


def test_verifier_rejects_missing_receipt_artifact(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    receipt_manifest = json.loads((report_run / "rpc_receipts.json").read_text(encoding="utf-8"))
    raw_path = _resolve_output_path(tmp_path, receipt_manifest["receipts"][0]["raw_response_path"])
    raw_path.unlink()

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("receipt" in failure for failure in payload["integrity_failures"])


def test_rpc_execute_recovers_nested_observations_into_receipts(tmp_path: Path) -> None:
    _raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)

    result = _run_cli(
        RUNNER,
        "rpc",
        "--output-root",
        str(tmp_path),
        "--run-id",
        report_run.name,
        "--revision",
        report_run.parent.name,
        "--execute",
        "--max-cases",
        "1",
        "--rpc-fixture-file",
        str(_make_rpc_fixture(tmp_path / "fixtures" / "rpc-fixture.json")),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    receipt_manifest = json.loads((report_run / "rpc_receipts.json").read_text(encoding="utf-8"))
    assert payload["status"] == "partial"
    assert len(receipt_manifest["receipts"]) == 3
    assert all(_resolve_output_path(tmp_path, receipt["request_path"]).exists() for receipt in receipt_manifest["receipts"])
    request_only_receipts = [receipt for receipt in receipt_manifest["receipts"] if receipt["response_sha256"] is None]
    assert len(request_only_receipts) == 1
    assert request_only_receipts[0]["raw_response_path"] is None
    assert request_only_receipts[0]["http_status"] == 429
    assert request_only_receipts[0]["error"] == "rate_limited"
    assert payload["receipt_recovery"]["request_only_error_receipt_count"] == 1
    assert payload["receipt_recovery"]["bindable_response_receipt_count"] == 2
    assert payload["receipt_recovery"]["nested_observation_count"] == 3
    recovered_results = json.loads((report_run / "rpc_case_results.json").read_text(encoding="utf-8"))
    assert recovered_results["results"][0]["capability_snapshot"] == nested_row["capability_snapshot"]


def test_rpc_execute_rejects_successful_request_only_observation_recovery(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    nested_row["capability_snapshot"]["rate_limit_probe"]["observations"][0]["http_status"] = 200
    nested_row["capability_snapshot"]["rate_limit_probe"]["observations"][0]["error"] = None
    rpc_results_path = report_run / "rpc_case_results.json"
    rpc_receipts_path = report_run / "rpc_receipts.json"
    original_results_bytes = rpc_results_path.read_bytes()
    original_receipts_bytes = rpc_receipts_path.read_bytes()
    rpc_results = json.loads(rpc_results_path.read_text(encoding="utf-8"))
    rpc_results["results"][0] = nested_row
    rpc_results_path.write_text(json.dumps(rpc_results, indent=2, sort_keys=True), encoding="utf-8")
    mutated_results_bytes = rpc_results_path.read_bytes()

    result = _run_cli(
        RUNNER,
        "rpc",
        "--output-root",
        str(tmp_path),
        "--run-id",
        report_run.name,
        "--revision",
        report_run.parent.name,
        "--execute",
        "--max-cases",
        "1",
        "--rpc-fixture-file",
        str(_make_rpc_fixture(tmp_path / "fixtures" / "rpc-fixture.json")),
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert "successful request-only" in payload["error"] or "response evidence" in payload["error"]
    assert not (report_run / "rpc_receipt_recovery_audit.json").exists()
    requests_root = raw_run / "requests"
    assert not requests_root.exists()
    assert rpc_results_path.read_bytes() == mutated_results_bytes
    assert rpc_receipts_path.read_bytes() == original_receipts_bytes


def _write_receipt_manifest_from_nested_row(raw_run: Path, report_run: Path, nested_row: dict[str, object]) -> list[dict[str, object]]:
    block_observation = nested_row["capability_snapshot"]["block"]["observations"][0]
    code_observation = nested_row["capability_snapshot"]["code"]["observations"][0]
    rate_limit_observation = nested_row["capability_snapshot"]["rate_limit_probe"]["observations"][0]
    block_request_sha, block_request_path = _write_request_artifact(raw_run, block_observation["method"], block_observation["params"])
    code_request_sha, code_request_path = _write_request_artifact(raw_run, code_observation["method"], code_observation["params"])
    rate_limit_request_sha, rate_limit_request_path = _write_request_artifact(raw_run, rate_limit_observation["method"], rate_limit_observation["params"])
    receipts = [
        {
            "case_id": nested_row["case_id"],
            "receipt_index": 1,
            "method": block_observation["method"],
            "provider_family": block_observation["provider_family"],
            "provider_id": block_observation["provider_id"],
            "params": block_observation["params"],
            "request_sha256": block_request_sha,
            "request_path": block_request_path,
            "response_sha256": block_observation["response_sha256"],
            "raw_response_path": block_observation["raw_response_path"],
            "http_status": block_observation["http_status"],
            "attempt": block_observation["attempt"],
            "observed_at_utc": block_observation["observed_at_utc"],
            "error": block_observation["error"],
        },
        {
            "case_id": nested_row["case_id"],
            "receipt_index": 2,
            "method": code_observation["method"],
            "provider_family": code_observation["provider_family"],
            "provider_id": code_observation["provider_id"],
            "params": code_observation["params"],
            "request_sha256": code_request_sha,
            "request_path": code_request_path,
            "response_sha256": code_observation["response_sha256"],
            "raw_response_path": code_observation["raw_response_path"],
            "http_status": code_observation["http_status"],
            "attempt": code_observation["attempt"],
            "observed_at_utc": code_observation["observed_at_utc"],
            "error": code_observation["error"],
        },
        {
            "case_id": nested_row["case_id"],
            "receipt_index": 3,
            "method": rate_limit_observation["method"],
            "provider_family": rate_limit_observation["provider_family"],
            "provider_id": rate_limit_observation["provider_id"],
            "params": rate_limit_observation["params"],
            "request_sha256": rate_limit_request_sha,
            "request_path": rate_limit_request_path,
            "response_sha256": None,
            "raw_response_path": None,
            "http_status": rate_limit_observation["http_status"],
            "attempt": rate_limit_observation["attempt"],
            "observed_at_utc": rate_limit_observation["observed_at_utc"],
            "error": rate_limit_observation["error"],
        },
    ]
    rpc_results_path = report_run / "rpc_case_results.json"
    rpc_results = json.loads(rpc_results_path.read_text(encoding="utf-8"))
    rpc_results["results"][0]["receipts"] = [
        {
            "case_id": receipt["case_id"],
            "receipt_index": receipt["receipt_index"],
            "request_sha256": receipt["request_sha256"],
            "response_sha256": receipt["response_sha256"],
        }
        for receipt in receipts
    ]
    rpc_results_path.write_text(json.dumps(rpc_results, indent=2, sort_keys=True), encoding="utf-8")
    (report_run / "rpc_receipts.json").write_text(
        json.dumps({"summary": rpc_results["summary"], "receipts": receipts}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return receipts


def test_verifier_rejects_orphan_raw_response_files(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)
    _write_response_artifact(raw_run, {"jsonrpc": "2.0", "id": 1, "result": "orphan"})

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("orphan" in failure for failure in payload["integrity_failures"])


def test_verifier_accepts_request_only_error_receipt_shape(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is True


def test_verifier_rejects_response_sha_without_path(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    receipts = _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)
    receipts[2]["response_sha256"] = "a" * 64
    (report_run / "rpc_receipts.json").write_text(json.dumps({"summary": json.loads((report_run / "rpc_case_results.json").read_text(encoding="utf-8"))["summary"], "receipts": receipts}, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("response" in failure and "path" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_path_without_response_sha(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    receipts = _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)
    orphan_sha, orphan_path = _write_response_artifact(raw_run, {"jsonrpc": "2.0", "id": 1, "error": {"code": 503, "message": "unavailable"}})
    receipts[2]["raw_response_path"] = orphan_path
    receipts[2]["response_sha256"] = None
    (report_run / "rpc_receipts.json").write_text(json.dumps({"summary": json.loads((report_run / "rpc_case_results.json").read_text(encoding="utf-8"))["summary"], "receipts": receipts}, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("response" in failure and "sha" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_success_observation_without_response_evidence(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    receipts = _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)
    receipts[2]["http_status"] = 200
    receipts[2]["error"] = None
    (report_run / "rpc_receipts.json").write_text(json.dumps({"summary": json.loads((report_run / "rpc_case_results.json").read_text(encoding="utf-8"))["summary"], "receipts": receipts}, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("successful" in failure or "response evidence" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_request_only_receipt_request_mismatch(tmp_path: Path) -> None:
    raw_run, _processed_run, report_run, nested_row = _write_nested_rpc_results_fixture(tmp_path)
    receipts = _write_receipt_manifest_from_nested_row(raw_run, report_run, nested_row)
    receipts[2]["request_sha256"] = "0" * 64
    (report_run / "rpc_receipts.json").write_text(json.dumps({"summary": json.loads((report_run / "rpc_case_results.json").read_text(encoding="utf-8"))["summary"], "receipts": receipts}, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("request reconstruction hash mismatch" in failure or "request artifact hash mismatch" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_manifest_path_escape(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    manifest_path = report_run / "public_acquisition_counter_inputs.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"]["positive_cases"]["path"] = str(tmp_path.parent / "escape.csv")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any(
        "outside run root" in failure
        or "containment" in failure
        or "manifest_sha256_mismatch" in failure
        or "counter input manifest validation failed" in failure
        for failure in payload["integrity_failures"]
    )


def test_verifier_rejects_malformed_counter_target_value(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    manifest_path = report_run / "public_acquisition_counter_inputs.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["counter_targets"]["deployment_denominator_required"] = "oops"
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("counter input manifest validation failed" in failure or "invalid_counter_target_value:deployment_denominator_required" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_downgraded_self_consistent_counter_targets(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, processed_run, report_run = _latest_run(tmp_path)
    manifest_path = report_run / "public_acquisition_counter_inputs.json"
    artifact_path = report_run / "public_acquisition_counters.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lowered_targets = {
        "deployment_denominator_required": 1,
        "deployment_denominator_per_chain": {
            "ethereum": 1,
            "bsc": 0,
            "base": 0,
            "arbitrum": 0,
        },
        "control_candidates_required": 1,
        "qualified_controls_required": 1,
        "independent_r5_blocks_required": 0,
    }
    manifest["counter_targets"] = lowered_targets
    manifest["minimum_independent_r5_blocks"] = 0
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    evidence = {
        "positive_cases": public_acquisition_runner._projectable_positive_cases(
            _read_csv_or_empty(_resolve_output_path(tmp_path, manifest["inputs"]["positive_cases"]["path"]))
        ),
        "deployment_denominator": _read_csv_or_empty(_resolve_output_path(tmp_path, manifest["inputs"]["deployment_denominator"]["path"])),
        "control_rows": _read_csv_or_empty(_resolve_output_path(tmp_path, manifest["inputs"]["control_rows"]["path"])),
        "positive_case_review_packets": json.loads(_resolve_output_path(tmp_path, manifest["inputs"]["positive_case_review_packets"]["path"]).read_text(encoding="utf-8")),
        "control_review_packets": json.loads(_resolve_output_path(tmp_path, manifest["inputs"]["control_review_packets"]["path"]).read_text(encoding="utf-8")),
        "finalized_positive_adjudications": json.loads(_resolve_output_path(tmp_path, manifest["inputs"]["finalized_positive_adjudications"]["path"]).read_text(encoding="utf-8")),
        "minimum_independent_r5_blocks": 0,
        "counter_targets": lowered_targets,
    }
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("counter input manifest validation failed" in failure or "counter_targets_canonical_mismatch" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_duplicate_denominator_identity(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    processed_run = _latest_run(tmp_path)[1]
    denominator_path = processed_run / "deployment_denominator.csv"
    denominator = pd.read_csv(denominator_path)
    denominator = pd.concat([denominator, denominator.iloc[[0]]], ignore_index=True)
    denominator.to_csv(denominator_path, index=False)

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("duplicate" in failure for failure in payload["integrity_failures"])


def test_verifier_allows_same_contract_address_on_different_supported_chains(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    processed_run = _latest_run(tmp_path)[1]
    denominator_path = processed_run / "deployment_denominator.csv"
    denominator = pd.read_csv(denominator_path)
    shared_address = "0x" + "ab" * 20
    denominator.loc[0, "chain"] = "ethereum"
    denominator.loc[0, "chain_id"] = 1
    denominator.loc[0, "contract_address"] = shared_address
    denominator.loc[1, "chain"] = "bsc"
    denominator.loc[1, "chain_id"] = 56
    denominator.loc[1, "contract_address"] = shared_address
    denominator.loc[1, "deployment_id"] = str(denominator.loc[1, "deployment_id"]) + "-bsc"
    denominator.loc[1, "creation_tx_hash"] = "0x" + "cd" * 32
    denominator.loc[1, "source_record_sha256"] = "e" * 64
    denominator.to_csv(denominator_path, index=False)

    report_run = _latest_run(tmp_path)[2]
    manifest_path = report_run / "denominator_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["denominator_csv_sha256"] = hashlib.sha256(denominator_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    counter_manifest_path = report_run / "public_acquisition_counter_inputs.json"
    counter_artifact_path = report_run / "public_acquisition_counters.json"
    counter_manifest = json.loads(counter_manifest_path.read_text(encoding="utf-8"))
    counter_manifest["inputs"]["deployment_denominator"]["sha256"] = hashlib.sha256(denominator_path.read_bytes()).hexdigest()
    counter_manifest["input_manifest_sha256"] = canonical_manifest_sha256(counter_manifest)
    counter_manifest_path.write_text(json.dumps(counter_manifest, indent=2, sort_keys=True), encoding="utf-8")
    evidence = {
        "positive_cases": public_acquisition_runner._projectable_positive_cases(
            _read_csv_or_empty(_resolve_output_path(tmp_path, counter_manifest["inputs"]["positive_cases"]["path"]))
        ),
        "deployment_denominator": _read_csv_or_empty(_resolve_output_path(tmp_path, counter_manifest["inputs"]["deployment_denominator"]["path"])),
        "control_rows": _read_csv_or_empty(_resolve_output_path(tmp_path, counter_manifest["inputs"]["control_rows"]["path"])),
        "positive_case_review_packets": json.loads(_resolve_output_path(tmp_path, counter_manifest["inputs"]["positive_case_review_packets"]["path"]).read_text(encoding="utf-8")),
        "control_review_packets": json.loads(_resolve_output_path(tmp_path, counter_manifest["inputs"]["control_review_packets"]["path"]).read_text(encoding="utf-8")),
        "finalized_positive_adjudications": json.loads(_resolve_output_path(tmp_path, counter_manifest["inputs"]["finalized_positive_adjudications"]["path"]).read_text(encoding="utf-8")),
        "minimum_independent_r5_blocks": int(counter_manifest["minimum_independent_r5_blocks"]),
        "counter_targets": counter_manifest["counter_targets"],
    }
    counter_artifact = build_counter_artifact(evidence, input_manifest_sha256=counter_manifest["input_manifest_sha256"])
    counter_artifact_path.write_text(json.dumps(counter_artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    check = next(check for check in payload["checks"] if check["name"] == "deployment_denominator")
    assert check["passed"] is True
    assert payload["structure_valid"] is True
    assert not any("duplicate chain-scoped deployment identity detected" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_same_chain_duplicate_contract_address(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    processed_run = _latest_run(tmp_path)[1]
    denominator_path = processed_run / "deployment_denominator.csv"
    denominator = pd.read_csv(denominator_path)
    denominator.loc[1, "chain"] = str(denominator.loc[0, "chain"])
    denominator.loc[1, "chain_id"] = int(denominator.loc[0, "chain_id"])
    denominator.loc[1, "contract_address"] = str(denominator.loc[0, "contract_address"])
    denominator.loc[1, "deployment_id"] = str(denominator.loc[1, "deployment_id"]) + "-same-chain"
    denominator.loc[1, "creation_tx_hash"] = "0x" + "ef" * 32
    denominator.loc[1, "source_record_sha256"] = "f" * 64
    denominator.to_csv(denominator_path, index=False)

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("duplicate chain-scoped deployment identity detected" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_denominator_missing_chain_identity_column(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    processed_run = _latest_run(tmp_path)[1]
    denominator_path = processed_run / "deployment_denominator.csv"
    denominator = pd.read_csv(denominator_path).drop(columns=["chain"])
    denominator.to_csv(denominator_path, index=False)

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any("denominator missing required identity columns: chain" in failure for failure in payload["integrity_failures"])


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("deployment_id", None),
        ("chain", "   "),
        ("contract_address", ""),
    ],
)
def test_verifier_rejects_blank_denominator_identity_values(tmp_path: Path, field: str, bad_value: object) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    processed_run = _latest_run(tmp_path)[1]
    denominator_path = processed_run / "deployment_denominator.csv"
    denominator = pd.read_csv(denominator_path)
    denominator.loc[0, field] = bad_value
    denominator.to_csv(denominator_path, index=False)

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is False
    assert any(f"denominator identity field contains blank values: {field}" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_tampered_control_review_packet(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, processed_run, report_run = _latest_run(tmp_path)
    control_rows = pd.DataFrame([_make_control_row()])
    control_rows.to_csv(processed_run / "control_candidates.csv", index=False)
    packets = build_review_bundle(control_rows, packet_type="control_review_packets", blinding_seed=report_run.name)
    packets[0]["packet_sha256"] = "0" * 64
    (report_run / "control_review_packets.json").write_text(json.dumps(packets, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("control review packet" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_duplicate_control_packet_id(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, processed_run, report_run = _latest_run(tmp_path)
    control_rows = pd.DataFrame([_make_control_row(), {**_make_control_row(), "case_name": "control-case-002", "control_rank": 2, "control_row_sha256": ""}])
    control_rows.loc[1, "control_row_sha256"] = make_control_row_sha256(control_rows.loc[1].to_dict())
    control_rows.to_csv(processed_run / "control_candidates.csv", index=False)
    packets = build_review_bundle(control_rows, packet_type="control_review_packets", blinding_seed=report_run.name)
    packets[1]["packet_id"] = packets[0]["packet_id"]
    (report_run / "control_review_packets.json").write_text(json.dumps(packets, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("duplicate control_review_packets packet_id" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_spoofed_reviewer_placeholder_complete(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    (report_run / "reviewer_independence.json").write_text(
        json.dumps({"status": "complete"}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("reviewer independence" in failure for failure in payload["integrity_failures"])


def test_verifier_accepts_valid_reviewer_fixture_without_promoting_release(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, _processed_run, report_run = _latest_run(tmp_path)
    positive_packets = json.loads((report_run / "positive_case_review_packets.json").read_text(encoding="utf-8"))
    reviewer_rows = [
        _make_reviewer_row(
            positive_packets[0]["visible_payload"]["case_name"],
            positive_packets[0]["packet_sha256"],
        )
    ]
    (report_run / "finalized_positive_adjudications.json").write_text(json.dumps(reviewer_rows, indent=2, sort_keys=True), encoding="utf-8")
    (report_run / "reviewer_independence.json").write_text(
        json.dumps({"status": "complete", "reviewed_cases": 1}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    rerun_project = _run_cli(RUNNER, "project", "--output-root", str(tmp_path), "--run-id", report_run.name)
    assert rerun_project.returncode == 0, rerun_project.stderr
    counters = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))["counters"]
    assert counters["independent_adjudications"]["observed"] == 1
    assert counters["independent_adjudications"]["passed"] is False

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is True
    assert payload["release_ready"] is False
    assert len(positive_packets) > len(reviewer_rows)
    assert any("reviewer independence artifacts do not yet cover" in gap for gap in payload["scientific_gaps"])


def test_ai_only_track_is_generated_without_changing_human_counter(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    _raw_run, _processed_run, report_run = _latest_run(tmp_path)
    before = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))

    result = _run_cli(
        RUNNER,
        "ai-adjudication-track",
        "--output-root",
        str(tmp_path),
        "--run-id",
        report_run.name,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "READY_NOT_EXECUTED"
    assert payload["case_count"] == 417
    assert payload["human_independent_adjudication_counter_effect"] == "NONE"
    ai_dir = report_run / "ai_only_adjudication"
    assert (ai_dir / "ai_adjudication_manifest.json").exists()
    summary = json.loads((ai_dir / "ai_adjudication_summary.json").read_text(encoding="utf-8"))
    assert summary["independently_ai_adjudicated"]["observed"] == 0
    assert summary["human_independent_adjudications"]["observed"] == 0

    after = json.loads((report_run / "public_acquisition_counters.json").read_text(encoding="utf-8"))
    assert after == before


def test_verifier_rejects_tampered_ai_only_track_artifact(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    summary_path = report_run / "ai_only_adjudication" / "ai_adjudication_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["human_independent_adjudications"]["observed"] = 417
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("AI-only adjudication" in failure for failure in payload["integrity_failures"])


def test_verifier_rejects_release_false_positive_projection(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    report_run = _latest_run(tmp_path)[2]
    release_path = report_run / "release_predicates.json"
    release_payload = json.loads(release_path.read_text(encoding="utf-8"))
    release_payload["release_eligible_cases"] = 1
    release_path.write_text(json.dumps(release_payload, indent=2, sort_keys=True), encoding="utf-8")

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert any("release predicates" in failure or "release_eligible_cases" in failure for failure in payload["integrity_failures"])


def test_verifier_reports_structural_incomplete_without_promoting_release(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["structure_valid"] is True
    assert payload["scientifically_complete"] is False
    assert payload["release_ready"] is False
    assert payload["scientific_gaps"]
    gap_text = " ".join(payload["scientific_gaps"]).lower()
    assert "review" in gap_text
    assert "r5" in gap_text
    assert "release" in gap_text


def test_verifier_reconciles_completed_amendment_a2_pilot(tmp_path: Path) -> None:
    run_result = _run_public_execute(tmp_path)
    assert run_result.returncode == 0, run_result.stderr

    a2_report = tmp_path / "reports" / "public_acquisition" / "2026-08-09" / "evidence-grade-pilot-amendment-a2"
    a2_processed = tmp_path / "processed" / "public_acquisition" / "2026-08-09" / "evidence-grade-pilot-amendment-a2"
    a2_processed.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        [
            {"case_name": "arb-1", "chain": "arbitrum"},
            {"case_name": "arb-2", "chain": "arbitrum"},
            {"case_name": "arb-3", "chain": "arbitrum"},
            {"case_name": "bsc-1", "chain": "bsc"},
            {"case_name": "bsc-2", "chain": "bsc"},
            {"case_name": "bsc-3", "chain": "bsc"},
            {"case_name": "eth-1", "chain": "ethereum"},
            {"case_name": "eth-2", "chain": "ethereum"},
            {"case_name": "eth-3", "chain": "ethereum"},
            {"case_name": "base-1", "chain": "base"},
        ]
    ).to_csv(a2_processed / "pilot_case_queue_amended.csv", index=False)
    _write_json(
        a2_report / "pilot_closure_report.json",
        {
            "cases_attempted": 10,
            "disposition": "COMPLETE",
            "pilot_case_count": 10,
            "release_eligible": False,
            "status": "complete",
            "strict_snapshots_closed": 10,
        },
    )

    result = _run_cli(VERIFIER, "--output-root", str(tmp_path), "--latest")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    a2_check = next(check for check in payload["checks"] if check["name"] == "evidence_grade_pilot_amendment_a2")
    assert a2_check["passed"] is True
    assert not any("pilot remains scientifically incomplete" in gap for gap in payload["scientific_gaps"])
    assert payload["release_ready"] is False
