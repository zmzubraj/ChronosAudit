from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import chronosaudit_stage2.public_acquisition.historical_snapshot_run as snapshot_run_module
from chronosaudit_stage2.public_acquisition.strict_snapshot import STRICT_HISTORICAL_STATUS
from test_historical_snapshot_batch import (
    _prepare_run,
    _sealed_case_envelope,
    _sealed_transition,
    _selected_cases,
    _strict_provider,
)
from test_public_acquisition_strict_snapshot import (
    _rehash_snapshot as _rehash_strict_snapshot,
    _strict_snapshot as _strict_snapshot_template,
)

from chronosaudit_stage2.public_acquisition.historical_snapshot_verifier import (
    verify_historical_snapshot_run,
)


ROOT = Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _rewrite_manifest_hashes(run_manifest: dict[str, Any]) -> None:
    run_manifest["binding_sha256"] = snapshot_run_module._sha256_json(run_manifest["binding"])
    run_manifest["authoritative_sha256"] = snapshot_run_module._sha256_json(
        {
            "binding_sha256": run_manifest["binding_sha256"],
            "frozen_inputs_sha256": snapshot_run_module._sha256_json(run_manifest["frozen_inputs"]["entries"]),
            "aggregate_paths": run_manifest["aggregate_paths"],
            "aggregate_hashes": run_manifest["aggregate_hashes"],
            "summary": run_manifest["summary"],
        }
    )


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _strict_snapshot_for_selected_case(
    receipt_root: Path,
    *,
    case: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    snapshot = _strict_snapshot_template(receipt_root)
    snapshot["provider_identity"] = {
        "complete": True,
        "families": [
            {
                "family_id": "family-one",
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": "3" * 64,
                "evidence": [
                    {
                        "provider_id": "provider-a",
                        "provider_identity": "identity-a",
                        "endpoint_template_sha256": "3" * 64,
                        "operator_evidence_url": "https://operators.example/family-one",
                    }
                ],
            },
            {
                "family_id": "family-two",
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": "4" * 64,
                "evidence": [
                    {
                        "provider_id": "provider-b",
                        "provider_identity": "identity-b",
                        "endpoint_template_sha256": "4" * 64,
                        "operator_evidence_url": "https://operators.example/family-two",
                    }
                ],
            },
        ],
    }
    snapshot["case_id"] = str(case["case_id"])
    snapshot["case_name"] = str(case["case_name"])
    snapshot["chain"] = str(case["chain"])
    snapshot["address"] = str(case["address"]).lower()
    snapshot["incident_block"] = int(case["incident_block"])
    snapshot["case_input"] = dict(case)
    snapshot["case_input_sha256"] = snapshot_run_module._sha256_json(case)
    snapshot["policy_input"] = dict(policy)
    snapshot["policy_sha256"] = snapshot_run_module._sha256_json(snapshot["policy_input"])
    snapshot["provider_identity_sha256"] = snapshot_run_module._sha256_json(snapshot["provider_identity"])
    for field in (
        "deployment_transition",
        "cutoff_search",
        "cutoff_bracket",
        "incident_block_consensus",
    ):
        payload = snapshot.get(field) or {}
        if not isinstance(payload, dict):
            continue
        _normalize_receipt_paths(payload)
    _normalize_receipt_paths(snapshot.get("state_cells") or {})
    return _rehash_strict_snapshot(snapshot)


def _normalize_receipt_paths(value: Any) -> None:
    if isinstance(value, dict):
        raw_path = value.get("raw_response_path")
        if isinstance(raw_path, str) and raw_path:
            value["raw_response_path"] = str(Path(raw_path).resolve(strict=False))
        for nested in value.values():
            _normalize_receipt_paths(nested)
    elif isinstance(value, list):
        for nested in value:
            _normalize_receipt_paths(nested)


def _strict_family_providers(_chain: str, _receipt_root: Path) -> list[Any]:
    return [
        _strict_provider(provider_id="provider-a", family="family-one", identity="identity-a"),
        _strict_provider(provider_id="provider-b", family="family-two", identity="identity-b"),
    ]


def _build_selected_slice_run(tmp_path: Path) -> tuple[dict[str, Any], Path, dict[str, dict[str, Any]]]:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])
    cases = _selected_cases(prepared_run)
    verified_case_id = str(cases["saddle"]["case_id"])

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        if str(case["case_id"]) == verified_case_id:
            def transition_discoverer(case_arg, providers_arg, receipt_root_arg):
                assert providers_arg == providers
                return _sealed_transition(
                    str(case_arg["case_id"]),
                    receipt_root=Path(receipt_root_arg),
                    status="VERIFIED",
                    blockers=[],
                    candidate_block=100,
                )

            def snapshot_acquirer(case_arg, *, providers, policy, receipt_root, cached_artifact=None):
                del providers, cached_artifact
                return _strict_snapshot_for_selected_case(
                    Path(receipt_root),
                    case=dict(case_arg),
                    policy=dict(policy),
                )

            return snapshot_run_module.execute_snapshot_case(
                case,
                providers=providers,
                policy=policy,
                receipt_root=receipt_root,
                case_root=case_root,
                transition_discoverer=transition_discoverer,
                snapshot_acquirer=snapshot_acquirer,
                resume=resume,
            )

        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=False,
            blockers=["transition_not_verified"],
        )

    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=_strict_family_providers,
        case_executor=case_executor,
    )
    return prepared_run, run_root, cases


def test_verify_historical_snapshot_run_selected_slice_writes_report_and_projection(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, cases = _build_selected_slice_run(tmp_path)

    result = verify_historical_snapshot_run(run_root)
    report = _read_json(run_root / "historical_snapshot_verification_report.json")
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert result == report
    assert report["required"] == 417
    assert report["observed"] == 1
    assert report["passed"] is False
    assert report["counter_authority"] is True
    assert report["operational_metadata"]["independently_derived"] is False
    assert report["operational_metadata"]["verified_via_manifest_binding_only"] == [
        "resumed",
        "quarantined",
        "retried",
    ]
    assert len(projection_rows) == 417

    by_case_id = {row["case_id"]: row for row in projection_rows}
    verified_row = by_case_id[cases["saddle"]["case_id"]]
    assert verified_row["historical_snapshot_status"] == STRICT_HISTORICAL_STATUS
    assert verified_row["historical_snapshot_schema_valid"] == "true"
    assert verified_row["historical_snapshot_hash_bound"] == "true"

    partial_row = by_case_id[cases["shadowfi"]["case_id"]]
    assert partial_row["historical_snapshot_status"] == ""
    assert partial_row["historical_snapshot_schema_valid"] == "false"
    assert partial_row["historical_snapshot_hash_bound"] == "false"


def test_verify_historical_snapshot_run_tampered_manifest_fail_closes_projection(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    manifest = _read_json(run_manifest_path)
    manifest["authoritative_sha256"] = "0" * 64
    run_manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["passed"] is False
    assert "run_manifest_authoritative_hash_mismatch" in report["integrity_errors"]
    assert all(row["historical_snapshot_status"] == "" for row in projection_rows)


def test_verify_historical_snapshot_run_cli_emits_deterministic_json(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    output_root = tmp_path / "verification-output"

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "verify_historical_snapshots_417.py"),
            "--run-root",
            str(run_root),
            "--output",
            str(output_root),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["required"] == 417
    assert payload["observed"] == 1
    assert payload["passed"] is False
    assert completed.stderr == ""
    assert (output_root / "historical_snapshot_verification_report.json").is_file()
    assert (output_root / "historical_snapshot_verified_projection.csv").is_file()


def test_verify_historical_snapshot_run_rejects_exact_case_input_mismatch(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, cases = _build_selected_slice_run(tmp_path)
    case_path = run_root / "cases" / f"{cases['saddle']['case_id']}.json"
    envelope = _read_json(case_path)
    envelope["case_input"]["address"] = "0x0000000000000000000000000000000000000001"
    envelope["case_input_sha256"] = snapshot_run_module._sha256_json(envelope["case_input"])
    payload = {
        key: value
        for key, value in envelope.items()
        if key not in {"envelope_sha256", "envelope_sha256_without_self_hash"}
    }
    envelope["envelope_sha256_without_self_hash"] = snapshot_run_module._sha256_json(payload)
    outer_envelope = dict(payload)
    outer_envelope["envelope_sha256_without_self_hash"] = envelope["envelope_sha256_without_self_hash"]
    envelope["envelope_sha256"] = snapshot_run_module._sha256_json(outer_envelope)
    _write_json(case_path, envelope)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert any("case_input" in code for code in report["integrity_errors"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("case_id", "ca2-wrong-envelope"),
        ("case_name", "wrong-envelope-name"),
        ("chain", "bsc"),
        ("address", "0x0000000000000000000000000000000000000001"),
        ("incident_block", 999999),
    ],
)
def test_verify_historical_snapshot_run_rejects_top_level_envelope_case_binding_mismatch(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    _prepared_run, run_root, cases = _build_selected_slice_run(tmp_path)
    case_path = run_root / "cases" / f"{cases['saddle']['case_id']}.json"
    envelope = _read_json(case_path)
    envelope[field] = value
    payload = {
        key: val
        for key, val in envelope.items()
        if key not in {"envelope_sha256", "envelope_sha256_without_self_hash"}
    }
    envelope["envelope_sha256_without_self_hash"] = snapshot_run_module._sha256_json(payload)
    outer_envelope = dict(payload)
    outer_envelope["envelope_sha256_without_self_hash"] = envelope["envelope_sha256_without_self_hash"]
    envelope["envelope_sha256"] = snapshot_run_module._sha256_json(outer_envelope)
    _write_json(case_path, envelope)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert "case_envelope_binding_mismatch" in report["integrity_errors"]


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (
            lambda report: report["chains"].append(dict(report["chains"][0])),
            "provider_report_duplicate_chain",
        ),
        (
            lambda report: report["chains"][0]["providers"].append(dict(report["chains"][0]["providers"][0])),
            "provider_report_duplicate_provider_identity",
        ),
        (
            lambda report: report["chains"][0]["providers"][0].__setitem__("endpoint_template_sha256", "not-a-sha256"),
            "provider_report_sha256_invalid",
        ),
    ],
)
def test_verify_historical_snapshot_run_fail_closes_invalid_provider_report(
    tmp_path: Path,
    mutator,
    expected_error: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    provider_report_path = run_root / "provider_identity_verification.json"
    provider_report = _read_json(provider_report_path)
    mutator(provider_report)
    _write_json(provider_report_path, provider_report)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert expected_error in report["integrity_errors"]


def test_verify_historical_snapshot_run_rejects_frozen_manifest_entry_byte_drift(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    manifest_path = run_root / "frozen_inputs" / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["entries"][0]["bytes"] += 1
    manifest["entries_sha256"] = snapshot_run_module._sha256_json(manifest["entries"])
    _write_json(manifest_path, manifest)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert "frozen_manifest_entries_mismatch" in report["integrity_errors"]


def test_verify_historical_snapshot_run_rejects_aggregate_alias_and_missing_hash_key(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    run_manifest = _read_json(run_manifest_path)
    run_manifest["aggregate_paths"]["case_qualification"] = "blocker_ledger.csv"
    del run_manifest["aggregate_hashes"]["case_qualification"]
    run_manifest["authoritative_sha256"] = snapshot_run_module._sha256_json(
        {
            "binding_sha256": run_manifest["binding_sha256"],
            "frozen_inputs_sha256": snapshot_run_module._sha256_json(run_manifest["frozen_inputs"]["entries"]),
            "aggregate_paths": run_manifest["aggregate_paths"],
            "aggregate_hashes": run_manifest["aggregate_hashes"],
            "summary": run_manifest["summary"],
        }
    )
    _write_json(run_manifest_path, run_manifest)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert "run_manifest_aggregate_paths_mismatch" in report["integrity_errors"]
    assert "run_manifest_aggregate_hashes_mismatch" in report["integrity_errors"]


@pytest.mark.parametrize("mutation", ["wrong_shard", "symlink", "path_escape"])
def test_verify_historical_snapshot_run_fail_closes_invalid_receipt_layout(
    tmp_path: Path,
    mutation: str,
) -> None:
    _prepared_run, run_root, cases = _build_selected_slice_run(tmp_path)
    case_id = cases["saddle"]["case_id"]
    receipt_root = run_root / "rpc_receipts"
    case_path = run_root / "cases" / f"{case_id}.json"
    envelope = _read_json(case_path)
    observation = envelope["transition_proof"]["search"]["observations"][0]
    canonical_path = Path(observation["raw_response_path"])
    original_bytes = canonical_path.read_bytes()

    if mutation == "wrong_shard":
        relocated = receipt_root / "00" / canonical_path.name
        relocated.parent.mkdir(parents=True, exist_ok=True)
        canonical_path.unlink()
        relocated.write_bytes(original_bytes)
    elif mutation == "symlink":
        target_path = receipt_root / "ff" / canonical_path.name
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(original_bytes)
        canonical_path.unlink()
        canonical_path.symlink_to(target_path)
    else:
        envelope["transition_proof"]["search"]["observations"][0]["raw_response_path"] = str(receipt_root.parent / "escape.json")
        envelope["transition_proof"]["proof_sha256_without_self_hash"] = snapshot_run_module._sha256_json(
            {
                key: value
                for key, value in envelope["transition_proof"].items()
                if key != "proof_sha256"
            }
        )
        outer = dict(envelope["transition_proof"])
        outer["proof_sha256_without_self_hash"] = envelope["transition_proof"]["proof_sha256_without_self_hash"]
        envelope["transition_proof"]["proof_sha256"] = snapshot_run_module._sha256_json(outer)
        envelope["transition_proof_sha256"] = envelope["transition_proof"]["proof_sha256"]
        payload = {key: value for key, value in envelope.items() if key not in {"envelope_sha256", "envelope_sha256_without_self_hash"}}
        envelope["envelope_sha256_without_self_hash"] = snapshot_run_module._sha256_json(payload)
        outer_envelope = dict(payload)
        outer_envelope["envelope_sha256_without_self_hash"] = envelope["envelope_sha256_without_self_hash"]
        envelope["envelope_sha256"] = snapshot_run_module._sha256_json(outer_envelope)
        _write_json(case_path, envelope)

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    expected_error = "receipt_manifest_mismatch" if mutation in {"wrong_shard", "symlink"} else "receipt_binding_invalid"
    assert expected_error in report["integrity_errors"]


def test_verify_historical_snapshot_run_is_relocation_deterministic(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    relocated_root = tmp_path / "relocated-run"
    shutil.copytree(run_root, relocated_root)

    original = verify_historical_snapshot_run(run_root)
    relocated = verify_historical_snapshot_run(relocated_root)

    assert original["observed"] == relocated["observed"] == 1
    assert original["integrity_errors"] == relocated["integrity_errors"] == []


def test_verify_historical_snapshot_run_rejects_output_symlink(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    output_target = tmp_path / "output-target"
    output_target.mkdir()
    output_link = tmp_path / "output-link"
    output_link.symlink_to(output_target, target_is_directory=True)

    with pytest.raises(ValueError):
        verify_historical_snapshot_run(run_root, output_path=output_link)


def test_verify_historical_snapshot_run_cli_parser_errors_are_sanitized(
    tmp_path: Path,
) -> None:
    secret = "super-secret-run-root"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "verify_historical_snapshots_417.py"),
            "--definitely-unknown-flag",
            secret,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert secret not in completed.stderr
    assert json.loads(completed.stderr) == {
        "code": "invalid_cli_argument",
        "error": "historical_snapshot_verification_failed",
    }


@pytest.mark.parametrize("mutation", ["missing_csv", "malformed_provider_json"])
def test_verify_historical_snapshot_run_fail_closes_missing_or_malformed_artifact(
    tmp_path: Path,
    mutation: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    if mutation == "missing_csv":
        (run_root / "case_qualification.csv").unlink()
    else:
        (run_root / "provider_identity_verification.json").write_text("{not-json", encoding="utf-8")

    report = verify_historical_snapshot_run(run_root)

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert report["integrity_errors"]


def test_verify_historical_snapshot_run_fail_closes_corrupt_selected_binding(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    manifest = _read_json(run_manifest_path)
    manifest["binding"]["selected"]["selected_case_ids"] = ["definitely-not-a-real-case-id"]
    manifest["binding_sha256"] = snapshot_run_module._sha256_json(manifest["binding"])
    manifest["authoritative_sha256"] = snapshot_run_module._sha256_json(
        {
            "binding_sha256": manifest["binding_sha256"],
            "frozen_inputs_sha256": snapshot_run_module._sha256_json(manifest["frozen_inputs"]["entries"]),
            "aggregate_paths": manifest["aggregate_paths"],
            "aggregate_hashes": manifest["aggregate_hashes"],
            "summary": manifest["summary"],
        }
    )
    _write_json(run_manifest_path, manifest)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert all(row["historical_snapshot_status"] == "" for row in projection_rows)
    assert any("binding" in code for code in report["integrity_errors"])


@pytest.mark.parametrize("mutation", ["escape", "symlink"])
def test_verify_historical_snapshot_run_fail_closes_aggregate_path_invalid(
    tmp_path: Path,
    mutation: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    manifest = _read_json(run_manifest_path)

    if mutation == "escape":
        manifest["aggregate_paths"]["case_qualification"] = "../escape.csv"
    else:
        target = tmp_path / "case-qualification-target.csv"
        target.write_text((run_root / "case_qualification.csv").read_text(encoding="utf-8"), encoding="utf-8")
        link = run_root / "case_qualification_link.csv"
        link.symlink_to(target)
        manifest["aggregate_paths"]["case_qualification"] = "case_qualification_link.csv"

    manifest["aggregate_hashes"]["case_qualification"] = snapshot_run_module._sha256_file(
        run_root / "case_qualification.csv"
    )
    manifest["authoritative_sha256"] = snapshot_run_module._sha256_json(
        {
            "binding_sha256": manifest["binding_sha256"],
            "frozen_inputs_sha256": snapshot_run_module._sha256_json(manifest["frozen_inputs"]["entries"]),
            "aggregate_paths": manifest["aggregate_paths"],
            "aggregate_hashes": manifest["aggregate_hashes"],
            "summary": manifest["summary"],
        }
    )
    _write_json(run_manifest_path, manifest)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert all(row["historical_snapshot_status"] == "" for row in projection_rows)
    assert any("aggregate" in code for code in report["integrity_errors"])


def test_verify_historical_snapshot_run_fail_closes_synchronized_frozen_byte_drift(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    frozen_manifest_path = run_root / "frozen_inputs" / "manifest.json"
    run_manifest = _read_json(run_manifest_path)
    frozen_manifest = _read_json(frozen_manifest_path)

    for payload in (run_manifest["frozen_inputs"]["entries"], frozen_manifest["entries"]):
        payload[0]["bytes"] += 1

    run_manifest["authoritative_sha256"] = snapshot_run_module._sha256_json(
        {
            "binding_sha256": run_manifest["binding_sha256"],
            "frozen_inputs_sha256": snapshot_run_module._sha256_json(run_manifest["frozen_inputs"]["entries"]),
            "aggregate_paths": run_manifest["aggregate_paths"],
            "aggregate_hashes": run_manifest["aggregate_hashes"],
            "summary": run_manifest["summary"],
        }
    )
    frozen_manifest["entries_sha256"] = snapshot_run_module._sha256_json(frozen_manifest["entries"])
    _write_json(run_manifest_path, run_manifest)
    _write_json(frozen_manifest_path, frozen_manifest)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert all(row["historical_snapshot_status"] == "" for row in projection_rows)
    assert "frozen_input_hash_mismatch" in report["integrity_errors"]


@pytest.mark.parametrize("mutation", ["escape", "symlink"])
def test_verify_historical_snapshot_run_fail_closes_invalid_required_frozen_input_path(
    tmp_path: Path,
    mutation: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    frozen_manifest_path = run_root / "frozen_inputs" / "manifest.json"
    run_manifest = _read_json(run_manifest_path)
    frozen_manifest = _read_json(frozen_manifest_path)
    replacement_path = "../escaped-queue.csv"
    if mutation == "symlink":
        target = tmp_path / "queue-target.csv"
        target.write_text((run_root / "frozen_inputs" / "queue.csv").read_text(encoding="utf-8"), encoding="utf-8")
        link = run_root / "frozen_inputs" / "queue-link.csv"
        link.symlink_to(target)
        replacement_path = "frozen_inputs/queue-link.csv"

    for payload in (run_manifest["frozen_inputs"]["entries"], frozen_manifest["entries"]):
        for entry in payload:
            if entry["name"] == "queue":
                entry["frozen_path"] = replacement_path
                break

    frozen_manifest["entries_sha256"] = snapshot_run_module._sha256_json(frozen_manifest["entries"])
    _rewrite_manifest_hashes(run_manifest)
    _write_json(run_manifest_path, run_manifest)
    _write_json(frozen_manifest_path, frozen_manifest)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 0
    assert "canonical_population_unavailable" in report["integrity_errors"]
    assert any(code.startswith("frozen_input_path_invalid:queue") for code in report["integrity_errors"])


def test_verify_historical_snapshot_run_fail_closes_missing_required_frozen_input_fallback(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"
    frozen_manifest_path = run_root / "frozen_inputs" / "manifest.json"
    run_manifest = _read_json(run_manifest_path)
    frozen_manifest = _read_json(frozen_manifest_path)

    run_manifest["frozen_inputs"]["entries"] = [
        entry for entry in run_manifest["frozen_inputs"]["entries"] if entry["name"] != "queue"
    ]
    frozen_manifest["entries"] = [
        entry for entry in frozen_manifest["entries"] if entry["name"] != "queue"
    ]
    (run_root / "frozen_inputs" / "queue.csv").unlink()
    frozen_manifest["entries_sha256"] = snapshot_run_module._sha256_json(frozen_manifest["entries"])
    _rewrite_manifest_hashes(run_manifest)
    _write_json(run_manifest_path, run_manifest)
    _write_json(frozen_manifest_path, frozen_manifest)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 0
    assert "canonical_population_unavailable" in report["integrity_errors"]
    assert "frozen_required_entry_missing:queue" in report["integrity_errors"]
    assert "frozen_input_missing:queue" in report["integrity_errors"]


def test_verify_historical_snapshot_run_fail_closes_canonical_aggregate_symlink(
    tmp_path: Path,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    target = tmp_path / "case-qualification-target.csv"
    target.write_text((run_root / "case_qualification.csv").read_text(encoding="utf-8"), encoding="utf-8")
    (run_root / "case_qualification.csv").unlink()
    (run_root / "case_qualification.csv").symlink_to(target)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert all(row["historical_snapshot_status"] == "" for row in projection_rows)
    assert "aggregate_path_invalid:case_qualification" in report["integrity_errors"]
    assert any(code.startswith("aggregate_fallback_invalid:case_qualification") for code in report["integrity_errors"])


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", "run_manifest_missing"),
        ("malformed", "run_manifest_invalid"),
        ("symlink", "run_manifest_path_invalid"),
    ],
)
def test_verify_historical_snapshot_run_fail_closes_canonical_run_manifest(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    run_manifest_path = run_root / "run_manifest.json"

    if mutation == "missing":
        run_manifest_path.unlink()
    elif mutation == "malformed":
        run_manifest_path.write_text("{not-json", encoding="utf-8")
    else:
        target = tmp_path / "run-manifest-target.json"
        target.write_text(run_manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
        run_manifest_path.unlink()
        run_manifest_path.symlink_to(target)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["required"] == 417
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert expected_code in report["integrity_errors"]
    assert "selected_binding_invalid" in report["integrity_errors"]


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", "frozen_manifest_missing"),
        ("malformed", "frozen_manifest_invalid"),
        ("symlink", "frozen_manifest_path_invalid"),
    ],
)
def test_verify_historical_snapshot_run_fail_closes_canonical_frozen_manifest(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    _prepared_run, run_root, _cases = _build_selected_slice_run(tmp_path)
    frozen_manifest_path = run_root / "frozen_inputs" / "manifest.json"

    if mutation == "missing":
        frozen_manifest_path.unlink()
    elif mutation == "malformed":
        frozen_manifest_path.write_text("{not-json", encoding="utf-8")
    else:
        target = tmp_path / "frozen-manifest-target.json"
        target.write_text(frozen_manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
        frozen_manifest_path.unlink()
        frozen_manifest_path.symlink_to(target)

    report = verify_historical_snapshot_run(run_root)
    projection_rows = _read_csv_rows(run_root / "historical_snapshot_verified_projection.csv")

    assert report["observed"] == 0
    assert report["required"] == 417
    assert report["counter_authority"] is False
    assert len(projection_rows) == 417
    assert expected_code in report["integrity_errors"]
