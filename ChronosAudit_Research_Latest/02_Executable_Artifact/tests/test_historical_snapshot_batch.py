from __future__ import annotations

import csv
import hashlib
import json
import shutil
import threading
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import chronosaudit_stage2.public_acquisition.historical_snapshot_run as snapshot_run_module
from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderConfigurationError
from test_public_acquisition_strict_snapshot import (
    _identity_artifact as _strict_identity_artifact,
    _policy as _strict_policy,
    _rehash_snapshot as _rehash_strict_snapshot,
    _strict_snapshot as _strict_snapshot_template,
)


ROOT = Path(__file__).resolve().parents[1]
QUEUE_PATH = (
    ROOT
    / "processed"
    / "public_acquisition"
    / "2026-08-08"
    / "public-acquisition-20260808T122104Z-2942b2819e08"
    / "case_queue.csv"
)
TEMPORAL_PATH = ROOT / "processed" / "stage2a_temporal_provenance.csv"
POLICY_PATH = ROOT / "config" / "public_acquisition_policy.yaml"
TEMPLATE_PATH = ROOT / "config" / "managed_archive_provider_templates.yaml"


def _copy_preparation_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    queue_copy = tmp_path / "case_queue.csv"
    temporal_copy = tmp_path / "stage2a_temporal_provenance.csv"
    policy_copy = tmp_path / "public_acquisition_policy.yaml"
    template_copy = tmp_path / "managed_archive_provider_templates.yaml"
    shutil.copyfile(QUEUE_PATH, queue_copy)
    shutil.copyfile(TEMPORAL_PATH, temporal_copy)
    shutil.copyfile(POLICY_PATH, policy_copy)
    shutil.copyfile(TEMPLATE_PATH, template_copy)
    return queue_copy, temporal_copy, policy_copy, template_copy


def _prepare_run(tmp_path: Path, *, selected_cases: list[str]) -> dict[str, Any]:
    queue_copy, temporal_copy, policy_copy, template_copy = _copy_preparation_inputs(tmp_path)
    return snapshot_run_module.prepare_historical_snapshot_run(
        queue_copy,
        temporal_copy,
        policy_path=policy_copy,
        provider_template_path=template_copy,
        output_root=tmp_path / "runner-output",
        revision="2026-08-09-historical-snapshots-batch",
        run_id="historical-snapshots-batch",
        selected_cases=selected_cases,
        max_cases=len(selected_cases),
    )


def _selected_cases(prepared_run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    attempts = prepared_run["plan"]["selected"]["selected_attempts"]
    return {str(case["case_name"]).lower(): dict(case) for case in attempts}


def _fake_provider(*, chain: str, provider_id: str, family: str) -> SimpleNamespace:
    return SimpleNamespace(
        provider_id=provider_id,
        provider_family=family,
        public_endpoint_id=f"{provider_id}@{chain}",
        provider_identity_evidence={
            "provider_id": provider_id,
            "operator_family": family,
            "chain": chain,
            "endpoint_template_sha256": hashlib.sha256(f"{provider_id}:{chain}".encode("utf-8")).hexdigest(),
            "operator_evidence_url": f"https://operators.example/{family}/{chain}",
            "public_endpoint_template": f"https://rpc.example/{chain}/{family}/<redacted>",
        },
    )


def _strict_provider(*, provider_id: str, family: str, identity: str) -> SimpleNamespace:
    endpoint_template_sha256 = {
        "family-one": "3" * 64,
        "family-two": "4" * 64,
    }[family]
    return SimpleNamespace(
        provider_id=provider_id,
        provider_family=family,
        public_endpoint_id=identity,
        provider_identity_evidence={
            "provider_id": provider_id,
            "operator_family": family,
            "chain": "ethereum",
            "endpoint_template_sha256": endpoint_template_sha256,
            "operator_evidence_url": f"https://operators.example/{family}",
            "public_endpoint_template": f"https://rpc.example/{family}/<redacted>",
        },
    )


def _write_receipt(receipt_root: Path, *, case_id: str) -> str:
    payload = json.dumps({"case_id": case_id}, sort_keys=True).encode("utf-8")
    response_sha256 = hashlib.sha256(payload).hexdigest()
    receipt_path = receipt_root / response_sha256[:2] / f"{response_sha256}.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(payload)
    return response_sha256


def _sealed_transition(
    case_id: str,
    *,
    receipt_root: Path,
    status: str = "VERIFIED",
    blockers: list[str] | None = None,
    relative_to_receipt_root: bool = False,
    candidate_block: int = 123,
) -> dict[str, Any]:
    response_sha256 = _write_receipt(receipt_root, case_id=case_id)
    receipt_path = receipt_root / response_sha256[:2] / f"{response_sha256}.json"
    transition = {
        "status": status,
        "blockers": list(blockers or []),
        "candidate_block": candidate_block,
        "proof": {
            "headers": {"previous": {"observations": []}, "candidate": {"observations": []}},
            "code": {"previous": {"observations": []}, "candidate": {"observations": []}},
        },
        "search": {
            "observations": [
                {
                    "method": "eth_getCode",
                    "observed_at_utc": "2026-08-09T00:00:00Z",
                    "request_sha256": "1" * 64,
                    "response_sha256": response_sha256,
                    "raw_response_path": (
                        snapshot_run_module._portable_path(receipt_path, root=receipt_root)
                        if relative_to_receipt_root
                        else str(receipt_path)
                    ),
                    "provider_id": f"provider-{case_id}",
                    "provider_family": "alchemy",
                    "provider_identity": f"provider-{case_id}@identity",
                    "result": "0x1234",
                }
            ]
        },
    }
    transition["proof_sha256_without_self_hash"] = snapshot_run_module._sha256_json(transition)
    outer = dict(transition)
    outer["proof_sha256_without_self_hash"] = transition["proof_sha256_without_self_hash"]
    transition["proof_sha256"] = snapshot_run_module._sha256_json(outer)
    return transition


def _sealed_case_envelope(
    case: dict[str, Any],
    *,
    receipt_root: Path,
    case_root: Path,
    policy: dict[str, Any],
    strict_snapshot_closed: bool,
    blockers: list[str] | None = None,
    resumed: bool = False,
    quarantined: bool = False,
    retried: bool | None = None,
) -> dict[str, Any]:
    blocker_codes = list(blockers or ([] if strict_snapshot_closed else ["transition_not_verified"]))
    transition = _sealed_transition(
        str(case["case_id"]),
        receipt_root=receipt_root,
        status="VERIFIED" if not blocker_codes else "PARTIAL",
        blockers=blocker_codes,
        relative_to_receipt_root=True,
    )
    strict_snapshot = {
        "strict_snapshot_closed": strict_snapshot_closed,
        "status": "VERIFIED" if strict_snapshot_closed else "PARTIAL",
        "blockers": list(blocker_codes),
        "artifact_sha256": hashlib.sha256(f"strict:{case['case_id']}".encode("utf-8")).hexdigest(),
    }
    envelope = {
        "case_id": str(case["case_id"]),
        "case_input": dict(case),
        "case_input_sha256": snapshot_run_module._sha256_json(case),
        "policy_input": dict(policy),
        "policy_sha256": snapshot_run_module._sha256_json(policy),
        "transition_proof": transition,
        "transition_proof_sha256": str(transition["proof_sha256"]),
        "strict_snapshot": strict_snapshot,
        "strict_snapshot_sha256": str(strict_snapshot["artifact_sha256"]),
        "strict_snapshot_closed": strict_snapshot_closed,
        "status": "VERIFIED" if strict_snapshot_closed and not blocker_codes else "PARTIAL",
        "blockers": blocker_codes,
        "case_path": f"{case['case_id']}.json",
        "receipt_root": snapshot_run_module._portable_path(receipt_root, root=case_root.parent),
    }
    sealed = snapshot_run_module._seal_snapshot_case_envelope(envelope)
    case_path = case_root / f"{case['case_id']}.json"
    case_path.parent.mkdir(parents=True, exist_ok=True)
    case_path.write_text(json.dumps(sealed, indent=2, sort_keys=True), encoding="utf-8")
    result = snapshot_run_module._with_snapshot_case_runtime_flags(
        sealed,
        resumed=resumed,
        quarantined=quarantined,
        quarantine_reason="resume_drift" if quarantined else None,
    )
    if retried is not None:
        result["retried"] = retried
    return result


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _strict_compat_case() -> dict[str, Any]:
    return {
        "case_id": "ca2-strict-compat-case",
        "case_name": "strict-compat-case",
        "chain": "ethereum",
        "address": "0x" + "11" * 20,
        "incident_block": 250,
        "deployment_block": 100,
        "prediction_cutoff_block": 110,
        "input_row_sha256": "2" * 64,
    }


def _strict_compat_policy() -> dict[str, Any]:
    return {
        **_strict_policy(),
        "provider_identity": _strict_identity_artifact(),
    }


def _strict_snapshot_for_case(receipt_root: Path, case: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    del policy
    snapshot = _strict_snapshot_template(receipt_root)
    snapshot["case_id"] = str(case["case_id"])
    snapshot["case_name"] = str(case["case_name"])
    snapshot["chain"] = str(case["chain"])
    snapshot["address"] = str(case["address"]).lower()
    snapshot["incident_block"] = int(case["incident_block"])
    snapshot["deployment_block"] = int(case["deployment_block"])
    snapshot["prediction_cutoff_block"] = int(case["prediction_cutoff_block"])
    snapshot["case_input"] = dict(case)
    snapshot["case_input_sha256"] = snapshot_run_module._sha256_json(case)
    snapshot["policy_input"] = _strict_policy()
    return _rehash_strict_snapshot(snapshot)


def test_execute_historical_snapshot_cases_mixed_chain_success_and_partial_write_sorted_tables(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])
    cases = _selected_cases(prepared_run)

    def provider_resolver(chain: str, receipt_root: Path) -> list[SimpleNamespace]:
        assert receipt_root == run_root / "rpc_receipts"
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        assert len(providers) == 2
        assert resume is True
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=(case["case_id"] == cases["shadowfi"]["case_id"]),
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")
    blocker_rows = _load_csv_rows(run_root / "blocker_ledger.csv")

    assert result["summary"] == {
        "selected_case_count": 2,
        "processed_case_count": 2,
        "candidate_closed_count": 1,
        "reused_case_count": 0,
        "quarantined_case_count": 0,
        "retried_case_count": 0,
    }
    assert [row["case_id"] for row in qualification_rows] == sorted(row["case_id"] for row in qualification_rows)
    by_case_id = {row["case_id"]: row for row in qualification_rows}
    assert by_case_id[cases["saddle"]["case_id"]]["candidate_closed"] == "false"
    assert by_case_id[cases["shadowfi"]["case_id"]]["candidate_closed"] == "true"
    assert [tuple(row[key] for key in ("chain", "case_id", "code")) for row in blocker_rows] == sorted(
        (row["chain"], row["case_id"], row["code"]) for row in blocker_rows
    )


def test_execute_historical_snapshot_cases_provider_failure_blocks_affected_chain_only(tmp_path: Path) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])
    executed_case_ids: list[str] = []

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        if chain == "bsc":
            raise ManagedProviderConfigurationError(
                "missing_api_key",
                "missing https://secret.example.invalid/rpc?api_key=super-secret",
                chain=chain,
                operator_family="alchemy",
            )
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        executed_case_ids.append(str(case["case_id"]))
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
            resumed=resume,
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    blocker_rows = _load_csv_rows(run_root / "blocker_ledger.csv")
    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")

    assert executed_case_ids == [qualification_rows[1]["case_id"]]
    assert any(row["chain"] == "bsc" and row["code"] == "provider_credentials_missing" for row in blocker_rows)
    blocked_case = next(row for row in qualification_rows if row["chain"] == "bsc")
    assert blocked_case["candidate_closed"] == "false"
    blocked_envelope = json.loads(
        (run_root / "cases" / f"{blocked_case['case_id']}.json").read_text(encoding="utf-8")
    )
    assert "NaN" not in json.dumps(blocked_envelope["case_input"], sort_keys=True)
    assert blocked_envelope["case_input_sha256"] == snapshot_run_module._sha256_json(
        blocked_envelope["case_input"]
    )
    assert result["summary"]["processed_case_count"] == 2


def test_execute_historical_snapshot_cases_resume_quarantine_retry_flags_aggregate(tmp_path: Path) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])
    cases = _selected_cases(prepared_run)

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        if case["case_id"] == cases["saddle"]["case_id"]:
            return _sealed_case_envelope(
                case,
                receipt_root=receipt_root,
                case_root=case_root,
                policy=policy,
                strict_snapshot_closed=False,
                resumed=True,
            )
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
            quarantined=True,
            retried=True,
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")
    by_case_id = {row["case_id"]: row for row in qualification_rows}

    assert result["summary"]["reused_case_count"] == 1
    assert result["summary"]["quarantined_case_count"] == 1
    assert result["summary"]["retried_case_count"] == 1
    assert by_case_id[cases["saddle"]["case_id"]]["resumed"] == "true"
    assert by_case_id[cases["shadowfi"]["case_id"]]["quarantined"] == "true"
    assert by_case_id[cases["shadowfi"]["case_id"]]["retried"] == "true"


def test_execute_historical_snapshot_cases_reversed_worker_completion_is_deterministic(tmp_path: Path) -> None:
    prepared_run_serial = _prepare_run(tmp_path / "serial", selected_cases=["saddle", "uerii"])
    prepared_run_parallel = _prepare_run(tmp_path / "parallel", selected_cases=["saddle", "uerii"])
    serial_root = Path(prepared_run_serial["run_root"])
    parallel_root = Path(prepared_run_parallel["run_root"])
    parallel_cases = _selected_cases(prepared_run_parallel)
    execution_counts: Counter[str] = Counter()
    release_uerii = threading.Event()

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def serial_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )

    def parallel_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        case_id = str(case["case_id"])
        execution_counts[case_id] += 1
        if case_id == parallel_cases["saddle"]["case_id"]:
            release_uerii.set()
        else:
            assert release_uerii.wait(timeout=1.0)
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )

    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run_serial,
        provider_resolver=provider_resolver,
        case_executor=serial_executor,
        max_workers=1,
    )
    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run_parallel,
        provider_resolver=provider_resolver,
        case_executor=parallel_executor,
        max_workers=2,
    )

    assert execution_counts == Counter(
        {
            parallel_cases["saddle"]["case_id"]: 1,
            parallel_cases["uerii"]["case_id"]: 1,
        }
    )
    assert (serial_root / "case_qualification.csv").read_bytes() == (parallel_root / "case_qualification.csv").read_bytes()
    assert (serial_root / "blocker_ledger.csv").read_bytes() == (parallel_root / "blocker_ledger.csv").read_bytes()
    assert (serial_root / "blocker_ledger.csv").read_text(encoding="utf-8") == "chain,case_id,code\n"


def test_execute_historical_snapshot_cases_tamper_fails_before_provider_resolution_and_preserves_tables(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])
    provider_calls: list[str] = []

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        provider_calls.append(chain)
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )

    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )
    qualification_before = (run_root / "case_qualification.csv").read_bytes()
    blocker_before = (run_root / "blocker_ledger.csv").read_bytes()

    queue_frozen = run_root / "frozen_inputs" / "queue.csv"
    queue_frozen.write_bytes(queue_frozen.read_bytes() + b"\n")
    provider_calls.clear()

    with pytest.raises(ValueError, match="frozen input hash mismatch"):
        snapshot_run_module.execute_historical_snapshot_cases(
            prepared_run,
            provider_resolver=provider_resolver,
            case_executor=case_executor,
        )

    assert provider_calls == []
    assert (run_root / "case_qualification.csv").read_bytes() == qualification_before
    assert (run_root / "blocker_ledger.csv").read_bytes() == blocker_before


def test_execute_historical_snapshot_cases_never_serializes_secret_provider_message(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        raise ManagedProviderConfigurationError(
            "missing_api_key",
            f"{chain} failed at https://secret.example.invalid/rpc?api_key=super-secret",
            chain=chain,
            operator_family="alchemy",
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
    )

    captured = capsys.readouterr()
    serialized = json.dumps(result, sort_keys=True)
    qualification_bytes = (run_root / "case_qualification.csv").read_text(encoding="utf-8")
    blocker_bytes = (run_root / "blocker_ledger.csv").read_text(encoding="utf-8")

    for secret in ("super-secret", "https://secret.example.invalid", "api_key"):
        assert secret not in serialized
        assert secret not in qualification_bytes
        assert secret not in blocker_bytes
        assert secret not in captured.out
        assert secret not in captured.err


def test_execute_historical_snapshot_cases_all_partial_attempts_yield_zero_candidate_closures(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle", "shadowfi"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=False,
            blockers=["transition_not_verified"],
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")

    assert result["summary"]["candidate_closed_count"] == 0
    assert all(row["candidate_closed"] == "false" for row in qualification_rows)


def test_execute_historical_snapshot_cases_missing_persisted_case_file_forces_candidate_closed_false(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        result = _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )
        (case_root / f"{case['case_id']}.json").unlink()
        return result

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")

    assert result["summary"]["candidate_closed_count"] == 0
    assert qualification_rows[0]["candidate_closed"] == "false"


def test_execute_historical_snapshot_cases_noncanonical_case_path_forces_candidate_closed_false(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        result = _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )
        result["case_path"] = f"cases/../cases/{case['case_id']}.json"
        return result

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")

    assert result["summary"]["candidate_closed_count"] == 0
    assert qualification_rows[0]["candidate_closed"] == "false"


def test_execute_historical_snapshot_cases_tampered_persisted_case_file_forces_candidate_closed_false(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
            _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
        ]

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        result = _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )
        case_path = case_root / f"{case['case_id']}.json"
        persisted = json.loads(case_path.read_text(encoding="utf-8"))
        persisted["case_input_sha256"] = "0" * 64
        case_path.write_text(json.dumps(persisted, indent=2, sort_keys=True), encoding="utf-8")
        return result

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")

    assert result["summary"]["candidate_closed_count"] == 0
    assert qualification_rows[0]["candidate_closed"] == "false"


def test_execute_snapshot_case_relative_receipt_root_supports_fresh_write_and_resume(tmp_path: Path) -> None:
    case = _strict_compat_case()
    policy = _strict_compat_policy()
    providers = [
        _strict_provider(provider_id="provider-a", family="family-one", identity="identity-a"),
        _strict_provider(provider_id="provider-b", family="family-two", identity="identity-b"),
    ]
    transition = {
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    }

    def transition_discoverer(case_arg, providers_arg, receipt_root_arg):
        assert dict(case_arg)["case_id"] == case["case_id"]
        assert providers_arg == providers
        receipt_root_path = Path(receipt_root_arg)
        return _sealed_transition(
            str(case["case_id"]),
            receipt_root=receipt_root_path,
            status="VERIFIED",
            blockers=[],
            candidate_block=100,
        )

    def snapshot_acquirer(case_arg, *, providers, policy, receipt_root, cached_artifact=None):
        assert cached_artifact is None
        return _strict_snapshot_for_case(Path(receipt_root), dict(case_arg), dict(policy))

    fresh = snapshot_run_module.execute_snapshot_case(
        case,
        providers=providers,
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=transition_discoverer,
        snapshot_acquirer=snapshot_acquirer,
        resume=True,
    )
    persisted = json.loads((tmp_path / "cases" / f"{case['case_id']}.json").read_text(encoding="utf-8"))

    resumed = snapshot_run_module.execute_snapshot_case(
        case,
        providers=providers,
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=transition_discoverer,
        snapshot_acquirer=snapshot_acquirer,
        resume=True,
    )

    assert fresh["strict_snapshot_closed"] is True
    assert persisted["receipt_root"] == "receipts"
    assert resumed["resumed"] is True
    assert resumed["strict_snapshot_closed"] is True
    assert snapshot_run_module._validate_snapshot_case_envelope_hashes(resumed) is True
