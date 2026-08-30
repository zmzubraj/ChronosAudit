from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import chronosaudit_stage2.public_acquisition.historical_snapshot_run as snapshot_run_module
from test_historical_snapshot_batch import (
    _fake_provider,
    _load_csv_rows,
    _prepare_run,
    _sealed_case_envelope,
    _selected_cases,
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
    return [
        _fake_provider(chain=chain, provider_id=f"{chain}-alchemy", family="alchemy"),
        _fake_provider(chain=chain, provider_id=f"{chain}-infura", family="infura"),
    ]


def _closed_case_result(
    case: dict[str, Any],
    *,
    policy: dict[str, Any],
    receipt_root: Path,
    case_root: Path,
) -> dict[str, Any]:
    return _sealed_case_envelope(
        case,
        receipt_root=receipt_root,
        case_root=case_root,
        policy=policy,
        strict_snapshot_closed=True,
    )


def _mutate_referenced_receipt(*, case_path: Path, receipt_root: Path, mutation: str) -> None:
    persisted = _read_json(case_path)
    observation = persisted["transition_proof"]["search"]["observations"][0]
    response_sha256 = observation["response_sha256"]
    canonical_path = receipt_root / response_sha256[:2] / f"{response_sha256}.json"
    original_bytes = canonical_path.read_bytes()

    if mutation == "tampered":
        canonical_path.write_text('{"tampered":true}', encoding="utf-8")
        return
    if mutation == "wrong_shard":
        moved_path = receipt_root / "00" / canonical_path.name
        moved_path.parent.mkdir(parents=True, exist_ok=True)
        canonical_path.replace(moved_path)
        return
    if mutation == "malformed":
        malformed_path = canonical_path.with_name("not-a-sha.json")
        canonical_path.replace(malformed_path)
        return
    if mutation == "duplicate":
        duplicate_path = receipt_root / "00" / canonical_path.name
        duplicate_path.parent.mkdir(parents=True, exist_ok=True)
        duplicate_path.write_bytes(original_bytes)
        return
    if mutation == "symlink":
        target_path = receipt_root / "external-target.json"
        target_path.write_bytes(original_bytes)
        canonical_path.unlink()
        canonical_path.symlink_to(target_path)
        return
    raise ValueError(f"unsupported mutation: {mutation}")


def _provider_with_identity_artifact(
    *,
    chain: str,
    provider_id: str,
    family: str,
    public_endpoint_id: str,
    endpoint_template_sha256: str | None,
    operator_evidence_url: str = "https://operators.example/safe",
    public_endpoint_template: str = "https://rpc.example/safe/<redacted>",
) -> SimpleNamespace:
    return SimpleNamespace(
        provider_id=provider_id,
        provider_family=family,
        public_endpoint_id=public_endpoint_id,
        provider_identity_evidence={
            "provider_id": provider_id,
            "operator_family": family,
            "chain": chain,
            "endpoint_template_sha256": endpoint_template_sha256,
            "operator_evidence_url": operator_evidence_url,
            "public_endpoint_template": public_endpoint_template,
        },
    )


def test_execute_historical_snapshot_cases_writes_canonical_manifests_and_closure_report(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        return _sealed_case_envelope(
            case,
            receipt_root=receipt_root,
            case_root=case_root,
            policy=policy,
            strict_snapshot_closed=True,
        )

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=_canonical_provider_resolver,
        case_executor=case_executor,
    )

    receipt_manifest = _read_json(run_root / "rpc_receipt_manifest.json")
    provider_identity = _read_json(run_root / "provider_identity_verification.json")
    closure_report = _read_json(run_root / "historical_snapshot_closure_report.json")
    run_manifest = _read_json(run_root / "run_manifest.json")

    assert result["summary"]["candidate_closed_count"] == 1
    assert receipt_manifest["valid_receipt_count"] == 1
    assert receipt_manifest["invalid_receipt_count"] == 0
    assert provider_identity["complete"] is True
    assert closure_report["counter_authority"] is False
    assert closure_report["offline_verification_required"] is True
    assert closure_report["historical_snapshots_observed"] == 0
    assert run_manifest["aggregate_paths"] == {
        "rpc_receipt_manifest": "rpc_receipt_manifest.json",
        "provider_identity_verification": "provider_identity_verification.json",
        "historical_snapshot_closure_report": "historical_snapshot_closure_report.json",
        "case_qualification": "case_qualification.csv",
        "blocker_ledger": "blocker_ledger.csv",
    }


@pytest.mark.parametrize("mutation", ["tampered", "wrong_shard", "malformed", "duplicate", "symlink"])
def test_execute_historical_snapshot_cases_invalid_referenced_receipt_forces_candidate_closed_false(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])
    cases = _selected_cases(prepared_run)

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        result = _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)
        case_path = case_root / f"{case['case_id']}.json"
        _mutate_referenced_receipt(case_path=case_path, receipt_root=receipt_root, mutation=mutation)
        return result

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=_canonical_provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")
    blocker_rows = _load_csv_rows(run_root / "blocker_ledger.csv")
    receipt_manifest = _read_json(run_root / "rpc_receipt_manifest.json")
    closure_report = _read_json(run_root / "historical_snapshot_closure_report.json")

    assert result["summary"]["candidate_closed_count"] == 0
    assert qualification_rows[0]["case_id"] == cases["saddle"]["case_id"]
    assert qualification_rows[0]["candidate_closed"] == "false"
    assert any(row["code"] == "receipt_binding_invalid" for row in blocker_rows)
    assert receipt_manifest["invalid_receipt_count"] >= 1
    assert closure_report["candidate_closures_by_chain"][qualification_rows[0]["chain"]] == 0


@pytest.mark.parametrize(
    ("label", "providers", "expected_code", "expected_error"),
    [
        (
            "same-family",
            lambda chain: [
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-alchemy-a",
                    family="alchemy",
                    public_endpoint_id=f"{chain}-alchemy-a@identity",
                    endpoint_template_sha256="2" * 64,
                ),
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-alchemy-b",
                    family="alchemy",
                    public_endpoint_id=f"{chain}-alchemy-b@identity",
                    endpoint_template_sha256="3" * 64,
                ),
            ],
            "provider_identity_same_family",
            "same_family",
        ),
        (
            "unverified-family",
            lambda chain: [
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-unknown",
                    family="unverified-family",
                    public_endpoint_id=f"{chain}-unknown@identity",
                    endpoint_template_sha256="2" * 64,
                ),
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-infura",
                    family="infura",
                    public_endpoint_id=f"{chain}-infura@identity",
                    endpoint_template_sha256="3" * 64,
                ),
            ],
            "provider_identity_unverified",
            "unverified_family",
        ),
        (
            "incomplete",
            lambda chain: [
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-alchemy",
                    family="alchemy",
                    public_endpoint_id=f"{chain}-alchemy@identity",
                    endpoint_template_sha256=None,
                ),
                _provider_with_identity_artifact(
                    chain=chain,
                    provider_id=f"{chain}-infura",
                    family="infura",
                    public_endpoint_id=f"{chain}-infura@identity",
                    endpoint_template_sha256="4" * 64,
                ),
            ],
            "provider_identity_incomplete",
            "incomplete_identity",
        ),
    ],
)
def test_execute_historical_snapshot_cases_provider_identity_fail_closed_for_chain(
    tmp_path: Path,
    label: str,
    providers: Any,
    expected_code: str,
    expected_error: str,
) -> None:
    del label
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return providers(chain)

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        return _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    qualification_rows = _load_csv_rows(run_root / "case_qualification.csv")
    blocker_rows = _load_csv_rows(run_root / "blocker_ledger.csv")
    provider_identity = _read_json(run_root / "provider_identity_verification.json")

    assert result["summary"]["candidate_closed_count"] == 0
    assert qualification_rows[0]["candidate_closed"] == "false"
    assert any(row["code"] == expected_code for row in blocker_rows)
    assert provider_identity["complete"] is False
    assert expected_error in provider_identity["errors"]


def test_execute_historical_snapshot_cases_aggregate_manifests_are_deterministic_across_run_roots_and_order(
    tmp_path: Path,
) -> None:
    prepared_run_serial = _prepare_run(tmp_path / "serial", selected_cases=["saddle", "uerii"])
    prepared_run_parallel = _prepare_run(tmp_path / "parallel", selected_cases=["saddle", "uerii"])
    serial_root = Path(prepared_run_serial["run_root"])
    parallel_root = Path(prepared_run_parallel["run_root"])
    parallel_cases = _selected_cases(prepared_run_parallel)
    release_uerii = __import__("threading").Event()

    def serial_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        return _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)

    def parallel_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        if str(case["case_id"]) == parallel_cases["saddle"]["case_id"]:
            release_uerii.set()
        else:
            assert release_uerii.wait(timeout=1.0)
        return _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)

    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run_serial,
        provider_resolver=_canonical_provider_resolver,
        case_executor=serial_executor,
        max_workers=1,
    )
    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run_parallel,
        provider_resolver=_canonical_provider_resolver,
        case_executor=parallel_executor,
        max_workers=2,
    )

    for relative_path in (
        "rpc_receipt_manifest.json",
        "provider_identity_verification.json",
        "historical_snapshot_closure_report.json",
        "run_manifest.json",
    ):
        assert (serial_root / relative_path).read_bytes() == (parallel_root / relative_path).read_bytes()


def test_execute_historical_snapshot_cases_never_serializes_secret_provider_identity_material(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def provider_resolver(chain: str, _receipt_root: Path) -> list[SimpleNamespace]:
        return [
            _provider_with_identity_artifact(
                chain=chain,
                provider_id=f"{chain}-alchemy",
                family="alchemy",
                public_endpoint_id=f"{chain}-alchemy@identity",
                endpoint_template_sha256="2" * 64,
                operator_evidence_url="https://secret.example.invalid/proof?token=super-secret",
                public_endpoint_template="https://secret.example.invalid/rpc?api_key=super-secret",
            ),
            _provider_with_identity_artifact(
                chain=chain,
                provider_id=f"{chain}-infura",
                family="infura",
                public_endpoint_id=f"{chain}-infura@identity",
                endpoint_template_sha256="3" * 64,
                operator_evidence_url="https://secret.example.invalid/proof?token=super-secret",
                public_endpoint_template="https://secret.example.invalid/rpc?api_key=super-secret",
            ),
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
        del providers, resume
        return _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)

    result = snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=provider_resolver,
        case_executor=case_executor,
    )

    captured = capsys.readouterr()
    serialized = json.dumps(result, sort_keys=True)
    aggregate_text = "\n".join(
        [
            (run_root / "rpc_receipt_manifest.json").read_text(encoding="utf-8"),
            (run_root / "provider_identity_verification.json").read_text(encoding="utf-8"),
            (run_root / "historical_snapshot_closure_report.json").read_text(encoding="utf-8"),
            (run_root / "run_manifest.json").read_text(encoding="utf-8"),
        ]
    )

    for secret in ("super-secret", "https://secret.example.invalid", "api_key", "token="):
        assert secret not in serialized
        assert secret not in aggregate_text
        assert secret not in captured.out
        assert secret not in captured.err


def test_execute_historical_snapshot_cases_changed_frozen_input_fails_before_aggregate_mutation(
    tmp_path: Path,
) -> None:
    prepared_run = _prepare_run(tmp_path, selected_cases=["saddle"])
    run_root = Path(prepared_run["run_root"])

    def case_executor(
        case: dict[str, Any],
        *,
        providers: list[Any],
        policy: dict[str, Any],
        receipt_root: Path,
        case_root: Path,
        resume: bool,
    ) -> dict[str, Any]:
        del providers, resume
        return _closed_case_result(case, policy=policy, receipt_root=receipt_root, case_root=case_root)

    snapshot_run_module.execute_historical_snapshot_cases(
        prepared_run,
        provider_resolver=_canonical_provider_resolver,
        case_executor=case_executor,
    )
    before = {
        relative_path: (run_root / relative_path).read_bytes()
        for relative_path in (
            "case_qualification.csv",
            "blocker_ledger.csv",
            "rpc_receipt_manifest.json",
            "provider_identity_verification.json",
            "historical_snapshot_closure_report.json",
            "run_manifest.json",
        )
    }

    queue_frozen = run_root / "frozen_inputs" / "queue.csv"
    queue_frozen.write_bytes(queue_frozen.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="frozen input hash mismatch"):
        snapshot_run_module.execute_historical_snapshot_cases(
            prepared_run,
            provider_resolver=_canonical_provider_resolver,
            case_executor=case_executor,
        )

    for relative_path, expected_bytes in before.items():
        assert (run_root / relative_path).read_bytes() == expected_bytes
