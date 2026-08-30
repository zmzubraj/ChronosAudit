from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from chronosaudit_stage2.onchain import canonical_block_selector
from chronosaudit_stage2.public_acquisition.cohort_revision import OUTPUT_CANDIDATE_FIELDS, _candidate_id


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/chronosaudit_stage2/public_acquisition/candidate_archive_qualification.py"
CLI_PATH = ROOT / "run_candidate_archive_qualification.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _candidate_module():
    return _load_module("candidate_archive_qualification_module", MODULE_PATH)


def _cli_module():
    return _load_module("candidate_archive_qualification_cli_module", CLI_PATH)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _candidate_row(
    *,
    chain: str,
    incident_name: str,
    incident_date: str,
    fork_block: int,
    target_address: str,
    tx_hash: str,
    suffix: str,
) -> dict[str, str]:
    row = {
        "candidate_status": "screened_candidate_needs_deployment_age_verification",
        "incident_date": incident_date,
        "incident_name": incident_name,
        "mechanism": "reentrancy",
        "chain": chain,
        "fork_block": str(fork_block),
        "exploit_tx_hashes": json.dumps([tx_hash]),
        "target_addresses": json.dumps([target_address]),
        "target_extraction_rule": "explicit_vulnerable_target_or_victim_contract_line",
        "source_path": f"candidate_sources/{suffix}/source/source.md",
        "source_sha256": "a" * 64,
        "readme_path": f"candidate_sources/{suffix}/readme/README.md",
        "readme_sha256": "b" * 64,
        "public_evidence_urls": json.dumps([f"https://example.invalid/{suffix}"]),
        "all_source_urls": json.dumps([f"https://example.invalid/all/{suffix}"]),
        "duplicate_reasons": "",
        "deployment_age_status": "",
        "chain_conflict": "false",
    }
    row["candidate_id"] = _candidate_id(row, target_address.lower(), [tx_hash.lower()])
    row["frozen_source_path"] = row["source_path"]
    row["frozen_readme_path"] = row["readme_path"]
    return row


def _cohort_root(tmp_path: Path, *, rows: list[dict[str, str]] | None = None) -> Path:
    cohort_root = tmp_path / "cohort-revision"
    cohort_root.mkdir(parents=True)
    candidates = rows or [
        _candidate_row(
            chain="ethereum",
            incident_name="Alpha",
            incident_date="2024-01-02",
            fork_block=101,
            target_address="0x" + "11" * 20,
            tx_hash="0x" + "aa" * 32,
            suffix="alpha",
        ),
        _candidate_row(
            chain="ethereum",
            incident_name="Beta",
            incident_date="2024-01-03",
            fork_block=102,
            target_address="0x" + "22" * 20,
            tx_hash="0x" + "bb" * 32,
            suffix="beta",
        ),
    ]

    _write_csv(cohort_root / "screened_candidates.csv", list(OUTPUT_CANDIDATE_FIELDS), candidates)
    _write_csv(
        cohort_root / "replacement_slots.csv",
        ["chain", "slot_case_id", "blocker_code"],
        [{"chain": "ethereum", "slot_case_id": "slot-001", "blocker_code": "insufficient_incident_lead_time"}],
    )
    _write_csv(
        cohort_root / "slot_candidate_order.csv",
        ["slot_case_id", "chain", "global_rank", "candidate_id", "rank_sha256", "assignment_role"],
        [
            {
                "slot_case_id": "slot-001",
                "chain": "ethereum",
                "global_rank": "1",
                "candidate_id": candidates[0]["candidate_id"],
                "rank_sha256": "1" * 64,
                "assignment_role": "PRIMARY",
            },
            {
                "slot_case_id": "slot-001",
                "chain": "ethereum",
                "global_rank": "2",
                "candidate_id": candidates[1]["candidate_id"],
                "rank_sha256": "2" * 64,
                "assignment_role": "ALTERNATE",
            },
        ],
    )
    (cohort_root / "revision_plan.json").write_text(
        json.dumps(
            {
                "schema_version": "historical_snapshot_cohort_revision_plan.v1",
                "status": "WAITING_FOR_ARCHIVE_QUALIFICATION",
                "no_provider_results_observed": True,
                "slot_count": 1,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (cohort_root / "provenance.json").write_text(
        json.dumps({"schema_version": "cohort_revision_candidate_provenance.v1"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (cohort_root / "screening_log.json").write_text(
        json.dumps({"schema_version": "cohort_revision_screening_log.v1"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    checksum_lines = []
    for path in sorted(item for item in cohort_root.iterdir() if item.is_file() and item.name != "SHA256SUMS.txt"):
        checksum_lines.append(f"{_sha256_bytes(path.read_bytes())}  {path.name}")
    (cohort_root / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return cohort_root


class FakeProvider:
    def __init__(
        self,
        *,
        provider_id: str,
        provider_family: str,
        public_endpoint_id: str,
        artifact_root: Path,
        replies: dict[tuple[str, str], dict[str, Any]],
        secret_url: str = "https://secret.invalid/v2/secret-token-123",
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = provider_family
        self.public_endpoint_id = public_endpoint_id
        self.artifact_root = artifact_root
        self.replies = replies
        self.provider_identity_evidence = {
            "provider_id": provider_id,
            "operator_family": provider_family,
            "chain": "ethereum",
            "expected_chain_id": "0x1",
            "operator_evidence_url": "https://operators.example.invalid/about",
            "endpoint_template_sha256": "e" * 64,
            "secret_url": secret_url,
        }

    def call(self, method: str, params: list[Any]) -> SimpleNamespace:
        key = (method, json.dumps(params, sort_keys=True, separators=(",", ":")))
        reply = dict(self.replies[key])
        response_body = json.dumps(reply, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        response_sha = _sha256_bytes(response_body)
        raw_path = self.artifact_root / response_sha[:2] / f"{response_sha}.json"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_bytes(response_body)
        request_body = json.dumps({"method": method, "params": params}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return SimpleNamespace(
            method=method,
            params=params,
            result=reply.get("result"),
            error=reply.get("error"),
            observed_at_utc="2026-08-10T00:00:00Z",
            request_sha256=_sha256_bytes(request_body),
            response_sha256=response_sha,
            raw_response_path=str(raw_path),
        )


def _providers_for_receipt(
    receipt_root: Path,
    *,
    block_number: int = 101,
    block_hash: str = "0x" + "12" * 32,
    status: str = "0x1",
    families: tuple[str, str] = ("alchemy", "infura"),
) -> list[FakeProvider]:
    receipt_params = ["0x" + "aa" * 32]
    header_params = [hex(block_number), False]
    replies = {
        ("eth_getTransactionReceipt", json.dumps(receipt_params, sort_keys=True, separators=(",", ":"))): {
            "result": {
                "blockNumber": hex(block_number),
                "blockHash": block_hash,
                "status": status,
            }
        },
        ("eth_getBlockByNumber", json.dumps(header_params, sort_keys=True, separators=(",", ":"))): {
            "result": {
                "number": hex(block_number),
                "hash": block_hash,
                "timestamp": hex(1723500000),
            }
        },
    }
    return [
        FakeProvider(
            provider_id=f"provider-{index}",
            provider_family=family,
            public_endpoint_id=f"identity-{family}",
            artifact_root=receipt_root,
            replies=replies,
        )
        for index, family in enumerate(families, 1)
    ]


def _prepared_run(module, tmp_path: Path, cohort_root: Path) -> dict[str, Any]:
    return module.prepare_candidate_archive_run(
        cohort_revision_root=cohort_root,
        output_root=tmp_path / "candidate-output",
        revision="2026-08-10",
        run_id="qualification-run",
    )


def test_prepare_rejects_candidate_with_multiple_exploit_transactions_before_write(tmp_path: Path) -> None:
    module = _candidate_module()
    candidate = _candidate_row(
        chain="ethereum",
        incident_name="Alpha",
        incident_date="2024-01-02",
        fork_block=101,
        target_address="0x" + "11" * 20,
        tx_hash="0x" + "aa" * 32,
        suffix="alpha",
    )
    candidate["exploit_tx_hashes"] = json.dumps(["0x" + "aa" * 32, "0x" + "bb" * 32])
    cohort_root = _cohort_root(tmp_path, rows=[candidate, dict(candidate, candidate_id=dict(candidate)["candidate_id"].replace("a", "c", 1), incident_name="Beta", source_path="candidate_sources/beta/source/source.md", frozen_source_path="candidate_sources/beta/source/source.md")])
    output_root = tmp_path / "candidate-output"

    with pytest.raises(ValueError, match="candidate_exploit_tx_count_invalid"):
        module.prepare_candidate_archive_run(
            cohort_revision_root=cohort_root,
            output_root=output_root,
            revision="2026-08-10",
            run_id="qualification-run",
        )

    assert not output_root.exists()


def test_execute_fails_closed_when_receipt_agreement_comes_from_same_family(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)

    invoked = {"called": False}

    def fail_case_executor(*args, **kwargs):
        invoked["called"] = True
        raise AssertionError("historical execution must not run before receipt-family qualification")

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=lambda chain, receipt_root: _providers_for_receipt(Path(receipt_root), families=("alchemy", "alchemy")),
        case_executor=fail_case_executor,
        max_workers=1,
    )

    row = result["cases"][0]
    assert row["status"] == "PARTIAL"
    assert "same_family" in row["blockers"]
    assert row["qualified"] is False
    assert invoked["called"] is False


def test_execute_fails_closed_on_receipt_provider_disagreement(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)

    def provider_resolver(chain: str, receipt_root: Path):
        providers = _providers_for_receipt(receipt_root)
        providers[1].replies[
            ("eth_getTransactionReceipt", json.dumps(["0x" + "aa" * 32], sort_keys=True, separators=(",", ":")))
        ] = {
            "result": {
                "blockNumber": hex(101),
                "blockHash": "0x" + "34" * 32,
                "status": "0x0",
            }
        }
        return providers

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=provider_resolver,
        case_executor=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not execute historical case")),
        max_workers=1,
    )

    row = result["cases"][0]
    assert row["status"] == "PARTIAL"
    assert "provider_disagreement" in row["blockers"]
    assert row["qualified"] is False


def test_execute_rejects_distinct_families_with_same_endpoint_identity(tmp_path: Path) -> None:
    module = _candidate_module()
    prepared = _prepared_run(module, tmp_path, _cohort_root(tmp_path))

    def resolver(chain: str, receipt_root: Path):
        providers = _providers_for_receipt(Path(receipt_root))
        providers[1].public_endpoint_id = providers[0].public_endpoint_id
        return providers

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=resolver,
        case_executor=lambda *args, **kwargs: pytest.fail("must not execute historical case"),
        max_workers=1,
    )
    assert result["cases"][0]["blockers"] == ["same_family"]
    assert result["cases"][0]["qualified"] is False


def test_execute_rejects_raw_receipt_path_outside_candidate_root(tmp_path: Path) -> None:
    module = _candidate_module()
    prepared = _prepared_run(module, tmp_path, _cohort_root(tmp_path))

    def resolver(chain: str, receipt_root: Path):
        return _providers_for_receipt(tmp_path / "escaped-receipts")

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=resolver,
        case_executor=lambda *args, **kwargs: pytest.fail("must not execute historical case"),
        max_workers=1,
    )
    assert result["cases"][0]["blockers"] == ["receipt_path_or_hash_invalid"]
    assert result["cases"][0]["qualified"] is False


def test_execute_refuses_incident_block_mutation_when_receipt_block_differs(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=lambda chain, receipt_root: _providers_for_receipt(Path(receipt_root), block_number=109),
        case_executor=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not execute historical case")),
        max_workers=1,
    )

    row = result["cases"][0]
    assert row["status"] == "PARTIAL"
    assert "incident_block_mismatch" in row["blockers"]
    assert row["receipt_summary"]["agreed_block_number"] == 109
    assert row["frozen_incident_block"] == 101


def test_plan_preserves_candidate_order_from_frozen_slot_ranks_even_if_screened_csv_is_reversed(tmp_path: Path) -> None:
    module = _candidate_module()
    rows = list(reversed(_cohort_root(tmp_path / "seed").joinpath("screened_candidates.csv").read_text(encoding="utf-8").splitlines()))
    del rows
    seed_root = _cohort_root(tmp_path)
    reversed_root = tmp_path / "reversed"
    shutil.copytree(seed_root, reversed_root)
    candidates = list(csv.DictReader((reversed_root / "screened_candidates.csv").open(encoding="utf-8", newline="")))
    _write_csv(reversed_root / "screened_candidates.csv", list(OUTPUT_CANDIDATE_FIELDS), list(reversed(candidates)))
    checksum_lines = []
    for path in sorted(item for item in reversed_root.iterdir() if item.is_file() and item.name != "SHA256SUMS.txt"):
        checksum_lines.append(f"{_sha256_bytes(path.read_bytes())}  {path.name}")
    (reversed_root / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    plan = module.build_candidate_archive_run_plan(reversed_root)

    assert [item["candidate_id"] for item in plan["ordered_candidates"]] == [
        candidates[0]["candidate_id"],
        candidates[1]["candidate_id"],
    ]


def test_prepare_refuses_resume_when_frozen_revision_inputs_drift(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)

    screened = cohort_root / "screened_candidates.csv"
    screened.write_bytes(screened.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="resume input mismatch"):
        module.prepare_candidate_archive_run(
            cohort_revision_root=cohort_root,
            output_root=tmp_path / "candidate-output",
            revision="2026-08-10",
            run_id="qualification-run",
        )

    assert Path(prepared["run_root"]).is_dir()


def test_prepare_refuses_tampered_run_manifest_binding(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)
    manifest_path = Path(prepared["run_root"]) / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["binding_sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="resume input mismatch"):
        module.prepare_candidate_archive_run(
            cohort_revision_root=cohort_root,
            output_root=tmp_path / "candidate-output",
            revision="2026-08-10",
            run_id="qualification-run",
        )


def test_execute_never_persists_provider_secrets_or_exception_secrets(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)
    secret = "secret-token-123"

    def exploding_case_executor(*args, **kwargs):
        raise RuntimeError(f"historical snapshot failed with {secret}")

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=lambda chain, receipt_root: _providers_for_receipt(Path(receipt_root)),
        case_executor=exploding_case_executor,
        max_workers=1,
    )

    run_root = Path(result["run_root"])
    text = (run_root / "cases" / f"{result['cases'][0]['candidate_id']}.json").read_text(encoding="utf-8")
    assert secret not in text
    assert "https://secret.invalid" not in text


def test_execute_quarantines_partial_cached_case_and_retries(tmp_path: Path) -> None:
    module = _candidate_module()
    cohort_root = _cohort_root(tmp_path)
    prepared = _prepared_run(module, tmp_path, cohort_root)
    run_root = Path(prepared["run_root"])
    case_root = run_root / "cases"
    case_root.mkdir(parents=True, exist_ok=True)
    candidate_id = prepared["plan"]["ordered_candidates"][0]["candidate_id"]

    partial_case = {
        "candidate_id": candidate_id,
        "candidate_input": prepared["plan"]["ordered_candidates"][0],
        "candidate_input_sha256": module._sha256_json(prepared["plan"]["ordered_candidates"][0]),
        "run_binding_sha256": prepared["binding_sha256"],
        "status": "PARTIAL",
        "qualified": False,
        "qualification_closed": False,
        "blockers": ["strict_snapshot_partial"],
    }
    cached = module._seal_case_envelope(partial_case)
    (case_root / f"{candidate_id}.json").write_text(json.dumps(cached, indent=2, sort_keys=True), encoding="utf-8")

    def partial_case_executor(case, **kwargs):
        historical_case_root = Path(kwargs["case_root"])
        historical_case_root.mkdir(parents=True, exist_ok=True)
        historical_path = historical_case_root / f"{case['case_id']}.json"
        historical_payload = {
            "case_id": case["case_id"],
            "case_path": historical_path.name,
            "case_input": dict(case),
            "case_input_sha256": module._sha256_json(dict(case)),
            "policy_input": dict(kwargs["policy"]),
            "policy_sha256": module._sha256_json(dict(kwargs["policy"])),
            "transition_proof": {
                "candidate_block": 77,
                "proof_sha256_without_self_hash": "1" * 64,
                "proof_sha256": "2" * 64,
                "proof": {"headers": {}, "code": {}},
                "search": {"observations": []},
            },
            "strict_snapshot": {"strict_snapshot_closed": False, "blockers": ["missing_historical_code"]},
            "strict_snapshot_sha256": "3" * 64,
            "strict_snapshot_closed": False,
            "status": "PARTIAL",
            "blockers": ["missing_historical_code"],
            "envelope_sha256": "4" * 64,
        }
        historical_path.write_text(json.dumps(historical_payload, indent=2, sort_keys=True), encoding="utf-8")
        return historical_payload

    result = module.execute_candidate_archive_qualification(
        prepared,
        provider_resolver=lambda chain, receipt_root: _providers_for_receipt(Path(receipt_root)),
        case_executor=partial_case_executor,
        max_workers=1,
    )

    row = result["cases"][0]
    assert row["status"] == "PARTIAL"
    assert row["qualified"] is False
    quarantine_dir = run_root / "cases" / "quarantine" / candidate_id
    assert quarantine_dir.is_dir()
    assert any(path.name.startswith("retry_partial-") for path in quarantine_dir.iterdir())


def test_cli_plan_is_offline_and_side_effect_free(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = _candidate_module()
    cli = _cli_module()
    cohort_root = _cohort_root(tmp_path)
    output_root = tmp_path / "cli-output"

    exit_code = cli.main(
        [
            "plan",
            "--cohort-revision-root",
            str(cohort_root),
            "--output-root",
            str(output_root),
            "--revision",
            "2026-08-10",
            "--run-id",
            "qualification-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["command"] == "plan"
    assert payload["candidate_count"] == len(module.build_candidate_archive_run_plan(cohort_root)["ordered_candidates"])
    assert not output_root.exists()
