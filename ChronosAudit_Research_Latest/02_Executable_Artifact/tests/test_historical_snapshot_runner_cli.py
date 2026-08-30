from __future__ import annotations

import importlib.util
import csv
import json
import sys
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderConfigurationError


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "run_historical_snapshots_417.py"
QUEUE_FIXTURE = ROOT / "processed" / "stage2b_onchain_query_queue.csv"
TEMPORAL_FIXTURE = ROOT / "processed" / "stage2a_temporal_provenance.csv"
POLICY_FIXTURE = ROOT / "config" / "public_acquisition_policy.yaml"
PROVIDER_TEMPLATE_FIXTURE = ROOT / "config" / "managed_archive_provider_templates.yaml"
RUNNER_SPEC = importlib.util.spec_from_file_location("historical_snapshot_runner_cli", RUNNER)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)


def _parse_json_lines(text: str) -> dict[str, object]:
    payload = text.strip()
    assert payload
    return json.loads(payload)


def _prepared_run(tmp_path: Path) -> dict[str, object]:
    run_root = tmp_path / "historical-snapshots-417" / "run-001"
    frozen_root = run_root / "frozen_inputs"
    frozen_root.mkdir(parents=True, exist_ok=True)
    template_path = frozen_root / "provider_template.yaml"
    template_path.write_text("version: 1\nproviders: []\n", encoding="utf-8")
    return {
        "revision": "historical-snapshots-417",
        "run_id": "run-001",
        "run_root": str(run_root),
        "run_manifest_path": str(run_root / "run_manifest.json"),
        "frozen_inputs": {
            "entries": [
                {
                    "name": "provider_template",
                    "available": True,
                    "frozen_path": "frozen_inputs/provider_template.yaml",
                    "sha256": "1" * 64,
                    "bytes": len(template_path.read_bytes()),
                }
            ]
        },
    }


def _write_near_real_queue_fixture(tmp_path: Path) -> Path:
    source_rows: list[dict[str, str]] = []
    with QUEUE_FIXTURE.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            source_rows.append(dict(row))

    queue_path = tmp_path / "near-real-queue.csv"
    with queue_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_name", "chain", "address", "incident_block"],
        )
        writer.writeheader()
        for row in source_rows:
            writer.writerow(
                {
                    "case_name": row["case_name"],
                    "chain": row["chain"],
                    "address": row["target_contract_address"],
                    "incident_block": row["fork_block_number"],
                }
            )
    return queue_path


def test_plan_command_stays_offline_and_side_effect_free(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seen: dict[str, object] = {}

    def fake_build_snapshot_run_plan(queue, temporal, *, policy_path, provider_template_path, selected_cases, max_cases):
        seen.update(
            {
                "queue": queue,
                "temporal": temporal,
                "policy_path": policy_path,
                "provider_template_path": provider_template_path,
                "selected_cases": list(selected_cases),
                "max_cases": max_cases,
            }
        )
        return {"plan_sha256": "p" * 64, "selected": {"selected_case_count": 2}}

    def fail_load_dotenv(*args, **kwargs):
        raise AssertionError("plan must not load dotenv")

    def fail_prepare(*args, **kwargs):
        raise AssertionError("plan must not prepare a run root")

    monkeypatch.setattr(runner, "build_snapshot_run_plan", fake_build_snapshot_run_plan)
    monkeypatch.setattr(runner, "_load_execute_env", fail_load_dotenv, raising=False)
    monkeypatch.setattr(runner, "prepare_historical_snapshot_run", fail_prepare, raising=False)

    queue = tmp_path / "queue.csv"
    temporal = tmp_path / "temporal.csv"
    policy = tmp_path / "policy.yaml"
    template = tmp_path / "provider-template.yaml"
    output_root = tmp_path / "output"
    for path in (queue, temporal, policy, template):
        path.write_text("fixture\n", encoding="utf-8")

    exit_code = runner.main(
        [
            "plan",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
            "--case",
            "alpha",
            "--max-cases",
            "2",
        ]
    )

    assert exit_code == 0
    assert seen == {
        "queue": queue,
        "temporal": temporal,
        "policy_path": policy,
        "provider_template_path": template,
        "selected_cases": ["alpha"],
        "max_cases": 2,
    }
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["command"] == "plan"
    assert payload["plan_sha256"] == "p" * 64
    assert not output_root.exists()


def test_plan_command_without_case_selects_full_canonical_population(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    queue_fixture = _write_near_real_queue_fixture(tmp_path)
    output_root = tmp_path / "output"

    exit_code = runner.main(
        [
            "plan",
            "--queue",
            str(queue_fixture),
            "--temporal",
            str(TEMPORAL_FIXTURE),
            "--policy",
            str(POLICY_FIXTURE),
            "--provider-template",
            str(PROVIDER_TEMPLATE_FIXTURE),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
        ]
    )

    assert exit_code == 0
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["command"] == "plan"
    assert payload["population"]["target_case_count"] == 417
    assert payload["population"]["actual_case_count"] == 417
    assert payload["selected"]["requested_case_names"] == []
    assert payload["selected"]["selected_case_count"] == 417
    assert len(payload["selected"]["selected_case_ids"]) == 417
    assert not output_root.exists()


def test_plan_command_without_case_applies_max_cases_to_full_population(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    queue_fixture = _write_near_real_queue_fixture(tmp_path)
    output_root = tmp_path / "output"

    exit_code = runner.main(
        [
            "plan",
            "--queue",
            str(queue_fixture),
            "--temporal",
            str(TEMPORAL_FIXTURE),
            "--policy",
            str(POLICY_FIXTURE),
            "--provider-template",
            str(PROVIDER_TEMPLATE_FIXTURE),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
            "--max-cases",
            "5",
        ]
    )

    assert exit_code == 0
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["selected"]["requested_case_names"] == []
    assert payload["selected"]["selected_case_count"] == 5
    assert len(payload["selected"]["selected_case_ids"]) == 5
    assert payload["population"]["target_case_count"] == 417
    assert payload["population"]["actual_case_count"] == 417


def test_execute_command_prepares_then_executes_with_managed_provider_resolver(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    prepared = _prepared_run(tmp_path)
    call_order: list[str] = []
    prepare_seen: dict[str, object] = {}
    resolver_seen: dict[str, object] = {}

    def fake_prepare(queue, temporal, *, policy_path, provider_template_path, incident_input_path, output_root, revision, run_id, selected_cases, max_cases):
        call_order.append("prepare")
        prepare_seen.update(
            {
                "queue": queue,
                "temporal": temporal,
                "policy_path": policy_path,
                "provider_template_path": provider_template_path,
                "incident_input_path": incident_input_path,
                "output_root": output_root,
                "revision": revision,
                "run_id": run_id,
                "selected_cases": list(selected_cases),
                "max_cases": max_cases,
            }
        )
        return prepared

    def fake_load_templates(path):
        resolver_seen["template_path"] = Path(path)
        return {"loaded_from": str(path)}

    def fake_providers_for_chain(chain, *, templates, env, artifact_root, timeout, retries, backoff_seconds):
        resolver_seen.update(
            {
                "chain": chain,
                "templates": templates,
                "artifact_root": Path(artifact_root),
                "timeout": timeout,
                "retries": retries,
                "backoff_seconds": backoff_seconds,
                "env_has_secret": env["CHRONOS_ALCHEMY_API_KEY"] == "super-secret-value",
            }
        )
        return [object(), object()]

    def fake_execute(prepared_run, *, provider_resolver, case_executor, max_workers, resume):
        call_order.append("execute")
        providers = provider_resolver("ethereum", Path(prepared_run["run_root"]) / "rpc_receipts")
        assert len(providers) == 2
        assert case_executor is runner.execute_snapshot_case
        assert prepared_run is prepared
        assert max_workers == 3
        assert resume is False
        return {
            "summary": {
                "selected_case_count": 2,
                "processed_case_count": 2,
                "candidate_closed_count": 1,
                "reused_case_count": 0,
                "quarantined_case_count": 1,
                "retried_case_count": 1,
            },
            "case_results": [
                {"case_id": "ca2-a", "status": "VERIFIED", "candidate_closed": True, "blockers": []},
                {"case_id": "ca2-b", "status": "WAITING_EXTERNAL", "candidate_closed": False, "blockers": ["missing_api_key"]},
            ],
            "blocker_rows": [
                {"chain": "ethereum", "case_id": "ca2-b", "code": "missing_api_key"},
                {"chain": "ethereum", "case_id": "ca2-b", "code": "receipt_binding_invalid"},
            ],
            "aggregate_artifacts": {
                "paths": {
                    "rpc_receipt_manifest": "rpc_receipt_manifest.json",
                    "provider_identity_verification": "provider_identity_verification.json",
                    "historical_snapshot_closure_report": "historical_snapshot_closure_report.json",
                },
                "hashes": {
                    "rpc_receipt_manifest": "a" * 64,
                    "provider_identity_verification": "b" * 64,
                    "historical_snapshot_closure_report": "c" * 64,
                },
            },
        }

    monkeypatch.setattr(runner, "prepare_historical_snapshot_run", fake_prepare)
    monkeypatch.setattr(runner, "load_managed_provider_templates", fake_load_templates, raising=False)
    monkeypatch.setattr(runner, "providers_for_chain_from_managed_env", fake_providers_for_chain, raising=False)
    monkeypatch.setattr(runner, "execute_historical_snapshot_cases", fake_execute)
    monkeypatch.setattr(runner, "_load_execute_env", lambda: {"CHRONOS_ALCHEMY_API_KEY": "super-secret-value"}, raising=False)

    queue = tmp_path / "queue.csv"
    temporal = tmp_path / "temporal.csv"
    policy = tmp_path / "policy.yaml"
    template = tmp_path / "provider-template.yaml"
    incident = tmp_path / "incidents.json"
    output_root = tmp_path / "output"
    for path in (queue, temporal, policy, template, incident):
        path.write_text("fixture\n", encoding="utf-8")

    exit_code = runner.main(
        [
            "execute",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--incident-input",
            str(incident),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
            "--case",
            "alpha",
            "--case",
            "alpha",
            "--case",
            "beta",
            "--max-cases",
            "2",
            "--max-workers",
            "3",
            "--no-resume",
        ]
    )

    assert exit_code == 0
    assert call_order == ["prepare", "execute"]
    assert prepare_seen["selected_cases"] == ["alpha", "alpha", "beta"]
    assert prepare_seen["max_cases"] == 2
    assert resolver_seen["template_path"] == Path(prepared["run_root"]) / "frozen_inputs" / "provider_template.yaml"
    assert resolver_seen["artifact_root"] == Path(prepared["run_root"]) / "rpc_receipts"
    assert resolver_seen["env_has_secret"] is True
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["command"] == "execute"
    assert payload["run_id"] == "run-001"
    assert payload["revision"] == "historical-snapshots-417"
    assert payload["selected_case_count"] == 2
    assert payload["processed_case_count"] == 2
    assert payload["candidate_closed_count"] == 1
    assert payload["quarantined_case_count"] == 1
    assert payload["retried_case_count"] == 1
    assert payload["blocker_count"] == 2
    assert payload["blocker_counts_by_code"] == {"missing_api_key": 1, "receipt_binding_invalid": 1}
    assert payload["artifact_paths"]["rpc_receipt_manifest"]["relative"] == "rpc_receipt_manifest.json"
    assert payload["artifact_paths"]["rpc_receipt_manifest"]["absolute"].endswith("rpc_receipt_manifest.json")
    serialized = json.dumps(payload, sort_keys=True)
    assert "super-secret-value" not in serialized
    assert "https://" not in serialized


def test_execute_without_case_forwards_none_and_max_cases_scopes_full_population(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepared = _prepared_run(tmp_path)
    seen: dict[str, object] = {}

    def fake_prepare(queue, temporal, *, policy_path, provider_template_path, incident_input_path, output_root, revision, run_id, selected_cases, max_cases):
        seen.update(
            {
                "queue": queue,
                "temporal": temporal,
                "policy_path": policy_path,
                "provider_template_path": provider_template_path,
                "incident_input_path": incident_input_path,
                "output_root": output_root,
                "revision": revision,
                "run_id": run_id,
                "selected_cases": selected_cases,
                "max_cases": max_cases,
            }
        )
        return prepared

    def fake_execute(prepared_run, *, provider_resolver, case_executor, max_workers, resume):
        return {
            "summary": {
                "selected_case_count": 5,
                "processed_case_count": 5,
                "candidate_closed_count": 0,
                "reused_case_count": 0,
                "quarantined_case_count": 0,
                "retried_case_count": 0,
            },
            "blocker_rows": [],
            "aggregate_artifacts": {"paths": {}, "hashes": {}},
        }

    monkeypatch.setattr(runner, "prepare_historical_snapshot_run", fake_prepare)
    monkeypatch.setattr(runner, "execute_historical_snapshot_cases", fake_execute)
    monkeypatch.setattr(runner, "load_managed_provider_templates", lambda path: {"loaded_from": str(path)}, raising=False)
    monkeypatch.setattr(
        runner,
        "providers_for_chain_from_managed_env",
        lambda *args, **kwargs: [],
        raising=False,
    )
    monkeypatch.setattr(runner, "_load_execute_env", lambda: {}, raising=False)

    queue = tmp_path / "queue.csv"
    temporal = tmp_path / "temporal.csv"
    policy = tmp_path / "policy.yaml"
    template = tmp_path / "provider-template.yaml"
    output_root = tmp_path / "output"
    for path in (queue, temporal, policy, template):
        path.write_text("fixture\n", encoding="utf-8")

    exit_code = runner.main(
        [
            "execute",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
            "--max-cases",
            "5",
        ]
    )

    assert exit_code == 0
    assert seen["selected_cases"] is None
    assert seen["max_cases"] == 5
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["command"] == "execute"
    assert payload["selected_case_count"] == 5
    assert payload["processed_case_count"] == 5


def test_execute_validation_and_error_sanitization(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    queue = tmp_path / "queue.csv"
    temporal = tmp_path / "temporal.csv"
    policy = tmp_path / "policy.yaml"
    template = tmp_path / "provider-template.yaml"
    output_root = tmp_path / "output"
    for path in (queue, temporal, policy, template):
        path.write_text("fixture\n", encoding="utf-8")

    monkeypatch.setattr(runner, "_load_execute_env", lambda: (_ for _ in ()).throw(AssertionError("env should not load for invalid max_workers")), raising=False)
    invalid_exit = runner.main(
        [
            "execute",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
            "--max-workers",
            "0",
        ]
    )
    assert invalid_exit == 1
    invalid_stdout = _parse_json_lines(capsys.readouterr().out)
    assert invalid_stdout["status"] == "error"
    assert invalid_stdout["error_code"] == "invalid_cli_argument"
    assert invalid_stdout["message"] == "max_workers must be >= 1"

    def fake_prepare(*args, **kwargs):
        raise ManagedProviderConfigurationError(
            "missing_api_key",
            "missing secret super-secret-value at https://rpc.example/provider",
            chain="ethereum",
            operator_family="alchemy",
        )

    monkeypatch.setattr(runner, "prepare_historical_snapshot_run", fake_prepare)
    monkeypatch.setattr(runner, "_load_execute_env", lambda: {"CHRONOS_ALCHEMY_API_KEY": "super-secret-value"}, raising=False)

    managed_exit = runner.main(
        [
            "execute",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
        ]
    )
    assert managed_exit == 1
    managed_payload = _parse_json_lines(capsys.readouterr().out)
    assert managed_payload["status"] == "error"
    assert managed_payload["error_code"] == "missing_api_key"
    assert managed_payload["message"] == "managed provider configuration failed"
    serialized = json.dumps(managed_payload, sort_keys=True)
    assert "super-secret-value" not in serialized
    assert "https://rpc.example/provider" not in serialized


def test_parser_level_failures_return_sanitized_json(capsys: pytest.CaptureFixture[str]) -> None:
    missing_required_exit = runner.main(["execute"])
    assert missing_required_exit == 1
    missing_required_payload = _parse_json_lines(capsys.readouterr().out)
    assert missing_required_payload["status"] == "error"
    assert missing_required_payload["error_code"] == "invalid_cli_argument"
    assert missing_required_payload["message"] == "invalid command line arguments"

    malformed_exit = runner.main(["execute", "--definitely-unknown-flag"])
    assert malformed_exit == 1
    malformed_payload = _parse_json_lines(capsys.readouterr().out)
    assert malformed_payload["status"] == "error"
    assert malformed_payload["error_code"] == "invalid_cli_argument"
    assert malformed_payload["message"] == "invalid command line arguments"


def test_missing_input_paths_use_stable_sanitized_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    queue = tmp_path / "missing-super-secret-value.csv"
    temporal = tmp_path / "temporal.csv"
    policy = tmp_path / "policy.yaml"
    template = tmp_path / "provider-template.yaml"
    output_root = tmp_path / "output"
    for path in (temporal, policy, template):
        path.write_text("fixture\n", encoding="utf-8")

    monkeypatch.setattr(
        runner,
        "build_snapshot_run_plan",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("missing inputs must fail before planning")),
    )
    monkeypatch.setattr(
        runner,
        "_load_execute_env",
        lambda: (_ for _ in ()).throw(AssertionError("missing inputs must fail before dotenv loading")),
        raising=False,
    )

    exit_code = runner.main(
        [
            "plan",
            "--queue",
            str(queue),
            "--temporal",
            str(temporal),
            "--policy",
            str(policy),
            "--provider-template",
            str(template),
            "--output-root",
            str(output_root),
            "--revision",
            "historical-snapshots-417",
            "--run-id",
            "run-001",
        ]
    )

    assert exit_code == 1
    payload = _parse_json_lines(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert payload["error_code"] == "input_not_found"
    assert payload["message"] == "required input path missing for --queue"
    serialized = json.dumps(payload, sort_keys=True)
    assert str(queue) not in serialized
    assert "super-secret-value" not in serialized
